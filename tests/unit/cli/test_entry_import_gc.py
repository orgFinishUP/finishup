"""The full CLI loads with cyclic collection off and runs its command with it on over a frozen heap.

Loading ``finishup.cli.app`` builds a large heap that a short command never frees; collecting
it during the import and again at interpreter exit was pure overhead. The guard is a count, not a
clock: no collection runs during the import, the heap is frozen, and collection is on before the
command body. Garbage that existed before the call is collected first, never frozen. ``mcp serve``
(already off; the bridge freezes its own heap), the commands that serve until stopped (``service
run``, ``service rest run``, ``helper run``), and an in-process caller that already loaded the CLI
keep their collection behaviour exactly as before.
"""

from __future__ import annotations

import gc
import json
import subprocess
import sys

import pytest

from finishup.cli import entry

_PROBE = r"""
import gc, importlib.abc, importlib.machinery, json, sys

argv, mode = json.loads(sys.argv[1])
# Python 3.12 starts with objects already in the permanent generation, so "frozen" is always
# measured against the count this process started with.
record = {"collections_during_import": 0, "frozen_at_start": gc.get_freeze_count()}
importing = [False]
finalized = []


class Cycle:
    def __del__(self):
        finalized.append(True)


dead = Cycle()
dead.self = dead
del dead


def on_collect(phase, info):
    if phase == "start" and importing[0]:
        record["collections_during_import"] += 1


class Hook(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path, target=None):
        if name != "finishup.cli.app":
            return None
        if mode == "raise":
            raise ImportError("probe_import_failure")
        sys.meta_path.remove(self)
        spec = importlib.machinery.PathFinder.find_spec(name, path)
        loader = spec.loader
        real_exec = loader.exec_module

        def exec_module(module):
            importing[0] = True
            try:
                real_exec(module)
            finally:
                importing[0] = False

            def body():
                record["enabled_in_body"] = gc.isenabled()
                record["frozen_in_body"] = gc.get_freeze_count()

            module.main = body

        loader.exec_module = exec_module
        return spec


if mode == "preloaded":
    import finishup.cli.app

    finishup.cli.app.main = lambda: record.update(
        enabled_in_body=gc.isenabled(), frozen_in_body=gc.get_freeze_count()
    )
else:
    sys.meta_path.insert(0, Hook())
gc.callbacks.append(on_collect)
sys.argv = ["finishup", *argv]
from finishup.cli import entry

try:
    entry._run_full_cli()
except ImportError as error:
    record["raised"] = str(error)
record["enabled_after"] = gc.isenabled()
record["frozen_after"] = gc.get_freeze_count()
gc.collect()
record["earlier_garbage_finalized"] = finalized == [True]
print(json.dumps(record))
"""


def _probe(argv: list[str], mode: str = "fresh") -> dict[str, object]:
    result = subprocess.run(
        [sys.executable, "-c", _PROBE, json.dumps([argv, mode])],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def _newly_frozen(record: dict[str, object]) -> int:
    """Objects frozen between the probe's start and the command body."""

    start, body = record["frozen_at_start"], record["frozen_in_body"]
    assert isinstance(start, int) and isinstance(body, int)
    return body - start


@pytest.mark.parametrize("argv", [["--help"], ["status", "--json"], ["service", "status", "-x"]])
def test_a_fresh_full_cli_freezes_its_import_heap_and_runs_with_collection_on(
    argv: list[str],
) -> None:
    record = _probe(argv)
    assert record["collections_during_import"] == 0
    assert record["enabled_in_body"] is True
    assert _newly_frozen(record) > 0
    assert record["enabled_after"] is True


@pytest.mark.parametrize(
    "argv",
    [
        ["service", "run"],
        ["service", "rest", "run", "--edge", "native"],
        ["service", "rest", "run"],
        ["helper", "run", "--target", "t_00000000"],
    ],
)
def test_a_serving_process_keeps_its_collection_behaviour(argv: list[str]) -> None:
    record = _probe(argv)
    collections = record["collections_during_import"]
    assert isinstance(collections, int) and collections > 0
    assert record["enabled_in_body"] is True
    assert _newly_frozen(record) == 0


def test_an_already_loaded_cli_is_never_frozen() -> None:
    record = _probe(["--help"], mode="preloaded")
    assert record["enabled_in_body"] is True
    assert _newly_frozen(record) == 0


def test_a_failed_import_still_turns_collection_back_on() -> None:
    record = _probe(["--help"], mode="raise")
    assert record["raised"] == "probe_import_failure"
    assert record["enabled_after"] is True
    assert "enabled_in_body" not in record


def test_a_cold_in_process_call_never_freezes_garbage_that_already_existed() -> None:
    # The probe is itself an in-process caller: it calls _run_full_cli from its own heap.
    record = _probe(["--help"])
    assert _newly_frozen(record) > 0
    assert record["earlier_garbage_finalized"] is True


def test_in_process_calls_after_the_cli_loaded_leave_the_heap_unfrozen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.app as cli_app

    seen: list[tuple[bool, int]] = []
    monkeypatch.setattr(
        cli_app, "main", lambda: seen.append((gc.isenabled(), gc.get_freeze_count()))
    )
    monkeypatch.setattr(sys, "argv", ["finishup", "--help"])
    frozen_before = gc.get_freeze_count()
    entry._run_full_cli()  # pyright: ignore[reportPrivateUsage]
    entry._run_full_cli()  # pyright: ignore[reportPrivateUsage]
    assert seen == [(True, frozen_before), (True, frozen_before)]
    assert gc.isenabled()
