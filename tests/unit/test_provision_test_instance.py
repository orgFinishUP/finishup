"""Test-instance tooling drives runtimes built before and after the rename (ADR-028, ADR-048).

These cases exercise the script's launcher probe, environment scrub, and dispose bootstrap with
fake runtime trees and an intercepted subprocess runner; nothing is built or installed. The
disposal cases (issue #1350) hold real leases where the in-use check is the subject.
"""

from __future__ import annotations

import argparse
import fcntl
import importlib.util
import json
import os
import subprocess
import sys
from collections.abc import Callable, Generator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "provision_test_instance.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("provision_test_instance", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["provision_test_instance"] = module
    spec.loader.exec_module(module)
    return module


_MODULE = _load()


def _accept_base(monkeypatch: pytest.MonkeyPatch) -> None:
    # ``tmp_path`` sits under shared temp, which the real base check refuses by design.
    def accept(base: Path) -> Path:
        return base

    monkeypatch.setattr(_MODULE, "_validate_base", accept)


def _runtime(root: Path, *launchers: str) -> Path:
    runtime = root / "runtime"
    (runtime / "bin").mkdir(parents=True)
    for name in launchers:
        (runtime / "bin" / name).write_text("#!/bin/sh\n", encoding="ascii")
    return runtime


@pytest.mark.parametrize(
    ("launchers", "expected"),
    [
        (("finishup",), ("finishup", "finishup")),
        (("yoetz",), ("yoetz", "yoetz")),
        # A runtime that ships the deprecated alias too is still a FinishUP runtime.
        (("finishup", "yoetz"), ("finishup", "finishup")),
    ],
)
def test_the_runtime_launcher_probe_prefers_finishup_then_legacy(
    tmp_path: Path, launchers: tuple[str, ...], expected: tuple[str, str]
) -> None:
    runtime = _runtime(tmp_path, *launchers)
    launcher, package = _MODULE._runtime_launcher(runtime)
    assert (launcher.name, package) == expected
    assert launcher.parent == runtime / "bin"


def test_a_runtime_without_any_launcher_is_absent(tmp_path: Path) -> None:
    assert _MODULE._runtime_launcher(_runtime(tmp_path)) is None


def test_snapshot_commands_inherit_neither_variable_prefix(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("FINISHUP_ISOLATED_ROOT", "/elsewhere")
    monkeypatch.setenv("YOETZ_ISOLATED_ROOT", "/elsewhere")
    monkeypatch.setenv("YOETZ_PROFILE", "test-fake")
    monkeypatch.setenv("_FINISHUP_TEST_INSTALLATION", "kept")
    env = _MODULE._clean_env(tmp_path)
    assert not any(name.startswith(("FINISHUP_", "YOETZ_")) for name in env)
    assert env["_FINISHUP_TEST_INSTALLATION"] == "kept"
    assert env["HOME"] == str(tmp_path)


def test_the_environment_export_names_both_spellings_with_one_root(tmp_path: Path) -> None:
    root = tmp_path / "state"
    assert _MODULE._environment_export(root) == (
        f"FINISHUP_ISOLATED_ROOT={root} YOETZ_ISOLATED_ROOT={root}"
    )


def test_status_drives_a_pre_rename_runtime_through_its_legacy_launcher(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _accept_base(monkeypatch)
    base = tmp_path / "base"
    layout = _MODULE._layout(base, "old")
    layout["root"].mkdir(parents=True)
    runtime = _runtime(layout["root"], "yoetz")
    # A provisioned runtime carries its pin (a launcher without one is reported, never run).
    (runtime / _MODULE._PIN_NAME).write_text("{}", encoding="utf-8")
    layout["provenance"].write_text("{}", encoding="utf-8")
    invoked: list[Path] = []

    def snapshot(launcher: Path, args: list[str], env: dict[str, str]) -> dict[str, object]:
        invoked.append(launcher)
        return {"state": "ok"}

    monkeypatch.setattr(_MODULE, "_snapshot_command", snapshot)
    result = _MODULE.command_status(argparse.Namespace(base=str(base), tag="old"))
    assert result["state"] == "present"
    assert invoked == [layout["runtime"] / "bin" / "yoetz"]


# --- dispose (issue #1350): a refused disposal changes nothing; no launcher is left unpinned ---

_GEN = "a" * 64


def _instance(tmp_path: Path, launcher: str = "finishup") -> dict[str, Path]:
    """A provisioned layout: launchers and ``python`` in ``bin``, the pin, the sealed state."""

    base = tmp_path / "base"
    layout = _MODULE._layout(base, "inst")
    layout["root"].mkdir(parents=True)
    runtime = _runtime(layout["root"], launcher, "python")
    (runtime / _MODULE._PIN_NAME).write_text("{}", encoding="utf-8")
    (layout["state"] / "state").mkdir(parents=True)
    (layout["state"] / "state" / "instance-identity.json").write_text("{}", encoding="utf-8")
    (runtime.parent / f".{runtime.name}-releases" / _GEN).mkdir(parents=True)
    (runtime.parent / f".{runtime.name}-releases" / _GEN / ".in-use").write_bytes(b"")
    return {**layout, "base": base}


def _status(pid: int | None = None, **overrides: object) -> dict[str, object]:
    holder = None if pid is None else {"pid": pid}
    return {
        "mode": "isolated",
        "binding": "runtime_pin",
        "lifecycle": "disposable",
        "service_holder": holder,
        **overrides,
    }


class _Runner:
    """Answers the script's subprocesses by kind and records what each saw on disk."""

    def __init__(self, layout: dict[str, Path], status: dict[str, object]) -> None:
        self.layout = layout
        self.status = status
        self.calls: list[str] = []
        self.dispose_exit = 0
        self.dispose_out: dict[str, object] = {"disposed": True, "service_stopped": True}
        self.on_dispose: Callable[[], None] | None = None
        self.seen_at_dispose: dict[str, bool] = {}

    def __call__(self, args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        runtime = self.layout["runtime"]
        if args[1:3] == ["instance", "status"]:
            self.calls.append("status")
            return subprocess.CompletedProcess(args, 0, json.dumps(self.status).encode(), b"")
        script = args[-2] if len(args) >= 2 and args[-2].startswith("import") else args[-1]
        if "dispose_instance" in script:
            self.calls.append("dispose")
            request = json.loads(args[-1])
            self.seen_at_dispose = {
                "bin": (runtime / "bin").exists(),
                "withdrawn": (runtime / _MODULE._WITHDRAWN_BIN).exists(),
                "pin": (runtime / _MODULE._PIN_NAME).is_file(),
                "prefix_is_withdrawn": request["prefix"] == str(runtime / _MODULE._WITHDRAWN_BIN),
            }
            if self.on_dispose is not None:
                self.on_dispose()
            elif self.dispose_exit == 0:
                import shutil

                shutil.rmtree(self.layout["state"])
            return subprocess.CompletedProcess(
                args, self.dispose_exit, json.dumps(self.dispose_out).encode(), b""
            )
        if "prune_release_runtimes" in script:
            self.calls.append("prune")
            return subprocess.CompletedProcess(args, 0, b"[1, 0]", b"")
        if args[:1] == ["ps"] or args[0].endswith("lsof"):
            return _REAL_RUN(args, **_kwargs)  # pyright: ignore[reportArgumentType]
        raise AssertionError(f"unexpected subprocess {args[:3]}")


_REAL_RUN = _MODULE._run


def _dispose(layout: dict[str, Path]) -> dict[str, object]:
    return _MODULE.command_dispose(
        argparse.Namespace(base=str(layout["base"]), tag="inst", retain_logs=None)
    )


@contextmanager
def _held(lease: Path) -> Generator[None]:
    descriptor = os.open(lease, os.O_RDONLY)
    fcntl.flock(descriptor, fcntl.LOCK_SH)
    try:
        yield
    finally:
        os.close(descriptor)


def _unchanged(layout: dict[str, Path]) -> None:
    runtime = layout["runtime"]
    assert (runtime / "bin" / "finishup").is_file()
    assert not (runtime / _MODULE._WITHDRAWN_BIN).exists()
    assert (runtime / _MODULE._PIN_NAME).is_file()
    assert (layout["state"] / "state" / "instance-identity.json").is_file()


@pytest.mark.parametrize(("launcher", "package"), [("finishup", "finishup"), ("yoetz", "yoetz")])
def test_dispose_withdraws_the_launchers_before_anything_and_keeps_the_pin_to_the_end(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, launcher: str, package: str
) -> None:
    _accept_base(monkeypatch)
    layout = _instance(tmp_path, launcher)
    runner = _Runner(layout, _status())
    monkeypatch.setattr(_MODULE, "_run", runner)

    result = _dispose(layout)

    assert runner.calls == ["status", "dispose", "prune"]
    # When the state was removed, no registered path could start the runtime any more, and the
    # pin was still there: at no moment did a launcher exist without its pin.
    assert runner.seen_at_dispose == {
        "bin": False,
        "withdrawn": True,
        "pin": True,
        "prefix_is_withdrawn": True,
    }
    assert result["state"] == "removed" and result["launchers_withdrawn"] is True
    assert not layout["root"].exists()


def test_a_host_session_s_lease_refuses_before_anything_is_stopped_or_removed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _accept_base(monkeypatch)
    layout = _instance(tmp_path)
    runner = _Runner(layout, _status(pid=None))
    monkeypatch.setattr(_MODULE, "_run", runner)
    lease = layout["runtime"].parent / ".runtime-releases" / _GEN / ".in-use"

    with _held(lease), pytest.raises(_MODULE.ProvisionError, match="^runtime_in_use: "):
        _dispose(layout)

    assert runner.calls == ["status"]
    _unchanged(layout)


def test_the_instance_s_own_service_lease_does_not_refuse(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The service holds a lease too; it is the one process disposal stops itself."""

    _accept_base(monkeypatch)
    layout = _instance(tmp_path)
    runner = _Runner(layout, _status(pid=os.getpid()))
    monkeypatch.setattr(_MODULE, "_run", runner)
    lease = layout["runtime"].parent / ".runtime-releases" / _GEN / ".in-use"

    with _held(lease):
        result = _dispose(layout)

    assert result["state"] == "removed"


def test_a_lease_held_beside_the_running_service_refuses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _accept_base(monkeypatch)
    layout = _instance(tmp_path)
    lease = layout["runtime"].parent / ".runtime-releases" / _GEN / ".in-use"
    holder_code = (
        "import fcntl,os,sys,time; d=os.open(sys.argv[1], os.O_RDONLY); "
        "fcntl.flock(d, fcntl.LOCK_SH); print('held', flush=True); time.sleep(60)"
    )
    service = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    host = subprocess.Popen([sys.executable, "-c", holder_code, str(lease)], stdout=subprocess.PIPE)
    try:
        assert host.stdout is not None and host.stdout.readline() == b"held\n"
        runner = _Runner(layout, _status(pid=service.pid))
        monkeypatch.setattr(_MODULE, "_run", runner)
        with pytest.raises(_MODULE.ProvisionError, match="^runtime_in_use: "):
            _dispose(layout)
        assert runner.calls == ["status"]
        _unchanged(layout)
    finally:
        for proc in (service, host):
            proc.kill()
            proc.wait(timeout=10)
        if host.stdout is not None:
            host.stdout.close()


def test_when_holders_cannot_be_named_disposal_refuses_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _accept_base(monkeypatch)
    layout = _instance(tmp_path)
    runner = _Runner(layout, _status(pid=os.getpid()))
    monkeypatch.setattr(_MODULE, "_run", runner)

    def unknown(_leases: list[Path]) -> None:
        return None

    monkeypatch.setattr(_MODULE, "_lease_holders", unknown)
    lease = layout["runtime"].parent / ".runtime-releases" / _GEN / ".in-use"

    with (
        _held(lease),
        pytest.raises(_MODULE.ProvisionError, match="^runtime_in_use_unverifiable: "),
    ):
        _dispose(layout)
    _unchanged(layout)


@pytest.mark.parametrize(
    ("status", "token"),
    [
        (_status(binding="ambient", mode="ambient"), "instance_not_pinned"),
        (_status(lifecycle="unlabeled"), "instance_not_disposable"),
    ],
)
def test_a_launcher_not_pinned_to_a_disposable_root_is_refused_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, status: dict[str, object], token: str
) -> None:
    _accept_base(monkeypatch)
    layout = _instance(tmp_path)
    monkeypatch.setattr(_MODULE, "_run", _Runner(layout, status))
    with pytest.raises(_MODULE.ProvisionError, match=f"^{token}: "):
        _dispose(layout)
    _unchanged(layout)


def test_a_failure_that_removed_nothing_puts_the_launchers_back_pinned(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _accept_base(monkeypatch)
    layout = _instance(tmp_path)
    runner = _Runner(layout, _status())
    runner.dispose_exit = 3
    runner.dispose_out = {"refused": "instance_service_running"}
    monkeypatch.setattr(_MODULE, "_run", runner)

    with pytest.raises(
        _MODULE.ProvisionError, match="^instance_dispose_failed: instance_service_running: "
    ):
        _dispose(layout)
    _unchanged(layout)


def test_a_failure_part_way_keeps_the_launchers_withdrawn_and_a_rerun_finishes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _accept_base(monkeypatch)
    layout = _instance(tmp_path)
    runner = _Runner(layout, _status())
    runner.dispose_exit = 1
    runner.dispose_out = {}

    def half() -> None:
        (layout["state"] / "state" / "instance-identity.json").unlink()

    runner.on_dispose = half
    monkeypatch.setattr(_MODULE, "_run", runner)
    with pytest.raises(_MODULE.ProvisionError, match="^instance_dispose_incomplete: "):
        _dispose(layout)
    runtime = layout["runtime"]
    assert not (runtime / "bin").exists() and (runtime / _MODULE._WITHDRAWN_BIN).is_dir()
    status = _MODULE.command_status(argparse.Namespace(base=str(layout["base"]), tag="inst"))
    assert status["state"] == "disposing"

    finisher = _Runner(layout, _status())
    monkeypatch.setattr(_MODULE, "_run", finisher)
    assert _dispose(layout)["state"] == "removed"
    # The rerun never ran a launcher: it resumed from the withdrawn copy.
    assert "status" not in finisher.calls
    assert not layout["root"].exists()


def test_a_launcher_an_older_dispose_left_unpinned_is_never_run_only_removed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The state #1350 left behind: state and pin gone, the launcher still at its path."""

    _accept_base(monkeypatch)
    layout = _instance(tmp_path)
    (layout["runtime"] / _MODULE._PIN_NAME).unlink()
    import shutil

    shutil.rmtree(layout["state"])
    status = _MODULE.command_status(argparse.Namespace(base=str(layout["base"]), tag="inst"))
    assert status["state"] == "unpinned"
    runner = _Runner(layout, _status())
    monkeypatch.setattr(_MODULE, "_run", runner)

    assert _dispose(layout)["state"] == "removed"
    assert runner.calls == ["prune"]
    assert not layout["root"].exists()


@pytest.mark.parametrize("source", ["proc", "lsof"])
def test_lease_holders_are_named_through_proc_and_through_lsof(tmp_path: Path, source: str) -> None:
    """``/proc`` on Linux; ``lsof`` where there is none (macOS), forced here where it exists."""

    import shutil

    if source == "proc" and not Path("/proc/self/fd").is_dir():
        pytest.skip("no /proc on this system")
    if source == "lsof" and shutil.which("lsof") is None and not Path("/usr/sbin/lsof").is_file():
        pytest.skip("no lsof on this system")
    lease = tmp_path / ".in-use"
    lease.write_bytes(b"")
    code = (
        "import fcntl,os,sys,time; d=os.open(sys.argv[1], os.O_RDONLY); "
        "fcntl.flock(d, fcntl.LOCK_SH); print('held', flush=True); time.sleep(60)"
    )
    holder = subprocess.Popen([sys.executable, "-c", code, str(lease)], stdout=subprocess.PIPE)
    try:
        assert holder.stdout is not None and holder.stdout.readline() == b"held\n"
        proc = Path("/proc") if source == "proc" else tmp_path / "no-proc"
        assert _MODULE._held_leases(tmp_path.parent) == []  # not a releases folder
        found = _MODULE._lease_holders([lease], proc=proc)
        assert found is not None and holder.pid in found
        assert _MODULE._process_tree(holder.pid) == {holder.pid}
    finally:
        holder.kill()
        holder.wait(timeout=10)
        if holder.stdout is not None:
            holder.stdout.close()


def test_create_over_a_half_disposed_tag_refuses_before_touching_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _accept_base(monkeypatch)
    layout = _instance(tmp_path)
    os.rename(layout["runtime"] / "bin", layout["runtime"] / _MODULE._WITHDRAWN_BIN)
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "pyproject.toml").write_text("", encoding="utf-8")
    arguments = argparse.Namespace(
        base=str(layout["base"]),
        tag="inst",
        checkout=str(checkout),
        revision="HEAD",
        lifecycle="disposable",
        expires_in=None,
        allow_dirty=False,
        python=sys.executable,
    )
    with pytest.raises(_MODULE.ProvisionError, match="^instance_exists: dispose that tag first"):
        _MODULE.command_create(arguments)
    # Nothing was removed: the next dispose finishes what the earlier one started.
    assert (layout["runtime"] / _MODULE._WITHDRAWN_BIN / "finishup").is_file()
    assert (layout["runtime"] / _MODULE._PIN_NAME).is_file()
