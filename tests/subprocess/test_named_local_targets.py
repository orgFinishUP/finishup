"""Two named local servers, each with its own service, and CLI calls that follow the selection.

ADR-051 (design section 5): ``finishup server add NAME --local`` makes an independent instance
root; ``finishup server use NAME`` writes the owner-only selection; every new client process then
resolves that root, so ``service start`` and ``service status`` reach that target's own service,
and switching the selection switches the service a fresh process reaches. Nothing here sets an
isolation-root variable: the selection alone decides (run with both root variables unset).

Services are stopped only through ``finishup server remove``, which signals the process stamped
in that target root's own singleton lock — never anything matched by name or pattern.

A start may answer the product's own retryable ``service_handshake_timeout``: the spawned service
holds its root but has not answered a hello within the 30-second start budget. That happened once
in about 89 runs of this test on a slow CI runner, with the same budget as on ``main`` (run u8,
part C). The test then waits on the service's real state (``service status --json``) to a bounded
deadline, never on a sleep, and on any failure it keeps the services' logs (copied beside the
test, and their last lines printed) before teardown removes them.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import cast

import pytest

from builders.server_targets import short_home_base

_TIMEOUT = 90
# How long a start that answered the retryable handshake timeout may take to become reachable.
_START_DEADLINE_SECONDS = 120.0
_LOG_TAIL_BYTES = 4_000


@contextmanager
def _private_everyday_folders(prefix: str) -> Generator[dict[str, str]]:
    """The environment with every everyday folder (data, state, config, cache, runtime) moved.

    One short owner-only tree beneath a home short enough for the socket bound (outside shared
    temp): target roots live beneath the ambient state directory and must keep their socket
    paths under ``sun_path``. No folder may resolve to this account's real installation, whose
    everyday service a probe of the ``local`` server would otherwise find, so ``HOME`` moves
    into the tree too.
    """

    base = Path(tempfile.mkdtemp(prefix=prefix, dir=short_home_base()))
    base.chmod(0o700)
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("FINISHUP_", "YOETZ_"))
    }
    environment["HOME"] = str(base)
    for variable, leaf in (
        ("XDG_STATE_HOME", "s"),
        ("XDG_CONFIG_HOME", "c"),
        ("XDG_DATA_HOME", "d"),
        ("XDG_CACHE_HOME", "k"),
        ("XDG_RUNTIME_DIR", "r"),
    ):
        (base / leaf).mkdir(mode=0o700)
        environment[variable] = str(base / leaf)
    try:
        yield environment
    finally:
        shutil.rmtree(base, ignore_errors=True)


@pytest.fixture
def selection_environment() -> Iterator[dict[str, str]]:
    """The hermetic environment for two named local servers; ``local`` reaches nothing real."""

    with _private_everyday_folders(".yz-nlt-") as environment:
        yield environment


def _finishup(environment: dict[str, str], *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - this interpreter and fixed arguments
        (sys.executable, "-m", "finishup", *arguments),
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=_TIMEOUT,
        check=False,
    )


def _json(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    assert result.returncode == 0, result.stderr
    return cast(dict[str, object], json.loads(result.stdout))


def _started(environment: dict[str, str]) -> dict[str, object]:
    """``service start --json``; after the retryable handshake timeout, the service it started.

    Only that one refusal is waited on: exit 20 naming ``service_handshake_timeout``, which the
    product marks retryable because the spawned service is still starting. The wait reads the
    service's own status until it answers or the bounded deadline passes; any other failure fails
    the test at once.
    """

    started = _finishup(environment, "service", "start", "--json")
    if started.returncode == 0:
        return cast(dict[str, object], json.loads(started.stdout))
    assert started.returncode == 20, started.stderr
    assert "service_handshake_timeout" in started.stdout + started.stderr, started.stderr
    deadline = time.monotonic() + _START_DEADLINE_SECONDS
    while True:
        status = _finishup(environment, "service", "status", "--json")
        if status.returncode == 0:
            return cast(dict[str, object], json.loads(status.stdout))
        assert time.monotonic() < deadline, status.stderr


@contextmanager
def _logs_kept_on_failure(environment: dict[str, str], keep: Path) -> Generator[None]:
    """On any failure, copy every service log beneath the test's folders to ``keep`` and print
    the end of each, before teardown removes the folders."""

    try:
        yield
    except BaseException:
        base = Path(environment["HOME"])
        for log in sorted(base.rglob("log/*")):
            if not log.is_file() or log.is_symlink():
                continue
            target = keep / log.relative_to(base)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(log, target)
            tail = log.read_bytes()[-_LOG_TAIL_BYTES:].decode("utf-8", errors="replace")
            sys.stderr.write(f"--- {log.relative_to(base)} (last bytes) ---\n{tail}\n")
        sys.stderr.write(f"service logs kept in {keep}\n")
        raise


def test_cli_calls_follow_the_selection_between_two_named_local_servers(
    selection_environment: dict[str, str], tmp_path: Path
) -> None:
    env = selection_environment
    names = ("work", "lab")
    try:
        with _logs_kept_on_failure(env, tmp_path / "service-logs"):
            for name in names:
                added = _finishup(env, "server", "add", name, "--local")
                assert added.returncode == 0, added.stderr

            assert _finishup(env, "server", "use", "work").returncode == 0
            work_started = _started(env)
            work_status = _json(_finishup(env, "service", "status", "--json"))
            assert work_status["service_instance_id"] == work_started["service_instance_id"]
            work_isolation = _json(_finishup(env, "service", "isolation", "--json"))
            assert (work_isolation["binding"], work_isolation["mode"]) == ("selection", "isolated")
            assert work_isolation["lifecycle"] == "persistent"

            assert _finishup(env, "server", "use", "lab").returncode == 0
            lab_started = _started(env)
            lab_status = _json(_finishup(env, "service", "status", "--json"))
            assert lab_status["service_instance_id"] == lab_started["service_instance_id"]
            assert lab_status["service_instance_id"] != work_status["service_instance_id"]
            lab_isolation = _json(_finishup(env, "service", "isolation", "--json"))
            assert (
                lab_isolation["path_identity"]
                != work_isolation["path_identity"]  # every root moved
            )

            # ``service start`` is idempotent: the running service is kept.
            again = _json(_finishup(env, "service", "start", "--json"))
            assert again["service_instance_id"] == lab_status["service_instance_id"]

            # ``server status NAME`` probes one target without changing the selection.
            work_probe = _json(_finishup(env, "server", "status", "work", "--json"))
            probe = cast(dict[str, object], work_probe["probe"])
            assert probe["service_instance_id"] == work_status["service_instance_id"]
            assert probe["outcome"] in {"ready", "reachable"}
            assert work_probe["source"] == "selection"
            current = _json(_finishup(env, "server", "status", "--json"))
            assert cast(dict[str, object], current["target"])["name"] == "lab"
            assert (
                cast(dict[str, object], current["probe"])["service_instance_id"]
                == lab_status["service_instance_id"]
            )

            # Back to the everyday server: a fresh process no longer reaches either target.
            assert _finishup(env, "server", "use", "local").returncode == 0
            everyday = _json(_finishup(env, "server", "status", "--json"))
            assert everyday["source"] == "ambient"
            assert cast(dict[str, object], everyday["probe"])["outcome"] == "not_running"
    finally:
        for name in names:
            _finishup(env, "server", "remove", name, "--select-local")
    listed = _finishup(env, "server", "list")
    assert listed.returncode == 0
    assert "work" not in listed.stdout and "lab" not in listed.stdout


@pytest.fixture
def hermetic_everyday_environment() -> Iterator[dict[str, str]]:
    """The everyday service is started here, so none of its folders may be the account's own."""

    with _private_everyday_folders(".yz-amb-") as environment:
        yield environment


def test_the_everyday_server_starts_in_its_own_root_while_another_is_selected(
    hermetic_everyday_environment: dict[str, str], tmp_path: Path
) -> None:
    """ADR-051: a spawned service serves its spawner's root, never the selection it did not use.

    With ``work`` selected, ``server connect local`` starts the everyday service; its spawn is
    told the everyday installation (``service run --ambient-root``), so the service binds the
    everyday endpoint and nothing starts in ``work``'s root.
    """

    env = hermetic_everyday_environment
    try:
        with _logs_kept_on_failure(env, tmp_path / "service-logs"):
            assert _finishup(env, "server", "add", "work", "--local").returncode == 0
            assert _finishup(env, "server", "use", "work").returncode == 0

            connected = _finishup(env, "server", "connect", "local")
            assert connected.returncode == 0, connected.stderr
            assert "this computer's everyday server" in connected.stdout

            everyday = _json(_finishup(env, "server", "status", "local", "--json"))
            everyday_probe = cast(dict[str, object], everyday["probe"])
            assert everyday_probe["outcome"] in {"ready", "reachable"}, everyday_probe
            assert everyday["source"] == "selection"  # the selection is untouched
            work = _json(_finishup(env, "server", "status", "work", "--json"))
            assert cast(dict[str, object], work["probe"])["outcome"] == "not_running"
    finally:
        # Stopped through its own control channel, never by pattern.
        _finishup(env, "server", "disconnect", "local")
        _finishup(env, "server", "remove", "work", "--select-local")


def _answer(code: int, stdout: str, stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(("finishup",), code, stdout, stderr)


def test_a_start_that_timed_out_its_handshake_is_waited_on_through_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    timeout = '{"reason":"service_handshake_timeout","retryable":true}'
    answers = iter(
        [
            _answer(20, timeout, "service_unavailable: service_handshake_timeout"),
            _answer(20, "", "service_unavailable: not_running"),
            _answer(0, '{"service_instance_id":"svc_1"}'),
        ]
    )
    seen: list[tuple[str, ...]] = []

    def answer(_environment: dict[str, str], *arguments: str) -> subprocess.CompletedProcess[str]:
        seen.append(arguments)
        return next(answers)

    monkeypatch.setattr(sys.modules[__name__], "_finishup", answer)
    assert _started({}) == {"service_instance_id": "svc_1"}
    assert seen == [
        ("service", "start", "--json"),
        ("service", "status", "--json"),
        ("service", "status", "--json"),
    ]


def test_any_other_start_failure_fails_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    def answer(_environment: dict[str, str], *_arguments: str) -> subprocess.CompletedProcess[str]:
        return _answer(20, '{"reason":"service_startup_failed"}', "service_startup_failed")

    monkeypatch.setattr(sys.modules[__name__], "_finishup", answer)
    with pytest.raises(AssertionError):
        _started({})


def test_service_logs_are_kept_when_the_test_fails(tmp_path: Path) -> None:
    home = tmp_path / "home"
    log = home / "s" / "finishup" / "log" / "service.stderr.jsonl"
    log.parent.mkdir(parents=True)
    log.write_text('{"event":"started"}\n', encoding="utf-8")
    keep = tmp_path / "kept"
    with pytest.raises(RuntimeError), _logs_kept_on_failure({"HOME": str(home)}, keep):
        raise RuntimeError("failed")
    assert (keep / "s" / "finishup" / "log" / "service.stderr.jsonl").read_text(
        encoding="utf-8"
    ) == '{"event":"started"}\n'
