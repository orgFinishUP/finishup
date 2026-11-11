"""The acceptance harness's own logic (``scripts/acceptance/``), without any server.

The real runs (the matrix, the WAN gate, the upgrade) start services; these cases pin what decides
their verdicts: the cells are exactly the design's section 1.2 matrix, a cell fails when any step
failed, the WAN gate's percentile and budgets, its table, and the relay that counts dials and
injects the userspace delay; and what keeps a run honest and contained: the private ``sshd``'s
session, a cold hook sample that only counts when measured and failing open as an outage, a run's
cleanup that keeps its folder until its shutdown is proven, a ``SIGTERM`` that ends a run through
that cleanup, one redaction before anything is cut short, and the upgrade steps' own predicates.
"""

from __future__ import annotations

import importlib.util
import json
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_SCRIPTS = Path(__file__).resolve().parents[2] / "scripts" / "acceptance"


def _load(name: str) -> Any:
    sys.path.insert(0, str(_SCRIPTS))
    try:
        spec = importlib.util.spec_from_file_location(name, _SCRIPTS / f"{name}.py")
        assert spec is not None and spec.loader is not None
        module: ModuleType = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(_SCRIPTS))


harness = _load("harness")
matrix = _load("matrix")
wan_gate = _load("wan_gate")
upgrade = _load("upgrade")


@pytest.fixture(autouse=True)
def no_run_folder_outlives_its_test(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """A ``Run`` a test makes in this process never leaves its ``~/.yz-acc-*`` folder behind,
    even when the test fails before the run's own cleanup (only the folders made here)."""

    made: list[Any] = []
    original = harness.Run.__init__

    def recording(self: Any, *arguments: Any, **options: Any) -> None:
        original(self, *arguments, **options)
        made.append(self)

    monkeypatch.setattr(harness.Run, "__init__", recording)
    yield
    for run in made:
        harness.remove_tree(run.base)


def test_the_cells_are_the_design_matrix_and_nothing_else() -> None:
    cells = matrix.all_cells()
    names = [cell.name for cell in cells]
    assert len(names) == len(set(names)) == 23
    assert names[:2] == ["local", "named-local"]
    assert {(c.kind, c.edge, c.style, c.level) for c in cells if c.kind == "ssh"} == {
        ("ssh", "ssh", style, level) for style in ("relay", "direct") for level in ("L1", "L2")
    }
    assert {(c.kind, c.edge, c.style, c.level) for c in cells if c.kind in {"port", "https"}} == {
        (kind, edge, style, level)
        for kind in ("port", "https")
        for edge in ("gateway", "native")
        for style in ("relay", "direct")
        for level in ("L1", "L2")
    }
    assert names[-1] == "official"
    # Target names fit ``server add``'s 1-16 lowercase letters, digits and dashes, and differ.
    targets = [cell.target for cell in cells if cell.kind in {"ssh", "port", "https"}]
    assert len(set(targets)) == len(targets)
    assert all(len(t) <= 16 and t.replace("-", "").isalnum() and t.islower() for t in targets)


def test_cells_are_selected_by_name_or_glob() -> None:
    assert [c.name for c in matrix.select("ssh-*")] == [
        "ssh-relay-L1",
        "ssh-relay-L2",
        "ssh-direct-L1",
        "ssh-direct-L2",
    ]
    assert [c.name for c in matrix.select("local, official")] == ["local", "official"]
    assert matrix.select("nothing-like-this") == []


@pytest.mark.parametrize(
    ("verdicts", "expected"),
    [
        (["pass", "info", "pass"], "pass"),
        (["pass", "fail", "pass"], "fail"),
        (["skip", "info"], "skip"),
        ([], "skip"),
    ],
)
def test_one_failed_step_fails_the_cell(verdicts: list[str], expected: str) -> None:
    assert harness.verdict_of({"verdict": v} for v in verdicts) == expected
    report = harness.Report("cell")
    for index, verdict in enumerate(verdicts):
        if verdict == "skip":
            report.skip(f"s{index}", "skipped")
        else:
            report.add(f"s{index}", {"pass": True, "fail": False, "info": None}[verdict], "")
    assert report.verdict == expected


def test_a_refusal_counts_only_when_its_surface_names_it_typed() -> None:
    """The profile-changed step: a traceback that happens to name the phase (exit 1) fails."""

    document = json.dumps(
        {
            "ok": False,
            "phase": "server_profile_changed",
            "recovery": {"continuation": "remote_reconsent"},
        }
    )

    def result(code: int, out: str, err: str = "") -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(["finishup"], code, out, err)

    typed = matrix.typed_refusal
    assert typed(result(20, document), "server_profile_changed", "remote_reconsent")
    traceback = "Traceback (most recent call last):\nControlProtocolError: server_profile_changed"
    assert not typed(result(1, "", traceback), "server_profile_changed", "remote_reconsent")
    assert not typed(result(20, document, traceback), "server_profile_changed", "remote_reconsent")
    assert not typed(result(1, document), "server_profile_changed", "remote_reconsent")
    assert not typed(result(0, document), "server_profile_changed", "remote_reconsent")
    assert not typed(result(20, document), "server_profile_changed", "remote_reauthorize")
    assert not typed(result(20, "{}"), "server_profile_changed", "remote_reconsent")


def test_the_percentile_is_nearest_rank() -> None:
    values = [float(n) for n in range(1, 21)]
    assert wan_gate.percentile(values, 0.95) == 19.0
    assert wan_gate.percentile(values, 0.5) == 10.0
    assert wan_gate.percentile([7.0], 0.95) == 7.0
    assert wan_gate.percentile([], 0.95) is None


def _style(warm: float, hook: float, process: float, failures: int = 0) -> dict[str, Any]:
    return {
        "warm_connect_status": {"p95": warm, "failures": failures},
        "hook_cold_connect": {"p95": hook, "failures": 0},
        "warm_process": {"p95": process, "failures": 0},
    }


def test_the_gate_passes_only_within_every_budget_and_without_a_failed_sample() -> None:
    assert wan_gate.gate(_style(650, 1150, 3200))["pass"] is True
    over = wan_gate.gate(_style(651, 900, 2000))
    assert over["pass"] is False and over["checks"]["warm_connect_status"]["pass"] is False
    assert over["checks"]["hook_cold_connect"]["pass"] is True
    assert wan_gate.gate(_style(100, 100, 100, failures=1))["pass"] is False
    assert wan_gate.gate({})["pass"] is False  # nothing measured is never a pass


def test_the_gate_table_names_every_style_and_its_verdict(tmp_path: Path) -> None:
    style = {
        **_style(600, 1002, 1500),
        "warm_connect_status": {"p50": 550, "p95": 600, "failures": 0},
        "warm_process": {"p95": 1500, "failures": 0},
        "hook_cold_connect": {
            "n": 5,
            "p50": 1001,
            "p95": 1002,
            "served_within_budget": 0,
            "failed_open_phases": ["ControlError:service_unavailable:remote_unreachable"],
            "next_call_served": 5,
            "failures": 0,
        },
        "cold_connect": {"p50": 2500},
        "server_test": {"round_trip_p95_ms": 120},
    }
    style["gate"] = wan_gate.gate(style)
    path = tmp_path / "wan.json"
    path.write_text(
        json.dumps(
            {
                "rtt_ms": 100,
                "mode": "netns",
                "styles": {"ssh-relay": style, "ssh-direct": {"error": "x"}},
            }
        )
    )
    table = wan_gate.render([path])
    assert "| 100 ms | netns | – | ssh-relay | 550 / 600 | – / – | 1500 |" in table
    assert "failed open: remote_unreachable; next call served 5/5" in table
    assert table.rstrip().endswith("| fail |")  # the style that errored fails, never vanishes
    assert "| ssh-relay |" in table and "| pass |" in table
    assert "| –, – | pass |" in table  # no import time or calibration recorded: said, not zero


def test_the_gate_table_shows_the_split_and_this_computers_speed(tmp_path: Path) -> None:
    style: dict[str, Any] = {
        **_style(600, 1002, 1500),
        "warm_connect_status": {"p50": 550, "p95": 600, "failures": 0},
        "warm_parts": {
            "connect": {"p50": 320.4},
            "status": {"p50": 229.6},
            "import": {"p50": 841.0},
        },
        "warm_process": {"p95": 1500, "failures": 0},
        "hook_cold_connect": {
            "n": 1,
            "p50": 1001,
            "p95": 1002,
            "served_within_budget": 1,
            "failed_open_phases": [],
            "next_call_served": 1,
            "failures": 0,
        },
        "cold_connect": {"p50": 2500},
        "server_test": {"round_trip_p95_ms": 120, "new_connection_slowest_ms": 702, "warned": True},
        "cpu_calibration_ms": 78.3,
    }
    style["gate"] = wan_gate.gate(style)
    path = tmp_path / "wan.json"
    path.write_text(
        json.dumps(
            {"rtt_ms": 100, "mode": "netns", "commit": "abc1234-dirty", "styles": {"x": style}}
        )
    )
    table = wan_gate.render([path])
    assert "| 100 ms | netns | abc1234-dirty | x | 550 / 600 | 320 / 230 | 1500 |" in table
    assert "| 841, 78 | pass |" in table
    assert "| 120; new 702 (warned) |" in table


def test_the_new_connection_line_server_test_prints_is_read() -> None:
    line = "New connection and status: 702 ms at the slowest of 5 new processes (the required"
    found = wan_gate.NEW_CONNECTION_LINE.search("Round trip p95: 120 ms\n" + line)
    assert found is not None and found.group(1, 2) == ("702", "5")


def test_the_calibration_is_a_number_of_milliseconds() -> None:
    measured = wan_gate.calibration()
    assert isinstance(measured, float) and measured > 0


def test_a_modified_tree_names_its_commit_dirty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def git(*arguments: str) -> None:
        subprocess.run(["git", "-C", str(tmp_path), *arguments], check=True, capture_output=True)

    git("init", "-q")
    (tmp_path / "a").write_text("a\n")
    git("add", "a")
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "a")
    monkeypatch.setattr(wan_gate, "REPO", tmp_path)
    clean = wan_gate.revision()
    assert clean and not clean.endswith("-dirty")
    (tmp_path / "untracked").write_text("x\n")
    assert wan_gate.revision() == clean  # an untracked file is not a change to the code
    (tmp_path / "a").write_text("b\n")
    assert wan_gate.revision() == clean + "-dirty"


def _echo_server() -> tuple[socket.socket, int]:
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    return server, int(server.getsockname()[1])


def _echo_once(server: socket.socket) -> None:
    connection, _ = server.accept()
    with connection:
        connection.sendall(connection.recv(64))


def test_the_relay_counts_each_dial_and_carries_bytes_both_ways() -> None:
    import threading

    server, port = _echo_server()
    relay = harness.Relay(port)
    try:
        for expected in (1, 2):
            thread = threading.Thread(target=_echo_once, args=(server,))
            thread.start()
            with socket.create_connection(("127.0.0.1", relay.port), timeout=5) as client:
                client.sendall(b"ping")
                assert client.recv(64) == b"ping"
            thread.join(5)
            assert relay.connections == expected
            # Bytes each way (traffic over an open connection, which a dial count misses).
            assert (relay.bytes_up, relay.bytes_down) == (4 * expected, 4 * expected)
    finally:
        relay.stop()
        server.close()


def test_the_relay_holds_every_chunk_for_its_delay_in_each_direction() -> None:
    import threading

    server, port = _echo_server()
    relay = harness.Relay(port, delay=0.1)
    try:
        thread = threading.Thread(target=_echo_once, args=(server,))
        thread.start()
        with socket.create_connection(("127.0.0.1", relay.port), timeout=5) as client:
            began = time.monotonic()
            client.sendall(b"ping")
            assert client.recv(64) == b"ping"
            elapsed = time.monotonic() - began
        thread.join(5)
        assert elapsed >= 0.2  # one delay on the way there, one on the way back
    finally:
        relay.stop()
        server.close()


def test_the_private_sshd_runs_no_user_rc_and_gives_sessions_a_private_home(tmp_path: Path) -> None:
    """Harness finding 1: the account's ``~/.ssh/rc`` and shell startup files never run before a
    server command, and nothing a session does lands in the account's default folders."""

    session = tmp_path / "session-home"
    lines = harness.sshd_config(tmp_path, 2222, session).splitlines()
    assert "PermitUserRC no" in lines and "PermitUserEnvironment no" in lines
    (setenv,) = [line for line in lines if line.startswith("SetEnv ")]
    assignments = dict(item.split("=", 1) for item in setenv.split()[1:])
    assert assignments["HOME"] == str(session)
    assert {assignments[f"XDG_{name}_HOME"] for name in ("STATE", "CONFIG", "DATA", "CACHE")} == {
        str(session / leaf) for leaf in ("s", "c", "d", "k")
    }
    assert "ListenAddress 127.0.0.1" in lines and "PasswordAuthentication no" in lines


@pytest.mark.parametrize(
    ("timing", "problem", "served"),
    [
        ({"ok": True, "total_ms": 900.0}, None, True),
        (
            {"error": "ControlError:service_unavailable:remote_unreachable", "total_ms": 1010.0},
            None,
            False,
        ),
        ({"error": "RuntimeError::", "total_ms": 40.0}, "failed_as:RuntimeError::", False),
        (
            {"error": "ControlError:service_unavailable:server_profile_changed", "total_ms": 300.0},
            "failed_as:ControlError:service_unavailable:server_profile_changed",
            False,
        ),
        ({"error": "a probe that crashed and printed no timing"}, "not_measured", False),
        ({"ok": True}, "not_measured", False),
        ({"ok": True, "total_ms": 0}, "not_measured", False),
        ({"ok": False, "total_ms": 500.0}, "call_not_ok", False),
        ({"ok": True, "total_ms": 500.0, "close_error": "OSError"}, "close_failed:OSError", True),
    ],
)
def test_a_cold_hook_sample_counts_only_when_measured_and_served_or_failing_open_as_an_outage(
    timing: dict[str, Any], problem: str | None, served: bool
) -> None:
    """Harness finding 2: a crashed or timed-out probe is never 0 ms, and only an outage phase
    is a fail-open."""

    judged = wan_gate.judge_hook_sample(timing)
    assert (judged["problem"], judged["served"]) == (problem, served)
    if problem == "not_measured":
        assert judged["total_ms"] is None


def test_the_hook_gate_fails_on_any_sample_that_does_not_count_or_an_unserved_next_call() -> None:
    good = [wan_gate.judge_hook_sample({"ok": True, "total_ms": 800.0}) for _ in range(3)]
    passing = {
        "warm_connect_status": {"p95": 500, "failures": 0},
        "warm_process": {"p95": 1500, "failures": 0},
        "hook_cold_connect": wan_gate.hook_summary(good, recovered=3),
    }
    assert wan_gate.gate(passing)["pass"] is True
    unserved = {**passing, "hook_cold_connect": wan_gate.hook_summary(good, recovered=2)}
    assert wan_gate.gate(unserved)["pass"] is False
    crashed = [*good[:2], wan_gate.judge_hook_sample({"error": "no timing"})]
    summary = wan_gate.hook_summary(crashed, recovered=3)
    # The crashed sample is not a 0 ms sample pulling the percentile down: it is a failure.
    assert summary["n"] == 3 and summary["p50"] == 800.0 and summary["failures"] == 1
    assert summary["problems"] == ["not_measured"]
    assert wan_gate.gate({**passing, "hook_cold_connect": summary})["pass"] is False


def test_the_complete_cold_operation_is_what_the_hook_gate_times() -> None:
    """Harness finding 8: the probe times connect, call and close (``total_ms``), not the connect
    alone."""

    assert '"total_ms"' in wan_gate.PROBE and "await client.close()" in wan_gate.PROBE
    assert wan_gate.PROBE.index("await client.close()") < wan_gate.PROBE.index('"total_ms"')
    slow_close = wan_gate.judge_hook_sample({"ok": True, "connect_ms": 200.0, "total_ms": 2400.0})
    assert slow_close["total_ms"] == 2400.0
    summary = wan_gate.hook_summary([slow_close], recovered=1)
    assert summary["served_within_budget"] == 0
    style = {
        "warm_connect_status": {"p95": 500, "failures": 0},
        "warm_process": {"p95": 1500, "failures": 0},
        "hook_cold_connect": summary,
    }
    assert wan_gate.gate(style)["checks"]["hook_cold_connect"]["pass"] is False


class _FakeClient:
    """``Client`` for the WAN gate's checks before sampling: each ``fu`` answers from a script."""

    def __init__(self, answers: dict[tuple[str, ...], tuple[int, str]]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, ...]] = []

    def ceremony(self, _arguments: list[str], _replies: list[Any]) -> Any:
        return type("Ceremony", (), {"exit_code": 0, "transcript": ""})()

    def fu(self, *arguments: str, timeout: float = 180) -> subprocess.CompletedProcess[str]:
        del timeout
        self.calls.append(arguments)
        code, out = self.answers.get(arguments[:2], (0, "{}"))
        return subprocess.CompletedProcess(["finishup", *arguments], code, out, "")


def _style_document(style: str) -> str:
    return json.dumps({"target": {"connection": {"style": style}}})


@pytest.mark.parametrize(
    ("set_code", "reported", "error"),
    [(1, "relay", "style_not_set"), (0, "relay", "style_not_effective"), (0, None, None)],
)
def test_a_style_is_sampled_only_once_it_was_set_and_is_the_effective_one(
    monkeypatch: pytest.MonkeyPatch, set_code: int, reported: str | None, error: str | None
) -> None:
    """Harness finding 9: a failed ``server set --style direct`` (the target still relay) never
    yields numbers reported as direct."""

    status = _style_document(reported or "direct")
    client = _FakeClient({("server", "set"): (set_code, ""), ("server", "status"): (0, status)})
    run = harness.Run("style-check")
    try:
        world = type("World", (), {"client": client, "run": run})()

        def no_address(_world: object, _cell: object) -> list[str]:
            return []

        monkeypatch.setattr(wan_gate, "address_of", no_address)

        def started(_world: object, _title: str) -> tuple[Any, Any]:
            return harness.Task(None, None, None), subprocess.CompletedProcess([], 1, "", "")

        monkeypatch.setattr(wan_gate, "start_task", started)
        cell = wan_gate.STYLES[1]
        assert cell.style == "direct"
        result = wan_gate.measure_style(world, cell, 1)
    finally:
        run.close()
    # With the style effective, sampling begins (here the task start is what fails).
    assert result["error"] == (error or "start_failed")
    assert matrix.effective_style(client, cell.target) == (reported or "direct")


def test_cleanup_keeps_the_folder_while_a_lock_beneath_it_is_held(tmp_path: Path) -> None:
    """Harness finding 3: a finalizer that fails is reported, and the folder is removed only once
    no lock beneath it is held (a service, helper or retained runtime of the run alive)."""

    import fcntl
    import os

    run = harness.Run("cleanup-check")
    lock = run.folder("srv") / "state"
    lock.mkdir(mode=0o700)
    held = lock / "service.lock"
    descriptor = os.open(held, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX)

    def stop_service() -> bool:
        return False

    def disconnect_all() -> None:
        raise RuntimeError(f"failed under {harness.real_home()}")

    run.finalizers += [stop_service, disconnect_all]
    try:
        problems = run.close(seconds=0.2)
        assert run.base.exists()
        assert "stop_service: did not stop" in problems
        assert any(
            p.startswith("disconnect_all: RuntimeError: failed under <home>") for p in problems
        )
        assert "lock still held: <base>/srv/state/service.lock" in problems
        assert harness.held_locks(run.base) == [held]
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
    run.finalizers.clear()
    assert run.close(seconds=0.2) == []
    assert not run.base.exists()


def test_a_service_that_holds_its_lock_is_running_whatever_its_status_answers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Harness finding 3: an incompatible or unresponsive service (``service status`` fails) that
    still holds its singleton lock is not stopped."""

    import fcntl
    import os

    run = harness.Run("service-check")
    try:
        server = harness.Server(run, "srv", Path("/nonexistent/finishup"), code_copy=False)
        (server.root / "state").mkdir(mode=0o700)

        def incompatible(*_arguments: str, **_options: object) -> Any:
            return subprocess.CompletedProcess([], 1, "", "service_incompatible")

        monkeypatch.setattr(server, "srv", incompatible)
        assert server.service_running() is False
        descriptor = os.open(server.singleton_lock(), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            os.write(descriptor, json.dumps({"pid": os.getpid()}).encode())
            assert server.service_running() is True
            assert server.service_pid() == os.getpid()
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        assert server.service_running() is False and server.service_pid() is None
    finally:
        run.close(seconds=0.2)


def test_a_run_past_its_bound_is_asked_to_stop_and_cleans_up_through_its_finally(
    tmp_path: Path,
) -> None:
    """Harness finding 4: the outer runner's timeout ends the harness through its own cleanup
    (``SIGTERM``), so the processes it started stop and its folder goes; never a bare kill."""

    import os

    script = tmp_path / "fake_run.py"
    script.write_text(
        "import json, signal, sys\n"
        f"sys.path.insert(0, {str(_SCRIPTS)!r})\n"
        "import harness\n"
        "harness.graceful_termination()\n"
        "run = harness.Run('fake')\n"
        "child = run.spawn([sys.executable, '-c', 'import signal; signal.pause()'], env={})\n"
        "print(json.dumps({'base': str(run.base), 'child': child.pid}), flush=True)\n"
        "try:\n"
        "    signal.pause()\n"
        "finally:\n"
        "    run.close(seconds=5)\n"
    )
    result, actions = harness.run_bounded(
        [sys.executable, str(script)], env=dict(os.environ), seconds=5.0, cleanup_seconds=60.0
    )
    assert (result.returncode, actions) == (124, ["asked_to_stop"])
    started = json.loads(result.stdout.splitlines()[0])
    assert not Path(started["base"]).exists()
    with pytest.raises(ProcessLookupError):
        os.kill(started["child"], 0)


def test_one_redaction_comes_before_anything_is_cut_short_or_stored(tmp_path: Path) -> None:
    """Harness finding 10: provisioning output and exception text name no home folder."""

    home = str(harness.real_home())
    text = f"error: cannot build {home}/.yz-l7i/new/src: {home}/secret-key"
    cut = harness.tail(harness.redact(text, tmp_path, secrets=["secret-key"]), 30)
    assert home not in cut and "<home>" in cut and "secret-key" not in cut
    report = harness.Report("redaction")
    report.add("provision", False, text, transcript=f"in {home}")
    stored = report.to_json()["steps"][0]
    assert home not in stored["detail"] and home not in stored["transcript"]
    run = harness.Run("redaction")
    try:
        assert run.redact(f"{run.base}/x {home}/y") == "<base>/x <home>/y"
    finally:
        run.close(seconds=0.2)


def test_traffic_counts_every_kind_that_moved() -> None:
    assert matrix.sent_between(
        {"dials": 3, "server_channels": 7}, {"dials": 3, "server_channels": 7}
    ) == {
        "dials": 0,
        "server_channels": 0,
    }
    moved = matrix.sent_between(
        {"dials": 3, "bytes_toward_server": 10}, {"dials": 3, "bytes_toward_server": 12}
    )
    assert moved == {"bytes_toward_server": 2, "dials": 0} and any(moved.values())


def test_a_helper_counts_as_replaced_only_by_a_live_helper_of_the_newer_build() -> None:
    """Harness finding 6: a failed replacement (no helper, the old one, another build) fails."""

    new = "sha256:" + "b" * 64
    old = {"pid": 10, "digest": ("sha256:" + "a" * 64)[:19], "alive": True}
    assert upgrade.replaced_by(old, {"pid": 11, "digest": new[:19], "alive": True}, new)
    assert not upgrade.replaced_by(old, {}, new)  # nothing holds it now
    assert not upgrade.replaced_by(old, {"pid": None, "alive": False}, new)
    assert not upgrade.replaced_by(old, {"pid": 11, "digest": new[:19], "alive": False}, new)
    assert not upgrade.replaced_by(old, {**old}, new)
    assert not upgrade.replaced_by(old, {"pid": 11, "digest": old["digest"], "alive": True}, new)


def test_the_older_bridge_refusal_must_be_its_typed_release_mismatch() -> None:
    message = (
        "The running local FinishUP service belongs to a different FinishUP installation than "
        "this bridge (control schema-manifest or protocol mismatch)"
    )
    typed = {
        "ok": False,
        "body": {"error": {"code": "SERVICE_UNAVAILABLE", "message": message}},
        "error": None,
    }
    assert upgrade.older_bridge_refused(typed, alive=True)
    assert not upgrade.older_bridge_refused(typed, alive=False)  # it crashed after answering
    crashed = {"ok": False, "body": {}, "error": {"message": "bridge_exited"}}
    assert not upgrade.older_bridge_refused(crashed, alive=False)
    other = {"ok": False, "body": {"error": {"code": "VAULT_LOCKED", "message": "locked"}}}
    assert not upgrade.older_bridge_refused(other, alive=True)
    assert not upgrade.older_bridge_refused({"ok": True, "body": {}}, alive=True)


def test_a_replayed_write_is_recorded_once_only_with_one_event_and_an_unmoved_head() -> None:
    """Harness finding 7: equal responses alone do not prove one durable event."""

    assert upgrade.recorded_once(3, 4, 4, 1)
    # The bridge's reduced envelope lists no accepted events: the ledger head is the proof.
    assert upgrade.recorded_once(3, 4, 4, None)
    assert not upgrade.recorded_once(3, 4, 5, 1)  # the replay recorded again
    assert not upgrade.recorded_once(3, 4, 5, None)
    assert not upgrade.recorded_once(3, 3, 3, 1)  # nothing durable
    assert not upgrade.recorded_once(3, 5, 5, 2)
    assert not upgrade.recorded_once(3, 4, 4, 0)  # a listed answer with no event
    assert not upgrade.recorded_once(None, 4, 4, 1)
