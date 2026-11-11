"""The acceptance harness's own logic (``scripts/acceptance/``), without any server.

The real runs (the matrix, the WAN gate, the upgrade) start services; these cases pin what decides
their verdicts: the cells are exactly the design's section 1.2 matrix, a cell fails when any step
failed, the WAN gate's percentile and budgets, its table, and the relay that counts dials and
injects the userspace delay.
"""

from __future__ import annotations

import importlib.util
import json
import socket
import subprocess
import sys
import time
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
