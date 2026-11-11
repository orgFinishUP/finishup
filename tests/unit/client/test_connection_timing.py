"""``server test``'s new-process timing: what a new process times and how its answer is read.

Design v2 section 8.9: the required startup gate times a new process's connection and a task's
status; ``server test`` compares the same window with the gate's bound, in new processes, so
neither the schema parsing of a first handshake nor a relayed connection's new channel is missed.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from builders.server_targets import ambient_home
from finishup.client import connection_timing, target_runtime, targets
from finishup.client.target_runtime import TargetRuntimeError, time_new_connections
from finishup.ports.control import ControlError


class _Client:
    def __init__(self, calls: list[str]) -> None:
        self._calls = calls

    async def service_status(self) -> object:
        self._calls.append("service_status")
        return object()

    async def close(self) -> None:
        self._calls.append("close")


def _connect(calls: list[str], *, error: Exception | None = None) -> Any:
    async def connect(_kind: object, *, workspace_locator: object = None) -> _Client:
        calls.append(f"connect:{workspace_locator}")
        if error is not None:
            raise error
        return _Client(calls)

    return connect


def test_a_new_process_times_one_connection_and_one_status_naming_no_workspace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr("finishup.service.client.connect_service", _connect(calls))
    answer = connection_timing.measure("local")
    assert set(answer) == {"ms"}
    assert isinstance(answer["ms"], int) and answer["ms"] >= 0
    assert calls == ["connect:None", "service_status", "close"]


def test_a_refused_connection_names_only_its_closed_reason_and_phase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    refusal = ControlError("service_unavailable", retryable=True, phase="repository_egress_held")
    monkeypatch.setattr("finishup.service.client.connect_service", _connect(calls, error=refusal))
    assert connection_timing.measure("local") == {
        "error": "service_unavailable",
        "phase": "repository_egress_held",
    }


@pytest.mark.parametrize("target", ["", "lab", "t_0000000g", "../t_01234567", "t_01234567"])
def test_a_target_that_is_not_a_recorded_target_is_never_connected_to(
    monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    calls: list[str] = []
    monkeypatch.setattr("finishup.service.client.connect_service", _connect(calls))
    with ambient_home(monkeypatch):
        assert connection_timing.measure(target) == {"error": "target_unknown", "phase": None}
    assert calls == []


def test_a_recorded_target_is_measured_as_its_own_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.config.paths import active_root

    seen: list[Path | None] = []

    async def connect(_kind: object, *, workspace_locator: object = None) -> _Client:
        del workspace_locator
        seen.append(active_root())
        return _Client([])

    monkeypatch.setattr("finishup.service.client.connect_service", connect)
    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, root = targets.new_remote_target(
                "lab", "ssh", host="lab.example", port=22, remote_launcher="/opt/fu/bin/finishup"
            )
        assert "ms" in connection_timing.measure(record.target_id)
        assert "ms" in connection_timing.measure("own")
    assert seen == [root, None]  # ``own``: the selection this process inherits (none here)


def test_the_runtime_names_a_root_by_its_target_or_by_what_its_process_selects(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, root = targets.new_remote_target(
                "lab", "ssh", host="lab.example", port=22, remote_launcher="/opt/fu/bin/finishup"
            )
        assert target_runtime._timing_target(None) == "local"
        assert target_runtime._timing_target(root) == record.target_id
        assert target_runtime._timing_target(tmp_path) == "own"


def _answers(monkeypatch: pytest.MonkeyPatch, *stdout: bytes) -> list[list[str]]:
    argvs: list[list[str]] = []
    pending = list(stdout)

    def run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        argvs.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout=pending.pop(0), stderr=b"")

    monkeypatch.setattr(subprocess, "run", run)
    return argvs


def test_each_new_process_is_timed_one_after_another(monkeypatch: pytest.MonkeyPatch) -> None:
    argvs = _answers(monkeypatch, b'{"ms": 410}\n', b'noise\n{"ms": 433}\n', b'{"ms": 0}\n')
    assert time_new_connections(None, 3) == (410, 433, 0)
    assert [argv[-2:] for argv in argvs] == [["finishup.client.connection_timing", "local"]] * 3


@pytest.mark.parametrize(
    ("stdout", "reason", "phase"),
    [
        (
            b'{"error": "service_unavailable", "phase": "remote_unreachable"}',
            "service_unavailable",
            "remote_unreachable",
        ),
        (b'{"error": "target_unknown", "phase": null}', "target_unknown", None),
        (b'{"error": "Not A Token /srv/x", "phase": null}', "service_unavailable", None),
        (b'{"error": "service_unavailable", "phase": "/a/path"}', "service_unavailable", None),
        (b'{"ms": -1}', "service_unavailable", None),
        (b'{"ms": "12"}', "service_unavailable", None),
        (b"Traceback (most recent call last):", "service_unavailable", None),
        (b"", "service_unavailable", None),
    ],
)
def test_a_new_process_that_did_not_time_one_names_only_a_closed_reason(
    monkeypatch: pytest.MonkeyPatch, stdout: bytes, reason: str, phase: str | None
) -> None:
    _answers(monkeypatch, b'{"ms": 300}', stdout, b'{"ms": 300}')
    with pytest.raises(TargetRuntimeError) as raised:
        time_new_connections(None, 3)
    assert (raised.value.reason, raised.value.phase) == (reason, phase)


def test_a_new_process_past_its_bound_is_a_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.TimeoutExpired(argv, float(kwargs["timeout"]))  # type: ignore[arg-type]

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(TargetRuntimeError) as raised:
        time_new_connections(None, 2)
    assert (raised.value.reason, raised.value.phase) == ("service_unavailable", "timeout")


def test_a_real_new_process_reports_a_server_that_does_not_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End to end: the interpreter, the module and its one JSON line, against an everyday server
    of a fresh home that runs no service (``connect_service`` never starts one)."""

    with ambient_home(monkeypatch):
        done = subprocess.run(
            [
                __import__("sys").executable,
                "-m",
                "finishup.client.connection_timing",
                "local",
            ],
            capture_output=True,
            timeout=60,
            check=False,
        )
        assert done.returncode == 0, done.stderr[-2000:]
        answer = json.loads(done.stdout.decode().strip().splitlines()[-1])
        assert answer["error"] == "service_unavailable", answer
        with pytest.raises(TargetRuntimeError) as raised:
            time_new_connections(None, 1)
    assert raised.value.reason == "service_unavailable"
