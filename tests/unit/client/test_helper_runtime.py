"""``server connect|disconnect`` for an SSH target, and the CLI's background registration (ADR-052)."""

from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from builders.control_relay import scripted_service
from builders.server_targets import ambient_home, open_remote_kinds
from finishup.client import helper_status, ssh_transport, targets
from finishup.client.everyday_policy import record_reported_policy
from finishup.client.helper_runtime import SshTargetRuntime, register_for_background
from finishup.client.helper_status import (
    new_status,
    now_stamp,
    write_connection_style,
    write_helper_status,
)
from finishup.client.target_runtime import TargetRuntimeError
from finishup.service import client as service_client


@pytest.fixture
def ssh_target(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[targets.ServerTarget, Path]]:
    with ambient_home(monkeypatch):
        open_remote_kinds(monkeypatch, "ssh")
        with targets.registry_lock():
            _record, root = targets.new_remote_target(
                "lab",
                "ssh",
                user="owner",
                host="lab.example",
                port=22,
                remote_root="/srv/fu",
                remote_launcher="/srv/bin/finishup",
            )
        record = targets.read_target(root)
        assert record is not None
        yield record, root


def test_connect_is_refused_before_anything_while_the_gate_refuses(
    ssh_target: tuple[targets.ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    _record, root = ssh_target

    def nothing(*_args: object) -> object:
        raise AssertionError("nothing is started or dialled")

    monkeypatch.setattr(helper_status, "spawn_helper", nothing)
    monkeypatch.setattr(service_client, "connect_control", nothing)
    assert record_reported_policy(zero_network=True)
    with pytest.raises(TargetRuntimeError) as raised:
        SshTargetRuntime().ensure_ready(root)
    assert (raised.value.reason, raised.value.phase) == (
        "service_unavailable",
        "zero_network_remote_selected",
    )


def test_connect_checks_again_whatever_the_helper_last_recorded(
    ssh_target: tuple[targets.ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A-CONNECT-STALE: an outage recorded earlier, since repaired, is never repeated."""

    _record, root = ssh_target
    write_helper_status(
        root, new_status(None, "unavailable", "remote_unreachable", started_at=now_stamp())
    )
    connections: list[int] = []

    def serve() -> None:
        connections.append(1)

    async def dial():  # noqa: ANN202
        serve()
        return await real()

    holder: dict[str, object] = {}

    async def real():  # noqa: ANN202
        daemon = holder["daemon"]
        from builders.control_relay import ScriptedDaemon, memory_pair

        assert isinstance(daemon, ScriptedDaemon)
        client_end, server_end = memory_pair()
        daemon.serving.append(asyncio.create_task(daemon.serve(server_end)))
        return client_end

    from builders.control_relay import ScriptedDaemon

    holder["daemon"] = ScriptedDaemon()
    monkeypatch.setattr(service_client, "connect_control", dial)
    SshTargetRuntime().ensure_ready(root)
    assert connections == [1]


_HOLDER = """
import signal, sys, time
from pathlib import Path
sys.path.insert(0, {src!r})
from finishup.client.helper_status import HelperLock
lock = HelperLock(Path({root!r}))
lock.acquire(version="0.0.1", schema_manifest_digest="sha256:" + "0" * 64)
if {ignore!r}:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
print("held", flush=True)
signal.pause()
"""


def _holder(root: Path, *, ignore: bool) -> subprocess.Popen[str]:
    source = _HOLDER.format(
        src=str(Path(__file__).parents[3] / "src"), root=str(root), ignore=ignore
    )
    process = subprocess.Popen(  # noqa: S603 - this interpreter and fixed source
        (sys.executable, "-c", source), stdout=subprocess.PIPE, text=True
    )
    assert process.stdout is not None
    assert process.stdout.readline().strip() == "held"
    return process


def test_disconnect_stops_the_stamped_helper_and_exits_the_master(
    ssh_target: tuple[targets.ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    _record, root = ssh_target
    exited: list[Path] = []

    def exit_master(_ssh: str, where: Path, _record: object) -> None:
        exited.append(where)

    monkeypatch.setattr(ssh_transport, "resolve_ssh", lambda: "/usr/bin/ssh")
    monkeypatch.setattr(ssh_transport, "exit_master_now", exit_master)
    process = _holder(root, ignore=False)
    try:
        SshTargetRuntime().stop(root)
        assert process.wait(timeout=10) == -signal.SIGTERM
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    assert exited == [root]


def test_a_helper_that_does_not_stop_keeps_the_target_connected(
    ssh_target: tuple[targets.ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    _record, root = ssh_target
    monkeypatch.setattr(helper_status, "_STOP_POLL_SECONDS", 0.01)
    process = _holder(root, ignore=True)
    try:
        with pytest.raises(TargetRuntimeError) as raised:
            SshTargetRuntime().stop(root)
        assert raised.value.reason == "target_still_connected"
    finally:
        # Stopped by the pid this test started, never by a pattern.
        os.kill(process.pid, signal.SIGKILL)
        process.wait()


@pytest.mark.parametrize("style", ["relay", "direct"])
def test_a_cli_connection_registers_its_workspace_once_and_starts_a_helper_only_for_direct(
    ssh_target: tuple[targets.ServerTarget, Path],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    style: str,
) -> None:
    from finishup.client.helper_registrations import registrations_dir
    from finishup.config.paths import reset_selection_memo
    from finishup.ports.control import ControlClientKind, WorkspaceLocator
    from finishup.service.client import connect_service

    record, root = ssh_target
    if style == "direct":
        write_connection_style(root, "direct")
        from builders.control_relay import ScriptedDaemon, memory_pair

        daemon = ScriptedDaemon()

        async def open_stream(_argv: tuple[str, ...]):  # noqa: ANN202
            client_end, server_end = memory_pair()
            daemon.serving.append(asyncio.create_task(daemon.serve(server_end)))
            return client_end

        monkeypatch.setattr(ssh_transport, "resolve_ssh", lambda: "/usr/bin/ssh")
        monkeypatch.setattr(ssh_transport.SshControlStream, "open", staticmethod(open_stream))
    with targets.registry_lock():
        targets.write_selection(record)
    reset_selection_memo()
    spawned: list[str] = []
    monkeypatch.setattr(helper_status, "spawn_helper", lambda _root, target: spawned.append(target))
    worktree = tmp_path / "repo"
    worktree.mkdir()
    subprocess.run(("git", "init", "-q", str(worktree)), check=True)  # noqa: S607

    async def run() -> bool:
        if style == "relay":
            scripted_service(monkeypatch)
        client = await connect_service(
            ControlClientKind.CLI, workspace_locator=WorkspaceLocator(str(worktree))
        )
        try:
            return await asyncio.to_thread(register_for_background, client, "cli")
        finally:
            await client.close()

    assert asyncio.run(run()) is True
    records = list(registrations_dir(record.target_id).glob("*.json"))
    assert len(records) == 1 and b'"source":"cli"' in records[0].read_bytes()
    assert spawned == ([record.target_id] if style == "direct" else [])
