"""The unified helper of an SSH server, in process (design v2 section 3; ADR-052 FR-1/2/3, O8).

A scripted service stands behind a stand-in upstream (each upstream stream is one in-memory pair
served by ``ScriptedDaemon``), so the relay, the admission, the background agents, the drain, the
profile refresh and the idle exit are exercised without OpenSSH; the real OpenSSH runs in
``tests/capability/test_openssh_helper.py``. The helper's tick is stepped by the test
(``Helper.step``) and its clock injected: nothing here waits on time.
"""

from __future__ import annotations

import asyncio
import shutil
import socket
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from builders.control_relay import (
    ScriptedDaemon,
    call_request,
    hello_frame,
    memory_pair,
    run_scripted_session,
)
from builders.server_profiles import TEST_REVISION
from builders.server_targets import ambient_home, open_remote_kinds
from finishup.adapters.control.unix_socket import AuthenticatedUnixStream, authenticate_peer
from finishup.client import targets
from finishup.client.authorization import authorize_target, bump_credential_generation
from finishup.client.helper import Helper, HelperAgent
from finishup.client.helper_status import read_helper_status, request_profile_refresh
from finishup.client.targets import ServerTarget
from finishup.ports.control import ControlMethod
from finishup.service.control_protocol import encode_control_frame


class FakeUpstream:
    """Each stream is one in-memory pair served by ``daemon`` (or refused while not running)."""

    def __init__(self, daemon: ScriptedDaemon) -> None:
        self.daemon = daemon
        self.opened = 0
        self.started = 0
        self.not_running = False
        self.closed = False
        self.zero = False

    async def ensure(self) -> None:
        return None

    async def open_stream(self):  # noqa: ANN201
        self.opened += 1
        client_end, server_end = memory_pair()
        if self.not_running:
            # sshd could not reach the server's endpoint: the channel closes unanswered.
            await server_end.aclose()
        else:
            self.daemon.serving.append(asyncio.create_task(self.daemon.serve(server_end)))
        return client_end

    async def start_remote_service(self) -> bool:
        self.started += 1
        self.not_running = False
        return True

    async def close(self) -> None:
        self.closed = True

    async def zero_network(self) -> None:
        self.zero = True


class Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def ssh_target(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[ServerTarget, Path]]:
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
        assert record is not None and record.consent is not None
        yield record, root


def _pair() -> tuple[AuthenticatedUnixStream, AuthenticatedUnixStream]:
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    return (
        AuthenticatedUnixStream(left, authenticate_peer(left)),
        AuthenticatedUnixStream(right, authenticate_peer(right)),
    )


async def _no_refresh(_record: ServerTarget) -> None:
    return None


async def _no_sync() -> None:
    """Keep the agents a test placed (no registration is read)."""


def _helper(record: ServerTarget, root: Path, upstream: FakeUpstream, **options: object) -> Helper:
    arguments: dict[str, object] = {"upstream": upstream, "refresher": _no_refresh}
    arguments.update(options)
    return Helper(root, record, **arguments)  # type: ignore[arg-type]


def test_a_relayed_session_reaches_the_server_byte_for_byte(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    record, root = ssh_target

    async def reference() -> list[bytes]:
        daemon = ScriptedDaemon()
        client, server = memory_pair()
        served = asyncio.create_task(daemon.serve(server))
        received = await run_scripted_session(client, server_profile=TEST_REVISION)
        await client.aclose()
        await served
        return received

    async def relayed() -> tuple[list[bytes], FakeUpstream]:
        daemon = ScriptedDaemon()
        upstream = FakeUpstream(daemon)
        helper = _helper(record, root, upstream)
        client, local = _pair()
        relay = asyncio.create_task(helper._serve_local(local))  # pyright: ignore[reportPrivateUsage]
        async with asyncio.timeout(10):
            received = await run_scripted_session(client, server_profile=TEST_REVISION)
            await client.shutdown_write()
            await relay
        await client.aclose()
        return received, upstream

    expected = asyncio.run(reference())
    received, upstream = asyncio.run(relayed())
    assert received == expected
    assert upstream.opened == 1 and upstream.started == 0
    status = read_helper_status(root)
    assert status is not None and status.phase == "ready"


@pytest.mark.parametrize("hello", ["locator", "no_profile", "not_a_hello"])
def test_a_hello_that_may_not_leave_this_computer_is_never_forwarded(
    ssh_target: tuple[ServerTarget, Path], hello: str
) -> None:
    record, root = ssh_target
    if hello == "locator":
        import json
        import struct

        from finishup.protocol.canonical import canonical_encode

        document = json.loads(hello_frame(server_profile=TEST_REVISION)[4:])
        document["workspace_locator"] = {"schema_version": "1.0.0", "path": "/home/owner/repo"}
        payload = canonical_encode(document)
        frame = struct.pack(">I", len(payload)) + payload
    elif hello == "no_profile":
        frame = hello_frame()
    else:
        frame = encode_control_frame(call_request(1, ControlMethod.SERVICE_STATUS))

    async def run() -> tuple[bytes, int]:
        upstream = FakeUpstream(ScriptedDaemon())
        helper = _helper(record, root, upstream)
        client, local = _pair()
        relay = asyncio.create_task(helper._serve_local(local))  # pyright: ignore[reportPrivateUsage]
        await client.send_all(frame)
        async with asyncio.timeout(10):
            answered = await client.receive(65_536)
            await relay
        await client.aclose()
        return answered, upstream.opened

    answered, opened = asyncio.run(run())
    assert answered == b"" and opened == 0


@pytest.mark.parametrize("change", ["credential", "consent", "zero_network"])
def test_a_relayed_frame_is_checked_against_the_helpers_admission(
    ssh_target: tuple[ServerTarget, Path], change: str
) -> None:
    """FR-2: the relay checks each client frame; O8: a credential change ends the relay too."""

    record, root = ssh_target

    async def run() -> tuple[ScriptedDaemon, bytes, Helper]:
        daemon = ScriptedDaemon()
        helper = _helper(record, root, FakeUpstream(daemon))
        client, local = _pair()
        relay = asyncio.create_task(helper._serve_local(local))  # pyright: ignore[reportPrivateUsage]
        await client.send_all(hello_frame(server_profile=TEST_REVISION))
        async with asyncio.timeout(10):
            assert await client.receive(65_536)  # the hello result
            if change == "credential":
                bump_credential_generation(root)
            elif change == "consent":
                (root / "config" / "consent-envelope.json").unlink()
            else:
                from finishup.client.everyday_policy import record_reported_policy

                assert record_reported_policy(zero_network=True)
            await client.send_all(
                encode_control_frame(call_request(1, ControlMethod.SERVICE_STATUS))
            )
            rest = await client.receive(65_536)
            await relay
        await client.aclose()
        return daemon, rest, helper

    daemon, rest, helper = asyncio.run(run())
    assert rest == b""
    # The server received the hello alone: the request after the change never left.
    assert len(daemon.received(0)) == 1
    del helper


def test_a_lapse_ends_every_relay_on_the_next_tick(ssh_target: tuple[ServerTarget, Path]) -> None:
    record, root = ssh_target

    async def run() -> tuple[bytes, bool]:
        helper = _helper(record, root, FakeUpstream(ScriptedDaemon()))
        assert helper._admitted() is not None  # pyright: ignore[reportPrivateUsage]
        client, local = _pair()
        helper._spawn_relay(local, own=False)  # pyright: ignore[reportPrivateUsage]
        await client.send_all(hello_frame(server_profile=TEST_REVISION))
        async with asyncio.timeout(10):
            assert await client.receive(65_536)
            bump_credential_generation(root)
            stopping = await helper.step()
            ended = await client.receive(65_536)
        await client.aclose()
        return ended, stopping

    ended, stopping = asyncio.run(run())
    assert ended == b"" and stopping is False


def test_zero_network_stops_the_helper_without_a_last_delivery(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    from finishup.client.everyday_policy import record_reported_policy

    record, root = ssh_target
    delivered: list[str] = []

    class Agent:
        alive = True

        async def drain(self, *, may_send: object) -> None:
            delivered.append("drain")

        async def aclose(self) -> None:
            delivered.append("closed")

    async def run() -> tuple[str, FakeUpstream]:
        upstream = FakeUpstream(ScriptedDaemon())
        helper = _helper(record, root, upstream, tick=asyncio.Event().wait)
        helper._sync_agents = _no_sync  # type: ignore[method-assign]
        helper._agents[("x",)] = Agent()  # type: ignore[assignment]  # pyright: ignore[reportPrivateUsage,reportArgumentType]
        serving = asyncio.create_task(helper.serve(None))
        await asyncio.sleep(0)
        assert record_reported_policy(zero_network=True)
        assert await helper.step() is True
        async with asyncio.timeout(10):
            reason = await serving
        return reason, upstream

    reason, upstream = asyncio.run(run())
    assert reason == "zero_network_remote_selected"
    assert delivered == ["closed"] and upstream.zero and not upstream.closed
    status = read_helper_status(root)
    assert status is not None
    assert (status.phase, status.reason) == ("stopped", "zero_network_remote_selected")


def test_a_delivery_pass_never_holds_up_the_zero_network_stop(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    """A-ZN-DRAIN: a pass still under way is cancelled by the stop, never waited for."""

    from finishup.client.everyday_policy import record_reported_policy

    record, root = ssh_target
    started = asyncio.Event()

    class SlowAgent:
        alive = True

        async def drain(self, *, may_send: object) -> None:
            started.set()
            await asyncio.Event().wait()

        async def aclose(self) -> None:
            return None

    async def run() -> str:
        clock = Clock()
        helper = _helper(
            record, root, FakeUpstream(ScriptedDaemon()), tick=asyncio.Event().wait, clock=clock
        )
        helper._sync_agents = _no_sync  # type: ignore[method-assign]
        helper._agents[("x",)] = SlowAgent()  # type: ignore[assignment]  # pyright: ignore[reportPrivateUsage,reportArgumentType]
        serving = asyncio.create_task(helper.serve(None))
        clock.now += 31
        await helper.step()
        await started.wait()
        assert record_reported_policy(zero_network=True)
        await helper.step()
        async with asyncio.timeout(10):
            return await serving

    assert asyncio.run(run()) == "zero_network_remote_selected"


def test_a_client_connection_starts_a_stopped_service_once_and_an_agents_never_does(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    """A-SVC-RESTART: only a client's own connection is demand for the server's service."""

    record, root = ssh_target

    async def run(own: bool) -> tuple[int, int]:
        upstream = FakeUpstream(ScriptedDaemon())
        upstream.not_running = True
        helper = _helper(record, root, upstream)
        client, local = _pair()
        relay = asyncio.create_task(
            helper._serve_local(local, own=own)  # pyright: ignore[reportPrivateUsage]
        )
        await client.send_all(hello_frame(server_profile=TEST_REVISION))
        async with asyncio.timeout(10):
            answered = await client.receive(65_536)
            await client.shutdown_write()
            await relay
        await client.aclose()
        return upstream.started, len(answered)

    started, answered = asyncio.run(run(own=False))
    assert started == 1 and answered > 0
    started, answered = asyncio.run(run(own=True))
    assert started == 0 and answered == 0
    status = read_helper_status(root)
    assert status is not None and status.reason == "remote_service_not_running"


def test_the_helper_exits_when_idle_but_never_while_a_registration_is_served(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    record, root = ssh_target

    async def run() -> tuple[bool, bool]:
        clock = Clock()
        helper = _helper(record, root, FakeUpstream(ScriptedDaemon()), clock=clock)
        helper._served_count = 1  # pyright: ignore[reportPrivateUsage]

        async def served() -> None:
            helper._last_sync = clock()  # pyright: ignore[reportPrivateUsage]

        helper._sync_agents = served  # type: ignore[method-assign]
        clock.now += 901
        kept = await helper.step()
        helper._served_count = 0  # pyright: ignore[reportPrivateUsage]
        clock.now += 901
        idle = await helper.step()
        return kept, idle

    kept, idle = asyncio.run(run())
    assert kept is False and idle is True


def test_the_profile_is_refreshed_at_start_on_a_request_and_while_used_never_faster(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    record, root = ssh_target
    fetched: list[float] = []

    async def run() -> list[float]:
        clock = Clock()

        async def refresher(_record: ServerTarget) -> None:
            fetched.append(clock())

        helper = _helper(
            record, root, FakeUpstream(ScriptedDaemon()), refresher=refresher, clock=clock
        )

        async def settle() -> None:
            task = helper._refresh.task  # pyright: ignore[reportPrivateUsage]
            if task is not None:
                await task

        await helper.step()  # due at start
        await settle()
        request_profile_refresh(root)
        clock.now += 5
        await helper.step()  # too soon: never faster than every 30 s
        await settle()
        clock.now += 30
        await helper.step()  # the marker a refused client left
        await settle()
        clock.now += 600
        await helper.step()  # not used in the last 10 minutes: no periodic fetch
        await settle()
        helper._last_upstream_use = clock()  # pyright: ignore[reportPrivateUsage]
        clock.now += 300
        await helper.step()  # used in the last 10 minutes, fetched 10 minutes ago: periodic
        await settle()
        return fetched

    assert asyncio.run(run()) == [1_000.0, 1_035.0, 1_935.0]


def test_a_removed_target_stops_the_helper_and_nothing_makes_its_folder_again(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    """A-REMOVE-RACE."""

    record, root = ssh_target

    async def run() -> str:
        helper = _helper(record, root, FakeUpstream(ScriptedDaemon()), tick=asyncio.Event().wait)
        serving = asyncio.create_task(helper.serve(None))
        await asyncio.sleep(0)
        shutil.rmtree(root)
        await helper.step()
        async with asyncio.timeout(10):
            return await serving

    assert asyncio.run(run()) == "target_removed"
    assert not root.exists()


def _git_worktree(base: Path) -> Path:
    worktree = base / "repo"
    worktree.mkdir()
    subprocess.run(("git", "init", "-q", str(worktree)), check=True)  # noqa: S607
    (worktree / "a.txt").write_text("a\n", encoding="utf-8")
    return worktree


def test_a_registration_gets_one_background_agent_until_it_is_no_longer_served(
    ssh_target: tuple[ServerTarget, Path], tmp_path: Path
) -> None:
    """FR-1: the helper's agent declares role background; a dropped registration closes it."""

    import base64
    from typing import cast

    from finishup.client.helper_registrations import new_registrant, register, release
    from finishup.client.remote_binding import remote_workspace_binding
    from finishup.client.repository_hold import SendHold
    from finishup.ports.control import WorkspaceLocator

    record, root = ssh_target
    worktree = _git_worktree(tmp_path)

    async def run() -> tuple[bytes, int, int, int]:
        admission = authorize_target(record)
        salt = base64.b64decode(str(record.claim_salt))
        binding = await remote_workspace_binding(
            WorkspaceLocator(str(worktree)), salt, serve_workspace=False, target=record
        )
        assert binding.worktree is not None
        hold = cast(SendHold, binding.authorization)
        registration = register(
            admission.for_repository(hold.key),
            binding.claim,
            binding.worktree,
            registrant=new_registrant(),
            source="cli",
        )
        daemon = ScriptedDaemon()
        helper = _helper(record, root, FakeUpstream(daemon))
        await helper.step()
        assert len(helper._agents) == 1  # pyright: ignore[reportPrivateUsage]
        agent = next(iter(helper._agents.values()))  # pyright: ignore[reportPrivateUsage]
        assert isinstance(agent, HelperAgent)
        async with asyncio.timeout(10):
            while agent.client is None:
                await asyncio.sleep(0)
        hello = daemon.received(0)[0]
        served = len(helper._agents)  # pyright: ignore[reportPrivateUsage]
        release(registration.target_id, registration.claim, registration.registrant)
        await helper.step()
        remaining = len(helper._agents)  # pyright: ignore[reportPrivateUsage]
        await helper._close_agents()  # pyright: ignore[reportPrivateUsage]
        return hello, daemon.connections, served, remaining

    hello, connections, served, remaining = asyncio.run(run())
    assert b'"role":"background"' in hello
    assert b'"workspace_claim"' in hello and b'"server_profile"' in hello
    assert connections == 1 and served == 1 and remaining == 0
