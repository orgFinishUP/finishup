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
from types import SimpleNamespace
from typing import cast

import pytest

from builders.control_relay import (
    RELAY_KEY,
    MemoryStream,
    ScriptedDaemon,
    call_request,
    hello_frame,
    memory_pair,
    relay_binding_frame,
    run_scripted_session,
)
from builders.server_profiles import TEST_REVISION
from builders.server_targets import ambient_home, open_remote_kinds
from finishup.adapters.control.unix_socket import AuthenticatedUnixStream, authenticate_peer
from finishup.client import targets
from finishup.client.authorization import authorize_target, bump_credential_generation
from finishup.client.helper import Helper, HelperAgent
from finishup.client.helper_status import (
    HelperStatus,
    read_helper_status,
    request_profile_refresh,
)
from finishup.client.targets import ServerTarget
from finishup.ports.control import ControlError, ControlMethod
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


def test_a_relayed_frame_is_never_forwarded_once_the_relays_repository_is_held(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    """B3: every frame a relay forwards is checked against the repository its client named, by
    that repository's key: once it is held (whatever worktrees the record lists) the relay ends
    before the frame leaves; the helper's admission is untouched."""

    from finishup.client.everyday_policy import record_repository_report

    record, root = ssh_target

    async def relayed() -> tuple[ScriptedDaemon, bytes, bool]:
        daemon = ScriptedDaemon()
        upstream = FakeUpstream(daemon)
        helper = _helper(record, root, upstream)
        client, local = _pair()
        relay = asyncio.create_task(helper._serve_local(local))  # pyright: ignore[reportPrivateUsage]
        try:
            async with asyncio.timeout(10):
                await client.send_all(relay_binding_frame())
                await client.send_all(hello_frame(agent=True, server_profile=TEST_REVISION))
                assert await client.receive(65_536)  # the hello-result
                assert record_repository_report(RELAY_KEY, "/work/elsewhere", no_network=True)
                await client.send_all(encode_control_frame(call_request(1, ControlMethod.START)))
                await relay
                ended = await client.receive(65_536)
            return daemon, ended, helper._admitted() is not None  # pyright: ignore[reportPrivateUsage]
        finally:
            await client.aclose()

    daemon, ended, admitted = asyncio.run(relayed())
    assert ended == b""
    assert len(daemon.received(0)) == 1  # the hello only: the call never left
    assert admitted


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
            received = await run_scripted_session(client, server_profile=TEST_REVISION, relay=True)
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
        document["workspace_locator"] = {"schema_version": "1.0.0", "path": "/srv/work/repo"}
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
        client = None

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
        client = None

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


class _ChangingUpstream(FakeUpstream):
    """An upstream whose dial awaits while the owner acts.

    ``change`` runs inside the await: with ``during="open"`` before the stream is handed back (the
    moment a real master start or channel open takes); with ``during="answer"`` while the
    helper waits for the server's first answer, which here never comes (the server's endpoint
    refused the channel: its service is not running).
    """

    def __init__(self, daemon: ScriptedDaemon, change: object, *, during: str) -> None:
        super().__init__(daemon)
        self.change = change
        self.during = during

    async def open_stream(self):  # noqa: ANN201  # pyright: ignore[reportIncompatibleMethodOverride]
        stream = await super().open_stream()
        if self.during == "open":
            self.change()  # type: ignore[operator]
            return stream
        change = self.change

        class Answering:
            async def send_all(self, data: bytes) -> None:
                await stream.send_all(data)

            async def receive(self, max_bytes: int = 65_536) -> bytes:
                answered = await stream.receive(max_bytes)
                change()  # type: ignore[operator]
                return answered

            async def aclose(self) -> None:
                await stream.aclose()

        return Answering()


def _act(root: Path, change: str) -> None:
    if change == "credential":
        bump_credential_generation(root)
    elif change == "consent":
        (root / "config" / "consent-envelope.json").unlink()
    elif change == "zero_network":
        from finishup.client.everyday_policy import record_reported_policy

        assert record_reported_policy(zero_network=True)


@pytest.mark.parametrize("change", ["credential", "consent", "zero_network"])
def test_an_authorization_change_while_the_upstream_opens_sends_no_hello(
    ssh_target: tuple[ServerTarget, Path], change: str
) -> None:
    """A1: the captured admission is asked again right before the hello leaves."""

    record, root = ssh_target

    async def run() -> tuple[ScriptedDaemon, bytes]:
        daemon = ScriptedDaemon()
        upstream = _ChangingUpstream(daemon, lambda: _act(root, change), during="open")
        helper = _helper(record, root, upstream)
        client, local = _pair()
        relay = asyncio.create_task(helper._serve_local(local))  # pyright: ignore[reportPrivateUsage]
        await client.send_all(hello_frame(server_profile=TEST_REVISION))
        async with asyncio.timeout(10):
            answered = await client.receive(65_536)
            await relay
            await asyncio.gather(*daemon.serving, return_exceptions=True)
        await client.aclose()
        return daemon, answered

    daemon, answered = asyncio.run(run())
    assert answered == b""
    # The stream was opened, but the hello never reached the server.
    assert daemon.connections == 1 and daemon.received(0) == []


@pytest.mark.parametrize("change", ["none", "credential", "consent", "zero_network"])
def test_an_authorization_change_before_the_remote_start_starts_nothing(
    ssh_target: tuple[ServerTarget, Path], change: str
) -> None:
    """A1: a retry's remote ``service start`` is asked for only under a live admission."""

    record, root = ssh_target

    async def run() -> int:
        upstream = _ChangingUpstream(ScriptedDaemon(), lambda: _act(root, change), during="answer")
        upstream.not_running = True
        helper = _helper(record, root, upstream)
        client, local = _pair()
        relay = asyncio.create_task(helper._serve_local(local))  # pyright: ignore[reportPrivateUsage]
        await client.send_all(hello_frame(server_profile=TEST_REVISION))
        async with asyncio.timeout(10):
            await client.receive(65_536)
            await relay
        await client.aclose()
        return upstream.started

    assert asyncio.run(run()) == (1 if change == "none" else 0)


async def _open_relays(
    helper: Helper, count: int
) -> list[tuple[AuthenticatedUnixStream, asyncio.Task[None]]]:
    """``count`` relayed client connections, each past its hello."""

    opened: list[tuple[AuthenticatedUnixStream, asyncio.Task[None]]] = []
    for _ in range(count):
        client, local = _pair()
        before = set(helper._relays)  # pyright: ignore[reportPrivateUsage]
        # As the endpoint's accept loop does, so the helper knows the relay.
        helper._spawn_relay(local, own=False)  # pyright: ignore[reportPrivateUsage]
        [relay] = set(helper._relays) - before  # pyright: ignore[reportPrivateUsage]
        await client.send_all(hello_frame(server_profile=TEST_REVISION))
        assert await client.receive(65_536)  # the hello result
        opened.append((client, relay))
    return opened


def test_a_frame_refused_on_one_relay_ends_every_relay_of_that_admission(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    """A4: a refusal one relay sees ends the others too, before another admission is taken."""

    record, root = ssh_target

    async def run() -> bytes:
        helper = _helper(record, root, FakeUpstream(ScriptedDaemon()))
        async with asyncio.timeout(10):
            (first, first_relay), (second, second_relay) = await _open_relays(helper, 2)
            bump_credential_generation(root)
            await first.send_all(
                encode_control_frame(call_request(1, ControlMethod.SERVICE_STATUS))
            )
            assert await first.receive(65_536) == b""
        # Waited on without cancelling them: a relay swallows a cancellation as its end.
        done, _ = await asyncio.wait((first_relay, second_relay), timeout=10)
        # No tick ran: the other relay of that admission ended with it.
        assert done == {first_relay, second_relay}
        async with asyncio.timeout(10):
            ended = await second.receive(65_536)
            # The next tick admits again (a credential change is a new generation) with none of
            # the old relays left.
            await helper.step()
            assert not helper._relays  # pyright: ignore[reportPrivateUsage]
        await first.aclose()
        await second.aclose()
        return ended

    assert asyncio.run(run()) == b""


def test_a_refresh_that_ends_the_admission_ends_its_relays(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    """A4: a refresh that changes what the connections were admitted under ends them all."""

    from builders.server_profiles import profile_document, refreshed

    record, root = ssh_target

    async def refresher(current: ServerTarget) -> None:
        # The same offer under a new revision: the consent follows it quietly, and connections
        # that named the old revision in their hello are no longer what it admits.
        refreshed(current, profile_document(revision=2))

    async def run() -> bytes:
        helper = _helper(record, root, FakeUpstream(ScriptedDaemon()), refresher=refresher)
        async with asyncio.timeout(10):
            assert helper._admitted() is not None  # pyright: ignore[reportPrivateUsage]
            [(client, relay)] = await _open_relays(helper, 1)
            await helper._run_refresh()  # pyright: ignore[reportPrivateUsage]
        done, _ = await asyncio.wait((relay,), timeout=10)
        assert done == {relay}
        async with asyncio.timeout(10):
            ended = await client.receive(65_536)
        await client.aclose()
        return ended

    assert asyncio.run(run()) == b""


class _SilentUpstream(FakeUpstream):
    """Its server accepts every channel and never answers anything (a wedged remote end)."""

    def __init__(self) -> None:
        super().__init__(ScriptedDaemon())
        self.streams: list[MemoryStream] = []
        self.ends: list[MemoryStream] = []

    async def open_stream(self):  # noqa: ANN201
        self.opened += 1
        client_end, server_end = memory_pair()
        self.streams.append(client_end)
        self.ends.append(server_end)  # held open, never read from or answered
        return client_end


def test_an_upstream_that_never_answers_the_hello_ends_the_relay_within_its_bound(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    """A5: the setup is bounded; the stream is closed and the client no longer counts."""

    record, root = ssh_target

    async def run() -> tuple[bool, list[bool], int, bytes]:
        upstream = _SilentUpstream()
        helper = _helper(record, root, upstream, setup_seconds=0.2)
        client, local = _pair()
        helper._spawn_relay(local, own=False)  # pyright: ignore[reportPrivateUsage]
        [relay] = helper._relays  # pyright: ignore[reportPrivateUsage]
        await client.send_all(hello_frame(server_profile=TEST_REVISION))
        done, _ = await asyncio.wait((relay,), timeout=10)
        async with asyncio.timeout(10):
            answered = await client.receive(65_536)
        await client.aclose()
        closed = [stream.closed for stream in upstream.streams]
        return relay in done, closed, helper._active, answered  # pyright: ignore[reportPrivateUsage]

    ended, closed, active, answered = asyncio.run(run())
    assert ended and answered == b""
    assert closed == [True] and active == 0
    status = read_helper_status(root)
    assert status is not None
    assert (status.phase, status.reason) == ("unavailable", "remote_unreachable")


def test_a_relay_cancelled_while_it_waits_for_the_server_closes_its_stream(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    """A5: a stop or a lapse during the setup leaves no upstream stream open."""

    record, root = ssh_target

    async def run() -> tuple[list[bool], int]:
        upstream = _SilentUpstream()
        helper = _helper(record, root, upstream)
        client, local = _pair()
        helper._spawn_relay(local, own=False)  # pyright: ignore[reportPrivateUsage]
        [relay] = helper._relays  # pyright: ignore[reportPrivateUsage]
        await client.send_all(hello_frame(server_profile=TEST_REVISION))
        async with asyncio.timeout(10):
            while not upstream.streams:
                await asyncio.sleep(0)
        helper._end_relays()  # pyright: ignore[reportPrivateUsage]
        done, _ = await asyncio.wait((relay,), timeout=10)
        assert done == {relay}
        await client.aclose()
        closed = [stream.closed for stream in upstream.streams]
        return closed, helper._active  # pyright: ignore[reportPrivateUsage]

    closed, active = asyncio.run(run())
    assert closed == [True] and active == 0


def test_a_consent_that_refuses_the_cached_profile_is_refreshed_back_into_admission(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    """A6: the refresh is not under the admission it exists to repair.

    The cached profile no longer agrees with the consent (here a wider offer was fetched; an
    interrupted narrowing leaves the same state): the gate refuses ``server_profile_changed``.
    The server offers what was agreed to again, and only the helper's refresh can record that.
    """

    from builders.server_profiles import fetched, profile_document, refreshed
    from finishup.client.server_profile import refresh_profile
    from finishup.client.targets import registry_lock
    from finishup.protocol.server_profile import ReviewEgress

    record, root = ssh_target
    refreshed(record, profile_document(review=ReviewEgress("server_policy", "openai"), revision=2))
    fetches: list[str] = []

    async def refresher(current: ServerTarget) -> None:
        fetches.append("fetched")
        with registry_lock():
            refresh_profile(current, fetched(current, profile_document(revision=3)))

    async def run() -> tuple[bool, bool]:
        helper = _helper(record, root, FakeUpstream(ScriptedDaemon()), refresher=refresher)
        refused = helper._admitted() is None  # pyright: ignore[reportPrivateUsage]
        await helper.step()
        task = helper._refresh.task  # pyright: ignore[reportPrivateUsage]
        if task is not None:
            await task
        return refused, helper._admitted() is not None  # pyright: ignore[reportPrivateUsage]

    refused, admitted = asyncio.run(run())
    assert refused and fetches == ["fetched"] and admitted
    status = read_helper_status(root)
    assert status is not None and status.reason == "server_profile_changed"


@pytest.mark.parametrize("refusal", ["zero_network", "disclosure"])
def test_the_refresh_still_waits_for_zero_network_and_an_older_disclosure(
    ssh_target: tuple[ServerTarget, Path], refusal: str
) -> None:
    """A6: what the refresh does still ask: no fetch while either refuses (gate steps 2-3)."""

    from dataclasses import replace
    from typing import cast

    record, root = ssh_target
    fetches: list[str] = []

    async def refresher(_current: ServerTarget) -> None:
        fetches.append("fetched")

    if refusal == "disclosure":
        with targets.registry_lock():
            older = cast(int, record.disclosure_version) - 1
            targets.write_target(root, replace(record, disclosure_version=older))
    else:
        from finishup.client.everyday_policy import record_reported_policy

        assert record_reported_policy(zero_network=True)

    async def run() -> None:
        helper = _helper(record, root, FakeUpstream(ScriptedDaemon()), refresher=refresher)
        await helper.step()
        task = helper._refresh.task  # pyright: ignore[reportPrivateUsage]
        if task is not None:
            await task

    asyncio.run(run())
    assert fetches == []


@pytest.mark.parametrize("live", [True, False])
def test_a_live_direct_agent_keeps_the_periodic_refresh_due(
    ssh_target: tuple[ServerTarget, Path], live: bool
) -> None:
    """A7: in the direct style an agent's traffic never passes the relay that counts use."""

    record, root = ssh_target
    fetched_at: list[float] = []

    class Agent:
        alive = True
        client = object() if live else None

        async def drain(self, *, may_send: object) -> None:
            return None

        async def aclose(self) -> None:
            return None

    async def run() -> list[float]:
        clock = Clock()

        async def refresher(_record: ServerTarget) -> None:
            fetched_at.append(clock())

        helper = _helper(
            record,
            root,
            FakeUpstream(ScriptedDaemon()),
            style="direct",
            refresher=refresher,
            clock=clock,
        )
        helper._sync_agents = _no_sync  # type: ignore[method-assign]
        helper._agents[("x",)] = Agent()  # type: ignore[assignment]  # pyright: ignore[reportPrivateUsage,reportArgumentType]
        # As when the agent was opened: the only use the direct style recorded before.
        helper._last_upstream_use = clock()  # pyright: ignore[reportPrivateUsage]
        for _ in range(3):
            await helper.step()
            task = helper._refresh.task  # pyright: ignore[reportPrivateUsage]
            if task is not None:
                await task
            clock.now += 601
        return fetched_at

    # At start, then every 10 minutes while the agent's connection is live; with no live
    # connection, the one use recorded at its opening is soon older than 10 minutes.
    assert asyncio.run(run()) == ([1_000.0, 1_601.0, 2_202.0] if live else [1_000.0])


def test_a_helper_spawned_before_a_stop_serves_nothing_once_it_starts(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    """A2: ``disconnect`` came between the spawn and the lock: the late helper never serves."""

    from finishup.client.helper import run_helper_process
    from finishup.client.helper_status import read_helper_epoch, stop_helper
    from finishup.config.paths import selection_override

    record, root = ssh_target
    spawned_with = read_helper_epoch(root)
    # Nothing holds the lock yet (the spawned process is still starting): the stop is done.
    assert stop_helper(root, timeout_seconds=1.0) is True

    async def run() -> int:
        return await asyncio.wait_for(
            run_helper_process(root, record, idle_seconds=900.0, epoch=spawned_with), 10
        )

    with selection_override(root):
        assert asyncio.run(run()) == 0
    # It bound no endpoint and left the lock free; its status says it was stopped.
    assert not (root / "run" / "control.sock").exists()
    status = read_helper_status(root)
    assert status is not None and (status.phase, status.reason) == ("stopped", "stop_requested")
    assert stop_helper(root, timeout_seconds=0.2) is True


def test_a_running_helper_stops_when_the_epoch_moves_and_the_stop_sees_its_lock_free(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    """A2/A3: the stop is the epoch, read on the helper's tick; no signal is sent to it."""

    from finishup.client.helper import run_helper_process
    from finishup.client.helper_status import helper_holder, read_helper_epoch, stop_helper
    from finishup.config.paths import selection_override

    record, root = ssh_target

    async def run() -> tuple[int, bool]:
        serving = asyncio.create_task(
            run_helper_process(root, record, idle_seconds=900.0, epoch=read_helper_epoch(root))
        )
        async with asyncio.timeout(10):
            while helper_holder(root) is None or not (root / "run" / "control.sock").exists():
                await asyncio.sleep(0)
        stopped = await asyncio.to_thread(stop_helper, root, timeout_seconds=10.0)
        async with asyncio.timeout(10):
            code = await serving
        return code, stopped

    with selection_override(root):
        code, stopped = asyncio.run(run())
    assert (code, stopped) == (0, True)
    status = read_helper_status(root)
    assert status is not None and (status.phase, status.reason) == ("stopped", "stop_requested")


def test_one_background_agent_serves_a_workspace_however_many_processes_registered_it(
    ssh_target: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every command registers the worktree it ran in under its own registrant, so a busy
    worktree has many registrations; the helper opens one agent per workspace (a REST key may
    hold sixteen agents, and the client's own connections need room too), served under the
    registration that holds it longest."""

    from finishup.client import helper_registrations

    record, root = ssh_target

    def item(claim: str, worktree: str, registrant: str, expires: str) -> object:
        return SimpleNamespace(
            registration=SimpleNamespace(
                claim=claim, worktree=worktree, registrant=registrant, expires_at=expires
            )
        )

    rows = [
        item("claim-a", "/w/one", f"r{index}", f"2026-11-10T14:{index:02d}:00.000Z")
        for index in range(20)
    ] + [item("claim-a", "/w/two", "r99", "2026-11-10T14:30:00.000Z")]
    served_now: list[list[object]] = [rows]

    async def served(_record: ServerTarget) -> tuple[object, ...]:
        return tuple(served_now[0])

    monkeypatch.setattr(helper_registrations, "served_workspaces", served)
    opened: list[SimpleNamespace] = []
    closed: list[SimpleNamespace] = []

    class Agent:
        alive = True

        def __init__(self, registration: SimpleNamespace) -> None:
            self.registration = registration

        async def aclose(self) -> None:
            closed.append(self.registration)

    async def opener(*arguments: object) -> Agent:
        registration = cast(SimpleNamespace, arguments[2])
        opened.append(registration)
        return Agent(registration)

    async def run() -> None:
        helper = _helper(record, root, FakeUpstream(ScriptedDaemon()), agent_opener=opener)
        monkeypatch.setattr(helper, "_admitted", lambda: object())
        await helper._sync_agents()  # pyright: ignore[reportPrivateUsage]
        assert [(row.worktree, row.registrant) for row in opened] == [
            ("/w/one", "r19"),
            ("/w/two", "r99"),
        ]
        # More registrations of the same worktree open nothing more; a worktree no longer
        # served loses its agent.
        served_now[0] = rows[1:20]
        await helper._sync_agents()  # pyright: ignore[reportPrivateUsage]
        assert len(opened) == 2
        assert [row.worktree for row in closed] == ["/w/two"]

    asyncio.run(run())


class _DownUpstream(FakeUpstream):
    """The server's endpoint refuses every channel (its service is down) and it cannot be
    started: each relay ends unanswered, named ``remote_service_not_running``."""

    def __init__(self) -> None:
        super().__init__(ScriptedDaemon())
        self.not_running = True

    async def start_remote_service(self) -> bool:
        self.started += 1
        return False


def test_a_clients_relay_refused_like_an_agents_before_it_is_named_to_that_client_at_once(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    """Defect B (dogfood, 2026-11-11): a background agent's relay refused for a reason left the
    status naming it; a client's relay then refused for the same reason wrote nothing new, so
    the client (``service.client._helper_failure``, which takes only a record made after it
    began) waited out its deadline and read ``remote_unreachable``. Each refusal of a client's
    relay is recorded again for that client; the generation (what latches key on) stays."""

    from finishup.service.client import _helper_failure  # pyright: ignore[reportPrivateUsage]

    record, root = ssh_target

    async def relay(helper: Helper, *, own: bool) -> bytes:
        client, local = _pair()
        task = asyncio.create_task(helper._serve_local(local, own=own))  # pyright: ignore[reportPrivateUsage]
        try:
            await client.send_all(hello_frame(server_profile=TEST_REVISION))
            async with asyncio.timeout(10):
                answered = await client.receive(65_536)
                await task
        finally:
            await client.aclose()
        return answered

    async def run() -> tuple[HelperStatus | None, ControlError | None, HelperStatus | None]:
        helper = _helper(record, root, _DownUpstream())
        assert await relay(helper, own=True) == b""  # the helper's background agent
        before = read_helper_status(root)
        assert await relay(helper, own=False) == b""  # a client's command, same refusal
        named = _helper_failure(root, before)
        return before, named, read_helper_status(root)

    before, named, after = asyncio.run(run())
    assert before is not None and after is not None
    assert (before.phase, before.reason) == ("unavailable", "remote_service_not_running")
    assert named is not None and named.phase == "remote_service_not_running"
    assert after.generation == before.generation


def test_a_clients_relay_refused_by_the_helpers_own_standing_refusal_is_named_at_once(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    """The same for a relay the helper refuses before any dial: its admission is refused (here
    the consent's envelope is gone) and the status already names why."""

    from finishup.service.client import _helper_failure  # pyright: ignore[reportPrivateUsage]

    record, root = ssh_target

    async def run() -> tuple[HelperStatus | None, ControlError | None]:
        helper = _helper(record, root, FakeUpstream(ScriptedDaemon()))
        _act(root, "consent")
        assert helper._admitted() is None  # pyright: ignore[reportPrivateUsage]
        before = read_helper_status(root)
        client, local = _pair()
        task = asyncio.create_task(helper._serve_local(local))  # pyright: ignore[reportPrivateUsage]
        try:
            await client.send_all(hello_frame(server_profile=TEST_REVISION))
            async with asyncio.timeout(10):
                assert await client.receive(65_536) == b""
                await task
        finally:
            await client.aclose()
        return before, _helper_failure(root, before)

    before, named = asyncio.run(run())
    assert before is not None and before.phase == "unavailable"
    assert named is not None and named.phase == before.reason
