"""A connection whose authorization lapses ends within one check (ADR-052).

A connection admitted to a server elsewhere keeps the ``AuthorizationCheck`` it was admitted
under: the client checks it before every frame it sends and on a watch while it is open, so a
long-lived holder (the MCP bridge's kept connection, the terminal interface, a CLI command under
way) sends nothing more once the selection, the server record or the key changed, this computer
reported zero-network, or the repository was held or kept. Its pending calls and later calls fail
with the phase every surface renders. A local connection carries no check and no watch (O2).

No test waits on time: the watch's interval is an injected tick, and every wait is on an event
the code under test sets.

Adapted from the round-5 send-hold test (``2fa87ef2a``, ``tests/unit/service/test_client_send_hold.py``).
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Buffer
from typing import cast

import pytest

from finishup.adapters.control.unix_socket import AuthenticatedUnixStream
from finishup.domain.values import JsonObject
from finishup.ports.control import (
    ControlClientKind,
    ControlError,
    ControlMethod,
    WorkspaceAgentDeclaration,
    WorkspaceCall,
    WorkspaceReply,
)
from finishup.protocol.ids import IdKind, new_id
from finishup.service import client as client_module
from finishup.service.client import GENERATION_RECHECK_SECONDS, ServiceClient
from finishup.service.control_protocol import (
    ControlSession,
    encode_control_frame,
    workspace_call_frame,
)

_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000001"
_HANDLE = "client:0123456789abcdef"
_WAIT_SECONDS = 10.0
_PHASES = (
    "server_authorization_changed",
    "zero_network_remote_selected",
    "repository_egress_held",
    "repository_egress_kept",
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _FakeStream:
    def __init__(self) -> None:
        self.peer_identity = object()
        self.sent: list[bytes] = []
        self.sent_one = asyncio.Event()
        self.ended = asyncio.Event()
        self._incoming = bytearray()
        self._ready = asyncio.Condition()
        self.closed = False

    async def receive(self, max_bytes: int) -> bytes:
        async with self._ready:
            await self._ready.wait_for(lambda: bool(self._incoming) or self.closed)
            if not self._incoming:
                return b""
            size = min(max_bytes, len(self._incoming))
            result = bytes(self._incoming[:size])
            del self._incoming[:size]
            return result

    async def send_all(self, data: Buffer) -> None:
        self.sent.append(bytes(data))
        self.sent_one.set()

    async def aclose(self) -> None:
        async with self._ready:
            self.closed = True
            self.ended.set()
            self._ready.notify_all()

    async def feed(self, data: bytes) -> None:
        async with self._ready:
            self._incoming.extend(data)
            self._ready.notify_all()


class _Check:
    """An authorization the test flips; counts how often it was asked (from any thread)."""

    def __init__(self) -> None:
        self.current: str | None = None
        self._lock = threading.Lock()
        self.checks = 0

    def refusal(self) -> str | None:
        with self._lock:
            self.checks += 1
            return self.current


class _Tick:
    """The watch's interval, injected: each ``release`` lets exactly one check run."""

    def __init__(self) -> None:
        self._ticks = asyncio.Semaphore(0)
        self.waiting = asyncio.Event()

    async def __call__(self) -> None:
        self.waiting.set()
        await self._ticks.acquire()

    async def one_check(self) -> None:
        """Release one tick and wait until the watch has made its check and waits again."""

        await asyncio.wait_for(self.waiting.wait(), _WAIT_SECONDS)
        self.waiting.clear()
        self._ticks.release()
        await asyncio.wait_for(self.waiting.wait(), _WAIT_SECONDS)


class _Agent:
    def __init__(self, gate: threading.Event) -> None:
        self.declaration = WorkspaceAgentDeclaration(("read_task_base",), 6_291_456)
        self.gate = gate
        self.answered = threading.Event()

    def answer(self, call: WorkspaceCall, *, workspace_handle: str | None) -> WorkspaceReply:
        self.answered.set()
        if not self.gate.wait(timeout=_WAIT_SECONDS):
            raise RuntimeError("test_gate_never_opened")
        return WorkspaceReply("workspace_reply", "1.0", call.call_id, "ok", {"n": 1}, None)


def _client(
    stream: _FakeStream,
    check: _Check | None,
    tick: _Tick | None = None,
    agent: _Agent | None = None,
) -> ServiceClient:
    session = ControlSession(
        protocol_version="1.0",
        client_kind=ControlClientKind.CLI,
        service_instance_id=_SERVICE_ID,
        service_generation="1",
        allowed_methods=tuple(sorted(ControlMethod, key=lambda method: method.value.encode())),
        peer_identity=stream.peer_identity,
        connection_nonce="0" * 64,
        workspace_binding="client_claim",
        workspace_handle=_HANDLE,
        workspace_agent=None if agent is None else agent.declaration,
    )
    factory = client_module._connected_client  # pyright: ignore[reportPrivateUsage]
    return factory(
        cast(AuthenticatedUnixStream, stream),
        session,
        ControlClientKind.CLI,
        agent,
        authorization=check,
        recheck=tick,
    )


def _closed(client: ServiceClient) -> bool:
    return client._closed  # pyright: ignore[reportPrivateUsage]


def _phase(error: ControlError) -> tuple[str, bool, str | None]:
    return error.reason, error.retryable, error.phase


@pytest.mark.anyio
@pytest.mark.parametrize("phase", _PHASES)
async def test_a_pending_call_fails_as_a_changed_authorization_within_one_check(
    phase: str,
) -> None:
    """Whatever the check names, an open connection has already sent something: it ends as
    ``server_authorization_changed`` (FinishUP stopped sending over it), never with a phase whose
    words say nothing was sent (design v2 section 8.10)."""

    stream, check, tick = _FakeStream(), _Check(), _Tick()
    client = _client(stream, check, tick)
    pending = asyncio.create_task(client.service_status())
    await asyncio.wait_for(stream.sent_one.wait(), _WAIT_SECONDS)
    # Checks pass while nothing changed: the connection stays open.
    await tick.one_check()
    assert not _closed(client) and not pending.done()

    check.current = phase
    tick.waiting.clear()
    tick._ticks.release()  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(ControlError) as raised:
        await asyncio.wait_for(pending, _WAIT_SECONDS)

    ended = ("service_unavailable", True, "server_authorization_changed")
    assert _phase(raised.value) == ended
    assert _closed(client) and stream.closed
    # A later call is refused the same way, and nothing more is sent.
    with pytest.raises(ControlError) as later:
        await client.service_status()
    assert _phase(later.value) == ended
    with pytest.raises(ControlError) as reused:
        await client.connect()
    assert _phase(reused.value) == ended
    assert len(stream.sent) == 1


@pytest.mark.anyio
@pytest.mark.parametrize("phase", _PHASES)
async def test_a_frame_refused_on_an_open_connection_is_a_changed_authorization(
    phase: str,
) -> None:
    stream, check, tick = _FakeStream(), _Check(), _Tick()
    client = _client(stream, check, tick)
    check.current = phase
    with pytest.raises(ControlError) as raised:
        await client.service_status()
    assert _phase(raised.value) == ("service_unavailable", True, "server_authorization_changed")
    assert stream.sent == [] and _closed(client)


@pytest.mark.anyio
async def test_no_frame_is_sent_once_the_authorization_lapsed() -> None:
    # The watch never ticks here: the check before the frame refuses it.
    stream, check, tick = _FakeStream(), _Check(), _Tick()
    client = _client(stream, check, tick)
    check.current = "server_authorization_changed"

    with pytest.raises(ControlError) as raised:
        await client.service_status()

    assert _phase(raised.value) == ("service_unavailable", True, "server_authorization_changed")
    assert stream.sent == []
    assert _closed(client)


@pytest.mark.anyio
async def test_the_bridge_reuse_check_names_a_lapsed_authorization_before_a_request() -> None:
    stream, check, tick = _FakeStream(), _Check(), _Tick()
    client = _client(stream, check, tick)
    await client.connect()
    assert not _closed(client)
    check.current = "server_authorization_changed"
    with pytest.raises(ControlError) as raised:
        await client.connect()
    assert _phase(raised.value) == ("service_unavailable", True, "server_authorization_changed")
    assert stream.sent == [] and _closed(client)


@pytest.mark.anyio
async def test_a_workspace_reply_is_not_sent_once_the_authorization_lapsed_meanwhile() -> None:
    stream, check, tick = _FakeStream(), _Check(), _Tick()
    gate = threading.Event()
    agent = _Agent(gate)
    client = _client(stream, check, tick, agent)
    call = WorkspaceCall(
        kind="workspace_call",
        protocol_version="1.0",
        call_id=new_id(IdKind.CONTROL_RPC),
        service_instance_id=_SERVICE_ID,
        service_generation="1",
        operation="read_task_base",
        arguments=JsonObject({"workspace": _HANDLE}),
        deadline_ms=30_000,
    )
    await stream.feed(encode_control_frame(workspace_call_frame(call)))
    assert await asyncio.to_thread(agent.answered.wait, _WAIT_SECONDS)

    # The repository is held while the agent reads: its answer never leaves.
    check.current = "repository_egress_held"
    gate.set()
    await asyncio.wait_for(stream.ended.wait(), _WAIT_SECONDS)

    assert stream.sent == []
    assert _closed(client)


@pytest.mark.anyio
async def test_a_connection_whose_authorization_holds_stays_open_and_close_ends_the_watch() -> None:
    stream, check, tick = _FakeStream(), _Check(), _Tick()
    client = _client(stream, check, tick)
    for _ in range(3):
        await tick.one_check()
    assert not _closed(client)
    assert check.checks >= 3
    watch = client._watch  # pyright: ignore[reportPrivateUsage]
    assert watch is not None
    await client.close()
    await asyncio.wait_for(asyncio.gather(watch, return_exceptions=True), _WAIT_SECONDS)
    assert watch.done()
    asked = check.checks
    tick._ticks.release()  # pyright: ignore[reportPrivateUsage]
    assert check.checks == asked


@pytest.mark.anyio
async def test_a_local_connection_has_no_check_and_no_watch() -> None:
    """O2: a connection to a server on this computer is made exactly as before."""

    stream = _FakeStream()
    client = _client(stream, None)
    assert client._watch is None  # pyright: ignore[reportPrivateUsage]
    pending = asyncio.create_task(client.service_status())
    await asyncio.wait_for(stream.sent_one.wait(), _WAIT_SECONDS)
    assert len(stream.sent) == 1
    pending.cancel()
    await asyncio.gather(pending, return_exceptions=True)
    await client.close()


def test_the_watch_checks_once_a_second() -> None:
    assert GENERATION_RECHECK_SECONDS == 1.0


# --- the server refuses a request on an open connection (review of layer 3: B2) -----------------


def _sent_rpc_ids(stream: _FakeStream) -> list[str]:
    import json

    return [json.loads(frame[4:])["rpc_id"] for frame in stream.sent]


async def _refuse_with_changed_profile(stream: _FakeStream, rpc_id: str) -> None:
    from finishup.service.control_protocol import ControlResult

    result = ControlResult(
        protocol_version="1.0",
        rpc_id=rpc_id,
        service_instance_id=_SERVICE_ID,
        service_generation="1",
        method=ControlMethod.SERVICE_STATUS,
        outcome="error",
        body=ControlError("server_profile_changed"),
    )
    await stream.feed(encode_control_frame(result))


@pytest.mark.anyio
async def test_a_request_the_server_refuses_ends_every_other_sent_call_as_an_unknown_outcome() -> (
    None
):
    """The server refused one request before doing any work for it (``server_profile_changed``);
    another call was already sent over the connection and may have been recorded, so it ends as
    ``server_authorization_changed`` (its outcome is unknown), never with words that say nothing
    was sent. A later call is refused before it is sent, under the refusal's own phase."""

    stream = _FakeStream()
    client = _client(stream, _Check())
    first = asyncio.create_task(client.service_status())
    await asyncio.wait_for(stream.sent_one.wait(), _WAIT_SECONDS)
    stream.sent_one.clear()
    second = asyncio.create_task(client.service_status())
    await asyncio.wait_for(stream.sent_one.wait(), _WAIT_SECONDS)
    sent_first, sent_second = _sent_rpc_ids(stream)

    await _refuse_with_changed_profile(stream, sent_second)

    with pytest.raises(ControlError) as refused:
        await asyncio.wait_for(second, _WAIT_SECONDS)
    assert _phase(refused.value) == ("service_unavailable", True, "server_profile_changed")
    with pytest.raises(ControlError) as other:
        await asyncio.wait_for(first, _WAIT_SECONDS)
    assert _phase(other.value) == ("service_unavailable", True, "server_authorization_changed")
    assert sent_first != sent_second and _closed(client) and stream.closed
    with pytest.raises(ControlError) as later:
        await client.service_status()
    assert _phase(later.value) == ("service_unavailable", True, "server_profile_changed")
    assert len(stream.sent) == 2


@pytest.mark.anyio
@pytest.mark.parametrize("phase", ["server_profile_changed", "server_level_unavailable"])
async def test_a_connection_torn_down_with_a_refusal_phase_ends_sent_calls_as_unknown_outcomes(
    phase: str,
) -> None:
    """Whatever phase ends an open connection, a call already sent over it never fails with a
    refusal whose words say nothing was sent or no work was done."""

    stream = _FakeStream()
    client = _client(stream, _Check())
    pending = asyncio.create_task(client.service_status())
    await asyncio.wait_for(stream.sent_one.wait(), _WAIT_SECONDS)

    teardown = ControlError("service_unavailable", retryable=True, phase=phase)
    await client._fail_connection(teardown)  # pyright: ignore[reportPrivateUsage]

    with pytest.raises(ControlError) as ended:
        await asyncio.wait_for(pending, _WAIT_SECONDS)
    assert _phase(ended.value) == ("service_unavailable", True, "server_authorization_changed")
