"""A connection whose repository becomes held, or kept, closes within one check (ADR-051 d. 8).

Maintainer decision of 2026-11-07, round 4. A repository whose privacy policy on this computer
allows no network use is held from a server elsewhere until the owner decides. A connection made
while it could be sent carries its ``SendHold``: the client re-checks it before every frame it
sends and once a second while it is open, so a long-lived holder (the MCP bridge's cached
connection, the terminal interface, a CLI command under way, the connector's background agents)
sends nothing more once the repository is held or kept, and its pending calls and later calls
fail with the phase every surface renders. No test here waits on a sleep: the check interval is
injected and every wait is bounded on observed state.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Buffer, Callable
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
    WorkspaceClaim,
    WorkspaceReply,
)
from finishup.protocol.ids import IdKind, new_id
from finishup.service import client as client_module
from finishup.service.client import ClientWorkspaceBinding, ServiceClient
from finishup.service.control_protocol import (
    ControlSession,
    decode_control_frame,
    encode_control_frame,
    workspace_call_frame,
)

_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000001"
_HANDLE = "client:0123456789abcdef"
_CLAIM = WorkspaceClaim(
    identity_kind="git_common_root", digest="sha256:" + "ab" * 32, worktree="sha256:" + "cd" * 32
)
_WAIT_SECONDS = 10.0
_HELD = "repository_egress_held"
_KEPT = "repository_egress_kept"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _FakeStream:
    def __init__(self) -> None:
        self.peer_identity = object()
        self.sent: list[bytes] = []
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

    async def aclose(self) -> None:
        async with self._ready:
            self.closed = True
            self._ready.notify_all()

    async def feed(self, data: bytes) -> None:
        async with self._ready:
            self._incoming.extend(data)
            self._ready.notify_all()


class _Hold:
    """A send hold the test flips; counts how often it was asked."""

    def __init__(self) -> None:
        self.current: str | None = None
        self.checks = 0

    def phase(self) -> str | None:
        self.checks += 1
        return self.current

    def held(self) -> bool:
        return self.phase() is not None


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


def _client(stream: _FakeStream, hold: _Hold, agent: _Agent | None = None) -> ServiceClient:
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
        transport="connector",
        send_hold=hold,
    )


async def _until(condition: Callable[[], bool]) -> None:
    """A bounded wait on observed state: fails at the deadline, never infers from elapsed time."""

    deadline = time.monotonic() + _WAIT_SECONDS
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("condition_not_reached")
        await asyncio.sleep(0.001)


def _phase(error: ControlError) -> tuple[str, bool, str | None]:
    return error.reason, error.retryable, error.phase


@pytest.mark.anyio
@pytest.mark.parametrize("phase", [_HELD, _KEPT])
async def test_a_pending_call_fails_with_the_phase_once_the_repository_is_held(
    monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    # One check slice, injected: the watch re-reads the hold every 10 ms here, every second live.
    monkeypatch.setattr(client_module, "_HOLD_RECHECK_SECONDS", 0.01)
    stream = _FakeStream()
    hold = _Hold()
    client = _client(stream, hold)
    pending = asyncio.create_task(client.service_status())
    await _until(lambda: len(stream.sent) == 1)
    checks = hold.checks

    hold.current = phase
    with pytest.raises(ControlError) as raised:
        async with asyncio.timeout(_WAIT_SECONDS):
            await pending

    assert _phase(raised.value) == ("service_unavailable", True, phase)
    assert hold.checks > checks
    assert client.closed and stream.closed
    # A later call is refused with the same phase, and nothing more is sent.
    with pytest.raises(ControlError) as later:
        await client.service_status()
    assert _phase(later.value) == ("service_unavailable", True, phase)
    assert len(stream.sent) == 1


@pytest.mark.anyio
async def test_no_frame_is_sent_once_the_repository_is_held(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The watch would not look for a minute: the check before the frame refuses it.
    monkeypatch.setattr(client_module, "_HOLD_RECHECK_SECONDS", 60.0)
    stream = _FakeStream()
    hold = _Hold()
    client = _client(stream, hold)
    hold.current = _HELD

    with pytest.raises(ControlError) as raised:
        await client.service_status()

    assert _phase(raised.value) == ("service_unavailable", True, _HELD)
    assert stream.sent == []
    assert client.closed


@pytest.mark.anyio
async def test_a_workspace_reply_is_not_sent_for_a_repository_held_meanwhile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(client_module, "_HOLD_RECHECK_SECONDS", 60.0)
    stream = _FakeStream()
    hold = _Hold()
    gate = threading.Event()
    agent = _Agent(gate)
    client = _client(stream, hold, agent)
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
    await _until(agent.answered.is_set)

    # The repository is held while the agent reads: its answer never leaves.
    hold.current = _HELD
    gate.set()
    await _until(lambda: client.closed)

    assert [decode_control_frame(item).get("kind") for item in stream.sent] == []


@pytest.mark.anyio
async def test_a_connection_whose_repository_stays_sendable_stays_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(client_module, "_HOLD_RECHECK_SECONDS", 0.01)
    stream = _FakeStream()
    hold = _Hold()
    client = _client(stream, hold)
    # Several check slices pass with the repository sendable.
    await _until(lambda: hold.checks >= 5)
    assert not client.closed
    watch = client._hold_watch  # pyright: ignore[reportPrivateUsage]
    assert watch is not None
    await client.close()
    # Closing ends the watch: the hold is not asked again.
    await _until(watch.done)
    assert client.closed and watch.done()


@pytest.mark.anyio
async def test_the_binding_hold_reaches_a_relayed_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``connect_service_stream`` (the connector's own agents) keeps the binding's hold."""

    monkeypatch.setattr(client_module, "_HOLD_RECHECK_SECONDS", 0.01)
    stream = _FakeStream()
    hold = _Hold()

    async def handshake(*_args: object, **_kwargs: object) -> ControlSession:
        return ControlSession(
            protocol_version="1.0",
            client_kind=ControlClientKind.CLI,
            service_instance_id=_SERVICE_ID,
            service_generation="1",
            allowed_methods=tuple(sorted(ControlMethod, key=lambda method: method.value.encode())),
            peer_identity=stream.peer_identity,
            connection_nonce="0" * 64,
            workspace_binding="client_claim",
            workspace_handle=_HANDLE,
            workspace_agent=None,
        )

    monkeypatch.setattr(client_module, "client_handshake", handshake)
    client = await client_module.connect_service_stream(
        cast(AuthenticatedUnixStream, stream),
        ControlClientKind.CLI,
        workspace_binding=ClientWorkspaceBinding(_CLAIM, hold=hold),
        transport="connector",
    )
    hold.current = _KEPT
    await _until(lambda: client.closed)
    with pytest.raises(ControlError) as raised:
        await client.service_status()
    assert _phase(raised.value) == ("service_unavailable", True, _KEPT)
