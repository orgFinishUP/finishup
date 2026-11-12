"""The gateway's control-socket backend (ADR-053, design v2 section 8.4).

Every REST request re-enters the service as an ordinary control connection: the hello carries the
(already namespaced) claim and the consented revision, so the service itself refuses a stale
revision before the claim is keyed; a call's cancel follows its call frame on the same connection,
never before it; an agent is one claim-bound connection whose pushed workspace calls reach the REST
queue and whose replies go back; a dropped connection ends the agent (the edge follows the
service's generation); a background agent never starts a stopped service. The gateway package
imports nothing but SHARED modules and ``service.client``.
"""

from __future__ import annotations

import ast
import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import replace
from pathlib import Path

import pytest

from builders.control_relay import (
    SERVICE_ID,
    SLOW_METHOD,
    ScriptedDaemon,
    call_request,
    memory_pair,
)
from builders.rest_backend import AGENT_DECLARATION
from builders.server_profiles import TEST_REVISION
from finishup.domain.values import JsonObject
from finishup.gateway.backend import ControlSocketBackend
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
from finishup.protocol.server_profile import ServerProfileRevision
from finishup.rest.backend import AgentHandle, BackendRefusal
from finishup.service.control_protocol import (
    ControlStream,
    read_control_frame,
    server_handshake,
    workspace_call_frame,
    write_control_frame,
)

pytestmark = pytest.mark.anyio

_CLAIM = WorkspaceClaim(
    identity_kind="git_common_root", digest="sha256:" + "a" * 64, worktree="sha256:" + "b" * 64
)
_HANDLE = "client:0123456789abcdef"
_STALE = ServerProfileRevision(TEST_REVISION.issuer, 5, "sha256:" + "c" * 64)
_SRC = Path(__file__).resolve().parents[3] / "src" / "finishup"


def _served(daemon: ScriptedDaemon) -> Callable[[], Awaitable[ControlStream]]:
    async def connect() -> ControlStream:
        client, server = memory_pair()
        daemon.serving.append(asyncio.create_task(daemon.serve(server)))
        return client

    return connect


async def _until(condition: Callable[[], object], seconds: float = 10.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + seconds
    while not condition():
        assert loop.time() < deadline, "condition not reached"
        await asyncio.sleep(0)


async def test_a_session_names_the_claim_and_revision_and_a_stale_one_is_never_keyed() -> None:
    daemon = ScriptedDaemon()
    daemon.claim_handle = _HANDLE
    backend = ControlSocketBackend(connect=_served(daemon))
    with pytest.raises(BackendRefusal) as refused:
        await backend.session(client_kind=ControlClientKind.CLI, claim=_CLAIM, revision=_STALE)
    assert refused.value.reason == "server_profile_changed"
    assert daemon.claims == []
    session = await backend.session(
        client_kind=ControlClientKind.CLI, claim=_CLAIM, revision=TEST_REVISION
    )
    assert (session.workspace_binding, session.workspace_handle) == ("client_claim", _HANDLE)
    assert session.server_profile == TEST_REVISION
    assert session.status.service_instance_id == SERVICE_ID
    assert daemon.claims == [_CLAIM]


async def test_a_call_runs_on_its_own_connection_bound_to_the_revision() -> None:
    daemon = ScriptedDaemon()
    backend = ControlSocketBackend(connect=_served(daemon))
    call = call_request(7, ControlMethod.SERVICE_STATUS)
    result = await backend.dispatch(
        client_kind=ControlClientKind.CLI,
        call=call,
        claim=None,
        revision=TEST_REVISION,
        start_service=True,
    )
    assert result.outcome == "ok" and result.rpc_id == call.rpc_id
    with pytest.raises(BackendRefusal) as refused:
        await backend.dispatch(
            client_kind=ControlClientKind.CLI,
            call=call_request(8, ControlMethod.SERVICE_STATUS),
            claim=None,
            revision=_STALE,
            start_service=True,
        )
    assert refused.value.reason == "server_profile_changed"
    # The stale hello was refused before any call frame was read on it.
    assert len(daemon.received(-1)) == 1


async def test_a_cancel_follows_its_call_on_the_same_connection_and_the_result_answers() -> None:
    daemon = ScriptedDaemon()
    backend = ControlSocketBackend(connect=_served(daemon))
    call = call_request(0x51F0, SLOW_METHOD)
    task = asyncio.create_task(
        backend.dispatch(
            client_kind=ControlClientKind.CLI,
            call=call,
            claim=None,
            revision=TEST_REVISION,
            start_service=True,
        )
    )
    await _until(lambda: daemon.inbound and len(daemon.received(-1)) == 2)
    task.cancel()
    result = await asyncio.wait_for(task, timeout=10)
    assert result.outcome == "error" and result.rpc_id == call.rpc_id
    frames = daemon.received(-1)
    assert b'"kind":"call"' in frames[1] and b'"kind":"cancel"' in frames[2]


async def test_a_call_cancelled_before_its_frame_is_written_never_reaches_the_service() -> None:
    daemon = ScriptedDaemon()
    release = asyncio.Event()
    served = _served(daemon)

    async def slow_connect() -> ControlStream:
        await release.wait()
        return await served()

    backend = ControlSocketBackend(connect=slow_connect)
    call = call_request(9, ControlMethod.SERVICE_STATUS)
    task = asyncio.create_task(
        backend.dispatch(
            client_kind=ControlClientKind.CLI,
            call=call,
            claim=None,
            revision=TEST_REVISION,
            start_service=True,
        )
    )
    await asyncio.sleep(0)
    task.cancel()
    result = await asyncio.wait_for(task, timeout=10)
    assert result.outcome == "error"
    assert daemon.connections == 0


async def test_the_service_is_started_for_a_client_never_for_a_background_agent() -> None:
    started: list[bool] = []

    async def refuse() -> ControlStream:
        raise OSError("absent")

    async def start() -> None:
        started.append(True)

    backend = ControlSocketBackend(connect=refuse, start=start)
    background = _background_declaration()
    with pytest.raises(BackendRefusal):
        await backend.register_agent(
            client_kind=ControlClientKind.MCP_BRIDGE,
            claim=_CLAIM,
            declaration=background,
            revision=TEST_REVISION,
            writer=_sink([]),
        )
    assert started == []
    with pytest.raises(BackendRefusal):
        await backend.dispatch(
            client_kind=ControlClientKind.CLI,
            call=call_request(10, ControlMethod.SERVICE_STATUS),
            claim=None,
            revision=TEST_REVISION,
            start_service=True,
        )
    assert started == [True]


class _AgentDaemon:
    """Keys every claim to ``_HANDLE``, pushes one workspace call, and records the reply."""

    def __init__(self) -> None:
        self.replies: list[JsonObject] = []
        self.replied = asyncio.Event()
        self.server: ControlStream | None = None
        self.declared_role: str | None = None

    async def serve(self, stream: ControlStream) -> None:
        from finishup.ports.control import RepositoryPrivacyContext

        async def key(claim: WorkspaceClaim) -> RepositoryPrivacyContext:
            del claim
            return RepositoryPrivacyContext(
                commitment="hmac-sha256:" + "c" * 64,
                identity_kind="client_claim",
                workspace_handle=_HANDLE,
            )

        from builders.control_relay import service_status

        session = await server_handshake(
            stream,
            stream.peer_identity,
            service_status(),
            claim_context_resolver=key,
            profile_revision=lambda: TEST_REVISION,
        )
        assert session.workspace_agent is not None
        self.declared_role = session.workspace_agent.role
        self.server = stream
        await write_control_frame(stream, workspace_call_frame(_CALL))
        frame = await read_control_frame(stream)
        self.replies.append(frame)
        self.replied.set()


_CALL = WorkspaceCall(
    kind="workspace_call",
    protocol_version="1.0",
    call_id=new_id(IdKind.CONTROL_RPC),
    service_instance_id=SERVICE_ID,
    service_generation="1",
    operation="read_task_base",
    arguments=JsonObject({"workspace": _HANDLE}),
    deadline_ms=5_000,
)


def _sink(received: list[WorkspaceCall]) -> Callable[[WorkspaceCall], Awaitable[None]]:
    async def write(call: WorkspaceCall) -> None:
        received.append(call)

    return write


def _background_declaration() -> WorkspaceAgentDeclaration:
    return replace(AGENT_DECLARATION, role="background")


async def test_an_agent_takes_pushed_calls_sends_replies_and_ends_with_its_connection() -> None:
    fake = _AgentDaemon()
    tasks: list[asyncio.Task[None]] = []

    async def connect() -> ControlStream:
        client, server = memory_pair()
        tasks.append(asyncio.create_task(fake.serve(server)))
        return client

    backend = ControlSocketBackend(connect=connect)
    received: list[WorkspaceCall] = []
    handle = await backend.register_agent(
        client_kind=ControlClientKind.MCP_BRIDGE,
        claim=_CLAIM,
        declaration=_background_declaration(),
        revision=TEST_REVISION,
        writer=_sink(received),
    )
    assert handle.workspace_handle == _HANDLE
    assert fake.declared_role == "background"
    await _until(lambda: received)
    assert received[0].call_id == _CALL.call_id
    reply = WorkspaceReply(
        kind="workspace_reply",
        protocol_version="1.0",
        call_id=_CALL.call_id,
        outcome="refused",
        result=None,
        reason="arguments_invalid",
    )
    await handle.deliver(reply)
    await asyncio.wait_for(fake.replied.wait(), timeout=10)
    assert fake.replies[0]["call_id"] == _CALL.call_id
    # The service side goes (a restart under a new generation): the agent is gone.
    assert fake.server is not None
    await fake.server.aclose()
    await asyncio.wait_for(handle.ended.wait(), timeout=10)
    await handle.close()
    await asyncio.gather(*tasks, return_exceptions=True)


async def test_no_agent_registers_while_the_service_cannot_key_the_claim() -> None:
    daemon = ScriptedDaemon()  # no claim handle: a locked vault keys nothing
    backend = ControlSocketBackend(connect=_served(daemon))
    with pytest.raises(BackendRefusal) as refused:
        await backend.register_agent(
            client_kind=ControlClientKind.MCP_BRIDGE,
            claim=_CLAIM,
            declaration=AGENT_DECLARATION,
            revision=TEST_REVISION,
            writer=_sink([]),
        )
    assert refused.value.reason == "workspace_agent_unavailable"


def test_the_gateway_imports_no_vault_storage_or_daemon_module() -> None:
    forbidden = (
        "finishup.service.daemon",
        "finishup.service.vault",
        "finishup.service.rest_native",
        "finishup.adapters.keys",
        "finishup.adapters.sqlite",
        "finishup.kernel",
        "finishup.application",
    )
    for path in (_SRC / "gateway").glob("*.py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                names = [node.module]
            for name in names:
                assert not name.startswith(forbidden), (path.name, name)


async def test_the_admission_is_a_hello_that_names_only_the_revision() -> None:
    """A1-1: the routes ask before they read a body; the service refuses a stale revision."""

    daemon = ScriptedDaemon()
    backend = ControlSocketBackend(connect=_served(daemon))
    await backend.admit(
        client_kind=ControlClientKind.CLI, revision=TEST_REVISION, start_service=True
    )
    assert daemon.connections == 1 and len(daemon.received(-1)) == 1
    with pytest.raises(BackendRefusal) as refused:
        await backend.admit(client_kind=ControlClientKind.CLI, revision=_STALE, start_service=True)
    assert refused.value.reason == "server_profile_changed"
    assert daemon.claims == []


async def test_a_call_cancelled_whose_result_never_comes_has_an_unknown_outcome() -> None:
    """A2-2: once the call frame was written, a cancel answered by no result (here the service
    ends the connection) is ``request_timeout``, never a definite ``request_cancelled``."""

    daemon = ScriptedDaemon()
    daemon.hold_calls = True
    backend = ControlSocketBackend(connect=_served(daemon))
    call = call_request(0x2A, ControlMethod.RECEIPT)
    task = asyncio.create_task(
        backend.dispatch(
            client_kind=ControlClientKind.CLI,
            call=call,
            claim=None,
            revision=TEST_REVISION,
            start_service=True,
        )
    )
    await asyncio.wait_for(daemon.held.wait(), timeout=10)
    task.cancel()
    result = await asyncio.wait_for(task, timeout=10)
    assert result.outcome == "error" and result.rpc_id == call.rpc_id
    assert isinstance(result.body, ControlError) and result.body.reason == "request_timeout"


async def _registered(
    daemon: ScriptedDaemon, received: list[WorkspaceCall]
) -> tuple[ControlSocketBackend, AgentHandle]:
    daemon.claim_handle = _HANDLE
    backend = ControlSocketBackend(connect=_served(daemon))
    handle = await backend.register_agent(
        client_kind=ControlClientKind.CLI,
        claim=_CLAIM,
        declaration=AGENT_DECLARATION,
        revision=TEST_REVISION,
        writer=_sink(received),
    )
    return backend, handle


async def test_a_call_naming_the_agent_runs_on_that_agents_own_connection() -> None:
    """A1-4: the service sees the call on the connection whose hello declared the agent, so it
    offers that agent the call's workspace operations first (``live_call_scope``)."""

    daemon = ScriptedDaemon()
    received: list[WorkspaceCall] = []
    backend, handle = await _registered(daemon, received)
    call = call_request(0x0A, ControlMethod.SERVICE_STATUS)
    result = await backend.dispatch(
        client_kind=ControlClientKind.CLI,
        call=call,
        claim=_CLAIM,
        revision=TEST_REVISION,
        start_service=True,
        agent=handle,
    )
    assert result.outcome == "ok" and result.rpc_id == call.rpc_id
    assert daemon.connections == 1
    frames = daemon.received(0)
    assert len(frames) == 2 and b'"kind":"call"' in frames[1]
    # The service's workspace call on that connection still reaches the agent's queue.
    await _until(lambda: received)
    await handle.close()
    with pytest.raises(BackendRefusal) as refused:
        await backend.dispatch(
            client_kind=ControlClientKind.CLI,
            call=call_request(0x0B, ControlMethod.SERVICE_STATUS),
            claim=_CLAIM,
            revision=TEST_REVISION,
            start_service=True,
            agent=handle,
        )
    assert refused.value.reason == "agent_unknown"
    await asyncio.gather(*daemon.serving, return_exceptions=True)


async def test_a_call_on_an_agents_connection_that_ends_has_an_unknown_outcome() -> None:
    """A1-4 with A2-2: written on the agent's connection, then the connection ended without
    its result: ``request_timeout``."""

    daemon = ScriptedDaemon()
    daemon.hold_calls = True
    backend, handle = await _registered(daemon, [])
    call = call_request(0x0C, ControlMethod.RECEIPT)
    task = asyncio.create_task(
        backend.dispatch(
            client_kind=ControlClientKind.CLI,
            call=call,
            claim=_CLAIM,
            revision=TEST_REVISION,
            start_service=True,
            agent=handle,
        )
    )
    await asyncio.wait_for(daemon.held.wait(), timeout=10)
    task.cancel()
    result = await asyncio.wait_for(task, timeout=10)
    assert isinstance(result.body, ControlError) and result.body.reason == "request_timeout"
    await handle.close()
    await asyncio.gather(*daemon.serving, return_exceptions=True)


async def test_an_ended_agents_handle_is_let_go() -> None:
    """A2-3: a deleted or expired registration leaves nothing behind in the backend."""

    daemon = ScriptedDaemon()
    backend, handle = await _registered(daemon, [])
    assert len(backend._handles) == 1  # pyright: ignore[reportPrivateUsage]
    await handle.close()
    assert len(backend._handles) == 0  # pyright: ignore[reportPrivateUsage]
    await asyncio.gather(*daemon.serving, return_exceptions=True)
