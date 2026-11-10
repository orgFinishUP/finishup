"""The frame-to-REST mapping state machine (ADR-053, design v2 section 8.4).

A ``ServiceClient`` runs over a ``RestControlStream`` to the real REST routes (``rest.app``) with a
scripted backend, over ``httpx``'s ASGI transport: the hello becomes the session and the agent's
registration, calls map to operations (``202`` long-polled), a cancel follows its call's admission,
pushed workspace calls reach the client's agent and its reply reaches the service. Scripted
transports cover what a real server rarely does on cue: answers lost (the same operation id sent
again), an operation whose answer is gone (``request_timeout``), an agent the server forgot (the
stream ends), and a close that sends nothing under zero-network and never waits past its bound.
"""

from __future__ import annotations

import asyncio
import os
import shutil
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

from builders.rest_backend import AGENT_DECLARATION, STATUS, ScriptedRestBackend
from builders.server_profiles import TEST_REVISION
from finishup.client.rest_client import RestAnswer, RestTransport, RestUnavailable
from finishup.client.rest_stream import RestControlStream
from finishup.domain.values import JsonObject
from finishup.ports.control import (
    ControlCallRequest,
    ControlClientKind,
    ControlError,
    ControlMethod,
    WorkspaceCall,
    WorkspaceClaim,
    WorkspaceReply,
)
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.server_profile import ServerProfileRevision
from finishup.rest.api_keys import ApiKeyStore
from finishup.rest.app import RestApp
from finishup.rest.contract import claim_for_principal
from finishup.service.client import ClientWorkspaceBinding, ServiceClient, connect_service_via
from finishup.service.control_protocol import (
    client_handshake,
    encode_control_frame,
    read_control_frame,
)

pytestmark = pytest.mark.anyio

_CLAIM = WorkspaceClaim(
    identity_kind="git_common_root", digest="sha256:" + "a" * 64, worktree="sha256:" + "b" * 64
)


class _Admitted:
    """An admission that refuses nothing (the authorization's own checks are layer 2's)."""

    server_profile = TEST_REVISION

    def refusal(self) -> str | None:
        return None


class _Agent:
    """A connection's agent that refuses every call (its reply is what the test follows)."""

    declaration = AGENT_DECLARATION

    def answer(self, call: WorkspaceCall, *, workspace_handle: str | None) -> WorkspaceReply:
        del workspace_handle
        return WorkspaceReply(
            kind="workspace_reply",
            protocol_version="1.0",
            call_id=call.call_id,
            outcome="refused",
            result=None,
            reason="arguments_invalid",
        )


@dataclass
class _Edge:
    backend: ScriptedRestBackend
    app: RestApp
    key: str
    principal: str

    def transport(self) -> RestTransport:
        return RestTransport(
            "https://edge.test",
            key=self.key,
            transport=httpx.ASGITransport(app=self.app.asgi()),
        )

    async def connect(
        self,
        *,
        binding: ClientWorkspaceBinding | None = None,
        may_send: Callable[[], bool] | None = None,
    ) -> tuple[ServiceClient, RestControlStream]:
        streams: list[RestControlStream] = []

        async def dial() -> RestControlStream:
            stream = RestControlStream(self.transport(), may_send=may_send, owns_transport=True)
            streams.append(stream)
            return stream

        client = await connect_service_via(
            dial,
            ControlClientKind.CLI,
            workspace_binding=binding,
            authorization=cast(Any, _Admitted()),
            transport="https",
        )
        return client, streams[0]


@pytest.fixture
def keys_dir() -> Iterator[Path]:
    base = Path.home() / f".yz-rest-stream-{os.getpid()}-{id(object())}"
    base.mkdir(mode=0o700)
    try:
        yield base
    finally:
        shutil.rmtree(base, ignore_errors=True)


@pytest.fixture
async def edge(keys_dir: Path) -> AsyncIterator[_Edge]:
    keys = ApiKeyStore(keys_dir / "rest")
    record, key = keys.create("bridge", "agent")
    backend = ScriptedRestBackend()
    app = RestApp(backend, keys)
    yield _Edge(backend, app, key, record.principal)
    await app.aclose()


def _call(method: ControlMethod = ControlMethod.SERVICE_STATUS) -> ControlCallRequest:
    return ControlCallRequest(
        kind="call",
        protocol_version="1.0",
        rpc_id=new_id(IdKind.CONTROL_RPC),
        service_instance_id=STATUS.service_instance_id,
        service_generation=STATUS.service_generation,
        method=method,
        body=JsonObject({}),
        deadline_ms=20_000,
    )


async def _until(condition: Callable[[], object], seconds: float = 10.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + seconds
    while not condition():
        assert loop.time() < deadline, "condition not reached"
        await asyncio.sleep(0)


async def test_a_hello_becomes_the_session_and_a_call_its_operation(edge: _Edge) -> None:
    client, stream = await edge.connect()
    try:
        assert stream.state == "open"
        status = await client.service_status()
        assert status.service_instance_id == STATUS.service_instance_id
        ((kind, claim),) = edge.backend.sessions
        assert kind is ControlClientKind.CLI and claim is None
    finally:
        await client.close()


async def test_a_claim_and_its_agent_register_and_pushed_calls_reach_the_agent(
    edge: _Edge,
) -> None:
    binding = ClientWorkspaceBinding(claim=_CLAIM, agent=cast(Any, _Agent()))
    client, _stream = await edge.connect(binding=binding)
    try:
        (recorded,) = edge.backend.agents
        assert recorded.claim == claim_for_principal(_CLAIM, edge.principal)
        call = WorkspaceCall(
            kind="workspace_call",
            protocol_version="1.0",
            call_id=new_id(IdKind.CONTROL_RPC),
            service_instance_id=STATUS.service_instance_id,
            service_generation=STATUS.service_generation,
            operation="inspect",
            arguments=JsonObject({"opaque": True}),
            deadline_ms=5_000,
        )
        await recorded.writer(call)
        await _until(lambda: recorded.replies)
        assert recorded.replies[0].call_id == call.call_id
        assert recorded.replies[0].reason == "arguments_invalid"
    finally:
        await client.close()
    await _until(lambda: recorded.closed)


async def test_a_stale_revision_ends_the_hello_before_any_agent_or_call(edge: _Edge) -> None:
    edge.backend.revision = ServerProfileRevision(TEST_REVISION.issuer, 4, "sha256:" + "c" * 64)
    binding = ClientWorkspaceBinding(claim=_CLAIM, agent=cast(Any, _Agent()))
    with pytest.raises(ControlError) as refused:
        await edge.connect(binding=binding)
    assert refused.value.phase == "server_profile_changed"
    assert edge.backend.agents == [] and edge.backend.calls == []


async def test_a_hello_naming_a_path_is_never_sent(edge: _Edge) -> None:
    from finishup.ports.control import WorkspaceLocator

    stream = RestControlStream(edge.transport(), owns_transport=True)
    with pytest.raises(Exception):  # noqa: B017, PT011 - the hello is not answered
        await client_handshake(
            stream,
            ControlClientKind.CLI,
            "0.3.0",
            workspace_locator=WorkspaceLocator("/srv/work/project"),
        )
    assert edge.backend.sessions == []
    assert await stream.failure_phase() is None
    await stream.aclose()


async def test_a_long_call_is_long_polled_and_its_cancel_follows_its_admission(
    edge: _Edge,
) -> None:
    edge.backend.gate = asyncio.Event()
    client, _stream = await edge.connect()
    try:
        long = asyncio.create_task(client.call(_call()))
        await _until(lambda: edge.backend.calls)
        long.cancel()
        with pytest.raises(asyncio.CancelledError):
            await long
        await _until(lambda: edge.backend.cancelled)
        assert edge.backend.cancelled == [edge.backend.calls[0][0].rpc_id]
        edge.backend.gate = None
        # The connection goes on serving after the cancel.
        status = await client.service_status()
        assert status.service_generation == STATUS.service_generation
    finally:
        await client.close()


# --- scripted transports -----------------------------------------------------------------------


class _Scripted(RestTransport):
    """Answers each request from ``script`` (a callable per request) and records it."""

    def __init__(
        self, script: Callable[[str, str, Mapping[str, str]], Awaitable[RestAnswer]]
    ) -> None:
        super().__init__("https://scripted.test", key="fuk_test")
        self.script = script
        self.sent: list[tuple[str, str, Mapping[str, str]]] = []
        # Per request: its ``wait_ms`` (or None) and its own time bound (or None).
        self.bounds: list[tuple[str | None, float | None]] = []

    async def request(  # type: ignore[override]
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
        content: bytes | None = None,
        params: Mapping[str, str] | None = None,
        poll: bool = False,
        limit: int = 0,
        seconds: float | None = None,
    ) -> RestAnswer:
        del content, poll, limit
        self.sent.append((method, path, dict(headers or {})))
        self.bounds.append(((params or {}).get("wait_ms"), seconds))
        return await self.script(method, path, dict(headers or {}))


def _session_answer() -> RestAnswer:
    from finishup.rest.contract import Session, session_document

    return RestAnswer(200, {}, session_document(Session(STATUS, "none", None, TEST_REVISION)))


def _error(status: int, reason: str) -> RestAnswer:
    from finishup.rest.contract import rest_error_document

    return RestAnswer(status, {}, rest_error_document(reason))


async def _open(stream: RestControlStream) -> None:
    await client_handshake(stream, ControlClientKind.CLI, "0.3.0", server_profile=TEST_REVISION)


async def _result_of(stream: RestControlStream) -> dict[str, Any]:
    frame = await asyncio.wait_for(read_control_frame(stream), timeout=10)
    return dict(frame)


async def test_a_lost_answer_is_sent_again_with_the_same_operation_id_then_is_unknown() -> None:
    async def script(method: str, path: str, headers: Mapping[str, str]) -> RestAnswer:
        del method, headers
        if path == "/v1/session":
            return _session_answer()
        raise RestUnavailable("remote_unreachable")

    transport = _Scripted(script)
    stream = RestControlStream(transport)
    await _open(stream)
    call = _call()
    await stream.send_all(encode_control_frame(call))
    result = await _result_of(stream)
    assert result["rpc_id"] == call.rpc_id
    assert cast(Mapping[str, Any], result["body"])["code"] == "request_timeout"
    posts = [headers for method, _path, headers in transport.sent if method == "POST"]
    assert len(posts) == 3
    assert {headers["finishup-operation-id"] for headers in posts} == {call.rpc_id}
    assert await stream.failure_phase() == "remote_unreachable"
    assert await stream.receive(1) == b""
    await stream.aclose()


async def test_an_operation_whose_answer_is_gone_is_request_timeout() -> None:
    from finishup.rest.contract import operation_pending_document

    async def script(method: str, path: str, headers: Mapping[str, str]) -> RestAnswer:
        if path == "/v1/session":
            return _session_answer()
        if method == "POST":
            return RestAnswer(202, {}, operation_pending_document(headers["finishup-operation-id"]))
        return _error(404, "operation_unknown")

    stream = RestControlStream(_Scripted(script))
    await _open(stream)
    call = _call()
    await stream.send_all(encode_control_frame(call))
    result = await _result_of(stream)
    assert cast(Mapping[str, Any], result["body"])["code"] == "request_timeout"
    await stream.aclose()


async def test_a_refused_revision_on_a_call_is_its_server_profile_changed_result() -> None:
    async def script(method: str, path: str, headers: Mapping[str, str]) -> RestAnswer:
        del method, headers
        if path == "/v1/session":
            return _session_answer()
        return _error(409, "server_profile_changed")

    stream = RestControlStream(_Scripted(script))
    await _open(stream)
    await stream.send_all(encode_control_frame(_call()))
    result = await _result_of(stream)
    assert cast(Mapping[str, Any], result["body"])["code"] == "server_profile_changed"
    await stream.aclose()


async def test_an_agent_the_server_forgot_ends_the_stream() -> None:
    from finishup.rest.contract import (
        AgentRegistration,
        Session,
        agent_registration_document,
        session_document,
    )

    async def script(method: str, path: str, headers: Mapping[str, str]) -> RestAnswer:
        del headers
        if path == "/v1/session":
            return RestAnswer(
                200,
                {},
                session_document(
                    Session(STATUS, "client_claim", "client:0123456789abcdef", TEST_REVISION)
                ),
            )
        if method == "POST" and path == "/v1/agents":
            return RestAnswer(
                201,
                {},
                agent_registration_document(
                    AgentRegistration("agt_" + "0" * 32, "client:0123456789abcdef", 60_000)
                ),
            )
        return _error(404, "agent_unknown")

    stream = RestControlStream(_Scripted(script))
    await client_handshake(
        stream,
        ControlClientKind.MCP_BRIDGE,
        "0.3.0",
        workspace_claim=_CLAIM,
        workspace_agent=AGENT_DECLARATION,
        server_profile=TEST_REVISION,
    )
    assert await asyncio.wait_for(stream.receive(1), timeout=10) == b""
    await stream.aclose()


async def test_close_sends_nothing_under_zero_network_and_never_waits_past_its_bound() -> None:
    from finishup.rest.contract import operation_pending_document

    hold = asyncio.Event()

    async def script(method: str, path: str, headers: Mapping[str, str]) -> RestAnswer:
        if path == "/v1/session":
            return _session_answer()
        if method == "POST":
            return RestAnswer(202, {}, operation_pending_document(headers["finishup-operation-id"]))
        await hold.wait()  # a black-holed network: no poll and no DELETE ever answers
        raise RestUnavailable("remote_unreachable")

    for allowed in (False, True):
        transport = _Scripted(script)
        sending = {"now": True}
        stream = RestControlStream(transport, may_send=lambda sending=sending: sending["now"])
        await _open(stream)
        await stream.send_all(encode_control_frame(_call()))
        await _until(
            lambda transport=transport: any(
                path.startswith("/v1/operations/") for _m, path, _h in transport.sent
            )
        )
        # This computer reports zero-network now (or not): what the close may send follows it.
        sending["now"] = allowed
        loop = asyncio.get_running_loop()
        started = loop.time()
        await stream.aclose()
        assert loop.time() - started < 3.0
        deletes = [path for method, path, _headers in transport.sent if method == "DELETE"]
        assert bool(deletes) is allowed


# --- review fixes (layer 5 review) --------------------------------------------------------------


async def test_a_call_names_the_connections_own_agent(edge: _Edge) -> None:
    """A1-4: once the hello registered the agent, every call carries it, so the server gives
    the call's workspace operations to this connection's agent first."""

    binding = ClientWorkspaceBinding(claim=_CLAIM, agent=cast(Any, _Agent()))
    client, _stream = await edge.connect(binding=binding)
    try:
        (recorded,) = edge.backend.agents
        await client.service_status()
        assert edge.backend.call_agents == [recorded.handle]
    finally:
        await client.close()
    plain, _stream = await edge.connect()
    try:
        await plain.service_status()
        assert edge.backend.call_agents == [recorded.handle, None]
    finally:
        await plain.close()


def _registration_script(
    sending: dict[str, bool],
) -> Callable[[str, str, Mapping[str, str]], Awaitable[RestAnswer]]:
    from finishup.rest.contract import (
        AgentRegistration,
        Session,
        agent_registration_document,
        session_document,
    )

    async def script(method: str, path: str, headers: Mapping[str, str]) -> RestAnswer:
        del headers
        if path == "/v1/session":
            # The authorization changes while the session's answer is on its way.
            sending["now"] = False
            return RestAnswer(
                200,
                {},
                session_document(
                    Session(STATUS, "client_claim", "client:0123456789abcdef", TEST_REVISION)
                ),
            )
        if method == "POST" and path == "/v1/agents":
            return RestAnswer(
                201,
                {},
                agent_registration_document(
                    AgentRegistration("agt_" + "0" * 32, "client:0123456789abcdef", 60_000)
                ),
            )
        return _error(404, "route_unknown")

    return script


@pytest.mark.parametrize("how", ["may_send", "bound"])
async def test_the_agents_registration_is_never_sent_once_the_authorization_refuses(
    how: str,
) -> None:
    """B2 (and B3's binding): a lapse, a hold or zero-network that lands while ``/v1/session``
    is answered stops the registration; neither the key nor the claim is sent again."""

    sending = {"now": True}
    transport = _Scripted(_registration_script(sending))
    if how == "may_send":
        stream = RestControlStream(transport, may_send=lambda: sending["now"])
    else:
        stream = RestControlStream(transport)
        stream.bind(lambda: None if sending["now"] else "repository_egress_held")
    from finishup.service.control_protocol import ControlProtocolError

    with pytest.raises(ControlProtocolError):
        # The hello is never answered: the stream ends before the agent is registered.
        await asyncio.wait_for(
            client_handshake(
                stream,
                ControlClientKind.MCP_BRIDGE,
                "0.3.0",
                workspace_claim=_CLAIM,
                workspace_agent=AGENT_DECLARATION,
                server_profile=TEST_REVISION,
            ),
            timeout=10,
        )
    assert [(method, path) for method, path, _headers in transport.sent] == [("GET", "/v1/session")]
    expected = "server_authorization_changed" if how == "may_send" else "repository_egress_held"
    assert await stream.failure_phase() == expected
    await stream.aclose()


async def test_a_call_never_sends_or_waits_past_its_own_deadline() -> None:
    """B5: one absolute deadline across the POST's retries, the waits between them and every
    request's own bound; no POST is sent again after it, and the outcome is unknown."""

    loop = asyncio.get_running_loop()
    posted: list[float] = []

    async def script(method: str, path: str, headers: Mapping[str, str]) -> RestAnswer:
        del headers
        if path == "/v1/session":
            return _session_answer()
        if method == "POST":
            posted.append(loop.time())
        raise RestUnavailable("remote_unreachable")

    transport = _Scripted(script)
    stream = RestControlStream(transport)
    await _open(stream)
    call = replace(_call(), deadline_ms=400)
    started = loop.time()
    await stream.send_all(encode_control_frame(call))
    result = await _result_of(stream)
    assert cast(Mapping[str, Any], result["body"])["code"] == "request_timeout"
    assert posted and all(at - started < 0.4 for at in posted)
    assert len(posted) < 3
    post_bounds = [
        bound
        for (method, _path, _h), bound in zip(transport.sent, transport.bounds, strict=True)
        if method == "POST"
    ]
    assert all(seconds is not None and seconds <= 0.4 for _wait, seconds in post_bounds)
    await stream.aclose()


async def test_a_long_poll_never_waits_past_the_calls_deadline() -> None:
    """B5: the polls' ``wait_ms`` and bounds shrink with what is left of the deadline, and the
    call ends ``request_timeout`` at it instead of polling on."""

    from finishup.rest.contract import operation_pending_document

    async def script(method: str, path: str, headers: Mapping[str, str]) -> RestAnswer:
        if path == "/v1/session":
            return _session_answer()
        operation = headers.get("finishup-operation-id") or path.rsplit("/", 1)[-1]
        # A server that keeps the long-poll open as long as it was asked to, then says pending.
        wait = transport.bounds[-1][0]
        await asyncio.sleep(int(wait or "0") / 1000)
        del method
        return RestAnswer(202, {}, operation_pending_document(operation))

    transport = _Scripted(script)
    stream = RestControlStream(transport)
    await _open(stream)
    call = replace(_call(), deadline_ms=1_500)
    await stream.send_all(encode_control_frame(call))
    result = await _result_of(stream)
    assert cast(Mapping[str, Any], result["body"])["code"] == "request_timeout"
    waits = [int(wait) for wait, _seconds in transport.bounds if wait is not None]
    assert waits and all(wait <= 1_500 for wait in waits)
    assert all(seconds is not None and seconds <= 1.5 for _w, seconds in transport.bounds[1:])
    await stream.aclose()


async def test_a_cancel_refused_before_admission_is_sent_again_whatever_the_answer_order() -> None:
    """B6: the DELETE leaves before the POST is admitted, the POST's ``202`` comes back first,
    then the DELETE's ``operation_unknown``: the cancel is sent again, and the call stops."""

    from finishup.rest.contract import operation_pending_document

    delete_sent = asyncio.Event()
    polled = asyncio.Event()
    second_delete = asyncio.Event()
    deletes: list[str] = []

    async def script(method: str, path: str, headers: Mapping[str, str]) -> RestAnswer:
        if path == "/v1/session":
            return _session_answer()
        if method == "POST":
            await delete_sent.wait()
            return RestAnswer(202, {}, operation_pending_document(headers["finishup-operation-id"]))
        if method == "DELETE":
            deletes.append(path)
            if len(deletes) == 1:
                delete_sent.set()
                await polled.wait()  # the 202 was taken (the poll began) before this answer
                return _error(404, "operation_unknown")
            second_delete.set()
            return RestAnswer(204, {}, b"")
        polled.set()
        await second_delete.wait()
        return RestAnswer(
            200,
            {
                "finishup-outcome": "error",
                "finishup-service-instance": STATUS.service_instance_id,
                "finishup-service-generation": STATUS.service_generation,
            },
            b'{"code":"request_cancelled","retryable":true}',
        )

    from finishup.ports.control import ControlCancelRequest

    stream = RestControlStream(_Scripted(script))
    await _open(stream)
    call = _call()
    cancel = ControlCancelRequest(
        kind="cancel",
        protocol_version="1.0",
        rpc_id=new_id(IdKind.CONTROL_RPC),
        service_instance_id=call.service_instance_id,
        service_generation=call.service_generation,
        target_rpc_id=call.rpc_id,
    )
    await stream.send_all(encode_control_frame(call) + encode_control_frame(cancel))
    result = await _result_of(stream)
    assert cast(Mapping[str, Any], result["body"])["code"] == "request_cancelled"
    assert deletes == [f"/v1/operations/{call.rpc_id}"] * 2
    await stream.aclose()


# --- review fixes, second round -------------------------------------------------------------------


async def test_close_asks_again_after_it_awaited_the_cancellations() -> None:
    """B2: a logout (here: the stream's authorization refusing) that lands while the close awaits
    its running requests' cancellation sends no courtesy DELETE under the key the stream holds."""

    from finishup.rest.contract import operation_pending_document

    sending = {"now": True}

    async def script(method: str, path: str, headers: Mapping[str, str]) -> RestAnswer:
        if path == "/v1/session":
            return _session_answer()
        if method == "POST":
            return RestAnswer(202, {}, operation_pending_document(headers["finishup-operation-id"]))
        if method == "GET":
            try:
                await asyncio.Event().wait()  # the poll stays under way until the close
            finally:
                sending["now"] = False  # the owner's logout lands while it is cancelled
        return RestAnswer(204, {}, b"")

    transport = _Scripted(script)
    stream = RestControlStream(transport, may_send=lambda: sending["now"])
    await _open(stream)
    await stream.send_all(encode_control_frame(_call()))
    await _until(lambda: any(path.startswith("/v1/operations/") for _m, path, _h in transport.sent))
    assert sending["now"]
    await stream.aclose()
    assert not sending["now"]
    assert [path for method, path, _headers in transport.sent if method == "DELETE"] == []
