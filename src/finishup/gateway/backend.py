"""The control-socket REST backend of the gateway process (ADR-053, design v2 section 8.4).

Every REST request re-enters this server's service over its owner-only control socket as an
ordinary, peer-authenticated control connection of the service's own user, so the gateway never
holds the installation MAC, a vault handle or any storage:

* **session** — a hello naming the request's claim (already namespaced by the key's principal) and
  its consented revision; the service answers its status, the claim's handle and the revision, or
  refuses a stale revision before the claim is keyed (``server_profile_changed``); the connection
  then closes;
* **call** — its own claim-bound connection: the hello, then the call frame (its rpc id is the
  REST operation id), then frames until its result. The service binds the call to the hello's
  revision and refuses work once it issues another. A cancel is written on that same connection
  **after** the call frame, never before (cancellation order); a call cancelled before its frame
  was written never reached the service and answers ``request_cancelled``;
* **agent** — one long-lived claim-bound connection whose hello declares the agent (its role
  included): each ``workspace_call`` frame the service sends is handed to the REST agent's queue;
  each reply is written back as ``workspace_reply``. When the connection ends (the service
  stopped, restarted under a new generation, or closed it), the agent is gone and its next poll
  answers ``agent_unknown``: the gateway follows generation changes;
* **profile** — an owner hello and the ``server_profile`` method.

An open connection holds the service's idle shutdown like any client's. The service is started on
demand for a client's request (the sanctioned ``connect_service_on_demand`` path), never for a
``background`` agent, so a service its owner stopped stays stopped until a client asks.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from typing import Final, cast

from finishup import __version__
from finishup.adapters.control.unix_socket import LocalControlTransportError, connect_control
from finishup.domain.values import JsonObject
from finishup.ports.control import (
    ControlCallRequest,
    ControlCancelRequest,
    ControlClientKind,
    ControlError,
    ControlMethod,
    ControlResult,
    WorkspaceAgentDeclaration,
    WorkspaceCall,
    WorkspaceClaim,
    WorkspaceReply,
)
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.server_profile import (
    ProfileError,
    ServerProfile,
    ServerProfileRevision,
    profile_from_json,
)
from finishup.rest.backend import AgentHandle, BackendRefusal, Edge
from finishup.rest.contract import Session
from finishup.service.control_protocol import (
    ControlProtocolError,
    ControlSession,
    ControlStream,
    client_handshake,
    is_workspace_call_frame,
    parse_control_result,
    parse_workspace_call,
    read_control_frame,
    write_control_frame,
    write_workspace_reply,
)

__all__ = ["ControlSocketBackend"]

_EDGE: Final[Edge] = "gateway"
# How long a cancelled call's own result is awaited once the cancel was written.
_CANCEL_SECONDS: Final = 5.0
_HELLO_SECONDS: Final = 10.0


async def _start_service() -> None:
    """Start this root's service through the sanctioned on-demand path, then let it go."""

    from finishup.service.client import connect_service_on_demand

    client = await connect_service_on_demand(ControlClientKind.CLI)
    await client.close()


async def _close(stream: ControlStream) -> None:
    with contextlib.suppress(Exception):
        await stream.aclose()


class ControlSocketBackend:
    """The gateway's backend (see the module text)."""

    def __init__(
        self,
        *,
        connect: Callable[[], Awaitable[ControlStream]] | None = None,
        start: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        self._connect = connect or connect_control
        self._start = start or _start_service
        self._handles: list[AgentHandle] = []
        self._tasks: set[asyncio.Task[None]] = set()

    def __repr__(self) -> str:
        return "ControlSocketBackend(<redacted>)"

    @property
    def edge(self) -> Edge:
        return _EDGE

    async def _open(self, *, start_service: bool) -> ControlStream:
        try:
            return await self._connect()
        except (LocalControlTransportError, OSError):
            if not start_service:
                raise BackendRefusal("service_unavailable") from None
        try:
            await self._start()
            return await self._connect()
        except Exception:  # noqa: BLE001 - a service that cannot be started is unavailable
            raise BackendRefusal("service_unavailable") from None

    async def _hello(
        self,
        stream: ControlStream,
        client_kind: ControlClientKind,
        *,
        claim: WorkspaceClaim | None,
        agent: WorkspaceAgentDeclaration | None,
        revision: ServerProfileRevision | None,
    ) -> ControlSession:
        try:
            async with asyncio.timeout(_HELLO_SECONDS):
                return await client_handshake(
                    stream,
                    client_kind,
                    __version__,
                    workspace_claim=claim,
                    workspace_agent=agent,
                    server_profile=revision,
                )
        except ControlProtocolError as error:
            await _close(stream)
            if error.reason == "server_profile_changed":
                # The service refused the revision before keying the claim (ADR-052).
                raise BackendRefusal("server_profile_changed") from None
            raise BackendRefusal("service_unavailable") from None
        except (LocalControlTransportError, TimeoutError, OSError):
            await _close(stream)
            raise BackendRefusal("service_unavailable") from None

    @staticmethod
    async def _result_of(stream: ControlStream, rpc_id: str) -> ControlResult:
        while True:
            frame = await read_control_frame(stream, eof_reason="session_closed")
            if is_workspace_call_frame(frame):
                continue
            result = parse_control_result(frame)
            if result.rpc_id == rpc_id:
                return result

    async def profile(self) -> ServerProfile:
        stream = await self._open(start_service=True)
        try:
            session = await self._hello(
                stream, ControlClientKind.CLI, claim=None, agent=None, revision=None
            )
            request = ControlCallRequest(
                kind="call",
                protocol_version="1.0",
                rpc_id=new_id(IdKind.CONTROL_RPC),
                service_instance_id=session.service_instance_id,
                service_generation=session.service_generation,
                method=ControlMethod.SERVER_PROFILE,
                body=JsonObject({}),
            )
            try:
                await write_control_frame(stream, request)
                result = await self._result_of(stream, request.rpc_id)
            except (ControlProtocolError, LocalControlTransportError, OSError):
                raise BackendRefusal("service_unavailable") from None
            if result.outcome != "ok":
                raise BackendRefusal("service_unavailable")
            try:
                return profile_from_json(canonical_encode(cast(JsonValue, result.body)))
            except ProfileError:
                raise BackendRefusal("internal_failure") from None
        finally:
            await _close(stream)

    async def session(
        self,
        *,
        client_kind: ControlClientKind,
        claim: WorkspaceClaim | None,
        revision: ServerProfileRevision,
    ) -> Session:
        stream = await self._open(start_service=True)
        try:
            session = await self._hello(
                stream, client_kind, claim=claim, agent=None, revision=revision
            )
        finally:
            await _close(stream)
        status = session.service_status
        if status is None or session.server_profile is None:
            raise BackendRefusal("service_unavailable")
        return Session(
            status,
            "client_claim" if claim is not None else "none",
            session.workspace_handle,
            session.server_profile,
        )

    async def dispatch(
        self,
        *,
        client_kind: ControlClientKind,
        call: ControlCallRequest,
        claim: WorkspaceClaim | None,
        revision: ServerProfileRevision,
        start_service: bool,
    ) -> ControlResult:
        sent = False
        stream: ControlStream | None = None
        try:
            stream = await self._open(start_service=start_service)
            await self._hello(stream, client_kind, claim=claim, agent=None, revision=revision)
            await write_control_frame(stream, call)
            sent = True
            reader = asyncio.ensure_future(self._result_of(stream, call.rpc_id))
            try:
                return await asyncio.shield(reader)
            except asyncio.CancelledError:
                # Cancellation order: the call frame is already on this connection; the cancel
                # follows it there, and the call's own result is still the answer.
                cancel = ControlCancelRequest(
                    kind="cancel",
                    protocol_version="1.0",
                    rpc_id=new_id(IdKind.CONTROL_RPC),
                    service_instance_id=call.service_instance_id,
                    service_generation=call.service_generation,
                    target_rpc_id=call.rpc_id,
                )
                with contextlib.suppress(Exception):
                    await write_control_frame(stream, cancel)
                try:
                    return await asyncio.wait_for(reader, _CANCEL_SECONDS)
                except Exception:  # noqa: BLE001 - no result in time: it stopped as far as we know
                    reader.cancel()
                    return _error(call, ControlError("request_cancelled", retryable=True))
        except asyncio.CancelledError:
            if not sent:
                # Cancelled before its frame was written: it never reached the service.
                return _error(call, ControlError("request_cancelled", retryable=True))
            raise
        except (ControlProtocolError, LocalControlTransportError, OSError):
            if not sent:
                raise BackendRefusal("service_unavailable") from None
            # Sent, then the connection ended without its result: the outcome is unknown.
            return _error(call, ControlError("request_timeout", retryable=True))
        finally:
            if stream is not None:
                await _close(stream)

    async def register_agent(
        self,
        *,
        client_kind: ControlClientKind,
        claim: WorkspaceClaim,
        declaration: WorkspaceAgentDeclaration,
        revision: ServerProfileRevision,
        writer: Callable[[WorkspaceCall], Awaitable[None]],
    ) -> AgentHandle:
        # A background agent never starts a service its owner stopped.
        stream = await self._open(start_service=declaration.role != "background")
        session = await self._hello(
            stream, client_kind, claim=claim, agent=declaration, revision=revision
        )
        if session.workspace_handle is None:
            # The service cannot key the claim now (a locked vault): no agent answers for it.
            await _close(stream)
            raise BackendRefusal("workspace_agent_unavailable")
        ended = asyncio.Event()
        lock = asyncio.Lock()

        async def read() -> None:
            try:
                while True:
                    frame = await read_control_frame(stream, eof_reason="session_closed")
                    if is_workspace_call_frame(frame):
                        await writer(parse_workspace_call(frame))
            except Exception:  # noqa: BLE001 - any end of the connection ends the agent
                return
            finally:
                ended.set()

        task = asyncio.create_task(read())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

        async def deliver(reply: WorkspaceReply) -> None:
            if ended.is_set():
                return
            async with lock:
                with contextlib.suppress(Exception):
                    await write_workspace_reply(stream, reply)

        async def close() -> None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await _close(stream)

        handle = AgentHandle(session.workspace_handle, deliver, close, ended)
        self._handles.append(handle)
        return handle

    async def aclose(self) -> None:
        handles, self._handles = self._handles, []
        for handle in handles:
            with contextlib.suppress(Exception):
                await handle.close()


def _error(call: ControlCallRequest, error: ControlError) -> ControlResult:
    return ControlResult(
        protocol_version="1.0",
        rpc_id=call.rpc_id,
        service_instance_id=call.service_instance_id,
        service_generation=call.service_generation,
        method=call.method,
        outcome="error",
        body=error,
    )
