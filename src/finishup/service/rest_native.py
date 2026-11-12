"""The native REST backend: REST v1 served from inside the service (ADR-053, approach C).

``finishup service rest run --edge native`` runs this root's service in the foreground with the
REST edge in its own event loop (``ServiceComposition.rest_edge``): the server owner's opt-in.
The process that holds the vault is then on the network; its security review is the owner's
(design v2 U13). The default edge is the separate gateway (``finishup.gateway``).

``NativeBackend`` reaches the daemon through ``ServiceDaemon.native_rest_bindings`` only:

* a session or a call is admitted only under the revision the service issues now (refused
  ``server_profile_changed`` before the claim is keyed or anything is dispatched), and each call is
  dispatched bound to it (the daemon's own per-request check);
* a claim (already namespaced by the key's principal) is keyed with the installation MAC exactly
  as a claim-bound hello is, never resolved to a path; a claim the service cannot key now (a
  locked vault) makes its calls answer ``vault_locked``, never served unbound;
* an agent registers an in-process channel with the same hub claim-bound control connections use,
  holding idle relock like an open connection while it is registered; a call naming it is
  dispatched with that channel as its connection's own agent (``live_call_scope``), as a call on
  the agent's control connection is; its handle is let go once it is ended;
* a call holds idle relock while it runs; cancelling it cancels the dispatch, which answers
  ``request_cancelled``.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Final, cast

from finishup.ports.control import (
    ControlCallRequest,
    ControlClientKind,
    ControlError,
    ControlResult,
    RepositoryPrivacyContext,
    WorkspaceAgentDeclaration,
    WorkspaceCall,
    WorkspaceClaim,
    WorkspaceReply,
)
from finishup.protocol.server_profile import ServerProfile, ServerProfileRevision
from finishup.rest.backend import AgentHandle, BackendRefusal, Edge
from finishup.rest.contract import Session
from finishup.service.server_profile import ProfileUnavailable

if TYPE_CHECKING:
    from finishup.rest.api_keys import ApiKeyStore
    from finishup.rest.audit import AuditSink
    from finishup.rest.listener import RestListener
    from finishup.service.daemon import NativeRestBindings, ServiceDaemon

__all__ = ["NativeBackend", "NativeRestEdge"]

_EDGE: Final[Edge] = "native"


class NativeBackend:
    """The REST backend inside the service (see the module text)."""

    def __init__(self, bindings: NativeRestBindings) -> None:
        self._bindings = bindings
        # Only live registrations: a handle leaves this set when its agent is ended.
        self._handles: set[AgentHandle] = set()

    def __repr__(self) -> str:
        return "NativeBackend(<redacted>)"

    @property
    def edge(self) -> Edge:
        return _EDGE

    def _admit(self, revision: ServerProfileRevision) -> None:
        if revision != self._bindings.current_revision():
            # Before the claim is keyed or anything dispatched (ADR-052).
            raise BackendRefusal("server_profile_changed")

    async def admit(
        self,
        *,
        client_kind: ControlClientKind,
        revision: ServerProfileRevision,
        start_service: bool,
    ) -> None:
        del client_kind, start_service
        self._admit(revision)

    async def profile(self) -> ServerProfile:
        try:
            return self._bindings.profile()
        except ProfileUnavailable:
            # A configuration the profile cannot state exactly offers no profile (ADR-052).
            raise BackendRefusal("service_unavailable") from None

    async def _context(self, claim: WorkspaceClaim | None) -> RepositoryPrivacyContext | None:
        if claim is None:
            return None
        context = await self._bindings.resolve_claim(claim)
        if context is not None and (
            type(context) is not RepositoryPrivacyContext
            or context.identity_kind != "client_claim"
            or context.workspace_locator is not None
        ):
            raise BackendRefusal("internal_failure")
        return context

    async def session(
        self,
        *,
        client_kind: ControlClientKind,
        claim: WorkspaceClaim | None,
        revision: ServerProfileRevision,
    ) -> Session:
        del client_kind
        self._admit(revision)
        context = await self._context(claim)
        if claim is None:
            return Session(self._bindings.status(), "none", None, revision)
        handle = None if context is None else context.workspace_handle
        return Session(self._bindings.status(), "client_claim", handle, revision)

    async def dispatch(
        self,
        *,
        client_kind: ControlClientKind,
        call: ControlCallRequest,
        claim: WorkspaceClaim | None,
        revision: ServerProfileRevision,
        start_service: bool,
        agent: AgentHandle | None = None,
    ) -> ControlResult:
        del start_service  # this service is running: it answers the request itself
        self._admit(revision)
        context = await self._context(claim)
        unkeyed = claim is not None and context is None
        channel = None if agent is None or agent not in self._handles else agent.binding
        if agent is not None and channel is None:
            raise BackendRefusal("agent_unknown")
        try:
            async with self._bindings.activity():
                return await self._bindings.dispatch(
                    client_kind, call, context, unkeyed, revision, channel
                )
        except asyncio.CancelledError:
            return _error(call, ControlError("request_cancelled", retryable=True))

    async def register_agent(
        self,
        *,
        client_kind: ControlClientKind,
        claim: WorkspaceClaim,
        declaration: WorkspaceAgentDeclaration,
        revision: ServerProfileRevision,
        writer: Callable[[WorkspaceCall], Awaitable[None]],
    ) -> AgentHandle:
        del client_kind
        self._admit(revision)
        context = await self._context(claim)
        if context is None or context.workspace_handle is None:
            # The service cannot key the claim now (a locked vault): no agent can answer for it.
            raise BackendRefusal("workspace_agent_unavailable")
        hub = self._bindings.hub
        status = self._bindings.status()
        stack = contextlib.AsyncExitStack()
        try:
            # A registered agent holds idle relock like an open agent connection does.
            await stack.enter_async_context(self._bindings.activity())
            channel = await hub.register(
                handle=context.workspace_handle,
                declaration=declaration,
                service_instance_id=status.service_instance_id,
                service_generation=status.service_generation,
                writer=writer,
                worktree=claim.worktree,
            )
        except Exception:
            await stack.aclose()
            raise BackendRefusal("workspace_agent_unavailable") from None
        closed = False
        handle: AgentHandle | None = None

        async def deliver(reply: WorkspaceReply) -> None:
            hub.deliver(channel, reply)

        async def close() -> None:
            nonlocal closed
            if closed:
                return
            closed = True
            self._handles.discard(cast(AgentHandle, handle))
            try:
                await hub.unregister(channel)
            finally:
                await stack.aclose()

        handle = AgentHandle(context.workspace_handle, deliver, close, binding=channel)
        self._handles.add(handle)
        return handle

    async def aclose(self) -> None:
        handles, self._handles = tuple(self._handles), set()
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


class NativeRestEdge:
    """The bound listener the daemon serves its REST app on (``ServiceComposition.rest_edge``)."""

    def __init__(
        self, listener: RestListener, keys: ApiKeyStore, *, audit: AuditSink | None
    ) -> None:
        self._listener = listener
        self._keys = keys
        self._audit = audit

    def __repr__(self) -> str:
        return "NativeRestEdge(<redacted>)"

    async def start(self, daemon: ServiceDaemon) -> None:
        from finishup.rest.app import RestApp

        app = RestApp(NativeBackend(daemon.native_rest_bindings()), self._keys, audit=self._audit)
        await self._listener.start(app.asgi(), app)

    async def close(self) -> None:
        await self._listener.close()
