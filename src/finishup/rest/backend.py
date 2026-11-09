"""The backend interface the REST v1 routes call (ADR-053, design v2 section 8.4).

``rest.app`` owns everything the two edges share: authentication, the unauthenticated budget,
scopes, the per-principal claim namespace, the revision and API-manifest checks, the operations
table (idempotent operation ids, long-polls, cancellation, retained answers) and the agents table
(leases, queues). A backend owns only how a request reaches the service:

* ``service.rest_native.NativeBackend`` — in process, inside the service (approach C); the owner's
  opt-in (``finishup service rest run --edge native``);
* ``gateway.backend.ControlSocketBackend`` — in the separate same-user gateway process, re-entering
  over ``control.sock`` as ordinary claim-bound control connections; it never holds the
  installation MAC or a vault handle (approach A's hardening; the default edge).

Every backend method takes the claim **already namespaced** by the caller's principal
(``rest.contract.claim_for_principal``) and the consented revision; a revision that is not the
server's current one is refused ``server_profile_changed`` before anything is keyed, registered or
dispatched (ADR-052). Failures are ``BackendRefusal`` with a closed ``rest-error`` reason.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Literal, Protocol

from finishup.ports.control import (
    ControlCallRequest,
    ControlClientKind,
    ControlResult,
    WorkspaceAgentDeclaration,
    WorkspaceCall,
    WorkspaceClaim,
    WorkspaceReply,
)
from finishup.protocol.server_profile import ServerProfile, ServerProfileRevision
from finishup.rest.contract import REST_ERROR_STATUS, Session

__all__ = [
    "AgentHandle",
    "BackendRefusal",
    "Edge",
    "RestBackend",
]

type Edge = Literal["gateway", "native"]


class BackendRefusal(Exception):
    """A request the backend refused before any work; ``reason`` is a closed ``rest-error``."""

    def __init__(self, reason: str) -> None:
        if reason not in REST_ERROR_STATUS:
            raise ValueError("rest_error_reason_invalid")
        self.reason = reason
        super().__init__(reason)


@dataclass(slots=True)
class AgentHandle:
    """One registered workspace agent as its backend keeps it.

    ``deliver`` hands the service one ``workspace_reply``; ``close`` ends the registration (the
    agent's channel in the service goes); ``ended`` is set by the backend when the agent is gone
    on the service's side (a closed control connection, a stopped service), so the next poll
    answers ``agent_unknown`` and the client makes a new connection.
    """

    workspace_handle: str
    deliver: Callable[[WorkspaceReply], Awaitable[None]]
    close: Callable[[], Awaitable[None]]
    ended: asyncio.Event = field(default_factory=asyncio.Event)


class RestBackend(Protocol):
    """How REST requests reach this server's service (see the module text)."""

    @property
    def edge(self) -> Edge: ...

    async def profile(self) -> ServerProfile:
        """The service's own profile (owner view); the routes put the caller's key in it."""
        ...

    async def session(
        self,
        *,
        client_kind: ControlClientKind,
        claim: WorkspaceClaim | None,
        revision: ServerProfileRevision,
    ) -> Session:
        """What a control hello answers for ``claim`` under ``revision``."""
        ...

    async def dispatch(
        self,
        *,
        client_kind: ControlClientKind,
        call: ControlCallRequest,
        claim: WorkspaceClaim | None,
        revision: ServerProfileRevision,
        start_service: bool,
    ) -> ControlResult:
        """Run one call and return its result.

        Cancelling the task asks the service to cancel the call, after the call itself reached
        it (never before: cancellation order), and still returns the call's own result
        (``request_cancelled`` when it stopped). ``start_service`` is false for a background
        agent's client, which never starts a service its owner stopped.
        """
        ...

    async def register_agent(
        self,
        *,
        client_kind: ControlClientKind,
        claim: WorkspaceClaim,
        declaration: WorkspaceAgentDeclaration,
        revision: ServerProfileRevision,
        writer: Callable[[WorkspaceCall], Awaitable[None]],
    ) -> AgentHandle:
        """Register an agent answering ``claim``'s workspace calls; each call goes to ``writer``."""
        ...

    async def aclose(self) -> None:
        """End every agent and connection this backend holds."""
        ...
