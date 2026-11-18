"""An in-memory REST backend and app for the REST v1 routes (ADR-053), with no service behind it.

``ScriptedRestBackend`` stands in for either edge's backend: it issues one profile revision,
refuses any other (``server_profile_changed``) before recording anything, answers sessions for a
claim with a handle derived from the claim (as a service keys it), runs calls (a gate can hold
them to exercise long-polls and cancellation), and keeps registered agents whose workspace calls a
test pushes. ``rest_client_for`` serves a ``RestApp`` over ``httpx.ASGITransport``: real HTTP
semantics, no socket.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from builders.server_profiles import TEST_REVISION, profile_document
from finishup.ports.control import (
    ControlCallRequest,
    ControlClientKind,
    ControlError,
    ControlMethod,
    ControlResult,
    ServiceState,
    ServiceStatus,
    WorkspaceAgentDeclaration,
    WorkspaceCall,
    WorkspaceClaim,
    WorkspaceReply,
)
from finishup.protocol.server_profile import (
    ServerProfile,
    ServerProfileRevision,
    profile_from_json,
)
from finishup.rest.api_keys import ApiKeyStore
from finishup.rest.backend import AgentHandle, BackendRefusal, Edge
from finishup.rest.contract import Session

__all__ = [
    "AGENT_DECLARATION",
    "STATUS",
    "RecordedAgent",
    "ScriptedRestBackend",
    "handle_for",
    "status",
]

STATUS_INSTANCE = "svc_01234567-89ab-4def-8123-456789abcdef"
AGENT_DECLARATION = WorkspaceAgentDeclaration(
    operations=("capture_metadata", "inspect"), max_reply_bytes=1_048_576
)


def status(generation: str = "1") -> ServiceStatus:
    return ServiceStatus(
        protocol_version="1.0",
        service_version="0.3.0",
        service_instance_id=STATUS_INSTANCE,
        service_generation=generation,
        state=ServiceState.READY,
        state_reason="none",
        vault_mode="passphrase",
        capabilities=(),
        session_monitor="unavailable",
    )


STATUS = status()


def handle_for(claim: WorkspaceClaim) -> str:
    """The handle a service would derive for ``claim`` (the stand-in's own derivation)."""

    digest = hashlib.sha256((claim.digest + claim.worktree).encode()).hexdigest()
    return f"client:{digest[:16]}"


@dataclass(slots=True)
class RecordedAgent:
    claim: WorkspaceClaim
    declaration: WorkspaceAgentDeclaration
    writer: Callable[[WorkspaceCall], Awaitable[None]]
    handle: AgentHandle
    replies: list[WorkspaceReply] = field(default_factory=list[WorkspaceReply])
    closed: bool = False


@dataclass(slots=True)
class ScriptedRestBackend:
    """See the module text. ``gate``, when set, holds every call until it is set;
    ``register_gate`` holds every agent registration the same way."""

    edge: Edge = "native"
    revision: ServerProfileRevision = TEST_REVISION
    profile_document: dict[str, Any] = field(default_factory=profile_document)
    unkeyed: bool = False
    gate: asyncio.Event | None = None
    register_gate: asyncio.Event | None = None
    refuse_dispatch: str | None = None
    admissions: list[ServerProfileRevision] = field(default_factory=list[ServerProfileRevision])
    call_agents: list[AgentHandle | None] = field(default_factory=list[AgentHandle | None])
    sessions: list[tuple[ControlClientKind, WorkspaceClaim | None]] = field(
        default_factory=list[tuple[ControlClientKind, WorkspaceClaim | None]]
    )
    calls: list[tuple[ControlCallRequest, WorkspaceClaim | None, bool]] = field(
        default_factory=list[tuple[ControlCallRequest, WorkspaceClaim | None, bool]]
    )
    cancelled: list[str] = field(default_factory=list[str])
    agents: list[RecordedAgent] = field(default_factory=list[RecordedAgent])
    closed: bool = False

    def _admit(self, revision: ServerProfileRevision) -> None:
        if revision != self.revision:
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
        self.admissions.append(revision)

    async def profile(self) -> ServerProfile:
        return profile_from_json(json.dumps(self.profile_document).encode())

    async def session(
        self,
        *,
        client_kind: ControlClientKind,
        claim: WorkspaceClaim | None,
        revision: ServerProfileRevision,
    ) -> Session:
        self._admit(revision)
        self.sessions.append((client_kind, claim))
        if claim is None:
            return Session(STATUS, "none", None, self.revision)
        handle = None if self.unkeyed else handle_for(claim)
        return Session(STATUS, "client_claim", handle, self.revision)

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
        del client_kind
        self._admit(revision)
        if self.refuse_dispatch is not None:
            raise BackendRefusal(self.refuse_dispatch)
        self.calls.append((call, claim, start_service))
        self.call_agents.append(agent)
        if self.gate is not None:
            try:
                await self.gate.wait()
            except asyncio.CancelledError:
                self.cancelled.append(call.rpc_id)
                return _result(call, "error", ControlError("request_cancelled", retryable=True))
        if call.method is ControlMethod.SERVICE_STATUS:
            return _result(call, "ok", STATUS)
        return _result(call, "error", ControlError("method_forbidden"))

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
        if self.register_gate is not None:
            await self.register_gate.wait()
        if self.unkeyed:
            raise BackendRefusal("workspace_agent_unavailable")
        recorded: RecordedAgent | None = None

        async def deliver(reply: WorkspaceReply) -> None:
            assert recorded is not None
            recorded.replies.append(reply)

        async def close() -> None:
            assert recorded is not None
            recorded.closed = True

        handle = AgentHandle(handle_for(claim), deliver, close)
        recorded = RecordedAgent(claim, declaration, writer, handle)
        self.agents.append(recorded)
        return handle

    async def aclose(self) -> None:
        self.closed = True


def _result(call: ControlCallRequest, outcome: str, body: object) -> ControlResult:
    return ControlResult(
        protocol_version="1.0",
        rpc_id=call.rpc_id,
        service_instance_id=call.service_instance_id,
        service_generation=call.service_generation,
        method=call.method,
        outcome=outcome,  # type: ignore[arg-type]
        body=body,  # type: ignore[arg-type]
    )


def key_store(base: Path) -> ApiKeyStore:
    return ApiKeyStore(base / "rest")


def fixed_now() -> datetime:
    return datetime(2026, 11, 9, 12, 0, tzinfo=UTC)


def asgi_client(application: Any, *, base_url: str = "https://edge.test") -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url=base_url, timeout=30.0
    )
