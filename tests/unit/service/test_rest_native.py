"""The native REST backend (ADR-053): the service's own bindings, revision first, claims keyed.

``NativeBackend`` reaches the daemon only through ``ServiceDaemon.native_rest_bindings``. Stand-in
bindings record what it asks: a stale revision is refused before any claim is keyed or call
dispatched; a claim the service cannot key makes its calls answer as unkeyed (``vault_locked`` by
the daemon), never unbound; an agent registers with the real agent hub under the keyed handle and
holds activity while registered; a cancelled call answers ``request_cancelled``.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncGenerator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, cast

import pytest

from builders.rest_backend import AGENT_DECLARATION, STATUS
from builders.server_profiles import TEST_REVISION, profile_document
from finishup.domain.values import freeze_json
from finishup.ports.control import (
    ControlCallRequest,
    ControlClientKind,
    ControlMethod,
    ControlResult,
    RepositoryPrivacyContext,
    WorkspaceCall,
    WorkspaceClaim,
)
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.server_profile import ServerProfile, ServerProfileRevision, profile_from_json
from finishup.rest.backend import BackendRefusal
from finishup.service.daemon import NativeRestBindings
from finishup.service.rest_native import NativeBackend
from finishup.service.server_profile import ProfileUnavailable
from finishup.service.workspace_hub import WorkspaceAgentHub

pytestmark = pytest.mark.anyio

_CLAIM = WorkspaceClaim(
    identity_kind="git_common_root", digest="sha256:" + "a" * 64, worktree="sha256:" + "b" * 64
)
_STALE = ServerProfileRevision(TEST_REVISION.issuer, 9, "sha256:" + "c" * 64)
_HANDLE = "client:0123456789abcdef"


def _context() -> RepositoryPrivacyContext:
    return RepositoryPrivacyContext(
        commitment="hmac-sha256:" + "d" * 64,
        identity_kind="client_claim",
        workspace_handle=_HANDLE,
    )


def _call(method: ControlMethod = ControlMethod.SERVICE_STATUS) -> ControlCallRequest:
    return ControlCallRequest(
        kind="call",
        protocol_version="1.0",
        rpc_id=new_id(IdKind.CONTROL_RPC),
        service_instance_id=STATUS.service_instance_id,
        service_generation=STATUS.service_generation,
        method=method,
        body=cast(Any, freeze_json({})),
    )


@dataclass
class _Daemon:
    keyed: bool = True
    profile_unavailable: bool = False
    gate: asyncio.Event | None = None
    resolved: list[WorkspaceClaim] = field(default_factory=list[WorkspaceClaim])
    dispatched: list[tuple[RepositoryPrivacyContext | None, bool, ServerProfileRevision]] = field(
        default_factory=list[tuple[RepositoryPrivacyContext | None, bool, ServerProfileRevision]]
    )
    active: int = 0
    hub: WorkspaceAgentHub = field(default_factory=WorkspaceAgentHub)

    def bindings(self) -> NativeRestBindings:
        async def resolve(claim: WorkspaceClaim) -> RepositoryPrivacyContext | None:
            self.resolved.append(claim)
            return _context() if self.keyed else None

        async def dispatch(
            kind: ControlClientKind,
            call: ControlCallRequest,
            context: RepositoryPrivacyContext | None,
            unkeyed: bool,
            revision: ServerProfileRevision,
        ) -> ControlResult:
            del kind
            self.dispatched.append((context, unkeyed, revision))
            if self.gate is not None:
                await self.gate.wait()
            return ControlResult(
                protocol_version="1.0",
                rpc_id=call.rpc_id,
                service_instance_id=call.service_instance_id,
                service_generation=call.service_generation,
                method=call.method,
                outcome="ok",
                body=STATUS,
            )

        @contextlib.asynccontextmanager
        async def activity() -> AsyncGenerator[None]:
            self.active += 1
            try:
                yield
            finally:
                self.active -= 1

        def profile() -> ServerProfile:
            if self.profile_unavailable:
                raise ProfileUnavailable("review_provider_unrepresentable")
            import json

            return profile_from_json(json.dumps(profile_document()).encode())

        return NativeRestBindings(
            status=lambda: STATUS,
            current_revision=lambda: TEST_REVISION,
            profile=profile,
            dispatch=dispatch,
            resolve_claim=resolve,
            hub=self.hub,
            activity=activity,
        )


async def test_a_stale_revision_is_refused_before_the_claim_is_keyed() -> None:
    daemon = _Daemon()
    backend = NativeBackend(daemon.bindings())
    for attempt in (
        backend.session(client_kind=ControlClientKind.CLI, claim=_CLAIM, revision=_STALE),
        backend.dispatch(
            client_kind=ControlClientKind.CLI,
            call=_call(),
            claim=_CLAIM,
            revision=_STALE,
            start_service=True,
        ),
        backend.register_agent(
            client_kind=ControlClientKind.CLI,
            claim=_CLAIM,
            declaration=AGENT_DECLARATION,
            revision=_STALE,
            writer=_writer([]),
        ),
    ):
        with pytest.raises(BackendRefusal) as refused:
            await cast(Awaitable[Any], attempt)
        assert refused.value.reason == "server_profile_changed"
    assert daemon.resolved == [] and daemon.dispatched == []


async def test_a_session_answers_the_keyed_handle_or_none_while_the_vault_is_locked() -> None:
    daemon = _Daemon()
    backend = NativeBackend(daemon.bindings())
    session = await backend.session(
        client_kind=ControlClientKind.CLI, claim=_CLAIM, revision=TEST_REVISION
    )
    assert (session.workspace_binding, session.workspace_handle) == ("client_claim", _HANDLE)
    daemon.keyed = False
    locked = await backend.session(
        client_kind=ControlClientKind.CLI, claim=_CLAIM, revision=TEST_REVISION
    )
    assert (locked.workspace_binding, locked.workspace_handle) == ("client_claim", None)
    unbound = await backend.session(
        client_kind=ControlClientKind.CLI, claim=None, revision=TEST_REVISION
    )
    assert unbound.workspace_binding == "none"


async def test_a_call_is_bound_to_its_revision_and_an_unkeyed_claim_is_never_unbound() -> None:
    daemon = _Daemon(keyed=False)
    backend = NativeBackend(daemon.bindings())
    result = await backend.dispatch(
        client_kind=ControlClientKind.CLI,
        call=_call(),
        claim=_CLAIM,
        revision=TEST_REVISION,
        start_service=True,
    )
    assert result.outcome == "ok"
    assert daemon.dispatched == [(None, True, TEST_REVISION)]
    assert daemon.active == 0


async def test_a_cancelled_call_answers_request_cancelled() -> None:
    daemon = _Daemon(gate=asyncio.Event())
    backend = NativeBackend(daemon.bindings())
    task = asyncio.create_task(
        backend.dispatch(
            client_kind=ControlClientKind.CLI,
            call=_call(),
            claim=None,
            revision=TEST_REVISION,
            start_service=True,
        )
    )
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 5
    while not daemon.dispatched:
        assert loop.time() < deadline
        await asyncio.sleep(0)
    assert daemon.active == 1
    task.cancel()
    result = await task
    assert result.outcome == "error"
    assert daemon.active == 0


async def test_an_agent_registers_with_the_hub_under_the_keyed_handle_and_holds_activity() -> None:
    daemon = _Daemon()
    backend = NativeBackend(daemon.bindings())
    received: list[WorkspaceCall] = []
    handle = await backend.register_agent(
        client_kind=ControlClientKind.CLI,
        claim=_CLAIM,
        declaration=AGENT_DECLARATION,
        revision=TEST_REVISION,
        writer=_writer(received),
    )
    assert handle.workspace_handle == _HANDLE
    assert daemon.hub.has_agent(_HANDLE)
    assert daemon.active == 1
    await handle.close()
    assert not daemon.hub.has_agent(_HANDLE)
    assert daemon.active == 0


async def test_no_agent_registers_while_the_claim_cannot_be_keyed() -> None:
    daemon = _Daemon(keyed=False)
    backend = NativeBackend(daemon.bindings())
    with pytest.raises(BackendRefusal) as refused:
        await backend.register_agent(
            client_kind=ControlClientKind.CLI,
            claim=_CLAIM,
            declaration=AGENT_DECLARATION,
            revision=TEST_REVISION,
            writer=_writer([]),
        )
    assert refused.value.reason == "workspace_agent_unavailable"
    assert daemon.active == 0


async def test_a_service_that_offers_no_profile_answers_service_unavailable() -> None:
    backend = NativeBackend(_Daemon(profile_unavailable=True).bindings())
    with pytest.raises(BackendRefusal) as refused:
        await backend.profile()
    assert refused.value.reason == "service_unavailable"


def _writer(sink: list[WorkspaceCall]) -> Callable[[WorkspaceCall], Awaitable[None]]:
    async def write(call: WorkspaceCall) -> None:
        sink.append(call)

    return write
