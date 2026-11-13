"""The REST v1 routes, served by either edge over a ``rest.backend.RestBackend`` (ADR-053).

One application for both edges (design v2 section 1.1): the separate gateway process
(``finishup service rest run``, the default) and the native listener inside the service
(``--edge native``). Routes (bodies and answers canonical JSON, ``cache-control: no-store``, never a
redirect):

* ``GET /.well-known/finishup`` — ``rest-discovery``, unauthenticated, minimal and drawn from the
  unauthenticated budget;
* ``GET /v1/server`` — the ``server-profile`` 1.0.0 document with the caller's key
  (``{id, scope, principal}``) and the edge ``rest-1``;
* ``GET /v1/session`` — ``rest-session``: what a control hello answers, for the request's claim;
* ``POST /v1/{method}`` — one control call; the answer is the control-result body byte for byte
  with ``finishup-outcome``; a call still running after ``wait_ms`` answers ``202`` with
  ``rest-operation`` and ``location: /v1/operations/{id}``; ``GET`` there long-polls it and
  ``DELETE`` cancels it;
* ``POST /v1/agents`` registers a workspace agent for the request's claim; ``GET
  /v1/agents/{id}/work`` long-polls its ``workspace_call`` frames; ``POST /v1/agents/{id}/replies``
  delivers one ``workspace_reply``; ``DELETE /v1/agents/{id}`` ends it.

**Order of checks on every request**, first refusal wins: an ``Origin`` header
(``origin_forbidden``: browsers and DNS rebinding); the unauthenticated budget for discovery
(whatever its method) and for every refusal of a request no key authenticated, whatever its reason
(``rate_limited``); the bearer key (``api_key_invalid|revoked|expired``, ``server_keys_unusable``);
the client's REST API manifest (``header_invalid`` when absent, ``api_manifest_unsupported`` when
this server does not serve it, U18); the consented profile revision (``header_invalid`` when
absent, ``server_profile_changed`` when it is not the server's current one, asked of the backend
before any body is read and again where the work is done, ADR-052); the key's scope as a method
allow-list (an out-of-scope call is answered with the control protocol's own ``method_forbidden``
result, never dispatched); the claim, namespaced by the key's principal before the backend sees it
(``rest.contract.claim_for_principal``); the per-key caps (``operation_limit``, ``agent_limit``,
whose slot a registration holds from before it reaches the backend).

A call naming its connection's registered agent (``finishup-agent``) is sent to that agent first,
as a control connection's call is; the agent must be the caller's own, live, and registered for the
same claim and revision (``agent_unknown`` otherwise).

A start, or any call naming a ``workspace_ref``, never names a path over the network: a start
needs a claim (``workspace_claim_required``) and a ``workspace_ref`` must be a ``client:`` handle.

Operation ids are idempotent per key (at most once: an id already admitted answers with that
operation; one whose answer was dropped stays spent). Answers are kept as their encoded bytes,
bounded per key, in all and in bytes. The audit (``rest.audit``) carries closed tokens only, never a
body, a header value, a key or an address; refusals of unauthenticated requests are written at
most once per reason per minute.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Final, cast

from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

from finishup.domain.values import JsonObject, freeze_json
from finishup.ports.control import (
    ControlCallRequest,
    ControlClientKind,
    ControlError,
    ControlMethod,
    ControlResult,
    WorkspaceCall,
    WorkspaceClaim,
)
from finishup.ports.workspace_agent import MAX_WORKSPACE_FRAME_BYTES, workspace_handle_valid
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.ids import IdKind, new_id, validate_id
from finishup.protocol.server_profile import ProfileKey, ServerProfileRevision, profile_to_json
from finishup.rest.api_keys import ApiKeyError, ApiKeyStore
from finishup.rest.audit import AuditSink, RestAudit
from finishup.rest.backend import AgentHandle, BackendRefusal, RestBackend
from finishup.rest.contract import (
    AGENT_LEASE_MS,
    HEADER_AGENT,
    HEADER_API_MANIFEST,
    HEADER_CLAIM,
    HEADER_CLIENT_KIND,
    HEADER_DEADLINE_MS,
    HEADER_HOST_PROFILE,
    HEADER_OPERATION_ID,
    HEADER_OUTCOME,
    HEADER_ROUTE_PROFILE,
    HEADER_SERVER_PROFILE,
    HEADER_SERVICE_GENERATION,
    HEADER_SERVICE_INSTANCE,
    REST_ERROR_STATUS,
    REST_MAJOR,
    WELL_KNOWN_PATH,
    AgentRegistration,
    ApiScope,
    Discovery,
    RestDocumentError,
    agent_id_valid,
    agent_registration_document,
    agent_work_document,
    claim_for_principal,
    current_api_manifest,
    discovery_document,
    method_allowed,
    new_agent_id,
    operation_pending_document,
    parse_agent_declaration,
    parse_claim_header,
    parse_client_kind,
    parse_host_profile,
    parse_revision_header,
    parse_wait_ms,
    rest_error_document,
    session_document,
)
from finishup.service.control_protocol import (
    CONTROL_PROTOCOL_VERSION,
    MAX_CONTROL_FRAME_BYTES,
    ControlProtocolError,
    encode_control_frame,
    parse_control_request,
    parse_workspace_reply,
    validate_result,
    workspace_call_frame,
)

__all__ = [
    "MAX_AGENTS_PER_KEY",
    "MAX_PENDING_OPERATIONS_PER_KEY",
    "MAX_RETAINED_OPERATIONS",
    "MAX_RETAINED_OPERATIONS_PER_KEY",
    "MAX_RETAINED_RESULT_BYTES",
    "OPERATION_RESULT_SECONDS",
    "SPENT_OPERATION_SECONDS",
    "RestApp",
    "UnauthenticatedBudget",
]

MAX_PENDING_OPERATIONS_PER_KEY: Final = 32
MAX_AGENTS_PER_KEY: Final = 16
# A finished operation's answer stays retrievable this long (an answer lost on the way can be
# fetched again by its id).
OPERATION_RESULT_SECONDS: Final = 120.0
MAX_RETAINED_OPERATIONS_PER_KEY: Final = 64
MAX_RETAINED_OPERATIONS: Final = 1_024
MAX_RETAINED_RESULT_BYTES: Final = 64 * 1024 * 1024
# An operation id whose answer was dropped stays spent this long, so a late duplicate is refused
# (``operation_unknown``) rather than dispatched again.
SPENT_OPERATION_SECONDS: Final = 900.0
MAX_SPENT_OPERATIONS: Final = 16_384
_AGENT_QUEUE_CAPACITY: Final = 64
_MAX_CALLS_PER_POLL: Final = 16
_SWEEP_SECONDS: Final = 5.0
_JSON: Final = "application/json"
_NO_STORE: Final = {"cache-control": "no-store"}
_MAX_CALL_BODY_BYTES: Final = MAX_CONTROL_FRAME_BYTES
_MAX_SMALL_BODY_BYTES: Final = 65_536
_CALLER_SCOPE_KEY: Final = "finishup.caller"
# The unauthenticated budget: per peer address and in total (token buckets).
_PEER_CAPACITY: Final = 20.0
_PEER_REFILL_PER_SECOND: Final = 5.0
_TOTAL_CAPACITY: Final = 200.0
_TOTAL_REFILL_PER_SECOND: Final = 50.0
_MAX_PEERS_TRACKED: Final = 4_096
_AGENT_PATH: Final = re.compile(r"^/v1/agents/(agt_[0-9a-f]{32})(/work|/replies)?$", re.ASCII)
_OPERATION_PATH: Final = re.compile(r"^/v1/operations/([A-Za-z0-9_-]{1,64})$", re.ASCII)
_METHOD_PATH: Final = re.compile(r"^/v1/([a-z_]{1,64})$", re.ASCII)


class _Refusal(Exception):
    def __init__(self, reason: str) -> None:
        if reason not in REST_ERROR_STATUS:
            raise ValueError("rest_error_reason_invalid")
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class _Caller:
    """Who a request acts as: its key id, scope and principal."""

    key_id: str
    scope: ApiScope
    principal: str


@dataclass(frozen=True, slots=True)
class _Answer:
    """A finished operation's answer: its encoded body, or the refusal it ended with."""

    body: bytes | None
    outcome: str
    service_instance_id: str
    service_generation: str
    refusal: str | None = None


@dataclass(slots=True)
class _Operation:
    operation_id: str
    key_id: str
    revision: ServerProfileRevision
    task: asyncio.Task[ControlResult] | None
    request: ControlCallRequest | None
    finished_at: float | None = None
    answer: _Answer | None = None


@dataclass(slots=True)
class _Admission:
    key_id: str
    settled: asyncio.Event = field(default_factory=asyncio.Event)


@dataclass(slots=True)
class _Agent:
    agent_id: str
    key_id: str
    client_kind: ControlClientKind
    claim: WorkspaceClaim
    revision: ServerProfileRevision
    max_reply_bytes: int
    handle: AgentHandle
    calls: asyncio.Queue[WorkspaceCall]
    lease_expires: float


class UnauthenticatedBudget:
    """Token buckets for unauthenticated requests: per peer address and in total.

    Discovery and every refusal of a request no key authenticated draw one token from both; a
    request finding either empty is answered ``rate_limited`` and nothing more is read.
    """

    __slots__ = ("_clock", "_peers", "_total")

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        now = clock()
        self._total = (_TOTAL_CAPACITY, now)
        self._peers: OrderedDict[str, tuple[float, float]] = OrderedDict()

    @staticmethod
    def _refill(bucket: tuple[float, float], capacity: float, rate: float, now: float) -> float:
        tokens, at = bucket
        return min(capacity, tokens + max(0.0, now - at) * rate)

    def take(self, peer: str | None) -> bool:
        now = self._clock()
        total = self._refill(self._total, _TOTAL_CAPACITY, _TOTAL_REFILL_PER_SECOND, now)
        key = peer or "?"
        previous = self._peers.pop(key, (_PEER_CAPACITY, now))
        mine = self._refill(previous, _PEER_CAPACITY, _PEER_REFILL_PER_SECOND, now)
        allowed = total >= 1.0 and mine >= 1.0
        if allowed:
            total -= 1.0
            mine -= 1.0
        self._total = (total, now)
        self._peers[key] = (mine, now)
        while len(self._peers) > _MAX_PEERS_TRACKED:
            self._peers.popitem(last=False)
        return allowed


def _error_response(reason: str) -> Response:
    return Response(
        rest_error_document(reason),
        status_code=REST_ERROR_STATUS[reason],
        media_type=_JSON,
        headers=dict(_NO_STORE),
    )


def _single_header(request: Request, name: str) -> str | None:
    values = request.headers.getlist(name)
    if len(values) > 1:
        raise _Refusal("header_invalid")
    return values[0] if values else None


async def _read_body(request: Request, limit: int) -> bytes:
    declared = _single_header(request, "content-length")
    if declared is not None:
        if not declared.isascii() or not declared.isdigit() or len(declared) > 12:
            raise _Refusal("header_invalid")
        if int(declared) > limit:
            raise _Refusal("frame_too_large")
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise _Refusal("frame_too_large")
        chunks.append(chunk)
    return b"".join(chunks)


def _json_object(body: bytes) -> dict[str, JsonValue]:
    try:
        value = strict_json_parse(body)
    except ValueError:
        raise _Refusal("frame_invalid") from None
    if not isinstance(value, dict):
        raise _Refusal("frame_invalid")
    return value


def _wait_ms(request: Request) -> int:
    values = request.query_params.getlist("wait_ms")
    if len(values) > 1 or set(request.query_params) - {"wait_ms"}:
        raise _Refusal("header_invalid")
    try:
        return parse_wait_ms(values[0] if values else None)
    except ValueError:
        raise _Refusal("header_invalid") from None


def _result_body(result: ControlResult) -> bytes:
    """The result's body exactly as the control socket frames it (canonical JSON is
    compositional, so the sub-object encodes to the same bytes it occupies in the frame)."""

    frame = encode_control_frame(result)
    parsed = strict_json_parse(frame[4:])
    return canonical_encode(cast(dict[str, JsonValue], parsed)["body"])


def _peer(scope: Scope) -> str | None:
    client: object = scope.get("client")
    if isinstance(client, (tuple, list)):
        items = cast(tuple[object, ...] | list[object], client)
        host = items[0] if items else None
        if isinstance(host, str) and host:
            return host
    return None


class RestApp:
    """The routes, the operations still running and the registered agents of one edge."""

    def __init__(
        self,
        backend: RestBackend,
        keys: ApiKeyStore,
        *,
        audit: AuditSink | None = None,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], datetime] | None = None,
        api_manifests: tuple[str, ...] | None = None,
        budget: UnauthenticatedBudget | None = None,
    ) -> None:
        self._backend = backend
        self._keys = keys
        self._clock = clock
        self._wall_clock = wall_clock or (lambda: datetime.now(UTC))
        self._audit = RestAudit(audit, clock=clock, edge=backend.edge)
        self._manifests = api_manifests or (current_api_manifest(),)
        self._budget = budget or UnauthenticatedBudget(clock)
        self._operations: dict[str, _Operation] = {}
        self._admitting: dict[str, _Admission] = {}
        self._spent: dict[str, tuple[str, float]] = {}
        self._agents: dict[str, _Agent] = {}
        # Registrations on their way to the backend, per key: each holds an agent slot.
        self._registering: dict[str, int] = {}
        self._closing = asyncio.Event()
        self._sweeper: asyncio.Task[None] | None = None
        self._discovery = discovery_document(
            Discovery(rest_majors=(REST_MAJOR,), api_manifests=tuple(sorted(self._manifests)))
        )

    def __repr__(self) -> str:
        return "RestApp(<redacted>)"

    @property
    def edge(self) -> str:
        return self._backend.edge

    # --- ASGI entry ---------------------------------------------------------------------------

    def asgi(self) -> ASGIApp:
        """The ASGI application of one listener."""

        async def application(scope: Scope, receive: Receive, send: Send) -> None:
            if scope.get("type") != "http":
                # Websockets are off in the server; lifespan is not used. Nothing else is served.
                return
            request = Request(scope, receive)
            route = "unknown"
            try:
                route, response = await self._serve(request, scope)
            except _Refusal as refusal:
                response = _error_response(refusal.reason)
                self._audit.refusal(route, refusal.reason, authenticated=False)
            except Exception:  # noqa: BLE001 - a defect of this edge answers a bounded 500
                response = _error_response("internal_failure")
                self._audit.refusal(route, "internal_failure", authenticated=True)
            await response(scope, receive, send)

        return application

    def _unauthenticated(self, scope: Scope, reason: str) -> _Refusal:
        """The refusal of a request no key authenticated, drawn from the budget whatever its
        reason (a malformed header is as cheap to send as a wrong key)."""

        if not self._budget.take(_peer(scope)):
            return _Refusal("rate_limited")
        return _Refusal(reason)

    async def _serve(self, request: Request, scope: Scope) -> tuple[str, Response]:
        if request.headers.getlist("origin"):
            raise self._unauthenticated(scope, "origin_forbidden")
        path = cast(str, scope.get("path", ""))
        if path == WELL_KNOWN_PATH:
            # Charged before its method is looked at: every request here is unauthenticated.
            if not self._budget.take(_peer(scope)):
                raise _Refusal("rate_limited")
            if request.method != "GET":
                raise _Refusal("method_not_allowed")
            self._audit.request("discovery", 200, None)
            return "discovery", Response(self._discovery, media_type=_JSON, headers=dict(_NO_STORE))
        try:
            caller = self._authenticate(request)
        except _Refusal as refusal:
            raise self._unauthenticated(scope, refusal.reason) from None
        route = "unknown"
        try:
            route, handler = self._route(path, request.method)
            self._require_manifest(request)
            response = await handler(request, caller)
        except _Refusal as refusal:
            self._audit.refusal(route, refusal.reason, authenticated=True, key_id=caller.key_id)
            return route, _error_response(refusal.reason)
        self._audit.request(route, response.status_code, caller.key_id)
        return route, response

    def _route(
        self, path: str, method: str
    ) -> tuple[str, Callable[[Request, _Caller], Awaitable[Response]]]:
        table: tuple[tuple[str, bool, Mapping[str, Callable[..., Awaitable[Response]]]], ...] = (
            ("server", path == "/v1/server", {"GET": self._server}),
            ("session", path == "/v1/session", {"GET": self._session}),
            ("agents", path == "/v1/agents", {"POST": self._register_agent}),
        )
        for name, matched, methods in table:
            if matched:
                return self._pick(name, methods, method)
        agent = _AGENT_PATH.fullmatch(path)
        if agent is not None:
            suffix = agent.group(2)
            if suffix == "/work":
                return self._pick("agent_work", {"GET": self._agent_work}, method)
            if suffix == "/replies":
                return self._pick("agent_reply", {"POST": self._agent_reply}, method)
            return self._pick("agent", {"DELETE": self._end_agent}, method)
        if _OPERATION_PATH.fullmatch(path) is not None:
            return self._pick(
                "operation", {"GET": self._operation, "DELETE": self._cancel_operation}, method
            )
        if _METHOD_PATH.fullmatch(path) is not None:
            return self._pick("call", {"POST": self._call}, method)
        raise _Refusal("route_unknown")

    @staticmethod
    def _pick(
        name: str, methods: Mapping[str, Callable[..., Awaitable[Response]]], method: str
    ) -> tuple[str, Callable[[Request, _Caller], Awaitable[Response]]]:
        handler = methods.get(method)
        if handler is None:
            raise _Refusal("method_not_allowed")
        return name, handler

    def _authenticate(self, request: Request) -> _Caller:
        authorization = _single_header(request, "authorization")
        if authorization is None or not authorization.startswith("Bearer "):
            raise _Refusal("api_key_invalid")
        try:
            record = self._keys.authenticate(
                authorization.removeprefix("Bearer "), now=self._wall_clock()
            )
        except ApiKeyError as error:
            reason = error.reason
            if reason not in {"api_key_invalid", "api_key_revoked", "api_key_expired"}:
                # The key file itself is unusable: no request is authenticated until it is fixed.
                raise _Refusal("server_keys_unusable") from None
            raise _Refusal(reason) from None
        return _Caller(record.key_id, record.scope, record.principal)

    def _require_manifest(self, request: Request) -> None:
        manifest = _single_header(request, HEADER_API_MANIFEST)
        if manifest is None:
            raise _Refusal("header_invalid")
        if manifest not in self._manifests:
            raise _Refusal("api_manifest_unsupported")

    @staticmethod
    def _revision(request: Request) -> ServerProfileRevision:
        raw = _single_header(request, HEADER_SERVER_PROFILE)
        if raw is None:
            raise _Refusal("header_invalid")
        try:
            return parse_revision_header(raw)
        except ValueError:
            raise _Refusal("header_invalid") from None

    async def _admit_revision(
        self, client_kind: ControlClientKind, revision: ServerProfileRevision, *, start: bool
    ) -> None:
        """The backend's own revision check, before a body is read (the work checks again)."""

        try:
            await self._backend.admit(
                client_kind=client_kind, revision=revision, start_service=start
            )
        except BackendRefusal as refusal:
            raise _Refusal(refusal.reason) from None

    def _calling_agent(
        self,
        request: Request,
        caller: _Caller,
        claim: WorkspaceClaim | None,
        revision: ServerProfileRevision,
    ) -> _Agent | None:
        """The registered agent a call names as its own connection's (``finishup-agent``)."""

        raw = _single_header(request, HEADER_AGENT)
        if raw is None:
            return None
        if not agent_id_valid(raw):
            raise _Refusal("header_invalid")
        agent = self._agents.get(raw)
        if (
            agent is None
            or agent.key_id != caller.key_id
            or agent.handle.ended.is_set()
            or agent.claim != claim
        ):
            raise _Refusal("agent_unknown")
        if agent.revision != revision:
            raise _Refusal("server_profile_changed")
        return agent

    @staticmethod
    def _client_kind(request: Request) -> ControlClientKind:
        try:
            return parse_client_kind(_single_header(request, HEADER_CLIENT_KIND))
        except ValueError:
            raise _Refusal("header_invalid") from None

    @staticmethod
    def _claim(request: Request, caller: _Caller) -> WorkspaceClaim | None:
        """The request's claim, namespaced by the caller's principal; ``None`` without one."""

        raw = _single_header(request, HEADER_CLAIM)
        if raw is None:
            return None
        try:
            return claim_for_principal(parse_claim_header(raw), caller.principal)
        except (TypeError, ValueError):
            raise _Refusal("header_invalid") from None

    # --- GET /v1/server and /v1/session -------------------------------------------------------

    async def _server(self, request: Request, caller: _Caller) -> Response:
        del request
        try:
            profile = await self._backend.profile()
        except BackendRefusal as refusal:
            raise _Refusal(refusal.reason) from None
        keyed = replace(
            profile,
            key=ProfileKey(caller.key_id, caller.scope, caller.principal),
            edges=("rest-1",),
        )
        return Response(
            canonical_encode(profile_to_json(keyed)), media_type=_JSON, headers=dict(_NO_STORE)
        )

    async def _session(self, request: Request, caller: _Caller) -> Response:
        revision = self._revision(request)
        client_kind = self._client_kind(request)
        claim = self._claim(request, caller)
        try:
            session = await self._backend.session(
                client_kind=client_kind, claim=claim, revision=revision
            )
        except BackendRefusal as refusal:
            raise _Refusal(refusal.reason) from None
        return Response(session_document(session), media_type=_JSON, headers=dict(_NO_STORE))

    # --- POST /v1/{method} --------------------------------------------------------------------

    @staticmethod
    def _addressed(request: Request) -> tuple[str, str]:
        """The service instance and generation a call is addressed to (from its session).

        A call addressed to an earlier generation is answered ``service_generation_changed`` by
        the service exactly as on the socket.
        """

        instance = _single_header(request, HEADER_SERVICE_INSTANCE)
        generation = _single_header(request, HEADER_SERVICE_GENERATION)
        if instance is None or generation is None:
            raise _Refusal("header_invalid")
        try:
            validate_id(IdKind.SERVICE_INSTANCE, instance)
        except (TypeError, ValueError):
            raise _Refusal("header_invalid") from None
        if not generation.isascii() or not generation.isdigit() or len(generation) > 20:
            raise _Refusal("header_invalid")
        return instance, generation

    def _call_request(
        self,
        request: Request,
        method: ControlMethod,
        body: dict[str, JsonValue],
        rpc_id: str,
        addressed: tuple[str, str],
    ) -> ControlCallRequest:
        wire: dict[str, JsonValue] = {
            "body": body,
            "kind": "call",
            "method": method.value,
            "protocol_version": CONTROL_PROTOCOL_VERSION,
            "rpc_id": rpc_id,
            "service_generation": addressed[1],
            "service_instance_id": addressed[0],
        }
        deadline = _single_header(request, HEADER_DEADLINE_MS)
        if deadline is not None:
            if not deadline.isascii() or not deadline.isdigit() or len(deadline) > 7:
                raise _Refusal("header_invalid")
            wire["deadline_ms"] = int(deadline)
        route = _single_header(request, HEADER_ROUTE_PROFILE)
        if route is not None:
            if route not in {"policy", "strict"}:
                raise _Refusal("header_invalid")
            wire["route_profile"] = route
        try:
            host = parse_host_profile(_single_header(request, HEADER_HOST_PROFILE))
        except ValueError:
            raise _Refusal("header_invalid") from None
        if host is not None:
            wire["host_profile"] = host
        try:
            frozen = freeze_json(wire)
            if type(frozen) is not JsonObject:
                raise _Refusal("frame_invalid")
            parsed = parse_control_request(frozen)
            # The ordinary frame bounds hold over the network exactly as on the socket.
            encode_control_frame(parsed)
        except ControlProtocolError as error:
            raise _Refusal(
                "frame_too_large" if error.reason == "frame_too_large" else "frame_invalid"
            ) from None
        except (TypeError, ValueError):
            raise _Refusal("frame_invalid") from None
        if not isinstance(parsed, ControlCallRequest):
            raise _Refusal("frame_invalid")
        return parsed

    async def _call(self, request: Request, caller: _Caller) -> Response:
        try:
            method = ControlMethod(cast(str, request.scope["path"]).removeprefix("/v1/"))
        except ValueError:
            raise _Refusal("route_unknown") from None
        revision = self._revision(request)
        client_kind = self._client_kind(request)
        wait_ms = _wait_ms(request)
        operation_id = _single_header(request, HEADER_OPERATION_ID)
        admission: _Admission | None = None
        if operation_id is not None:
            try:
                validate_id(IdKind.CONTROL_RPC, operation_id)
            except (TypeError, ValueError):
                raise _Refusal("header_invalid") from None
            while True:
                existing = self._known_operation(operation_id, caller)
                if existing is not None:
                    # At most once: an id already admitted answers with that operation.
                    if existing.revision != revision:
                        raise _Refusal("server_profile_changed")
                    return await self._answer(existing, wait_ms)
                admitting = self._admitting.get(operation_id)
                if admitting is None:
                    break
                if admitting.key_id != caller.key_id:
                    raise _Refusal("header_invalid")
                # The same id is being admitted on another request: its outcome decides.
                await admitting.settled.wait()
            admission = _Admission(caller.key_id)
            self._admitting[operation_id] = admission
        try:
            operation = await self._admit(
                request, caller, method, client_kind, operation_id, revision
            )
        finally:
            if admission is not None and operation_id is not None:
                if self._admitting.get(operation_id) is admission:
                    del self._admitting[operation_id]
                admission.settled.set()
        if isinstance(operation, Response):
            return operation
        return await self._answer(operation, wait_ms)

    def _known_operation(self, operation_id: str, caller: _Caller) -> _Operation | None:
        """The operation an id already names for this caller; a spent id is refused."""

        existing = self._operations.get(operation_id)
        spent = self._spent.get(operation_id)
        owner = existing.key_id if existing is not None else None if spent is None else spent[0]
        if owner is not None and owner != caller.key_id:
            raise _Refusal("header_invalid")
        if existing is None and spent is not None:
            # Its answer was dropped: it is never dispatched again.
            raise _Refusal("operation_unknown")
        return existing

    async def _admit(
        self,
        request: Request,
        caller: _Caller,
        method: ControlMethod,
        client_kind: ControlClientKind,
        operation_id: str | None,
        revision: ServerProfileRevision,
    ) -> _Operation | Response:
        """Check, read and dispatch one call; a refusal before dispatch is answered at once."""

        claim = self._claim(request, caller)
        addressed = self._addressed(request)
        agent = self._calling_agent(request, caller, claim, revision)
        rpc_id = operation_id or new_id(IdKind.CONTROL_RPC)
        if not method_allowed(caller.scope, method, claim_bound=claim is not None):
            # The key's scope, not the client's own word, bounds its methods: the control
            # protocol's own refusal, before any body is read or dispatched.
            self._audit.refusal(
                "call", "method_forbidden", authenticated=True, key_id=caller.key_id
            )
            forbidden = self._error_result(
                rpc_id, addressed, method, ControlError("method_forbidden")
            )
            return self._result_response(forbidden, operation_id=rpc_id)
        # A stale revision is refused before up to a frame's worth of body is read or admitted.
        await self._admit_revision(client_kind, revision, start=True)
        body = _json_object(await _read_body(request, _MAX_CALL_BODY_BYTES))
        self._require_portable(method, body, claim)
        call = self._call_request(request, method, body, rpc_id, addressed)
        self._purge()
        pending = sum(
            1
            for item in self._operations.values()
            if item.key_id == caller.key_id and item.answer is None
        )
        if pending >= MAX_PENDING_OPERATIONS_PER_KEY:
            raise _Refusal("operation_limit")
        task = asyncio.create_task(self._dispatch(client_kind, call, claim, revision, agent))
        operation = _Operation(call.rpc_id, caller.key_id, revision, task, call)
        task.add_done_callback(lambda _task: self._finished(operation))
        self._operations[call.rpc_id] = operation
        self._ensure_sweeper()
        return operation

    def _require_portable(
        self, method: ControlMethod, body: Mapping[str, JsonValue], claim: WorkspaceClaim | None
    ) -> None:
        """A network call never names a path: a start needs a claim, a ``workspace_ref`` is a
        ``client:`` handle (the service checks it is the claim's own)."""

        reference = body.get("workspace_ref")
        if reference is not None and not workspace_handle_valid(reference):
            self._audit.refusal("call", "workspace_ref_not_portable", authenticated=True)
            raise _Refusal("frame_invalid")
        if method is ControlMethod.START and claim is None:
            raise _Refusal("workspace_claim_required")

    async def _dispatch(
        self,
        client_kind: ControlClientKind,
        call: ControlCallRequest,
        claim: WorkspaceClaim | None,
        revision: ServerProfileRevision,
        agent: _Agent | None,
    ) -> ControlResult:
        started = time.monotonic()
        try:
            if agent is not None and agent.agent_id not in self._agents:
                # Its agent ended while the call was admitted: the connection is gone.
                raise BackendRefusal("agent_unknown")
            result = await self._backend.dispatch(
                client_kind=client_kind,
                call=call,
                claim=claim,
                revision=revision,
                start_service=True,
                agent=None if agent is None else agent.handle,
            )
        except asyncio.CancelledError:
            result = self._call_error(call, ControlError("request_cancelled", retryable=True))
        except BackendRefusal:
            raise
        except Exception:  # noqa: BLE001 - a backend defect is a correlated internal error
            result = self._call_error(call, ControlError("internal_error"))
        self._audit.call(
            call.method.value,
            result.outcome,
            max(0, int((time.monotonic() - started) * 1_000)),
        )
        return result

    @staticmethod
    def _error_result(
        rpc_id: str, addressed: tuple[str, str], method: ControlMethod, error: ControlError
    ) -> ControlResult:
        result = ControlResult(
            protocol_version=CONTROL_PROTOCOL_VERSION,
            rpc_id=rpc_id,
            service_instance_id=addressed[0],
            service_generation=addressed[1],
            method=method,
            outcome="error",
            body=error,
        )
        validate_result(result)
        return result

    @classmethod
    def _call_error(cls, call: ControlCallRequest, error: ControlError) -> ControlResult:
        return cls._error_result(
            call.rpc_id, (call.service_instance_id, call.service_generation), call.method, error
        )

    def _finished(self, operation: _Operation) -> None:
        """Keep only the finished call's encoded answer, then hold the retained answers' bounds."""

        task, request = operation.task, operation.request
        if operation.answer is not None or task is None or request is None or not task.done():
            return
        error = None if task.cancelled() else task.exception()
        if isinstance(error, BackendRefusal):
            # Refused before any work (a stale revision, a service that cannot be reached): the
            # request's own REST refusal, never a control result.
            operation.answer = _Answer(
                None,
                "error",
                request.service_instance_id,
                request.service_generation,
                error.reason,
            )
        else:
            if task.cancelled():
                result = self._call_error(
                    request, ControlError("request_cancelled", retryable=True)
                )
            elif error is not None:
                result = self._call_error(request, ControlError("internal_error"))
            else:
                result = task.result()
            try:
                body: bytes | None = _result_body(result)
            except ControlProtocolError:
                body = None
            operation.answer = _Answer(
                body, result.outcome, result.service_instance_id, result.service_generation
            )
        operation.task = None
        operation.request = None
        operation.finished_at = self._clock()
        self._retain()

    def _drop_answer(self, operation_id: str, now: float) -> None:
        operation = self._operations.pop(operation_id, None)
        if operation is None:
            return
        self._spent.pop(operation_id, None)
        self._spent[operation_id] = (operation.key_id, now + SPENT_OPERATION_SECONDS)
        while len(self._spent) > MAX_SPENT_OPERATIONS:
            del self._spent[next(iter(self._spent))]

    def _retain(self) -> None:
        """Drop the oldest finished answers past the per-key, total and byte bounds."""

        now = self._clock()
        finished = sorted(
            (item for item in self._operations.values() if item.answer is not None),
            key=lambda item: cast(float, item.finished_at),
        )
        per_key: dict[str, int] = {}
        for item in finished:
            per_key[item.key_id] = per_key.get(item.key_id, 0) + 1
        total = len(finished)
        size = sum(len(cast(_Answer, item.answer).body or b"") for item in finished)
        for item in finished:
            if (
                per_key[item.key_id] <= MAX_RETAINED_OPERATIONS_PER_KEY
                and total <= MAX_RETAINED_OPERATIONS
                and size <= MAX_RETAINED_RESULT_BYTES
            ):
                continue
            per_key[item.key_id] -= 1
            total -= 1
            size -= len(cast(_Answer, item.answer).body or b"")
            self._drop_answer(item.operation_id, now)

    def _purge(self) -> None:
        now = self._clock()
        for operation_id, operation in tuple(self._operations.items()):
            if (
                operation.finished_at is not None
                and now - operation.finished_at >= OPERATION_RESULT_SECONDS
            ):
                self._drop_answer(operation_id, now)
        for operation_id, (_owner, until) in tuple(self._spent.items()):
            if until <= now:
                del self._spent[operation_id]

    async def _answer(self, operation: _Operation, wait_ms: int) -> Response:
        task = operation.task
        if task is not None and not task.done() and wait_ms > 0:
            closing = asyncio.ensure_future(self._closing.wait())
            try:
                await asyncio.wait(
                    {task, closing}, timeout=wait_ms / 1_000, return_when=asyncio.FIRST_COMPLETED
                )
            finally:
                closing.cancel()
        # A task that just ended may not have run its done callback yet.
        self._finished(operation)
        answer = operation.answer
        if answer is None:
            return Response(
                operation_pending_document(operation.operation_id),
                status_code=202,
                media_type=_JSON,
                headers={
                    **_NO_STORE,
                    "location": f"/v1/operations/{operation.operation_id}",
                    HEADER_OPERATION_ID: operation.operation_id,
                },
            )
        return self._answer_response(answer, operation_id=operation.operation_id)

    def _result_response(self, result: ControlResult, *, operation_id: str) -> Response:
        try:
            body: bytes | None = _result_body(result)
        except ControlProtocolError:
            body = None
        answer = _Answer(
            body, result.outcome, result.service_instance_id, result.service_generation
        )
        return self._answer_response(answer, operation_id=operation_id)

    @staticmethod
    def _answer_response(answer: _Answer, *, operation_id: str) -> Response:
        if answer.refusal is not None:
            raise _Refusal(answer.refusal)
        if answer.body is None:
            # A result this edge cannot frame is its own defect; the socket would drop it too.
            raise _Refusal("internal_failure")
        headers = {
            **_NO_STORE,
            HEADER_OUTCOME: answer.outcome,
            HEADER_OPERATION_ID: operation_id,
            HEADER_SERVICE_INSTANCE: answer.service_instance_id,
            HEADER_SERVICE_GENERATION: answer.service_generation,
        }
        return Response(answer.body, media_type=_JSON, headers=headers)

    def _owned_operation(self, request: Request, caller: _Caller) -> _Operation:
        match = _OPERATION_PATH.fullmatch(cast(str, request.scope["path"]))
        operation = None if match is None else self._operations.get(match.group(1))
        if operation is None or operation.key_id != caller.key_id:
            raise _Refusal("operation_unknown")
        return operation

    async def _operation(self, request: Request, caller: _Caller) -> Response:
        revision = self._revision(request)
        wait_ms = _wait_ms(request)
        self._purge()
        operation = self._owned_operation(request, caller)
        if operation.revision != revision:
            raise _Refusal("server_profile_changed")
        return await self._answer(operation, wait_ms)

    async def _cancel_operation(self, request: Request, caller: _Caller) -> Response:
        operation = self._owned_operation(request, caller)
        if operation.task is not None and not operation.task.done():
            operation.task.cancel()
        return Response(status_code=204, headers=dict(_NO_STORE))

    # --- workspace agents ---------------------------------------------------------------------

    async def _register_agent(self, request: Request, caller: _Caller) -> Response:
        revision = self._revision(request)
        client_kind = self._client_kind(request)
        claim = self._claim(request, caller)
        if claim is None:
            raise _Refusal("workspace_claim_required")
        # The revision is admitted before the body is read, without starting a stopped service:
        # only a running one can check it then. A stopped one is started only once the
        # declaration (a small body) says the agent is not a background agent, whose
        # registration never starts the service its owner stopped.
        try:
            await self._admit_revision(client_kind, revision, start=False)
            admitted = True
        except _Refusal as refusal:
            if refusal.reason != "service_unavailable":
                raise
            admitted = False
        try:
            declaration = parse_agent_declaration(await _read_body(request, _MAX_SMALL_BODY_BYTES))
        except RestDocumentError:
            raise _Refusal("frame_invalid") from None
        if not admitted:
            if declaration.role == "background":
                raise _Refusal("service_unavailable")
            await self._admit_revision(client_kind, revision, start=True)
        live = sum(1 for agent in self._agents.values() if agent.key_id == caller.key_id)
        if live + self._registering.get(caller.key_id, 0) >= MAX_AGENTS_PER_KEY:
            raise _Refusal("agent_limit")
        calls: asyncio.Queue[WorkspaceCall] = asyncio.Queue(maxsize=_AGENT_QUEUE_CAPACITY)

        async def writer(call: WorkspaceCall) -> None:
            # The service bounds calls in flight per agent well below this capacity.
            calls.put_nowait(call)

        # The slot is held from here: concurrent registrations of one key never pass the cap
        # while they wait for the backend, and a failed or cancelled one gives it back.
        self._registering[caller.key_id] = self._registering.get(caller.key_id, 0) + 1
        try:
            handle = await self._backend.register_agent(
                client_kind=client_kind,
                claim=claim,
                declaration=declaration,
                revision=revision,
                writer=writer,
            )
        except BackendRefusal as refusal:
            raise _Refusal(refusal.reason) from None
        finally:
            remaining = self._registering[caller.key_id] - 1
            if remaining:
                self._registering[caller.key_id] = remaining
            else:
                del self._registering[caller.key_id]
        agent = _Agent(
            agent_id=new_agent_id(),
            key_id=caller.key_id,
            client_kind=client_kind,
            claim=claim,
            revision=revision,
            max_reply_bytes=declaration.max_reply_bytes,
            handle=handle,
            calls=calls,
            lease_expires=self._clock() + AGENT_LEASE_MS / 1_000,
        )
        self._agents[agent.agent_id] = agent
        self._ensure_sweeper()
        registration = AgentRegistration(agent.agent_id, handle.workspace_handle, AGENT_LEASE_MS)
        return Response(
            agent_registration_document(registration),
            status_code=201,
            media_type=_JSON,
            headers={**_NO_STORE, "location": f"/v1/agents/{agent.agent_id}"},
        )

    async def _owned_agent(self, request: Request, caller: _Caller) -> _Agent:
        match = _AGENT_PATH.fullmatch(cast(str, request.scope["path"]))
        agent = None if match is None else self._agents.get(match.group(1))
        if agent is None or agent.key_id != caller.key_id:
            raise _Refusal("agent_unknown")
        if agent.handle.ended.is_set():
            # Gone on the service's side (a closed connection, a restarted service): the client
            # makes a new connection, as after a dropped control connection.
            await self._unregister(agent)
            raise _Refusal("agent_unknown")
        agent.lease_expires = self._clock() + AGENT_LEASE_MS / 1_000
        return agent

    async def _agent_work(self, request: Request, caller: _Caller) -> Response:
        revision = self._revision(request)
        wait_ms = _wait_ms(request)
        agent = await self._owned_agent(request, caller)
        if agent.revision != revision:
            raise _Refusal("server_profile_changed")
        calls: list[WorkspaceCall] = []
        if agent.calls.empty() and wait_ms > 0:
            getter = asyncio.ensure_future(agent.calls.get())
            ended = asyncio.ensure_future(agent.handle.ended.wait())
            closing = asyncio.ensure_future(self._closing.wait())
            try:
                done, _pending = await asyncio.wait(
                    {getter, ended, closing},
                    timeout=wait_ms / 1_000,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if getter in done:
                    calls.append(getter.result())
            finally:
                ended.cancel()
                closing.cancel()
                if not getter.done():
                    getter.cancel()
                elif not getter.cancelled() and not calls:
                    # The call arrived as the wait ended: keep it for this answer.
                    calls.append(getter.result())
            if not calls and agent.handle.ended.is_set():
                await self._unregister(agent)
                raise _Refusal("agent_unknown")
        frames: list[Mapping[str, JsonValue]] = [workspace_call_frame(call) for call in calls]
        size = sum(len(canonical_encode(dict(frame))) for frame in frames)
        while len(frames) < _MAX_CALLS_PER_POLL and not agent.calls.empty():
            frame = workspace_call_frame(agent.calls.get_nowait())
            frames.append(frame)
            size += len(canonical_encode(dict(frame)))
            if size >= MAX_WORKSPACE_FRAME_BYTES:
                break
        agent.lease_expires = self._clock() + AGENT_LEASE_MS / 1_000
        return Response(agent_work_document(frames), media_type=_JSON, headers=dict(_NO_STORE))

    async def _agent_reply(self, request: Request, caller: _Caller) -> Response:
        revision = self._revision(request)
        agent = await self._owned_agent(request, caller)
        if agent.revision != revision:
            raise _Refusal("server_profile_changed")
        await self._admit_revision(agent.client_kind, revision, start=False)
        body = await _read_body(request, agent.max_reply_bytes)
        try:
            frozen = freeze_json(_json_object(body))
            if type(frozen) is not JsonObject:
                raise _Refusal("frame_invalid")
            reply = parse_workspace_reply(frozen)
        except ControlProtocolError:
            raise _Refusal("frame_invalid") from None
        except (TypeError, ValueError):
            raise _Refusal("frame_invalid") from None
        await agent.handle.deliver(reply)
        return Response(status_code=202, headers=dict(_NO_STORE))

    async def _end_agent(self, request: Request, caller: _Caller) -> Response:
        match = _AGENT_PATH.fullmatch(cast(str, request.scope["path"]))
        agent = None if match is None else self._agents.get(match.group(1))
        if agent is None or agent.key_id != caller.key_id:
            raise _Refusal("agent_unknown")
        await self._unregister(agent)
        return Response(status_code=204, headers=dict(_NO_STORE))

    async def _unregister(self, agent: _Agent) -> None:
        if self._agents.pop(agent.agent_id, None) is None:
            return
        with contextlib.suppress(Exception):
            await agent.handle.close()

    def _ensure_sweeper(self) -> None:
        if self._sweeper is None or self._sweeper.done():
            self._sweeper = asyncio.create_task(self._sweep())

    async def _sweep(self) -> None:
        """Drop expired answers, and end agents whose lease ran out or whose key ended."""

        while (self._agents or self._operations or self._spent) and not self._closing.is_set():
            await asyncio.sleep(_SWEEP_SECONDS)
            self._purge()
            await self.sweep_once()

    async def sweep_once(self) -> None:
        now = self._clock()
        wall = self._wall_clock()
        for agent in tuple(self._agents.values()):
            if (
                agent.lease_expires <= now
                or agent.handle.ended.is_set()
                or not self._keys.is_active(agent.key_id, now=wall)
            ):
                await self._unregister(agent)

    # --- lifecycle ----------------------------------------------------------------------------

    async def aclose(self) -> None:
        """Answer every long-poll, cancel running calls, end every agent and the backend."""

        self._closing.set()
        running = [
            operation.task
            for operation in self._operations.values()
            if operation.task is not None and not operation.task.done()
        ]
        for task in running:
            task.cancel()
        await asyncio.gather(*running, return_exceptions=True)
        for agent in tuple(self._agents.values()):
            await self._unregister(agent)
        if self._sweeper is not None:
            self._sweeper.cancel()
            await asyncio.gather(self._sweeper, return_exceptions=True)
        with contextlib.suppress(Exception):
            await self._backend.aclose()
