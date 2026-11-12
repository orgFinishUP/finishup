"""The REST v1 public contract, shared by every edge and the one client (ADR-053, design v2 U9).

A FinishUP server answers the same resource-shaped REST API from either edge its owner runs (the
separate gateway process or the native listener inside the service); clients reach it with
``client.rest_client`` (the direct style and the helper's relay alike). This module holds what both
sides must agree on and nothing else: routes, header names, key scopes and their method lists, the
API key token shape, the claim header and its per-principal namespace, the profile-revision header,
the closed ``rest-error`` reasons, every REST document (``rest-discovery``, ``rest-session``,
``rest-operation``, ``rest-agent``, ``rest-agent-work``, ``rest-agent-declaration``, ``rest-error``,
all 1.0.0), and the **REST API manifest** a client and a server compare (U18).

Bodies of calls are not redefined: a call's body is the method's existing request body and its
answer the existing control-result body, byte for byte. ``GET /v1/server`` answers the
``server-profile`` 1.0.0 document of layer 3 (``protocol.server_profile``).

**The API manifest** is ``sha256`` over ``yoetz/rest-api-manifest/v1\\0`` and the canonical list of
``[path, sha256]`` of every schema in the transitive ``$ref`` closure of ``REST_ROOT_SCHEMAS``,
read from the packaged schema manifest. Two releases with the same API manifest speak a
byte-identical public contract. Discovery lists the manifests a server serves; every ``/v1``
request names the client's own; a server refuses one it does not serve before any work. The core
server serves exactly its own release's (a window of one).

Everything that crosses the wire is canonical JSON with closed tokens: no document here carries a
path, a host name, an owner-typed label or a key. Standard library and ``finishup.protocol`` only
(plus the shared control codec for the service status), so it stays light for a client.
"""

from __future__ import annotations

import base64
import binascii
import functools
import hashlib
import json
import re
import secrets
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from importlib import resources
from typing import Any, Final, Literal, cast

from finishup.ports.control import (
    ControlClientKind,
    ControlMethod,
    McpHostProfile,
    ServiceStatus,
    WorkspaceAgentDeclaration,
    WorkspaceBinding,
    WorkspaceClaim,
)
from finishup.ports.workspace_agent import workspace_handle_valid
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.server_profile import ProfileError, ServerProfileRevision

__all__ = [
    "AGENTS_PATH",
    "AGENT_LEASE_MS",
    "AGENT_SCOPE_METHODS",
    "API_KEY_PREFIX",
    "API_MANIFEST_DOMAIN",
    "API_SCOPES",
    "CLAIM_BOUND_ONLY_METHODS",
    "DEFAULT_WAIT_MS",
    "HEADER_AGENT",
    "HEADER_API_MANIFEST",
    "HEADER_CLAIM",
    "HEADER_CLIENT_KIND",
    "HEADER_DEADLINE_MS",
    "HEADER_HOST_PROFILE",
    "HEADER_OPERATION_ID",
    "HEADER_OUTCOME",
    "HEADER_ROUTE_PROFILE",
    "HEADER_SERVER_PROFILE",
    "HEADER_SERVICE_GENERATION",
    "HEADER_SERVICE_INSTANCE",
    "HEADER_WORKSPACE_HANDLE",
    "MAX_DISCOVERY_BYTES",
    "MAX_DOCUMENT_BYTES",
    "MAX_WAIT_MS",
    "OPERATOR_SCOPE_METHODS",
    "PRODUCT",
    "PROFILE_PATH",
    "REST_MAJOR",
    "REST_ROOT_SCHEMAS",
    "REST_SCHEMA_VERSION",
    "REST_ERROR_STATUS",
    "SESSION_PATH",
    "UNAUTHENTICATED_REASONS",
    "WELL_KNOWN_PATH",
    "AgentRegistration",
    "AgentWork",
    "ApiKeyToken",
    "ApiScope",
    "Discovery",
    "RestDocumentError",
    "Session",
    "agent_declaration_document",
    "agent_id_valid",
    "agent_registration_document",
    "agent_work_document",
    "api_manifest_digest",
    "claim_for_principal",
    "current_api_manifest",
    "discovery_document",
    "encode_claim_header",
    "encode_revision_header",
    "method_allowed",
    "mint_api_key",
    "new_agent_id",
    "operation_id_valid",
    "operation_pending_document",
    "parse_agent_declaration",
    "parse_agent_registration",
    "parse_agent_work",
    "parse_api_key",
    "parse_claim_header",
    "parse_client_kind",
    "parse_discovery",
    "parse_host_profile",
    "parse_operation_pending",
    "parse_rest_error",
    "parse_revision_header",
    "parse_session",
    "parse_wait_ms",
    "rest_error_document",
    "session_document",
]

REST_SCHEMA_VERSION: Final = "1.0.0"
# The REST major this release speaks, in the path (``/v1``) and in discovery.
REST_MAJOR: Final = "1"
PRODUCT: Final = "finishup"
WELL_KNOWN_PATH: Final = "/.well-known/finishup"
# The fixed, same-origin profile route (design v2 section 8.8): a client never takes another.
PROFILE_PATH: Final = "/v1/server"
SESSION_PATH: Final = "/v1/session"
AGENTS_PATH: Final = "/v1/agents"
# Long-poll bound: under the 60 s idle timeout common HTTP proxies apply.
MAX_WAIT_MS: Final = 25_000
DEFAULT_WAIT_MS: Final = 25_000
# How long a registered workspace agent stays registered without polling for work.
AGENT_LEASE_MS: Final = 60_000
# The discovery document is tiny; a client reads at most this much of it.
MAX_DISCOVERY_BYTES: Final = 4_096
MAX_DOCUMENT_BYTES: Final = 65_536

# Request headers (header names are case-insensitive; these are the canonical lowercase spellings).
HEADER_CLAIM: Final = "finishup-workspace-claim"
HEADER_CLIENT_KIND: Final = "finishup-client-kind"
HEADER_SERVICE_INSTANCE: Final = "finishup-service-instance"
HEADER_SERVICE_GENERATION: Final = "finishup-service-generation"
HEADER_OPERATION_ID: Final = "finishup-operation-id"
HEADER_DEADLINE_MS: Final = "finishup-deadline-ms"
HEADER_ROUTE_PROFILE: Final = "finishup-route-profile"
HEADER_HOST_PROFILE: Final = "finishup-host-profile"
# The workspace agent the calling connection registered (``POST /v1/agents``): its calls go to
# that agent first, as a control connection's calls go to the agent its own hello declared.
HEADER_AGENT: Final = "finishup-agent"
# The server-profile revision the client consented to (ADR-052): on every ``/v1`` request but the
# profile route and the two reverse ``DELETE`` routes.
HEADER_SERVER_PROFILE: Final = "finishup-server-profile"
# The client's REST API manifest (U18): on every ``/v1`` request.
HEADER_API_MANIFEST: Final = "finishup-api-manifest"
# Response headers.
HEADER_OUTCOME: Final = "finishup-outcome"
HEADER_WORKSPACE_HANDLE: Final = "finishup-workspace-handle"

type ApiScope = Literal["agent", "operator"]
API_SCOPES: Final[tuple[ApiScope, ...]] = ("agent", "operator")

# Every method a hook, the closure gate, the startup-gate probe or the MCP bridge calls.
AGENT_SCOPE_METHODS: Final[frozenset[ControlMethod]] = frozenset(
    {
        ControlMethod.START,
        ControlMethod.PUBLISH_WORK,
        ControlMethod.CHECK,
        ControlMethod.RESPOND,
        ControlMethod.STATUS,
        ControlMethod.RECEIPT,
        ControlMethod.SERVICE_STATUS,
        ControlMethod.OBSERVATION_INGEST,
        # Level L2 (ADR-054): reducing what a server keeps is never an operator privilege.
        ControlMethod.CODE_COPY,
    }
)
OPERATOR_SCOPE_METHODS: Final[frozenset[ControlMethod]] = AGENT_SCOPE_METHODS | frozenset(
    {
        ControlMethod.PROJECT,
        ControlMethod.REVIEW,
        ControlMethod.IMPORT_CODEX_JSONL,
        ControlMethod.OBSERVATION_STATUS,
        ControlMethod.PRIVACY_GET_SETUP,
        ControlMethod.PRIVACY_GET_EFFECTIVE,
        ControlMethod.PRIVACY_PENDING_LIST,
        ControlMethod.PRIVACY_RECEIPTS_LIST,
        ControlMethod.PRIVACY_RECEIPTS_GET,
        ControlMethod.PRIVACY_PROPOSE_POLICY,
        ControlMethod.PRIVACY_TIGHTEN_POLICY,
        ControlMethod.SERVICE_LOCK,
    }
)
# Allowed only on a request whose claim the service keyed (the workspace it names is the client's
# own, read by the client's workspace agent).
CLAIM_BOUND_ONLY_METHODS: Final[frozenset[ControlMethod]] = frozenset(
    {ControlMethod.OBSERVATION_INGEST, ControlMethod.CODE_COPY}
)

# Transport and authentication refusals. A dispatched call's own outcome (a workflow error,
# ``vault_locked``, ``method_forbidden``) is never one of these: it is the control-result body.
REST_ERROR_STATUS: Final[Mapping[str, int]] = {
    "frame_invalid": 400,
    "header_invalid": 400,
    "api_key_invalid": 401,
    "api_key_revoked": 401,
    "api_key_expired": 401,
    "origin_forbidden": 403,
    "workspace_claim_required": 403,
    "route_unknown": 404,
    "operation_unknown": 404,
    "agent_unknown": 404,
    "method_not_allowed": 405,
    # The consented profile revision is not the one the server issues now (ADR-052): no work done.
    "server_profile_changed": 409,
    # The client's REST API manifest is not one this server serves (U18).
    "api_manifest_unsupported": 412,
    "frame_too_large": 413,
    "operation_limit": 429,
    "agent_limit": 429,
    # Unauthenticated requests (discovery, refusals) over the server's budget.
    "rate_limited": 429,
    "internal_failure": 500,
    "service_unavailable": 503,
    # The server's key file is unusable: no key can be checked until its owner repairs it there.
    "server_keys_unusable": 503,
    "workspace_agent_unavailable": 503,
}
# The refusals of a request no key authenticated: they draw on the unauthenticated budget.
UNAUTHENTICATED_REASONS: Final = frozenset(
    {"api_key_invalid", "api_key_revoked", "api_key_expired", "origin_forbidden", "rate_limited"}
)

API_KEY_PREFIX: Final = "fuk_"
API_MANIFEST_DOMAIN: Final = b"yoetz/rest-api-manifest/v1\x00"
_CLAIM_PRINCIPAL_DOMAIN: Final = b"yoetz/claim-principal/v1\x00"
_API_KEY: Final = re.compile(r"^fuk_([0-9a-f]{12})_([A-Za-z0-9_-]{43})$", re.ASCII)
_API_KEY_SECRET_BYTES: Final = 32
_CLAIM_HEADER: Final = re.compile(
    r"^(git_common_root|directory):(sha256:[0-9a-f]{64}):(sha256:[0-9a-f]{64})$", re.ASCII
)
_REVISION_HEADER: Final = re.compile(
    r"^([0-9a-f]{32})\.([1-9][0-9]{0,15})\.(sha256:[0-9a-f]{64})$", re.ASCII
)
_AGENT_ID: Final = re.compile(r"^agt_[0-9a-f]{32}$", re.ASCII)
_SHA256: Final = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_CLIENT_KINDS: Final = frozenset(kind.value for kind in ControlClientKind)
_HOST_PROFILES: Final = frozenset({"generic", "codex", "claude", "cursor"})
_BINDINGS: Final = frozenset({"none", "client_claim"})
_MAX_API_MANIFESTS: Final = 16
_MAX_CALLS_PER_WORK: Final = 64


class RestDocumentError(ValueError):
    """A REST document this release refuses; the message is a closed token, never input."""

    def __init__(self, reason: str = "rest_document_invalid") -> None:
        super().__init__(reason)
        self.reason = reason


# --- scopes, small header values ---------------------------------------------------------------


def method_allowed(scope: ApiScope, method: ControlMethod, *, claim_bound: bool) -> bool:
    """Whether a key of ``scope`` may call ``method`` on a request bound (or not) to a claim."""

    allowed = AGENT_SCOPE_METHODS if scope == "agent" else OPERATOR_SCOPE_METHODS
    if method not in allowed:
        return False
    return claim_bound or method not in CLAIM_BOUND_ONLY_METHODS


def parse_wait_ms(raw: str | None, *, default: int = DEFAULT_WAIT_MS) -> int:
    """A ``wait_ms`` query value: decimal milliseconds in ``0..MAX_WAIT_MS``."""

    if raw is None:
        return default
    if not raw.isascii() or not raw.isdigit() or len(raw) > 6:
        raise ValueError("wait_ms_invalid")
    value = int(raw)
    if value > MAX_WAIT_MS:
        raise ValueError("wait_ms_invalid")
    return value


def parse_client_kind(raw: str | None) -> ControlClientKind:
    """The ``finishup-client-kind`` header; absent means ``cli``."""

    if raw is None:
        return ControlClientKind.CLI
    if raw not in _CLIENT_KINDS:
        raise ValueError("client_kind_invalid")
    return ControlClientKind(raw)


def parse_host_profile(raw: str | None) -> McpHostProfile | None:
    if raw is None:
        return None
    if raw not in _HOST_PROFILES:
        raise ValueError("host_profile_invalid")
    return cast(McpHostProfile, raw)


def operation_id_valid(value: object) -> bool:
    """Whether ``value`` is a control rpc id (``rpc_<uuid4>``), the shape of an operation id."""

    from finishup.protocol.ids import IdKind, validate_id

    try:
        validate_id(IdKind.CONTROL_RPC, value)
    except (TypeError, ValueError):
        return False
    return True


# --- API keys ----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ApiKeyToken:
    """A parsed ``fuk_<12 hex key id>_<43 base64url secret>`` bearer key."""

    key_id: str
    secret: bytes = b""

    def __repr__(self) -> str:
        return f"ApiKeyToken(key_id={self.key_id!r}, secret=<redacted>)"


def parse_api_key(token: object) -> ApiKeyToken | None:
    """The key id and secret of a well-formed key, or ``None`` (never echoing the value)."""

    if type(token) is not str:
        return None
    match = _API_KEY.fullmatch(token)
    if match is None:
        return None
    try:
        secret = base64.urlsafe_b64decode(match.group(2) + "=")
    except (ValueError, binascii.Error):
        return None
    if len(secret) != _API_KEY_SECRET_BYTES:
        return None
    # One spelling per key: the final character's padding bits must be zero.
    if base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=") != match.group(2):
        return None
    return ApiKeyToken(match.group(1), secret)


def mint_api_key() -> tuple[ApiKeyToken, str]:
    """A fresh key: its parsed form and the one-time token text the owner copies."""

    key_id = secrets.token_hex(6)
    secret = secrets.token_bytes(_API_KEY_SECRET_BYTES)
    encoded = base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")
    return ApiKeyToken(key_id, secret), f"{API_KEY_PREFIX}{key_id}_{encoded}"


# --- claims, principals and the profile revision ------------------------------------------------


def encode_claim_header(claim: WorkspaceClaim) -> str:
    """``<identity_kind>:sha256:<64 hex>:sha256:<64 hex>``: a request's workspace claim.

    The first digest is the repository claim, the second the worktree digest (ADR-051). Neither
    names a path.
    """

    if type(claim) is not WorkspaceClaim:
        raise TypeError("workspace_claim_invalid")
    return f"{claim.identity_kind}:{claim.digest}:{claim.worktree}"


def parse_claim_header(raw: object) -> WorkspaceClaim:
    match = _CLAIM_HEADER.fullmatch(raw) if type(raw) is str else None
    if match is None:
        raise ValueError("workspace_claim_invalid")
    kind = cast(Literal["git_common_root", "directory"], match.group(1))
    return WorkspaceClaim(identity_kind=kind, digest=match.group(2), worktree=match.group(3))


def claim_for_principal(claim: WorkspaceClaim, principal: str) -> WorkspaceClaim:
    """The claim as a server keys it for one key principal (design v2 Q7).

    Two principals presenting the same digest reach different repositories; a rotated key keeps
    its predecessor's principal, so rotation never strands a task. Only the repository digest is
    namespaced; the worktree digest is kept. Both edges call this, so a request reaches the same
    commitment whichever edge serves it. A claim that arrives over SSH (owner-equivalent) is not
    namespaced.
    """

    if type(claim) is not WorkspaceClaim or type(principal) is not str or not principal:
        raise TypeError("workspace_claim_invalid")
    digest = hashlib.sha256(
        _CLAIM_PRINCIPAL_DOMAIN + principal.encode("ascii") + b"\x00" + claim.digest.encode("ascii")
    ).hexdigest()
    return WorkspaceClaim(
        identity_kind=claim.identity_kind, digest="sha256:" + digest, worktree=claim.worktree
    )


def encode_revision_header(revision: ServerProfileRevision) -> str:
    """``<issuer>.<revision>.<profile digest>``: the consented profile revision (ADR-052)."""

    if type(revision) is not ServerProfileRevision:
        raise TypeError("server_profile_invalid")
    return f"{revision.issuer}.{revision.revision}.{revision.profile_digest}"


def parse_revision_header(raw: object) -> ServerProfileRevision:
    match = _REVISION_HEADER.fullmatch(raw) if type(raw) is str else None
    if match is None:
        raise ValueError("server_profile_invalid")
    try:
        return ServerProfileRevision(match.group(1), int(match.group(2)), match.group(3))
    except ProfileError:
        raise ValueError("server_profile_invalid") from None


# --- documents ---------------------------------------------------------------------------------


def _encode(document: Mapping[str, JsonValue]) -> bytes:
    return canonical_encode(dict(document))


def _decode(
    body: object, keys: frozenset[str], *, limit: int = MAX_DOCUMENT_BYTES
) -> dict[str, JsonValue]:
    if type(body) is not bytes or len(body) > limit:
        raise RestDocumentError
    try:
        value = strict_json_parse(body)
    except ValueError:
        raise RestDocumentError from None
    if not isinstance(value, Mapping):
        raise RestDocumentError
    document = dict(cast(Mapping[str, JsonValue], value))
    if frozenset(document) != keys or document.get("schema_version") != REST_SCHEMA_VERSION:
        raise RestDocumentError
    return document


def _strings(value: JsonValue, *, maximum: int) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not 1 <= len(value) <= maximum:
        raise RestDocumentError
    items = tuple(value)
    if any(type(item) is not str for item in items):
        raise RestDocumentError
    return cast(tuple[str, ...], items)


def rest_error_document(reason: str) -> bytes:
    """The body of a transport refusal: ``{reason, schema_version}`` with a closed reason."""

    if reason not in REST_ERROR_STATUS:
        raise ValueError("rest_error_reason_invalid")
    return _encode({"reason": reason, "schema_version": REST_SCHEMA_VERSION})


def parse_rest_error(body: object) -> str | None:
    """The closed reason of a transport refusal body, or ``None`` when it is not one."""

    try:
        document = _decode(body, frozenset({"reason", "schema_version"}))
    except RestDocumentError:
        return None
    reason = document["reason"]
    return reason if type(reason) is str and reason in REST_ERROR_STATUS else None


@dataclass(frozen=True, slots=True)
class Discovery:
    """``GET /.well-known/finishup``: what a FinishUP REST server is, before any credential.

    Minimal on purpose (design v2 section 2.1): the product, the REST majors, the API manifests it
    serves, the authentication methods, the fixed profile route and the server's ``official``
    claim (a claim only: it never counts on its own). No release, no instance id, no key.
    """

    rest_majors: tuple[str, ...]
    api_manifests: tuple[str, ...]
    auth: tuple[str, ...] = ("api_key",)
    profile_endpoint: str = PROFILE_PATH
    official: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.rest_majors) is not tuple
            or not self.rest_majors
            or len(self.rest_majors) > 8
            or any(
                type(item) is not str or not item.isdigit() or len(item) > 3
                for item in self.rest_majors
            )
            or list(self.rest_majors) != sorted(set(self.rest_majors), key=int)
        ):
            raise RestDocumentError
        if (
            type(self.api_manifests) is not tuple
            or not 1 <= len(self.api_manifests) <= _MAX_API_MANIFESTS
            or any(
                type(item) is not str or not _SHA256.fullmatch(item) for item in self.api_manifests
            )
            or list(self.api_manifests) != sorted(set(self.api_manifests))
        ):
            raise RestDocumentError
        if (
            type(self.auth) is not tuple
            or not self.auth
            or len(self.auth) > 8
            or any(
                type(item) is not str or not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", item)
                for item in self.auth
            )
            or list(self.auth) != sorted(set(self.auth))
        ):
            raise RestDocumentError
        if type(self.profile_endpoint) is not str or not re.fullmatch(
            r"/[A-Za-z0-9/._-]{1,127}", self.profile_endpoint
        ):
            raise RestDocumentError
        if type(self.official) is not bool:
            raise RestDocumentError


_DISCOVERY_KEYS: Final = frozenset(
    {
        "api_manifests",
        "auth",
        "official",
        "product",
        "profile_endpoint",
        "rest_majors",
        "schema_version",
    }
)


def discovery_document(discovery: Discovery) -> bytes:
    if type(discovery) is not Discovery:
        raise TypeError("discovery_invalid")
    return _encode(
        {
            "api_manifests": list(discovery.api_manifests),
            "auth": list(discovery.auth),
            "official": discovery.official,
            "product": PRODUCT,
            "profile_endpoint": discovery.profile_endpoint,
            "rest_majors": list(discovery.rest_majors),
            "schema_version": REST_SCHEMA_VERSION,
        }
    )


def parse_discovery(body: object) -> Discovery:
    """A discovery document, bounded and strict (``RestDocumentError`` otherwise)."""

    document = _decode(body, _DISCOVERY_KEYS, limit=MAX_DISCOVERY_BYTES)
    if document["product"] != PRODUCT:
        raise RestDocumentError
    return Discovery(
        rest_majors=_strings(document["rest_majors"], maximum=8),
        api_manifests=_strings(document["api_manifests"], maximum=_MAX_API_MANIFESTS),
        auth=_strings(document["auth"], maximum=8),
        profile_endpoint=cast(str, document["profile_endpoint"]),
        official=cast(bool, document["official"]),
    )


@dataclass(frozen=True, slots=True)
class Session:
    """``GET /v1/session``: what a control hello answers, for one claim (or none).

    The service status the request reached, whether the request's claim was keyed
    (``client_claim``) and the workspace handle it was keyed to (``None`` while the server cannot
    key it, a locked vault say), and the profile revision the request was admitted under.
    """

    status: ServiceStatus
    workspace_binding: WorkspaceBinding
    workspace_handle: str | None
    server_profile: ServerProfileRevision

    def __post_init__(self) -> None:
        if type(self.status) is not ServiceStatus:
            raise RestDocumentError
        if self.workspace_binding not in _BINDINGS:
            raise RestDocumentError
        if self.workspace_handle is not None and (
            self.workspace_binding != "client_claim"
            or not workspace_handle_valid(self.workspace_handle)
        ):
            raise RestDocumentError
        if type(self.server_profile) is not ServerProfileRevision:
            raise RestDocumentError


_SESSION_KEYS: Final = frozenset(
    {"schema_version", "server_profile", "status", "workspace_binding", "workspace_handle"}
)


def session_document(session: Session) -> bytes:
    from finishup.protocol.server_profile import revision_to_json
    from finishup.service.control_protocol import service_status_wire

    if type(session) is not Session:
        raise TypeError("session_invalid")
    return _encode(
        {
            "schema_version": REST_SCHEMA_VERSION,
            "server_profile": revision_to_json(session.server_profile),
            "status": cast(JsonValue, service_status_wire(session.status)),
            "workspace_binding": session.workspace_binding,
            "workspace_handle": session.workspace_handle,
        }
    )


def parse_session(body: object) -> Session:
    from finishup.protocol.server_profile import revision_from_json
    from finishup.service.control_protocol import service_status_from_wire

    document = _decode(body, _SESSION_KEYS)
    try:
        return Session(
            status=service_status_from_wire(document["status"]),
            workspace_binding=cast(WorkspaceBinding, document["workspace_binding"]),
            workspace_handle=cast(str | None, document["workspace_handle"]),
            server_profile=revision_from_json(document["server_profile"]),
        )
    except RestDocumentError:
        raise
    except Exception:  # noqa: BLE001 - every malformed member refuses the whole document
        raise RestDocumentError from None


def operation_pending_document(operation_id: str) -> bytes:
    """``202``: the call is still running; follow it at ``/v1/operations/{id}``."""

    if not operation_id_valid(operation_id):
        raise ValueError("operation_id_invalid")
    return _encode(
        {"operation_id": operation_id, "schema_version": REST_SCHEMA_VERSION, "state": "pending"}
    )


def parse_operation_pending(body: object) -> str:
    document = _decode(body, frozenset({"operation_id", "schema_version", "state"}))
    operation_id = document["operation_id"]
    if document["state"] != "pending" or not operation_id_valid(operation_id):
        raise RestDocumentError
    return cast(str, operation_id)


def agent_declaration_document(declaration: WorkspaceAgentDeclaration) -> bytes:
    """``POST /v1/agents`` body: the agent's offer, the same members a hello's agent has."""

    if type(declaration) is not WorkspaceAgentDeclaration:
        raise TypeError("workspace_agent_invalid")
    return _encode(
        {
            "max_reply_bytes": declaration.max_reply_bytes,
            "operations": list(declaration.operations),
            "role": declaration.role,
            "schema_version": declaration.schema_version,
        }
    )


def parse_agent_declaration(body: object) -> WorkspaceAgentDeclaration:
    document = _decode(body, frozenset({"max_reply_bytes", "operations", "role", "schema_version"}))
    try:
        return WorkspaceAgentDeclaration(
            operations=_strings(document["operations"], maximum=64),
            max_reply_bytes=cast(int, document["max_reply_bytes"]),
            role=cast(Literal["connection", "background"], document["role"]),
        )
    except (TypeError, ValueError):
        raise RestDocumentError from None


@dataclass(frozen=True, slots=True)
class AgentRegistration:
    """``201`` answer to ``POST /v1/agents``: the agent id and the handle it answers for."""

    agent_id: str
    workspace_handle: str
    lease_ms: int

    def __post_init__(self) -> None:
        if not agent_id_valid(self.agent_id):
            raise RestDocumentError
        if not workspace_handle_valid(self.workspace_handle):
            raise RestDocumentError
        if type(self.lease_ms) is not int or not 1_000 <= self.lease_ms <= 600_000:
            raise RestDocumentError


def new_agent_id() -> str:
    return f"agt_{secrets.token_hex(16)}"


def agent_id_valid(value: object) -> bool:
    return type(value) is str and _AGENT_ID.fullmatch(value) is not None


def agent_registration_document(registration: AgentRegistration) -> bytes:
    return _encode(
        {
            "agent_id": registration.agent_id,
            "lease_ms": registration.lease_ms,
            "schema_version": REST_SCHEMA_VERSION,
            "workspace_handle": registration.workspace_handle,
        }
    )


def parse_agent_registration(body: object) -> AgentRegistration:
    document = _decode(
        body, frozenset({"agent_id", "lease_ms", "schema_version", "workspace_handle"})
    )
    try:
        return AgentRegistration(
            agent_id=cast(str, document["agent_id"]),
            workspace_handle=cast(str, document["workspace_handle"]),
            lease_ms=cast(int, document["lease_ms"]),
        )
    except (TypeError, ValueError):
        raise RestDocumentError from None


@dataclass(frozen=True, slots=True)
class AgentWork:
    """``GET /v1/agents/{id}/work``: the pending ``workspace_call`` frames, oldest first."""

    calls: tuple[Mapping[str, JsonValue], ...]


def agent_work_document(calls: Sequence[Mapping[str, JsonValue]]) -> bytes:
    return _encode(
        {
            "calls": [cast(JsonValue, dict(call)) for call in calls],
            "schema_version": REST_SCHEMA_VERSION,
        }
    )


def parse_agent_work(body: object, *, max_bytes: int) -> AgentWork:
    """The agent's pending calls, each one a complete ``workspace_call`` frame as the control
    wire defines it (``control-result`` 2.10.0); anything else refuses the whole document."""

    from finishup.domain.values import freeze_json
    from finishup.service.control_protocol import ControlProtocolError, parse_workspace_call

    document = _decode(body, frozenset({"calls", "schema_version"}), limit=max_bytes)
    calls = document["calls"]
    if not isinstance(calls, (list, tuple)) or len(calls) > _MAX_CALLS_PER_WORK:
        raise RestDocumentError
    items = tuple(calls)
    if any(not isinstance(call, Mapping) for call in items):
        raise RestDocumentError
    for call in items:
        try:
            parse_workspace_call(cast(Any, freeze_json(call)))
        except (ControlProtocolError, TypeError, ValueError):
            raise RestDocumentError from None
    return AgentWork(tuple(cast(Mapping[str, JsonValue], call) for call in items))


# --- the REST API manifest (U18) ---------------------------------------------------------------

_CONTROL_WIRE_VERSION: Final = "2.10.0"
# The schemas whose transitive ``$ref`` closure is the REST v1 public contract.
REST_ROOT_SCHEMAS: Final[tuple[str, ...]] = (
    f"service/control-request-{_CONTROL_WIRE_VERSION}.schema.json",
    f"service/control-result-{_CONTROL_WIRE_VERSION}.schema.json",
    "service/rest-agent-1.0.0.schema.json",
    "service/rest-agent-declaration-1.0.0.schema.json",
    "service/rest-agent-work-1.0.0.schema.json",
    "service/rest-discovery-1.0.0.schema.json",
    "service/rest-error-1.0.0.schema.json",
    "service/rest-operation-1.0.0.schema.json",
    "service/rest-session-1.0.0.schema.json",
    "service/server-profile-1.0.0.schema.json",
    "service/service-status-1.0.0.schema.json",
)
_SCHEMA_NAMESPACE: Final = "https://schemas.yoetz.dev/0.1/"


def _refs(value: object) -> list[str]:
    found: list[str] = []
    stack: list[object] = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, item in cast(dict[str, object], current).items():
                if key == "$ref" and type(item) is str:
                    found.append(item)
                else:
                    stack.append(item)
        elif isinstance(current, list):
            stack.extend(cast(list[object], current))
    return found


def api_manifest_digest(
    members: Mapping[str, str],
    read_schema: Callable[[str], bytes],
    roots: Sequence[str] = REST_ROOT_SCHEMAS,
) -> str:
    """The API manifest over ``roots``' closure; ``members`` maps a schema path to its sha256.

    ``read_schema(path) -> bytes`` reads one schema document. Raises ``RestDocumentError`` when a
    root or a referenced schema is not in ``members`` (a contract that cannot be named exactly is
    never compared).
    """

    closure: dict[str, str] = {}
    pending = list(roots)
    while pending:
        path = pending.pop()
        if path in closure:
            continue
        digest = members.get(path)
        if digest is None:
            raise RestDocumentError("rest_api_manifest_incomplete")
        closure[path] = digest
        document: object = json.loads(read_schema(path))
        for reference in _refs(document):
            target = reference.split("#", 1)[0]
            if not target:
                continue
            if not target.startswith(_SCHEMA_NAMESPACE):
                raise RestDocumentError("rest_api_manifest_incomplete")
            pending.append(target[len(_SCHEMA_NAMESPACE) :])
    listed: list[JsonValue] = [[path, closure[path]] for path in sorted(closure)]
    return "sha256:" + hashlib.sha256(API_MANIFEST_DOMAIN + canonical_encode(listed)).hexdigest()


@functools.cache
def current_api_manifest() -> str:
    """This release's REST API manifest, from its packaged schema manifest (computed once)."""

    root = resources.files("finishup").joinpath("resources", "schemas")
    manifest = json.loads(root.joinpath("manifest.json").read_bytes())
    members = {
        cast(str, member["path"]): cast(str, member["sha256"])
        for member in cast(list[dict[str, object]], manifest["members"])
    }

    def read(path: str) -> bytes:
        resource = root
        for part in path.split("/"):
            resource = resource.joinpath(part)
        return resource.read_bytes()

    return api_manifest_digest(members, read)
