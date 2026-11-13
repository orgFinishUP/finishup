"""Bounded ordinary client for the authenticated per-user FinishUP service."""

from __future__ import annotations

import asyncio
import contextvars
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Awaitable, Buffer, Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Final, Literal, Protocol, TypedDict, cast

from finishup import __version__
from finishup.adapters.control.unix_socket import (
    LocalControlTransportError,
    connect_control,
)
from finishup.client.attribution import (
    CONNECTION_LEVELS,
    CONNECTION_TRANSPORTS,
    ConnectionLevel,
    ConnectionTransport,
)
from finishup.config.env import canonical_env_name
from finishup.config.paths import (
    ISOLATED_ROOT_ENV_NAMES,
    PathSafetyError,
    active_root,
    ensure_owner_only_dir,
    log_dir,
)
from finishup.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    ConsentSource,
    CredentialHeuristic,
    EgressChannel,
    EgressOriginOperation,
    EgressReceipt,
    LocalDisclosureReceipt,
    LocalDisclosureSink,
    NonLlmDestination,
    PrivacyOutcome,
    PrivacyReason,
    ProviderBinding,
    ReceiptCapacity,
    ReceiptCounts,
    ReceiptPolicyBinding,
    ReceiptSecretScan,
    ReceiptSecretScanStage,
    ReceiptTransformations,
    RequestCommitment,
    ScanMatchClass,
)
from finishup.domain.values import (
    JsonObject,
    JsonValue,
    format_rfc3339_millis,
    parse_rfc3339_millis,
)
from finishup.ports.control import (
    ControlCallBody,
    ControlCallRequest,
    ControlCancelRequest,
    ControlClientKind,
    ControlClientPort,
    ControlError,
    ControlMethod,
    ControlResult,
    McpHostProfile,
    McpRouteProfile,
    ProjectionRenderMode,
    ServiceStatus,
    ServiceStopResult,
    WorkspaceAgentDeclaration,
    WorkspaceBinding,
    WorkspaceCall,
    WorkspaceClaim,
    WorkspaceLocator,
    WorkspaceReply,
)
from finishup.ports.privacy import (
    LocalDisclosureReceiptView,
    NetworkEgressReceiptView,
    PrivacyReceiptPage,
    PrivacyReceiptView,
)
from finishup.ports.workspace_agent import outcome_for_reason
from finishup.protocol.canonical import (
    canonical_encode,
    parse_canonical_integer_string,
    strict_json_parse,
)
from finishup.protocol.errors import (
    AUTHORIZATION_REFUSAL_PHASES,
    REMOTE_CONNECTION_PHASES,
    SERVICE_HANDSHAKE_PHASES,
    SERVICE_START_TIMEOUT_PHASE,
)
from finishup.protocol.ids import IdKind, new_id, validate_id, validate_opaque_item_id
from finishup.protocol.models import (
    CheckRequest,
    CheckResult,
    DataCategory,
    PublishWorkRequest,
    PublishWorkResult,
    ReceiptRequest,
    ReceiptResult,
    RespondRequest,
    RespondResult,
    StartRequest,
    StartResult,
    StatusRequest,
    StatusResult,
)
from finishup.protocol.server_profile import (
    ProfileError,
    ServerProfile,
    ServerProfileRevision,
    profile_from_json,
)
from finishup.service.control_protocol import (
    CONTROL_PROTOCOL_VERSION,
    ControlProtocolError,
    ControlSession,
    ControlStream,
    client_handshake,
    encode_control_frame,
    is_workspace_call_frame,
    parse_control_result,
    parse_workspace_call,
    read_control_frame,
    validate_request,
    validate_result,
    workspace_reply_frame,
    write_control_frame,
)

if TYPE_CHECKING:
    from finishup.client.helper_status import HelperStamp
    from finishup.service.confidential_protocol import OwnerReceiptViewTarget
    from finishup.service.lifecycle import SingletonHolder

__all__ = [
    "GENERATION_RECHECK_SECONDS",
    "AuthorizationCheck",
    "ClientWorkspaceBinding",
    "GetPrivacyReceiptRequest",
    "ListPrivacyReceiptsRequest",
    "PreparedProjectRequest",
    "PrivacyReceiptFilters",
    "PrivacyReceiptFound",
    "PrivacyReceiptGetResult",
    "PrivacyReceiptNotFound",
    "ServiceClient",
    "WorkspaceCallHandler",
    "accepted_but_unresponsive",
    "connect_service",
    "connect_service_on_demand",
    "connect_service_via",
    "holder_version_order",
    "newer_helper_build_holds_selection",
    "path_refusal_reason",
    "prepare_project_request",
    "service_holder_identity",
    "supersede_incompatible_service",
    "wait_for_singleton_release",
]

_MAX_IN_FLIGHT: Final = 32
# How often a connection admitted to a server elsewhere re-checks its authorization (ADR-052), in
# seconds; ``finishup.client.repository_hold.HOLD_RECHECK_SECONDS``, spelled here so the service
# package imports no client code. A connection whose authorization lapses ends within one check.
GENERATION_RECHECK_SECONDS: Final = 1.0
# The phase every lapse of an open connection's authorization ends it with, whatever changed: it
# has already sent something (its hello, at least), so what FinishUP can say is that it stopped
# sending over it, never that nothing was sent (design v2 section 8.10, ADR-052). The refusal now
# in force is named before anything is sent, by the next connection's admission.
_LAPSED_PHASE: Final = "server_authorization_changed"
# The hidden ``service run`` option a spawner whose root is the everyday installation passes, so the
# service never reads a server selection its spawner did not use (``config.paths``).
_AMBIENT_ROOT_OPTION: Final = "--ambient-root"
# At most this many workspace calls run at once on one connection (ADR-051). A call beyond them is
# answered ``agent_busy`` at once, so a slow read never holds the connection's other calls back,
# and a slot stays taken until its worker thread has actually finished.
_MAX_WORKSPACE_CALLS: Final = 4
# The length prefix ``encode_control_frame`` puts before a frame's canonical JSON.
_FRAME_PREFIX_BYTES: Final = 4
_CANCEL_SEND_TIMEOUT_SECONDS: Final = 0.05
_STREAM_CLOSE_TIMEOUT_SECONDS: Final = 0.05
_WORKFLOW_METHODS: Final = frozenset(
    {
        ControlMethod.START,
        ControlMethod.PUBLISH_WORK,
        ControlMethod.CHECK,
        ControlMethod.RESPOND,
        ControlMethod.STATUS,
        ControlMethod.RECEIPT,
    }
)
_LIFECYCLE_METHODS: Final = frozenset(
    {ControlMethod.SERVICE_STATUS, ControlMethod.SERVICE_LOCK, ControlMethod.SERVICE_STOP}
)
_PRIVATE_CONSTRUCTOR_TOKEN: Final = object()
_CONNECT_HANDSHAKE_TIMEOUT_SECONDS: Final = 5.0
_SERVICE_START_TIMEOUT_SECONDS: Final = 30.0
_SERVICE_START_POLL_SECONDS: Final = 0.05
# The packaged schema manifest's bound when the build installed now is read from its files.
_INSTALLED_MANIFEST_MAX_BYTES: Final = 8_388_608
# A listening service shown to be a different FinishUP installation (or generation) sharing the one
# per-user endpoint: it answered with another manifest or protocol, or closed on this client's
# hello while its singleton stamp names another identity (``_unanswered_hello``). Both reasons
# name that condition; only these may make on-demand startup replace the running process.
_SUPERSEDE_REASONS: Final = frozenset({"service_incompatible", "protocol_mismatch"})
_SECRET_ENV_MARKERS: Final = (
    "API_KEY",
    "AUTHORIZATION",
    "CREDENTIAL",
    "PASSWORD",
    "SECRET",
    "TOKEN",
)
_SERVICE_CONFIG_ENV_NAMES: Final = frozenset(
    {
        "FINISHUP_CONFIG",
        # The exact-target isolation root must reach the detached service process, or an
        # isolated client would spawn a service whose state, storage, and endpoints silently
        # land in the ambient install (issue #518).
        "FINISHUP_ISOLATED_ROOT",
        "FINISHUP_LOG_LEVEL",
        "FINISHUP_PROFILE",
        "FINISHUP_PROVIDER_ENDPOINT_PROFILE_ID",
        "FINISHUP_PROVIDER_ENDPOINT_PROFILE_VERSION",
        "FINISHUP_PROVIDER_ID",
        "FINISHUP_PROVIDER_MODEL",
        "FINISHUP_PROVIDER_TIMEOUT_SECONDS",
        "FINISHUP_STORAGE_DATA_DIR",
        "FINISHUP_STORAGE_DURABILITY",
        "FINISHUP_VERIFICATION_MAX_FINDINGS",
        "FINISHUP_VERIFICATION_SEMANTIC",
    }
)


def _forwarded_to_service(name: str) -> bool:
    """Whether one inherited variable may reach the detached service process.

    A product variable is forwarded under whichever spelling it arrived in: the service reads the
    legacy ``YOETZ_`` spelling of an allowlisted name too, and refuses two that disagree (ADR-048).
    """

    canonical = canonical_env_name(name)
    return canonical is None or canonical in _SERVICE_CONFIG_ENV_NAMES


def _service_environment() -> dict[str, str]:
    """Return inherited nonsecret process context for the detached service.

    The service never consumes provider credentials from ambient environment state.  Filtering
    secret-shaped names here also prevents an unrelated harness/API credential inherited by the
    MCP bridge from becoming visible in the service process metadata.
    """

    environment = {
        name: value
        for name, value in os.environ.items()
        if not any(marker in name.upper() for marker in _SECRET_ENV_MARKERS)
        and _forwarded_to_service(name)
    }
    # A runtime pin resolves the root without the variable (issue #604). The detached service
    # runs the same interpreter and would resolve the same pin, but forwarding the resolved root
    # explicitly keeps the chain visible and identical to the environment-selected case. Both
    # spellings carry it (ADR-048), so the child agrees with itself under either name. A server
    # selection (ADR-051) is forwarded the same way: the spawned service is that target's own.
    try:
        root = active_root()
    except PathSafetyError:
        root = None
    if root is not None:
        for name in ISOLATED_ROOT_ENV_NAMES:
            environment[name] = str(root)
    return environment


def _open_service_stderr_log() -> BinaryIO:
    root = log_dir()
    ensure_owner_only_dir(root)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(root / "service.stderr.jsonl", flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        return cast(BinaryIO, os.fdopen(descriptor, "ab", buffering=0))
    except BaseException:
        os.close(descriptor)
        raise


@dataclass(frozen=True, slots=True)
class _SpawnedService:
    """A detached service this process started, and the id it records a startup failure under."""

    process: subprocess.Popen[bytes]
    startup_correlation_id: str


def _refuse_remote_target_root() -> None:
    """A remote server target's root is never connected to and never starts a service (ADR-051).

    Its record names a remote kind, or cannot be read and may: every connection and spawn is
    refused at once, before anything is sent or started, instead of trying an endpoint no service
    of this computer serves or starting a child that refuses unseen while the caller waits out its
    whole start budget. The shared connection check decides first
    (``targets.require_current_authorization``): ``zero_network_remote_selected`` and
    ``target_reauthorization_required`` keep their names (ADR-051 decision 8); every other remote
    root is the closed phase ``target_root_is_remote``, since this release reaches no server on
    another machine. A root that cannot be resolved at all is left to the caller's own
    path-safety refusal.
    """

    from finishup.client.targets import (
        TargetError,
        TargetRecordUnreadable,
        active_target_record,
        require_current_authorization,
    )

    try:
        record = active_target_record()
    except TargetRecordUnreadable:
        raise ControlError(
            "service_unavailable", retryable=True, phase="target_root_is_remote"
        ) from None
    except TargetError:
        return
    if record is None or not record.is_remote:
        return
    try:
        require_current_authorization(record)
    except TargetError as error:
        raise _remote_target_refusal(error) from None
    raise ControlError("service_unavailable", retryable=True, phase="target_root_is_remote")


def _remote_target_refusal(error: Exception) -> ControlError:
    """A remote root's own ``TargetError`` as the retryable phase every surface renders.

    ``zero_network_remote_selected`` and ``target_reauthorization_required`` keep their names; any
    other reason is ``target_root_is_remote``. The reason is a closed token and names no path.
    """

    reason = getattr(error, "reason", None)
    phase = reason if reason in REMOTE_CONNECTION_PHASES else "target_root_is_remote"
    return ControlError("service_unavailable", retryable=True, phase=phase)


def _spawn_service_process() -> _SpawnedService:
    """Start one detached service that records any startup failure under a fresh id (#1040).

    A remote server target's root raises ``service_unavailable`` with its closed phase
    (``_refuse_remote_target_root``) and starts nothing.
    """

    _refuse_remote_target_root()
    startup_correlation_id = new_id(IdKind.CORRELATION)
    command: tuple[str, ...] = (
        sys.executable,
        "-m",
        "finishup",
        "service",
        "run",
        "--startup-correlation-id",
        startup_correlation_id,
    )
    with _open_service_stderr_log() as stderr_log:
        environment = _service_environment()
        if not any(name in environment for name in ISOLATED_ROOT_ENV_NAMES):
            # No variable, pin or selection decided this process's root, so it uses the everyday
            # installation; the service it starts must too, whatever the selection file says by
            # the time that service reads it (ADR-051). A resolved root rides in the variable.
            command = (*command, _AMBIENT_ROOT_OPTION)
        if os.name == "nt":
            creationflags = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)) | int(
                getattr(subprocess, "DETACHED_PROCESS", 0),
            )
            process = subprocess.Popen(  # noqa: S603 - fixed interpreter/module/arguments
                command,
                close_fds=True,
                creationflags=creationflags,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stderr_log,
            )
        else:
            process = subprocess.Popen(  # noqa: S603 - fixed interpreter/module/arguments
                command,
                close_fds=True,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stderr_log,
                start_new_session=True,
            )
    return _SpawnedService(process, startup_correlation_id)


def _spawned_startup_failure(spawned: _SpawnedService) -> ControlError | None:
    """Name the startup failure of a service this process spawned, once it has exited.

    A spawned service that exits having recorded a startup failure under the id it was given will
    fail the same way on every spawn, so waiting out the rest of the budget only hides why. One
    that exits without a record (it lost the singleton to a concurrent start) says nothing, and
    the caller keeps polling for whichever service holds the endpoint.
    """

    if spawned.process.poll() is None:
        return None
    from finishup.service.startup_failure import read_startup_failure

    failure = read_startup_failure(spawned.startup_correlation_id)
    if failure is None:
        return None
    return ControlError(
        "service_unavailable",
        retryable=False,
        correlation_id=failure.correlation_id,
        phase=failure.stage,
    )


class WorkspaceCallHandler(Protocol):
    """What answers ``workspace_call`` frames on a claim-bound connection (ADR-051).

    ``finishup.client.workspace_agent.WorkspaceAgentHandler`` is the production handler. ``answer``
    runs in a worker thread, never on the event loop; it returns the reply to the call it was given
    and should never raise (a raise is answered ``failed`` with ``internal_error``).
    """

    @property
    def declaration(self) -> WorkspaceAgentDeclaration: ...

    def answer(self, call: WorkspaceCall, *, workspace_handle: str | None) -> WorkspaceReply: ...


class AuthorizationCheck(Protocol):
    """Whether a connection to a server elsewhere may go on (ADR-052).

    ``finishup.client.authorization.ConnectionAuthorization`` is the production check (and
    ``finishup.client.repository_hold.SendHold`` the hold alone); declared structurally here so
    the service package imports no client code. ``refusal()`` is None while the connection may go
    on, else the closed remote phase that refuses it (``server_authorization_changed``, a
    zero-network report, the repository hold). It reads small owner-only files and never raises; a
    long-lived holder re-checks it before every frame and at least once a second. Before anything
    is written the phase itself refuses the connection; once it is open, any phase ends it as
    ``server_authorization_changed``.
    """

    def refusal(self) -> str | None: ...


@dataclass(frozen=True, slots=True)
class ClientWorkspaceBinding:
    """How a connection to a FinishUP server on another machine names its workspace (ADR-051).

    ``claim`` takes the place of the workspace locator in the hello, so no path is sent. ``agent``,
    when set, is declared in the hello and answers the server's workspace calls on this
    connection; without one the connection answers none. ``authorization``, when set, is the
    check the connection was admitted under (ADR-052), bound to this repository's hold: the
    binding was made while it passed, and the connection re-checks it before every frame and on
    its watch.

    ``copy_control`` (``server code list``/``forget``, #1357) names only the copy a server keeps
    of the claimed repository (ADR-054): no agent, no check of its own and no worktree, so it is
    admitted by the shared gate alone, never by the repository's hold, is made directly (never
    relayed by the target's helper, whose relay binds a claim to that hold) and sends no request
    but ``code_copy`` (``ServiceClient.copy_only``).
    """

    claim: WorkspaceClaim
    agent: WorkspaceCallHandler | None = None
    authorization: AuthorizationCheck | None = None
    # The worktree top level the claim was made for, on this computer only (never sent): what a
    # registration with the target's helper names (ADR-052, ``client.helper_registrations``).
    worktree: str | None = field(default=None, repr=False)
    # The repository key the binding's hold is decided by (``client.repository_hold``), on this
    # computer only: the target's helper binds a relayed connection to it (``helper_status``'s
    # relay binding), never sent anywhere else.
    repository_key: str | None = field(default=None, repr=False)
    copy_control: bool = field(default=False, repr=False)

    def __post_init__(self) -> None:
        if type(self.claim) is not WorkspaceClaim:
            raise TypeError("workspace_claim_invalid")
        if self.agent is not None and type(self.agent.declaration) is not WorkspaceAgentDeclaration:
            raise TypeError("workspace_agent_invalid")
        if type(self.copy_control) is not bool:
            raise TypeError("workspace_binding_invalid")
        if self.copy_control and (
            self.agent is not None
            or self.authorization is not None
            or self.worktree is not None
            or self.repository_key is not None
        ):
            # Copy control names the copy and nothing else (no workspace served, no hold bound).
            raise ValueError("workspace_binding_invalid")


@dataclass(frozen=True, slots=True)
class PrivacyReceiptFilters:
    outcome: PrivacyOutcome | None = None
    channel: EgressChannel | None = None
    sink: LocalDisclosureSink | None = None
    provider_id: str | None = None
    endpoint_profile_id: str | None = None
    policy_version: int | None = None
    scope_kind: AuthorizationScopeKind | None = None
    finished_from: datetime | None = None
    finished_through: datetime | None = None

    def __post_init__(self) -> None:
        for value, expected in (
            (self.outcome, PrivacyOutcome),
            (self.channel, EgressChannel),
            (self.sink, LocalDisclosureSink),
            (self.scope_kind, AuthorizationScopeKind),
        ):
            if value is not None and type(value) is not expected:
                raise TypeError("privacy_receipt_filter_invalid")
        for value in (self.provider_id, self.endpoint_profile_id):
            if value is not None and (type(value) is not str or not value):
                raise ValueError("privacy_receipt_filter_invalid")
        if self.policy_version is not None and (
            type(self.policy_version) is not int or self.policy_version <= 0
        ):
            raise ValueError("privacy_receipt_filter_invalid")
        if self.finished_from is not None:
            format_rfc3339_millis(self.finished_from)
        if self.finished_through is not None:
            format_rfc3339_millis(self.finished_through)
        if (
            self.finished_from is not None
            and self.finished_through is not None
            and self.finished_from > self.finished_through
        ):
            raise ValueError("privacy_receipt_filter_invalid")

    def _wire(self) -> JsonObject:
        values: dict[str, JsonValue] = {}
        for name in ("outcome", "channel", "sink", "scope_kind"):
            value = getattr(self, name)
            if value is not None:
                values[name] = value.value
        for name in ("provider_id", "endpoint_profile_id"):
            value = getattr(self, name)
            if value is not None:
                values[name] = value
        if self.policy_version is not None:
            values["policy_version"] = str(self.policy_version)
        if self.finished_from is not None:
            values["finished_from"] = format_rfc3339_millis(self.finished_from)
        if self.finished_through is not None:
            values["finished_through"] = format_rfc3339_millis(self.finished_through)
        return JsonObject(values)


@dataclass(frozen=True, slots=True)
class ListPrivacyReceiptsRequest:
    filters: PrivacyReceiptFilters = field(default_factory=PrivacyReceiptFilters)
    page_size: int = 50
    cursor: str | None = None
    schema_version: Literal["1.0.0"] = "1.0.0"

    def __post_init__(self) -> None:
        if type(self.filters) is not PrivacyReceiptFilters:
            raise TypeError("privacy_receipt_filters_invalid")
        if type(self.page_size) is not int or not 1 <= self.page_size <= 100:
            raise ValueError("privacy_receipt_page_size_invalid")
        if self.cursor is not None and (
            type(self.cursor) is not str or not 1 <= len(self.cursor) <= 1_024
        ):
            raise ValueError("privacy_receipt_cursor_invalid")
        if self.schema_version != "1.0.0":
            raise ValueError("privacy_receipt_schema_version_invalid")

    def _wire(self) -> JsonObject:
        values: dict[str, JsonValue] = {
            "schema_version": self.schema_version,
            "filters": self.filters._wire(),  # pyright: ignore[reportPrivateUsage]
            "page_size": self.page_size,
        }
        if self.cursor is not None:
            values["cursor"] = self.cursor
        return JsonObject(values)


@dataclass(frozen=True, slots=True)
class GetPrivacyReceiptRequest:
    receipt_id: str
    schema_version: Literal["1.0.0"] = "1.0.0"

    def __post_init__(self) -> None:
        validate_id(IdKind.EGRESS_RECEIPT, self.receipt_id)
        if self.schema_version != "1.0.0":
            raise ValueError("privacy_receipt_schema_version_invalid")

    def _wire(self) -> JsonObject:
        return JsonObject({"schema_version": self.schema_version, "receipt_id": self.receipt_id})


@dataclass(frozen=True, slots=True)
class PrivacyReceiptFound:
    receipt: PrivacyReceiptView
    schema_version: Literal["1.0.0"] = "1.0.0"
    outcome: Literal["found"] = "found"

    def __post_init__(self) -> None:
        if self.schema_version != "1.0.0" or self.outcome != "found":
            raise ValueError("privacy_receipt_get_result_invalid")
        if type(self.receipt) not in {
            NetworkEgressReceiptView,
            LocalDisclosureReceiptView,
        }:
            raise TypeError("privacy_receipt_get_result_invalid")


@dataclass(frozen=True, slots=True)
class PrivacyReceiptNotFound:
    schema_version: Literal["1.0.0"] = "1.0.0"
    outcome: Literal["not_found"] = "not_found"

    def __post_init__(self) -> None:
        if self.schema_version != "1.0.0" or self.outcome != "not_found":
            raise ValueError("privacy_receipt_get_result_invalid")


type PrivacyReceiptGetResult = PrivacyReceiptFound | PrivacyReceiptNotFound


@dataclass(frozen=True, slots=True)
class PreparedProjectRequest:
    """A project body together with the exact request identity sent on the wire.

    Project mutations are journaled by ``request_id``.  Keeping the normalized body and its
    identity together gives callers a safe value to retain when a response is lost or a consent
    continuation requires a later replay.  The project result deliberately remains unchanged;
    this wrapper is client-side request preparation metadata only.
    """

    body: JsonObject
    request_id: str

    def __post_init__(self) -> None:
        if type(self.body) is not JsonObject:
            raise TypeError("project_request_body_invalid")
        validate_id(IdKind.REQUEST, self.request_id)
        if self.body.get("request_id") != self.request_id:
            raise ValueError("project_request_id_mismatch")

    @property
    def request(self) -> JsonObject:
        """Alias for callers that refer to the prepared wire body as a request."""

        return self.body


def prepare_project_request(
    request: JsonObject, *, request_id: str | None = None
) -> PreparedProjectRequest:
    """Add one stable project request identity without changing supplied IDs.

    A body that already carries ``request_id`` is returned with that exact identity.  When the
    body omits it, an explicit ``request_id`` is validated and used; otherwise one is generated
    and returned in the wrapper so the caller can retain the exact body for recovery.  This is
    intentionally separate from the result body: project responses have their own closed schema
    and must not grow request metadata merely to make client retries possible.
    """

    if type(request) is not JsonObject:
        raise TypeError("project_request_body_invalid")
    explicit = None if request_id is None else validate_id(IdKind.REQUEST, request_id)
    supplied = request.get("request_id")
    if supplied is not None:
        selected = validate_id(IdKind.REQUEST, supplied)
        if explicit is not None and selected != explicit:
            raise ValueError("project_request_id_conflict")
        return PreparedProjectRequest(request, selected)
    selected = explicit if explicit is not None else new_id(IdKind.REQUEST)
    values = dict(request)
    values["request_id"] = selected
    return PreparedProjectRequest(JsonObject(values), selected)


class _ReceiptCommon(TypedDict):
    schema_version: Literal["1.0.0", "1.1.0"]
    receipt_id: str
    request_id: str
    privacy_proposal_id: str
    outcome: PrivacyOutcome
    finished_at: datetime
    scope: AuthorizationScope
    purpose: str
    policy: ReceiptPolicyBinding
    consent_source: ConsentSource
    approved_categories: tuple[DataCategory, ...]
    blocked_categories: tuple[DataCategory, ...]
    counts: ReceiptCounts
    transformations: ReceiptTransformations
    secret_scan: ReceiptSecretScan
    withheld_item_ids: tuple[str, ...]
    withheld_item_reason: Literal["never_send_heuristic"] | None
    safe_failure_reason: PrivacyReason | None
    audit_store_version: Literal[1]


def _transport_error(error: LocalControlTransportError) -> ControlError:
    if error.path_reason is not None:
        return _EndpointRootRefused(error.path_reason)
    if error.reason == "peer_untrusted":
        return ControlError("peer_untrusted")
    if error.reason == "endpoint_unsafe":
        return ControlError("endpoint_unsafe")
    return ControlError("service_unavailable", retryable=True)


def _server_profile_of(authorization: AuthorizationCheck | None) -> ServerProfileRevision | None:
    """The server-profile revision an admitted remote connection names in its hello (ADR-052)."""

    revision = getattr(authorization, "server_profile", None)
    return revision if type(revision) is ServerProfileRevision else None


def _sent_outcome(error: ControlError) -> ControlError:
    """What a call whose body was already sent fails with when its connection ends with ``error``.

    A refusal phase says nothing was sent, or that the server did no work for that one request;
    neither holds for another call already sent over the connection, which the server may have
    recorded. Such a call ends as ``server_authorization_changed``: its outcome is unknown and it
    is never sent again (ADR-052, review of layer 3: B2). Any other failure is its own.
    """

    if error.phase in AUTHORIZATION_REFUSAL_PHASES and error.phase != _LAPSED_PHASE:
        return ControlError("service_unavailable", retryable=True, phase=_LAPSED_PHASE)
    return error


def _ask_helper_to_refresh(authorization: AuthorizationCheck | None) -> None:
    """Leave the marker that asks a remote target's helper to fetch the profile again, naming
    the profile revision this connection's hello named (the one the server no longer issues)."""

    grant = getattr(authorization, "grant", None)
    target_id = getattr(grant, "target_id", None)
    if type(target_id) is not str:
        return
    try:
        from finishup.client.helper_status import request_profile_refresh
        from finishup.client.targets import target_root

        request_profile_refresh(target_root(target_id), _server_profile_of(authorization))
    except Exception:  # noqa: BLE001 - a marker that cannot be left asks nothing
        return


def _protocol_error(error: ControlProtocolError) -> ControlError:
    if error.reason == "server_profile_changed":
        # The service did not admit this remote client's hello: the profile revision it consented
        # to is not the one the server issues now (ADR-052). The hello was sent, but the service
        # did no work for it: it closed before keying the claim, registering an agent or reading a
        # request, and nothing more was sent.
        return ControlError("service_unavailable", retryable=True, phase="server_profile_changed")
    if error.reason == "manifest_mismatch":
        # The peer is a live FinishUP service from another installation: it answered with a
        # different schema-manifest digest. Retryable: it heals once the endpoint is owned by a
        # service of this installation. A hello closed without any answer (``handshake_rejected``)
        # proves nothing by itself; ``_unanswered_hello`` classifies it.
        return ControlError("service_incompatible", retryable=True)
    if error.reason == "protocol_mismatch":
        return ControlError("protocol_mismatch")
    if error.reason == "peer_untrusted":
        return ControlError("peer_untrusted")
    if error.reason == "frame_too_large":
        return ControlError("frame_too_large")
    if error.reason == "method_forbidden":
        return ControlError("method_forbidden")
    if error.reason in {"frame_invalid", "correlation_mismatch", "duplicate_rpc_id"}:
        return ControlError("frame_invalid")
    # Everything left, `transport_failed` from a failed local write included, is a bounded
    # connection fact: the frame validated and encoded, so the caller never sees INVALID_REQUEST
    # for it and the retry stays open (issue #678).
    return ControlError("service_unavailable", retryable=True)


type _StampIdentity = Literal["same", "other", "legacy", "unknown"]


def _validated_version(value: str | None) -> str | None:
    """A stamped package version that parses as one, else None (never evidence either way)."""

    if value is None:
        return None
    from packaging.version import InvalidVersion, Version

    try:
        Version(value)
    except InvalidVersion:
        return None
    return value


def _stamp_identity(holder: SingletonHolder) -> _StampIdentity:
    """How a stamped holder's identity compares with this installation's, on evidence only.

    ``other`` needs a present, validated field that differs: a schema-manifest digest or a
    package version that is not this installation's. ``same`` needs both fields readable and
    equal. Anything else, a field absent or unreadable beside fields that match, is ``unknown``:
    missing information is never read as another installation, so it never makes a holder
    incompatible or an automatic supersede candidate.

    ``legacy`` is a stamp with neither identity key at all. Yoetz 0.1.x wrote that shape, but so
    did every writer from 0.2.1 until the #1040 follow-up whenever its schema-manifest lookup
    failed, and such a stamp outlives the upgrade for as long as its process runs. Absence alone
    therefore cannot tell an older installation from a compatible one: ``legacy`` is treated like
    ``unknown`` everywhere automatic (an unanswered hello is ``service_handshake_failed``, never
    ``service_incompatible``), and only an explicit ``finishup service restart`` may replace it
    (``supersede_incompatible_service(replace_legacy=True)``).
    """

    if holder.identity_fields_absent:
        return "legacy"
    digest = holder.schema_manifest_digest
    version = _validated_version(holder.service_version)
    if (digest is not None and digest != _manifest_digest_for_client()) or (
        version is not None and version != __version__
    ):
        return "other"
    if digest is not None and version is not None:
        return "same"
    return "unknown"


# The one stamp class that is evidence of another installation: reported as
# ``service_incompatible`` and replaceable without an explicit human restart.
_REPLACEABLE_STAMPS: Final[frozenset[_StampIdentity]] = frozenset({"other"})


def _system_git_below_minimum() -> bool:
    """True when the system Git (the one the service resolves workspaces with) is too old."""

    from finishup.adapters.git_version import git_version, git_version_supported

    executable = shutil.which("git", path=os.defpath)
    return executable is not None and not git_version_supported(git_version(executable))


def _unanswered_hello(workspace_locator: WorkspaceLocator | None) -> ControlError:
    """Classify a hello the listening service closed without answering (#1040 follow-up).

    Two different services do that. One of another installation closes on a hello it cannot
    decode; one of this very installation closes when its own side of the handshake fails, such
    as resolving the caller's repository with a Git it cannot use (it records why). Only the
    owner-only singleton stamp tells them apart, so ``service_incompatible``, whose remedy is
    replacing the service, is reported only when the stamp shows another identity: a validated
    field that differs (``_stamp_identity``). A holder stamped with this installation's
    identity, one whose stamp cannot be read, one whose identity fields are only partly readable,
    and one stamped without any identity field is a failed handshake that is never replaced
    automatically: non-retryable ``service_unavailable`` with ``phase`` ``handshake``, or
    ``handshake_git_version`` when this hello named a workspace and the system Git is older than
    the documented minimum. The correlation id resolves the client-side record; the service's
    own record names the cause.
    """

    holder = service_holder_identity()
    if holder is not None and _stamp_identity(holder) in _REPLACEABLE_STAMPS:
        return ControlError("service_incompatible", retryable=True)
    from finishup.observability.logging import record_public_error_without_raising

    git_too_old = workspace_locator is not None and _system_git_below_minimum()
    correlation_id = record_public_error_without_raising(
        component="service.client",
        operation="control_handshake",
        reason="service_handshake_failed",
        reason_code="git_version_unsupported" if git_too_old else None,
    )
    return ControlError(
        "service_unavailable",
        retryable=False,
        phase="handshake_git_version" if git_too_old else "handshake",
        correlation_id=correlation_id,
    )


def start_timed_out(error: BaseException) -> bool:
    """True when a service of this installation was starting but did not answer in budget."""

    return (
        isinstance(error, ControlError)
        and error.reason == "service_unavailable"
        and error.phase == SERVICE_START_TIMEOUT_PHASE
    )


def starting_service_pid() -> int | None:
    """The pid of a live singleton holder whose lock is held, or None.

    The stamp alone is advisory; the flock corroborates that a service process really holds the
    singleton (it may still be importing or unlocking before it accepts connections).
    """

    holder = service_holder_identity()
    if holder is None or _singleton_holder_lock_is_held() is not True:
        return None
    return holder.pid


def handshake_failure(error: BaseException) -> str | None:
    """The ``SERVICE_HANDSHAKE_PHASES`` member a failed-handshake error carries, or None."""

    if (
        isinstance(error, ControlError)
        and error.reason == "service_unavailable"
        and error.phase in SERVICE_HANDSHAKE_PHASES
    ):
        return error.phase
    return None


def _object(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError("privacy_receipt_wire_invalid")
    return cast(Mapping[str, object], value)


def _decimal(value: object) -> int:
    return parse_canonical_integer_string(cast(str, value))


def _scope_from_wire(value: object) -> AuthorizationScope:
    source = _object(value)
    kind = AuthorizationScopeKind(cast(str, source["kind"]))
    return AuthorizationScope(
        kind=kind,
        installation_id=cast(str, source["installation_id"]),
        workspace_ref_commitment=cast(str | None, source.get("workspace_ref_commitment")),
        task_id=cast(str | None, source.get("task_id")),
        request_id=cast(str | None, source.get("request_id")),
    )


def _policy_from_wire(value: object) -> ReceiptPolicyBinding:
    source = _object(value)
    return ReceiptPolicyBinding(
        policy_id=cast(str, source["policy_id"]),
        version=_decimal(source["version"]),
        policy_digest=cast(str, source["policy_digest"]),
        authorization_scope_digest=cast(str, source["authorization_scope_digest"]),
    )


def _counts_from_wire(value: object) -> ReceiptCounts:
    source = _object(value)
    return ReceiptCounts(
        candidate_items=_decimal(source["candidate_items"]),
        included_items=_decimal(source["included_items"]),
        removed_items=_decimal(source["removed_items"]),
        approved_items=_decimal(source["approved_items"]),
        blocked_items=_decimal(source["blocked_items"]),
        candidate_bytes=_decimal(source["candidate_bytes"]),
        final_bytes=_decimal(source["final_bytes"]),
        estimated_input_tokens=(
            None
            if "estimated_input_tokens" not in source
            else _decimal(source["estimated_input_tokens"])
        ),
        request_body_bytes=(
            None if "request_body_bytes" not in source else _decimal(source["request_body_bytes"])
        ),
    )


def _transformations_from_wire(value: object) -> ReceiptTransformations:
    source = _object(value)
    return ReceiptTransformations(
        minimized_items=_decimal(source["minimized_items"]),
        redacted_spans=_decimal(source["redacted_spans"]),
        blocked_items=_decimal(source["blocked_items"]),
    )


def _secret_scan_from_wire(value: object, *, legacy_unknown: bool = False) -> ReceiptSecretScan:
    source = _object(value)
    match_count = _decimal(source["match_count"])
    passed = cast(bool, source["passed"])
    raw_stage = source.get("stage")
    stage = (
        ReceiptSecretScanStage.LEGACY_UNKNOWN
        if legacy_unknown and raw_stage is None
        else ReceiptSecretScanStage(cast(str, raw_stage or "prepared_case"))
    )
    return ReceiptSecretScan(
        registry_version=cast(str, source["registry_version"]),
        scanner_profile_digest=cast(str, source["scanner_profile_digest"]),
        match_count=match_count,
        passed=passed,
        stage=stage,
        not_run_reason=(
            None
            if source.get("not_run_reason") is None
            else PrivacyReason(cast(str, source["not_run_reason"]))
        ),
        credential_heuristic=(
            CredentialHeuristic.ENFORCED
            if source.get("credential_heuristic") is None
            else CredentialHeuristic(cast(str, source["credential_heuristic"]))
        ),
        # #1138: the refusing match's confidence class and the items it sat in.
        match_class=cast(ScanMatchClass | None, source.get("match_class")),
        match_item_ids=(
            ()
            if source.get("match_item_ids") is None
            else tuple(cast(tuple[str, ...], source["match_item_ids"]))
        ),
    )


def _categories_from_wire(value: object) -> tuple[DataCategory, ...]:
    if type(value) is not tuple:
        raise ValueError("privacy_receipt_wire_invalid")
    members = cast(tuple[object, ...], value)
    return tuple(DataCategory(cast(str, item)) for item in members)


def _withheld_item_ids_from_wire(value: object) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise ValueError("privacy_receipt_wire_invalid")
    members = cast(tuple[object, ...], value)
    if any(not _valid_opaque_item_id(item) for item in members):
        raise ValueError("privacy_receipt_wire_invalid")
    return tuple(cast(str, item) for item in members)


def _valid_opaque_item_id(value: object) -> bool:
    try:
        validate_opaque_item_id(value)
    except ValueError:
        return False
    return True


def _destination_from_wire(value: object) -> ProviderBinding | NonLlmDestination:
    source = _object(value)
    if "provider_id" in source:
        return ProviderBinding(
            provider_id=cast(str, source["provider_id"]),
            model_id=cast(str, source["model_id"]),
            endpoint_profile_id=cast(str, source["endpoint_profile_id"]),
            endpoint_profile_version=cast(str, source["endpoint_profile_version"]),
            transport=cast(Literal["external", "local_af_unix"], source["transport"]),
        )
    return NonLlmDestination(
        kind=EgressChannel(cast(str, source["kind"])),
        profile_id=cast(str, source["profile_id"]),
        profile_version=cast(str, source["profile_version"]),
    )


def _request_commitment_from_wire(value: object) -> RequestCommitment:
    source = _object(value)
    return RequestCommitment(
        algorithm=cast(
            Literal["hmac-sha256/yoetz-privacy-egress-request-v1"],
            source["algorithm"],
        ),
        commitment=cast(str, source["commitment"]),
    )


def _receipt_capacity_from_wire(value: object) -> ReceiptCapacity | None:
    """A size refusal's typed capacity reason (#1129); absent on every other receipt."""

    if value is None:
        return None
    source = _object(value)
    return ReceiptCapacity(
        cast(Literal["disclosure", "excerpt", "excerpt_total"], source["scope"]),
        cast(Literal["bytes", "tokens", "excerpts"], source["unit"]),
        _decimal(source["attempted"]),
        _decimal(source["limit"]),
    )


def _receipt_view_from_wire(value: object) -> PrivacyReceiptView:
    wrapper = _object(value)
    receipt = _object(wrapper["receipt"])
    # Stage-less v1.0 receipts cannot prove whether scanning reached a prepared case.  Preserve
    # that uncertainty even for a historical completed/passed row instead of manufacturing a
    # clean PREPARED_CASE state.
    legacy_scan_unknown = "stage" not in _object(receipt["secret_scan"])
    common: _ReceiptCommon = {
        "schema_version": cast(Literal["1.0.0", "1.1.0"], receipt["schema_version"]),
        "receipt_id": cast(str, receipt["receipt_id"]),
        "request_id": cast(str, receipt["request_id"]),
        "privacy_proposal_id": cast(str, receipt["privacy_proposal_id"]),
        "outcome": PrivacyOutcome(cast(str, receipt["outcome"])),
        "finished_at": parse_rfc3339_millis(receipt["finished_at"]),
        "scope": _scope_from_wire(receipt["scope"]),
        "purpose": cast(str, receipt["purpose"]),
        "policy": _policy_from_wire(receipt["policy"]),
        "consent_source": ConsentSource(cast(str, receipt["consent_source"])),
        "approved_categories": _categories_from_wire(receipt["approved_categories"]),
        "blocked_categories": _categories_from_wire(receipt["blocked_categories"]),
        "counts": _counts_from_wire(receipt["counts"]),
        "transformations": _transformations_from_wire(receipt["transformations"]),
        "secret_scan": _secret_scan_from_wire(
            receipt["secret_scan"], legacy_unknown=legacy_scan_unknown
        ),
        "withheld_item_ids": _withheld_item_ids_from_wire(receipt.get("withheld_item_ids", ())),
        "withheld_item_reason": (
            None
            if receipt.get("withheld_item_reason") is None
            else cast(Literal["never_send_heuristic"], receipt["withheld_item_reason"])
        ),
        "safe_failure_reason": (
            None
            if "safe_failure_reason" not in receipt
            else PrivacyReason(cast(str, receipt["safe_failure_reason"]))
        ),
        "audit_store_version": cast(Literal[1], receipt["audit_store_version"]),
    }
    if wrapper["kind"] == "network_egress":
        network_receipt = EgressReceipt(
            **common,
            channel=EgressChannel(cast(str, receipt["channel"])),
            destination=_destination_from_wire(receipt["destination"]),
            authorization_id=cast(str | None, receipt.get("authorization_id")),
            dispatch_id=cast(str | None, receipt.get("dispatch_id")),
            dispatch_started_at=(
                None
                if "dispatch_started_at" not in receipt
                else parse_rfc3339_millis(receipt["dispatch_started_at"])
            ),
            request_commitment=(
                None
                if "request_commitment" not in receipt
                else _request_commitment_from_wire(receipt["request_commitment"])
            ),
            origin_operation=(
                None
                if "origin_operation" not in receipt
                else EgressOriginOperation(cast(str, receipt["origin_operation"]))
            ),
            capacity_exceeded=_receipt_capacity_from_wire(receipt.get("capacity_exceeded")),
        )
        return NetworkEgressReceiptView(kind="network_egress", receipt=network_receipt)
    local_receipt = LocalDisclosureReceipt(
        **common,
        sink=LocalDisclosureSink(cast(str, receipt["sink"])),
    )
    return LocalDisclosureReceiptView(kind="local_disclosure", receipt=local_receipt)


def _receipt_page_from_wire(value: JsonObject) -> PrivacyReceiptPage:
    source = _object(value)
    raw_receipts = source["receipts"]
    if type(raw_receipts) is not tuple:
        raise ValueError("privacy_receipt_wire_invalid")
    receipt_members = cast(tuple[object, ...], raw_receipts)
    raw_undecodable_ids = source.get("undecodable_receipt_ids", ())
    if type(raw_undecodable_ids) is not tuple:
        raise ValueError("privacy_receipt_wire_invalid")
    return PrivacyReceiptPage(
        snapshot_generation=_decimal(source["snapshot_generation"]),
        receipts=tuple(_receipt_view_from_wire(item) for item in receipt_members),
        next_cursor=cast(str | None, source.get("next_cursor")),
        undecodable_count=(
            0 if "undecodable_count" not in source else _decimal(source["undecodable_count"])
        ),
        undecodable_receipt_ids=tuple(
            cast(str, item) for item in cast(tuple[object, ...], raw_undecodable_ids)
        ),
    )


async def _unreadable_receipt_frame(operation: str) -> ControlError:
    """Name a receipt frame this client validated but cannot turn back into receipts.

    The frame passed the result envelope, so it is neither malformed nor the caller's request:
    what it carries is an audit record the domain refuses. Reporting ``frame_invalid`` here made
    the operator see ``invalid_request`` for a store-side condition (issue #921). The client's own
    diagnostic record makes the correlation id it hands back resolvable.
    """

    from finishup.observability.logging import record_public_error_without_raising

    correlation_id = record_public_error_without_raising(
        component="service.client",
        operation=operation,
        reason="privacy_receipt_wire_undecodable",
    )
    return ControlError("privacy_audit_unreadable", correlation_id=correlation_id)


def _receipt_get_from_wire(value: JsonObject) -> PrivacyReceiptGetResult:
    source = _object(value)
    if source["outcome"] == "not_found":
        return PrivacyReceiptNotFound(
            schema_version=cast(Literal["1.0.0"], source["schema_version"])
        )
    return PrivacyReceiptFound(
        schema_version=cast(Literal["1.0.0"], source["schema_version"]),
        receipt=_receipt_view_from_wire(source["receipt"]),
    )


class ServiceClient(ControlClientPort):
    """One authenticated ordinary-control session.

    Instances are created by :func:`connect_service`.  The package-private connected
    constructor exists solely so protocol tests can inject a bounded fake byte stream.
    """

    __slots__ = (
        "_agent",
        "_agent_busy",
        "_agent_calls",
        "_authorization",
        "_client_kind",
        "_closed",
        "_consent_level",
        "_copy_only",
        "_failure",
        "_last_project_request",
        "_pending",
        "_pid",
        "_receiver",
        "_retired_rpc_ids",
        "_session",
        "_stream",
        "_transport",
        "_watch",
        "_write_lock",
    )

    def __init__(
        self,
        stream: ControlStream,
        session: ControlSession,
        client_kind: ControlClientKind,
        *,
        _token: object,
        workspace_agent: WorkspaceCallHandler | None = None,
        transport: ConnectionTransport = "unix",
        authorization: AuthorizationCheck | None = None,
        recheck: Callable[[], Awaitable[None]] | None = None,
        copy_only: bool = False,
    ) -> None:
        if _token is not _PRIVATE_CONSTRUCTOR_TOKEN:
            raise TypeError("service_client_constructor_private")
        if type(client_kind) is not ControlClientKind:
            raise TypeError("control_client_kind_invalid")
        if transport not in CONNECTION_TRANSPORTS:
            raise ValueError("connection_transport_invalid")
        if workspace_agent is not None and (
            session.workspace_binding != "client_claim"
            or session.workspace_agent != workspace_agent.declaration
        ):
            # An agent answers only on the claim-bound connection whose hello declared it.
            raise ValueError("workspace_agent_invalid")
        self._agent = workspace_agent
        self._agent_busy = 0
        self._agent_calls: dict[str, asyncio.Task[None]] = {}
        self._stream = stream
        self._session = session
        self._transport: ConnectionTransport = transport
        # The level the owner consented to for a server elsewhere (ADR-054); None when local or
        # when the target records no consent. Set once the connection is admitted and made.
        self._consent_level: ConnectionLevel | None = None
        self._client_kind = client_kind
        # A copy-control connection (``ClientWorkspaceBinding.copy_control``) sends no request
        # but ``code_copy``.
        self._copy_only = copy_only is True
        self._pid = os.getpid()
        self._closed = False
        self._last_project_request: PreparedProjectRequest | None = None
        self._pending: dict[str, asyncio.Future[ControlResult]] = {}
        self._retired_rpc_ids: set[str] = set()
        self._write_lock = asyncio.Lock()
        # Why this connection ended when its authorization did: a later call is refused with that
        # phase, not as a lost connection.
        self._failure: ControlError | None = None
        # What a connection to a server elsewhere was admitted under (ADR-052): re-checked before
        # every frame it sends and on its watch. A local connection has none, and no watch (O2).
        self._authorization = authorization
        # The claim and worktree of a claim-bound connection to a server elsewhere, on this
        # computer only (ADR-052): what its owner registers with the target's helper.
        self._remote_workspace: tuple[WorkspaceClaim, str] | None = None
        self._receiver = asyncio.create_task(self._receive_results())
        self._watch = (
            None
            if authorization is None
            else asyncio.create_task(self._watch_authorization(recheck or _recheck_after_interval))
        )

    @property
    def authorization(self) -> AuthorizationCheck | None:
        """What a connection to a server elsewhere was admitted under; ``None`` when local."""

        return self._authorization

    @property
    def copy_only(self) -> bool:
        """Whether this connection sends no request but ``code_copy`` (copy control, #1357)."""

        return self._copy_only

    @property
    def remote_workspace(self) -> tuple[WorkspaceClaim, str] | None:
        """The claim and worktree a claim-bound remote connection serves; ``None`` otherwise."""

        return self._remote_workspace

    @property
    def closed(self) -> bool:
        """Whether this connection has ended (closed, failed, or its authorization lapsed)."""

        return self._closed

    async def wait_closed(self) -> None:
        """Wait until this connection has ended: its peer closed it, it failed, its authorization
        lapsed, or it was closed. A long-lived holder (a helper's background agent) waits here."""

        await asyncio.gather(asyncio.shield(self._receiver), return_exceptions=True)

    def _ensure_live(self) -> None:
        if os.getpid() != self._pid:
            self._closed = True
            raise ControlError("service_unavailable")
        if self._closed:
            if self._failure is not None:
                raise self._failure
            raise ControlError("service_unavailable", retryable=True)

    def _lapsed(self) -> ControlError | None:
        """The retryable refusal once this connection's authorization lapsed; else None.

        Whatever ``AuthorizationCheck.refusal`` names, an open connection ends with
        ``server_authorization_changed`` (``_LAPSED_PHASE``): it stopped sending over a
        connection that already sent something (ADR-052). A check that cannot be made refuses
        nothing new.
        """

        authorization = self._authorization
        if authorization is None:
            return None
        try:
            phase = authorization.refusal()
        except Exception:  # noqa: BLE001 - a check that cannot be made refuses nothing new
            return None
        if phase is None:
            return None
        return ControlError("service_unavailable", retryable=True, phase=_LAPSED_PHASE)

    async def _end_if_lapsed(self) -> None:
        """End this connection with its authorization's phase once it lapsed, and raise it."""

        failure = self._lapsed()
        if failure is not None:
            self._failure = self._failure or failure
            await self._fail_connection(failure)
            raise failure

    async def _watch_authorization(self, recheck: Callable[[], Awaitable[None]]) -> None:
        """Re-check the authorization after each ``recheck`` while the connection is open.

        Once it lapses, the connection ends at once: every pending call fails with
        ``server_authorization_changed``, the server's workspace calls go unanswered, and later
        calls are refused with it. The check
        runs in a worker thread (a few ``lstat`` calls). ``recheck`` waits
        ``GENERATION_RECHECK_SECONDS`` in production; a test injects an event-driven tick.
        """

        try:
            while not self._closed:
                await recheck()
                failure = await asyncio.to_thread(self._lapsed)
                if failure is not None and not self._closed:
                    self._failure = self._failure or failure
                    await self._fail_connection(failure)
                    return
        except asyncio.CancelledError:
            return

    def _admit(self, method: ControlMethod) -> None:
        if self._copy_only and method is not ControlMethod.CODE_COPY:
            # Copy control names a copy so it can be listed or forgotten, nothing more.
            raise ControlError("method_forbidden")
        if self._client_kind is ControlClientKind.MCP_BRIDGE and method not in _WORKFLOW_METHODS:
            raise ControlError("method_forbidden")
        if method in _LIFECYCLE_METHODS and self._client_kind is ControlClientKind.MCP_BRIDGE:
            raise ControlError("method_forbidden")

    async def connect(self) -> None:
        """Confirm that this already-handshaken session remains locally usable.

        A connection to a server elsewhere also re-checks its authorization here (ADR-052): the
        MCP bridge asks before it reuses one, so a lapsed one is named before a request is sent.
        """

        self._ensure_live()
        if self._authorization is not None:
            await self._end_if_lapsed()

    @property
    def hello_service_status(self) -> ServiceStatus | None:
        """The service-status snapshot this session's hello-result carried at connect time."""

        return self._session.service_status

    @property
    def workspace_binding(self) -> WorkspaceBinding:
        """How the service bound this connection to a workspace at handshake (ADR-051)."""

        return self._session.workspace_binding

    @property
    def workspace_handle(self) -> str | None:
        """The ``client:`` handle a claim-bound connection's tasks name their workspace by."""

        return self._session.workspace_handle

    @property
    def service_instance_id(self) -> str:
        """The instance id of the service that answered this connection's hello."""

        return self._session.service_instance_id

    @property
    def transport(self) -> ConnectionTransport:
        """How this connection reaches its service, a closed token (``finishup.client.attribution``).

        Whoever builds the connection names it; ``unix`` for the local control endpoint. Human
        renderings of a claim-bound connection's status and receipts show it (ADR-051).
        """

        return self._transport

    @property
    def consent_level(self) -> ConnectionLevel | None:
        """The level this connection's server target was consented at (``L1`` or ``L2``,
        ADR-054), read from the target record the connection was admitted under; None for a
        local connection or a target that records no consent. Human renderings of a claim-bound
        connection say, for ``L2``, that the server reads from its copy where it has one
        (``finishup.client.attribution``)."""

        return self._consent_level

    @property
    def last_project_request(self) -> PreparedProjectRequest | None:
        """Return the most recently prepared project request for retry/recovery.

        The value is retained even when the transport raises a retryable error or the caller's
        task is cancelled.  A caller that did not prepare the request explicitly can therefore
        recover the generated ID and exact normalized body before reconnecting.  A later project
        call replaces this snapshot, so long-lived callers should retain the returned wrapper.
        """

        return self._last_project_request

    async def _send(self, request: ControlCallRequest | ControlCancelRequest) -> None:
        validate_request(request)
        async with self._write_lock:
            self._ensure_live()
            # Nothing more is sent once the authorization a connection to a server elsewhere was
            # admitted under lapsed: it is checked before every frame (ADR-052).
            if self._authorization is not None:
                await self._end_if_lapsed()
            try:
                await write_control_frame(self._stream, request)
            except LocalControlTransportError as exc:
                await self._fail_connection(_transport_error(exc))
                raise _transport_error(exc) from exc
            except ControlProtocolError as exc:
                error = _protocol_error(exc)
                await self._fail_connection(error)
                raise error from exc

    async def _receive_results(self) -> None:
        failure = ControlError("service_unavailable", retryable=True)
        try:
            while not self._closed:
                frame = await read_control_frame(self._stream)
                if self._agent is not None and is_workspace_call_frame(frame):
                    # Only a connection that declared an agent answers the server's calls; on
                    # any other this frame fails as ``frame_invalid`` below, exactly as before.
                    self._accept_workspace_call(parse_workspace_call(frame))
                    continue
                result = parse_control_result(frame)
                validate_result(result)
                if (
                    result.service_instance_id != self._session.service_instance_id
                    or result.service_generation != self._session.service_generation
                ):
                    raise ControlError("service_unavailable", retryable=True)
                pending = self._pending.get(result.rpc_id)
                if result.rpc_id in self._retired_rpc_ids:
                    try:
                        self._session.correlate(result)
                    except ControlProtocolError as exc:
                        raise ControlError("frame_invalid") from exc
                    self._retired_rpc_ids.remove(result.rpc_id)
                    continue
                if pending is None or pending.done():
                    raise ControlError("frame_invalid")
                try:
                    self._session.correlate(result)
                except ControlProtocolError as exc:
                    raise ControlError("frame_invalid") from exc
                pending.set_result(result)
        except asyncio.CancelledError:
            return
        except ControlError as exc:
            failure = exc
        except ControlProtocolError as exc:
            failure = _protocol_error(exc)
        except Exception:
            failure = ControlError("service_unavailable", retryable=True)
        await self._fail_connection(failure, from_receiver=True)

    def _accept_workspace_call(self, call: WorkspaceCall) -> None:
        """Start answering one workspace call; the receive loop never waits for the answer."""

        if (
            call.service_instance_id != self._session.service_instance_id
            or call.service_generation != self._session.service_generation
        ):
            raise ControlError("service_unavailable", retryable=True)
        if call.call_id in self._agent_calls:
            raise ControlError("frame_invalid")
        task = asyncio.create_task(self._answer_workspace_call(call))
        self._agent_calls[call.call_id] = task
        task.add_done_callback(partial(self._forget_workspace_call, call.call_id))

    def _forget_workspace_call(self, call_id: str, task: asyncio.Task[None]) -> None:
        if self._agent_calls.get(call_id) is task:
            del self._agent_calls[call_id]
        _consume_background_task(task)

    async def _answer_workspace_call(self, call: WorkspaceCall) -> None:
        agent = self._agent
        if agent is None or self._closed:
            # A closed connection's pool is gone; never start a new one for it.
            return
        if self._agent_busy >= _MAX_WORKSPACE_CALLS:
            encoded = _encoded_workspace_reply(call.call_id, "agent_busy")
        else:
            encoded = await self._run_workspace_call(agent, call)
        async with self._write_lock:
            if self._closed:
                return
            if self._authorization is not None:
                # A reply computed while the authorization lapsed is never sent (ADR-052).
                try:
                    await self._end_if_lapsed()
                except ControlError:
                    return
            try:
                await self._stream.send_all(encoded)
            except LocalControlTransportError as exc:
                await self._fail_connection(_transport_error(exc))
            except Exception:
                await self._fail_connection(ControlError("service_unavailable", retryable=True))

    async def _run_workspace_call(self, agent: WorkspaceCallHandler, call: WorkspaceCall) -> bytes:
        """The encoded reply: the agent's, or ``deadline_exceeded`` once the call's deadline passes.

        The agent runs in a daemon worker thread of its own, at most ``_MAX_WORKSPACE_CALLS`` at a
        time per connection. A call past its deadline is answered without waiting; its worker
        keeps its slot until the adapter's own bound ends it. Being daemon threads, workers never
        hold a finished process open (a short-lived CLI exits after its command, not after a
        background check its connection happened to be serving); work still running at exit
        ends with the process, and an approved check it started stays in its own process group.
        """

        loop = asyncio.get_running_loop()
        work: asyncio.Future[bytes] = loop.create_future()
        answer = partial(
            _answer_in_worker,
            agent,
            call,
            self._session.workspace_handle,
            agent.declaration.max_reply_bytes,
        )

        def deliver(encoded: bytes) -> None:
            if not work.done():
                work.set_result(encoded)

        def run() -> None:
            # ``_answer_in_worker`` answers every exception itself; anything that escapes it still
            # frees the slot with a closed failure.
            encoded = _encoded_workspace_reply(call.call_id, "internal_error")
            try:
                encoded = answer()
            finally:
                try:
                    loop.call_soon_threadsafe(deliver, encoded)
                except RuntimeError:
                    # The loop already closed: the connection, and its answer, are gone.
                    pass

        self._agent_busy += 1
        work.add_done_callback(self._release_workspace_slot)
        try:
            # The answer runs in this connection's context, as ``asyncio.to_thread`` would: a
            # ``selection_override`` of the root that opened it holds there too.
            threading.Thread(
                target=contextvars.copy_context().run,
                args=(run,),
                name="finishup-workspace-agent",
                daemon=True,
            ).start()
        except RuntimeError:
            # No thread could be started (a process thread limit): nothing runs, the slot frees.
            work.set_result(_encoded_workspace_reply(call.call_id, "agent_busy"))
        try:
            async with asyncio.timeout(call.deadline_ms / 1_000):
                return await asyncio.shield(work)
        except TimeoutError:
            return _encoded_workspace_reply(call.call_id, "deadline_exceeded")

    def _release_workspace_slot(self, work: asyncio.Future[bytes]) -> None:
        self._agent_busy -= 1
        if not work.cancelled():
            work.exception()

    async def _fail_connection(self, error: ControlError, *, from_receiver: bool = False) -> None:
        if not self._closed:
            self._closed = True
            self._session.close()
            self._retired_rpc_ids.clear()
            # A pending call's body may have crossed the connection: it never fails with words
            # that say nothing was sent (``_sent_outcome``). One still waiting to be written is
            # refused by ``_ensure_live`` instead, with ``_failure`` or a lost connection.
            sent_error = _sent_outcome(error)
            for pending in tuple(self._pending.values()):
                if not pending.done():
                    pending.set_exception(sent_error)
            current = asyncio.current_task()
            for task in tuple(self._agent_calls.values()):
                # Unanswered workspace calls are the server's to fail when the connection drops.
                # Their daemon workers finish (or end with the process) without being waited for.
                if task is not current:
                    task.cancel()
            watch = self._watch
            if watch is not None and watch is not current and not watch.done():
                watch.cancel()
                watch.add_done_callback(_consume_background_task)
            await _best_effort_close_stream(self._stream)
        if not from_receiver and self._receiver is not asyncio.current_task():
            self._receiver.cancel()
            await asyncio.gather(self._receiver, return_exceptions=True)

    async def _request_cancel(self, target_rpc_id: str) -> None:
        if self._closed:
            return
        request = ControlCancelRequest(
            kind="cancel",
            protocol_version=CONTROL_PROTOCOL_VERSION,
            rpc_id=new_id(IdKind.CONTROL_RPC),
            service_instance_id=self._session.service_instance_id,
            service_generation=self._session.service_generation,
            target_rpc_id=target_rpc_id,
        )
        task = asyncio.create_task(self._send(request))
        try:
            done, _pending = await asyncio.wait((task,), timeout=_CANCEL_SEND_TIMEOUT_SECONDS)
        except asyncio.CancelledError:
            task.cancel()
            task.add_done_callback(_consume_background_task)
            return
        if task in done:
            _consume_background_task(task)
            return
        task.cancel()
        task.add_done_callback(_consume_background_task)

    def _retire_call(self, rpc_id: str, future: asyncio.Future[ControlResult]) -> None:
        """Keep bounded correlation state for a terminal result that may still arrive."""

        if not future.done() or future.cancelled():
            self._retired_rpc_ids.add(rpc_id)
            if not future.done():
                future.cancel()
        else:
            # The response can win the deadline race after the caller stops awaiting it.
            future.exception()

    async def call(self, request: ControlCallRequest) -> ControlResult:
        self._ensure_live()
        self._admit(request.method)
        if (
            request.service_instance_id != self._session.service_instance_id
            or request.service_generation != self._session.service_generation
        ):
            raise ControlError("service_unavailable", retryable=True)
        if request.rpc_id in self._pending or request.rpc_id in self._retired_rpc_ids:
            raise ControlError("service_unavailable", retryable=True)
        if len(self._pending) + len(self._retired_rpc_ids) >= _MAX_IN_FLIGHT:
            await self._fail_connection(ControlError("service_unavailable", retryable=True))
            raise ControlError("service_unavailable", retryable=True)

        future = asyncio.get_running_loop().create_future()
        self._pending[request.rpc_id] = future
        sent = False
        try:
            try:
                self._session.admit(request)
            except ControlProtocolError as exc:
                raise ControlError("frame_invalid") from exc
            if request.deadline_ms is None:
                await self._send(request)
                sent = True
                result = await future
            else:
                try:
                    async with asyncio.timeout(request.deadline_ms / 1_000):
                        await self._send(request)
                        sent = True
                        result = await asyncio.shield(future)
                except TimeoutError as exc:
                    if sent:
                        self._retire_call(request.rpc_id, future)
                        if request.method is not ControlMethod.CHECK:
                            await self._request_cancel(request.rpc_id)
                    else:
                        future.cancel()
                        await self._fail_connection(
                            ControlError("service_unavailable", retryable=True)
                        )
                    raise ControlError("request_timeout", retryable=True) from exc
        except asyncio.CancelledError:
            if sent:
                self._retire_call(request.rpc_id, future)
                if request.method is not ControlMethod.CHECK:
                    await self._request_cancel(request.rpc_id)
            else:
                future.cancel()
                await self._fail_connection(ControlError("service_unavailable", retryable=True))
            raise
        finally:
            settled = self._pending.pop(request.rpc_id, None)
            if settled is not None and settled.done() and not settled.cancelled():
                # A failed send fails the connection, and `_fail_connection` completes every
                # pending future — including this call's own, whose caller is still inside
                # `_send` and never reaches `await future`. Retrieve the outcome here so the
                # dropped future cannot surface as `Future exception was never retrieved`
                # (issue #678). On the ordinary paths the caller already consumed it and this
                # retrieval is a no-op.
                settled.exception()

        if result.outcome == "error" and isinstance(result.body, ControlError):
            # Only generation skew and a changed server profile force connection teardown.
            # Projection errors (privacy_projection_unavailable / privacy_projection_blocked)
            # must propagate so the agent can switch format or widen policy on the same connection.
            if result.body.reason == "server_profile_changed":
                # The service refused this request before doing any work for it: the profile
                # revision this connection was admitted under is no longer the one it issues
                # (ADR-052). The connection ends. This request and every later one, never sent,
                # name the phase and its way back; any other call already sent over it may have
                # been recorded, so it ends as ``server_authorization_changed`` (``_sent_outcome``).
                refused = ControlError(
                    "service_unavailable", retryable=True, phase="server_profile_changed"
                )
                _ask_helper_to_refresh(self._authorization)
                self._failure = self._failure or refused
                await self._fail_connection(refused)
                return ControlResult(
                    protocol_version=result.protocol_version,
                    rpc_id=result.rpc_id,
                    service_instance_id=result.service_instance_id,
                    service_generation=result.service_generation,
                    method=result.method,
                    outcome="error",
                    body=refused,
                )
            if result.body.reason == "service_generation_changed":
                await self._fail_connection(ControlError("service_unavailable", retryable=True))
                return ControlResult(
                    protocol_version=result.protocol_version,
                    rpc_id=result.rpc_id,
                    service_instance_id=result.service_instance_id,
                    service_generation=result.service_generation,
                    method=result.method,
                    outcome="error",
                    body=ControlError("service_unavailable", retryable=True),
                )
        return result

    async def cancel(self, request: ControlCancelRequest) -> None:
        self._ensure_live()
        if (
            request.service_instance_id != self._session.service_instance_id
            or request.service_generation != self._session.service_generation
        ):
            raise ControlError("service_unavailable", retryable=True)
        try:
            self._session.admit(request)
        except ControlProtocolError as exc:
            raise ControlError("frame_invalid") from exc
        await self._send(request)

    async def _invoke(
        self,
        method: ControlMethod,
        body: ControlCallBody,
        *,
        deadline_ms: int | None = None,
        route_profile: McpRouteProfile | None = None,
        host_profile: McpHostProfile | None = None,
    ) -> object:
        request = ControlCallRequest(
            kind="call",
            protocol_version=CONTROL_PROTOCOL_VERSION,
            rpc_id=new_id(IdKind.CONTROL_RPC),
            service_instance_id=self._session.service_instance_id,
            service_generation=self._session.service_generation,
            method=method,
            body=body,
            deadline_ms=deadline_ms,
            route_profile=route_profile,
            host_profile=host_profile,
        )
        result = await self.call(request)
        if result.outcome == "error":
            error = result.body
            if not isinstance(error, ControlError):
                raise ControlError("frame_invalid")
            raise error
        return result.body

    async def start(self, request: StartRequest, *, deadline_ms: int | None = None) -> StartResult:
        return cast(
            StartResult, await self._invoke(ControlMethod.START, request, deadline_ms=deadline_ms)
        )

    async def publish_work(
        self, request: PublishWorkRequest, *, deadline_ms: int | None = None
    ) -> PublishWorkResult:
        return cast(
            PublishWorkResult,
            await self._invoke(ControlMethod.PUBLISH_WORK, request, deadline_ms=deadline_ms),
        )

    async def check(
        self,
        request: CheckRequest,
        *,
        deadline_ms: int | None = None,
        route_profile: McpRouteProfile | None = None,
        host_profile: McpHostProfile | None = None,
    ) -> CheckResult:
        return cast(
            CheckResult,
            await self._invoke(
                ControlMethod.CHECK,
                request,
                deadline_ms=deadline_ms,
                route_profile=route_profile,
                host_profile=host_profile,
            ),
        )

    async def respond(
        self, request: RespondRequest, *, deadline_ms: int | None = None
    ) -> RespondResult:
        return cast(
            RespondResult,
            await self._invoke(ControlMethod.RESPOND, request, deadline_ms=deadline_ms),
        )

    async def status(
        self,
        request: StatusRequest,
        *,
        deadline_ms: int | None = None,
        route_profile: McpRouteProfile | None = None,
    ) -> StatusResult:
        return cast(
            StatusResult,
            await self._invoke(
                ControlMethod.STATUS,
                request,
                deadline_ms=deadline_ms,
                route_profile=route_profile,
            ),
        )

    def owner_receipt_view_target(self, request: ReceiptRequest) -> OwnerReceiptViewTarget:
        """The human-control target that binds an owner view to this request on this connection.

        The connection nonce never leaves the client; the target carries only its digest.
        """

        from finishup.service.owner_view import owner_receipt_view_target

        self._ensure_live()
        return owner_receipt_view_target(request, self._session.connection_nonce)

    async def receipt(
        self, request: ReceiptRequest, *, deadline_ms: int | None = None
    ) -> ReceiptResult:
        return cast(
            ReceiptResult,
            await self._invoke(ControlMethod.RECEIPT, request, deadline_ms=deadline_ms),
        )

    async def _support(
        self,
        method: ControlMethod,
        body: JsonObject,
        *,
        deadline_ms: int | None = None,
    ) -> JsonObject:
        return cast(JsonObject, await self._invoke(method, body, deadline_ms=deadline_ms))

    async def import_codex_jsonl(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> JsonObject:
        return await self._support(
            ControlMethod.IMPORT_CODEX_JSONL, request, deadline_ms=deadline_ms
        )

    def prepare_project_request(
        self, request: JsonObject, *, request_id: str | None = None
    ) -> PreparedProjectRequest:
        """Prepare and expose one stable project request before sending it."""

        prepared = prepare_project_request(request, request_id=request_id)
        self._last_project_request = prepared
        return prepared

    async def project(
        self,
        request: JsonObject,
        *,
        deadline_ms: int | None = None,
        request_id: str | None = None,
    ) -> JsonObject:
        """Send one CLI-only project lifecycle request to the ready service.

        The active 2.7 project schema requires ``request_id``.  Existing direct callers may still
        pass a body without it: the client prepares one generated identity and exposes the exact
        resulting body through :attr:`last_project_request`.  Callers recovering an ambiguous
        write must reuse that prepared body (or pass its ID explicitly), never invoke this method
        again with a fresh body and silently mint a replacement identity.
        """

        prepared = self.prepare_project_request(request, request_id=request_id)
        return await self._support(ControlMethod.PROJECT, prepared.body, deadline_ms=deadline_ms)

    async def review(self, request: JsonObject, *, deadline_ms: int | None = None) -> JsonObject:
        return await self._support(ControlMethod.REVIEW, request, deadline_ms=deadline_ms)

    async def backup_preview(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> JsonObject:
        return await self._support(ControlMethod.BACKUP_PREVIEW, request, deadline_ms=deadline_ms)

    async def backup_execute(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> JsonObject:
        return await self._support(ControlMethod.BACKUP_EXECUTE, request, deadline_ms=deadline_ms)

    async def restore_preview(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> JsonObject:
        return await self._support(ControlMethod.RESTORE_PREVIEW, request, deadline_ms=deadline_ms)

    async def restore_execute(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> JsonObject:
        return await self._support(ControlMethod.RESTORE_EXECUTE, request, deadline_ms=deadline_ms)

    async def migrate_preview(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> JsonObject:
        return await self._support(ControlMethod.MIGRATE_PREVIEW, request, deadline_ms=deadline_ms)

    async def migrate_execute(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> JsonObject:
        return await self._support(ControlMethod.MIGRATE_EXECUTE, request, deadline_ms=deadline_ms)

    async def integration_preview(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> JsonObject:
        return await self._support(
            ControlMethod.INTEGRATION_PREVIEW, request, deadline_ms=deadline_ms
        )

    async def integration_execute(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> JsonObject:
        return await self._support(
            ControlMethod.INTEGRATION_EXECUTE, request, deadline_ms=deadline_ms
        )

    async def observation_ingest(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> JsonObject:
        return await self._support(
            ControlMethod.OBSERVATION_INGEST, request, deadline_ms=deadline_ms
        )

    async def observation_status(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> JsonObject:
        return await self._support(
            ControlMethod.OBSERVATION_STATUS, request, deadline_ms=deadline_ms
        )

    async def observation_pause(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> JsonObject:
        return await self._support(
            ControlMethod.OBSERVATION_PAUSE, request, deadline_ms=deadline_ms
        )

    async def observation_resume(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> JsonObject:
        return await self._support(
            ControlMethod.OBSERVATION_RESUME, request, deadline_ms=deadline_ms
        )

    async def observation_revoke(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> JsonObject:
        return await self._support(
            ControlMethod.OBSERVATION_REVOKE, request, deadline_ms=deadline_ms
        )

    async def privacy_get_setup(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> JsonObject:
        return await self._support(
            ControlMethod.PRIVACY_GET_SETUP, request, deadline_ms=deadline_ms
        )

    async def privacy_get_effective(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> JsonObject:
        return await self._support(
            ControlMethod.PRIVACY_GET_EFFECTIVE, request, deadline_ms=deadline_ms
        )

    async def privacy_propose_policy(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> JsonObject:
        return await self._support(
            ControlMethod.PRIVACY_PROPOSE_POLICY, request, deadline_ms=deadline_ms
        )

    async def privacy_tighten_policy(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> JsonObject:
        return await self._support(
            ControlMethod.PRIVACY_TIGHTEN_POLICY, request, deadline_ms=deadline_ms
        )

    async def privacy_pending_list(self, *, deadline_ms: int | None = None) -> JsonObject:
        """List disclosure proposals awaiting a local decision.

        Returns the wire object unchanged: it carries only ids, task, and expiry, so there is no
        richer local type for it to become and nothing here to hide.
        """

        return await self._support(
            ControlMethod.PRIVACY_PENDING_LIST, JsonObject({}), deadline_ms=deadline_ms
        )

    async def privacy_receipts_list(
        self,
        request: ListPrivacyReceiptsRequest,
        *,
        deadline_ms: int | None = None,
    ) -> PrivacyReceiptPage:
        raw = await self._support(
            ControlMethod.PRIVACY_RECEIPTS_LIST,
            request._wire(),  # pyright: ignore[reportPrivateUsage]
            deadline_ms=deadline_ms,
        )
        try:
            return _receipt_page_from_wire(raw)
        except (KeyError, TypeError, ValueError) as exc:
            raise await _unreadable_receipt_frame("privacy_receipts_list") from exc

    async def privacy_receipts_get(
        self,
        request: GetPrivacyReceiptRequest,
        *,
        deadline_ms: int | None = None,
    ) -> PrivacyReceiptGetResult:
        raw = await self._support(
            ControlMethod.PRIVACY_RECEIPTS_GET,
            request._wire(),  # pyright: ignore[reportPrivateUsage]
            deadline_ms=deadline_ms,
        )
        try:
            return _receipt_get_from_wire(raw)
        except (KeyError, TypeError, ValueError) as exc:
            raise await _unreadable_receipt_frame("privacy_receipts_get") from exc

    async def service_status(self) -> ServiceStatus:
        return cast(ServiceStatus, await self._invoke(ControlMethod.SERVICE_STATUS, JsonObject({})))

    async def server_profile(self) -> ServerProfile:
        """What the service offers a client elsewhere (ADR-052), parsed and verified: a document
        whose digest does not recompute is ``frame_invalid``."""

        body = await self._invoke(ControlMethod.SERVER_PROFILE, JsonObject({}))
        try:
            return profile_from_json(canonical_encode(cast(JsonValue, body)))
        except ProfileError:
            raise ControlError("frame_invalid") from None

    async def code_copy(self, action: Literal["status", "forget"]) -> dict[str, object]:
        """The server's copy of this connection's claimed repository (level L2, ADR-054):
        ``status`` (what it holds, or null) or ``forget`` (exactly what was deleted)."""

        if action not in {"status", "forget"}:
            raise ValueError("code_copy_action_invalid")
        body = await self._invoke(ControlMethod.CODE_COPY, JsonObject({"action": action}))
        plain = strict_json_parse(canonical_encode(cast(JsonValue, body)))
        if type(plain) is not dict:
            raise ControlError("frame_invalid")
        answer = cast(dict[str, object], plain)
        if answer.get("action") != action:
            raise ControlError("frame_invalid")
        return answer

    async def lock(self) -> ServiceStatus:
        return cast(ServiceStatus, await self._invoke(ControlMethod.SERVICE_LOCK, JsonObject({})))

    async def stop(self) -> ServiceStopResult:
        return cast(
            ServiceStopResult,
            await self._invoke(ControlMethod.SERVICE_STOP, JsonObject({})),
        )

    async def close(self) -> None:
        if os.getpid() != self._pid:
            self._closed = True
            return
        await self._fail_connection(ControlError("service_unavailable", retryable=True))


def _encoded_workspace_reply(call_id: str, reason: str) -> bytes:
    """One encoded non-``ok`` workspace reply carrying a closed reason and no result."""

    reply = WorkspaceReply(
        "workspace_reply", "1.0", call_id, outcome_for_reason(reason), None, reason
    )
    return encode_control_frame(workspace_reply_frame(reply))


def _answer_in_worker(
    agent: WorkspaceCallHandler,
    call: WorkspaceCall,
    workspace_handle: str | None,
    max_reply_bytes: int,
) -> bytes:
    """Answer one call off the event loop and encode its reply frame there too.

    A reply above the declared bound, or one no frame can carry, becomes ``result_too_large``;
    anything else that goes wrong is ``internal_error``. No exception text reaches the reply.
    """

    try:
        reply = agent.answer(call, workspace_handle=workspace_handle)
        if type(reply) is not WorkspaceReply or reply.call_id != call.call_id:
            raise TypeError("workspace_reply_invalid")
        encoded = encode_control_frame(workspace_reply_frame(reply))
    except ControlProtocolError as exc:
        if exc.reason != "frame_too_large":
            return _encoded_workspace_reply(call.call_id, "internal_error")
        return _encoded_workspace_reply(call.call_id, "result_too_large")
    except Exception as exc:
        from finishup.observability.logging import record_unexpected_exception_without_raising

        record_unexpected_exception_without_raising(
            exc, component="service.client", operation="workspace_call_failed"
        )
        return _encoded_workspace_reply(call.call_id, "internal_error")
    if len(encoded) - _FRAME_PREFIX_BYTES > max_reply_bytes:
        return _encoded_workspace_reply(call.call_id, "result_too_large")
    return encoded


async def _recheck_after_interval() -> None:
    await asyncio.sleep(GENERATION_RECHECK_SECONDS)


def _connected_client(
    stream: ControlStream,
    session: ControlSession,
    client_kind: ControlClientKind,
    workspace_agent: WorkspaceCallHandler | None = None,
    *,
    transport: ConnectionTransport = "unix",
    authorization: AuthorizationCheck | None = None,
    recheck: Callable[[], Awaitable[None]] | None = None,
    copy_only: bool = False,
) -> ServiceClient:
    return ServiceClient(
        stream,
        session,
        client_kind,
        _token=_PRIVATE_CONSTRUCTOR_TOKEN,
        workspace_agent=workspace_agent,
        transport=transport,
        authorization=authorization,
        recheck=recheck,
        copy_only=copy_only,
    )


class _HelloRefused(Exception):
    """The connection's authorization lapsed before its hello was written."""


class _CheckedHelloStream:
    """The dialled stream while its hello is written: each write is checked first (ADR-052).

    The hello carries the workspace claim and the agent declaration, so it is guarded by the same
    authorization check as every later frame: a selection, record, key or hold change made while
    the dial was under way refuses the connection before anything is written (``refused`` names
    the phase), never after.
    """

    __slots__ = ("_authorization", "_stream", "refused")

    def __init__(self, stream: ControlStream, authorization: AuthorizationCheck) -> None:
        self._stream = stream
        self._authorization = authorization
        self.refused: str | None = None

    @property
    def peer_identity(self) -> object:
        return self._stream.peer_identity

    async def receive(self, max_bytes: int) -> bytes:
        return await self._stream.receive(max_bytes)

    async def send_all(self, data: Buffer) -> None:
        try:
            phase = self._authorization.refusal()
        except Exception:  # noqa: BLE001 - a check that cannot be made refuses nothing new
            phase = None
        if phase is not None:
            self.refused = phase
            raise _HelloRefused
        await self._stream.send_all(data)

    async def aclose(self) -> None:
        await self._stream.aclose()


class _AcceptedServiceUnresponsive(ControlError):
    """A fixed endpoint accepted locally but did not complete its bounded handshake."""

    def __init__(self) -> None:
        super().__init__("service_unavailable", retryable=True)


class _EndpointRootRefused(ControlError):
    """FinishUP's local folders cannot be used safely, so no service is reachable or startable.

    Raised before any socket is touched: the isolation root is set but unusable, the ambient
    roots exist under both the FinishUP and the legacy Yoetz names (ADR-048), or a folder the
    successor would log under fails a path-safety check. The condition does not heal on retry
    and a spawned service would die on it, so the control reason is the non-retryable
    ``endpoint_unsafe`` and the closed path-safety token rides alongside.
    """

    __slots__ = ("path_reason",)

    path_reason: str

    def __init__(self, path_reason: str) -> None:
        super().__init__("endpoint_unsafe")
        self.path_reason = path_reason


def path_refusal_reason(error: BaseException) -> str | None:
    """The closed path-safety token that refused this connection before any endpoint, or None.

    ``installation_root_ambiguous``, ``isolation_root_env_conflict`` and the other
    ``PathSafetyError`` tokens arrive here as the wire-visible ``endpoint_unsafe``; a renderer
    that can name the exact condition and its remedy asks for it here, like
    ``accepted_but_unresponsive``. Only the client that observed the refusal can tell.
    """

    return error.path_reason if type(error) is _EndpointRootRefused else None


def accepted_but_unresponsive(error: BaseException) -> bool:
    """True when a fixed endpoint accepted this connection and never completed its handshake.

    "Nothing is listening" and "something is listening and silent" call for opposite next steps,
    and the wire reason is the same for both. The distinction is only ever available here, on the
    client that observed it (#237).
    """

    return type(error) is _AcceptedServiceUnresponsive


def _consume_background_task[ResultT](task: asyncio.Task[ResultT]) -> None:
    try:
        task.result()
    except BaseException:
        pass


async def _best_effort_close_stream(stream: ControlStream) -> None:
    """Bound cleanup even when a faulty peer stream never completes ``aclose``."""

    task = asyncio.create_task(stream.aclose())
    try:
        done, _pending = await asyncio.wait((task,), timeout=_STREAM_CLOSE_TIMEOUT_SECONDS)
    except BaseException:
        task.cancel()
        task.add_done_callback(_consume_background_task)
        raise
    if task in done:
        _consume_background_task(task)
        return
    task.cancel()
    task.add_done_callback(_consume_background_task)


async def _connect_service_attempt(
    client_kind: ControlClientKind,
    *,
    workspace_locator: WorkspaceLocator | None,
    projection_render_mode: ProjectionRenderMode,
    output_is_controlling_tty: bool,
    timeout_seconds: float,
    workspace_binding: ClientWorkspaceBinding | None = None,
    authorization: AuthorizationCheck | None = None,
    dial: Callable[[], Awaitable[ControlStream]] | None = None,
    transport: ConnectionTransport = "unix",
) -> ServiceClient:
    """Connect and handshake within one attempt budget, preserving accepted-socket identity.

    A ``workspace_binding`` sends its claim (and declares its agent) in place of a locator. An
    ``authorization`` (a connection to a server elsewhere, ADR-052) is checked once more right
    before the dial and again right before the hello is written, and the connection keeps it.
    ``dial`` replaces the fixed endpoint for a connection to a server elsewhere (an SSH target's
    helper or its direct ``ssh -W`` stream); a transport that names why it failed (a closed
    remote phase) is reported with that phase.
    """

    agent = None if workspace_binding is None else workspace_binding.agent
    if authorization is not None:
        phase = authorization.refusal()
        if phase is not None:
            raise ControlError("service_unavailable", retryable=True, phase=phase)
    stream: ControlStream | None = None
    guarded: _CheckedHelloStream | None = None
    deadline = time.monotonic() + timeout_seconds
    try:
        async with asyncio.timeout(timeout_seconds):
            stream = await (connect_control() if dial is None else _remote_dial(dial))
            if (
                transport == "connector"
                and workspace_binding is not None
                and workspace_binding.repository_key is not None
            ):
                # Through the target's helper: the repository this connection's own admission is
                # bound to, on this local connection only (the helper binds its relay to it and
                # never forwards it; ``client.helper_status``).
                from finishup.client.helper_status import relay_binding

                await stream.send_all(relay_binding(workspace_binding.repository_key))
        if authorization is not None:
            _bind_stream(stream, authorization)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        guarded = None if authorization is None else _CheckedHelloStream(stream, authorization)
        handshake = asyncio.create_task(
            client_handshake(
                stream if guarded is None else guarded,
                client_kind,
                __version__,
                workspace_locator=workspace_locator,
                workspace_claim=None if workspace_binding is None else workspace_binding.claim,
                workspace_agent=None if agent is None else agent.declaration,
                projection_render_mode=projection_render_mode,
                output_is_controlling_tty=output_is_controlling_tty,
                server_profile=_server_profile_of(authorization),
            )
        )
        try:
            done, _pending = await asyncio.wait((handshake,), timeout=remaining)
        except BaseException:
            handshake.cancel()
            handshake.add_done_callback(_consume_background_task)
            raise
        if handshake not in done:
            handshake.cancel()
            handshake.add_done_callback(_consume_background_task)
            raise TimeoutError
        session = handshake.result()
        client = _connected_client(
            stream,
            session,
            client_kind,
            agent,
            transport=transport,
            authorization=authorization,
            copy_only=workspace_binding is not None and workspace_binding.copy_control,
        )
        if workspace_binding is not None and workspace_binding.worktree is not None:
            client._remote_workspace = (  # pyright: ignore[reportPrivateUsage]
                workspace_binding.claim,
                workspace_binding.worktree,
            )
        return client
    except TimeoutError as exc:
        accepted = stream is not None
        if stream is not None:
            await _best_effort_close_stream(stream)
        error: ControlError
        if accepted:
            error = _AcceptedServiceUnresponsive()
        else:
            error = ControlError("service_unavailable", retryable=True)
        raise error from exc
    except LocalControlTransportError as exc:
        named = await _remote_end_phase(stream, deadline)
        if stream is not None:
            await _best_effort_close_stream(stream)
        if named is not None:
            raise ControlError("service_unavailable", retryable=True, phase=named) from exc
        raise _transport_error(exc) from exc
    except ControlProtocolError as exc:
        named = await _remote_end_phase(stream, deadline)
        if stream is not None:
            await _best_effort_close_stream(stream)
        if guarded is not None and guarded.refused is not None:
            # Nothing was written: the hello was refused before it left.
            raise ControlError(
                "service_unavailable", retryable=True, phase=guarded.refused
            ) from None
        if named is not None:
            # The transport itself ended the stream (OpenSSH named why): the server never read
            # the hello, so the remote phase is the answer, not a protocol fault.
            raise ControlError("service_unavailable", retryable=True, phase=named) from exc
        if exc.reason == "handshake_rejected" and transport != "unix":
            # A server elsewhere's helper (or transport) closed the hello unanswered: no service
            # of this computer is involved; the caller names the outage the helper recorded.
            raise ControlError("service_unavailable", retryable=True) from exc
        if exc.reason == "handshake_rejected":
            raise _unanswered_hello(workspace_locator) from exc
        if transport != "unix" and exc.reason in {"manifest_mismatch", "protocol_mismatch"}:
            raise _remote_release_mismatch() from exc
        raise _protocol_error(exc) from exc
    except BaseException:
        if stream is not None:
            await _best_effort_close_stream(stream)
        raise


def _bind_stream(stream: ControlStream, authorization: AuthorizationCheck) -> None:
    """Bind a stream that sends on its own (a REST stream's retries, polls and registration) to
    the connection's own authorization, its repository's hold included: once it refuses, the
    stream sends nothing more, not only when the client next writes a frame. An open connection
    ends ``server_authorization_changed`` whatever the refusal names."""

    bind = getattr(stream, "bind", None)
    if not callable(bind):
        return

    def refusal() -> str | None:
        return None if authorization.refusal() is None else "server_authorization_changed"

    bind(refusal)


async def _remote_dial(dial: Callable[[], Awaitable[ControlStream]]) -> ControlStream:
    """Run a remote transport's dial; a failure it names (a closed remote phase) keeps its name."""

    try:
        return await dial()
    except (LocalControlTransportError, ControlError):
        raise
    except Exception as exc:
        reason = getattr(exc, "reason", None)
        if type(reason) is str and reason in REMOTE_CONNECTION_PHASES:
            raise ControlError("service_unavailable", retryable=True, phase=reason) from None
        raise ControlError(
            "service_unavailable", retryable=True, phase="remote_unreachable"
        ) from None


async def _remote_end_phase(stream: ControlStream | None, deadline: float) -> str | None:
    """The closed remote phase a direct stream names for its own end, if it can name one.

    Asked only within the connection's own ``deadline`` (a monotonic time): a transport that
    takes longer to say why (``ssh`` still running, its diagnostics still open) names nothing,
    and nothing is waited for once the deadline passed (a hook's budget is never overspent).
    """

    failure_phase = cast(
        Callable[[], Awaitable[str | None]] | None, getattr(stream, "failure_phase", None)
    )
    if failure_phase is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    try:
        async with asyncio.timeout(remaining):
            phase = await failure_phase()
    except TimeoutError:
        return None
    except asyncio.CancelledError:
        # A cancellation the stream's own task raised (a close ended its reader) is not this
        # caller's: it names nothing, so the answer the connection already has (a refusal the
        # hello named) stays the answer. Only a cancellation of this task leaves as one.
        current = asyncio.current_task()
        if current is not None and current.cancelling():
            raise
        return None
    except Exception:  # noqa: BLE001 - a stream that cannot say why names nothing
        return None
    return phase if phase in REMOTE_CONNECTION_PHASES else None


async def connect_service_via(
    dial: Callable[[], Awaitable[ControlStream]],
    client_kind: ControlClientKind,
    *,
    workspace_binding: ClientWorkspaceBinding | None,
    authorization: AuthorizationCheck | None,
    transport: ConnectionTransport,
    timeout_seconds: float = _CONNECT_HANDSHAKE_TIMEOUT_SECONDS,
) -> ServiceClient:
    """Handshake over a stream ``dial`` opens, with no admission of the active root.

    For a client that admitted its connection itself: an SSH target's helper holds its
    background workspace agents this way (``client.helper``), over its own relay (never through
    its endpoint, so they never count as client activity) or a direct ``ssh -W`` stream. The
    ``authorization`` is checked before the dial, before the hello and before every frame, and
    watched, exactly as for ``connect_service``. Failures are ``service_unavailable`` with a
    closed phase where the transport names one, or the protocol's own closed reason; never a
    path.
    """

    if type(client_kind) is not ControlClientKind:
        raise TypeError("control_client_kind_invalid")
    if workspace_binding is not None and type(workspace_binding) is not ClientWorkspaceBinding:
        raise TypeError("workspace_binding_invalid")
    if transport not in CONNECTION_TRANSPORTS:
        raise ValueError("connection_transport_invalid")
    return await _connect_service_attempt(
        client_kind,
        workspace_locator=None,
        projection_render_mode=ProjectionRenderMode.MACHINE_READABLE,
        output_is_controlling_tty=False,
        timeout_seconds=timeout_seconds,
        workspace_binding=workspace_binding,
        authorization=authorization,
        dial=dial,
        transport=transport,
    )


def _check_workspace_binding(
    workspace_locator: WorkspaceLocator | None, workspace_binding: ClientWorkspaceBinding | None
) -> None:
    if workspace_binding is None:
        return
    if type(workspace_binding) is not ClientWorkspaceBinding:
        raise TypeError("workspace_binding_invalid")
    if workspace_locator is not None:
        # A hello names its workspace by a path or by a claim, never both (ADR-051).
        raise ValueError("workspace_binding_conflict")


@dataclass(frozen=True, slots=True)
class _RemoteAdmission:
    """What the shared gate admitted a connection to a server elsewhere under (ADR-052)."""

    authorization: AuthorizationCheck
    workspace_binding: ClientWorkspaceBinding | None
    target_id: str = ""
    kind: str = ""
    # The level the target record's consent names (ADR-054), or None when it records none.
    level: ConnectionLevel | None = None


async def _admit_remote(
    workspace_locator: WorkspaceLocator | None,
    workspace_binding: ClientWorkspaceBinding | None,
    *,
    serve_workspace: bool,
) -> _RemoteAdmission | None:
    """The shared authorization gate every connection from a remote root passes first (ADR-052).

    ``None`` for a local root (the everyday server, a named local server, an isolated root that is
    not a target, or one that cannot be resolved, whose own path reports it): the connection is
    made exactly as before, with no authorization and no watch (O2). For a remote root the gate
    runs before any claim, dial or spawn (``client.authorization.authorize_active_root``); a
    refusal is a retryable ``service_unavailable`` naming its closed phase, and in this release,
    where no remote kind is open, every remote root is refused as ``target_root_is_remote``.
    Once admitted, ``workspace_locator`` becomes the target's claim, normalized to its worktree's
    top level, with the agent when ``serve_workspace`` (``remote_binding.binding_for_active_root``,
    which decides the repository hold); the locator itself is never sent. A workspace the shared
    root rule cannot resolve is not claimed and the connection names no workspace. A prebuilt
    ``workspace_binding`` keeps its own check (its repository's hold) beside the admission
    (``client.authorization.bind_prebuilt_check``); one made for another target is refused
    ``server_authorization_changed``.
    """

    from finishup.client.targets import TargetError, TargetRecordUnreadable, active_target_record

    try:
        record = active_target_record()
    except TargetRecordUnreadable:
        raise ControlError(
            "service_unavailable", retryable=True, phase="target_root_is_remote"
        ) from None
    except TargetError:
        return None
    if record is None or not record.is_remote:
        return None
    consent = record.consent
    level: ConnectionLevel | None = (
        consent.level if consent is not None and consent.level in CONNECTION_LEVELS else None
    )
    from finishup.client.authorization import authorize_active_root

    try:
        authorization = authorize_active_root()
    except TargetError as error:
        raise _remote_target_refusal(error) from None
    if authorization is None:
        # The root stopped being remote while it was admitted: refuse rather than guess.
        raise ControlError("service_unavailable", retryable=True, phase="target_root_is_remote")
    if workspace_binding is not None:
        # A binding made earlier keeps its own repository check beside this admission.
        from finishup.client.authorization import bind_prebuilt_check

        try:
            check = bind_prebuilt_check(authorization, workspace_binding.authorization)
        except TargetError as error:
            raise _remote_target_refusal(error) from None
        return _RemoteAdmission(check, workspace_binding, record.target_id, record.kind, level)
    if workspace_locator is None:
        return _RemoteAdmission(authorization, None, record.target_id, record.kind, level)
    from finishup.adapters.workspace_binding import canonical_workspace_locator
    from finishup.adapters.workspace_root import RepositoryIdentityError
    from finishup.client.remote_binding import binding_for_active_root

    # One worktree, one claim: a connection made from a subfolder claims its worktree's top level,
    # as the hooks and the CLI already do, so every surface reaches the same handle.
    canonical = canonical_workspace_locator(workspace_locator.path)
    if canonical is not None and canonical != workspace_locator.path:
        workspace_locator = WorkspaceLocator(canonical)
    try:
        binding = await binding_for_active_root(
            workspace_locator, serve_workspace=serve_workspace, authorization=authorization
        )
    except RepositoryIdentityError:
        return _RemoteAdmission(authorization, None, record.target_id, record.kind, level)
    except TargetError as error:
        raise _remote_target_refusal(error) from None
    if binding is None or binding.authorization is None:
        return _RemoteAdmission(authorization, binding, record.target_id, record.kind, level)
    return _RemoteAdmission(binding.authorization, binding, record.target_id, record.kind, level)


async def _connect_remote(
    admission: _RemoteAdmission,
    client_kind: ControlClientKind,
    *,
    projection_render_mode: ProjectionRenderMode,
    output_is_controlling_tty: bool,
    deadline: float,
) -> ServiceClient:
    """Reach an admitted server elsewhere (``_reach_remote``), the connection carrying the level
    its target was consented at (``ServiceClient.consent_level``, ADR-054)."""

    client = await _reach_remote(
        admission,
        client_kind,
        projection_render_mode=projection_render_mode,
        output_is_controlling_tty=output_is_controlling_tty,
        deadline=deadline,
    )
    client._consent_level = admission.level  # pyright: ignore[reportPrivateUsage]
    return client


async def _reach_remote(
    admission: _RemoteAdmission,
    client_kind: ControlClientKind,
    *,
    projection_render_mode: ProjectionRenderMode,
    output_is_controlling_tty: bool,
    deadline: float,
) -> ServiceClient:
    """Reach an admitted server elsewhere through its transport, within ``deadline``.

    An SSH target is reached through its helper (the relay style, the default) or directly
    (``ssh -W``, the owner's advanced choice), as its connection style record says (ADR-052,
    design v2 section 1.2). Nothing local is ever spawned or superseded but the target's own
    helper. A server that refused the consented profile revision (``server_profile_changed``)
    leaves the marker that asks the helper to fetch the profile again; never a fetch here.
    """

    if admission.kind != "ssh" and admission.kind not in _REST_KINDS:
        # No transport exists for this kind (the gate refuses it first); a test that opens one in
        # process without a server dials the target root's own endpoint, as layer 3 did.
        return await _connect_service_attempt(
            client_kind,
            workspace_locator=None,
            projection_render_mode=projection_render_mode,
            output_is_controlling_tty=output_is_controlling_tty,
            timeout_seconds=min(_CONNECT_HANDSHAKE_TIMEOUT_SECONDS, _remaining(deadline)),
            workspace_binding=admission.workspace_binding,
            authorization=admission.authorization,
        )
    from finishup.client.helper_status import (
        read_connection_style,
        read_helper_epoch,
        request_profile_refresh,
    )
    from finishup.client.targets import target_root

    root = target_root(admission.target_id)
    style = read_connection_style(root)
    binding = admission.workspace_binding
    if binding is not None and binding.copy_control:
        # Copy control is made directly: the helper's relay binds a claim to the repository's
        # hold, and copy control is admitted by the shared gate alone (#1357).
        style = "direct"
    # The target's stop epoch before any dial: every helper this attempt starts carries it, so a
    # stop made meanwhile (``server use``, ``disconnect``, ``remove``, a zero-network policy)
    # fences it before it serves anything or reaches the server (``helper_status.start_fenced``).
    epoch = read_helper_epoch(root)
    try:
        if style == "direct" and admission.kind in _REST_KINDS:
            return await _connect_direct_rest(
                root,
                admission,
                client_kind,
                projection_render_mode=projection_render_mode,
                output_is_controlling_tty=output_is_controlling_tty,
                deadline=deadline,
            )
        if style == "direct":
            return await _connect_direct(
                root,
                admission,
                client_kind,
                projection_render_mode=projection_render_mode,
                output_is_controlling_tty=output_is_controlling_tty,
                deadline=deadline,
            )
        return await _connect_through_helper(
            root,
            admission,
            client_kind,
            projection_render_mode=projection_render_mode,
            output_is_controlling_tty=output_is_controlling_tty,
            deadline=deadline,
            epoch=epoch,
        )
    except ControlError as error:
        if error.phase == "server_profile_changed":
            request_profile_refresh(root, _server_profile_of(admission.authorization))
            if style == "direct":
                _start_helper_to_refresh(root, admission, epoch)
        if error.reason == "service_unavailable" and error.phase is None:
            # A server elsewhere's outage always names its phase (design v2 section 8.9: hooks
            # fail open with the reason): a direct stream that did not answer within the
            # deadline is ``remote_unreachable``, as through the helper, never the local
            # service's hint.
            raise ControlError(
                "service_unavailable",
                retryable=True,
                phase="remote_unreachable",
                correlation_id=error.correlation_id,
            ) from error
        raise


def _remote_release_mismatch() -> ControlError:
    """A server elsewhere answered with another schema manifest or protocol.

    Self-hosted servers keep release lockstep with their clients (U18): the server's owner
    upgrades it (``remote_incompatible``); no service of this computer is involved, so the
    local ``service restart`` remedy is never named. Unless this process is the stale one: a
    newer build of this release now runs the target's helper (this process predates an
    in-place upgrade), which ``service_incompatible`` names (the bridge asks to reopen).
    """

    if newer_helper_build_holds_selection():
        return ControlError("service_incompatible", retryable=True)
    return ControlError("service_unavailable", retryable=True, phase="remote_incompatible")


def _installed_manifest_digest() -> str | None:
    """The schema-manifest digest of the build installed now, read from the installation's files.

    Never this process's own (cached) digest: a process that runs a retained copy of its runtime
    (an MCP bridge or a hook after an in-place upgrade, ``adapters.release_runtime``) reads the
    installation it was copied from, and any other process reads its package's files again. The
    package manager's files are the durable order of two builds of one version: the one
    installed now is the newer, whatever process started when. ``None`` when it cannot be read.
    """

    import hashlib

    import finishup
    from finishup.adapters.release_runtime import installation_prefix

    try:
        manifest = Path(finishup.__file__).resolve().parent / "resources" / "schemas"
        manifest /= "manifest.json"
        here = Path(sys.prefix).resolve()
        origin = installation_prefix()
        if origin.resolve() != here:
            # A retained runtime: the same package path beneath the installation it copies.
            manifest = origin / manifest.relative_to(here)
        with manifest.open("rb") as handle:
            data = handle.read(_INSTALLED_MANIFEST_MAX_BYTES + 1)
    except (OSError, ValueError):  # a ``ReleaseRuntimeError`` too: no order can be read
        return None
    if len(data) > _INSTALLED_MANIFEST_MAX_BYTES:
        return None
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _stale_against_helper(holder: HelperStamp) -> bool:
    """Whether this process must never replace ``holder``, a live helper of this release but
    another build: this process is not the build installed now (it predates an in-place upgrade,
    a retained runtime), or which build is installed cannot be read. Reads only.

    The order is the installation's (``_installed_manifest_digest``), never a process start
    time: a retained older bridge that starts its own helper after a newer process started (at a
    helper's idle exit) is still the older build, and the newer one replaces that helper.
    """

    if holder.version != __version__:
        return False
    own = _manifest_digest_for_client()
    return holder.schema_manifest_digest != own and _installed_manifest_digest() != own


def newer_helper_build_holds_selection() -> bool:
    """Whether the selected server elsewhere's helper is of this release but another build, and
    this process is not the build installed now (``_stale_against_helper``): this process is the
    stale one (it predates an in-place upgrade). For the MCP bridge's remedy text."""

    from finishup.client.helper_status import helper_holder

    root = _remote_target_root()
    if root is None:
        return False
    try:
        holder = helper_holder(root)
        return holder is not None and _stale_against_helper(holder)
    except Exception:  # noqa: BLE001 - a helper that cannot be read is not newer
        return False


def _start_helper_to_refresh(root: Path, admission: _RemoteAdmission, epoch: str) -> None:
    """Start the target's helper so it fetches the server's profile again (never on this path).

    The relay style's refusal came through the running helper, which takes the marker. The
    direct style has no helper on its path, and none may run (no registration started one): the
    marker alone would wait, ``server status`` would go on calling the consent current, and a
    narrowed profile would never be adjusted. The helper is client-owned and vault-less and does
    the fetch itself, detached (design v2 section 8.9: no profile refresh on a hook's path).

    Only while the admission this request was made under still holds (a ``server use`` of
    another server, a ``logout`` or a ``remove`` meanwhile starts nothing), and with the stop
    epoch read before the dial (``epoch``): a stop since then fences the helper before it
    reaches the server. Never raises.
    """

    from finishup.client.helper_status import helper_holder, spawn_helper

    try:
        if admission.authorization.refusal() is not None:
            return
        if helper_holder(root) is None:
            spawn_helper(root, admission.target_id, epoch=epoch)
    except OSError:
        return


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ControlError("service_unavailable", retryable=True, phase="remote_unreachable")
    return remaining


async def _connect_direct(
    root: Path,
    admission: _RemoteAdmission,
    client_kind: ControlClientKind,
    *,
    projection_render_mode: ProjectionRenderMode,
    output_is_controlling_tty: bool,
    deadline: float,
) -> ServiceClient:
    """The direct style: this process's own ``ssh -W`` stream (approach B's seam).

    A remote service that is not running is started once through the server's own launcher (this
    client's demand), then dialled again inside the same deadline.
    """

    from finishup.client.server_profile import consented_host_key
    from finishup.client.ssh_transport import (
        UpstreamUnavailable,
        direct_remote_argv,
        ensure_direct_master,
        open_direct_stream,
        require_host_key,
        resolve_ssh,
        run_ssh,
    )
    from finishup.client.targets import TargetError, read_target

    try:
        record = read_target(root)
    except TargetError:
        record = None
    if record is None or record.target_id != admission.target_id:
        raise ControlError(
            "service_unavailable", retryable=True, phase="server_authorization_changed"
        )
    try:
        ssh = resolve_ssh()
    except UpstreamUnavailable as error:
        raise ControlError("service_unavailable", retryable=True, phase=error.reason) from None

    async def dial() -> ControlStream:
        # Verified before it is handed back: it rode the master that verified the consented
        # host key, or verified that key over a connection of its own (ADR-052).
        return await open_direct_stream(
            ssh, root, record, expected=consented_host_key(root), deadline=deadline
        )

    async def attempt() -> ServiceClient:
        return await _connect_service_attempt(
            client_kind,
            workspace_locator=None,
            projection_render_mode=projection_render_mode,
            output_is_controlling_tty=output_is_controlling_tty,
            timeout_seconds=_remaining(deadline),
            workspace_binding=admission.workspace_binding,
            authorization=admission.authorization,
            dial=dial,
            transport="ssh",
        )

    try:
        return await attempt()
    except ControlError as error:
        if error.phase != "remote_service_not_running":
            raise
    phase = admission.authorization.refusal()
    if phase is not None:
        raise ControlError("service_unavailable", retryable=True, phase=phase)
    expected = consented_host_key(root)
    try:
        await ensure_direct_master(ssh, root, record, expected=expected, deadline=deadline)
        code, _stdout, stderr = await run_ssh(
            direct_remote_argv(ssh, root, record, "service", "start", "--json"),
            seconds=_remaining(deadline),
        )
        require_host_key(stderr, expected)
    except UpstreamUnavailable as error:
        raise ControlError("service_unavailable", retryable=True, phase=error.reason) from None
    if code != 0:
        raise ControlError(
            "service_unavailable", retryable=True, phase="remote_service_not_running"
        )
    return await attempt()


# The kinds reached over REST v1 (ADR-053): through the target's helper (the relay style, the
# default) or this process's own REST stream (the direct style). A unit test that opens one of
# them in process without a server empties this (``builders.server_targets.open_remote_kinds``),
# so its connection dials the target root's own endpoint as before.
_REST_KINDS: frozenset[str] = frozenset({"https", "local_port"})


async def _connect_direct_rest(
    root: Path,
    admission: _RemoteAdmission,
    client_kind: ControlClientKind,
    *,
    projection_render_mode: ProjectionRenderMode,
    output_is_controlling_tty: bool,
    deadline: float,
) -> ServiceClient:
    """The direct style over HTTPS: this process's own REST stream (ADR-053).

    This process reads the target's API key itself (off its event loop, within the deadline;
    the disclosure says each dialing process does) and maps its control frames to REST v1
    (``client.rest_stream``). The admission was checked before this dial and is checked before
    every frame and on its watch, as for any connection; the stream sends nothing more once it
    refuses.
    """

    from finishup.client.rest_client import RestTransport, RestUnavailable, load_key
    from finishup.client.rest_stream import RestControlStream
    from finishup.client.targets import TargetError, read_target

    try:
        record = read_target(root)
    except TargetError:
        record = None
    if record is None or record.target_id != admission.target_id:
        raise ControlError(
            "service_unavailable", retryable=True, phase="server_authorization_changed"
        )
    try:
        key = await load_key(record.target_id, seconds=min(10.0, _remaining(deadline)))
    except RestUnavailable as error:
        raise ControlError("service_unavailable", retryable=True, phase=error.reason) from None
    authorization = admission.authorization

    def may_send() -> bool:
        return authorization.refusal() is None

    async def dial() -> ControlStream:
        try:
            # Bound to the consented identity: a CA file replaced since is refused before the
            # key is sent (``remote_identity_changed``).
            transport = RestTransport.for_target(record, key=key, consented=True)
        except RestUnavailable as error:
            raise ControlError("service_unavailable", retryable=True, phase=error.reason) from None
        return RestControlStream(transport, may_send=may_send, owns_transport=True)

    return await _connect_service_attempt(
        client_kind,
        workspace_locator=None,
        projection_render_mode=projection_render_mode,
        output_is_controlling_tty=output_is_controlling_tty,
        timeout_seconds=min(_CONNECT_HANDSHAKE_TIMEOUT_SECONDS, _remaining(deadline)),
        workspace_binding=admission.workspace_binding,
        authorization=authorization,
        dial=dial,
        transport="https",
    )


def _helper_failure(root: Path, before: object) -> ControlError | None:
    """The phase the helper recorded for this attempt's failure, if it recorded one meanwhile."""

    from finishup.client.helper_status import read_helper_status

    status = read_helper_status(root)
    if status is None or status == before or status.reason is None:
        return None
    if status.phase != "unavailable" and (status.phase, status.reason) != (
        "stopped",
        "zero_network_remote_selected",
    ):
        return None
    if status.reason not in REMOTE_CONNECTION_PHASES:
        return None
    return ControlError(
        "service_unavailable",
        retryable=True,
        phase=status.reason,
        correlation_id=status.correlation_id,
    )


async def _connect_through_helper(
    root: Path,
    admission: _RemoteAdmission,
    client_kind: ControlClientKind,
    *,
    projection_render_mode: ProjectionRenderMode,
    output_is_controlling_tty: bool,
    deadline: float,
    epoch: str | None = None,
) -> ServiceClient:
    """The relay style: the target's helper serves ``<root>/run/control.sock``.

    The helper is client-owned and vault-less, so starting one is always safe: when nothing
    answers, one is started (never a service), and a helper left by an older release or build of
    this client is replaced through the target's stop epoch (never a newer one, and only by the
    build installed now: ``_stale_against_helper``). The replacement is fenced to the helper it
    decided about (``helper_status.supersede_helper``): one that took the target meanwhile is
    decided about again, never stopped blind. A helper that holds the lock but has not stamped
    it yet is unknown: it is waited for within the deadline, never stopped and never doubled. A
    helper ending at its idle exit is followed by a successor; any other stop (a ``server use``,
    ``disconnect``, ``remove``, a zero-network policy) stays a stop (A-HANDOFF): every helper
    started here carries ``epoch`` (the stop epoch read before the first dial, or the one this
    client's own replacement wrote), and only while the admission still holds. A failure the
    helper names (a remote phase) ends the wait at once; every ``service_unavailable`` raised
    here names a remote phase.
    """

    from finishup.client.helper_status import (
        HelperHolderChanged,
        helper_holder,
        helper_lock_held,
        read_helper_epoch,
        read_helper_status,
        spawn_helper,
        supersede_helper,
    )

    if epoch is None:
        epoch = read_helper_epoch(root)
    before = read_helper_status(root)

    def idle_exit_finished() -> bool:
        if helper_holder(root) is not None:
            return False
        status = read_helper_status(root)
        return status is not None and (status.phase, status.reason) == ("stopped", "idle_timeout")

    async def attempt() -> ServiceClient:
        return await _connect_service_attempt(
            client_kind,
            workspace_locator=None,
            projection_render_mode=projection_render_mode,
            output_is_controlling_tty=output_is_controlling_tty,
            timeout_seconds=min(_CONNECT_HANDSHAKE_TIMEOUT_SECONDS, _remaining(deadline)),
            workspace_binding=admission.workspace_binding,
            authorization=admission.authorization,
            transport="connector",
        )

    def named(error: ControlError) -> ControlError:
        if error.reason != "service_unavailable" or error.phase is not None:
            return error
        recorded = _helper_failure(root, before)
        if recorded is not None:
            return recorded
        return ControlError(
            "service_unavailable",
            retryable=True,
            phase="remote_unreachable",
            correlation_id=error.correlation_id,
        )

    def spawn() -> None:
        # The admission this attempt was made under, again: a ``server use`` of another server,
        # a ``logout`` or a ``remove`` since starts nothing (the helper's own admission is not
        # bound to the selection).
        phase = admission.authorization.refusal()
        if phase is not None:
            raise ControlError("service_unavailable", retryable=True, phase=phase)
        try:
            spawn_helper(root, admission.target_id, epoch=epoch)
        except FileNotFoundError:
            # The target's folder is gone (``server remove``): nothing is made again.
            raise ControlError(
                "service_unavailable", retryable=True, phase="server_authorization_changed"
            ) from None
        except OSError:
            raise ControlError(
                "service_unavailable", retryable=True, phase="remote_unreachable"
            ) from None

    spawned = False
    awaiting_stamp = False

    async def settle() -> None:
        """Replace a helper of an older release or build, start one when none holds the target,
        or note that the holder has not stamped the lock yet (``awaiting_stamp``)."""

        nonlocal awaiting_stamp, epoch, spawned
        holder = helper_holder(root)
        while (
            holder is not None
            and (
                holder.version != __version__
                or holder.schema_manifest_digest != _manifest_digest_for_client()
            )
            and holder_version_order(holder.version) != "newer"
        ):
            if _stale_against_helper(holder):
                # Another build of this same release, and this process is not the build
                # installed now: it predates an in-place upgrade (a retained runtime). It never
                # replaces that helper; its owner reopens the session (the bridge names that).
                raise ControlError("service_incompatible", retryable=True)
            # A helper left by an older release or build of this client (an in-place upgrade)
            # is client-owned: stop exactly that one (its stop epoch moves; no pid is
            # signalled), then start this build's. One a newer release started is never
            # replaced from here.
            try:
                written = await asyncio.to_thread(
                    supersede_helper, root, holder, timeout_seconds=_remaining(deadline)
                )
            except HelperHolderChanged:
                holder = helper_holder(root)
                continue
            if written is None:
                raise named(ControlError("service_unavailable", retryable=True))
            epoch = written
            holder = helper_holder(root)
        awaiting_stamp = holder is None and helper_lock_held(root) is True
        if holder is None and not awaiting_stamp:
            spawn()
            spawned = True

    try:
        return await attempt()
    except _AcceptedServiceUnresponsive as error:
        raise named(error) from error
    except ControlError as error:
        if error.reason != "service_unavailable" or error.phase is not None:
            raise
        recorded = _helper_failure(root, before)
        if recorded is not None and recorded.phase != "remote_unreachable":
            # The running helper read this hello and named why it could not carry it.
            raise recorded from error
    await settle()
    last_error: ControlError | None = None
    while time.monotonic() < deadline:
        await asyncio.sleep(min(_SERVICE_START_POLL_SECONDS, max(0.0, deadline - time.monotonic())))
        if awaiting_stamp:
            # A helper took the lock without a stamp yet: decide once its identity is known.
            await settle()
        elif not spawned and idle_exit_finished():
            # The helper that held the target was ending at its idle exit: start its successor
            # now instead of waiting on an endpoint nothing will serve again.
            spawn()
            spawned = True
        recorded = _helper_failure(root, before)
        if recorded is not None and recorded.phase not in {None, "remote_unreachable"}:
            # The helper named this outage: waiting longer cannot repair it.
            raise recorded
        try:
            return await attempt()
        except _AcceptedServiceUnresponsive as error:
            last_error = error
        except ControlError as error:
            last_error = error
            if error.reason != "service_unavailable" or error.phase is not None:
                raise
    raise named(last_error or ControlError("service_unavailable", retryable=True))


async def connect_service(
    client_kind: ControlClientKind,
    *,
    workspace_locator: WorkspaceLocator | None = None,
    projection_render_mode: ProjectionRenderMode = ProjectionRenderMode.MACHINE_READABLE,
    output_is_controlling_tty: bool = False,
    workspace_binding: ClientWorkspaceBinding | None = None,
    serve_workspace: bool = False,
) -> ServiceClient:
    """Connect only to the verified fixed ordinary endpoint and perform the handshake.

    ``workspace_binding`` is for a FinishUP server on another machine: the hello carries its claim
    instead of a locator, and its agent, if any, answers the server's workspace calls.

    A remote server target's root passes the shared authorization gate first (``_admit_remote``,
    ADR-052): nothing is claimed, dialled or started before it, and in this release, where no
    remote kind is open, it refuses every remote root. Once admitted (in a later release), the
    connection checks its authorization before every frame and watches it; with
    ``serve_workspace`` it answers the server's workspace calls (set it in a process whose calls
    run workspace work while they are live, never in a short-lived hook). A local root ignores
    ``serve_workspace``.
    """

    if type(client_kind) is not ControlClientKind:
        raise TypeError("control_client_kind_invalid")
    if workspace_locator is not None and type(workspace_locator) is not WorkspaceLocator:
        raise TypeError("workspace_locator_invalid")
    _check_workspace_binding(workspace_locator, workspace_binding)
    if type(projection_render_mode) is not ProjectionRenderMode:
        raise TypeError("projection_render_mode_invalid")
    if type(output_is_controlling_tty) is not bool:
        raise TypeError("projection_tty_fact_invalid")
    if type(serve_workspace) is not bool:
        raise TypeError("serve_workspace_invalid")
    admission = await _admit_remote(
        workspace_locator, workspace_binding, serve_workspace=serve_workspace
    )
    if admission is not None:
        # A server elsewhere is reached through its transport, which may have to start (its
        # helper, an OpenSSH master, the server's own idle-stopped service): the start budget,
        # never a local service. A hook passes its own, shorter budget to the on-demand path.
        return await _connect_remote(
            admission,
            client_kind,
            projection_render_mode=projection_render_mode,
            output_is_controlling_tty=output_is_controlling_tty,
            deadline=time.monotonic() + _SERVICE_START_TIMEOUT_SECONDS,
        )
    return await _connect_service_attempt(
        client_kind,
        workspace_locator=workspace_locator,
        projection_render_mode=projection_render_mode,
        output_is_controlling_tty=output_is_controlling_tty,
        timeout_seconds=_CONNECT_HANDSHAKE_TIMEOUT_SECONDS,
        workspace_binding=workspace_binding,
    )


def _singleton_lock_path() -> Path:
    from finishup.config.paths import state_dir
    from finishup.service.lifecycle import SINGLETON_LOCK_NAME

    return state_dir() / SINGLETON_LOCK_NAME


def service_holder_identity() -> SingletonHolder | None:
    """Read the advisory stamped holder of the fixed service without touching lock or endpoint.

    ``None`` means no live stamped holder could be read. The stamp is advisory identity only
    (never a fence); callers compare successive snapshots to learn that the service was started,
    stopped, or replaced, and must not infer health from it.
    """

    from finishup.service.lifecycle import SingletonHolder, probe_singleton_holder_identity

    remote_root = _remote_target_root()
    if remote_root is not None:
        # A remote target's endpoint belongs to its helper (ADR-052): the holder is the live
        # stamped helper, and its status generation moves when a repair changes the connection,
        # so a latched outage clears (the availability latch). It is never superseded from here.
        from finishup.client.helper_status import helper_holder, read_helper_status

        holder = helper_holder(remote_root)
        status = read_helper_status(remote_root)
        if holder is None or status is None or status.pid != holder.pid:
            return None
        return SingletonHolder(
            holder.pid, f"helper-{status.generation}", _manifest_digest_for_client(), __version__
        )
    try:
        return probe_singleton_holder_identity(_singleton_lock_path())
    except Exception:
        return None


def _remote_target_root() -> Path | None:
    """The active root when it is a server elsewhere's (its helper holds it), else ``None``."""

    try:
        root = active_root()
    except PathSafetyError:
        return None
    if root is None:
        return None
    from finishup.client.targets import TargetError, read_target

    try:
        record = read_target(root)
    except TargetError:
        return None
    return root if record is not None and record.is_remote else None


def _singleton_holder_lock_is_held() -> bool | None:
    """Corroborate an advisory holder stamp with the owner-only singleton flock."""

    from finishup.service.lifecycle import probe_singleton_holder_lock

    try:
        return probe_singleton_holder_lock(_singleton_lock_path())
    except Exception:
        return None


async def wait_for_singleton_release(pid: int, *, deadline: float) -> bool:
    """Poll until the stamped holder ``pid`` no longer owns the singleton, or the deadline passes."""

    from finishup.service.lifecycle import probe_singleton_holder_identity

    path = _singleton_lock_path()
    while True:
        current = probe_singleton_holder_identity(path)
        if current is None or current.pid != pid:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        await asyncio.sleep(min(_SERVICE_START_POLL_SECONDS, remaining))


def holder_version_order(holder_version: str | None) -> Literal["older", "same", "newer"] | None:
    """Order a running service's stamped package version against this installation's.

    ``None`` means the holder predates the stamp or either version does not parse; callers then
    keep their version-agnostic behavior instead of guessing an upgrade direction.
    """

    if holder_version is None:
        return None
    from packaging.version import InvalidVersion, Version

    try:
        holder = Version(holder_version)
        own = Version(__version__)
    except InvalidVersion:
        return None
    if holder < own:
        return "older"
    return "newer" if holder > own else "same"


async def supersede_incompatible_service(
    *, deadline: float, replace_newer: bool = False, replace_legacy: bool = False
) -> bool:
    """Ask the live same-user singleton holder to stop and wait for it to release the endpoint.

    Called after a listening service rejected this client's hello, or when a new host session
    retires an older installation's service. The holder is identified through the owner-only
    singleton stamp (never guessed from process listings), receives the daemon's ordinary
    bounded-shutdown signal, and is polled until it releases the lock. Returns ``True`` once the
    endpoint is free, ``False`` when no supersede candidate can be identified (no live stamped
    holder, an identical-identity holder that rejected us anyway, a holder whose identity fields
    are only partly readable, a holder stamped without any identity field unless
    ``replace_legacy``, a holder stamped by a newer package than this one, or a platform without
    POSIX signals), and raises ``service_incompatible`` when the holder outlives the deadline.
    Only an explicit human ``finishup service restart`` passes ``replace_newer`` and
    ``replace_legacy``: an upgrade moves forward, so a process left over from before an in-place
    package upgrade never replaces its successor, and a stamp without identity fields may be a
    compatible service (``_stamp_identity``), so only the owner's restart replaces it. A durable
    diagnostic names every attempt.
    """

    if os.name == "nt":
        return False
    from finishup.observability.logging import record_public_error_without_raising
    from finishup.service.lifecycle import probe_singleton_holder_identity

    holder = probe_singleton_holder_identity(_singleton_lock_path())
    if holder is None:
        return False
    identity = _stamp_identity(holder)
    if identity not in _REPLACEABLE_STAMPS and not (replace_legacy and identity == "legacy"):
        # Same installation identity yet it rejected the hello: this is not an upgrade, and
        # stopping it would not change the outcome. A stamp whose identity is only partly
        # readable, or absent, proves no other installation either, so it is never signalled
        # here; only the owner's explicit restart may replace an identity-less stamp. Report
        # instead of restarting.
        return False
    if not replace_newer and holder_version_order(holder.service_version) == "newer":
        # This process predates an in-place upgrade (an open session's bridge, typically). The
        # newer service is the one to keep; the session switches when its host reopens it.
        return False
    correlation_id = record_public_error_without_raising(
        component="service.client",
        operation="service_supersede",
        reason="service_incompatible",
    )
    try:
        os.kill(holder.pid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    except OSError as exc:
        raise ControlError(
            "service_incompatible", retryable=True, correlation_id=correlation_id
        ) from exc
    if await wait_for_singleton_release(holder.pid, deadline=deadline):
        return True
    raise ControlError("service_incompatible", retryable=True, correlation_id=correlation_id)


def _serves_older_package(client: ServiceClient) -> bool:
    status = client.hello_service_status
    return status is not None and holder_version_order(status.service_version) == "older"


def _manifest_digest_for_client() -> str:
    from finishup.protocol.schemas import schema_manifest_digest

    return schema_manifest_digest()


async def connect_service_on_demand(
    client_kind: ControlClientKind,
    *,
    workspace_locator: WorkspaceLocator | None = None,
    timeout_seconds: float = _SERVICE_START_TIMEOUT_SECONDS,
    supersede_incompatible: bool = True,
    workspace_binding: ClientWorkspaceBinding | None = None,
    serve_workspace: bool = False,
) -> ServiceClient:
    """Connect to the fixed service, starting one detached successor only when absent.

    Startup is deliberately narrower than workflow authority: it supplies no path, configuration,
    credential, vault input, or policy override.  Concurrent bridges may race to spawn; the
    service singleton admits exactly one winner and every caller reconnects to that winner.

    When ``supersede_incompatible`` is set and the running service rejects this client's hello
    (a stale process from another installation holding the one per-user endpoint after an
    upgrade), the holder is asked to stop through its ordinary bounded shutdown and a successor
    of this installation is spawned inside the same budget. The one endpoint then belongs to
    the installation that is actually being used. A holder stamped by a newer package is never
    replaced here: a process that predates an in-place upgrade reports ``service_incompatible``
    instead of undoing it.

    The MCP bridge a host starts for a session also retires a *compatible* service whose package
    is older than its own: sessions opened before an in-place upgrade keep that service, and the
    first session opened afterwards replaces it so the new package actually runs. When no holder
    can be identified the compatible service keeps serving.

    ``workspace_binding`` sends a claim (and declares an agent) in place of the locator, as for
    ``connect_service``; every connection this call opens carries it. A remote server target's
    root passes the shared authorization gate first (``_admit_remote``, ADR-052), which refuses
    it in this release; an admitted one is dialled once within the budget and never supersedes
    or starts a service of this computer.
    """

    if type(client_kind) is not ControlClientKind:
        raise TypeError("control_client_kind_invalid")
    if workspace_locator is not None and type(workspace_locator) is not WorkspaceLocator:
        raise TypeError("workspace_locator_invalid")
    _check_workspace_binding(workspace_locator, workspace_binding)
    if type(timeout_seconds) is not float or not 0.1 <= timeout_seconds <= 30.0:
        raise ValueError("service_start_timeout_invalid")
    if type(serve_workspace) is not bool:
        raise TypeError("serve_workspace_invalid")
    deadline = time.monotonic() + timeout_seconds
    admission = await _admit_remote(
        workspace_locator, workspace_binding, serve_workspace=serve_workspace
    )
    if admission is not None:
        # One deadline for the whole remote path (design v2 section 8.9): the gate above, the
        # helper's start, the transport, the handshake; the caller's call and cleanup follow.
        return await _connect_remote(
            admission,
            client_kind,
            projection_render_mode=ProjectionRenderMode.MACHINE_READABLE,
            output_is_controlling_tty=False,
            deadline=deadline,
        )

    async def connect_with_remaining_budget() -> ServiceClient:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ControlError("service_unavailable", retryable=True)
        return await _connect_service_attempt(
            client_kind,
            workspace_locator=workspace_locator,
            projection_render_mode=ProjectionRenderMode.MACHINE_READABLE,
            output_is_controlling_tty=False,
            timeout_seconds=min(_CONNECT_HANDSHAKE_TIMEOUT_SECONDS, remaining),
            workspace_binding=workspace_binding,
        )

    try:
        connected = await connect_with_remaining_budget()
    except _AcceptedServiceUnresponsive:
        # A process already owns and accepted the fixed endpoint. Starting a successor cannot
        # repair that process and only creates a singleton race, so fail this bounded attempt.
        raise
    except ControlError as exc:
        if exc.reason in _SUPERSEDE_REASONS and supersede_incompatible:
            if not await supersede_incompatible_service(deadline=deadline):
                raise
        elif exc.reason != "service_unavailable" or handshake_failure(exc) is not None:
            # A service of this installation that failed its own side of the handshake is
            # running: spawning a successor only races its singleton, so report it now.
            raise
    else:
        if not (
            client_kind is ControlClientKind.MCP_BRIDGE
            and supersede_incompatible
            and _serves_older_package(connected)
        ):
            return connected
        await connected.close()
        try:
            retired = await supersede_incompatible_service(deadline=deadline)
        except ControlError as exc:
            # The older service was asked to stop and is still draining calls of sessions opened
            # before the upgrade. A retry reaches whichever service holds the endpoint next.
            raise ControlError(
                "service_unavailable", retryable=True, correlation_id=exc.correlation_id
            ) from exc
        if not retired:
            # Nothing identifiable to retire (or a concurrent bridge already did): use whatever
            # holds the endpoint now, starting this installation's service only if none does.
            try:
                return await connect_with_remaining_budget()
            except _AcceptedServiceUnresponsive:
                raise
            except ControlError as exc:
                if exc.reason != "service_unavailable" or handshake_failure(exc) is not None:
                    raise
    if time.monotonic() >= deadline:
        raise ControlError("service_unavailable", retryable=True)
    # A consented hook may prime an absent service, but cannot replace a holder.
    # Before its endpoint appears, reuse a stamped starting holder only when the owner-only flock
    # is still held. A stale stamp is treated as absent regardless of its recorded version, so a
    # crashed or reused-pid service cannot suppress hook-driven startup forever. Identity remains
    # advisory; the subsequent authenticated handshake remains the authority.
    holder = service_holder_identity() if not supersede_incompatible else None
    lock_held = _singleton_holder_lock_is_held() if holder is not None else None
    if holder is not None and lock_held is not True:
        # The lock, rather than a stamped pid, is the authority. If it cannot be corroborated,
        # let the fixed launcher make a normal flock-protected attempt; it cannot supersede a live
        # holder and it gives a stale stamp a path back to startup.
        holder = None
    elif holder is not None and _stamp_identity(holder) in _REPLACEABLE_STAMPS:
        # Only a stamp that shows another installation is reported as one. A holder of this
        # installation, or one whose identity is only partly readable, holds the lock: it is
        # waited for below (never spawned beside), and its handshake has the last word.
        raise ControlError("service_incompatible", retryable=True)
    spawned: _SpawnedService | None = None
    if holder is None:
        try:
            spawned = _spawn_service_process()
        except PathSafetyError as exc:
            # The successor's log root failed a path-safety check (its root could not be
            # resolved, or a folder on the way is unsafe). A spawn cannot repair either, so name
            # the closed token instead of spending the start budget.
            raise _EndpointRootRefused(exc.reason_code) from exc
        except OSError as exc:
            raise ControlError("service_unavailable", retryable=True) from exc

    last_error: ControlError | None = None
    while time.monotonic() < deadline:
        await asyncio.sleep(min(_SERVICE_START_POLL_SECONDS, deadline - time.monotonic()))
        try:
            return await connect_with_remaining_budget()
        except _AcceptedServiceUnresponsive as exc:
            # This process spawned the owner milliseconds ago. Accepted-but-silent here means
            # "still starting", not "wedged": no successor is involved, so spending the remaining
            # budget is the remedy rather than an unbounded wait. The pre-spawn arm above is
            # unchanged and still fails fast for a pre-existing owner (#232/#233).
            last_error = exc
            continue
        except ControlError as exc:
            last_error = exc
            if exc.reason != "service_unavailable" or handshake_failure(exc) is not None:
                # The service answers connections but fails this one's handshake; waiting out
                # the budget would only bury that under a generic ``service_unavailable``.
                raise
        if spawned is not None and spawned.process.poll() is not None:
            startup_failure = _spawned_startup_failure(spawned)
            if startup_failure is not None:
                raise startup_failure from last_error
            spawned = None
    if (spawned is not None and spawned.process.poll() is None) or starting_service_pid():
        # A service is alive and holds the singleton but never completed a handshake within the
        # budget: still starting, not absent. A slow machine or the first start after an install
        # or update takes longer; naming that keeps callers from a supervisor or restart remedy.
        raise ControlError(
            "service_unavailable", retryable=True, phase=SERVICE_START_TIMEOUT_PHASE
        ) from last_error
    raise ControlError("service_unavailable", retryable=True) from last_error
