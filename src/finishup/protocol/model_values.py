"""Protocol bounds, wire enums, and AI-powered review outcome rules that need no pydantic.

The domain layer, the kernel, and the ports read these names, and so do the processes that never
build a protocol model: an observation hook refreshing its advice, or a codex hook draining its
outbox. Keeping them here lets those processes skip importing pydantic and the protocol model
graph. :mod:`finishup.protocol.models` re-exports every public name unchanged, so
``finishup.protocol.models.SemanticStatus is finishup.protocol.model_values.SemanticStatus``.

Each class and function keeps ``finishup.protocol.models`` as its ``__module__``: pickles, JSON
schema reference names, and anything else keyed on a definition's module stay exactly as they were
when these names were defined there.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
from types import MappingProxyType
from typing import Final

from finishup.protocol.errors import ProtocolValueError

PROTOCOL_VERSION: Final = "0.1"
MAX_EVENTS_PER_BATCH: Final = 100
MAX_CANONICAL_REQUEST_BYTES: Final = 1_048_576
MAX_FINDINGS_DEFAULT: Final = 3
MAX_FINDINGS_LIMIT: Final = 10
MAX_REASON_BYTES: Final = 4_096
MAX_OBJECT_PLAINTEXT_BYTES: Final = 4_194_304
MAX_SEMANTIC_ITEM_BYTES: Final = 16_384
MAX_SEMANTIC_CASE_BYTES: Final = 262_144
MAX_REVIEW_TEXT_BYTES: Final = 4_096
# The agent-transcribed task statement (issue #908), bounded by UTF-8 bytes. It is recorded whole
# far above what one review item carries (16 KiB): the packet keeps its head and tail and marks
# the elision, so the ledger never has to shorten the user's words to fit the reviewer.
MAX_TASK_STATEMENT_BYTES: Final = 65_536
MAX_REVIEW_TIMELINE_ITEMS: Final = 64
MAX_REVIEW_ASSESSMENTS: Final = 64
MAX_REVIEW_CHANGE_OBSERVATIONS: Final = 32
# The protocol maximum on targeted excerpts in one review packet. It exists only to bound work:
# the owner-approved byte budget (``max_total_excerpt_bytes``) is meant to bind first. Privacy
# policy 1.2.0 lets the Expanded preset use it; wire 1.0.0/1.1.0 still cap a policy at 16
# (issue #907 Phase 1b).
MAX_REVIEW_EXCERPTS: Final = 64
MAX_REVIEW_OMISSIONS: Final = 64
# The true count of distinct omissions behind a review input manifest's capped listed count
# (issue #976): far above anything a bounded ledger case produces, so it never saturates.
MAX_REVIEW_OMISSION_TOTAL: Final = 1_048_576
MAX_REVIEW_CHALLENGES: Final = 3
# JSON Schema ``maxLength`` counts Unicode code points, while the durable AI-powered review contract
# bounds review prose by UTF-8 bytes. Four bytes is the largest UTF-8 encoding of one valid
# Unicode scalar value, so this conservative provider-facing limit guarantees that every string
# admitted by the machine-enforced schema also fits the 4 KiB domain boundary.
MAX_PROVIDER_REVIEW_TEXT_CHARS: Final = MAX_REVIEW_TEXT_BYTES // 4
# ``insufficient_packet`` names what the reviewer needed (issue #907). Targets are refs already in
# the packet; the short reason stays in the durable semantic response, never in structural records.
MAX_MISSING_FOR_ASSESSMENT: Final = 8
MAX_MISSING_TARGET_REFS: Final = 4
# Issue #1047: inside one check FinishUP may answer the reviewer's own request from its records and
# ask again at most this many times (the review input manifest's ``follow_up_round``).
MAX_REVIEW_FOLLOW_UP_ROUNDS: Final = 3
MAX_MISSING_REASON_BYTES: Final = 1_024
MAX_PROVIDER_MISSING_REASON_CHARS: Final = MAX_MISSING_REASON_BYTES // 4
MISSING_FOR_ASSESSMENT_KINDS: Final = frozenset(
    {
        "command_identity",
        "current_diff_for_path",
        "other",
        "plan_or_claim_text",
        "prior_finding_context",
        "task_statement",
        "verification_output",
    }
)
# Frozen legacy identifier (ADR-048): the ``yoetz_limit_*`` availability values are released.
MISSING_ITEM_AVAILABILITIES: Final = frozenset(
    {
        "agent_suppliable",
        "structurally_unavailable_on_this_host",
        "yoetz_limit_packet_room",
        "yoetz_limit_unsupported_data_type",
    }
)
GENESIS_PREDECESSOR_DIGEST: Final = "genesis"
MAX_PROJECTION_CONTENT_LEAVES: Final = 512
MAX_PROJECTION_POINTER_BYTES: Final = 256
MAX_INTERNAL_PROJECTABLE_RESULT_BYTES: Final = 524_288
MAX_PROJECTED_RESULT_BYTES: Final = 1_048_576


class DataCategory(str, Enum):  # noqa: UP042 - exact public wire enum base
    BOUNDED_STRUCTURAL_METADATA = "bounded_structural_metadata"
    DECLARED_FILE_TYPE = "declared_file_type"
    TASK_DESCRIPTION = "task_description"
    CLAIM_TEXT = "claim_text"
    OBLIGATION_TEXT = "obligation_text"
    DECISION_EXCERPT = "decision_excerpt"
    EVIDENCE_EXCERPT = "evidence_excerpt"
    FINDING_SUMMARY = "finding_summary"
    COMMAND_METADATA = "command_metadata"
    DIFF_METADATA = "diff_metadata"
    REPOSITORY_EXCERPT = "repository_excerpt"
    TRANSCRIPT_EXCERPT = "transcript_excerpt"
    DIAGNOSTIC_METADATA = "diagnostic_metadata"
    # #1220: a receipt-only label for a reviewer read of an agent-declared test file. No policy
    # names it: the read is admitted under ``repository_excerpt`` and egress receipts show this.
    DECLARED_TEST_EXCERPT = "declared_test_excerpt"


class ClientKind(str, Enum):  # noqa: UP042 - exact public wire enum base
    CODEX_CLI = "codex_cli"
    COOPERATIVE_AGENT = "cooperative_agent"
    # Frozen legacy identifier (ADR-048): the released client-kind wire value.
    FINISHUP_CLI = "yoetz_cli"
    TEST_CLIENT = "test_client"
    IMPORTER = "importer"


class IntegrationKind(str, Enum):  # noqa: UP042 - exact public wire enum base
    COOPERATIVE_MCP = "cooperative_mcp"
    LOCAL_CLI = "local_cli"
    CODEX_JSONL_IMPORT = "codex_jsonl_import"


class LineageReadGapReason(str, Enum):  # noqa: UP042 - exact wire enum base
    MISSING = "missing"
    UNREADABLE = "unreadable"
    QUARANTINED = "quarantined"
    REVOKED = "revoked"
    NOT_AUTHORIZED = "not_authorized"
    UNKNOWN = "unknown"


class LineageProvenanceRestriction(str, Enum):  # noqa: UP042 - exact wire enum base
    CATEGORY_RESTRICTED = "category_restricted"
    NEVER_SEND = "never_send"
    TASK_SCOPE = "task_scope"
    MINIMIZATION = "minimization"
    AUTHORIZATION_MISSING = "authorization_missing"


class ReceiptRedactionProfile(str, Enum):  # noqa: UP042 - exact public wire enum base
    FULL_LOCAL = "full_local"
    DEFAULT_LOCAL_EXPORT = "default_local_export"
    REDACTED_SHARE = "redacted_share"


class SemanticStatus(str, Enum):  # noqa: UP042 - exact public wire enum base
    NOT_REQUESTED = "not_requested"
    NOT_CONFIGURED = "not_configured"
    BLOCKED_BY_POLICY = "blocked_by_policy"
    BLOCKED_FORBIDDEN_DATA = "blocked_forbidden_data"
    CLASSIFICATION_UNCERTAIN = "classification_uncertain"
    AWAITING_HUMAN = "awaiting_human"
    HUMAN_DENIED = "human_denied"
    APPROVAL_EXPIRED = "approval_expired"
    SUCCEEDED = "succeeded"
    REFUSED = "refused"
    TIMEOUT = "timeout"
    INVALID = "invalid"
    UNAVAILABLE = "unavailable"
    LATE = "late"
    STALE = "stale"
    FAILED = "failed"


class SemanticReason(str, Enum):  # noqa: UP042 - exact public wire enum base
    DETERMINISTIC_MODE = "deterministic_mode"
    # Pre-edit deferral (#1046). Distinct from DETERMINISTIC_MODE so a reader does not
    # treat an AI-powered setting as ignored. Admitted on check-result / check-recorded 1.5.0.
    DEFERRED_BEFORE_FIRST_EDIT = "deferred_before_first_edit"
    ROUND_LIMIT_UNASSESSABLE = "round_limit_unassessable"
    NO_MATERIAL_SEMANTIC_CASE = "no_material_semantic_case"
    PROVIDER_NOT_CONFIGURED = "provider_not_configured"
    LOCAL_MODEL_NOT_CONFIGURED = "local_model_not_configured"
    NETWORK_EGRESS_DENIED = "network_egress_denied"
    ROUTE_SEMANTIC_CEILING = "route_semantic_ceiling"
    CHANNEL_DISABLED = "channel_disabled"
    PROVIDER_BINDING_NOT_AUTHORIZED = "provider_binding_not_authorized"
    SCOPE_NOT_AUTHORIZED = "scope_not_authorized"
    CONTENT_CATEGORY_NOT_AUTHORIZED = "content_category_not_authorized"
    POLICY_GENERATION_REVOKED = "policy_generation_revoked"
    NEVER_SEND_DETECTED = "never_send_detected"
    SECRET_DETECTED = "secret_detected"
    CLASSIFICATION_UNCERTAIN = "classification_uncertain"
    HUMAN_APPROVAL_REQUIRED = "human_approval_required"
    HUMAN_DENIED = "human_denied"
    HUMAN_APPROVAL_EXPIRED = "human_approval_expired"
    SEMANTIC_COMPLETED = "semantic_completed"
    PROVIDER_REFUSED = "provider_refused"
    PROVIDER_TIMEOUT = "provider_timeout"
    RESPONSE_SCHEMA_INVALID = "response_schema_invalid"
    RESPONSE_CONTENT_INVALID = "response_content_invalid"
    SEMANTIC_JUDGMENT_REJECTED = "semantic_judgment_rejected"
    CREDENTIAL_UNAVAILABLE = "credential_unavailable"
    ENDPOINT_PROFILE_UNAVAILABLE = "endpoint_profile_unavailable"
    TRANSPORT_UNAVAILABLE = "transport_unavailable"
    PROVIDER_RATE_LIMITED = "provider_rate_limited"
    PROVIDER_QUOTA_EXHAUSTED = "provider_quota_exhausted"
    RETRY_BUDGET_EXHAUSTED = "retry_budget_exhausted"
    AUDIT_RESERVATION_UNAVAILABLE = "audit_reservation_unavailable"
    RECEIPT_PERSISTENCE_UNKNOWN = "receipt_persistence_unknown"
    OUTCOME_UNKNOWN = "outcome_unknown"
    DEADLINE_AUTHORITY_LOST = "deadline_authority_lost"
    LEASE_AUTHORITY_LOST = "lease_authority_lost"
    FRONTIER_CHANGED = "frontier_changed"
    DEPENDENCY_CHANGED = "dependency_changed"
    CASE_CAPACITY_EXCEEDED = "case_capacity_exceeded"
    COORDINATOR_FAILURE = "coordinator_failure"


class SemanticProgressPhase(str, Enum):  # noqa: UP042 - exact public wire enum base
    """Structural phase of one durable AI-powered review job (issue #571 item A2).

    Declaration order is execution order. A job's recorded phase only moves forward: within one
    physical attempt by this order, and across attempts by attempt ordinal. ``terminal`` is
    derived from the terminal job row, so there is exactly one terminal state per job.
    """

    QUEUED = "queued"
    CASE_ADMITTED = "case_admitted"
    RUNTIME_STARTING = "runtime_starting"
    ACCOUNT_MODEL_VALIDATION = "account_model_validation"
    PROVIDER_SAMPLING = "provider_sampling"
    RESPONSE_VALIDATION = "response_validation"
    CLEANUP = "cleanup"
    TERMINAL = "terminal"


SEMANTIC_PROGRESS_PHASE_RANK: Final[Mapping[SemanticProgressPhase, int]] = MappingProxyType(
    {phase: index for index, phase in enumerate(SemanticProgressPhase, start=1)}
)


VALID_SEMANTIC_REASONS: Final[Mapping[SemanticStatus, frozenset[SemanticReason]]] = (
    MappingProxyType(
        {
            SemanticStatus.NOT_REQUESTED: frozenset(
                {
                    SemanticReason.DETERMINISTIC_MODE,
                    SemanticReason.DEFERRED_BEFORE_FIRST_EDIT,
                    SemanticReason.NO_MATERIAL_SEMANTIC_CASE,
                }
            ),
            SemanticStatus.NOT_CONFIGURED: frozenset(
                {SemanticReason.PROVIDER_NOT_CONFIGURED, SemanticReason.LOCAL_MODEL_NOT_CONFIGURED}
            ),
            SemanticStatus.BLOCKED_BY_POLICY: frozenset(
                {
                    SemanticReason.NETWORK_EGRESS_DENIED,
                    SemanticReason.ROUTE_SEMANTIC_CEILING,
                    SemanticReason.CHANNEL_DISABLED,
                    SemanticReason.PROVIDER_BINDING_NOT_AUTHORIZED,
                    SemanticReason.SCOPE_NOT_AUTHORIZED,
                    SemanticReason.CONTENT_CATEGORY_NOT_AUTHORIZED,
                    SemanticReason.POLICY_GENERATION_REVOKED,
                }
            ),
            SemanticStatus.BLOCKED_FORBIDDEN_DATA: frozenset(
                {SemanticReason.NEVER_SEND_DETECTED, SemanticReason.SECRET_DETECTED}
            ),
            SemanticStatus.CLASSIFICATION_UNCERTAIN: frozenset(
                {SemanticReason.CLASSIFICATION_UNCERTAIN}
            ),
            SemanticStatus.AWAITING_HUMAN: frozenset({SemanticReason.HUMAN_APPROVAL_REQUIRED}),
            SemanticStatus.HUMAN_DENIED: frozenset({SemanticReason.HUMAN_DENIED}),
            SemanticStatus.APPROVAL_EXPIRED: frozenset({SemanticReason.HUMAN_APPROVAL_EXPIRED}),
            SemanticStatus.SUCCEEDED: frozenset({SemanticReason.SEMANTIC_COMPLETED}),
            SemanticStatus.REFUSED: frozenset({SemanticReason.PROVIDER_REFUSED}),
            SemanticStatus.TIMEOUT: frozenset({SemanticReason.PROVIDER_TIMEOUT}),
            SemanticStatus.INVALID: frozenset(
                {
                    SemanticReason.RESPONSE_SCHEMA_INVALID,
                    SemanticReason.RESPONSE_CONTENT_INVALID,
                    SemanticReason.SEMANTIC_JUDGMENT_REJECTED,
                }
            ),
            SemanticStatus.UNAVAILABLE: frozenset(
                {
                    SemanticReason.ROUND_LIMIT_UNASSESSABLE,
                    SemanticReason.CREDENTIAL_UNAVAILABLE,
                    SemanticReason.ENDPOINT_PROFILE_UNAVAILABLE,
                    SemanticReason.TRANSPORT_UNAVAILABLE,
                    SemanticReason.PROVIDER_RATE_LIMITED,
                    SemanticReason.PROVIDER_QUOTA_EXHAUSTED,
                    SemanticReason.RETRY_BUDGET_EXHAUSTED,
                    SemanticReason.AUDIT_RESERVATION_UNAVAILABLE,
                    SemanticReason.RECEIPT_PERSISTENCE_UNKNOWN,
                    SemanticReason.OUTCOME_UNKNOWN,
                }
            ),
            SemanticStatus.LATE: frozenset(
                {SemanticReason.DEADLINE_AUTHORITY_LOST, SemanticReason.LEASE_AUTHORITY_LOST}
            ),
            SemanticStatus.STALE: frozenset(
                {SemanticReason.FRONTIER_CHANGED, SemanticReason.DEPENDENCY_CHANGED}
            ),
            SemanticStatus.FAILED: frozenset(
                {SemanticReason.COORDINATOR_FAILURE, SemanticReason.CASE_CAPACITY_EXCEEDED}
            ),
        }
    )
)


_PREDISPATCH_SEMANTIC_STATUSES: Final[frozenset[SemanticStatus]] = frozenset(
    {
        SemanticStatus.NOT_REQUESTED,
        SemanticStatus.NOT_CONFIGURED,
        SemanticStatus.BLOCKED_BY_POLICY,
        SemanticStatus.BLOCKED_FORBIDDEN_DATA,
        SemanticStatus.CLASSIFICATION_UNCERTAIN,
        SemanticStatus.AWAITING_HUMAN,
        SemanticStatus.HUMAN_DENIED,
        SemanticStatus.APPROVAL_EXPIRED,
    }
)
_REQUIRED_SEMANTIC_PROVENANCE_STATUSES: Final[frozenset[SemanticStatus]] = frozenset(
    {
        SemanticStatus.SUCCEEDED,
        SemanticStatus.REFUSED,
        SemanticStatus.TIMEOUT,
        SemanticStatus.INVALID,
        SemanticStatus.LATE,
        SemanticStatus.STALE,
    }
)
_REQUIRED_UNAVAILABLE_PROVENANCE_REASONS: Final[frozenset[SemanticReason]] = frozenset(
    {
        SemanticReason.TRANSPORT_UNAVAILABLE,
        SemanticReason.PROVIDER_RATE_LIMITED,
        SemanticReason.PROVIDER_QUOTA_EXHAUSTED,
        SemanticReason.OUTCOME_UNKNOWN,
    }
)
_FORBIDDEN_UNAVAILABLE_PROVENANCE_REASONS: Final[frozenset[SemanticReason]] = frozenset(
    {
        SemanticReason.ROUND_LIMIT_UNASSESSABLE,
        SemanticReason.CREDENTIAL_UNAVAILABLE,
        SemanticReason.ENDPOINT_PROFILE_UNAVAILABLE,
        SemanticReason.RETRY_BUDGET_EXHAUSTED,
        SemanticReason.AUDIT_RESERVATION_UNAVAILABLE,
        SemanticReason.RECEIPT_PERSISTENCE_UNKNOWN,
    }
)


def validate_semantic_outcome(status: SemanticStatus, reason: SemanticReason) -> None:
    """Validate one exact AI-powered review status/reason pair without coercion."""

    if type(status) is not SemanticStatus or type(reason) is not SemanticReason:
        raise ProtocolValueError("invalid_semantic_outcome_type")
    if reason not in VALID_SEMANTIC_REASONS[status]:
        raise ProtocolValueError("invalid_semantic_status_reason_pair")


def validate_semantic_provenance_binding(
    status: SemanticStatus,
    reason: SemanticReason,
    provenance_status: SemanticStatus | None,
    provenance_reason: SemanticReason | None,
) -> None:
    """Validate the closed provenance-presence and final-attempt identity partition."""

    validate_semantic_outcome(status, reason)

    if provenance_status is None and provenance_reason is None:
        provenance_present = False
    elif type(provenance_status) is SemanticStatus and type(provenance_reason) is SemanticReason:
        provenance_present = True
    else:
        raise ProtocolValueError("invalid_semantic_provenance")

    if provenance_present and (provenance_status is not status or provenance_reason is not reason):
        raise ProtocolValueError("invalid_semantic_provenance")

    if status in _PREDISPATCH_SEMANTIC_STATUSES or reason is SemanticReason.CASE_CAPACITY_EXCEEDED:
        provenance_required = False
    elif status in _REQUIRED_SEMANTIC_PROVENANCE_STATUSES:
        provenance_required = True
    elif status is SemanticStatus.UNAVAILABLE:
        if reason in _REQUIRED_UNAVAILABLE_PROVENANCE_REASONS:
            provenance_required = True
        elif reason in _FORBIDDEN_UNAVAILABLE_PROVENANCE_REASONS:
            provenance_required = False
        else:  # pragma: no cover - guarded by validate_semantic_outcome
            raise ProtocolValueError("invalid_semantic_provenance")
    elif status is SemanticStatus.FAILED:
        return
    else:  # pragma: no cover - the enum and status/reason registry are closed
        raise ProtocolValueError("invalid_semantic_provenance")

    if provenance_present is not provenance_required:
        raise ProtocolValueError("invalid_semantic_provenance")


# The public module these names were defined in, and are still re-exported from.
_PUBLIC_MODULE: Final = "finishup.protocol.models"
for _definition in (
    DataCategory,
    ClientKind,
    IntegrationKind,
    LineageReadGapReason,
    LineageProvenanceRestriction,
    ReceiptRedactionProfile,
    SemanticStatus,
    SemanticReason,
    SemanticProgressPhase,
    validate_semantic_outcome,
    validate_semantic_provenance_binding,
):
    _definition.__module__ = _PUBLIC_MODULE
del _definition
