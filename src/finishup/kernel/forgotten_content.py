"""What a task still shows once the content it read from a server copy was forgotten (ADR-054).

Owner ruling U20: forgetting a server copy deletes the copy, its snapshots and the excerpts derived
from it. The ledger is hash-chained, so a recorded event and its payload object stay exactly as
written; instead the service records one ``content_forgotten`` event, and every projection built
after it reads the quoted excerpts of the task's repository as absent:

* a finding's ``challenge.snippet`` (the reviewer's verbatim support from the review packet);
* a check's ``review_summary`` and the ``snippet`` of each of its ``verified`` rows.

Only excerpts recorded for a check that tested a frontier before the event are masked, so a check
of later work keeps what it read then; findings and checks themselves stay, with their ids, kinds,
severities, verdicts, outcomes and counts. The projected marker (``ContentForgottenMarker``) says
when and why, and ``content_forgotten_provenance`` turns it into the receipt's evidence account.
Pure functions: no I/O, nothing user-controlled added.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import replace
from typing import Final, cast

from finishup.domain.events import (
    AcceptedEvent,
    CheckRecordedPayload,
    ContentForgottenPayload,
    LedgerRecord,
    encode_payload,
    is_content_forgotten_record,
)
from finishup.domain.evidence_provenance import ContentForgotten, EvidenceProvenance
from finishup.domain.findings import Finding
from finishup.domain.values import FindingId, JsonObject, freeze_json
from finishup.kernel.projections import (
    ContentForgottenMarker,
    FindingProjectionRecord,
    ProjectionState,
)
from finishup.protocol.canonical import canonical_digest

__all__ = [
    "content_forgotten_marker",
    "content_forgotten_provenance",
    "forgotten_check_payload",
    "forgotten_finding",
    "forgotten_verified_row",
    "latest_content_forgotten",
    "mask_check_payload",
    "mask_finding",
    "mask_finding_record",
    "mask_projection_findings",
    "with_forgotten_content",
]

_SNIPPET: Final = "snippet"


def forgotten_finding(finding: Finding) -> Finding:
    """``finding`` without its quoted excerpt (the challenge snippet); itself when it has none."""

    challenge = finding.challenge
    if challenge is None or challenge.snippet is None:
        return finding
    return replace(finding, challenge=replace(challenge, snippet=None))


def forgotten_verified_row(row: JsonObject) -> JsonObject:
    """One ``verified`` row without its quoted ``snippet``; the row itself when it has none."""

    if _SNIPPET not in row:
        return row
    return cast(JsonObject, freeze_json({key: row[key] for key in row if key != _SNIPPET}))


def forgotten_check_payload(payload: CheckRecordedPayload) -> CheckRecordedPayload:
    """``payload`` without its review summary and verified snippets; itself when it has neither."""

    if payload.review_summary is None and not any(_SNIPPET in row for row in payload.verified):
        return payload
    return replace(
        payload,
        review_summary=None,
        verified=tuple(forgotten_verified_row(row) for row in payload.verified),
    )


def mask_finding(
    marker: ContentForgottenMarker | None, finding: Finding, recorded_at: int
) -> Finding:
    """``finding`` (recorded at ingestion sequence ``recorded_at``) as a view after ``marker``.

    Masked when it was recorded before the forget or tested an earlier frontier (a check in
    flight when the content was forgotten, committed after it).
    """

    if marker is None or not marker.masks(finding.subject_frontier.sequence, recorded_at):
        return finding
    return forgotten_finding(finding)


def mask_check_payload(
    marker: ContentForgottenMarker | None, payload: CheckRecordedPayload, recorded_at: int
) -> CheckRecordedPayload:
    """A check payload recorded at ``recorded_at`` as a view after ``marker`` (``mask_finding``)."""

    if marker is None or not marker.masks(payload.subject_frontier.sequence, recorded_at):
        return payload
    return forgotten_check_payload(payload)


def content_forgotten_marker(record: LedgerRecord) -> ContentForgottenMarker | None:
    """The marker ``record`` sets when it is a service-written ``content_forgotten`` event."""

    if not is_content_forgotten_record(record):
        return None
    accepted = cast(AcceptedEvent, record)
    return ContentForgottenMarker(
        source_event_id=accepted.event_id,
        source_frontier=accepted.ledger.ingestion_sequence,
        at=accepted.occurred_at.wire,
        payload=cast(ContentForgottenPayload | None, accepted.payload),
    )


def latest_content_forgotten(records: Iterable[LedgerRecord]) -> ContentForgottenMarker | None:
    """The marker of the latest service-written ``content_forgotten`` event among ``records``."""

    latest: ContentForgottenMarker | None = None
    for record in records:
        marker = content_forgotten_marker(record)
        if marker is not None and (
            latest is None or marker.source_frontier > latest.source_frontier
        ):
            latest = marker
    return latest


def mask_finding_record(
    marker: ContentForgottenMarker | None, record: FindingProjectionRecord
) -> FindingProjectionRecord:
    """One finding record as a view after ``marker`` shows it; the record itself when unchanged.

    A masked record's ``payload_digest`` is that of the payload it now holds, so the projection
    stays self-consistent; the event and its own payload digest are never changed.
    """

    payload = record.payload
    if payload is None:
        return record
    shown = mask_finding(marker, payload, record.source_frontier)
    if shown is payload:
        return record
    return replace(record, payload=shown, payload_digest=canonical_digest(encode_payload(shown)))


def mask_projection_findings(
    findings: Mapping[FindingId, FindingProjectionRecord], marker: ContentForgottenMarker | None
) -> dict[FindingId, FindingProjectionRecord]:
    """Every finding record as a view after ``marker`` shows it (records, ids and states kept)."""

    if marker is None:
        return dict(findings)
    return {key: mask_finding_record(marker, record) for key, record in findings.items()}


def with_forgotten_content(
    state: ProjectionState, marker: ContentForgottenMarker | None
) -> ProjectionState:
    """``state`` as any view built after ``marker`` shows it, also a view pinned before it.

    A projection replayed to an earlier frontier never saw the event; once the event exists, its
    excerpts are masked all the same and it carries the marker. ``state`` itself when nothing
    changes (no marker, or the marker it already carries).
    """

    if marker is None or state.content_forgotten == marker:
        return state
    return replace(
        state,
        findings=mask_projection_findings(state.findings, marker),
        content_forgotten=marker,
    )


def content_forgotten_provenance(state: ProjectionState) -> EvidenceProvenance | None:
    """The receipt's account of a task whose copy content was forgotten, or ``None``.

    The counts per evidence token and the fenced reads the latest ``content_forgotten`` event
    recorded, plus ``content_forgotten`` = when that event occurred and why. ``None`` when the task
    has no such event, or when its payload is unreadable (its reason is then unknown; the
    excerpts stay masked regardless).
    """

    marker = state.content_forgotten
    if marker is None or marker.payload is None:
        return None
    recorded = marker.payload.provenance
    return EvidenceProvenance(
        recorded.reads,
        recorded.fenced_reads,
        None,
        ContentForgotten(at=marker.at, reason=marker.payload.reason),
    )
