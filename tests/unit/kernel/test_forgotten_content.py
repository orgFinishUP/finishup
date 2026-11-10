"""ADR-054 (owner ruling U20): a forgotten copy's excerpts read as absent in every projection."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any, cast

import pytest

from builders.dialogue import reviewer_finding
from builders.observed_runs import ObservedLedger
from finishup.domain.events import (
    CONTENT_FORGOTTEN_EVENT_SCHEMA_VERSION,
    FINDING_SNIPPET_EVENT_SCHEMA_VERSION,
    ContentForgottenPayload,
    EventSchema,
    decode_payload,
    encode_payload,
)
from finishup.domain.evidence_provenance import (
    ContentForgotten,
    CopySnapshotRef,
    EvidenceProvenance,
)
from finishup.domain.findings import Finding
from finishup.domain.values import Frontier, freeze_json
from finishup.kernel.forgotten_content import (
    content_forgotten_provenance,
    forgotten_check_payload,
    latest_content_forgotten,
    mask_check_payload,
    with_forgotten_content,
)
from finishup.kernel.projections import projection_from_snapshot, projection_snapshot
from finishup.kernel.reducers import replay
from finishup.protocol.coverage import PublicationChannel
from finishup.protocol.errors import ProtocolValueError
from unit.kernel import test_finding_resolution as fr

_SCHEMA = EventSchema("content_forgotten", CONTENT_FORGOTTEN_EVENT_SCHEMA_VERSION)
_FINDING = EventSchema("finding_recorded", FINDING_SNIPPET_EVENT_SCHEMA_VERSION)
_SNIPPET = "def leaked_helper(): return 'excerpt of the repository'"
_DIGEST = "sha256:" + "5" * 64
_FORGET_ID = "0123456789abcdef0123456789abcdef"
_OBLIGATION = "obl_00000000-0000-4000-8000-000000000001"


def _payload(**changes: object) -> ContentForgottenPayload:
    fields: dict[str, object] = {
        "forget_id": _FORGET_ID,
        "reason": "owner",
        "source": "server_copy",
        "objects_erased": 3,
        "provenance": EvidenceProvenance({"server_copy_read": 4, "outside_read": 1}, 2),
    }
    fields.update(changes)
    return ContentForgottenPayload(**fields)  # type: ignore[arg-type]


def _finding(number: int, tested: int) -> Finding:
    finding = reviewer_finding(number, _OBLIGATION)
    assert finding.challenge is not None
    return replace(
        finding,
        subject_frontier=Frontier(tested, "genesis" if tested == 0 else _DIGEST),
        challenge=replace(finding.challenge, snippet=_SNIPPET),
    )


def _forget(ledger: ObservedLedger, **changes: object) -> None:
    ledger._append(  # pyright: ignore[reportPrivateUsage]
        _SCHEMA, _payload(**changes), observed=True, channel=PublicationChannel.ENGINE_DERIVED
    )


def _record_finding(ledger: ObservedLedger, number: int, tested: int) -> Finding:
    finding = _finding(number, tested)
    ledger._append(_FINDING, finding, observed=False)  # pyright: ignore[reportPrivateUsage]
    return finding


def test_payload_round_trips_exactly() -> None:
    payload = _payload()
    encoded = encode_payload(payload)
    assert decode_payload(_SCHEMA, encoded) == payload
    assert json.loads(json.dumps(encoded, default=dict))["provenance"]["reads"] == {
        "server_copy_read": 4,
        "client_attested_read": 0,
        "client_check": 0,
        "client_observation": 0,
        "outside_read": 1,
        "stale_copy_read": 0,
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"forget_id": "0123456789ABCDEF0123456789ABCDEF"},
        {"forget_id": "0123456789abcdef"},
        {"forget_id": 7},
        {"reason": "manual"},
        {"source": "client_copy"},
        {"objects_erased": -1},
        {"objects_erased": True},
        {
            "provenance": EvidenceProvenance(
                snapshot=CopySnapshotRef("2026-11-10T10:00:00.000Z", "a" * 40)
            )
        },
        {
            "provenance": EvidenceProvenance(
                content_forgotten=ContentForgotten("2026-11-10T10:00:00.000Z", "owner")
            )
        },
        {"provenance": {"reads": {}}},
    ],
)
def test_payload_refuses_anything_outside_its_closed_shape(changes: dict[str, object]) -> None:
    with pytest.raises(ProtocolValueError):
        _payload(**changes)


@pytest.mark.parametrize("mutation", ["extra_key", "missing_key", "foreign_provenance"])
def test_decode_refuses_an_open_or_foreign_payload(mutation: str) -> None:
    value = cast(dict[str, Any], json.loads(json.dumps(encode_payload(_payload()), default=dict)))
    if mutation == "extra_key":
        value["extra"] = 1
    elif mutation == "missing_key":
        del value["objects_erased"]
    else:
        value["provenance"]["schema"] = "other/1"
    with pytest.raises(ProtocolValueError):
        decode_payload(_SCHEMA, freeze_json(value))


def test_forget_masks_every_recorded_snippet_and_projects_the_marker() -> None:
    ledger = ObservedLedger()
    first = _record_finding(ledger, 1, 0)
    second = _record_finding(ledger, 2, 1)
    before = replay(ledger.records)
    assert all(
        record.payload is not None
        and record.payload.challenge is not None
        and record.payload.challenge.snippet == _SNIPPET
        for record in before.findings.values()
    )
    _forget(ledger)
    after = replay(ledger.records)

    # Findings stay, with every id, kind, priority and summary; only the excerpt is gone.
    assert after.findings.keys() == before.findings.keys() == {first.finding_id, second.finding_id}
    for key, record in after.findings.items():
        shown = record.payload
        original = before.findings[key].payload
        assert shown is not None and original is not None and shown.challenge is not None
        assert shown.challenge.snippet is None
        assert replace(shown, challenge=original.challenge) == original
        assert record.source_event_id == before.findings[key].source_event_id
    assert _SNIPPET not in json.dumps(projection_snapshot(after), default=str)
    marker = after.content_forgotten
    assert marker is not None and marker.source_frontier == 3
    assert marker.payload == _payload()
    assert projection_from_snapshot(projection_snapshot(after)) == after
    assert content_forgotten_provenance(after) == EvidenceProvenance(
        {"server_copy_read": 4, "outside_read": 1},
        2,
        None,
        ContentForgotten(marker.at, "owner"),
    )
    assert latest_content_forgotten(ledger.records) == marker


def test_an_in_flight_check_committed_after_the_forget_is_masked_and_later_work_is_not() -> None:
    ledger = ObservedLedger()
    _record_finding(ledger, 1, 0)
    _forget(ledger, reason="expired")
    in_flight = _record_finding(ledger, 2, 1)  # tested frontier 1, recorded after the forget
    later = _record_finding(ledger, 3, 3)  # a check of work after the forget
    state = replay(ledger.records)

    masked = state.findings[in_flight.finding_id].payload
    kept = state.findings[later.finding_id].payload
    assert masked is not None and masked.challenge is not None
    assert masked.challenge.snippet is None
    assert kept is not None and kept.challenge is not None
    assert kept.challenge.snippet == _SNIPPET
    provenance = content_forgotten_provenance(state)
    assert provenance is not None and provenance.content_forgotten is not None
    assert provenance.content_forgotten.reason == "expired"


def test_a_ledger_without_the_event_projects_exactly_as_before() -> None:
    ledger = ObservedLedger()
    _record_finding(ledger, 1, 0)
    state = replay(ledger.records)
    snapshot = projection_snapshot(state)
    assert "content_forgotten" not in snapshot
    assert state.content_forgotten is None
    assert content_forgotten_provenance(state) is None
    assert latest_content_forgotten(ledger.records) is None
    assert with_forgotten_content(state, None) is state
    assert _SNIPPET in json.dumps(snapshot, default=str)


def test_a_content_forgotten_event_an_agent_wrote_is_a_corrupt_ledger() -> None:
    ledger = ObservedLedger()
    _record_finding(ledger, 1, 0)
    ledger._append(_SCHEMA, _payload(), observed=False)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(ValueError, match="projection_corrupt"):
        replay(ledger.records)
    assert latest_content_forgotten(ledger.records) is None


def test_a_view_pinned_before_the_forget_is_masked_once_the_event_exists() -> None:
    ledger = ObservedLedger()
    _record_finding(ledger, 1, 0)
    pinned = replay(ledger.records)
    _forget(ledger)
    marker = replay(ledger.records).content_forgotten
    shown = with_forgotten_content(pinned, marker)
    assert shown.frontier == pinned.frontier
    assert shown.content_forgotten == marker
    assert _SNIPPET not in json.dumps(projection_snapshot(shown), default=str)
    assert shown.findings.keys() == pinned.findings.keys()


def test_check_payload_masking_drops_only_the_quoted_text() -> None:
    check = replace(
        fr._check(tested=1),  # pyright: ignore[reportPrivateUsage]
        review_summary="The reviewer quoted: " + _SNIPPET,
        verified=(
            freeze_json(
                {
                    "requirement_or_claim": "The helper exists",
                    "verdict": "supported",
                    "cited_refs": [_OBLIGATION],
                    "snippet": _SNIPPET,
                }
            ),
            freeze_json(
                {
                    "requirement_or_claim": "No quote here",
                    "verdict": "supported",
                    "cited_refs": [_OBLIGATION],
                }
            ),
        ),
    )
    masked = forgotten_check_payload(check)
    assert masked.review_summary is None
    assert [dict(row) for row in masked.verified] == [
        {
            "requirement_or_claim": "The helper exists",
            "verdict": "supported",
            "cited_refs": (_OBLIGATION,),
        },
        {
            "requirement_or_claim": "No quote here",
            "verdict": "supported",
            "cited_refs": (_OBLIGATION,),
        },
    ]
    assert replace(masked, review_summary=check.review_summary, verified=check.verified) == check
    assert forgotten_check_payload(masked) is masked

    ledger = ObservedLedger()
    _record_finding(ledger, 1, 0)
    _forget(ledger)
    marker = replay(ledger.records).content_forgotten
    assert mask_check_payload(marker, check, 1) == masked  # tested and recorded before it
    later = replace(check, subject_frontier=Frontier(5, _DIGEST))
    assert mask_check_payload(marker, later, 6) is later  # a check of later work keeps its text
    assert mask_check_payload(None, check, 1) is check
