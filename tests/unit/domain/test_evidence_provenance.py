"""``domain.evidence_provenance``: one task's per-evidence provenance (ADR-054, design v2 §8.6)."""

from __future__ import annotations

from typing import cast

import pytest

from finishup.domain.evidence_provenance import (
    EVIDENCE_PROVENANCE_SCHEMA,
    EVIDENCE_PROVENANCE_TOKENS,
    ContentForgotten,
    CopySnapshotRef,
    EvidenceProvenance,
    evidence_provenance_from_json,
)
from finishup.protocol.server_copy import EVIDENCE_PROVENANCE

_AT = "2026-11-10T11:00:00.000Z"
_TREE = "a" * 40


def test_tokens_are_the_wire_tokens_of_the_server_copy() -> None:
    assert EVIDENCE_PROVENANCE_TOKENS == EVIDENCE_PROVENANCE


def test_round_trip_and_canonical_form() -> None:
    account = EvidenceProvenance(
        {"server_copy_read": 3, "client_check": 1},
        fenced_reads=2,
        snapshot=CopySnapshotRef(_AT, _TREE),
        content_forgotten=ContentForgotten(_AT, "expired"),
    )
    wire = account.to_json()
    assert wire["schema"] == EVIDENCE_PROVENANCE_SCHEMA
    assert list(wire["reads"]) == list(EVIDENCE_PROVENANCE_TOKENS)  # pyright: ignore[reportArgumentType]
    assert evidence_provenance_from_json(wire) == account
    assert account.read_from_copy and account.level_l2


def test_client_only_account_is_not_level_l2() -> None:
    account = EvidenceProvenance({"client_attested_read": 4})
    assert not account.read_from_copy
    assert not account.level_l2
    assert EvidenceProvenance({"stale_copy_read": 1}).read_from_copy


def test_plus_adds_counts_and_keeps_the_later_snapshot_and_marker() -> None:
    early = EvidenceProvenance(
        {"server_copy_read": 1}, 1, CopySnapshotRef("2026-11-10T10:00:00.000Z", _TREE)
    )
    late = EvidenceProvenance(
        {"server_copy_read": 2, "outside_read": 1},
        0,
        CopySnapshotRef(_AT, "b" * 40),
        ContentForgotten(_AT, "owner"),
    )
    both = early.plus(late)
    assert both.count("server_copy_read") == 3
    assert both.count("outside_read") == 1
    assert both.fenced_reads == 1
    assert both.snapshot == late.snapshot
    assert both.content_forgotten == late.content_forgotten
    assert late.plus(early).snapshot == late.snapshot


@pytest.mark.parametrize(
    "build",
    [
        lambda: EvidenceProvenance({"server_read": 1}),  # pyright: ignore[reportArgumentType]
        lambda: EvidenceProvenance({"server_copy_read": -1}),
        lambda: EvidenceProvenance({"server_copy_read": True}),
        lambda: EvidenceProvenance(fenced_reads=-1),
        lambda: CopySnapshotRef("2026-11-10T11:00:00Z", _TREE),
        lambda: CopySnapshotRef(_AT, "A" * 40),
        lambda: ContentForgotten(_AT, "later"),  # pyright: ignore[reportArgumentType]
    ],
)
def test_invalid_values_are_refused(build: object) -> None:
    with pytest.raises(ValueError, match="evidence_provenance_invalid"):
        build()  # pyright: ignore[reportCallIssue]


@pytest.mark.parametrize(
    "case",
    ["schema", "no_fenced", "extra", "token_missing", "snapshot_open", "marker_open"],
)
def test_decoder_refuses_anything_but_the_canonical_form(case: str) -> None:
    wire: dict[str, object] = dict(EvidenceProvenance({"server_copy_read": 1}).to_json())
    reads: dict[str, object] = dict(cast("dict[str, object]", wire["reads"]))
    wire["reads"] = reads
    if case == "schema":
        wire["schema"] = "yoetz.evidence-provenance/2"
    elif case == "no_fenced":
        del wire["fenced_reads"]
    elif case == "extra":
        wire["extra"] = 1
    elif case == "token_missing":
        del reads["client_check"]
    elif case == "snapshot_open":
        wire["snapshot"] = {"synced_at": _AT}
    else:
        wire["content_forgotten"] = {"at": _AT, "reason": "owner", "x": 1}
    with pytest.raises(ValueError, match="evidence_provenance_invalid"):
        evidence_provenance_from_json(wire)
