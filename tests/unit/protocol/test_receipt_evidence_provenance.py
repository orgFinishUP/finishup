"""The receipt result's ``evidence_provenance`` member (ADR-054, design v2 section 8.6).

receipt-result 1.5.0 (unreleased, amended in place) admits it on every format: exactly a
level-L2 account's ``EvidenceProvenance.to_json()``, closed tokens, bounded counts, synthetic ids
and service-stamped times only. An account that is not level L2's is refused, so an L1 receipt
never carries one and keeps its bytes; the released 1.4.0 never admits it. Its leaves are
structural, and a paged receipt delivers it first.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from typing import Any, cast

import pydantic
import pytest
from tests.unit.protocol.test_models_and_schemas import _receipt_result_wire

from finishup.application.result_delivery import page_result
from finishup.domain.evidence_provenance import (
    EVIDENCE_PROVENANCE_TOKENS,
    ContentForgotten,
    CopySnapshotRef,
    EvidenceProvenance,
)
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import (
    ReceiptEvidenceProvenanceModel,
    ReceiptResultModel,
    ReceiptSuccessModel,
    classify_result_leaf,
    public_model_to_wire,
)
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance

_AT = "2026-11-10T11:00:00.000Z"
_TREE = "0123456789abcdef0123456789abcdef01234567"
_COPY_READ = EvidenceProvenance(
    {"server_copy_read": 4, "client_attested_read": 2, "outside_read": 1},
    fenced_reads=3,
    snapshot=CopySnapshotRef(_AT, _TREE),
)
_STALE = EvidenceProvenance({"stale_copy_read": 2, "client_check": 1})
_FORGOTTEN = EvidenceProvenance(content_forgotten=ContentForgotten(_AT, "owner"))
_ACCOUNTS = {"copy_read": _COPY_READ, "stale": _STALE, "forgotten": _FORGOTTEN}


def _wire(receipt_format: str, account: EvidenceProvenance) -> dict[str, JsonValue]:
    wire = _receipt_result_wire()
    if receipt_format != "json":
        wire["format"] = receipt_format
        wire["document"] = None
        wire["human_text"] = "Receipt"
    wire["evidence_provenance"] = cast(JsonValue, account.to_json())
    return wire


@pytest.mark.parametrize("name", list(_ACCOUNTS))
@pytest.mark.parametrize("receipt_format", ["json", "text", "markdown"])
def test_every_receipt_format_admits_a_level_l2_account(receipt_format: str, name: str) -> None:
    account = _ACCOUNTS[name]
    receipt = ReceiptResultModel.model_validate(_wire(receipt_format, account))
    success = receipt.root
    assert type(success) is ReceiptSuccessModel
    assert success.evidence_provenance is not None
    wire = public_model_to_wire(receipt)
    # Exactly the account's canonical form, every token present, in token order.
    assert wire["evidence_provenance"] == account.to_json()
    member = cast(dict[str, Any], wire["evidence_provenance"])
    assert list(member["reads"]) == list(EVIDENCE_PROVENANCE_TOKENS)
    validate_schema_instance("receipt-result", "1.5.0", cast(JsonValue, wire))
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("receipt-result", "1.4.0", cast(JsonValue, wire))


def _client_only() -> dict[str, Any]:
    return EvidenceProvenance({"client_attested_read": 5}, fenced_reads=2).to_json()


def _mutated(change: str) -> object:
    member = cast(dict[str, Any], _COPY_READ.to_json())
    member["reads"] = dict(member["reads"])
    match change:
        case "not_level_l2":
            return _client_only()
        case "explicit_null":
            return None
        case "schema":
            member["schema"] = "yoetz.evidence-provenance/2"
        case "missing_token":
            del member["reads"]["client_check"]
        case "extra_token":
            member["reads"]["server_read"] = 1
        case "negative":
            member["reads"]["outside_read"] = -1
        case "oversized":
            member["fenced_reads"] = 1_000_000_001
        case "boolean":
            member["reads"]["server_copy_read"] = True
        case "string_count":
            member["fenced_reads"] = "3"
        case "time":
            member["snapshot"] = {"synced_at": "2026-11-10T11:00:00Z", "tree": _TREE}
        case "tree":
            member["snapshot"] = {"synced_at": _AT, "tree": "/srv/project"}
        case "reason":
            member["content_forgotten"] = {"at": _AT, "reason": "later"}
        case "extra":
            member["host"] = "lab.example.org"
        case _:
            raise AssertionError(change)
    return member


_CHANGES = (
    "not_level_l2",
    "explicit_null",
    "schema",
    "missing_token",
    "extra_token",
    "negative",
    "oversized",
    "boolean",
    "string_count",
    "time",
    "tree",
    "reason",
    "extra",
)


@pytest.mark.parametrize("change", _CHANGES)
def test_nothing_but_a_level_l2_account_is_admitted(change: str) -> None:
    wire = _receipt_result_wire()
    wire["evidence_provenance"] = cast(JsonValue, _mutated(change))
    with pytest.raises(pydantic.ValidationError):
        ReceiptResultModel.model_validate(wire)
    # A reader that validates by the 1.5.0 schema alone refuses the same members.
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("receipt-result", "1.5.0", wire)


def test_the_member_model_refuses_an_account_that_is_not_level_l2() -> None:
    assert (
        ReceiptEvidenceProvenanceModel.model_validate(_COPY_READ.to_json()).model_dump(
            mode="json", by_alias=True
        )
        == _COPY_READ.to_json()
    )
    with pytest.raises(pydantic.ValidationError, match="evidence_provenance_not_level_l2"):
        ReceiptEvidenceProvenanceModel.model_validate(_client_only())


_LEAVES = (
    "schema",
    *(f"reads/{token}" for token in EVIDENCE_PROVENANCE_TOKENS),
    "fenced_reads",
    "snapshot/synced_at",
    "snapshot/tree",
    "content_forgotten/at",
    "content_forgotten/reason",
)


@pytest.mark.parametrize("leaf", _LEAVES)
def test_every_leaf_of_the_member_is_structural(leaf: str) -> None:
    account = EvidenceProvenance(
        {"server_copy_read": 1},
        snapshot=CopySnapshotRef(_AT, _TREE),
        content_forgotten=ContentForgotten(_AT, "expired"),
    )
    wire = public_model_to_wire(ReceiptResultModel.model_validate(_wire("text", account)))
    assert classify_result_leaf("receipt", wire, f"/evidence_provenance/{leaf}") == (
        "public_structural"
    )


@pytest.mark.parametrize("container", ["snapshot", "content_forgotten"])
def test_a_null_snapshot_or_marker_is_structural(container: str) -> None:
    account = EvidenceProvenance({"server_copy_read": 1})
    wire = public_model_to_wire(ReceiptResultModel.model_validate(_wire("json", account)))
    assert classify_result_leaf("receipt", wire, f"/evidence_provenance/{container}") == (
        "public_structural"
    )


def test_a_paged_receipt_delivers_the_member_whole_on_its_first_page() -> None:
    wire = _wire("text", _COPY_READ)
    wire["human_text"] = "\n".join(
        f"Section line {i}: " + "plain receipt prose. " * 6 for i in range(150)
    )
    page = page_result(
        wire,
        method="receipt",
        selector={"request_id": wire["request_id"]},
        writer_id="wri_00000000-0000-4000-8000-000000000095",
        sink="agent_context",
        position=0,
    )
    assert page["next_cursor"] is not None
    items = cast(list[dict[str, JsonValue]], page["items"])
    paths = [item["path"] for item in items]
    assert paths.index("/evidence_provenance") < paths.index("/human_text")
    assert {"path": "/evidence_provenance", "value": _COPY_READ.to_json()} in items


# --- the account could not be given: ``evidence_provenance_unknown`` -------------------------


def _unknown_wire(receipt_format: str, reason: str) -> dict[str, JsonValue]:
    from finishup.domain.evidence_provenance import evidence_provenance_unknown_wire

    wire = _receipt_result_wire()
    if receipt_format != "json":
        wire["format"] = receipt_format
        wire["document"] = None
        wire["human_text"] = "Receipt"
    wire["evidence_provenance_unknown"] = cast(
        JsonValue, evidence_provenance_unknown_wire(cast(Any, reason))
    )
    return wire


@pytest.mark.parametrize(
    "reason", ["evidence_provenance_unreadable", "evidence_provenance_counts_incomplete"]
)
@pytest.mark.parametrize("receipt_format", ["json", "text", "markdown"])
def test_every_receipt_format_says_when_the_account_is_unknown(
    receipt_format: str, reason: str
) -> None:
    receipt = ReceiptResultModel.model_validate(_unknown_wire(receipt_format, reason))
    success = receipt.root
    assert type(success) is ReceiptSuccessModel
    assert success.evidence_provenance_unknown is not None
    assert success.evidence_provenance_unknown.reason == reason
    wire = public_model_to_wire(receipt)
    validate_schema_instance("receipt-result", "1.5.0", cast(JsonValue, wire))
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("receipt-result", "1.4.0", cast(JsonValue, wire))
    for leaf in ("status", "reason", "notice"):
        assert classify_result_leaf("receipt", wire, f"/evidence_provenance_unknown/{leaf}") == (
            "public_structural"
        )


@pytest.mark.parametrize(
    "change",
    ["another_reasons_notice", "free_text_notice", "unknown_reason", "status", "extra"],
)
def test_nothing_but_a_closed_reason_with_its_own_notice_is_admitted(change: str) -> None:
    from finishup.domain.evidence_provenance import evidence_provenance_unknown_notice

    wire = _unknown_wire("json", "evidence_provenance_unreadable")
    member = cast(dict[str, Any], wire["evidence_provenance_unknown"])
    if change == "another_reasons_notice":
        member["notice"] = evidence_provenance_unknown_notice(
            "evidence_provenance_counts_incomplete"
        )
    elif change == "free_text_notice":
        member["notice"] = "The server did not read the repository itself."
    elif change == "unknown_reason":
        member["reason"] = "evidence_provenance_lost"
    elif change == "status":
        member["status"] = "known"
    else:
        member["extra"] = 1
    with pytest.raises(pydantic.ValidationError):
        ReceiptResultModel.model_validate(wire)
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("receipt-result", "1.5.0", cast(JsonValue, wire))


def test_a_receipt_never_carries_an_account_and_its_unknown_status_together() -> None:
    wire = _unknown_wire("json", "evidence_provenance_unreadable")
    wire["evidence_provenance"] = cast(JsonValue, _COPY_READ.to_json())
    with pytest.raises(pydantic.ValidationError, match="evidence_provenance_conflict"):
        ReceiptResultModel.model_validate(wire)


def test_a_paged_receipt_delivers_the_unknown_status_on_its_first_page() -> None:
    wire = _unknown_wire("text", "evidence_provenance_counts_incomplete")
    wire["human_text"] = "\n".join(
        f"Section line {i}: " + "plain receipt prose. " * 6 for i in range(150)
    )
    page = page_result(
        wire,
        method="receipt",
        selector={"request_id": wire["request_id"]},
        writer_id="wri_00000000-0000-4000-8000-000000000095",
        sink="agent_context",
        position=0,
    )
    paths = [item["path"] for item in cast(list[dict[str, JsonValue]], page["items"])]
    assert paths.index("/evidence_provenance_unknown") < paths.index("/human_text")
