"""The MCP receipt and status text for a level-L2 task and connection (ADR-054, section 8.6).

A JSON receipt's text gains the fixed server-copy lines rendered from its ``evidence_provenance``
member; a text receipt's canonical copy already carries the service's section and gains nothing
but the producer; a page of a paged receipt names only the producer; a status over an L2
connection says the server reads from its copy where it has one. The structured result never
changes, and an L1 answer keeps its exact bytes.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from typing import cast

import pytest
from tests.unit.protocol.test_models_and_schemas import _receipt_result_wire

import finishup.mcp.server as bridge
from builders.status_wire import compact_status
from finishup.application.result_delivery import page_result
from finishup.client.attribution import ServiceAttribution
from finishup.domain.evidence_provenance import (
    ContentForgotten,
    CopySnapshotRef,
    EvidenceProvenance,
)
from finishup.domain.receipts import (
    CLIENT_ATTESTED_OBSERVATION_LINE,
    CLIENT_ATTESTED_WORKSPACE_LINE,
    SERVER_COPY_CONNECTION_LINE,
    evidence_provenance_lines,
    server_copy_receipt_block,
)
from finishup.mcp.summaries import summary_for_receipt
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.models import ReceiptResultModel, public_model_to_wire

_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000087"
_L2 = ServiceAttribution(_SERVICE_ID, "https", "L2")
_L1 = ServiceAttribution(_SERVICE_ID, "https")
_REACHED = f"This client reached FinishUP service {_SERVICE_ID} (transport: https)."
_AT = "2026-11-10T11:00:00.000Z"
_ACCOUNT = EvidenceProvenance(
    {"server_copy_read": 5, "stale_copy_read": 1, "outside_read": 2},
    fenced_reads=1,
    snapshot=CopySnapshotRef(_AT, "ef" * 20),
    content_forgotten=ContentForgotten(_AT, "expired"),
)
_L1_SENTENCE = "the server did not read the repository itself"


def _text(result: object) -> str:
    content = cast(list[object], getattr(result, "content"))
    return cast(str, getattr(content[0], "text"))


def _section(account: EvidenceProvenance, *, hook_observed: bool = False) -> str:
    return "\n".join(
        ("Workspace evidence", *evidence_provenance_lines(account, hook_observed=hook_observed))
    )


def _receipt(*, text: str | None = None, hook_observed: bool = False) -> ReceiptResultModel:
    wire = _receipt_result_wire()
    if text is not None:
        wire["format"] = "text"
        wire["document"] = None
        wire["human_text"] = text
    wire["evidence_provenance"] = cast(JsonValue, _ACCOUNT.to_json())
    if hook_observed:
        coverage = cast(dict[str, JsonValue], wire["coverage"])
        channels = cast(list[JsonValue], coverage["publication_channels"])
        wire["coverage"] = {**coverage, "publication_channels": [*channels, "hook_observed"]}
    return ReceiptResultModel.model_validate(wire)


@pytest.mark.parametrize("attribution", [None, _L1, _L2], ids=["local", "l1", "l2"])
def test_a_json_receipt_text_gains_the_server_copy_lines_from_its_member(
    attribution: ServiceAttribution | None,
) -> None:
    receipt = _receipt(hook_observed=True)
    canonical = canonical_encode(cast(JsonValue, public_model_to_wire(receipt))).decode("utf-8")
    result = bridge.result_from_public_model(receipt, attribution=attribution)
    expected = [canonical, _section(_ACCOUNT, hook_observed=True)]
    if attribution is not None:
        expected.append(_REACHED)
    assert _text(result) == "\n".join(expected)
    assert _text(result).count(CLIENT_ATTESTED_OBSERVATION_LINE) == 1
    assert CLIENT_ATTESTED_WORKSPACE_LINE not in _text(result)
    assert SERVER_COPY_CONNECTION_LINE not in _text(result)
    # The structured result is the receipt's own, untouched.
    assert result.structuredContent == bridge.result_from_public_model(receipt).structuredContent
    assert cast(dict[str, JsonValue], result.structuredContent)["evidence_provenance"] == (
        _ACCOUNT.to_json()
    )


def test_a_text_receipt_carries_the_services_section_and_gains_only_the_producer() -> None:
    block = server_copy_receipt_block(_SERVICE_ID, _ACCOUNT, markdown=True)
    receipt = _receipt(text="Receipt\n\n" + block)
    local = _text(bridge.result_from_public_model(receipt))
    assert local == canonical_encode(cast(JsonValue, public_model_to_wire(receipt))).decode()
    assert "Evidence reads by source (yoetz.evidence-provenance/1): " in local
    for attribution in (_L1, _L2):
        attributed = _text(bridge.result_from_public_model(receipt, attribution=attribution))
        assert attributed == local + "\n" + _REACHED


def test_an_l1_json_receipt_keeps_its_exact_text() -> None:
    receipt = ReceiptResultModel.model_validate(_receipt_result_wire())
    canonical = canonical_encode(cast(JsonValue, public_model_to_wire(receipt))).decode("utf-8")
    assert _text(bridge.result_from_public_model(receipt, attribution=_L1)) == "\n".join(
        (canonical, CLIENT_ATTESTED_WORKSPACE_LINE, _REACHED)
    )
    # Over an L2 connection, the same receipt says what is true of that connection.
    assert _text(bridge.result_from_public_model(receipt, attribution=_L2)) == "\n".join(
        (canonical, SERVER_COPY_CONNECTION_LINE, _REACHED)
    )


def test_a_page_of_a_paged_receipt_names_only_the_producer() -> None:
    wire = public_model_to_wire(_receipt(text="x"))
    wire["human_text"] = "\n".join(
        f"Section line {i}: " + "plain receipt prose. " * 6 for i in range(150)
    )
    page = page_result(
        wire,
        method="receipt",
        selector={"request_id": wire["request_id"]},
        writer_id="wri_00000000-0000-4000-8000-000000000097",
        sink="agent_context",
        position=0,
    )
    model = ReceiptResultModel.model_validate(page)
    local = _text(bridge.result_from_public_model(model))
    attributed = _text(bridge.result_from_public_model(model, attribution=_L2))
    assert attributed == local + "\n" + _REACHED
    assert "Evidence reads by source" not in attributed


def test_a_status_over_an_l2_connection_says_the_server_reads_from_its_copy() -> None:
    status = compact_status().result
    local = _text(bridge.result_from_public_model(status))
    text = _text(bridge.result_from_public_model(status, attribution=_L2))
    assert text == "\n".join((local, SERVER_COPY_CONNECTION_LINE, _REACHED))
    assert _L1_SENTENCE not in text


def test_the_receipt_summary_carries_the_server_copy_lines() -> None:
    summary = summary_for_receipt(public_model_to_wire(_receipt(hook_observed=True)))
    for line in evidence_provenance_lines(_ACCOUNT, hook_observed=True):
        assert line in summary
    plain = summary_for_receipt(
        public_model_to_wire(ReceiptResultModel.model_validate(_receipt_result_wire()))
    )
    assert "Evidence reads by source" not in plain
    # A member that is not a level-L2 account's exact form adds nothing.
    source = public_model_to_wire(_receipt())
    source["evidence_provenance"] = cast(
        JsonValue, EvidenceProvenance({"client_check": 1}).to_json()
    )
    assert "Evidence reads by source" not in summary_for_receipt(source)
