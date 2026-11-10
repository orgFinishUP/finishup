"""The CLI's human receipt and status for a level-L2 task and connection (ADR-054, section 8.6).

A JSON receipt (no service text) shows the same fixed server-copy lines a text receipt ends with,
rendered from its ``evidence_provenance`` member; a text receipt shows the service's own section
once; neither ever gets the connection's client-attested line. A status over an L2 connection
says the server reads from its copy where it has one. An L1 receipt keeps its exact bytes.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from typing import Any, cast

from tests.unit.protocol.test_models_and_schemas import _receipt_result_wire

from builders.status_wire import compact_status
from finishup.cli.render import render_human_receipt, render_human_status
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
    client_attested_receipt_block,
    evidence_provenance_lines,
    server_copy_receipt_block,
)
from finishup.protocol.models import ReceiptSuccessModel, StatusSuccessModel

_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000086"
_L2 = ServiceAttribution(_SERVICE_ID, "ssh", "L2")
_L1 = ServiceAttribution(_SERVICE_ID, "ssh")
_REACHED = f"This client reached FinishUP service {_SERVICE_ID} (transport: ssh)."
_AT = "2026-11-10T11:00:00.000Z"
_ACCOUNT = EvidenceProvenance(
    {"server_copy_read": 3, "client_attested_read": 1, "client_check": 1},
    fenced_reads=2,
    snapshot=CopySnapshotRef(_AT, "cd" * 20),
)
_L1_SENTENCE = "the server did not read the repository itself"


def _receipt(
    *,
    text: str | None = None,
    account: EvidenceProvenance | None = None,
    hook_observed: bool = False,
) -> ReceiptSuccessModel:
    wire = cast(dict[str, Any], _receipt_result_wire())
    if text is not None:
        wire["format"] = "text"
        wire["document"] = None
        wire["human_text"] = text
    if account is not None:
        wire["evidence_provenance"] = account.to_json()
    if hook_observed:
        coverage = dict(wire["coverage"])
        coverage["publication_channels"] = [*coverage["publication_channels"], "hook_observed"]
        wire["coverage"] = coverage
    return ReceiptSuccessModel.model_validate(wire)


def _section(account: EvidenceProvenance, *, hook_observed: bool = False) -> str:
    return "\n".join(
        ("Workspace evidence", *evidence_provenance_lines(account, hook_observed=hook_observed))
    )


def test_a_json_receipt_shows_the_server_copy_lines_from_its_member() -> None:
    plain = render_human_receipt(_receipt())
    receipt = _receipt(account=_ACCOUNT)
    local = render_human_receipt(receipt)
    assert local == plain + "\n" + _section(_ACCOUNT)
    for attribution in (_L1, _L2):
        rendered = render_human_receipt(receipt, attribution=attribution)
        assert rendered == local + "\n" + _REACHED
        assert CLIENT_ATTESTED_WORKSPACE_LINE not in rendered
        assert SERVER_COPY_CONNECTION_LINE not in rendered
        assert _L1_SENTENCE not in rendered
    # An L1 JSON receipt keeps its exact bytes.
    assert render_human_receipt(_receipt(), attribution=_L1) == "\n".join(
        (plain, CLIENT_ATTESTED_WORKSPACE_LINE, _REACHED)
    )


def test_a_json_receipt_with_hook_observed_evidence_names_the_caveat_once() -> None:
    receipt = _receipt(account=_ACCOUNT, hook_observed=True)
    rendered = render_human_receipt(receipt, attribution=_L2)
    assert _section(_ACCOUNT, hook_observed=True) in rendered
    assert rendered.count(CLIENT_ATTESTED_OBSERVATION_LINE) == 1
    assert rendered.endswith("\n" + _REACHED)


def test_a_text_receipt_shows_the_services_section_once_and_only_the_producer() -> None:
    block = server_copy_receipt_block(_SERVICE_ID, _ACCOUNT, markdown=False)
    receipt = _receipt(text="Receipt\n\n" + block, account=_ACCOUNT)
    local = render_human_receipt(receipt)
    assert local.count("Evidence reads by source") == 1
    for attribution in (_L1, _L2):
        rendered = render_human_receipt(receipt, attribution=attribution)
        assert rendered == local + "\n" + _REACHED
        assert CLIENT_ATTESTED_WORKSPACE_LINE not in rendered


def test_a_forgotten_copy_shows_its_marker() -> None:
    forgotten = EvidenceProvenance(
        {"client_attested_read": 2}, content_forgotten=ContentForgotten(_AT, "owner")
    )
    rendered = render_human_receipt(_receipt(account=forgotten), attribution=_L2)
    assert (
        "The server's copy and the excerpts derived from it were deleted at "
        "2026-11-10T11:00:00.000Z (the owner forgot it); findings and checks remain without "
        "their excerpts." in rendered
    )
    assert _L1_SENTENCE not in rendered


def test_an_l1_task_on_an_l2_connection_keeps_its_own_section() -> None:
    """The service's client-attested section is the task's account: the L2 connection adds only
    its producer, never its own line beside it."""

    receipt = _receipt(
        text="Receipt\n\n" + client_attested_receipt_block(_SERVICE_ID, markdown=False)
    )
    rendered = render_human_receipt(receipt, attribution=_L2)
    assert rendered == render_human_receipt(receipt) + "\n" + _REACHED
    assert SERVER_COPY_CONNECTION_LINE not in rendered


def test_a_status_over_an_l2_connection_says_the_server_reads_from_its_copy() -> None:
    status = compact_status().result.root
    assert type(status) is StatusSuccessModel
    local = render_human_status(status)
    assert render_human_status(status, attribution=_L2) == "\n".join(
        (local, SERVER_COPY_CONNECTION_LINE, _REACHED)
    )
    assert _L1_SENTENCE not in render_human_status(status, attribution=_L2)
    # L1 keeps its exact bytes.
    assert render_human_status(status, attribution=_L1) == "\n".join(
        (local, CLIENT_ATTESTED_WORKSPACE_LINE, _REACHED)
    )


def _unknown_section(reason: str, *, hook_observed: bool = False) -> str:
    from finishup.domain.receipts import evidence_provenance_unknown_section_lines

    return "\n".join(
        (
            "Workspace evidence",
            *evidence_provenance_unknown_section_lines(reason, hook_observed=hook_observed),
        )
    )


def test_a_json_receipt_whose_account_is_unknown_never_gets_the_l1_sentence() -> None:
    # ADR-054: the account could not be given (after an L2 -> L1 downgrade the connection is L1):
    # the JSON receipt says so from its member, and never "the server did not read" it.
    from finishup.domain.evidence_provenance import (
        EVIDENCE_PROVENANCE_UNKNOWN_REASONS,
        evidence_provenance_unknown_wire,
    )

    plain = render_human_receipt(_receipt())
    for reason in EVIDENCE_PROVENANCE_UNKNOWN_REASONS:
        wire = cast(dict[str, Any], _receipt_result_wire())
        wire["evidence_provenance_unknown"] = evidence_provenance_unknown_wire(reason)
        receipt = ReceiptSuccessModel.model_validate(wire)
        for attribution in (_L1, _L2):
            rendered = render_human_receipt(receipt, attribution=attribution)
            assert rendered == "\n".join((plain, _unknown_section(reason), _REACHED))
            assert _L1_SENTENCE not in rendered
            assert SERVER_COPY_CONNECTION_LINE not in rendered
