"""A claim-bound task's per-evidence provenance on its receipts (ADR-054, design v2 section 8.6).

A service that keeps copies of repositories gives the application one source of a claim-bound
task's evidence account (``Application.evidence_provenance``). Every receipt, new or replayed,
asks it once: a level-L2 account (a read from the server's copy, or that copy's forgotten marker)
ends the text and markdown receipt with the server-copy section instead of the client-attested
one and rides every format as ``evidence_provenance``; any other answer leaves the receipt exactly
as before. A source that fails never refuses the receipt and never lets it claim more than the
server knows. These drive the real ``Application`` facade of the respond/status/receipt harness.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Literal, cast

import pytest

from builders.ledger_adapters import ownership_fence
from builders.start_application import start_request
from finishup.application import receipt as receipt_module
from finishup.application.service import ClientProjectionContext, ProjectionRenderMode
from finishup.domain.evidence_provenance import (
    ContentForgotten,
    CopySnapshotRef,
    EvidenceAccountIncomplete,
    EvidenceProvenance,
    evidence_provenance_unknown_wire,
)
from finishup.domain.receipts import (
    CLIENT_ATTESTED_WORKSPACE_LINE,
    client_attested_receipt_block,
    evidence_provenance_unknown_receipt_block,
    server_copy_receipt_block,
)
from finishup.ports.control import ControlClientKind
from finishup.ports.runtime import TaskRuntime
from finishup.protocol.models import ReceiptRequest
from integration.application.test_receipt_attestation import (  # pyright: ignore[reportPrivateUsage]
    _CLAIM,  # pyright: ignore[reportPrivateUsage]
    _project,  # pyright: ignore[reportPrivateUsage]
)
from integration.application.test_respond_status_receipt import (  # pyright: ignore[reportPrivateUsage]
    _build_app,  # pyright: ignore[reportPrivateUsage]
    _receipt_wire,  # pyright: ignore[reportPrivateUsage]
)

pytestmark = pytest.mark.anyio

_AT = "2026-11-10T11:00:00.000Z"
_ACCOUNT = EvidenceProvenance(
    {"server_copy_read": 4, "client_attested_read": 2, "outside_read": 1},
    fenced_reads=3,
    snapshot=CopySnapshotRef(_AT, "0123456789abcdef0123456789abcdef01234567"),
)
_L1_SENTENCE = "the server did not read the repository itself"
_CONTEXTS = (
    ClientProjectionContext(
        ControlClientKind.CLI, ProjectionRenderMode.HUMAN_READABLE, True, owner_view=True
    ),
    ClientProjectionContext(ControlClientKind.CLI, ProjectionRenderMode.HUMAN_READABLE, True),
    ClientProjectionContext(
        ControlClientKind.MCP_BRIDGE, ProjectionRenderMode.MACHINE_READABLE, False
    ),
)


class _Source:
    """An evidence source answering ``answer`` (or raising it), recording every call."""

    def __init__(self, answer: object) -> None:
        self.answer = answer
        self.calls: list[tuple[str, str]] = []

    async def __call__(self, handle: str, runtime: TaskRuntime) -> EvidenceProvenance | None:
        self.calls.append((handle, runtime.task_id))
        if isinstance(self.answer, BaseException):
            raise self.answer
        return cast(EvidenceProvenance | None, self.answer)


async def _claim_bound_receipt(
    source: _Source, seed: int, receipt_format: str, *, claim_bound: bool = True
) -> tuple[Any, ReceiptRequest, Any]:  # noqa: ANN401
    built, _runtime, _ = _build_app(seed_offset=seed)
    app = replace(built, evidence_provenance=source)
    started = await app.start(
        start_request(seed * 100, title="Evidence provenance receipt"),
        repository_privacy_context=_CLAIM if claim_bound else None,
    )
    request = ReceiptRequest.model_validate(
        {
            **_receipt_wire(
                seed * 100 + 10,
                task_id=started.task_id,
                session=started.session_id,
                writer=started.writer_id,
                frontier=started.frontier,
            ),
            "format": receipt_format,
        }
    )
    return app, request, started


@pytest.mark.parametrize("receipt_format", ["text", "markdown", "json"])
async def test_a_level_l2_account_ends_the_receipt_and_rides_every_format(
    receipt_format: Literal["text", "markdown", "json"],
) -> None:
    source = _Source(_ACCOUNT)
    app, request, started = await _claim_bound_receipt(source, 61, receipt_format)

    result = await app.receipt(request)

    # Asked once, with the claim's own handle and the task's runtime.
    assert source.calls == [(_CLAIM.workspace_handle, started.task_id)]
    assert result.as_json()["evidence_provenance"] == _ACCOUNT.to_json()
    if receipt_format == "json":
        assert result.human_text is None
    else:
        assert result.human_text is not None
        block = server_copy_receipt_block(
            ownership_fence().service_instance_id,
            _ACCOUNT,
            markdown=receipt_format == "markdown",
        )
        assert result.human_text.endswith("\n\n" + block)
        assert result.human_text.count(block) == 1
        assert CLIENT_ATTESTED_WORKSPACE_LINE not in result.human_text
        assert _L1_SENTENCE not in result.human_text
        # Every client receives it through the service's own projection and validation. (This
        # harness's JSON documents predate the receipt-document fields a projection requires, so
        # the JSON result is checked above, as the precedent tests do.)
        for context in _CONTEXTS:
            projected = await _project(app, request, result, context)
            assert projected.evidence_provenance is not None
            assert (
                projected.evidence_provenance.model_dump(mode="json", by_alias=True)
                == _ACCOUNT.to_json()
            )
            assert isinstance(projected.human_text, str)
            assert projected.human_text.endswith("\n\n" + block)


async def test_a_replay_asks_again_and_the_stored_receipt_never_changes() -> None:
    """The account is recomputed on every receipt and replay, never stored: a replay of an L1
    receipt shows the L2 account once the task has one, and the stored receipt keeps its digest.
    A source that says nothing keeps the client-attested section and no member: L1's bytes."""

    source = _Source(None)
    app, request, _started = await _claim_bound_receipt(source, 62, "text")
    service_id = ownership_fence().service_instance_id

    first = await app.receipt(request)
    assert first.human_text is not None
    assert first.human_text.endswith(
        "\n\n" + client_attested_receipt_block(service_id, markdown=False)
    )
    assert "evidence_provenance" not in first.as_json()
    # An account that is not level L2's is no account to show either.
    source.answer = EvidenceProvenance({"client_attested_read": 5}, fenced_reads=1)
    same = await app.receipt(request)
    assert same.as_json() == first.as_json()

    forgotten = EvidenceProvenance(
        {"server_copy_read": 2}, content_forgotten=ContentForgotten(_AT, "owner")
    )
    source.answer = forgotten
    replayed = await app.receipt(request)

    assert len(source.calls) == 3
    assert replayed.receipt_id == first.receipt_id
    assert replayed.receipt_digest == first.receipt_digest
    assert replayed.receipt_object_id == first.receipt_object_id
    assert replayed.as_json()["evidence_provenance"] == forgotten.to_json()
    assert replayed.human_text is not None
    assert replayed.human_text.endswith(
        "\n\n" + server_copy_receipt_block(service_id, forgotten, markdown=False)
    )
    assert "the excerpts derived from it were deleted" in replayed.human_text
    assert CLIENT_ATTESTED_WORKSPACE_LINE not in replayed.human_text


@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        (OSError(5, "copy record unreadable at /srv/state"), "evidence_provenance_source_failed"),
        ({"server_copy_read": 1}, "evidence_provenance_source_invalid"),
        (EvidenceAccountIncomplete(), "evidence_provenance_counts_incomplete"),
    ],
    ids=["raises", "not_an_account", "counts_incomplete"],
)
@pytest.mark.parametrize("receipt_format", ["text", "json"])
async def test_a_failing_source_never_claims_more_than_the_server_knows(
    answer: object,
    reason: str,
    receipt_format: Literal["text", "json"],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The receipt is built and recorded anyway; its section says neither that the server read
    its copy nor that it did not, no account is carried, and one bounded event names a closed
    reason (never the failure's text)."""

    recorded: list[dict[str, object]] = []

    def record(**fields: object) -> str:
        recorded.append(fields)
        return "cor_test"

    monkeypatch.setattr(receipt_module, "record_bounded_event_without_raising", record)
    source = _Source(answer)
    app, request, _started = await _claim_bound_receipt(source, 63, receipt_format)

    result = await app.receipt(request)

    assert len(source.calls) == 1
    wire = result.as_json()
    assert "evidence_provenance" not in wire
    # Every format, JSON included, says the account is unknown and why (ADR-054), so a client
    # rendering it never adds the connection's level-L1 line.
    unknown = (
        "evidence_provenance_counts_incomplete"
        if reason == "evidence_provenance_counts_incomplete"
        else "evidence_provenance_unreadable"
    )
    assert wire["evidence_provenance_unknown"] == evidence_provenance_unknown_wire(
        cast(Any, unknown)
    )
    assert recorded == [
        {
            "component": "application.receipt",
            "operation": "receipt_evidence_provenance_read",
            "reason": reason,
            "request_id": request.request_id,
        }
    ]
    if receipt_format == "text":
        assert result.human_text is not None
        assert result.human_text.endswith(
            "\n\n"
            + evidence_provenance_unknown_receipt_block(
                ownership_fence().service_instance_id, markdown=False, reason=cast(Any, unknown)
            )
        )
        assert _L1_SENTENCE not in result.human_text
        assert "/srv/state" not in result.human_text
    # Once the source reads again, the same request shows the account.
    source.answer = _ACCOUNT
    again = await app.receipt(request)
    assert again.receipt_id == result.receipt_id
    assert again.as_json()["evidence_provenance"] == _ACCOUNT.to_json()
    assert "evidence_provenance_unknown" not in again.as_json()


async def test_a_task_that_is_not_claim_bound_never_asks_the_source() -> None:
    source = _Source(_ACCOUNT)
    app, request, _started = await _claim_bound_receipt(source, 64, "text", claim_bound=False)

    result = await app.receipt(request)

    assert source.calls == []
    assert "evidence_provenance" not in result.as_json()
    assert result.human_text is not None
    assert "Workspace evidence" not in result.human_text


def test_the_application_refuses_a_source_that_cannot_be_called() -> None:
    built, _runtime, _ = _build_app(seed_offset=65)
    with pytest.raises(TypeError, match="evidence_provenance_invalid"):
        replace(built, evidence_provenance=cast(Any, "copy-store"))
