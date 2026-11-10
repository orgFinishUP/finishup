"""The terminal interface's receipt and status for a level-L2 task and connection (ADR-054).

Through ``FinishUpRuntime`` only (ADR-017): a JSON receipt whose result carries a level-L2
``evidence_provenance`` shows the fixed server-copy lines after its document and names only its
producer; a text receipt shows the service's section once; a status over an L2 connection says
the server reads from its copy where it has one. Never the L1 sentence for any of them.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import cast

import pytest
from tests.unit.tui.test_remote_attribution import (
    _BoundClient,
    _document_lines,
    _status_of,
)
from tests.unit.tui.test_workflow_contract import _SESSION

from finishup.cli.render import render_human_status
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
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import ReceiptRequestModel, ReceiptResultModel
from finishup.tui.runtime import FinishUpRuntime

pytestmark = pytest.mark.anyio
_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000084"
_REACHED = f"This client reached FinishUP service {_SERVICE_ID} (transport: connector)."
_AT = "2026-11-10T11:00:00.000Z"
_ACCOUNT = EvidenceProvenance(
    {"server_copy_read": 2, "client_observation": 3},
    snapshot=CopySnapshotRef(_AT, "12" * 20),
    content_forgotten=ContentForgotten(_AT, "owner"),
)
_L1_SENTENCE = "the server did not read the repository itself"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _CopyClient(_BoundClient):
    def __init__(self, level: str | None) -> None:
        super().__init__("client_claim")
        self.consent_level = level
        self.account: EvidenceProvenance | None = _ACCOUNT

    async def receipt(self, request: ReceiptRequestModel) -> object:
        result = cast(ReceiptResultModel, await super().receipt(request))
        if self.account is None:
            return result
        wire = cast(
            dict[str, JsonValue],
            result.root.model_dump(mode="json", by_alias=True, exclude_unset=True),
        )
        wire["evidence_provenance"] = cast(JsonValue, self.account.to_json())
        return ReceiptResultModel.model_validate(wire)


async def _runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, level: str | None
) -> tuple[FinishUpRuntime, _CopyClient]:
    client = _CopyClient(level)

    @asynccontextmanager
    async def connect(_runtime: FinishUpRuntime) -> AsyncGenerator[_CopyClient]:
        yield client

    monkeypatch.setattr(FinishUpRuntime, "_client", connect)
    runtime = FinishUpRuntime(cwd=tmp_path)
    await runtime.open_task(_SESSION)
    return runtime, client


@pytest.mark.parametrize("level", ["L1", "L2"])
async def test_a_json_receipt_shows_the_server_copy_lines_after_the_document(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, level: str
) -> None:
    runtime, client = await _runtime(monkeypatch, tmp_path, level)
    client.hook_observed = True
    summary = await runtime.build_receipt(_SESSION, "json")
    section = ("Workspace evidence", *evidence_provenance_lines(_ACCOUNT, hook_observed=True))
    assert summary.rendered_lines == (*_document_lines(), *section, _REACHED)
    assert summary.rendered_lines.count(CLIENT_ATTESTED_OBSERVATION_LINE) == 1
    assert CLIENT_ATTESTED_WORKSPACE_LINE not in summary.rendered_lines
    assert not any(_L1_SENTENCE in line for line in summary.rendered_lines)


async def test_a_text_receipt_shows_the_services_section_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime, client = await _runtime(monkeypatch, tmp_path, "L2")
    block = server_copy_receipt_block(_SERVICE_ID, _ACCOUNT, markdown=False)
    client.human_text = "Receipt\n\n" + block
    summary = await runtime.build_receipt(_SESSION, "text")
    rendered = "\n".join(summary.rendered_lines)
    assert rendered.count("Evidence reads by source") == 1
    assert "were deleted at 2026-11-10T11:00:00.000Z (the owner forgot it)" in rendered
    assert summary.rendered_lines[-1] == _REACHED
    assert CLIENT_ATTESTED_WORKSPACE_LINE not in summary.rendered_lines
    assert SERVER_COPY_CONNECTION_LINE not in summary.rendered_lines


async def test_an_l1_json_receipt_on_an_l1_connection_is_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime, client = await _runtime(monkeypatch, tmp_path, None)
    client.account = None
    summary = await runtime.build_receipt(_SESSION, "json")
    assert summary.rendered_lines == (*_document_lines(), CLIENT_ATTESTED_WORKSPACE_LINE, _REACHED)


async def test_a_task_view_over_an_l2_connection_says_the_server_reads_from_its_copy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime, client = await _runtime(monkeypatch, tmp_path, "L2")
    rendered = await runtime.task_status(_SESSION, "lineage")
    success = _status_of(await client.status(client.requests[-1]))  # pyright: ignore[reportArgumentType]
    assert rendered.lines == (
        *render_human_status(success).splitlines(),
        SERVER_COPY_CONNECTION_LINE,
        _REACHED,
    )
