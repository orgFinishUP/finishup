"""A claim-bound connection at level L2 never says the server did not read the repository.

ADR-054, design v2 section 8.6: a connection whose target the owner consented to at level L2 may
have its evidence read by the server from its copy, so its fixed line says the server reads from
its copy where it has one and the client's agent answers the rest. A receipt carrying a level-L2
account says per kind of evidence where it was read, rendered from the member when the service
sent no text, and the connection then names only its producer. Level L1 keeps its exact bytes.
"""

from __future__ import annotations

import asyncio
from collections.abc import Buffer
from types import SimpleNamespace
from typing import Any, cast

import pytest

from finishup.adapters.control.unix_socket import AuthenticatedUnixStream
from finishup.client.attribution import (
    CONNECTION_LEVELS,
    ServiceAttribution,
    attribution_lines,
    connection_attribution,
    evidence_provenance_section,
)
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
    evidence_provenance_unknown_receipt_block,
    server_copy_receipt_block,
)
from finishup.ports.control import ControlClientKind, ControlMethod
from finishup.protocol.models import ReceiptEvidenceProvenanceModel
from finishup.service import client as client_module
from finishup.service.control_protocol import ControlSession

_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000085"
_REACHED = f"This client reached FinishUP service {_SERVICE_ID} (transport: ssh)."
_L2 = ServiceAttribution(_SERVICE_ID, "ssh", "L2")
_L1 = ServiceAttribution(_SERVICE_ID, "ssh")
_AT = "2026-11-10T11:00:00.000Z"
_ACCOUNT = EvidenceProvenance(
    {"server_copy_read": 2, "client_attested_read": 1},
    snapshot=CopySnapshotRef(_AT, "ab" * 20),
)
_L1_SENTENCE = "the server did not read the repository itself"


def test_an_l2_connection_says_the_server_reads_from_its_copy_where_it_has_one() -> None:
    assert CONNECTION_LEVELS == ("L1", "L2")
    assert SERVER_COPY_CONNECTION_LINE == (
        "Workspace evidence is read by the server from its copy of the repository, synced from "
        "the client machine, where it has one; the FinishUP workspace agent on the client machine "
        "answers the rest over the connection."
    )
    assert _L2.lines() == (SERVER_COPY_CONNECTION_LINE, _REACHED)
    assert _L1_SENTENCE not in "\n".join(_L2.lines())
    # A status (no receipt text) ends with both lines; L1 keeps its exact bytes.
    assert attribution_lines(_L2) == (SERVER_COPY_CONNECTION_LINE, _REACHED)
    assert attribution_lines(_L1) == (CLIENT_ATTESTED_WORKSPACE_LINE, _REACHED)
    assert _L1.lines() == ServiceAttribution(_SERVICE_ID, "ssh", "L1").lines()
    with pytest.raises(ValueError, match="service_attribution_invalid"):
        ServiceAttribution(_SERVICE_ID, "ssh", "L3")  # pyright: ignore[reportArgumentType]


@pytest.mark.parametrize(
    ("level", "expected"), [(None, "L1"), ("L1", "L1"), ("L2", "L2")], ids=["none", "l1", "l2"]
)
def test_the_connection_carries_its_consent_level(level: str | None, expected: str) -> None:
    connection = SimpleNamespace(
        workspace_binding="client_claim",
        service_instance_id=_SERVICE_ID,
        transport="ssh",
        consent_level=level,
    )
    attribution = connection_attribution(connection)
    assert attribution is not None
    assert attribution.level == expected
    # A connection object without the fact at all is level L1.
    bare = SimpleNamespace(
        workspace_binding="client_claim", service_instance_id=_SERVICE_ID, transport="ssh"
    )
    assert connection_attribution(bare) == _L1


@pytest.mark.parametrize("level", ["L3", "l2", 2, ""])
def test_a_malformed_consent_level_never_drops_the_provenance(level: object) -> None:
    connection = SimpleNamespace(
        workspace_binding="client_claim",
        service_instance_id=_SERVICE_ID,
        transport="ssh",
        consent_level=level,
    )
    with pytest.raises(ValueError, match="service_attribution_invalid"):
        connection_attribution(connection)


@pytest.mark.parametrize("attribution", [_L1, _L2], ids=["l1", "l2"])
def test_a_receipt_carrying_the_server_copy_section_names_only_the_producer(
    attribution: ServiceAttribution,
) -> None:
    for block in (
        server_copy_receipt_block(_SERVICE_ID, _ACCOUNT, markdown=False, hook_observed=True),
        evidence_provenance_unknown_receipt_block(_SERVICE_ID, markdown=True),
    ):
        shown = "Conclusion: clean\n\n" + block
        assert attribution_lines(attribution, shown=shown, hook_observed=True) == (_REACHED,)
    # A JSON receipt whose result carries the member: its section is rendered from the member.
    assert attribution_lines(attribution, server_copy=True, hook_observed=True) == (_REACHED,)


def test_an_l2_connection_never_contradicts_a_receipts_client_attested_section() -> None:
    """A task that read nothing from the copy keeps the service's L1 section; the L2 connection
    adds only its producer, never its own line beside the task's account."""

    shown = "Conclusion: clean\n\n" + client_attested_receipt_block(
        _SERVICE_ID, markdown=False, hook_observed=True
    )
    assert attribution_lines(_L2, shown=shown, hook_observed=True) == (_REACHED,)
    assert attribution_lines(_L1, shown=shown, hook_observed=True) == (_REACHED,)
    # A JSON receipt without the member on an L2 connection says what is true of the
    # connection, never the L1 sentence.
    lines = attribution_lines(_L2, hook_observed=True)
    assert lines == (SERVER_COPY_CONNECTION_LINE, CLIENT_ATTESTED_OBSERVATION_LINE, _REACHED)
    assert CLIENT_ATTESTED_WORKSPACE_LINE not in lines
    # A page of a paged receipt keeps today's rule: only the producer.
    assert attribution_lines(_L2, shown="fragment", receipt_page=True) == (_REACHED,)


def test_the_section_is_rendered_from_the_member_in_fixed_words_only() -> None:
    expected = "\n".join(
        ("Workspace evidence", *evidence_provenance_lines(_ACCOUNT, hook_observed=True))
    )
    assert evidence_provenance_section(_ACCOUNT.to_json(), hook_observed=True) == expected
    model = ReceiptEvidenceProvenanceModel.model_validate(_ACCOUNT.to_json())
    assert evidence_provenance_section(model, hook_observed=True) == expected
    forgotten = EvidenceProvenance(content_forgotten=ContentForgotten(_AT, "expired"))
    section = evidence_provenance_section(forgotten.to_json())
    assert section is not None
    assert "were deleted at 2026-11-10T11:00:00.000Z (its retention expired)" in section
    assert _L1_SENTENCE not in section
    assert CLIENT_ATTESTED_OBSERVATION_LINE not in section


@pytest.mark.parametrize(
    "member",
    [
        EvidenceProvenance({"client_attested_read": 3}).to_json(),
        {**_ACCOUNT.to_json(), "schema": "yoetz.evidence-provenance/2"},
        {**_ACCOUNT.to_json(), "note": "/srv/project"},
        None,
        "server_copy_read 2",
    ],
    ids=["not_level_l2", "schema", "extra", "none", "text"],
)
def test_nothing_but_a_level_l2_account_renders_a_section(member: object) -> None:
    assert evidence_provenance_section(member) is None


# --- the connection carries the level its target was consented at ------------------------------


class _Stream:
    def __init__(self) -> None:
        self.peer_identity = object()
        self._closed = asyncio.Event()

    async def receive(self, max_bytes: int) -> bytes:
        del max_bytes
        await self._closed.wait()
        return b""

    async def send_all(self, data: Buffer) -> None:
        del data

    async def aclose(self) -> None:
        self._closed.set()


def _claim_bound_client() -> client_module.ServiceClient:
    stream = _Stream()
    session = ControlSession(
        protocol_version="1.0",
        client_kind=ControlClientKind.CLI,
        service_instance_id=_SERVICE_ID,
        service_generation="1",
        allowed_methods=tuple(sorted(ControlMethod, key=lambda method: method.value.encode())),
        peer_identity=stream.peer_identity,
        connection_nonce="0" * 64,
        workspace_binding="client_claim",
        workspace_handle="client:0123456789abcdef",
    )
    factory = client_module._connected_client  # pyright: ignore[reportPrivateUsage]
    return factory(
        cast(AuthenticatedUnixStream, stream), session, ControlClientKind.CLI, transport="ssh"
    )


@pytest.mark.anyio
@pytest.mark.parametrize("anyio_backend", ["asyncio"])
@pytest.mark.parametrize("consent", [None, "L1", "L2"], ids=["no_consent", "l1", "l2"])
async def test_a_remote_connection_carries_its_targets_consent_level(
    consent: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The level comes from the target record the connection was admitted under; a local
    connection names none."""

    from finishup.client import authorization as authorization_module
    from finishup.client import targets as targets_module

    record = SimpleNamespace(
        is_remote=True,
        target_id="tgt_lab",
        kind="ssh",
        consent=None if consent is None else SimpleNamespace(level=consent),
    )
    monkeypatch.setattr(targets_module, "active_target_record", lambda: record)
    admitted = object()
    monkeypatch.setattr(authorization_module, "authorize_active_root", lambda: admitted)
    admission = await client_module._admit_remote(  # pyright: ignore[reportPrivateUsage]
        None, None, serve_workspace=False
    )
    assert admission is not None
    assert admission.level == consent

    reached = _claim_bound_client()
    assert reached.consent_level is None

    async def reach(*_args: object, **_kwargs: object) -> client_module.ServiceClient:
        return reached

    monkeypatch.setattr(client_module, "_reach_remote", reach)
    client = await client_module._connect_remote(  # pyright: ignore[reportPrivateUsage]
        admission,
        ControlClientKind.CLI,
        projection_render_mode=cast(Any, None),
        output_is_controlling_tty=False,
        deadline=0.0,
    )
    try:
        assert client is reached
        assert client.consent_level == consent
        attribution = connection_attribution(client)
        assert attribution is not None
        assert attribution.level == ("L2" if consent == "L2" else "L1")
        assert attribution.lines()[0] == (
            SERVER_COPY_CONNECTION_LINE if consent == "L2" else CLIENT_ATTESTED_WORKSPACE_LINE
        )
    finally:
        await client.close()
