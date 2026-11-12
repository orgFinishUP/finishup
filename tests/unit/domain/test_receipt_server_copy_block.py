"""A level-L2 task's "Workspace evidence" section (ADR-054, design v2 section 8.6).

It says, per kind of evidence, where the task's evidence was read: from the server's copy of the
repository or by the client's workspace agent, with every token's count, the outside reads a held
repository fenced (ADR-052 O7), the copy snapshot last read, what a stale copy read means, and the
marker of a forgotten copy (U20). It never holds the level-L1 sentence that the server did not
read the repository itself, and nothing user-controlled ever joins it. When a server that keeps
copies cannot read the account, its section says neither that the server read its copy nor that
it did not.
"""

from __future__ import annotations

import pytest

from finishup.domain.evidence_provenance import (
    EVIDENCE_COUNT_MAX,
    EVIDENCE_PROVENANCE_TOKENS,
    ContentForgotten,
    CopySnapshotRef,
    EvidenceProvenance,
)
from finishup.domain.receipts import (
    CLIENT_ATTESTED_OBSERVATION_LINE,
    CLIENT_ATTESTED_WORKSPACE_LINE,
    EVIDENCE_PROVENANCE_UNREADABLE_LINE,
    EVIDENCE_READS_PREFIX,
    SERVER_COPY_NONE_COUNTED_LINE,
    SERVER_COPY_WORKSPACE_LINE,
    evidence_provenance_lines,
    evidence_provenance_unknown_receipt_block,
    server_copy_receipt_block,
)
from finishup.protocol.errors import ProtocolValueError

_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000093"
_SERVED = f"Served by FinishUP service {_SERVICE_ID} (connection: client_claim)."
_AT = "2026-11-10T11:00:00.000Z"
_TREE = "0123456789abcdef0123456789abcdef01234567"
_L1_SENTENCE = "the server did not read the repository itself"


def test_a_copy_read_names_every_source_and_the_snapshot_in_fixed_lines() -> None:
    account = EvidenceProvenance(
        {"server_copy_read": 4, "client_attested_read": 2, "outside_read": 1},
        fenced_reads=3,
        snapshot=CopySnapshotRef(_AT, _TREE),
    )

    block = server_copy_receipt_block(_SERVICE_ID, account, markdown=False)

    assert block.split("\n") == [
        "Workspace evidence",
        SERVER_COPY_WORKSPACE_LINE,
        "Evidence reads by source (yoetz.evidence-provenance/1): server_copy_read 4, "
        "client_attested_read 2, client_check 0, client_observation 0, outside_read 1, "
        "stale_copy_read 0.",
        "Outside reads the client's workspace agent left unread because they reached a "
        "repository its owner holds from this server: 3.",
        "The task's evidence was last read from the server's copy as synced at "
        "2026-11-10T11:00:00.000Z (tree 0123456789ab).",
        _SERVED,
    ]
    assert SERVER_COPY_WORKSPACE_LINE == (
        "Workspace evidence was read by the server from its copy of the repository, synced from "
        "the client machine; the FinishUP workspace agent on the client machine answered the "
        "rest over the connection."
    )
    assert server_copy_receipt_block(_SERVICE_ID, account, markdown=True) == ("## " + block)
    assert CLIENT_ATTESTED_WORKSPACE_LINE not in block
    assert _L1_SENTENCE not in block


def test_a_stale_read_says_the_client_was_offline_and_a_forgotten_copy_says_so() -> None:
    account = EvidenceProvenance(
        {"stale_copy_read": 2, "client_check": 1},
        content_forgotten=ContentForgotten(_AT, "expired"),
    )

    lines = evidence_provenance_lines(account, hook_observed=True)

    assert lines == (
        SERVER_COPY_WORKSPACE_LINE,
        EVIDENCE_READS_PREFIX + "server_copy_read 0, client_attested_read 0, client_check 1, "
        "client_observation 0, outside_read 0, stale_copy_read 2.",
        "Outside reads the client's workspace agent left unread because they reached a "
        "repository its owner holds from this server: 0.",
        "Reads counted as stale_copy_read were answered from the server's copy as last synced, "
        "because the client machine was offline; its files may have changed since.",
        "The server's copy and the excerpts derived from it were deleted at "
        "2026-11-10T11:00:00.000Z (its retention expired); findings and checks remain without "
        "their excerpts.",
        CLIENT_ATTESTED_OBSERVATION_LINE,
    )
    owner = EvidenceProvenance(
        {"server_copy_read": 1}, content_forgotten=ContentForgotten(_AT, "owner")
    )
    assert (
        "The server's copy and the excerpts derived from it were deleted at "
        "2026-11-10T11:00:00.000Z (the owner forgot it); findings and checks remain without "
        "their excerpts." in evidence_provenance_lines(owner)
    )
    # Without a stale read the stale line is absent; without a hook observation, so is its line.
    assert not any("stale_copy_read were" in line for line in evidence_provenance_lines(owner))
    assert CLIENT_ATTESTED_OBSERVATION_LINE not in evidence_provenance_lines(owner)


def test_a_marker_without_a_counted_copy_read_never_claims_one_nor_denies_one() -> None:
    """A forgotten copy's marker alone is level L2's: the section says what the account counts,
    never that the server read its copy and never the L1 sentence."""

    account = EvidenceProvenance(
        {"client_attested_read": 3}, content_forgotten=ContentForgotten(_AT, "owner")
    )

    block = server_copy_receipt_block(_SERVICE_ID, account, markdown=False, hook_observed=True)

    lines = block.split("\n")
    assert lines[1] == SERVER_COPY_NONE_COUNTED_LINE
    assert SERVER_COPY_WORKSPACE_LINE not in block
    assert _L1_SENTENCE not in block
    assert lines[-2:] == [CLIENT_ATTESTED_OBSERVATION_LINE, _SERVED]


@pytest.mark.parametrize("markdown", [False, True])
def test_the_longest_section_fits_the_closing_section_bound(markdown: bool) -> None:
    account = EvidenceProvenance(
        dict.fromkeys(EVIDENCE_PROVENANCE_TOKENS, EVIDENCE_COUNT_MAX),
        EVIDENCE_COUNT_MAX,
        CopySnapshotRef(_AT, "f" * 40),
        ContentForgotten(_AT, "expired"),
    )
    block = server_copy_receipt_block(_SERVICE_ID, account, markdown=markdown, hook_observed=True)
    assert len(block) <= 2_048
    assert len(block.split("\n")) == 9
    for line in block.split("\n"):
        assert "/" not in line.replace("yoetz.evidence-provenance/1", "")


@pytest.mark.parametrize(
    "account",
    [
        EvidenceProvenance(),
        EvidenceProvenance({"client_attested_read": 9, "outside_read": 2}, fenced_reads=4),
        EvidenceProvenance(snapshot=CopySnapshotRef(_AT, _TREE)),
        None,
        {"server_copy_read": 1},
    ],
    ids=["empty", "client_only", "snapshot_only", "none", "mapping"],
)
def test_an_account_that_is_not_level_l2s_has_no_server_copy_section(account: object) -> None:
    with pytest.raises(ProtocolValueError, match="invalid_receipt_document"):
        evidence_provenance_lines(account)  # pyright: ignore[reportArgumentType]
    with pytest.raises(ProtocolValueError, match="invalid_receipt_document"):
        server_copy_receipt_block(
            _SERVICE_ID,
            account,  # pyright: ignore[reportArgumentType]
            markdown=False,
        )


def test_the_serving_service_must_be_an_instance_id() -> None:
    account = EvidenceProvenance({"server_copy_read": 1})
    with pytest.raises(ProtocolValueError):
        server_copy_receipt_block("lab.example.org", account, markdown=False)
    with pytest.raises(ProtocolValueError):
        evidence_provenance_unknown_receipt_block("lab.example.org", markdown=False)


@pytest.mark.parametrize("hook_observed", [False, True])
def test_an_unreadable_account_says_neither_that_the_copy_was_read_nor_that_it_was_not(
    hook_observed: bool,
) -> None:
    block = evidence_provenance_unknown_receipt_block(
        _SERVICE_ID, markdown=False, hook_observed=hook_observed
    )

    assert block.split("\n") == [
        "Workspace evidence",
        EVIDENCE_PROVENANCE_UNREADABLE_LINE,
        "Some evidence may have been read from the server's copy of the repository, synced from "
        "the client machine; the rest was read on the client machine by the FinishUP workspace "
        "agent. Running receipt again may read the account.",
        *((CLIENT_ATTESTED_OBSERVATION_LINE,) if hook_observed else ()),
        _SERVED,
    ]
    assert _L1_SENTENCE not in block
    assert SERVER_COPY_WORKSPACE_LINE not in block
    assert EVIDENCE_READS_PREFIX not in block
