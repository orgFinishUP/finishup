"""Per-evidence provenance of a claim-bound task's workspace evidence (ADR-054, design v2 §8.6).

At level L2 the server keeps a copy of the repository and reads some evidence from it itself,
while the client's workspace agent still answers the rest. A task's receipt then says, per kind of
evidence, where it was read, never the level-L1 sentence that the server did not read the
repository itself. ``EvidenceProvenance`` is that account for one task, versioned as
``yoetz.evidence-provenance/1``:

* ``reads``: how many evidence reads of the task each source answered, one closed token each:
  ``server_copy_read`` (the server's copy, synced before the read), ``client_attested_read`` (the
  client's workspace agent, attested), ``client_check`` (an approved check run on the client),
  ``client_observation`` (hook observations captured on the client), ``outside_read`` (a read
  outside the repository root, answered by the client's agent under its outside-read policy) and
  ``stale_copy_read`` (the server's copy while the client was offline: the copy as last synced);
* ``fenced_reads``: outside reads the client's agent refused because they reached a repository its
  owner holds (ADR-052 O7);
* ``snapshot``: the copy snapshot the task's evidence was last read from, by its sync time and
  tree id (synthetic ids, never a path), or None;
* ``content_forgotten``: when the copy the task read was forgotten, the time and the closed reason
  (``owner`` or ``expired``): the copy, its snapshots and the excerpts derived from it were deleted,
  and the task keeps this marker instead (U20).

Closed tokens, counts, synthetic ids and times only; nothing user-controlled. Standard library
only, so the protocol models can admit exactly these values.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final, Literal, cast

__all__ = [
    "EVIDENCE_COUNT_MAX",
    "EVIDENCE_PROVENANCE_COUNTS_INCOMPLETE",
    "EVIDENCE_PROVENANCE_SCHEMA",
    "EVIDENCE_PROVENANCE_TOKENS",
    "EVIDENCE_PROVENANCE_UNKNOWN",
    "EVIDENCE_PROVENANCE_UNKNOWN_LINE",
    "EVIDENCE_PROVENANCE_UNKNOWN_REASONS",
    "EVIDENCE_PROVENANCE_UNREADABLE",
    "ContentForgotten",
    "CopySnapshotRef",
    "EvidenceAccountIncomplete",
    "EvidenceProvenance",
    "EvidenceProvenanceUnknownReason",
    "EvidenceToken",
    "evidence_provenance_from_json",
    "evidence_provenance_unknown_lines",
    "evidence_provenance_unknown_notice",
    "evidence_provenance_unknown_wire",
]

EVIDENCE_PROVENANCE_SCHEMA: Final = "yoetz.evidence-provenance/1"
type EvidenceToken = Literal[
    "server_copy_read",
    "client_attested_read",
    "client_check",
    "client_observation",
    "outside_read",
    "stale_copy_read",
]
EVIDENCE_PROVENANCE_TOKENS: Final[tuple[EvidenceToken, ...]] = (
    "server_copy_read",
    "client_attested_read",
    "client_check",
    "client_observation",
    "outside_read",
    "stale_copy_read",
)
type ForgottenReason = Literal["owner", "expired"]
_FORGOTTEN_REASONS: Final = frozenset({"owner", "expired"})
_MAX_COUNT: Final = 1_000_000_000
# The largest count an account holds, per token and for ``fenced_reads``.
EVIDENCE_COUNT_MAX: Final = _MAX_COUNT
_HEX40: Final = re.compile(r"^[0-9a-f]{40}$")
# RFC 3339 UTC with milliseconds, as the service stamps every time it records.
_TIME: Final = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


# A claim-bound task's account could not be given (every receipt format carries this as its
# ``evidence_provenance_unknown`` member): the receipt then says neither that the server read
# its copy nor that it did not. One closed reason each, fixed words only.
type EvidenceProvenanceUnknownReason = Literal[
    "evidence_provenance_unreadable", "evidence_provenance_counts_incomplete"
]
EVIDENCE_PROVENANCE_UNKNOWN: Final = "unknown"
# Passing: the account could not be read (the source failed or answered no account).
EVIDENCE_PROVENANCE_UNREADABLE: Final = "evidence_provenance_unreadable"
# Lasting: the copy served some evidence, but the counts of those reads were lost.
EVIDENCE_PROVENANCE_COUNTS_INCOMPLETE: Final = "evidence_provenance_counts_incomplete"
EVIDENCE_PROVENANCE_UNKNOWN_REASONS: Final[tuple[EvidenceProvenanceUnknownReason, ...]] = (
    EVIDENCE_PROVENANCE_UNREADABLE,
    EVIDENCE_PROVENANCE_COUNTS_INCOMPLETE,
)
EVIDENCE_PROVENANCE_UNKNOWN_LINE: Final = (
    "Where this task's workspace evidence was read could not be determined: this server keeps "
    "copies of repositories, and its account of which reads its copy answered could not be read."
)
_UNKNOWN_IMPACT_LINES: Final[Mapping[str, str]] = MappingProxyType(
    {
        EVIDENCE_PROVENANCE_UNREADABLE: (
            "Some evidence may have been read from the server's copy of the repository, synced "
            "from the client machine; the rest was read on the client machine by the FinishUP "
            "workspace agent. Running receipt again may read the account."
        ),
        EVIDENCE_PROVENANCE_COUNTS_INCOMPLETE: (
            "Some evidence was read from the server's copy of the repository, synced from the "
            "client machine, but the service stopped before it recorded how many reads; the rest "
            "was read on the client machine by the FinishUP workspace agent. This lasts: running "
            "receipt again cannot recover those counts."
        ),
    }
)


def evidence_provenance_unknown_lines(reason: object) -> tuple[str, str]:
    """The two fixed lines for ``reason``: what happened, then why it matters and whether a
    retry can help (the passing cause) or why it lasts. Any other value is ``ValueError``."""

    if type(reason) is not str or reason not in _UNKNOWN_IMPACT_LINES:
        raise ValueError("evidence_provenance_reason_invalid")
    return EVIDENCE_PROVENANCE_UNKNOWN_LINE, _UNKNOWN_IMPACT_LINES[reason]


def evidence_provenance_unknown_notice(reason: object) -> str:
    """The ``notice`` of the ``evidence_provenance_unknown`` member: the lines joined."""

    return "\n".join(evidence_provenance_unknown_lines(reason))


def evidence_provenance_unknown_wire(reason: EvidenceProvenanceUnknownReason) -> dict[str, str]:
    """The ``evidence_provenance_unknown`` member of a receipt whose account is unknown."""

    return {
        "status": EVIDENCE_PROVENANCE_UNKNOWN,
        "reason": reason,
        "notice": evidence_provenance_unknown_notice(reason),
    }


def _invalid() -> ValueError:
    return ValueError("evidence_provenance_invalid")


class EvidenceAccountIncomplete(Exception):
    """A task's account cannot be told: the server's copy served some of its evidence (its
    durable marker says so), but no read from the copy is counted (buffered counts lost when the
    service stopped). A receipt then says where the evidence was read is unknown, never that the
    server did not read the repository itself (design v2 section 8.6)."""

    def __init__(self) -> None:
        super().__init__("evidence_provenance_counts_incomplete")


def _count(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_COUNT:
        raise _invalid()
    return value


def _time(value: object) -> str:
    if type(value) is not str or _TIME.match(value) is None:
        raise _invalid()
    return value


@dataclass(frozen=True, slots=True)
class CopySnapshotRef:
    """The copy snapshot evidence was read from: its sync time and synthetic tree id."""

    synced_at: str
    tree: str

    def __post_init__(self) -> None:
        _time(self.synced_at)
        if type(self.tree) is not str or _HEX40.match(self.tree) is None:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class ContentForgotten:
    """The marker a task keeps once the copy it read was forgotten (U20)."""

    at: str
    reason: ForgottenReason

    def __post_init__(self) -> None:
        _time(self.at)
        if self.reason not in _FORGOTTEN_REASONS:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class EvidenceProvenance:
    """One task's evidence provenance (see the module text)."""

    reads: Mapping[EvidenceToken, int] = field(default_factory=lambda: MappingProxyType({}))
    fenced_reads: int = 0
    snapshot: CopySnapshotRef | None = None
    content_forgotten: ContentForgotten | None = None

    def __post_init__(self) -> None:
        given = cast(object, self.reads)
        if not isinstance(given, Mapping):
            raise _invalid()
        reads = cast(Mapping[object, object], given)
        if any(token not in EVIDENCE_PROVENANCE_TOKENS for token in reads):
            raise _invalid()
        frozen = {
            token: _count(reads[token])
            for token in EVIDENCE_PROVENANCE_TOKENS
            if token in reads and reads[token] != 0
        }
        object.__setattr__(self, "reads", MappingProxyType(frozen))
        _count(self.fenced_reads)
        if self.snapshot is not None and type(self.snapshot) is not CopySnapshotRef:
            raise _invalid()
        if self.content_forgotten is not None and type(self.content_forgotten) is not (
            ContentForgotten
        ):
            raise _invalid()

    def count(self, token: EvidenceToken) -> int:
        return self.reads.get(token, 0)

    @property
    def read_from_copy(self) -> bool:
        """Whether any evidence of the task was read from the server's copy (fresh or stale)."""

        return self.count("server_copy_read") + self.count("stale_copy_read") > 0

    @property
    def level_l2(self) -> bool:
        """Whether this account is level L2's: a copy read, or a forgotten copy's marker."""

        return self.read_from_copy or self.content_forgotten is not None

    def plus(self, other: EvidenceProvenance) -> EvidenceProvenance:
        """Both accounts together: counts add; the later snapshot and marker win."""

        reads: dict[EvidenceToken, int] = {
            token: self.count(token) + other.count(token) for token in EVIDENCE_PROVENANCE_TOKENS
        }
        snapshot = self.snapshot
        if other.snapshot is not None and (
            snapshot is None or other.snapshot.synced_at >= snapshot.synced_at
        ):
            snapshot = other.snapshot
        forgotten = self.content_forgotten
        if other.content_forgotten is not None and (
            forgotten is None or other.content_forgotten.at >= forgotten.at
        ):
            forgotten = other.content_forgotten
        return EvidenceProvenance(
            reads, self.fenced_reads + other.fenced_reads, snapshot, forgotten
        )

    def to_json(self) -> dict[str, object]:
        """The canonical JSON form: every token present, in token order."""

        return {
            "schema": EVIDENCE_PROVENANCE_SCHEMA,
            "reads": {token: self.count(token) for token in EVIDENCE_PROVENANCE_TOKENS},
            "fenced_reads": self.fenced_reads,
            "snapshot": None
            if self.snapshot is None
            else {"synced_at": self.snapshot.synced_at, "tree": self.snapshot.tree},
            "content_forgotten": None
            if self.content_forgotten is None
            else {"at": self.content_forgotten.at, "reason": self.content_forgotten.reason},
        }


def evidence_provenance_from_json(value: object) -> EvidenceProvenance:
    """Decode ``to_json``'s form exactly; anything else is ``evidence_provenance_invalid``."""

    if not isinstance(value, Mapping):
        raise _invalid()
    source = cast(Mapping[str, object], value)
    if set(source) != {"schema", "reads", "fenced_reads", "snapshot", "content_forgotten"}:
        raise _invalid()
    if source["schema"] != EVIDENCE_PROVENANCE_SCHEMA:
        raise _invalid()
    reads = source["reads"]
    if not isinstance(reads, Mapping) or set(cast(Mapping[str, object], reads)) != set(
        EVIDENCE_PROVENANCE_TOKENS
    ):
        raise _invalid()
    snapshot = source["snapshot"]
    forgotten = source["content_forgotten"]
    snapshot_ref: CopySnapshotRef | None = None
    if snapshot is not None:
        if not isinstance(snapshot, Mapping) or set(cast(Mapping[str, object], snapshot)) != {
            "synced_at",
            "tree",
        }:
            raise _invalid()
        fields = cast(Mapping[str, object], snapshot)
        snapshot_ref = CopySnapshotRef(cast(str, fields["synced_at"]), cast(str, fields["tree"]))
    marker: ContentForgotten | None = None
    if forgotten is not None:
        if not isinstance(forgotten, Mapping) or set(cast(Mapping[str, object], forgotten)) != {
            "at",
            "reason",
        }:
            raise _invalid()
        fields = cast(Mapping[str, object], forgotten)
        marker = ContentForgotten(cast(str, fields["at"]), cast(ForgottenReason, fields["reason"]))
    return EvidenceProvenance(
        cast(Mapping[EvidenceToken, int], reads),
        cast(int, source["fenced_reads"]),
        snapshot_ref,
        marker,
    )
