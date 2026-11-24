"""A ledger's projection digester re-encodes only changed records and keeps the exact digest."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from builders.replay import replay_records
from finishup.kernel import projections
from finishup.kernel.projections import (
    ProjectionDigester,
    ProjectionState,
    projection_digest,
)
from finishup.kernel.reducers import replay_extension, replay_with_index
from finishup.protocol.canonical import CanonicalFragment, JsonValue

_VECTORS = (
    "all-event-families",
    "multi-writer",
    "page-size-equivalence",
    "projection-rebuild",
    "supersession-redaction",
    "unknown-schema",
    "wall-clock-reversal",
)
_RECORD_MAPS = (
    "plans",
    "obligations",
    "decisions",
    "assignments",
    "actions",
    "results",
    "evidence",
    "claims",
    "findings",
    "responses",
    "coordination_contexts",
    "coordination_dispositions",
    "coordination_declarations",
)


def _successive_states(name: str) -> Iterator[ProjectionState]:
    """Yield the projection after each append, extending the previous one like a ledger does."""

    records = replay_records(name)
    state, _ = replay_with_index(records[:1])
    yield state
    for position in range(1, len(records)):
        state = replay_extension(state, records[:position], records[position : position + 1])
        yield state


def _record_ids(state: ProjectionState) -> set[int]:
    return {id(record) for name in _RECORD_MAPS for record in getattr(state, name).values()}


class _CountingFragments:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls = 0
        original = projections.canonical_fragment

        def counting(value: JsonValue | CanonicalFragment) -> CanonicalFragment:
            self.calls += 1
            return original(value)

        monkeypatch.setattr(projections, "canonical_fragment", counting)


@pytest.mark.parametrize("name", _VECTORS)
def test_digester_matches_projection_digest_after_every_append(name: str) -> None:
    digester = ProjectionDigester()
    for state in _successive_states(name):
        assert digester.digest(state) == projection_digest(state)


@pytest.mark.parametrize("name", _VECTORS)
def test_digester_encodes_only_records_that_are_new_since_the_last_digest(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    counter = _CountingFragments(monkeypatch)
    digester = ProjectionDigester()
    previous: set[int] = set()
    for state in _successive_states(name):
        current = _record_ids(state)
        before = counter.calls
        digester.digest(state)
        assert counter.calls - before == len(current - previous)
        before = counter.calls
        digester.digest(state)
        assert counter.calls == before
        previous = current


def test_digester_keeps_only_the_records_of_the_projection_it_digested() -> None:
    states = list(_successive_states("supersession-redaction"))
    digester = ProjectionDigester()
    for state in states:
        digester.digest(state)
    assert len(digester._fragments) == len(_record_ids(states[-1]))  # pyright: ignore[reportPrivateUsage]
    digester.digest(states[0])
    assert len(digester._fragments) == len(_record_ids(states[0]))  # pyright: ignore[reportPrivateUsage]


def test_a_failing_spliced_digest_falls_back_to_the_exact_uncached_outcome(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = list(_successive_states("all-event-families"))[-1]
    expected = projection_digest(state)

    def broken(value: JsonValue | CanonicalFragment) -> CanonicalFragment:
        raise ValueError("forced")

    monkeypatch.setattr(projections, "canonical_fragment", broken)
    assert ProjectionDigester().digest(state) == expected


def test_a_non_projection_raises_what_projection_digest_raises() -> None:
    with pytest.raises(ValueError) as uncached:
        projection_digest(object())  # type: ignore[arg-type]  # pyright: ignore[reportArgumentType]
    with pytest.raises(ValueError) as cached:
        ProjectionDigester().digest(object())  # type: ignore[arg-type]  # pyright: ignore[reportArgumentType]
    assert type(cached.value) is type(uncached.value)
    assert str(cached.value) == str(uncached.value)
    # Raised outside the spliced path's handler, so it chains exactly as the uncached error does.
    assert cached.value.__context__ is uncached.value.__context__ is None
    assert cached.value.__cause__ is uncached.value.__cause__ is None
