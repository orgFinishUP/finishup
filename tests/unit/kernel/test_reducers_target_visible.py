"""Missing-reference visibility answers without re-validating IDs already held as projection keys."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

import pytest

from builders.replay import replay_records
from finishup.domain.values import (
    action_id,
    claim_id,
    evidence_id,
    finding_id,
    obligation_id,
    result_id,
)
from finishup.kernel import reducers
from finishup.kernel.projections import projection_digest
from finishup.protocol.errors import ProtocolValueError

_UUID = "00000000-0000-4000-8000-0000000000{:02x}"
_VALIDATORS: dict[str, Callable[[object], str]] = {
    "obl_": obligation_id,
    "act_": action_id,
    "res_": result_id,
    "evd_": evidence_id,
    "clm_": claim_id,
    "fnd_": finding_id,
}
_VALIDATOR_NAMES = {
    "obl_": "obligation_id",
    "act_": "action_id",
    "res_": "result_id",
    "evd_": "evidence_id",
    "clm_": "claim_id",
    "fnd_": "finding_id",
}
_REPLAY_VECTORS = (
    "all-event-families",
    "empty",
    "multi-writer",
    "page-size-equivalence",
    "projection-rebuild",
    "supersession-redaction",
    "unknown-schema",
    "wall-clock-reversal",
)


def _legacy_target_visible(
    target: str,
    obligations: Mapping[Any, object],
    actions: Mapping[Any, object],
    results: Mapping[Any, object],
    evidence: Mapping[Any, object],
    claims: Mapping[Any, object],
    findings: Mapping[Any, object],
) -> bool:
    """The previous form, which validated every target before the lookup."""

    if target.startswith("obl_"):
        return obligation_id(target) in obligations
    if target.startswith("act_"):
        return action_id(target) in actions
    if target.startswith("res_"):
        return result_id(target) in results
    if target.startswith("evd_"):
        return evidence_id(target) in evidence
    if target.startswith("clm_"):
        return claim_id(target) in claims
    if target.startswith("fnd_"):
        return finding_id(target) in findings
    raise reducers._corrupt()


def _maps(prefix: str, present: str) -> list[dict[Any, object]]:
    order = tuple(_VALIDATORS)
    return [{present: object()} if key == prefix else {} for key in order]


def _outcome(call: Callable[[], bool]) -> tuple[str, object]:
    try:
        return ("value", call())
    except ValueError as exc:
        return (type(exc).__name__, str(exc))


@pytest.mark.parametrize("prefix", tuple(_VALIDATORS))
def test_target_visibility_matches_the_validating_form(prefix: str) -> None:
    present = _VALIDATORS[prefix](prefix + _UUID.format(1))
    maps = _maps(prefix, present)
    targets = (
        present,
        prefix + _UUID.format(2),
        prefix + "not-an-id",
        prefix + _UUID.format(1).upper(),
        prefix + _UUID.format(1)[:-1],
    )
    for target in targets:
        assert _outcome(lambda: reducers._target_visible(target, *maps)) == _outcome(
            lambda: _legacy_target_visible(target, *maps)
        )


def test_unknown_target_prefix_stays_corrupt() -> None:
    maps = _maps("act_", action_id("act_" + _UUID.format(1)))
    with pytest.raises(ValueError, match="projection_corrupt"):
        reducers._target_visible("xyz_" + _UUID.format(1), *maps)


@pytest.mark.parametrize("prefix", tuple(_VALIDATORS))
def test_a_present_target_skips_its_validator_and_a_miss_still_runs_it(
    monkeypatch: pytest.MonkeyPatch, prefix: str
) -> None:
    calls: list[object] = []
    original = _VALIDATORS[prefix]

    def counting(value: object) -> str:
        calls.append(value)
        return original(value)

    monkeypatch.setattr(reducers, _VALIDATOR_NAMES[prefix], counting)
    present = original(prefix + _UUID.format(1))
    maps = _maps(prefix, present)

    assert reducers._target_visible(present, *maps) is True
    assert calls == []

    absent = prefix + _UUID.format(2)
    assert reducers._target_visible(absent, *maps) is False
    assert calls == [absent]

    with pytest.raises(ProtocolValueError):
        reducers._target_visible(prefix + "bad", *maps)
    assert len(calls) == 2


def test_a_str_subclass_target_is_always_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    class Lying(str):
        __slots__ = ()

        def __eq__(self, other: object) -> bool:
            return True

        def __hash__(self) -> int:
            return hash(present)

    calls: list[object] = []

    def counting(value: object) -> str:
        calls.append(value)
        return action_id(value)

    present = action_id("act_" + _UUID.format(1))
    maps = _maps("act_", present)
    monkeypatch.setattr(reducers, "action_id", counting)

    with pytest.raises(ProtocolValueError):
        reducers._target_visible(Lying("act_bad"), *maps)
    assert len(calls) == 1


@pytest.mark.parametrize("name", _REPLAY_VECTORS)
def test_replay_vectors_project_identically_with_the_validating_form(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    records = replay_records(name)
    fast = reducers.replay(records)
    monkeypatch.setattr(reducers, "_target_visible", _legacy_target_visible)
    legacy = reducers.replay(records)

    assert fast.coverage_gaps == legacy.coverage_gaps
    assert projection_digest(fast) == projection_digest(legacy)
