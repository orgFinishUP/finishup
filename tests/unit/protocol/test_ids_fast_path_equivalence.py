"""Differential equivalence for the canonical-ID fast path in ``validate_id``.

``validate_id`` returns at once when an exact ``str`` fully matches its kind's precompiled
canonical pattern; every other input takes the step-by-step checks. IDs are load-bearing for
ledger identity, so the fast path must accept exactly what the checks accept and return the same
object. The reference below is the pre-fast-path implementation, verbatim, compared on return
identity and on the exact raised error over mutated IDs of every kind.
"""

from __future__ import annotations

import random
import string
from collections.abc import Callable
from typing import cast

import pytest

import finishup.protocol.ids as ids_module
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.ids import (
    ID_TOTAL_LENGTH,
    PREFIX_BY_KIND,
    IdKind,
    is_valid_id,
    new_id,
    validate_actor_id,
    validate_id,
)

_UUID_PATTERN = ids_module._UUID_PATTERN  # pyright: ignore[reportPrivateUsage]


def _reference_validate_id(kind: IdKind, value: object) -> str:
    """The pre-fast-path implementation, verbatim."""

    validated_kind = ids_module._validate_kind(kind)  # pyright: ignore[reportPrivateUsage]
    if validated_kind is IdKind.ACTOR:
        return validate_actor_id(value)
    if not ids_module._is_actual_str_instance(value):  # pyright: ignore[reportPrivateUsage]
        raise ProtocolValueError("id_wrong_type")
    candidate = cast(str, value)
    if ids_module._string_length(candidate) != ID_TOTAL_LENGTH:  # pyright: ignore[reportPrivateUsage]
        raise ProtocolValueError("id_wrong_length")
    try:
        encoded = str.encode(candidate, "ascii", "strict")
    except UnicodeEncodeError as exc:
        raise ProtocolValueError("id_not_ascii") from exc
    if any(byte < 0x21 or byte > 0x7E for byte in encoded):
        raise ProtocolValueError("id_not_ascii")
    if ids_module._string_slice(candidate, 0, 4) != PREFIX_BY_KIND[validated_kind]:  # pyright: ignore[reportPrivateUsage]
        raise ProtocolValueError("id_wrong_prefix")
    uuid_text = ids_module._string_slice(candidate, 4)  # pyright: ignore[reportPrivateUsage]
    if _UUID_PATTERN.fullmatch(uuid_text) is None:
        raise ProtocolValueError("id_malformed_uuid")
    if uuid_text[14] != "4":
        raise ProtocolValueError("id_uuid_not_version_4")
    if uuid_text[19] not in {"8", "9", "a", "b"}:
        raise ProtocolValueError("id_uuid_wrong_variant")
    return candidate


def _outcome(operation: Callable[[], str], value: object) -> object:
    try:
        result = operation()
    except (ProtocolValueError, TypeError) as exc:
        return ("error", type(exc).__name__, str(exc), exc.args)
    assert result is value
    return ("ok", id(result))


def _assert_equivalent(kind: object, value: object) -> None:
    typed_kind = cast(IdKind, kind)
    fast = _outcome(lambda: validate_id(typed_kind, value), value)
    reference = _outcome(lambda: _reference_validate_id(typed_kind, value), value)
    assert fast == reference, f"validate_id diverged on {kind!r}, {value!r}"


class _Str(str):
    __slots__ = ()


_MUTATION_ALPHABET = (
    string.ascii_lowercase
    + string.ascii_uppercase
    + string.digits
    + "-_ \t\n\x00\x7f\x80é\ud800\U0001f600"
)


def _mutations(rng: random.Random, value: str) -> list[str]:
    out: list[str] = []
    for position in range(len(value)):
        out.append(value[:position] + rng.choice(_MUTATION_ALPHABET) + value[position + 1 :])
    out.append(value[:-1])
    out.append(value + rng.choice(_MUTATION_ALPHABET))
    out.append(value + "\n")
    out.append(value.upper())
    out.append(value[:4] + value[4:].upper())
    out.append(value[:18] + "4" + value[19:])
    for variant in "0123456789abcdefABCDEF":
        out.append(value[:23] + variant + value[24:])
    for version in "0123456789abcdef":
        out.append(value[:18] + version + value[19:])
    return out


@pytest.mark.parametrize("kind", list(IdKind), ids=[kind.name for kind in IdKind])
def test_mutated_ids_match_the_reference_for_every_kind(kind: IdKind) -> None:
    rng = random.Random(f"ids-{kind.value}")
    sources = [new_id(other) for other in IdKind if other is not IdKind.ACTOR]
    for _ in range(40):
        base = (
            new_id(kind) if kind is not IdKind.ACTOR and rng.random() < 0.6 else rng.choice(sources)
        )
        _assert_equivalent(kind, base)
        _assert_equivalent(kind, _Str(base))
        for mutated in _mutations(rng, base):
            _assert_equivalent(kind, mutated)
            _assert_equivalent(kind, _Str(mutated))


@pytest.mark.parametrize(
    "value",
    [
        None,
        1,
        b"req_00000000-0000-4000-8000-000000000001",
        "",
        "req_00000000-0000-4000-8000-000000000001",
        "req_00000000-0000-4000-c000-000000000001",
        "req_00000000-0000-4000-8000-00000000000",
        "req_00000000-0000-4000-8000-0000000000001",
        "req_00000000-0000-4000-8000-000000000001\n",
        "\nreq_00000000-0000-4000-8000-00000000001",
        "REQ_00000000-0000-4000-8000-000000000001",
        "req-00000000-0000-4000-8000-000000000001",
        "req_000000000000-4000-8000-0000000000001",
        "req_0000000-00000-4000-8000-000000000001",
        "req_00000000-0000-4000-8000-00000000000g",
        "req_00000000-0000-4000-8000-0000000000０",
    ],
)
def test_boundary_values_match_the_reference(value: object) -> None:
    for kind in (IdKind.REQUEST, IdKind.TASK, IdKind.ACTOR):
        _assert_equivalent(kind, value)


@pytest.mark.parametrize("kind", ["request", IdKind.REQUEST.value, None, 0])
def test_wrong_kind_types_match_the_reference(kind: object) -> None:
    _assert_equivalent(kind, "req_00000000-0000-4000-8000-000000000001")
    _assert_equivalent(kind, None)


def test_canonical_id_skips_the_step_by_step_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    """Performance property: a canonical ID of an exact str never reaches the slow checks."""

    def _forbidden(*_: object) -> object:
        raise AssertionError("slow path reached")

    values = {kind: new_id(kind) for kind in IdKind if kind is not IdKind.ACTOR}
    monkeypatch.setattr(ids_module, "_validate_kind", _forbidden)
    monkeypatch.setattr(ids_module, "_is_actual_str_instance", _forbidden)
    monkeypatch.setattr(ids_module, "_string_length", _forbidden)
    for kind, value in values.items():
        assert validate_id(kind, value) is value
        assert is_valid_id(kind, value)
    with pytest.raises(AssertionError, match="slow path reached"):
        validate_id(IdKind.REQUEST, _Str(values[IdKind.REQUEST]))
