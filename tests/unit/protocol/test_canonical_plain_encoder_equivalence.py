"""Differential equivalence for the plain-value canonical fast path.

``_canonical_text`` and ``ensure_canonical_value`` first ask ``_plain_failure`` whether the
whole value is plain profile JSON; if so the C json encoder renders it. The codec is load-bearing
for digests and stored identities, so the fast path must be taken only for values the walker
accepts, with byte-identical text. The reference here is the walker itself with the fast path
switched off, compared on output bytes and on the identity of any raised error.
"""

from __future__ import annotations

import enum
import random
from collections import Counter, OrderedDict
from collections.abc import Callable, Generator, Iterator, Mapping
from contextlib import contextmanager
from types import MappingProxyType
from typing import Any, cast

import pytest

import finishup.protocol.canonical as canonical
from builders.canonical_reference import reference_canonical_text as _main_text
from finishup.protocol.canonical import (
    JsonValue,
    canonical_encode,
    canonical_fragment,
    ensure_canonical_value,
    strict_json_parse,
)
from finishup.protocol.errors import ProtocolValueError

_MAX_SAFE = 2**53 - 1


@contextmanager
def _walker_only() -> Generator[None]:
    original = canonical._plain_failure  # pyright: ignore[reportPrivateUsage]
    canonical._plain_failure = lambda value, depth: ()  # pyright: ignore[reportPrivateUsage]
    try:
        yield
    finally:
        canonical._plain_failure = original  # pyright: ignore[reportPrivateUsage]


def _outcome(operation: Callable[[], object]) -> object:
    try:
        return ("ok", operation())
    except ProtocolValueError as exc:
        return ("error", type(exc).__name__, str(exc), exc.args)


def _ensure_at(depth: int) -> Callable[[object], object]:
    def _run(value: object) -> object:
        ensure_canonical_value(cast(JsonValue, value), depth=depth)
        return None

    return _run


_OPERATIONS: tuple[Callable[[object], object], ...] = (
    lambda value: canonical_encode(cast(JsonValue, value)),
    lambda value: canonical_fragment(cast(JsonValue, value)).text,
    _ensure_at(0),
    _ensure_at(1),
    _ensure_at(62),
    _ensure_at(63),
    _ensure_at(64),
)


def _main_ensure_at(depth: int) -> Callable[[object], object]:
    def _run(value: object) -> object:
        _main_text(value, depth)
        return None

    return _run


_MAIN_OPERATIONS: tuple[Callable[[object], object], ...] = (
    lambda value: _main_text(value).encode("utf-8"),
    lambda value: value.text if type(value) is canonical.CanonicalFragment else _main_text(value),
    _main_ensure_at(0),
    _main_ensure_at(1),
    _main_ensure_at(62),
    _main_ensure_at(63),
    _main_ensure_at(64),
)


def _assert_equivalent(value: object) -> None:
    fast = [_outcome(lambda op=op: op(value)) for op in _OPERATIONS]
    with _walker_only():
        reference = [_outcome(lambda op=op: op(value)) for op in _OPERATIONS]
    assert fast == reference, f"fast path diverged on {value!r}"
    main = [_outcome(lambda op=op: op(value)) for op in _MAIN_OPERATIONS]
    assert fast == main, f"fast path diverged from the plain walker on {value!r}"


class _Color(enum.StrEnum):
    RED = "red"


class _Level(enum.IntEnum):
    ONE = 1


class _Str(str):
    __slots__ = ()


class _Int(int):
    pass


class _Dict(dict[str, object]):
    pass


class _ListEqualMeta(type):
    """A metaclass whose classes compare equal to ``list``, so ``type(v) in {list, tuple}``."""

    def __eq__(cls, other: object) -> bool:
        return other is list or super().__eq__(other)

    def __hash__(cls) -> int:
        return hash(list)


class _ListLike(metaclass=_ListEqualMeta):
    """Not a list subclass, yet the walker's ``in {list, tuple}`` test treats it as a sequence."""

    def __init__(self, *items: object) -> None:
        self._items = items

    def __iter__(self) -> Iterator[object]:
        return iter(self._items)


def _nested(levels: int, *, leaf: object = 1, container: str = "dict") -> object:
    value = leaf
    for _ in range(levels):
        value = {"k": value} if container == "dict" else [value]
    return value


_EDGE_VALUES: tuple[object, ...] = (
    None,
    True,
    False,
    0,
    -1,
    _MAX_SAFE,
    -_MAX_SAFE,
    _MAX_SAFE + 1,
    -_MAX_SAFE - 1,
    2**63,
    1.0,
    float("nan"),
    "",
    "plain",
    "\x00",
    "\ud800",
    "\x7f  ﻿￿",
    "\U0001f600",
    '"\\/\b\f\n\r\t\x01\x1f',
    {},
    [],
    (),
    {"b": 1, "a": 2, "": 3},
    {"a": [1, (2, 3), {"c": None}]},
    (1, "x", [True, None]),
    {"": 1, "\U0001f600": 2, "￿": 3},
    {"\U00010000": 1, "퟿": 2},
    {"ﬁ": 1, "\U0010ffff": 2},
    {"\x00": 1},
    {"a\ud800": 1},
    {"a": "\x00"},
    {"a": "\udfff"},
    {1: "a"},
    {True: "a"},
    {_Str("k"): 1},
    {"a": _Str("v")},
    {"a": _Int(5)},
    {"a": _Color.RED},
    {"a": _Level.ONE},
    {_Color.RED: 1},
    _Color.RED,
    _Level.ONE,
    _Dict(a=1),
    {"a": _Dict(b=2)},
    OrderedDict([("b", 1), ("a", 2)]),
    MappingProxyType({"b": 1, "a": [1, {"c": "d"}]}),
    {"a": MappingProxyType({"b": {"c": [1, 2]}})},
    {"a": 1.5},
    [1, 2, 3.0],
    {"a": [_MAX_SAFE + 1]},
    {"a": {1, 2}},
    {"a": b"bytes"},
    {"a": object()},
    [{"z": 1, "y": [{"x": {"w": "\U0001f600"}}]}],
    {"a": canonical_fragment({"b": [1, 2]})},
    [canonical_fragment("x"), {"y": canonical_fragment(None)}],
    {"big": {str(index): index for index in range(200)}},
    # First offender wins inside the walker; the fast path must defer to it.
    {"a": 1.5, "b": "\x00"},
    {"b": "\x00", "a": 1.5},
    [{"a": "\ud800"}, 2**60],
    _nested(62),
    _nested(63),
    _nested(64),
    _nested(65),
    _nested(63, container="list"),
    _nested(64, container="list"),
    _nested(65, container="list"),
    _nested(63, leaf={}),
    _nested(63, leaf=[]),
    _nested(62, leaf=canonical_fragment({"a": [1]})),
    _nested(63, leaf=canonical_fragment({"a": 1})),
    _ListLike(1, "a", [2]),
    {"k": _ListLike(1, _ListLike(2))},
    [_ListLike(1.5)],
    _nested(63, leaf=_ListLike()),
    _nested(64, leaf=_ListLike()),
)


@pytest.mark.parametrize("value", _EDGE_VALUES, ids=range(len(_EDGE_VALUES)))
def test_edge_values_match_the_walker(value: object) -> None:
    _assert_equivalent(value)


def test_every_bmp_codepoint_as_key_and_value_matches_the_walker() -> None:
    """Escapes and key order over the whole BMP, including surrogates and private use."""

    for start in range(0, 0x10000, 256):
        characters = [chr(code) for code in range(start, start + 256)]
        _assert_equivalent({f"k{character}": character for character in characters})
        _assert_equivalent([f"a{character}b" for character in characters])
        for character in characters:
            _assert_equivalent({character: character})


def test_astral_and_high_bmp_keys_sort_like_the_walker() -> None:
    rng = random.Random(1290)
    pool = [chr(code) for code in (0xD7FF, 0xE000, 0xF8FF, 0xFB01, 0xFFFD, 0xFFFF)] + [
        chr(code) for code in (0x10000, 0x1F600, 0x10FFFF)
    ]
    for _ in range(500):
        keys = {"".join(rng.choice(pool) for _ in range(rng.randint(1, 3))) for _ in range(6)}
        _assert_equivalent({key: index for index, key in enumerate(keys)})


def _random_tree(rng: random.Random, depth: int) -> object:
    alphabet = (
        [chr(code) for code in range(0x00, 0x22)]
        + ['"', "\\", "/", "a", "Z", "é", "\x7f", " ", "", "￿"]
        + ["\ud800", "\udfff", "\U0001f600", "\U0010ffff"]
    )
    roll = rng.random()
    if depth > 4 or roll < 0.45:
        scalar_roll = rng.random()
        if scalar_roll < 0.002:
            return 1.5
        if scalar_roll < 0.004:
            return _MAX_SAFE + 1
        if scalar_roll < 0.006:
            return _Str("s")
        if scalar_roll < 0.3:
            return rng.choice((None, True, False, 0, -_MAX_SAFE, _MAX_SAFE, rng.randint(-99, 99)))
        text = "".join(rng.choice(alphabet[:-4]) for _ in range(rng.randint(0, 6)))
        if scalar_roll > 0.995:
            text += rng.choice(alphabet[-4:-2])
        return text
    size = rng.randint(0, 5)
    if roll < 0.7:
        tree: dict[str, object] = {}
        for _ in range(size):
            key = "".join(rng.choice(alphabet[:-4]) for _ in range(rng.randint(0, 3)))
            if rng.random() < 0.02:
                key += rng.choice(alphabet[-4:])
            tree[key] = _random_tree(rng, depth + 1)
        return tree
    items = [_random_tree(rng, depth + 1) for _ in range(size)]
    return tuple(items) if rng.random() < 0.2 else items


def test_random_trees_match_the_walker() -> None:
    rng = random.Random(20261121)
    for _ in range(6_000):
        _assert_equivalent(_random_tree(rng, 0))


def test_strict_parse_round_trip_matches_the_walker() -> None:
    rng = random.Random(7)
    for _ in range(1_000):
        tree = _random_tree(rng, 0)
        with _walker_only():
            try:
                raw = canonical_encode(cast(JsonValue, tree))
            except ProtocolValueError:
                continue
            reference = canonical_encode(strict_json_parse(raw))
        assert canonical_encode(strict_json_parse(raw)) == reference == raw


def test_plain_document_is_encoded_without_the_walker(monkeypatch: pytest.MonkeyPatch) -> None:
    """Performance property: a plain document never reaches the per-node walker."""

    document: JsonValue = {"b": [1, "two", {"c": None, "d": True}], "a": ("x", -3), "é": {}}
    expected = b'{"a":["x",-3],"b":[1,"two",{"c":null,"d":true}],"\xc3\xa9":{}}'
    calls: list[str] = []

    def _forbidden(value: str) -> str:
        calls.append(value)
        raise AssertionError("walker string encoder reached")

    monkeypatch.setattr(canonical, "_encode_string", _forbidden)
    monkeypatch.setattr(canonical, "_validate_string", _forbidden)
    assert canonical_encode(document) == expected
    ensure_canonical_value(document)
    assert calls == []


def test_validation_of_a_plain_document_builds_no_text(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []
    original = canonical._canonical_text  # pyright: ignore[reportPrivateUsage]

    def _counting(value: object, *, depth: int = 0, failure: object = None) -> str:
        calls.append(value)
        return original(cast(JsonValue, value), depth=depth, failure=cast(Any, failure))

    monkeypatch.setattr(canonical, "_canonical_text", _counting)
    ensure_canonical_value({"a": [1, {"b": "c"}]})
    strict_json_parse(b'{"a":[1,{"b":"c"}]}')
    assert calls == []
    rejected = cast(JsonValue, {"a": [1.5]})
    with pytest.raises(ProtocolValueError, match="float_forbidden"):
        ensure_canonical_value(rejected)
    assert calls[0] is rejected


@pytest.mark.parametrize("operation", ["encode", "ensure"])
@pytest.mark.parametrize("failing", ["astral_key", "float", "fragment"])
def test_a_failed_check_never_rescans_a_subtree(
    monkeypatch: pytest.MonkeyPatch, operation: str, failing: str
) -> None:
    """Performance property: a value that fails the check deep down is still checked once.

    Every ancestor of the failing node used to re-check its whole subtree, so the fallback cost
    grew with depth times size. Each container must now reach the check at most once.
    """

    leaf: dict[str, object] = {"big": [[index, f"row{index}"] for index in range(50)]}
    if failing == "astral_key":
        leaf["\U0001f600"] = [["after", index] for index in range(5)]
    elif failing == "float":
        leaf["z"] = [0.5]
    else:
        leaf["z"] = canonical_fragment({"f": 1})
    value: object = leaf
    for level in range(30):
        value = {"a": [[level], [level, "x"]], "k": value, "z": {"tail": [level]}}

    def _run() -> object:
        if operation == "encode":
            return _outcome(lambda: canonical_encode(cast(JsonValue, value)))
        return _outcome(lambda: _ensure_at(0)(value))

    with _walker_only():
        expected = _run()
    visits: list[int] = []
    original = canonical._plain_failure  # pyright: ignore[reportPrivateUsage]

    def _counting(item: object, depth: int) -> object:
        visits.append(id(item))
        return original(item, depth)

    monkeypatch.setattr(canonical, "_plain_failure", _counting)
    assert _run() == expected
    repeated = {node: count for node, count in Counter(visits).items() if count > 1}
    assert repeated == {}
    assert len(visits) > 30


class _Hook(Mapping[str, object]):
    """A mapping whose iteration runs *effect*, as any Mapping's own code may."""

    def __init__(self, effect: Callable[[], object]) -> None:
        self._effect = effect

    def __getitem__(self, key: str) -> object:
        return 1

    def __iter__(self) -> Iterator[str]:
        self._effect()
        return iter(["e"])

    def __len__(self) -> int:
        return 1


def _appending(target: list[object], item: object) -> _Hook:
    return _Hook(lambda: target.append(item))


def _victim_after_hook() -> object:
    # The check accepts "b" before failing on "a"; "a" is emitted first and changes "b".
    victim: list[object] = []
    return {"b": victim, "a": _appending(victim, 1.5)}


def _nested_victim_after_hook() -> object:
    # The check fails inside "b" (at the proxy) after accepting its "x"; "a" then changes "x".
    victim: list[object] = []
    empty: dict[str, object] = {}
    return {"b": {"x": victim, "y": MappingProxyType(empty)}, "a": _appending(victim, 1.5)}


def _victim_before_hook() -> object:
    # "a" is emitted before the hook runs, so the change must not show.
    victim: list[object] = []
    return {"a": victim, "b": _appending(victim, 1.5)}


def _list_victim_before_hook() -> object:
    victim: list[object] = []
    return [victim, _appending(victim, 1.5), victim]


def _hook_extends_its_list() -> object:
    parent: list[object] = [1]
    parent.append(_appending(parent, 2**60))
    return parent


def _hook_rewrites_accepted_scalar_container() -> object:
    victim: dict[str, object] = {"x": 1}
    return {"c": victim, "a": _Hook(lambda: victim.update(x="\x00")), "b": [1]}


def _hook_makes_victim_valid() -> object:
    victim: list[object] = [1.5]
    return {"z": victim, "a": _Hook(victim.clear)}


def _hook_deep_inside_list() -> object:
    victim: dict[str, object] = {"k": [1, 2]}
    return {"m": victim, "a": [[0, _Hook(lambda: victim.update(k=[2**60]))]]}


_MUTATING: tuple[Callable[[], object], ...] = (
    _victim_after_hook,
    _nested_victim_after_hook,
    _victim_before_hook,
    _list_victim_before_hook,
    _hook_extends_its_list,
    _hook_rewrites_accepted_scalar_container,
    _hook_makes_victim_valid,
    _hook_deep_inside_list,
)


@pytest.mark.parametrize("build", _MUTATING, ids=[build.__name__ for build in _MUTATING])
def test_a_member_is_checked_when_it_is_emitted(build: Callable[[], object]) -> None:
    """A Mapping's own code can change a member the failed check already accepted.

    The walker checks every node as it emits it, so the change counts exactly when the member
    is emitted after that code ran; a fresh value per run keeps each run independent.
    """

    fast = [_outcome(lambda op=op: op(build())) for op in _OPERATIONS]
    main = [_outcome(lambda op=op: op(build())) for op in _MAIN_OPERATIONS]
    assert fast == main


def test_the_reported_mutation_is_rejected() -> None:
    with pytest.raises(ProtocolValueError, match="float_forbidden"):
        canonical_encode(cast(JsonValue, _victim_after_hook()))
    with pytest.raises(ProtocolValueError, match="float_forbidden"):
        ensure_canonical_value(cast(JsonValue, _victim_after_hook()))


@pytest.mark.parametrize("shape", ["list_end", "list_start", "dict_end", "dict_first_key"])
def test_wide_members_beside_one_offender_are_encoded_together(
    monkeypatch: pytest.MonkeyPatch, shape: str
) -> None:
    """Performance property: plain members around one non-plain member skip the walker.

    They are encoded by a fixed number of C encoder calls, not one walker step each.
    """

    offender = MappingProxyType({"p": 1})
    if shape == "list_end":
        value: object = [f"s{index}" for index in range(500)] + [offender]
    elif shape == "list_start":
        value = [offender] + [f"s{index}" for index in range(500)]
    elif shape == "dict_end":
        value = {**{f"k{index:04d}": [index] for index in range(500)}, "zz": offender}
    else:
        value = {"zz": offender, **{f"k{index:04d}": [index] for index in range(500)}}
    expected = _main_text(value).encode("utf-8")
    strings: list[str] = []
    encodes: list[object] = []
    original_string = canonical._encode_string  # pyright: ignore[reportPrivateUsage]
    original_text = canonical._PLAIN_JSON_TEXT  # pyright: ignore[reportPrivateUsage]

    def _string(text: str) -> str:
        strings.append(text)
        return original_string(text)

    def _text(item: object) -> str:
        encodes.append(item)
        return original_text(item)

    monkeypatch.setattr(canonical, "_encode_string", _string)
    monkeypatch.setattr(canonical, "_PLAIN_JSON_TEXT", _text)
    assert canonical_encode(cast(JsonValue, value)) == expected
    # Only the offender's own key, and its member "p", reach the walker's string encoder.
    assert len(strings) <= 2
    assert len(encodes) <= 3
