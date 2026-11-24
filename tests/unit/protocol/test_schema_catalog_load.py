"""Full schema catalog load: the frozen documents and reference checks it produced before.

``_freeze_json`` sorts ASCII keys with plain ``sorted`` (code-point order equals UTF-16BE order
there) and ``_validate_document_references`` admits and resolves each distinct reference of a
document once. Both only drop repeated work; these tests hold the frozen output, key order
included, and the reference verdicts to what the previous code produced.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import cast
from urllib.parse import SplitResult

import pytest

from finishup.protocol import schemas
from finishup.protocol.canonical import JsonValue, strict_json_parse
from finishup.protocol.errors import ProtocolValueError


def _reference_freeze(value: JsonValue) -> JsonValue:
    """``_freeze_json`` as it was: every key sorted by its UTF-16BE bytes."""

    if type(value) is dict:
        source = cast(dict[str, JsonValue], value)
        return MappingProxyType(
            {
                key: _reference_freeze(source[key])
                for key in sorted(source, key=lambda item: item.encode("utf-16-be"))
            }
        )
    if type(value) is list:
        return tuple(_reference_freeze(item) for item in cast(list[JsonValue], value))
    return value


def _assert_identical(actual: object, expected: object) -> None:
    """Same types, same values and the same mapping key order, all the way down."""

    assert type(actual) is type(expected)
    if isinstance(expected, Mapping):
        actual_mapping = cast(Mapping[str, object], actual)
        expected_mapping = cast(Mapping[str, object], expected)
        assert list(actual_mapping) == list(expected_mapping)
        for key in expected_mapping:
            _assert_identical(actual_mapping[key], expected_mapping[key])
    elif isinstance(expected, tuple):
        actual_items = cast(tuple[object, ...], actual)
        expected_items = cast(tuple[object, ...], expected)
        assert len(actual_items) == len(expected_items)
        for actual_item, expected_item in zip(actual_items, expected_items, strict=True):
            _assert_identical(actual_item, expected_item)
    else:
        assert actual == expected


def test_frozen_catalog_documents_match_the_utf16_key_order_exactly() -> None:
    for document in schemas.load_schema_catalog().documents:
        parsed = strict_json_parse(document.schema_bytes, validate=False)
        _assert_identical(schemas._freeze_json(parsed), _reference_freeze(parsed))
        _assert_identical(document.json_schema, _reference_freeze(parsed))


def test_non_ascii_keys_keep_utf16_order_where_it_differs_from_code_points() -> None:
    # U+1F600 is a surrogate pair (0xD83D...) in UTF-16, so it sorts before U+FFFF there even
    # though its code point is larger; ASCII siblings in the same object follow the same rule.
    value: JsonValue = {
        "￿": 1,
        "\U0001f600": 2,
        "b": {"z": [{"é": 1, "a": 2, "B": 3}], "a": None},
        "a": [{"y": True, "x": "s"}],
        "A": 0,
    }
    frozen = schemas._freeze_json(value)
    _assert_identical(frozen, _reference_freeze(value))
    assert list(cast(Mapping[str, JsonValue], frozen)) == ["A", "a", "b", "\U0001f600", "￿"]


def _refs_by_document() -> dict[str, list[str]]:
    state = schemas._load_catalog_state()
    return {
        schema_id: list(schemas._walk_refs(plain)) for schema_id, plain in state.plain_by_id.items()
    }


def test_reference_check_admits_each_distinct_reference_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = schemas._load_catalog_state()
    refs = _refs_by_document()
    real_urlsplit = schemas.urlsplit
    admitted: list[str] = []

    def counted(url: str) -> SplitResult:
        admitted.append(url)
        return real_urlsplit(url)

    monkeypatch.setattr(schemas, "urlsplit", counted)
    schemas._validate_references(state.plain_by_id, state.registry)
    distinct = sum(len(set(each)) for each in refs.values())
    assert len(admitted) == distinct
    # The catalog really repeats references, so the bound is a real saving.
    assert distinct < sum(len(each) for each in refs.values())
    # Admitted in each document's first-occurrence order.
    expected = [
        ref for schema_id in sorted(refs, key=str.encode) for ref in dict.fromkeys(refs[schema_id])
    ]
    assert admitted == expected


@pytest.mark.parametrize(
    "extra",
    [
        ["good", "good", "missing"],
        ["good", "missing", "good"],
        ["missing", "missing"],
        ["good", "good", "query"],
        ["good", "good", "relative"],
    ],
)
def test_a_repeated_good_reference_never_hides_a_bad_one(extra: list[str]) -> None:
    state = schemas._load_catalog_state()
    schema_id = next(
        schema_id
        for schema_id in sorted(state.plain_by_id)
        if schema_id.endswith("/common/actor-assertion-1.0.0.schema.json")
    )
    target = next(each for each in sorted(state.plain_by_id) if each != schema_id)
    refs = {
        "good": target,
        "missing": "https://schemas.yoetz.dev/0.1/common/missing-1.0.0.schema.json",
        "query": target + "?x=1",
        "relative": "other.schema.json",
    }
    document: dict[str, JsonValue] = {
        **state.plain_by_id[schema_id],
        "x-refs": [cast(JsonValue, {"$ref": refs[name]}) for name in extra],
    }
    with pytest.raises(ProtocolValueError) as refused:
        schemas._validate_document_references(
            schema_id, document, state.registry, frozenset(state.plain_by_id)
        )
    assert refused.value.reason_code == "schema_reference_unresolved"


def test_repeated_good_references_still_pass() -> None:
    state = schemas._load_catalog_state()
    schema_id = sorted(state.plain_by_id)[0]
    target = sorted(state.plain_by_id)[1]
    document: dict[str, JsonValue] = {
        **state.plain_by_id[schema_id],
        "x-refs": [cast(JsonValue, {"$ref": target}) for _ in range(3)],
    }
    schemas._validate_document_references(
        schema_id, document, state.registry, frozenset(state.plain_by_id)
    )
