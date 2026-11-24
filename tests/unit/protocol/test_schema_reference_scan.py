"""The lazy catalog walks each schema document once for its references (#1083 follow-up).

``_LazyCatalog`` used to walk every document it loads three times: ``_uses_dynamic_reference``
and ``_walk_refs`` in ``_closure_of``, then ``_walk_refs`` again in
``_validate_document_references``. ``_scan_refs`` does both closure walks in one, and the refs it
collects are handed to reference validation. These tests hold the one walk to the three separate
walks it replaces:

* over every packaged schema and seeded synthetic documents, ``_scan_refs`` reports exactly the
  refs, the dynamic-reference verdict and the non-string ``$ref`` refusal of the separate walks;
* a lazy load gives the same documents, verdicts and refusals, in the same precedence (dynamic
  reference first, then a non-string ``$ref``, then unresolved references in walk order), as the
  previous ``_closure_of`` with ``_walk_refs`` in reference validation;
* a lazy load walks each loaded document exactly once and never calls the separate walks.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import random
from urllib.parse import urldefrag

import pytest

from finishup.protocol import schemas
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.errors import ProtocolValueError

_FULL_STATE = schemas._load_catalog_state()
_DIALECT = "https://json-schema.org/draft/2020-12/schema"
_BASE = "https://finishup.test/schemas/"
_SEEDS = range(300)

type _Scan = tuple[str, object]
type _Step = tuple[object, ...]
type _Outcome = tuple[tuple[_Step, ...], tuple[str, ...], tuple[str, ...]]


def _separate_walks(document: JsonValue) -> _Scan:
    """What the previous ``_closure_of`` concluded from one document with the separate walks."""

    if schemas._uses_dynamic_reference(document):
        return ("dynamic", None)
    try:
        refs = list(schemas._walk_refs(document))
    except ProtocolValueError as error:
        return ("refused", error.reason_code)
    return ("refs", refs)


def _one_walk(document: JsonValue) -> _Scan:
    refs: list[str] = []
    flags = schemas._scan_refs(document, refs)
    if flags & schemas._DYNAMIC_REFERENCE:
        return ("dynamic", None)
    if flags & schemas._NON_STRING_REFERENCE:
        return ("refused", "schema_reference_unresolved")
    return ("refs", refs)


def _previous_closure_of(
    catalog: schemas._LazyCatalog, schema_id: str
) -> tuple[dict[str, dict[str, JsonValue]], dict[str, None]]:
    """``_LazyCatalog._closure_of`` before the one walk; ``None`` refs make validation walk."""

    added: dict[str, dict[str, JsonValue]] = {}
    pending = [schema_id]
    while pending:
        document_id = pending.pop()
        if document_id in catalog._plain or document_id in added:
            continue
        data = catalog.index.member_bytes.get(document_id)
        if data is None:
            raise schemas._LazyCatalogCannotDecide
        plain = schemas._plain_schema(data, digest_verified=True)
        if plain.get("$id") != document_id:
            schemas._protocol_error("schema_id_mismatch")
        if schemas._uses_dynamic_reference(plain):
            raise schemas._LazyCatalogCannotDecide
        added[document_id] = plain
        for ref in schemas._walk_refs(plain):
            if not ref.startswith("#"):
                base, _ = urldefrag(ref)
                if base in catalog.index.known_ids:
                    pending.append(base)
    return added, dict.fromkeys(added)


def _index(member_bytes: dict[str, bytes]) -> schemas._ManifestIndex:
    return schemas._ManifestIndex(
        member_bytes=member_bytes,
        known_ids=frozenset(member_bytes),
        id_by_identity={},
        request_result_versions={},
    )


def _load(
    monkeypatch: pytest.MonkeyPatch,
    index: schemas._ManifestIndex,
    schema_ids: list[str],
    *,
    previous: bool,
) -> _Outcome:
    """Load *schema_ids* in order into one fresh lazy catalog; everything a caller observes."""

    with monkeypatch.context() as patch:
        if previous:
            patch.setattr(schemas._LazyCatalog, "_closure_of", _previous_closure_of)
        catalog = schemas._LazyCatalog(index)
        steps: list[_Step] = []
        for schema_id in schema_ids:
            try:
                checker = catalog._checker_for(schema_id)
            except schemas._LazyCatalogCannotDecide:
                steps.append(("cannot-decide", schema_id))
            except ProtocolValueError as error:
                steps.append(("refused", schema_id, error.reason_code))
            else:
                steps.append(("loaded", schema_id, tuple(checker.plain_by_id)))
        return (tuple(steps), tuple(catalog._plain), tuple(catalog._stripped))


def _node(rng: random.Random, ids: list[str], depth: int) -> JsonValue:
    """One random subschema: mostly well formed, sometimes each refusal the walks can find."""

    roll = rng.random()
    if depth >= 4 or roll < 0.15:
        return {"type": "string"}
    if roll < 0.55:
        target = rng.choice(ids)
        return {
            "$ref": rng.choice(
                [
                    target,
                    target,
                    f"{target}#/$defs/d",
                    "#/$defs/d",
                    "#/$defs/missing",
                    "https://elsewhere.test/x",
                    f"{target}?q=1",
                    "relative/path",
                    "http://finishup.test/schemas/a",
                ]
            )
        }
    if roll < 0.6:
        return {"$ref": rng.choice([5, None, [], {"$dynamicRef": "#m"}, {"$ref": ids[0]}])}
    if roll < 0.64:
        return {rng.choice(["$dynamicRef", "$recursiveRef"]): "#meta"}
    if roll < 0.7:
        # A property named "$ref" is a non-string ``$ref`` to the walks.
        return {"properties": {"$ref": _node(rng, ids, depth + 1)}}
    if roll < 0.85:
        return {"properties": {"p": _node(rng, ids, depth + 1), "q": _node(rng, ids, depth + 1)}}
    return {"items": [_node(rng, ids, depth + 1) for _ in range(rng.randrange(3))]}


def _synthetic_catalog(seed: int) -> tuple[schemas._ManifestIndex, list[dict[str, JsonValue]]]:
    rng = random.Random(seed)
    ids = [f"{_BASE}{name}" for name in "abcdef"[: rng.randrange(2, 7)]]
    member_bytes: dict[str, bytes] = {}
    documents: list[dict[str, JsonValue]] = []
    for schema_id in ids:
        document: dict[str, JsonValue] = {
            "$schema": _DIALECT,
            "$id": schema_id if rng.random() > 0.03 else f"{schema_id}-mismatch",
            "$defs": {"d": {"type": "string"}},
            "allOf": [_node(rng, ids, 0) for _ in range(rng.randrange(1, 4))],
        }
        documents.append(document)
        member_bytes[schema_id] = canonical_encode(document)
    return _index(member_bytes), documents


def test_one_walk_matches_the_separate_walks_on_every_packaged_schema() -> None:
    assert _FULL_STATE.plain_by_id
    for plain in _FULL_STATE.plain_by_id.values():
        assert _one_walk(plain) == _separate_walks(plain)


_MALFORMED: tuple[JsonValue, ...] = (
    {"$ref": 1, "x": {"$dynamicRef": "#m"}},
    {"x": {"$recursiveRef": "#"}, "$ref": None},
    {"$ref": {"$dynamicRef": "#m"}},
    {"$ref": {"$ref": "https://a.test/x"}},
    {"a": [{"$ref": "#/a"}, {"$ref": []}, {"$ref": "#/b"}]},
    {"properties": {"$ref": {"type": "string"}}},
    {"$defs": {"$dynamicRef": {"$ref": "#/x"}}},
    {"$ref": "#/a", "$dynamicRef": "#/b"},
    {"$ref": "#/a", "items": [{"$ref": "#/b"}, [{"$ref": "#/a"}]], "z": {"$ref": "#/c"}},
    {"$dynamicAnchor": "m", "$ref": "#/a"},
    [{"$ref": "#/a"}, "$ref", {"$ref": "#/b"}],
    "$dynamicRef",
    None,
)


@pytest.mark.parametrize("document", _MALFORMED)
def test_one_walk_matches_the_separate_walks_on_malformed_documents(document: JsonValue) -> None:
    assert _one_walk(document) == _separate_walks(document)


@pytest.mark.parametrize("seed", _SEEDS)
def test_one_walk_matches_the_separate_walks_on_synthetic_documents(seed: int) -> None:
    _index_, documents = _synthetic_catalog(seed)
    for document in documents:
        assert _one_walk(document) == _separate_walks(document)


@pytest.mark.parametrize("seed", _SEEDS)
def test_a_synthetic_lazy_load_decides_exactly_as_before(
    monkeypatch: pytest.MonkeyPatch, seed: int
) -> None:
    index, _documents = _synthetic_catalog(seed)
    ids = sorted(index.known_ids)
    orders = [ids, ids[::-1], *([schema_id] for schema_id in ids)]
    for order in orders:
        assert _load(monkeypatch, index, order, previous=False) == _load(
            monkeypatch, index, order, previous=True
        )


def test_the_synthetic_catalogs_reach_every_outcome(monkeypatch: pytest.MonkeyPatch) -> None:
    """The seeds reach a load, both closure refusals, an id mismatch and a reference refusal."""

    kinds: set[object] = set()
    for seed in _SEEDS:
        index, _documents = _synthetic_catalog(seed)
        steps = _load(monkeypatch, index, sorted(index.known_ids), previous=False)[0]
        for step in steps:
            kinds.add((step[0], step[2]) if step[0] == "refused" else step[0])
    assert kinds >= {
        "loaded",
        "cannot-decide",
        ("refused", "schema_reference_unresolved"),
        ("refused", "schema_id_mismatch"),
    }


def test_the_packaged_lazy_load_decides_exactly_as_before(monkeypatch: pytest.MonkeyPatch) -> None:
    index = schemas._build_manifest_index()
    ids = sorted(index.known_ids, key=str.encode)
    current = _load(monkeypatch, index, ids, previous=False)
    assert current == _load(monkeypatch, index, ids, previous=True)
    assert set(current[1]) == set(ids)


def test_a_lazy_load_walks_each_document_once(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(_value: JsonValue) -> bool:
        raise AssertionError("a lazy load must not walk a document separately")

    roots: dict[int, int] = {}
    scan = schemas._scan_refs

    def counting_scan(value: JsonValue, refs: list[str]) -> int:
        roots[id(value)] = roots.get(id(value), 0) + 1
        return scan(value, refs)

    catalog_ = schemas.load_schema_catalog()
    versions = schemas.request_result_schema_versions(catalog_)
    schema_ids = [
        next(
            document.schema_id
            for document in catalog_.documents
            if document.schema_name == name
            and (name not in versions or document.schema_version == versions[name])
        )
        for name in ("control-hello", "control-request", "control-result")
    ]
    index = schemas._build_manifest_index()
    monkeypatch.setattr(schemas, "_walk_refs", refuse)
    monkeypatch.setattr(schemas, "_uses_dynamic_reference", refuse)
    monkeypatch.setattr(schemas, "_scan_refs", counting_scan)
    catalog = schemas._LazyCatalog(index)
    for schema_id in schema_ids:
        catalog.prepare(schema_id)
        assert schema_id in catalog._plain
    assert len(catalog._plain) > 3
    assert [roots.get(id(plain)) for plain in catalog._plain.values()] == [1] * len(catalog._plain)
