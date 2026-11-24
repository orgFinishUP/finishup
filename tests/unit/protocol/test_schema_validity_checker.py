"""The first-error validity checker decides exactly what the stock validator decides (issue #916).

``validate_schema_instance`` answers most calls from ``_ValidityChecker``: lazy ``anyOf``/``oneOf``
that stop each failing branch at its first error, ``$ref`` resolved once per base URI, and a
bounded memory of (schema, canonical bytes) pairs already found valid. It only changes how much
work a *valid* instance costs; every rejection still goes through the stock ``Draft202012Validator``
for the exact diagnostic. These tests hold the checker to the stock verdict on real projected
results of every workflow method, every status view and the control envelope, plus systematic
mutations of each, and pin the two places where sharing a verdict would be wrong.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest

from builders.projection_workflow import project_case, run_projection_workflow
from builders.start_application import protocol_id
from finishup.ports.control import ControlMethod, ControlResult
from finishup.protocol import schemas
from finishup.protocol.canonical import (
    JsonValue,
    canonical_encode,
    canonical_fragment,
    strict_json_parse,
)
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.models import StatusResult
from finishup.service.control_protocol import encode_control_frame

pytestmark = pytest.mark.anyio

_RESULT_SCHEMA = {
    ControlMethod.START: "start-result",
    ControlMethod.PUBLISH_WORK: "publish-work-result",
    ControlMethod.CHECK: "check-result",
    ControlMethod.RESPOND: "respond-result",
    ControlMethod.STATUS: "status-result",
    ControlMethod.RECEIPT: "receipt-result",
}
_MUTATIONS_PER_DOCUMENT = 24


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _schema_id(name: str) -> str:
    catalog = schemas.load_schema_catalog()
    version = schemas.request_result_schema_versions(catalog).get(name)
    if version is None:
        version = max(
            (
                document.schema_version
                for document in catalog.documents
                if document.schema_name == name
            ),
            key=lambda value: tuple(int(part) for part in value.split(".")),
        )
    return schemas.schema_document_for(name, version).schema_id


def _stock_accepts(schema_id: str, instance: JsonValue) -> bool:
    state = schemas._load_catalog_state()
    validator = schemas.Draft202012Validator(
        state.plain_by_id[schema_id],
        registry=state.registry,
        format_checker=schemas._FORMAT_CHECKER,
    )
    return next(cast(Any, validator).iter_errors(instance), None) is None


def _containers(
    value: JsonValue, path: tuple[str | int, ...] = ()
) -> Iterator[tuple[tuple[str | int, ...], JsonValue]]:
    yield path, value
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _containers(item, (*path, key))
    elif isinstance(value, list):
        for index, item in enumerate(cast(list[JsonValue], value)):
            yield from _containers(item, (*path, index))


def _replaced(document: JsonValue, path: tuple[str | int, ...], value: JsonValue) -> JsonValue:
    copy = strict_json_parse(canonical_encode(document))
    parent: Any = copy
    for step in path[:-1]:
        parent = parent[step]
    if value is _DELETE:
        del parent[path[-1]]
    else:
        parent[path[-1]] = value
    return copy


_DELETE: Any = object()


def _mutations(document: JsonValue) -> list[JsonValue]:
    """Deterministic, bounded mutations spread over the whole document."""

    candidates: list[tuple[tuple[str | int, ...], JsonValue]] = []
    for path, value in _containers(document):
        if not path:
            continue
        if isinstance(value, dict):
            candidates.append((path, {**value, "zz_unexpected": 1}))
            candidates.append((path, _DELETE))
        elif isinstance(value, list):
            items = cast(list[JsonValue], value)
            candidates.append((path, [*items, items[0]] if items else ["unexpected"]))
            candidates.append((path, []))
        elif isinstance(value, bool) or value is None:
            candidates.append((path, "not-a-boolean-or-null"))
        elif isinstance(value, int):
            candidates.append((path, str(value)))
            candidates.append((path, -1))
        elif isinstance(value, str):
            candidates.append((path, 7))
            candidates.append((path, ""))
            candidates.append((path, value + "é" * 300))
    step = max(1, len(candidates) // _MUTATIONS_PER_DOCUMENT)
    return [_replaced(document, path, value) for path, value in candidates[::step]]


async def _documents() -> list[tuple[str, str, JsonValue]]:
    workflow = await run_projection_workflow()
    documents: list[tuple[str, str, JsonValue]] = []
    envelope_id = _schema_id("control-result")
    for index, case in enumerate(workflow.cases):
        wire = cast(JsonValue, dict(await project_case(workflow.app, case, 5000 + index * 2)))
        documents.append((case.label, _schema_id(_RESULT_SCHEMA[case.method]), wire))
        if case.method is ControlMethod.STATUS:
            frame = encode_control_frame(
                ControlResult(
                    protocol_version="1.0",
                    rpc_id=protocol_id("rpc_", 6000 + index),
                    service_instance_id=protocol_id("svc_", 6100 + index),
                    service_generation="1",
                    method=ControlMethod.STATUS,
                    outcome="ok",
                    body=StatusResult.model_validate(wire),
                )
            )
            documents.append((f"{case.label}/envelope", envelope_id, strict_json_parse(frame[4:])))
    return documents


async def test_checker_agrees_with_stock_validator_on_results_and_mutations() -> None:
    checker = schemas._ValidityChecker.build(schemas._load_catalog_state())
    assert checker is not None
    compared = 0
    rejected = 0
    for label, schema_id, document in await _documents():
        assert _stock_accepts(schema_id, document), label
        for candidate in (document, *_mutations(document)):
            stock = _stock_accepts(schema_id, candidate)
            digest = hashlib.sha256(canonical_encode(candidate)).digest()
            # Twice: the second answer may come from the verdict memory and must not differ.
            assert checker.is_valid(schema_id, candidate, digest) is stock, label
            assert checker.is_valid(schema_id, candidate, digest) is stock, label
            assert checker.is_valid(schema_id, candidate, None) is stock, label
            compared += 1
            rejected += not stock
    # The mutations must actually exercise rejection, not only the happy path.
    assert compared > 400 and rejected > compared // 3


_COVERAGE: dict[str, JsonValue] = {
    "publication_channels": ["cooperative_mcp"],
    "authorship_assurance": "self_asserted",
    "artifact_observation": "published_only",
    "evidence_immutability": "content_digest",
    "ledger_freshness": "current",
    "check_types": ["none"],
    "known_gaps": [],
}


def _diagnostic(name: str, instance: JsonValue) -> tuple[object, ...]:
    with pytest.raises(schemas.SchemaInstanceInvalid) as invalid:
        schemas.validate_schema_instance(name, "1.0.0", instance)
    error = invalid.value
    return (
        error.reason_code,
        error.absolute_path,
        error.location_reasons,
        error.reason,
        error.family,
        error.unknown_count,
        error.misplaced_field,
        error.condition_field,
        error.condition_value,
    )


@pytest.mark.parametrize(
    "instance",
    [
        {**_COVERAGE, "extra": True},
        {key: value for key, value in _COVERAGE.items() if key != "known_gaps"},
        {**_COVERAGE, "publication_channels": []},
        {**_COVERAGE, "check_types": ["none", "none"]},
    ],
)
def test_rejection_keeps_the_stock_diagnostic(
    monkeypatch: pytest.MonkeyPatch, instance: JsonValue
) -> None:
    """A rejected instance is reported exactly as the stock validator alone reports it."""

    schemas.validate_schema_instance("coverage", "1.0.0", _COVERAGE)
    with_checker = _diagnostic("coverage", instance)
    monkeypatch.setattr(schemas, "_validity_checker", lambda: None)
    assert _diagnostic("coverage", instance) == with_checker


def test_a_spliced_fragment_never_shares_the_verdict_of_its_value() -> None:
    """A fragment has its value's canonical bytes but is not that value to the validator."""

    frontier: dict[str, JsonValue] = {"sequence": "3", "head_digest": "sha256:" + "a" * 64}
    schemas.validate_schema_instance("frontier", "1.0.0", frontier)
    spliced = cast(JsonValue, canonical_fragment(frontier))
    assert canonical_encode(spliced) == canonical_encode(frontier)
    with pytest.raises(ProtocolValueError):
        schemas.validate_schema_instance("frontier", "1.0.0", spliced)


def test_verdict_memory_is_bounded_and_never_holds_rejections() -> None:
    verdicts = schemas._ValidInstanceVerdicts(2)
    for index in range(3):
        verdicts.remember(("schema", bytes([index])))
    assert not verdicts.seen(("schema", bytes([0])))
    assert verdicts.seen(("schema", bytes([1]))) and verdicts.seen(("schema", bytes([2])))
    checker = schemas._ValidityChecker.build(schemas._load_catalog_state())
    assert checker is not None
    schema_id = _schema_id("frontier")
    invalid: JsonValue = {"sequence": "3"}
    digest = hashlib.sha256(canonical_encode(invalid)).digest()
    assert checker.is_valid(schema_id, invalid, digest) is False
    assert not checker.verdicts.seen((schema_id, digest))


async def test_a_checker_that_cannot_read_resolver_state_falls_back_to_stock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A jsonschema/referencing upgrade that renames the private resolver state the checker reads
    (``_resolver``, ``_base_uri``) costs speed only: every verdict still comes from the stock
    validator."""

    def unreadable(*_args: object) -> object:
        def keyword(*_keyword_args: object) -> Iterator[ProtocolValueError]:
            raise AttributeError("_base_uri")
            yield ProtocolValueError("unreachable")

        return keyword

    monkeypatch.setattr(schemas, "_ref_resolved_once", unreadable)
    monkeypatch.setattr(schemas, "_validity_checker_slot", [])
    by_id = {document.schema_id: document for document in schemas.load_schema_catalog().documents}
    checked = 0
    for label, schema_id, document in await _documents():
        checker = schemas._validity_checker()
        assert checker is not None
        # The broken ``$ref`` keyword is reached, so the checker cannot tell ...
        assert checker.is_valid(schema_id, document, None) is False, label
        # ... and the stock validator still accepts the valid result and rejects its mutation.
        identity = by_id[schema_id]
        schemas.validate_schema_instance(identity.schema_name, identity.schema_version, document)
        mutated = next(m for m in _mutations(document) if not _stock_accepts(schema_id, m))
        with pytest.raises(schemas.SchemaInstanceInvalid):
            schemas.validate_schema_instance(identity.schema_name, identity.schema_version, mutated)
        checked += 1
    assert checked > 5


async def test_the_pinned_dependencies_take_the_fast_path_for_valid_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Guard the ~8x speedup against a silent ``jsonschema``/``referencing`` regression.

    The checker reads private resolver state (``_resolver``, ``_base_uri``, ``resolved.resolver``)
    and falls back to the stock validator whenever it cannot, which keeps every verdict correct and
    would therefore pass every correctness test while losing the speedup. With the locked
    dependency versions, every valid workflow result, status page and control envelope must be
    decided by the checker alone: the checker exists, its ``$ref`` keyword really runs, and
    ``validate_schema_instance`` never builds a stock validator. An upgrade that breaks the private
    state fails here and must be adapted, or the fallback accepted on purpose.
    """

    from importlib.metadata import version

    installed = f"jsonschema {version('jsonschema')}, referencing {version('referencing')}"
    documents = await _documents()
    monkeypatch.setattr(schemas, "_validity_checker_slot", [])
    checker = schemas._validity_checker()
    assert checker is not None, f"no validity checker for the packaged catalog with {installed}"

    references = 0
    ref_keyword = checker.remembering_class.VALIDATORS["$ref"]

    def counted_ref(*args: object) -> Iterator[object]:
        nonlocal references
        references += 1
        return ref_keyword(*args)

    for validator_class in (checker.remembering_class, checker.forgetful_class):
        monkeypatch.setitem(validator_class.VALIDATORS, "$ref", counted_ref)

    stock_constructions = 0
    stock = schemas.Draft202012Validator

    def counted_stock(*args: object, **kwargs: object) -> object:
        nonlocal stock_constructions
        stock_constructions += 1
        return stock(*args, **kwargs)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(schemas, "Draft202012Validator", counted_stock)
    by_id = {document.schema_id: document for document in schemas.load_schema_catalog().documents}
    for label, schema_id, document in documents:
        identity = by_id[schema_id]
        assert checker.is_valid(schema_id, document, None) is True, (label, installed)
        schemas.validate_schema_instance(identity.schema_name, identity.schema_version, document)
    assert schemas._validity_checker() is checker
    assert references > len(documents), installed
    assert stock_constructions == 0, installed


_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures"


def _control_envelope_ids() -> list[str]:
    return sorted(
        document.schema_id
        for document in schemas.load_schema_catalog().documents
        if document.schema_name in {"control-request", "control-result"}
    )


def _pinned_values(schema_ids: list[str]) -> dict[str, list[str]]:
    """Every string ``const`` a top-level union branch of these schemas pins, by property."""

    state = schemas._load_catalog_state()
    values: dict[str, set[str]] = {}
    for schema_id in schema_ids:
        plain = state.plain_by_id[schema_id]
        for keyword in ("oneOf", "anyOf"):
            branches = plain.get(keyword)
            if isinstance(branches, list):
                for pins in schemas._branch_pins(branches):
                    for key, const in pins:
                        values.setdefault(key, set()).add(const)
    return {key: sorted(found) for key, found in values.items()}


def _fixture_envelopes() -> list[dict[str, JsonValue]]:
    """Every fixture object shaped like a control envelope (it carries an ``rpc_id``)."""

    found: list[dict[str, JsonValue]] = []

    def collect(value: JsonValue) -> None:
        if isinstance(value, dict):
            if "rpc_id" in value:
                found.append(value)
            for item in value.values():
                collect(item)
        elif isinstance(value, list):
            for item in cast(list[JsonValue], value):
                collect(item)

    for path in sorted(_FIXTURES.rglob("*.json")):
        collect(cast(JsonValue, json.loads(path.read_bytes())))
    return found


def _unscreened(monkeypatch: pytest.MonkeyPatch) -> None:
    """Turn the branch screen off: every branch is entered, exactly as before it existed."""

    def nothing_excluded(*_args: object) -> None:
        return None

    monkeypatch.setattr(schemas._BranchScreen, "excluded", nothing_excluded)


async def test_branch_screen_keeps_every_verdict_of_the_unscreened_checker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Skipping branches whose string ``const`` the instance contradicts changes no verdict.

    Differential against the same checker with the screen off, and against the stock validator:
    real projected results and envelopes plus every fixture envelope against every control
    envelope version, and copies of each with every pinned ``method``, ``kind`` and ``outcome``
    swapped in against the current request and result envelopes.
    """

    all_versions = _control_envelope_ids()
    current = [_schema_id("control-request"), _schema_id("control-result")]
    pinned = _pinned_values(current)
    originals: list[JsonValue] = [document for _label, _schema_id, document in await _documents()]
    originals += _fixture_envelopes()
    swapped: list[JsonValue] = []
    for original in originals:
        if not isinstance(original, dict):
            continue
        for key in ("method", "kind", "outcome"):
            if isinstance(original.get(key), str):
                for value in (*pinned.get(key, ()), "not-a-pinned-value"):
                    if value != original[key]:
                        swapped.append({**original, key: value})
    pairs = [(schema_id, original) for schema_id in all_versions for original in originals]
    pairs += [(schema_id, candidate) for schema_id in current for candidate in swapped]
    state = schemas._load_catalog_state()
    screened = schemas._ValidityChecker.build(state)
    assert screened is not None
    with monkeypatch.context() as patch:
        _unscreened(patch)
        unscreened = schemas._ValidityChecker.build(state)
        assert unscreened is not None
        expected = [
            unscreened.is_valid(schema_id, candidate, None) for schema_id, candidate in pairs
        ]
    actual = [screened.is_valid(schema_id, candidate, None) for schema_id, candidate in pairs]
    assert actual == expected
    # The corpus exercises both verdicts, and the screened accepts agree with the stock validator.
    accepted = [pair for pair, verdict in zip(pairs, actual, strict=True) if verdict]
    assert len(accepted) > 20 and len(pairs) - len(accepted) > 1_000
    assert all(_stock_accepts(schema_id, candidate) for schema_id, candidate in accepted)


async def test_branch_screen_enters_only_the_branches_the_discriminators_select(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid control envelope enters only the union branches its ``method``/``outcome`` pick.

    Counted on the envelope object itself through the branch-level ``additionalProperties``
    keyword every envelope branch carries: without the screen each of the dozens of branches is
    entered and builds an error before failing.
    """

    state = schemas._load_catalog_state()
    envelope_id = _schema_id("control-result")
    envelopes = [
        document for _label, schema_id, document in await _documents() if schema_id == envelope_id
    ]
    assert envelopes
    branches = cast(list[object], state.plain_by_id[envelope_id]["oneOf"])

    def entered(checker: schemas._ValidityChecker, envelope: JsonValue) -> int:
        stock_keyword = checker.forgetful_class.VALIDATORS["additionalProperties"]
        count = 0

        def counted(validator: object, value: object, instance: object, schema: object) -> object:
            nonlocal count
            count += instance is envelope
            return stock_keyword(validator, value, instance, schema)

        with monkeypatch.context() as patch:
            patch.setitem(checker.forgetful_class.VALIDATORS, "additionalProperties", counted)
            assert checker.is_valid(envelope_id, envelope, None) is True
        return count

    screened = schemas._ValidityChecker.build(state)
    assert screened is not None
    with monkeypatch.context() as patch:
        _unscreened(patch)
        unscreened = schemas._ValidityChecker.build(state)
        assert unscreened is not None
        unscreened_entries = [entered(unscreened, envelope) for envelope in envelopes]
    for envelope, before in zip(envelopes, unscreened_entries, strict=True):
        assert isinstance(envelope, dict)
        # Every branch the screen cannot rule out: the selected one plus any unpinned branch.
        open_branches = sum(
            not any(
                isinstance(envelope.get(key), str) and envelope[key] != const for key, const in pins
            )
            for pins in schemas._branch_pins(branches)
        )
        assert entered(screened, envelope) == open_branches
        assert open_branches < 5 < len(branches) // 2 < before


async def test_reused_validators_decide_exactly_what_fresh_ones_do() -> None:
    """A checker reuses one validator per (schema, memory mode), across calls and threads.

    Differential against building a fresh validator for every call (the previous behavior), over
    real results, envelopes and their mutations, with the same calls also issued concurrently.
    """

    from concurrent.futures import ThreadPoolExecutor

    state = schemas._load_catalog_state()
    reused = schemas._ValidityChecker.build(state)
    fresh = schemas._ValidityChecker.build(state)
    assert reused is not None and fresh is not None
    calls: list[tuple[str, JsonValue]] = []
    for _label, schema_id, document in await _documents():
        calls += [(schema_id, candidate) for candidate in (document, *_mutations(document))]

    def fresh_verdict(schema_id: str, candidate: JsonValue) -> bool:
        fresh.validators.clear()
        return fresh.is_valid(schema_id, candidate, None)

    expected = [fresh_verdict(schema_id, candidate) for schema_id, candidate in calls]
    assert [reused.is_valid(schema_id, candidate, None) for schema_id, candidate in calls] == (
        expected
    )

    def reused_verdict(call: tuple[str, JsonValue]) -> bool:
        return reused.is_valid(call[0], call[1], None)

    with ThreadPoolExecutor(max_workers=4) as pool:
        concurrent = list(pool.map(reused_verdict, calls))
    assert concurrent == expected
    assert True in expected and False in expected


def test_a_checker_builds_one_validator_per_schema_and_memory_mode() -> None:
    """Repeated validations reuse the validator instead of constructing one per call."""

    from dataclasses import replace

    checker = schemas._ValidityChecker.build(schemas._load_catalog_state())
    assert checker is not None
    built: list[tuple[str, bool]] = []

    def counted(validator_class: Any, remembers: bool) -> Any:
        def construct(schema: Any, **kwargs: Any) -> Any:
            built.append((cast(str, schema["$id"]), remembers))
            return validator_class(schema, **kwargs)

        return construct

    counting = replace(
        checker,
        remembering_class=counted(checker.remembering_class, True),
        forgetful_class=counted(checker.forgetful_class, False),
        validators={},
    )
    schema_id = _schema_id("frontier")
    for sequence in range(1, 6):
        frontier: JsonValue = {"sequence": str(sequence), "head_digest": "sha256:" + "a" * 64}
        digest = hashlib.sha256(canonical_encode(frontier)).digest()
        assert counting.is_valid(schema_id, frontier, None) is True
        assert counting.is_valid(schema_id, frontier, digest) is True
        assert counting.is_valid(schema_id, {"sequence": str(sequence)}, None) is False
    assert built == [(schema_id, False), (schema_id, True)]
