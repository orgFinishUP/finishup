"""The reviewer cache report sums exchange records exactly, in any order (#1172, ADR-006)."""

from __future__ import annotations

import importlib.util
from collections.abc import Iterator, Mapping
from pathlib import Path
from types import ModuleType
from typing import cast

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from finishup.cli.reviewer_cache import reviewer_cache_text
from finishup.domain.reviewer_cache import (
    ExchangeCacheUsage,
    ReviewerCacheState,
    exchange_cache_counts,
)
from finishup.domain.reviewer_cache_report import reviewer_cache_report
from finishup.observability.diagnostics import _public_view  # pyright: ignore[reportPrivateUsage]
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.reviewer_cache_report_contract import ReviewerCacheReportContract
from finishup.protocol.schemas import validate_schema_instance
from fixture_loader import load_fixture_bytes, load_fixture_json

_FIXTURE = "service/reviewer-cache-report-1.0.0.case.json"
_ONE = "req_72000000-0000-4000-8000-000000000001"
_TWO = "req_72000000-0000-4000-8000-000000000002"
_FIXTURE_RECORDS = 18

type _Report = Mapping[str, JsonValue]


def _record(
    index: int,
    *,
    request: str = _ONE,
    minute: int = 0,
    **fields: object,
) -> dict[str, object]:
    return {
        "timestamp": f"2026-11-21T10:{minute:02d}:00.000Z",
        "correlation_id": f"err_72000000-0000-4000-8000-{index:012d}",
        "component": "openai_responses",
        "operation": "exchange_cache",
        "reason": "completed",
        "request_id": request,
        "reviewer_exchange_index": index,
        **fields,
    }


def _counted(
    index: int,
    input_tokens: int,
    cached: int | None,
    *,
    prefix: int | None,
    label: str | None,
    requests: int = 1,
    first_cached: int | None = None,
    request: str = _ONE,
    minute: int = 0,
    **fields: object,
) -> dict[str, object]:
    counts: dict[str, object] = {
        "reviewer_model_requests": requests,
        "reviewer_input_tokens": input_tokens,
        "reviewer_output_tokens": 50,
        **fields,
    }
    if cached is not None:
        counts["reviewer_cached_input_tokens"] = cached
        counts["reviewer_prefix_cached_tokens"] = cached if first_cached is None else first_cached
    if prefix is not None:
        counts["reviewer_prefix_tokens"] = prefix
    if label is not None:
        counts["reviewer_cache_miss"] = label
    return _record(index, request=request, minute=minute, **counts)


def _total(report: _Report) -> Mapping[str, JsonValue]:
    return cast(Mapping[str, JsonValue], report["total"])


def _part(report: _Report, *path: str) -> JsonValue:
    value: JsonValue = cast(JsonValue, report)
    for name in path:
        value = cast(Mapping[str, JsonValue], value)[name]
    return value


def _valid(report: _Report) -> None:
    validate_schema_instance("reviewer-cache-report", "1.0.0", cast(JsonValue, dict(report)))
    ReviewerCacheReportContract.model_validate(report)


def _partition_holds(usage: Mapping[str, JsonValue]) -> None:
    uncached = cast(Mapping[str, JsonValue], usage["uncached_input"])
    parts = [
        uncached["first_turn_cold"],
        uncached["first_turn_warm"],
        *cast(Mapping[str, JsonValue], uncached["shortfall"]).values(),
        uncached["beyond_prefix"],
        *cast(Mapping[str, JsonValue], uncached["unattributed"]).values(),
    ]
    assert sum(cast(list[int], parts)) == uncached["tokens"]


def _fixture_records() -> list[JsonValue]:
    document = cast(Mapping[str, JsonValue], load_fixture_json(_FIXTURE))
    return cast(list[JsonValue], cast(Mapping[str, JsonValue], document["input"])["records"])


def _generator() -> ModuleType:
    root = Path(__file__).resolve().parents[3]
    spec = importlib.util.spec_from_file_location(
        "generate_reviewer_cache_report_fixture",
        root / "scripts/generate_reviewer_cache_report_fixture.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_an_empty_ring_reports_nothing_and_no_zero_it_did_not_see() -> None:
    report = reviewer_cache_report(())
    _valid(report)
    assert report["coverage"] == {
        "records_read": 0,
        "unreadable_records": 0,
        "reviews": 0,
        "exchange_records": 0,
        "duplicate_exchange_records": 0,
        "missing_exchanges": 0,
        "earliest_record_at": None,
        "latest_record_at": None,
    }
    assert report["reviews"] == [] and report["request_id"] is None
    assert _part(report, "total", "input_tokens") == {"sum": None, "exchanges": 0}
    assert _part(report, "total", "cached_share", "basis_points_floor") is None


def test_a_count_no_exchange_reported_is_never_summed_as_zero() -> None:
    report = reviewer_cache_report(
        [
            _counted(1, 70_000, None, prefix=0, label="first_turn"),
            _record(2, reviewer_usage_state="unreported"),
            _counted(
                3, 73_000, 71_936, prefix=None, label=None, reviewer_cache_write_input_tokens=0
            ),
        ]
    )
    _valid(report)
    total = _total(report)
    assert total["input_tokens"] == {"sum": 143_000, "exchanges": 2}
    assert total["cached_input_tokens"] == {"sum": 71_936, "exchanges": 1}
    # The one exchange that reported cache writes reported zero: that zero is its own.
    assert total["cache_write_input_tokens"] == {"sum": 0, "exchanges": 1}
    # The share's denominator is the input of the exchanges that reported a cached count only.
    assert total["cached_share"] == {
        "cached_input_tokens": 71_936,
        "input_tokens_of_exchanges_reporting_cached": 73_000,
        "basis_points_floor": 9_854,
    }
    assert _part(report, "total", "first_turn", "cached_unreported") == {
        "exchanges": 1,
        "input_tokens": 70_000,
    }
    assert _part(report, "total", "uncached_input", "unattributed", "prefix_unknown") == 1_064
    assert (total["exchanges_with_counts"], total["exchanges_unreported"]) == (2, 1)
    without = reviewer_cache_report([_counted(1, 70_000, None, prefix=0, label="first_turn")])
    assert _part(without, "total", "cache_write_input_tokens") == {"sum": None, "exchanges": 0}
    assert _part(without, "total", "cached_share", "basis_points_floor") is None


def test_every_label_has_its_bucket_and_the_partition_sums_to_the_uncached_input() -> None:
    records = [
        _counted(1, 90_000, 0, prefix=0, label="first_turn"),
        _counted(2, 92_000, 89_984, prefix=90_000, label="none"),
        _counted(3, 92_100, 60_032, prefix=92_000, label="retry"),
        _counted(4, 94_000, 1_024, prefix=92_100, label="schema_or_settings_change"),
        _counted(5, 96_000, 10_000, prefix=94_000, label="unexplained"),
        _counted(6, 97_000, 80_000, prefix=96_000, label="compaction"),
        _record(7, reviewer_usage_state="refused", reviewer_cache_miss="compaction"),
    ]
    report = reviewer_cache_report(records)
    _valid(report)
    total = _total(report)
    _partition_holds(total)
    assert total["miss_labels"] == {
        "none": 1,
        "first_turn": 1,
        "schema_or_settings_change": 1,
        "compaction": 2,
        "retry": 1,
        "unexplained": 1,
        "no_label": 0,
    }
    assert _part(report, "total", "uncached_input", "shortfall") == {
        "none": 16,  # within tolerance, kept under none
        "schema_or_settings_change": 91_076,
        "compaction": 16_000,
        "retry": 31_968,
        "unexplained": 84_000,
    }
    assert _part(report, "total", "uncached_input", "first_turn_cold") == 90_000
    # New tokens past each prefix, apart from the shortfall: 2,000 + 100 + 1,900 + 2,000 + 1,000.
    assert _part(report, "total", "uncached_input", "beyond_prefix") == 7_000
    assert _part(report, "total", "beyond_prefix") == {
        "exchanges": 5,
        "input_tokens": 7_000,
        "surplus_cached_tokens": 0,
    }
    assert total["exchanges_refused"] == 1


def test_a_first_turn_is_warm_only_when_its_first_request_reused_something() -> None:
    report = reviewer_cache_report(
        [
            _counted(1, 88_000, 4_096, prefix=0, label="first_turn"),
            _counted(1, 50_000, 0, prefix=0, label="first_turn", request=_TWO),
        ]
    )
    _valid(report)
    assert _part(report, "total", "first_turn") == {
        "cold": {"exchanges": 1, "input_tokens": 50_000},
        "warm": {"exchanges": 1, "input_tokens": 88_000, "prefix_cached_tokens": 4_096},
        "cached_unreported": {"exchanges": 0, "input_tokens": 0},
    }
    assert _part(report, "total", "uncached_input", "first_turn_warm") == 83_904
    assert _part(report, "total", "uncached_input", "first_turn_cold") == 50_000


def test_a_multi_request_exchange_attributes_only_its_first_requests_shortfall() -> None:
    # Two requests: 185,000 input, 150,016 cached in all, 88,960 by the first request against a
    # 91,000 prefix. Only that 2,040 shortfall is the label's; the rest cannot be split.
    report = reviewer_cache_report(
        [
            _counted(
                4,
                185_000,
                150_016,
                prefix=91_000,
                label="unexplained",
                requests=2,
                first_cached=88_960,
            ),
            _counted(1, 60_000, 0, prefix=0, label="first_turn", requests=3, request=_TWO),
        ]
    )
    _valid(report)
    uncached = cast(Mapping[str, JsonValue], _part(report, "total", "uncached_input"))
    _partition_holds(_total(report))
    assert cast(Mapping[str, int], uncached["shortfall"])["unexplained"] == 2_040
    # 32,944 from the two-request exchange; a three-request first turn's whole 60,000 too.
    assert uncached["unattributed"] == {
        "prefix_unknown": 0,
        "shortfall_exceeds_uncached": 0,
        "not_split_by_request": 92_944,
    }
    assert uncached["beyond_prefix"] == 0 and uncached["first_turn_cold"] == 0
    assert _part(report, "total", "beyond_prefix", "exchanges") == 0
    # Its input split by warmth still counts: nothing of its first request was cached.
    assert _part(report, "total", "first_turn", "cold", "exchanges") == 1


def test_a_shortfall_beyond_the_uncached_input_is_not_attributed() -> None:
    # A compaction rewrote the history: 40,000 input against a 61,500 prefix.
    report = reviewer_cache_report([_counted(3, 40_000, 0, prefix=61_500, label="compaction")])
    assert _part(report, "total", "uncached_input", "shortfall", "compaction") == 0
    assert (
        _part(report, "total", "uncached_input", "unattributed", "shortfall_exceeds_uncached")
        == 40_000
    )


def test_a_surplus_beyond_the_prefix_is_kept_apart() -> None:
    report = reviewer_cache_report([_counted(2, 60_000, 55_000, prefix=50_000, label="none")])
    assert _part(report, "total", "beyond_prefix") == {
        "exchanges": 1,
        "input_tokens": 10_000,
        "surplus_cached_tokens": 5_000,
    }
    assert _part(report, "total", "uncached_input", "beyond_prefix") == 5_000
    assert _part(report, "total", "uncached_input", "shortfall", "none") == 0


def test_duplicates_are_all_summed_and_missing_indices_are_ranges() -> None:
    records = [
        _counted(1, 50_000, 0, prefix=0, label="first_turn", minute=1),
        _counted(1, 50_000, 49_920, prefix=0, label="first_turn", minute=2),
        _counted(4, 51_800, 49_920, prefix=50_000, label="none", minute=3),
        _counted(7, 53_000, 51_712, prefix=51_800, label="none", minute=4),
    ]
    report = reviewer_cache_report(records)
    _valid(report)
    review = cast(list[Mapping[str, JsonValue]], report["reviews"])[0]
    assert review["exchange_indices"] == {
        "highest": 7,
        "distinct": 3,
        "duplicate_records": 1,
        "missing": 4,
        "missing_ranges": [{"first": 2, "last": 3}, {"first": 5, "last": 6}],
    }
    assert _part(review, "usage", "input_tokens") == {"sum": 204_800, "exchanges": 4}
    assert report["coverage"] == {
        "records_read": 4,
        "unreadable_records": 0,
        "reviews": 1,
        "exchange_records": 4,
        "duplicate_exchange_records": 1,
        "missing_exchanges": 4,
        "earliest_record_at": "2026-11-21T10:01:00.000Z",
        "latest_record_at": "2026-11-21T10:04:00.000Z",
    }


class _Hostile(Mapping[str, object]):
    """A mapping that fails every read."""

    def __getitem__(self, key: str) -> object:
        raise RuntimeError("unreadable")

    def __iter__(self) -> Iterator[str]:
        raise RuntimeError("unreadable")

    def __len__(self) -> int:
        return 1

    def get(self, key: str, default: object = None) -> object:  # type: ignore[override]
        raise RuntimeError("unreadable")


@pytest.mark.parametrize(
    "record",
    [
        None,
        7,
        "exchange_cache",
        [],
        _Hostile(),
        {**_counted(1, 10, 0, prefix=0, label="first_turn"), "operation": "turn_notifications"},
        {**_counted(1, 10, 0, prefix=0, label="first_turn"), "request_id": "req_bad"},
        {**_counted(1, 10, 0, prefix=0, label="first_turn"), "timestamp": "yesterday"},
        _counted(0, 10, 0, prefix=0, label="first_turn"),
        _counted(1, 10, 0, prefix=0, label="cold_start"),
        _counted(1, 10, 11, prefix=0, label="first_turn"),
        _counted(2, 10, 5, prefix=8, label="none", first_cached=6),
        _counted(1, 10, 0, prefix=None, label="first_turn"),
        # Only the exchange that opened the conversation is a first turn, and it opened at 0.
        _counted(2, 10, 0, prefix=0, label="first_turn"),
        _counted(1, 10, 5, prefix=0, label="none"),
        _counted(1, 10, 0, prefix=0, label=None),
        _counted(1, 10, 0, prefix=3, label="compaction"),
        _counted(1, 10, 0, prefix=None, label="compaction"),
        _counted(2, 10, 0, prefix=None, label="none"),
        _counted(2, 10, 5, prefix=8, label=None),
        _counted(1, 10, 0, prefix=0, label="first_turn", requests=0),
        _counted(1, True, 0, prefix=0, label="first_turn"),  # type: ignore[arg-type]
        _counted(1, 10, 0, prefix=0, label="first_turn", reviewer_output_tokens=1.5),
        _counted(1, 2**53, 0, prefix=0, label="first_turn"),
        {
            **_counted(1, 10, 0, prefix=0, label="first_turn"),
            "reviewer_input_tokens": "unavailable",
        },
        {**_counted(1, 10, 0, prefix=0, label="first_turn"), "reviewer_usage_state": "unreported"},
        _record(2, reviewer_usage_state="lost"),
        _record(2, reviewer_usage_state="refused", reviewer_cache_miss="none"),
        _record(2),
        {
            key: value
            for key, value in _counted(1, 10, 0, prefix=0, label="first_turn").items()
            if key != "reviewer_output_tokens"
        },
        {**_counted(2, 10, None, prefix=8, label=None), "reviewer_prefix_cached_tokens": 3},
    ],
)
def test_a_malformed_record_is_unreadable_and_adds_nothing_else(record: object) -> None:
    good = _counted(1, 90_000, 0, prefix=0, label="first_turn")
    report = reviewer_cache_report([good, record])
    _valid(report)
    assert _part(report, "coverage", "records_read") == 2
    assert _part(report, "coverage", "unreadable_records") == 1
    assert report["total"] == reviewer_cache_report([good])["total"]


def _usage(
    total: int, last: int, requests: int, cached: int | None, first: int, write: int | None
) -> ExchangeCacheUsage:
    """A usage the accounting accepts, its counts clamped to fit together."""

    return ExchangeCacheUsage(
        total,
        None if cached is None else min(cached, total),
        30,
        requests,
        None if cached is None else min(first, cached, total),
        min(last, total),
        cache_write_input_tokens=write,
    )


_USAGE = st.builds(
    _usage,
    st.integers(0, 200_000),
    st.integers(0, 200_000),
    st.integers(1, 3),
    st.none() | st.integers(0, 200_000),
    st.integers(0, 200_000),
    st.none() | st.integers(0, 200_000),
)
_STEP = st.tuples(
    st.none() | _USAGE,
    st.booleans(),  # compacted
    st.booleans(),  # usage refused
    st.booleans(),  # settings changed
    st.booleans(),  # the previous answer kept (else a repair)
)


@settings(max_examples=80, deadline=None)
@given(st.lists(st.lists(_STEP, min_size=1, max_size=6), min_size=1, max_size=3))
def test_every_record_the_accounting_writes_is_readable(attempts: list[list[object]]) -> None:
    # Each list is one attempt under the same request id: a fresh state, so a restarted attempt
    # records its first exchange again at index 1. A one-shot case is an attempt of one exchange.
    records: list[object] = []
    for attempt in attempts:
        state, roles, settings_digest = ReviewerCacheState(), ["system", "user"], "a"
        for step in attempt:
            usage, compacted, refused, changed, kept = cast(
                tuple[ExchangeCacheUsage | None, bool, bool, bool, bool], step
            )
            settings_digest = "b" if changed and settings_digest == "a" else settings_digest
            _review, counts = exchange_cache_counts(
                state,
                request_id=_ONE,
                settings=settings_digest,
                roles=tuple(roles),
                usage=usage,
                compacted=compacted,
                usage_refused=refused,
            )
            records.append({**_record(cast(int, counts["reviewer_exchange_index"])), **counts})
            roles = [*roles, "assistant", "user"] if kept else [*roles, "user"]
    report = reviewer_cache_report(records)
    _valid(report)
    assert _part(report, "coverage", "unreadable_records") == 0


def test_two_records_at_the_counter_bound_give_a_report_the_contract_holds() -> None:
    top = 2**53 - 1
    records = [
        _counted(1, top, 0, prefix=0, label="first_turn", minute=1),
        _counted(1, top, 0, prefix=0, label="first_turn", minute=2, request=_TWO),
    ]
    report = reviewer_cache_report(records)
    _valid(report)
    # The second review's record would carry the total input past the bound: it is unreadable.
    assert _part(report, "coverage", "unreadable_records") == 1
    assert _part(report, "coverage", "reviews") == 1
    assert _part(report, "total", "input_tokens") == {"sum": top, "exchanges": 1}
    reviews = cast(list[Mapping[str, JsonValue]], report["reviews"])
    assert [review["request_id"] for review in reviews] == [_ONE]
    expected = canonical_encode(cast(JsonValue, report))
    assert canonical_encode(cast(JsonValue, reviewer_cache_report(records[::-1]))) == expected


def test_which_record_passes_the_bound_does_not_depend_on_the_input_order() -> None:
    top = 2**53 - 1
    records = [
        # A review missing every index below its last: the missing total is one short of the bound.
        _record(top, reviewer_usage_state="unreported"),
        _record(2, request=_TWO, reviewer_usage_state="unreported"),
        # Index 5 would add two more missing indices, past the bound.
        _record(5, request=_TWO, reviewer_usage_state="refused"),
        _counted(1, top, 0, prefix=0, label="first_turn", request=_TWO, minute=1),
        # A second record of index 1 would carry the input past the bound.
        _counted(1, 1, 0, prefix=0, label="first_turn", request=_TWO, minute=2),
    ]
    report = reviewer_cache_report(records)
    _valid(report)
    assert _part(report, "coverage", "unreadable_records") == 2
    assert _part(report, "coverage", "missing_exchanges") == top - 1
    assert _part(report, "coverage", "duplicate_exchange_records") == 0
    assert _part(report, "total", "input_tokens") == {"sum": top, "exchanges": 1}
    assert _part(report, "total", "exchanges_refused") == 0
    second = cast(list[Mapping[str, JsonValue]], report["reviews"])[1]
    assert _part(second, "exchange_indices", "highest") == 2
    expected = canonical_encode(cast(JsonValue, report))
    for order in ([4, 3, 2, 1, 0], [2, 4, 0, 3, 1], [1, 2, 4, 0, 3]):
        shuffled = [records[position] for position in order]
        assert canonical_encode(cast(JsonValue, reviewer_cache_report(shuffled))) == expected


def test_a_selector_reads_only_that_reviews_records() -> None:
    records = [
        _counted(1, 90_000, 0, prefix=0, label="first_turn"),
        {**_counted(2, 1, 0, prefix=0, label="none"), "reviewer_input_tokens": "unavailable"},
        _counted(1, 50_000, 0, prefix=0, label="first_turn", request=_TWO),
        "not a record",
    ]
    report = reviewer_cache_report(records, request_id=_ONE)
    _valid(report)
    assert report["request_id"] == _ONE
    assert _part(report, "coverage", "records_read") == 2
    assert _part(report, "coverage", "unreadable_records") == 1
    reviews = cast(list[Mapping[str, JsonValue]], report["reviews"])
    assert [review["request_id"] for review in reviews] == [_ONE]


def test_reviews_are_listed_by_request_id_and_total_is_their_sum() -> None:
    records = _fixture_records()
    report = reviewer_cache_report(records)
    _valid(report)
    reviews = cast(list[Mapping[str, JsonValue]], report["reviews"])
    ids = [cast(str, review["request_id"]) for review in reviews]
    assert ids == sorted(ids, key=str.encode)
    for name in ("input_tokens", "cached_input_tokens", "output_tokens", "model_requests"):
        assert _part(report, "total", name, "exchanges") == sum(
            cast(int, _part(review, "usage", name, "exchanges")) for review in reviews
        )
    _partition_holds(_total(report))
    for review in reviews:
        _partition_holds(cast(Mapping[str, JsonValue], review["usage"]))


@settings(max_examples=60, deadline=None)
@given(st.permutations(range(_FIXTURE_RECORDS)))
def test_any_order_of_the_records_gives_the_same_report(order: list[int]) -> None:
    records = _fixture_records()
    assert len(records) == _FIXTURE_RECORDS
    expected = canonical_encode(cast(JsonValue, reviewer_cache_report(records)))
    shuffled = [records[position] for position in order]
    assert canonical_encode(cast(JsonValue, reviewer_cache_report(shuffled))) == expected


def test_the_fixture_is_reproduced_byte_for_byte_and_matches_its_schema() -> None:
    generator = _generator()
    data = canonical_encode(cast(JsonValue, generator.document()))
    assert data == load_fixture_bytes(_FIXTURE)
    document = cast(Mapping[str, JsonValue], load_fixture_json(_FIXTURE))
    inputs = cast(Mapping[str, JsonValue], document["input"])
    expected = cast(Mapping[str, Mapping[str, JsonValue]], document["expected"])
    records = cast(list[JsonValue], inputs["records"])
    for name, selector in (
        ("all_reviews", None),
        ("one_review", cast(str, inputs["one_review_request_id"])),
    ):
        report = reviewer_cache_report(records, request_id=selector)
        _valid(report)
        assert report == expected[name]["report"]
        assert canonical_digest(cast(JsonValue, report)) == expected[name]["digest"]
        assert reviewer_cache_text(report) == expected[name]["text"]
    assert expected["schema"] == "service/reviewer-cache-report-1.0.0.schema.json"


def test_the_fixture_records_are_what_the_diagnostics_ring_reads_back() -> None:
    # Each record is already the ring's bounded projection: reading it back changes nothing.
    for record in _fixture_records():
        source = cast(Mapping[str, object], record)
        assert dict(_public_view(source)) == dict(source)


def test_the_fixture_covers_each_case_the_report_distinguishes() -> None:
    report = reviewer_cache_report(_fixture_records())
    total = _total(report)
    coverage = cast(Mapping[str, int], report["coverage"])
    assert coverage["unreadable_records"] == 1
    assert coverage["missing_exchanges"] == 2 and coverage["duplicate_exchange_records"] == 1
    assert (total["exchanges_unreported"], total["exchanges_refused"]) == (1, 1)
    labels = cast(Mapping[str, int], total["miss_labels"])
    assert all(labels[name] for name in labels)
    assert cast(int, _part(report, "total", "first_turn", "warm", "exchanges")) >= 1
    unattributed = cast(Mapping[str, int], _part(report, "total", "uncached_input", "unattributed"))
    assert all(unattributed.values())
