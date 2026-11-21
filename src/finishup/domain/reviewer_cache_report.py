"""A deterministic report of reviewer prompt-cache use from ``exchange_cache`` records (#1172).

Every provider exchange of a review, except those INTERFACES lists as unrecorded (the local model
route, an API request that fails before an answer, a Codex exchange that fails before its turn's
settings are fixed), leaves one ``exchange_cache`` owner diagnostic (``domain.reviewer_cache``).
This module sums those records per review (one request id: the review's first provider request id)
and over all of them: exchanges seen and known missing, the provider-reported token counts, the
cached share, and the uncached input split by the closed cause the records support. It reads only
the records it is given, so its coverage is theirs: the diagnostics ring is bounded, and an older
review may be absent from it entirely.

Pure, integer-only and total: no clock, no I/O, no floats, and no record makes it raise. A record
that is not a well-formed ``exchange_cache`` record counts as unreadable and adds nothing else.
Every readable record is summed, duplicates included (a restarted attempt that kept its request id
records its exchanges again, and their tokens were spent again), so no record replaces another.
Records are accounted in one canonical order, reviews by request id and a review's records by
index and then every other field, and a record whose accounting would carry any sum past 2^53-1
(the bound every report integer has) counts as unreadable too and adds nothing else. Every sum
only grows along that order, so the report is the same for the same records in any input order.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Final, cast, get_args

from finishup.domain.reviewer_cache import ReviewerCacheMiss, ReviewerUsageState
from finishup.protocol.canonical import JsonValue
from finishup.protocol.ids import IdKind, validate_id

__all__ = ["REVIEWER_CACHE_REPORT_VERSION", "reviewer_cache_report"]

REVIEWER_CACHE_REPORT_VERSION: Final = "1.0.0"
_MAX_COUNTER: Final = 2**53 - 1
_TIMESTAMP: Final = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z")
_LABELS: Final[tuple[str, ...]] = get_args(ReviewerCacheMiss.__value__)
_USAGE_STATES: Final[tuple[str, ...]] = get_args(ReviewerUsageState.__value__)
# The labels a shortfall against a known prefix can carry; ``first_turn`` opens at prefix 0.
_SHORTFALL_LABELS: Final = (
    "none",
    "schema_or_settings_change",
    "compaction",
    "retry",
    "unexplained",
)
# Labels ``domain.reviewer_cache`` assigns only when the prefix and its reuse are both known.
_KNOWN_PREFIX_LABELS: Final = frozenset(
    {"none", "schema_or_settings_change", "retry", "unexplained"}
)
_COUNT_FIELDS: Final = (
    "reviewer_model_requests",
    "reviewer_input_tokens",
    "reviewer_cached_input_tokens",
    "reviewer_cache_write_input_tokens",
    "reviewer_output_tokens",
    "reviewer_prefix_tokens",
    "reviewer_prefix_cached_tokens",
)
_UNATTRIBUTED: Final = ("prefix_unknown", "shortfall_exceeds_uncached", "not_split_by_request")


@dataclass(frozen=True, slots=True)
class _Exchange:
    """One well-formed record; every count is ``None`` where the record left it out."""

    request_id: str
    index: int
    timestamp: str
    label: str | None
    usage_state: str | None
    requests: int | None
    input_tokens: int | None
    cached: int | None
    cache_write: int | None
    output_tokens: int | None
    prefix: int | None
    prefix_cached: int | None


def reviewer_cache_report(
    records: Iterable[object], *, request_id: str | None = None
) -> dict[str, JsonValue]:
    """The report over ``records``, or over one review's records when ``request_id`` is given.

    With ``request_id`` only mappings whose ``request_id`` equals it are read; anything else is
    outside the report. Never raises: a record that cannot be read is counted ``unreadable``.
    """

    read = unreadable = 0
    by_review: dict[str, list[_Exchange]] = {}
    for record in records:
        if request_id is not None and not _selected(record, request_id):
            continue
        read += 1
        exchange = _parse(record)
        if exchange is None:
            unreadable += 1
            continue
        by_review.setdefault(exchange.request_id, []).append(exchange)
    total = _Tally()
    reviews: list[JsonValue] = []
    duplicates = missing = 0
    stamps: list[str] = []
    # Canonical order, whatever order the records came in: reviews by request id, a review's
    # records by index and then by every other field. Every sum only grows along it, so a record
    # that would carry one past the counter bound is decided the same way for any input order.
    for review_id in sorted(by_review, key=str.encode):
        tally = _Tally()
        accepted: list[_Exchange] = []
        highest = distinct = 0
        for exchange in sorted(by_review[review_id], key=_canonical_key):
            additions = _accounting(exchange)
            # Indices arrive in ascending order, so a new one is above every accepted one.
            new = exchange.index != highest
            review_distinct = distinct + 1 if new else distinct
            review_missing = exchange.index - review_distinct
            review_duplicates = len(accepted) + 1 - review_distinct
            if not (
                tally.fits(additions)
                and total.fits(additions)
                and duplicates + review_duplicates <= _MAX_COUNTER
                and missing + review_missing <= _MAX_COUNTER
            ):
                # Past the bound the report's integers hold: unreadable, and it adds nothing else.
                unreadable += 1
                continue
            tally.apply(additions)
            total.apply(additions)
            accepted.append(exchange)
            stamps.append(exchange.timestamp)
            highest, distinct = exchange.index, review_distinct
        if not accepted:
            continue
        indices = _indices(accepted)
        duplicates += cast(int, indices["duplicate_records"])
        missing += cast(int, indices["missing"])
        reviews.append(
            {"request_id": review_id, "exchange_indices": indices, "usage": tally.wire()}
        )
    return {
        "schema_version": REVIEWER_CACHE_REPORT_VERSION,
        "source": "diagnostics_ring",
        "request_id": request_id,
        "coverage": {
            "records_read": read,
            "unreadable_records": unreadable,
            "reviews": len(reviews),
            "exchange_records": read - unreadable,
            "duplicate_exchange_records": duplicates,
            "missing_exchanges": missing,
            "earliest_record_at": min(stamps) if stamps else None,
            "latest_record_at": max(stamps) if stamps else None,
        },
        "total": total.wire(),
        "reviews": reviews,
    }


def _canonical_key(exchange: _Exchange) -> tuple[int | str, ...]:
    """A total order on one review's records: equal keys are equal records (``None`` sorts first)."""

    counts = (
        exchange.requests,
        exchange.input_tokens,
        exchange.cached,
        exchange.cache_write,
        exchange.output_tokens,
        exchange.prefix,
        exchange.prefix_cached,
    )
    return (
        exchange.index,
        exchange.timestamp,
        exchange.label or "",
        exchange.usage_state or "",
        *(-1 if value is None else value for value in counts),
    )


def _selected(record: object, request_id: str) -> bool:
    try:
        return (
            isinstance(record, Mapping)
            and cast(Mapping[object, object], record).get("request_id") == request_id
        )
    except Exception:  # noqa: BLE001 - a mapping that fails to answer is outside the selection
        return False


def _indices(exchanges: list[_Exchange]) -> dict[str, JsonValue]:
    """Highest index, duplicates and the gaps below it, as inclusive ranges in ascending order.

    A gap is a lost line: the ring evicted it or its best-effort write failed (an exchange that is
    not recorded does not advance the index). A duplicate can hide a lost line of the same index,
    so ``missing`` is a lower bound.
    """

    seen = sorted({exchange.index for exchange in exchanges})
    ranges: list[JsonValue] = []
    expected = 1
    for index in seen:
        if index > expected:
            ranges.append({"first": expected, "last": index - 1})
        expected = index + 1
    highest = seen[-1]
    return {
        "highest": highest,
        "distinct": len(seen),
        "duplicate_records": len(exchanges) - len(seen),
        "missing": highest - len(seen),
        "missing_ranges": ranges,
    }


def _parse(record: object) -> _Exchange | None:
    try:
        return _parse_mapping(record)
    except Exception:  # noqa: BLE001 - an unreadable record is counted, never raised
        return None


def _parse_mapping(record: object) -> _Exchange | None:
    if not isinstance(record, Mapping):
        return None
    source = cast(Mapping[object, object], record)
    if source.get("operation") != "exchange_cache":
        return None
    review = source.get("request_id")
    timestamp = source.get("timestamp")
    if type(review) is not str or type(timestamp) is not str:
        return None
    validate_id(IdKind.REQUEST, review)
    if _TIMESTAMP.fullmatch(timestamp) is None:
        return None
    index = _counter(source.get("reviewer_exchange_index"))
    if index is None or index < 1:
        return None
    label = source.get("reviewer_cache_miss")
    usage_state = source.get("reviewer_usage_state")
    if label is not None and label not in _LABELS:
        return None
    if usage_state is not None and usage_state not in _USAGE_STATES:
        return None
    counts: dict[str, int | None] = {}
    for name in _COUNT_FIELDS:
        if name not in source:
            counts[name] = None
            continue
        value = _counter(source[name])
        if value is None:
            return None
        counts[name] = value
    exchange = _Exchange(
        request_id=review,
        index=index,
        timestamp=timestamp,
        label=cast(str | None, label),
        usage_state=cast(str | None, usage_state),
        requests=counts["reviewer_model_requests"],
        input_tokens=counts["reviewer_input_tokens"],
        cached=counts["reviewer_cached_input_tokens"],
        cache_write=counts["reviewer_cache_write_input_tokens"],
        output_tokens=counts["reviewer_output_tokens"],
        prefix=counts["reviewer_prefix_tokens"],
        prefix_cached=counts["reviewer_prefix_cached_tokens"],
    )
    return exchange if _consistent(exchange, counts) else None


def _consistent(exchange: _Exchange, counts: Mapping[str, int | None]) -> bool:
    """The shape ``domain.reviewer_cache.exchange_cache_counts`` writes, and nothing else."""

    if exchange.usage_state is not None:
        # Without counts: no token count, and at most the compaction label.
        return all(value is None for value in counts.values()) and exchange.label in (
            None,
            "compaction",
        )
    if exchange.requests is None or exchange.input_tokens is None:
        return False
    if exchange.output_tokens is None or exchange.requests < 1:
        return False
    if (exchange.cached is None) != (exchange.prefix_cached is None):
        return False
    if exchange.cached is not None and exchange.prefix_cached is not None:
        if exchange.cached > exchange.input_tokens or exchange.prefix_cached > exchange.cached:
            return False
    known = exchange.prefix is not None and exchange.cached is not None
    if exchange.index == 1:
        # The exchange that opened the conversation: prefix 0, and its label says so or names a
        # compaction. Only it is a first turn.
        return exchange.prefix == 0 and exchange.label in ("first_turn", "compaction")
    if exchange.label == "first_turn":
        return False
    if exchange.label in _KNOWN_PREFIX_LABELS:
        return known
    if exchange.label is None:
        return not known
    return True  # compaction, with or without a known prefix


def _counter(value: object) -> int | None:
    return value if type(value) is int and 0 <= value <= _MAX_COUNTER else None


def _accounting(exchange: _Exchange) -> dict[str, int]:
    """What one exchange adds to a tally, keyed by its place in the wire report; never negative."""

    additions: dict[str, int] = {}

    def add(key: str, value: int = 1) -> None:
        additions[key] = additions.get(key, 0) + value

    add("exchange_records")
    add("label." + (exchange.label or "no_label"))
    if exchange.usage_state is not None:
        add("usage." + exchange.usage_state)
        return additions
    add("usage.with_counts")
    for key, value in (
        ("model_requests", exchange.requests),
        ("input_tokens", exchange.input_tokens),
        ("cached_input_tokens", exchange.cached),
        ("cache_write_input_tokens", exchange.cache_write),
        ("output_tokens", exchange.output_tokens),
    ):
        # An unreported count is never summed as zero: each sum names its contributors.
        if value is not None:
            add(key + ".sum", value)
            add(key + ".exchanges")
    _uncached(exchange, add)
    return additions


def _uncached(exchange: _Exchange, add: Callable[[str, int], None]) -> None:
    """Split one exchange's uncached input by the cause its integers support.

    The record's ``prefix_cached`` is its first model request's cached input, while ``input`` and
    ``cached`` sum every request. Only an exchange of one request whose first-request cached count
    equals its total splits exactly: shortfall ``max(0, prefix - prefix_cached)`` under its label,
    the rest beyond the prefix. With more requests (or counts that disagree) the first request's
    shortfall is still attributed, and the rest is ``not_split_by_request``: later requests re-read
    earlier ones, and the record does not say which of them missed. A shortfall larger than the
    uncached input means the prefix is not what this exchange read (a rewritten history, or counts
    that do not fit), so none of it is attributed.
    """

    input_tokens = cast(int, exchange.input_tokens)
    first_turn = exchange.label == "first_turn"
    warmth = None
    if first_turn:
        warmth = (
            "cached_unreported"
            if exchange.prefix_cached is None
            else ("warm" if exchange.prefix_cached > 0 else "cold")
        )
        add(f"first_turn.{warmth}.exchanges", 1)
        add(f"first_turn.{warmth}.input_tokens", input_tokens)
        if warmth == "warm":
            add("first_turn.warm.prefix_cached_tokens", cast(int, exchange.prefix_cached))
    if exchange.cached is None or exchange.prefix_cached is None:
        return
    uncached = input_tokens - exchange.cached
    add("uncached.exchanges", 1)
    add("uncached.tokens", uncached)
    add("share.input_tokens", input_tokens)
    split = exchange.requests == 1 and exchange.prefix_cached == exchange.cached
    if first_turn:
        add(
            f"uncached.first_turn_{warmth}" if split else "unattributed.not_split_by_request",
            uncached,
        )
        return
    if exchange.prefix is None:
        add("unattributed.prefix_unknown", uncached)
        return
    shortfall = max(0, exchange.prefix - exchange.prefix_cached)
    if shortfall > uncached:
        add("unattributed.shortfall_exceeds_uncached", uncached)
        return
    # A well-formed record with a known prefix and cached count always carries a label.
    add("shortfall." + cast(str, exchange.label), shortfall)
    if not split:
        add("unattributed.not_split_by_request", uncached - shortfall)
        return
    add("uncached.beyond_prefix", uncached - shortfall)
    add("beyond_prefix.exchanges", 1)
    add("beyond_prefix.input_tokens", input_tokens - exchange.prefix)
    add("beyond_prefix.surplus_cached_tokens", max(0, exchange.cached - exchange.prefix))


class _Tally:
    """Integer sums over a set of exchanges, keyed by their place in the wire report."""

    __slots__ = ("_counts",)

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}

    def fits(self, additions: Mapping[str, int]) -> bool:
        """Whether adding ``additions`` keeps every sum within the counter bound."""

        return all(self._get(key) + value <= _MAX_COUNTER for key, value in additions.items())

    def apply(self, additions: Mapping[str, int]) -> None:
        for key, value in additions.items():
            self._counts[key] = self._get(key) + value

    def _get(self, key: str) -> int:
        return self._counts.get(key, 0)

    def _sum(self, name: str) -> dict[str, JsonValue]:
        """A count's sum and its contributors; ``None`` when no exchange reported it, never 0."""

        exchanges = self._get(name + ".exchanges")
        return {"sum": self._get(name + ".sum") if exchanges else None, "exchanges": exchanges}

    def wire(self) -> dict[str, JsonValue]:
        cached = self._get("cached_input_tokens.sum")
        denominator = self._get("share.input_tokens")
        return {
            "exchange_records": self._get("exchange_records"),
            "exchanges_with_counts": self._get("usage.with_counts"),
            "exchanges_unreported": self._get("usage.unreported"),
            "exchanges_refused": self._get("usage.refused"),
            "model_requests": self._sum("model_requests"),
            "input_tokens": self._sum("input_tokens"),
            "cached_input_tokens": self._sum("cached_input_tokens"),
            "cache_write_input_tokens": self._sum("cache_write_input_tokens"),
            "output_tokens": self._sum("output_tokens"),
            "cached_share": {
                "cached_input_tokens": cached,
                "input_tokens_of_exchanges_reporting_cached": denominator,
                "basis_points_floor": cached * 10_000 // denominator if denominator else None,
            },
            "miss_labels": {name: self._get("label." + name) for name in (*_LABELS, "no_label")},
            "first_turn": {
                "cold": {
                    "exchanges": self._get("first_turn.cold.exchanges"),
                    "input_tokens": self._get("first_turn.cold.input_tokens"),
                },
                "warm": {
                    "exchanges": self._get("first_turn.warm.exchanges"),
                    "input_tokens": self._get("first_turn.warm.input_tokens"),
                    "prefix_cached_tokens": self._get("first_turn.warm.prefix_cached_tokens"),
                },
                "cached_unreported": {
                    "exchanges": self._get("first_turn.cached_unreported.exchanges"),
                    "input_tokens": self._get("first_turn.cached_unreported.input_tokens"),
                },
            },
            "beyond_prefix": {
                "exchanges": self._get("beyond_prefix.exchanges"),
                "input_tokens": self._get("beyond_prefix.input_tokens"),
                "surplus_cached_tokens": self._get("beyond_prefix.surplus_cached_tokens"),
            },
            "uncached_input": {
                "exchanges": self._get("uncached.exchanges"),
                "tokens": self._get("uncached.tokens"),
                "first_turn_cold": self._get("uncached.first_turn_cold"),
                "first_turn_warm": self._get("uncached.first_turn_warm"),
                "shortfall": {name: self._get("shortfall." + name) for name in _SHORTFALL_LABELS},
                "beyond_prefix": self._get("uncached.beyond_prefix"),
                "unattributed": {name: self._get("unattributed." + name) for name in _UNATTRIBUTED},
            },
        }
