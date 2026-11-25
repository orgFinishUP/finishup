"""Closed schema contract for ``reviewer-cache-report`` 1.0.0 (#1172, ADR-006).

``finishup service diagnostics --reviewer-cache --json`` prints the report
``domain.reviewer_cache_report`` builds from the ``exchange_cache`` records still in the owner-only
diagnostics ring. The generator derives ``schemas/service/reviewer-cache-report-1.0.0.schema.json``
from these models. What the schema cannot say (each partition summing to its total, a sum present
exactly when an exchange contributed, ranges ascending) the builder guarantees and tests pin.
"""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "REVIEWER_CACHE_REPORT_SCHEMA_VERSION",
    "ReviewerCacheReportContract",
]

REVIEWER_CACHE_REPORT_SCHEMA_VERSION: Literal["1.0.0"] = "1.0.0"

type Count = Annotated[int, Field(ge=0, le=9_007_199_254_740_991)]
type Index = Annotated[int, Field(ge=1, le=9_007_199_254_740_991)]
type RequestId = Annotated[
    str,
    Field(
        min_length=40,
        max_length=40,
        pattern=r"^req_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    ),
]
type RecordedAt = Annotated[
    str,
    Field(
        min_length=24,
        max_length=24,
        pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$",
    ),
]


class _Closed(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ReviewerCacheCountedSum(_Closed):
    """A provider count summed over the exchanges that reported it; ``null`` when none did."""

    sum: Count | None
    exchanges: Count


class ReviewerCacheShare(_Closed):
    """Cached over input tokens, both of the exchanges that reported a cached count."""

    cached_input_tokens: Count
    input_tokens_of_exchanges_reporting_cached: Count
    basis_points_floor: Annotated[int, Field(ge=0, le=10_000)] | None


class ReviewerCacheMissLabels(_Closed):
    """Exchange records per closed miss label, and those without one."""

    none: Count
    first_turn: Count
    schema_or_settings_change: Count
    compaction: Count
    retry: Count
    unexplained: Count
    no_label: Count


class ReviewerCacheFirstTurnCold(_Closed):
    exchanges: Count
    input_tokens: Count


class ReviewerCacheFirstTurnWarm(_Closed):
    exchanges: Count
    input_tokens: Count
    prefix_cached_tokens: Count


class ReviewerCacheFirstTurns(_Closed):
    """``first_turn`` exchanges by whether their first request reused anything."""

    cold: ReviewerCacheFirstTurnCold
    warm: ReviewerCacheFirstTurnWarm
    cached_unreported: ReviewerCacheFirstTurnCold


class ReviewerCacheBeyondPrefix(_Closed):
    """Exchanges of one request split exactly: input past the prefix and what was cached of it."""

    exchanges: Count
    input_tokens: Count
    surplus_cached_tokens: Count


class ReviewerCacheShortfall(_Closed):
    none: Count
    schema_or_settings_change: Count
    compaction: Count
    retry: Count
    unexplained: Count


class ReviewerCacheUnattributed(_Closed):
    prefix_unknown: Count
    shortfall_exceeds_uncached: Count
    not_split_by_request: Count


class ReviewerCacheUncached(_Closed):
    """Uncached input of the exchanges that reported a cached count, partitioned by cause."""

    exchanges: Count
    tokens: Count
    first_turn_cold: Count
    first_turn_warm: Count
    shortfall: ReviewerCacheShortfall
    beyond_prefix: Count
    unattributed: ReviewerCacheUnattributed


class ReviewerCacheUsage(_Closed):
    """One review's, or all reviews', sums over their exchange records."""

    exchange_records: Count
    exchanges_with_counts: Count
    exchanges_unreported: Count
    exchanges_refused: Count
    model_requests: ReviewerCacheCountedSum
    input_tokens: ReviewerCacheCountedSum
    cached_input_tokens: ReviewerCacheCountedSum
    cache_write_input_tokens: ReviewerCacheCountedSum
    output_tokens: ReviewerCacheCountedSum
    cached_share: ReviewerCacheShare
    miss_labels: ReviewerCacheMissLabels
    first_turn: ReviewerCacheFirstTurns
    beyond_prefix: ReviewerCacheBeyondPrefix
    uncached_input: ReviewerCacheUncached


class ReviewerCacheIndexRange(_Closed):
    first: Index
    last: Index


class ReviewerCacheIndices(_Closed):
    """A review's exchange indices: the gaps below the highest are lost lines."""

    highest: Index
    distinct: Index
    duplicate_records: Count
    missing: Count
    missing_ranges: list[ReviewerCacheIndexRange]


class ReviewerCacheReview(_Closed):
    request_id: RequestId
    exchange_indices: ReviewerCacheIndices
    usage: ReviewerCacheUsage


class ReviewerCacheCoverage(_Closed):
    """What the report read: the records still in the bounded diagnostics ring, no more."""

    records_read: Count
    unreadable_records: Count
    reviews: Count
    exchange_records: Count
    duplicate_exchange_records: Count
    missing_exchanges: Count
    earliest_record_at: RecordedAt | None
    latest_record_at: RecordedAt | None


class ReviewerCacheReportContract(_Closed):
    """``reviewer-cache-report`` 1.0.0: coverage, totals, and one entry per review."""

    schema_version: Literal["1.0.0"]
    source: Literal["diagnostics_ring"]
    request_id: RequestId | None
    coverage: ReviewerCacheCoverage
    total: ReviewerCacheUsage
    reviews: list[ReviewerCacheReview]
