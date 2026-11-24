"""Per-exchange prompt-cache telemetry every reviewer route records (#1172, ADR-006).

Each provider exchange writes one ``exchange_cache`` owner diagnostic: the provider-reported input,
cached input, cache-write (where the provider reports it) and output tokens, the prefix the
exchange could reuse from the review's earlier exchanges, and the closed miss label
``domain.reviewer_cache`` derives; an exchange without counts records its index and the closed
``reviewer_usage_state`` instead. Only integers, those closed tokens and the review's first
provider request id are recorded. Telemetry never changes an outcome: any failure here is dropped.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from finishup.domain.reviewer_cache import (
    ExchangeCacheUsage,
    ReviewerCacheState,
    exchange_cache_counts,
)
from finishup.observability.logging import record_bounded_counts_without_raising
from finishup.ports.semantic import ReviewerExchange, ReviewerSession
from finishup.protocol.canonical import JsonValue, canonical_digest

__all__ = ["api_exchange_usage", "record_exchange_cache"]

# The bound ``ExchangeCacheUsage`` holds every counter to: an exact JSON integer.
_MAX_COUNTER: Final = 2**53 - 1


def api_exchange_usage(
    usage: object, *, input_name: str, details_name: str, output_name: str
) -> ExchangeCacheUsage | None:
    """One stateless API request's reported usage, or ``None`` without input and output counts.

    Responses reports ``input_tokens``/``output_tokens`` and, in ``input_tokens_details``,
    ``cached_tokens`` and ``cache_write_tokens``; Chat Completions ``prompt_tokens``/
    ``completion_tokens`` and the same two in ``prompt_tokens_details``, which the SDK types as
    optional. Input and output must each be a plain integer counter, or there is no usage. A cached
    count is kept only when it is one and at most the input, a cache-write count only when it is
    one: an optional count the answer omits or reports inconsistently stays unknown, never zero,
    and never discards the input and output counts, so the input still becomes the next
    exchange's prefix (#1172). ``None`` for a present ``usage`` object means FinishUP refused its
    counts; the caller records that as ``usage_refused``, and an absent one as unreported.
    """

    try:
        input_tokens = getattr(usage, input_name, None)
        output_tokens = getattr(usage, output_name, None)
    except Exception:  # noqa: BLE001 - an unexpected SDK shape is no usage, never a failure
        return None
    input_count, output_count = _counter(input_tokens), _counter(output_tokens)
    if input_count is None or output_count is None:
        return None
    # Each optional read stands alone: one that fails is that count unknown, never the exchange's.
    details = _optional(usage, details_name)
    cached = _counter(_optional(details, "cached_tokens"))
    if cached is not None and cached > input_count:
        cached = None
    write_tokens = _optional(details, "cache_write_tokens")
    try:
        return ExchangeCacheUsage(
            input_count,
            cached,
            output_count,
            1,
            cached,
            input_count,
            cache_write_input_tokens=_counter(write_tokens),
        )
    except ValueError:
        return None


def _optional(source: object, name: str) -> object:
    """``source.name``, or ``None`` when it is absent or reading it raises."""

    try:
        return getattr(source, name, None)
    except Exception:  # noqa: BLE001 - an unreadable optional count is unknown, never a failure
        return None


def _counter(value: object) -> int | None:
    """``value`` when it is a plain integer within the counter range, else ``None``."""

    return value if type(value) is int and 0 <= value <= _MAX_COUNTER else None


def record_exchange_cache(
    *,
    component: str,
    request_id: str,
    session: ReviewerSession | None,
    exchange: ReviewerExchange | None,
    settings: Mapping[str, JsonValue],
    usage: ExchangeCacheUsage | None,
    completed: bool,
    compacted: bool = False,
    usage_refused: bool = False,
) -> None:
    """Account one exchange in its review's cache state and record it, never raising.

    ``settings`` is what the route sent beside the messages; only its digest is kept, to notice a
    change between a review's exchanges. A one-shot case (no review session) opens its own
    conversation. Without ``usage``, ``usage_refused`` says FinishUP refused the counts the
    provider reported rather than the provider reporting none.
    """

    try:
        state = (
            session.cache if exchange is not None and session is not None else ReviewerCacheState()
        )
        review_request, counts = exchange_cache_counts(
            state,
            request_id=request_id,
            settings=canonical_digest(dict(settings)),
            roles=() if exchange is None else tuple(role for role, _text in exchange.history),
            usage=usage,
            compacted=compacted,
            usage_refused=usage_refused,
        )
        record_bounded_counts_without_raising(
            component=component,
            operation="exchange_cache",
            outcome="completed" if completed else "incomplete",
            counts=counts,
            request_id=review_request,
        )
    except Exception:  # noqa: BLE001 - telemetry is never allowed to change a review
        return
