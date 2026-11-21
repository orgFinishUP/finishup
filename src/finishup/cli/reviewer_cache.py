"""Fixed-layout text for ``finishup service diagnostics --reviewer-cache`` (#1172, ADR-006).

Renders the report ``domain.reviewer_cache_report`` builds: integers as written and basis points as
an exact two-place percentage, never a float. Every line is bounded by what the diagnostics log
still holds.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from finishup.protocol.canonical import JsonValue

__all__ = ["reviewer_cache_text"]

type _Object = Mapping[str, JsonValue]


def reviewer_cache_text(report: _Object) -> str:
    """The report as plain lines; the same report always gives the same bytes."""

    coverage = _object(report, "coverage")
    total = _object(report, "total")
    selected = report.get("request_id")
    scope = "all reviews" if selected is None else f"review {selected}"
    lines = [
        f"reviewer prompt cache, {scope}, from the exchange records still in the diagnostics log",
        "(a bounded log: older reviews may be absent, and a review's earliest exchanges may be gone)",
        f"records: {coverage['records_read']} read, {coverage['unreadable_records']} unreadable; "
        f"reviews: {coverage['reviews']}; exchange records: {coverage['exchange_records']}, "
        f"{coverage['duplicate_exchange_records']} duplicate; "
        f"exchanges known missing: {coverage['missing_exchanges']}",
        *_usage_lines(total),
    ]
    for review in cast(list[_Object], report.get("reviews", [])):
        indices = _object(review, "exchange_indices")
        usage = _object(review, "usage")
        share = (
            f"cached share {_share(_object(usage, 'cached_share'))}"
            if _reported_cached(usage)
            else "no exchange reported a cached count"
        )
        lines.append(
            f"review {review['request_id']}: {usage['exchange_records']} exchange records, "
            f"highest index {indices['highest']}, known missing {_ranges(indices)}, "
            f"duplicates {indices['duplicate_records']}, {share}"
        )
    return "\n".join(lines)


def _usage_lines(usage: _Object) -> list[str]:
    share = _object(usage, "cached_share")
    first = _object(usage, "first_turn")
    cold, warm = _object(first, "cold"), _object(first, "warm")
    unknown = _object(first, "cached_unreported")
    beyond = _object(usage, "beyond_prefix")
    uncached = _object(usage, "uncached_input")
    shortfall = _object(uncached, "shortfall")
    unattributed = _object(uncached, "unattributed")
    labels = _object(usage, "miss_labels")
    # Without an exchange that reported a cached count, the share and the uncached split have no
    # basis: one line says so instead of zeros that would read as everything cached.
    cached_lines = (
        [
            f"cached share: {_share(share)} ({share['cached_input_tokens']} of "
            f"{share['input_tokens_of_exchanges_reporting_cached']} input tokens) of the "
            f"{uncached['exchanges']} exchanges still in the diagnostics log that reported a "
            "cached count",
            f"uncached input: {uncached['tokens']} tokens of those exchanges",
            f"  first turn, cold: {uncached['first_turn_cold']}",
            f"  first turn, warm: {uncached['first_turn_warm']}",
            *(f"  shortfall, {name}: {value}" for name, value in shortfall.items()),
            f"  beyond the prefix: {uncached['beyond_prefix']}",
            *(
                f"  unattributed, {name.replace('_', ' ')}: {value}"
                for name, value in unattributed.items()
            ),
        ]
        if _reported_cached(usage)
        else [
            "cached share and uncached input: no exchange still in the diagnostics log reported a "
            "cached count"
        ]
    )
    return [
        f"exchanges: {usage['exchanges_with_counts']} with counts, "
        f"{usage['exchanges_unreported']} unreported, {usage['exchanges_refused']} refused",
        _sum_line("model requests", _object(usage, "model_requests")),
        _sum_line("input tokens", _object(usage, "input_tokens")),
        _sum_line("cached input tokens", _object(usage, "cached_input_tokens")),
        _sum_line("cache-write input tokens", _object(usage, "cache_write_input_tokens")),
        _sum_line("output tokens", _object(usage, "output_tokens")),
        *cached_lines,
        f"first turns: {cold['exchanges']} cold ({cold['input_tokens']} input tokens), "
        f"{warm['exchanges']} warm ({warm['input_tokens']} input tokens, "
        f"{warm['prefix_cached_tokens']} cached), {unknown['exchanges']} without a cached count "
        f"({unknown['input_tokens']} input tokens)",
        f"beyond the prefix: {beyond['input_tokens']} input tokens over {beyond['exchanges']} "
        f"exchanges, {beyond['surplus_cached_tokens']} of them cached",
        "miss labels: " + ", ".join(f"{name} {value}" for name, value in labels.items()),
    ]


def _reported_cached(usage: _Object) -> bool:
    """Whether any exchange the usage covers reported a cached count: the share's basis."""

    return _object(usage, "uncached_input")["exchanges"] != 0


def _sum_line(name: str, value: _Object) -> str:
    if value["sum"] is None:
        return f"{name}: not reported by any exchange"
    return f"{name}: {value['sum']} over {value['exchanges']} exchanges"


def _share(share: _Object) -> str:
    points = share["basis_points_floor"]
    if type(points) is not int:
        return "unknown"
    return f"{points // 100}.{points % 100:02d}%"


def _ranges(indices: _Object) -> str:
    ranges = cast(list[_Object], indices["missing_ranges"])
    if not ranges:
        return "none"
    return ",".join(
        str(item["first"]) if item["first"] == item["last"] else f"{item['first']}-{item['last']}"
        for item in ranges
    )


def _object(source: _Object, name: str) -> _Object:
    return cast(_Object, source[name])
