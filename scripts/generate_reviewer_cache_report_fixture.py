"""Golden vectors for the reviewer cache report, reviewer-cache-report 1.0.0 (#1172, ADR-006).

The input is a realistic slice of the owner-only diagnostics ring: five reviews' ``exchange_cache``
records, each built by the real per-exchange accounting (``domain.reviewer_cache``), plus one line
the diagnostics fence left unreadable. One review spends its repair and then changes its schema,
one opens warm, one has an unreported, a refused and a prefix-unknown exchange, the oldest lost its
first two lines to the ring and saw a compaction, and one was restarted under its request id, so
its first exchange is recorded twice. The expected reports and text are what ``finishup service
diagnostics --reviewer-cache`` prints for all reviews and for one.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Final, cast

from finishup.cli.reviewer_cache import reviewer_cache_text
from finishup.domain.reviewer_cache import (
    ExchangeCacheUsage,
    ReviewerCacheState,
    exchange_cache_counts,
)
from finishup.domain.reviewer_cache_report import reviewer_cache_report
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode

_PATH: Final = "service/reviewer-cache-report-1.0.0.case.json"
_FIXTURE_ID: Final = "CACHE-1172"
_SCHEMA: Final = "service/reviewer-cache-report-1.0.0.schema.json"
_FIRST: Final = ("system", "user", "user")

type _Step = tuple[Sequence[str], str, ExchangeCacheUsage | None, bool, bool]


def _request(n: int) -> str:
    return f"req_11720000-0000-4000-8000-{n:012d}"


def _usage(
    input_tokens: int,
    cached: int | None,
    output_tokens: int,
    *,
    requests: int = 1,
    first_cached: int | None = None,
    last_input: int | None = None,
    cache_write: int | None = None,
) -> ExchangeCacheUsage:
    return ExchangeCacheUsage(
        input_tokens=input_tokens,
        cached_input_tokens=cached,
        output_tokens=output_tokens,
        requests=requests,
        first_cached_tokens=cached if first_cached is None else first_cached,
        last_input_tokens=input_tokens if last_input is None else last_input,
        cache_write_input_tokens=cache_write,
    )


def _step(
    roles: Sequence[str],
    usage: ExchangeCacheUsage | None,
    *,
    settings: str = "turn",
    compacted: bool = False,
    refused: bool = False,
) -> _Step:
    return (roles, settings, usage, compacted, refused)


def _exchanges(review: int, steps: Sequence[_Step]) -> list[dict[str, object]]:
    """The counts each exchange records, by the same state machine every route uses."""

    state = ReviewerCacheState()
    counts: list[dict[str, object]] = []
    for roles, settings, usage, compacted, refused in steps:
        _review, recorded = exchange_cache_counts(
            state,
            request_id=_request(review),
            settings=settings,
            roles=roles,
            usage=usage,
            compacted=compacted,
            usage_refused=refused,
        )
        counts.append(recorded)
    return counts


def _records() -> list[JsonValue]:
    turn = (*_FIRST, "assistant", "user")
    repair = (*turn, "user")
    after_repair = (*repair, "assistant", "user")
    third = (*turn, "assistant", "user")
    fourth = (*third, "assistant", "user")
    # The oldest review (Codex): the ring evicted its first two lines; its third turn compacted.
    oldest = _exchanges(
        4,
        (
            _step(_FIRST, _usage(60_000, 0, 280, cache_write=0)),
            _step(turn, _usage(61_500, 59_904, 260, cache_write=0)),
            _step(third, _usage(40_000, 0, 240, cache_write=0), compacted=True),
            _step(fourth, _usage(42_000, 39_936, 900, cache_write=0)),
        ),
    )[2:]
    # Responses: a read, a malformed answer and its repair, then the read-free final turn.
    repaired = _exchanges(
        1,
        (
            _step(_FIRST, _usage(90_000, 0, 310)),
            _step(turn, _usage(92_000, 89_984, 300)),
            _step(repair, _usage(92_100, 60_032, 290)),
            _step(after_repair, _usage(94_000, 1_024, 1_100), settings="final"),
        ),
    )
    # Codex: a first turn that reused 4,096 tokens another review left, and a turn of two requests.
    warm = _exchanges(
        2,
        (
            _step(_FIRST, _usage(88_000, 4_096, 330, cache_write=0)),
            _step(turn, _usage(89_500, 87_936, 320, cache_write=0)),
            _step(third, _usage(91_000, 89_472, 300, cache_write=0)),
            _step(
                fourth,
                _usage(
                    185_000,
                    150_016,
                    1_200,
                    requests=2,
                    first_cached=88_960,
                    last_input=93_000,
                    cache_write=0,
                ),
            ),
        ),
    )
    # Chat Completions: no cached count on the first answer, then no usage, then refused counts.
    sparse = _exchanges(
        3,
        (
            _step(_FIRST, _usage(70_000, None, 200)),
            _step(turn, None),
            _step(third, _usage(73_000, 71_936, 210)),
            _step(fourth, None, refused=True),
        ),
    )
    # Responses, restarted under the same request id: its first exchange is recorded twice, and
    # the second time reuses what the first attempt left in the provider's cache.
    restarted = [
        *_exchanges(5, (_step(_FIRST, _usage(50_000, 0, 150, cache_write=0)),)),
        *_exchanges(
            5,
            (
                _step(_FIRST, _usage(50_000, 49_920, 150, cache_write=49_920)),
                _step(turn, _usage(51_800, 49_920, 800)),
            ),
        ),
    ]
    ordered: list[tuple[int, str, str, dict[str, object]]] = [
        *((4, "codex_app_server", "completed", item) for item in oldest),
        *((1, "openai_responses", "completed", item) for item in repaired),
        *((2, "codex_app_server", "completed", item) for item in warm),
        *((3, "openai_chat_completions", "completed", item) for item in sparse),
        *((5, "openai_responses", "completed", item) for item in restarted),
    ]
    records: list[JsonValue] = []
    for position, (review, component, reason, counts) in enumerate(ordered, start=1):
        records.append(
            cast(
                JsonValue,
                {
                    "timestamp": f"2026-11-21T09:{position:02d}:00.000Z",
                    "correlation_id": f"err_11720000-0000-4000-8000-{position:012d}",
                    "component": component,
                    "operation": "exchange_cache",
                    "reason": reason,
                    "request_id": _request(review),
                    **counts,
                },
            )
        )
    # A line the diagnostics fence read back as ``unavailable``: an out-of-range input count.
    records.insert(
        6,
        {
            "timestamp": "2026-11-21T09:06:30.000Z",
            "correlation_id": "err_11720000-0000-4000-8000-000000000099",
            "component": "openai_responses",
            "operation": "exchange_cache",
            "reason": "completed",
            "request_id": _request(1),
            "reviewer_exchange_index": 5,
            "reviewer_model_requests": 1,
            "reviewer_input_tokens": "unavailable",
            "reviewer_output_tokens": 40,
        },
    )
    return records


def _expected(records: list[JsonValue], request_id: str | None) -> dict[str, JsonValue]:
    report = reviewer_cache_report(records, request_id=request_id)
    return {
        "report": report,
        "digest": canonical_digest(report),
        "text": reviewer_cache_text(report),
    }


def document() -> dict[str, JsonValue]:
    records = _records()
    return {
        "controls": {
            "clock": "fixture_supplied",
            "external_io": "forbidden",
            "network": "forbidden",
            "randomness": "forbidden",
        },
        "expected": {
            "all_reviews": _expected(records, None),
            "one_review": _expected(records, _request(1)),
            "schema": _SCHEMA,
        },
        "fixture_id": _FIXTURE_ID,
        "fixture_schema": "yoetz.fixture-case/1.0.0",
        "fixture_version": "1.0.0",
        "input": {"records": records, "one_review_request_id": _request(1)},
        "minimum_versions": {"engine": "0.1.0", "reviewer_cache_report_schema": "1.0.0"},
        "owns_requirements": ["ADR-006:reviewer-cache-report", "ISSUE-1172:reviewer-cache-report"],
        "purpose": (
            "Freeze the reviewer cache report: exact per-review and total sums of the "
            "exchange_cache records still in the diagnostics ring, in any record order."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    data = canonical_encode(cast(JsonValue, document()))
    target = root / "fixtures" / _PATH
    manifest_path = root / "fixtures/manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    unrelated = [item for item in manifest["members"] if item["path"] != _PATH]
    if any(item["fixture_id"] == _FIXTURE_ID for item in unrelated):
        raise ValueError("fixture_identity_conflict")
    member = {
        "byte_length": len(data),
        "fixture_id": _FIXTURE_ID,
        "media_type": "application/vnd.yoetz.fixture-case+json",
        "path": _PATH,
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    if args.check:
        if (
            not target.is_file()
            or target.read_bytes() != data
            or [item for item in manifest["members"] if item["path"] == _PATH] != [member]
        ):
            raise ValueError("reviewer_cache_report_fixture_stale")
    else:
        manifest["members"] = sorted([*unrelated, member], key=lambda item: item["path"])
        target.write_bytes(data)
        manifest_path.write_text(json.dumps(manifest) + "\n")
    print("reviewer cache report fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
