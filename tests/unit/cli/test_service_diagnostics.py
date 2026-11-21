"""CLI read surface for durable diagnostic records."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from finishup.cli.app import app
from finishup.observability.diagnostics import append_diagnostic_record

_CORRELATION = "err_cccccccc-cccc-4ccc-8ccc-cccccccccccc"
_NOW = datetime(2026, 7, 27, 15, 30, 0, tzinfo=UTC)
_RUNNER = CliRunner()


def test_service_diagnostics_resolves_correlation_id(tmp_path: Path, monkeypatch: object) -> None:
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "finishup.observability.diagnostics.log_dir",
        lambda: tmp_path,
    )
    append_diagnostic_record(
        correlation_id=_CORRELATION,
        component="service.daemon",
        operation="publish_work_response_projection_failed",
        reason="exception_runtime_error",
        request_id="req_dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        root=tmp_path,
        now=_NOW,
    )
    result = _RUNNER.invoke(
        app,
        ["service", "diagnostics", "--correlation-id", _CORRELATION, "--json"],
    )
    assert result.exit_code == 0
    assert _CORRELATION in result.stdout
    assert "exception_runtime_error" in result.stdout
    assert "publish_work_response_projection_failed" in result.stdout


def test_service_diagnostics_unknown_correlation_exits_one(
    tmp_path: Path, monkeypatch: object
) -> None:
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "finishup.observability.diagnostics.log_dir",
        lambda: tmp_path,
    )
    result = _RUNNER.invoke(
        app,
        [
            "service",
            "diagnostics",
            "--correlation-id",
            "err_00000000-0000-4000-8000-000000000001",
            "--json",
        ],
    )
    assert result.exit_code == 1


def test_request_selector_joins_multiple_failure_stages(
    tmp_path: Path, monkeypatch: object
) -> None:
    monkeypatch.setattr("finishup.observability.diagnostics.log_dir", lambda: tmp_path)  # type: ignore[attr-defined]
    request = "req_dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    for suffix, operation in [
        (1, "semantic_attempt_dispatch_entered_failed"),
        (2, "semantic_terminalize_attempt_failed"),
    ]:
        append_diagnostic_record(
            correlation_id=f"err_00000000-0000-4000-8000-{suffix:012d}",
            component="semantic_attempts",
            operation=operation,
            reason="exception_runtime_error",
            request_id=request,
            root=tmp_path,
            now=_NOW,
        )
    result = _RUNNER.invoke(app, ["service", "diagnostics", "--request-id", request, "--json"])
    assert result.exit_code == 0
    assert "semantic_attempt_dispatch_entered_failed" in result.stdout
    assert "semantic_terminalize_attempt_failed" in result.stdout
    assert request in result.stdout
    invalid = _RUNNER.invoke(
        app,
        [
            "service",
            "diagnostics",
            "--request-id",
            request,
            "--correlation-id",
            _CORRELATION,
            "--json",
        ],
    )
    assert invalid.exit_code != 0


_REVIEW = "req_72000000-0000-4000-8000-000000000001"
_OTHER_REVIEW = "req_72000000-0000-4000-8000-000000000002"


def _exchange(
    root: Path, index: int, review: str, counts: Mapping[str, object], *, minute: int
) -> None:
    append_diagnostic_record(
        correlation_id=f"err_72000000-0000-4000-8000-{minute:012d}",
        component="openai_responses",
        operation="exchange_cache",
        reason="completed",
        request_id=review,
        counts={"reviewer_exchange_index": index, **counts},
        root=root,
        now=_NOW.replace(minute=minute),
    )


def _two_reviews(root: Path) -> None:
    first_turn = {
        "reviewer_model_requests": 1,
        "reviewer_input_tokens": 90_000,
        "reviewer_cached_input_tokens": 0,
        "reviewer_prefix_cached_tokens": 0,
        "reviewer_output_tokens": 300,
        "reviewer_prefix_tokens": 0,
        "reviewer_cache_miss": "first_turn",
    }
    _exchange(root, 1, _REVIEW, first_turn, minute=1)
    _exchange(
        root,
        2,
        _REVIEW,
        {
            "reviewer_model_requests": 1,
            "reviewer_input_tokens": 92_000,
            "reviewer_cached_input_tokens": 89_984,
            "reviewer_prefix_cached_tokens": 89_984,
            "reviewer_output_tokens": 300,
            "reviewer_prefix_tokens": 90_000,
            "reviewer_cache_miss": "none",
        },
        minute=2,
    )
    _exchange(root, 1, _OTHER_REVIEW, first_turn, minute=3)
    _exchange(root, 2, _OTHER_REVIEW, {"reviewer_usage_state": "unreported"}, minute=4)
    # Another operation under the same request id is not an exchange record.
    append_diagnostic_record(
        correlation_id="err_72000000-0000-4000-8000-000000000099",
        component="semantic_attempts",
        operation="semantic_attempt_dispatch_entered_failed",
        reason="exception_runtime_error",
        request_id=_REVIEW,
        root=root,
        now=_NOW,
    )


def test_reviewer_cache_reports_every_review_still_in_the_ring(
    tmp_path: Path, monkeypatch: object
) -> None:
    from finishup.protocol.schemas import validate_schema_instance

    monkeypatch.setattr("finishup.observability.diagnostics.log_dir", lambda: tmp_path)  # type: ignore[attr-defined]
    _two_reviews(tmp_path)
    result = _RUNNER.invoke(app, ["service", "diagnostics", "--reviewer-cache", "--json"])
    assert result.exit_code == 0
    report = json.loads(result.stdout)
    validate_schema_instance("reviewer-cache-report", "1.0.0", report)
    assert report["request_id"] is None
    assert report["coverage"]["records_read"] == 4
    assert report["coverage"]["reviews"] == 2
    assert report["total"]["input_tokens"] == {"sum": 272_000, "exchanges": 3}
    assert report["total"]["exchanges_unreported"] == 1
    assert report["total"]["cached_share"]["basis_points_floor"] == 3_308


def test_reviewer_cache_narrows_to_one_review_by_its_request_id(
    tmp_path: Path, monkeypatch: object
) -> None:
    monkeypatch.setattr("finishup.observability.diagnostics.log_dir", lambda: tmp_path)  # type: ignore[attr-defined]
    _two_reviews(tmp_path)
    result = _RUNNER.invoke(
        app, ["service", "diagnostics", "--reviewer-cache", "--request-id", _REVIEW, "--json"]
    )
    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["request_id"] == _REVIEW
    assert [review["request_id"] for review in report["reviews"]] == [_REVIEW]
    assert report["coverage"]["records_read"] == 2


def test_reviewer_cache_text_is_a_fixed_coverage_bounded_summary(
    tmp_path: Path, monkeypatch: object
) -> None:
    from finishup.cli.reviewer_cache import reviewer_cache_text
    from finishup.domain.reviewer_cache_report import reviewer_cache_report
    from finishup.observability.diagnostics import lookup_exchange_cache_records

    monkeypatch.setattr("finishup.observability.diagnostics.log_dir", lambda: tmp_path)  # type: ignore[attr-defined]
    _two_reviews(tmp_path)
    result = _RUNNER.invoke(app, ["service", "diagnostics", "--reviewer-cache"])
    assert result.exit_code == 0
    expected = reviewer_cache_text(reviewer_cache_report(lookup_exchange_cache_records()))
    assert result.stdout == expected + "\n"
    assert "of the 3 exchanges still in the diagnostics log that reported a cached count" in (
        result.stdout
    )
    assert "cached share: 33.08% (89984 of 272000 input tokens)" in result.stdout
    assert "cache-write input tokens: not reported by any exchange" in result.stdout


def test_reviewer_cache_json_prints_a_report_at_the_counter_bound_and_exits_zero(
    tmp_path: Path, monkeypatch: object
) -> None:
    from finishup.protocol.schemas import validate_schema_instance

    monkeypatch.setattr("finishup.observability.diagnostics.log_dir", lambda: tmp_path)  # type: ignore[attr-defined]
    top = 2**53 - 1
    at_bound = {
        "reviewer_model_requests": 1,
        "reviewer_input_tokens": top,
        "reviewer_cached_input_tokens": 0,
        "reviewer_prefix_cached_tokens": 0,
        "reviewer_output_tokens": top,
        "reviewer_prefix_tokens": 0,
        "reviewer_cache_miss": "first_turn",
    }
    _exchange(tmp_path, 1, _REVIEW, at_bound, minute=1)
    _exchange(tmp_path, 1, _OTHER_REVIEW, at_bound, minute=2)
    result = _RUNNER.invoke(app, ["service", "diagnostics", "--reviewer-cache", "--json"])
    assert result.exit_code == 0
    report = json.loads(result.stdout)
    validate_schema_instance("reviewer-cache-report", "1.0.0", report)
    # The second record would carry the totals past the bound, so it is counted unreadable.
    assert report["coverage"]["records_read"] == 2
    assert report["coverage"]["unreadable_records"] == 1
    assert report["total"]["input_tokens"] == {"sum": top, "exchanges": 1}
    text = _RUNNER.invoke(app, ["service", "diagnostics", "--reviewer-cache"])
    assert text.exit_code == 0 and "1 unreadable" in text.stdout


def test_reviewer_cache_text_without_a_cached_count_shows_no_zero_share(
    tmp_path: Path, monkeypatch: object
) -> None:
    monkeypatch.setattr("finishup.observability.diagnostics.log_dir", lambda: tmp_path)  # type: ignore[attr-defined]
    # A Chat Completions endpoint may omit the cached count: every exchange has counts but that.
    for index, (prefix, label) in enumerate(((0, "first_turn"), (70_000, None)), start=1):
        _exchange(
            tmp_path,
            index,
            _REVIEW,
            {
                "reviewer_model_requests": 1,
                "reviewer_input_tokens": 70_000 + index,
                "reviewer_output_tokens": 300,
                "reviewer_prefix_tokens": prefix,
                **({} if label is None else {"reviewer_cache_miss": label}),
            },
            minute=index,
        )
    result = _RUNNER.invoke(app, ["service", "diagnostics", "--reviewer-cache"])
    assert result.exit_code == 0
    lines = result.stdout.splitlines()
    assert (
        "cached share and uncached input: no exchange still in the diagnostics log reported a "
        "cached count"
    ) in lines
    assert "cached input tokens: not reported by any exchange" in lines
    assert not any(line.startswith(("cached share:", "uncached input:", "  ")) for line in lines), (
        result.stdout
    )
    assert lines[-1] == (
        f"review {_REVIEW}: 2 exchange records, highest index 2, known missing none, "
        "duplicates 0, no exchange reported a cached count"
    )


def test_reviewer_cache_text_for_an_empty_selection_shows_no_zero_share(
    tmp_path: Path, monkeypatch: object
) -> None:
    monkeypatch.setattr("finishup.observability.diagnostics.log_dir", lambda: tmp_path)  # type: ignore[attr-defined]
    _two_reviews(tmp_path)
    absent = "req_72000000-0000-4000-8000-000000000003"
    result = _RUNNER.invoke(
        app, ["service", "diagnostics", "--reviewer-cache", "--request-id", absent]
    )
    assert result.exit_code == 1
    lines = result.stdout.splitlines()
    assert lines[0].startswith(f"reviewer prompt cache, review {absent},")
    assert (
        "cached share and uncached input: no exchange still in the diagnostics log reported a "
        "cached count"
    ) in lines
    assert "input tokens: not reported by any exchange" in lines
    assert not any(
        line.startswith(("cached share:", "uncached input:", "  ", "review req_")) for line in lines
    ), result.stdout


def test_reviewer_cache_text_says_missing_indices_are_only_those_known(
    tmp_path: Path, monkeypatch: object
) -> None:
    monkeypatch.setattr("finishup.observability.diagnostics.log_dir", lambda: tmp_path)  # type: ignore[attr-defined]
    _exchange(tmp_path, 3, _REVIEW, {"reviewer_usage_state": "unreported"}, minute=1)
    result = _RUNNER.invoke(app, ["service", "diagnostics", "--reviewer-cache"])
    assert result.exit_code == 0
    assert result.stdout.splitlines()[-1] == (
        f"review {_REVIEW}: 1 exchange records, highest index 3, known missing 1-2, "
        "duplicates 0, no exchange reported a cached count"
    )


def test_reviewer_cache_with_an_empty_ring_prints_the_empty_report_and_exits_one(
    tmp_path: Path, monkeypatch: object
) -> None:
    monkeypatch.setattr("finishup.observability.diagnostics.log_dir", lambda: tmp_path)  # type: ignore[attr-defined]
    result = _RUNNER.invoke(app, ["service", "diagnostics", "--reviewer-cache", "--json"])
    assert result.exit_code == 1
    report = json.loads(result.stdout)
    assert report["coverage"]["records_read"] == 0 and report["reviews"] == []


def test_reviewer_cache_keeps_the_selector_rules(tmp_path: Path, monkeypatch: object) -> None:
    monkeypatch.setattr("finishup.observability.diagnostics.log_dir", lambda: tmp_path)  # type: ignore[attr-defined]
    _two_reviews(tmp_path)
    with_correlation = _RUNNER.invoke(
        app,
        ["service", "diagnostics", "--reviewer-cache", "--correlation-id", _CORRELATION, "--json"],
    )
    assert with_correlation.exit_code == 2
    malformed = _RUNNER.invoke(
        app, ["service", "diagnostics", "--reviewer-cache", "--request-id", "req_bad", "--json"]
    )
    assert malformed.exit_code == 2
    # Without --reviewer-cache, exactly one selector is still required.
    no_selector = _RUNNER.invoke(app, ["service", "diagnostics", "--json"])
    assert no_selector.exit_code == 2
    # The request selector still returns every record of that id, exchange records included.
    joined = _RUNNER.invoke(app, ["service", "diagnostics", "--request-id", _REVIEW, "--json"])
    assert joined.exit_code == 0
    assert json.loads(joined.stdout)["count"] == 3
