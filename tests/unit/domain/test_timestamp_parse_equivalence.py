"""The fixed-position timestamp parser accepts, rejects and returns exactly what strptime did.

``parse_rfc3339_millis`` used to build its ``datetime`` through ``datetime.strptime``, which
imports ``_strptime`` and its locale machinery on first use. The reference below is that previous
implementation, kept verbatim so every input is compared against it: the accepted set, the
rejected set, the reason code, the chained cause type and the resulting value must not move.
"""

from __future__ import annotations

import itertools
import subprocess
import sys
from datetime import UTC, datetime

import pytest
from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st

from finishup.domain import values
from finishup.domain.values import (
    Timestamp,
    format_rfc3339_millis,
    parse_rfc3339_millis,
    timestamp_from_string,
)
from finishup.protocol.errors import ProtocolValueError


def _reference_parse(value: object) -> datetime:
    if type(value) is not str or values._RFC3339_MILLIS_PATTERN.fullmatch(value) is None:  # pyright: ignore[reportPrivateUsage]
        raise ProtocolValueError("invalid_timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise ProtocolValueError("invalid_timestamp") from exc
    normalized = parsed.replace(tzinfo=UTC)
    if format_rfc3339_millis(normalized) != value:
        raise ProtocolValueError("invalid_timestamp")
    return normalized


def _reference_timestamp_from_string(value: object) -> Timestamp:
    _reference_parse(value)
    return Timestamp(str(value))


type _Outcome = tuple[str, object, object, object]


def _outcome(function: object, value: object) -> _Outcome:
    assert callable(function)
    try:
        result = function(value)
    except ProtocolValueError as exc:
        cause = exc.__cause__
        return ("rejected", exc.reason_code, type(cause), type(exc))
    except Exception as exc:  # any other escape must match too
        return ("raised", type(exc), str(exc), None)
    if isinstance(result, datetime):
        return ("accepted", result, result.tzinfo is UTC, type(result))
    assert type(result) is Timestamp
    return ("accepted", result.wire, type(result.wire), result.as_datetime())


def _assert_same(value: object) -> None:
    assert _outcome(parse_rfc3339_millis, value) == _outcome(_reference_parse, value), value
    assert _outcome(timestamp_from_string, value) == _outcome(
        _reference_timestamp_from_string, value
    ), value


_YEARS = ("0000", "0001", "0999", "1900", "1970", "2000", "2023", "2024", "2100", "9999")
_MONTHS = tuple(f"{month:02d}" for month in range(14))
_DAYS = tuple(f"{day:02d}" for day in range(33))


def test_every_calendar_date_edge_matches_strptime() -> None:
    """Day 31 in short months, Feb 29 on (non-)leap years, month 00/13, year 0000/9999."""

    for year, month, day in itertools.product(_YEARS, _MONTHS, _DAYS):
        _assert_same(f"{year}-{month}-{day}T12:34:56.789Z")


def test_every_clock_edge_matches_strptime() -> None:
    """Hour 24/25, minute 60, leap seconds 60/61, second 62, millisecond bounds."""

    for hour, minute, second, millis in itertools.product(
        tuple(f"{hour:02d}" for hour in range(26)),
        ("00", "30", "59", "60", "99"),
        ("00", "59", "60", "61", "62", "99"),
        ("000", "001", "500", "999"),
    ):
        _assert_same(f"2024-02-29T{hour}:{minute}:{second}.{millis}Z")
        _assert_same(f"9999-12-31T{hour}:{minute}:{second}.{millis}Z")


class _StrSubclass(str):
    __slots__ = ()


@pytest.mark.parametrize(
    "value",
    [
        "2024-01-02T03:04:05.006Z",
        "2024-01-02t03:04:05.006Z",
        "2024-01-02T03:04:05.006z",
        " 2024-01-02T03:04:05.006Z",
        "2024-01-02T03:04:05.006Z ",
        "2024-01-02T03:04:05.006Z\n",
        "2024-01-02 03:04:05.006Z",
        "2024-01-02T03:04:05Z",
        "2024-01-02T03:04:05.06Z",
        "2024-01-02T03:04:05.0060Z",
        "2024-01-02T03:04:05.006+00:00",
        "2024-1-02T03:04:05.006Z",
        "+2024-01-02T03:04:05.006Z",
        "２０２４-01-02T03:04:05.006Z",
        "٢٠٢٤-01-02T03:04:05.006Z",
        "2024-01-02T03:04:05.٠٠٦Z",
        "",
        "Z",
        _StrSubclass("2024-01-02T03:04:05.006Z"),
        b"2024-01-02T03:04:05.006Z",
        None,
        0,
        1.5,
        datetime(2024, 1, 2, 3, 4, 5, 6000, tzinfo=UTC),
        ["2024-01-02T03:04:05.006Z"],
    ],
)
def test_named_odd_inputs_match_strptime(value: object) -> None:
    _assert_same(value)


_DIGITS = st.sampled_from("0123456789")


@st.composite
def _near_timestamps(draw: st.DrawFn) -> str:
    fields = [
        draw(st.text(_DIGITS, min_size=size, max_size=size)) for size in (4, 2, 2, 2, 2, 2, 3)
    ]
    return "{}-{}-{}T{}:{}:{}.{}Z".format(*fields)


@given(st.one_of(_near_timestamps(), st.text(max_size=30)))
@example("1900-02-29T00:00:00.000Z")
@example("2000-02-29T00:00:00.000Z")
@example("2023-04-31T23:59:59.999Z")
@settings(deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_generated_inputs_match_strptime(value: str) -> None:
    _assert_same(value)


def test_parsing_does_not_import_strptime() -> None:
    """The parse no longer loads ``_strptime`` (and its locale/calendar imports)."""

    code = (
        "import sys\n"
        "from finishup.domain.values import parse_rfc3339_millis, timestamp_from_string\n"
        "parse_rfc3339_millis('2024-01-02T03:04:05.006Z')\n"
        "timestamp_from_string('2024-01-02T03:04:05.006Z')\n"
        "print('_strptime' in sys.modules)\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert completed.stdout == "False\n"


def test_timestamp_from_string_parses_once(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []
    original = values.parse_rfc3339_millis

    def counting(value: object) -> datetime:
        calls.append(value)
        return original(value)

    monkeypatch.setattr(values, "parse_rfc3339_millis", counting)
    timestamp_from_string("2024-01-02T03:04:05.006Z")
    assert calls == ["2024-01-02T03:04:05.006Z"]
