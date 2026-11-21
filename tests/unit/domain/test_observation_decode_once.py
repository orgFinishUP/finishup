"""Decoding a stored envelope walks its structural payload once, with the same outcomes as before.

``observation_envelope_from_json`` validates the payload while evaluating the constructor's
arguments; ``ObservationEnvelope.__post_init__`` used to validate that same object a second time.
The reference below is the previous decode, kept so every accepted and rejected wire is compared
against it, including which error wins when several fields are wrong at once.
"""

from __future__ import annotations

import itertools
import threading
from typing import cast

import pytest

from finishup.domain import observation
from finishup.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationSource,
    observation_cursor_from_json,
    observation_envelope_from_json,
    observation_envelope_to_json,
)
from finishup.domain.values import JsonObject, JsonValue, Timestamp, timestamp_from_string
from finishup.protocol.errors import ProtocolValueError

_COMMITMENT = "hmac-sha256:" + "a" * 64


def _reference_from_json(value: JsonValue) -> ObservationEnvelope:
    if type(value) is not JsonObject:
        raise observation._invalid()  # pyright: ignore[reportPrivateUsage]
    source = value
    required = (
        "session_commitment",
        "event_kind",
        "source_identity",
        "source",
        "cursor",
        "receipt_time",
        "structural_payload",
        "content_object_refs",
        "gap_codes",
    )
    if set(source) != set(required):
        raise observation._invalid()  # pyright: ignore[reportPrivateUsage]
    try:
        observation_source = ObservationSource(cast(str, source["source"]))
    except ValueError as exc:
        raise observation._invalid("invalid_event_enum") from exc  # pyright: ignore[reportPrivateUsage]
    return ObservationEnvelope(
        session_commitment=cast(str, source["session_commitment"]),
        event_kind=cast(str, source["event_kind"]),
        source_identity=cast(str, source["source_identity"]),
        source=observation_source,
        cursor=observation_cursor_from_json(source["cursor"]),
        receipt_time=timestamp_from_string(source["receipt_time"]),
        structural_payload=observation._structural_payload(source["structural_payload"]),  # pyright: ignore[reportPrivateUsage]
        content_object_refs=observation._content_object_refs(source["content_object_refs"]),  # pyright: ignore[reportPrivateUsage]
        gap_codes=observation._sorted_unique_gap_codes(source["gap_codes"]),  # pyright: ignore[reportPrivateUsage]
    )


def _valid_wire() -> JsonObject:
    envelope = ObservationEnvelope(
        session_commitment=_COMMITMENT,
        event_kind="PostToolUse",
        source_identity="hook:1",
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=0,
            event_position=0,
            last_source_commitment=_COMMITMENT,
            mapping_version="codex-obs-1",
        ),
        receipt_time=Timestamp("2026-07-22T21:00:00.000Z"),
        structural_payload=JsonObject({"tool_name": "shell", "exit_status": 0}),
        content_object_refs=(),
        gap_codes=("unsupported_event",),
    )
    return observation_envelope_to_json(envelope)


_BAD_FIELDS: dict[str, tuple[JsonValue, ...]] = {
    "session_commitment": ("/tmp/session.jsonl", 7),
    "event_kind": ("has spaces", None),
    "source_identity": ("", 3),
    "source": ("not-a-source",),
    "cursor": (JsonObject({}), "cursor"),
    "receipt_time": ("2026-02-30T00:00:00.000Z", 5),
    "structural_payload": (
        JsonObject({"transcript": "prose"}),
        JsonObject({"cwd": "/workspace"}),
        "payload",
    ),
    "content_object_refs": (("not-a-digest",), "refs"),
    "gap_codes": (("zz_unknown_gap",), ("unsupported_event", "unsupported_event")),
}


def _outcome(decode: object, wire: JsonValue) -> tuple[object, ...]:
    assert callable(decode)
    try:
        envelope = decode(wire)
    except ProtocolValueError as exc:
        return ("rejected", exc.reason_code, exc.field, type(exc.__cause__))
    assert type(envelope) is ObservationEnvelope
    return ("accepted", observation_envelope_to_json(envelope))


def _mutated(**changes: JsonValue) -> JsonObject:
    wire = dict(_valid_wire())
    wire.update(changes)
    return JsonObject(wire)


def test_valid_wire_decodes_identically() -> None:
    wire = _valid_wire()
    assert _outcome(observation_envelope_from_json, wire) == _outcome(_reference_from_json, wire)


def test_every_single_and_paired_bad_field_fails_identically() -> None:
    singles = [(name, bad) for name, bads in _BAD_FIELDS.items() for bad in bads]
    for name, bad in singles:
        wire = _mutated(**{name: bad})
        assert _outcome(observation_envelope_from_json, wire) == _outcome(
            _reference_from_json, wire
        ), name
    for (first, first_bad), (second, second_bad) in itertools.combinations(singles, 2):
        if first == second:
            continue
        wire = _mutated(**{first: first_bad, second: second_bad})
        assert _outcome(observation_envelope_from_json, wire) == _outcome(
            _reference_from_json, wire
        ), (first, second)


def _count_payload_walks(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    calls: list[object] = []
    original = observation._structural_payload  # pyright: ignore[reportPrivateUsage]

    def counting(value: object) -> JsonObject:
        calls.append(value)
        return original(value)

    monkeypatch.setattr(observation, "_structural_payload", counting)
    return calls


def test_decode_walks_the_payload_once(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = _valid_wire()
    calls = _count_payload_walks(monkeypatch)
    for _ in range(3):
        observation_envelope_from_json(wire)
    assert len(calls) == 3


def test_direct_construction_still_validates_the_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    decoded = observation_envelope_from_json(_valid_wire())
    calls = _count_payload_walks(monkeypatch)
    ObservationEnvelope(
        session_commitment=decoded.session_commitment,
        event_kind=decoded.event_kind,
        source_identity=decoded.source_identity,
        source=decoded.source,
        cursor=decoded.cursor,
        receipt_time=decoded.receipt_time,
        structural_payload=decoded.structural_payload,
        content_object_refs=decoded.content_object_refs,
        gap_codes=decoded.gap_codes,
    )
    assert calls == [decoded.structural_payload]
    with pytest.raises(ProtocolValueError):
        ObservationEnvelope(
            session_commitment=decoded.session_commitment,
            event_kind=decoded.event_kind,
            source_identity=decoded.source_identity,
            source=decoded.source,
            cursor=decoded.cursor,
            receipt_time=decoded.receipt_time,
            structural_payload=cast(JsonObject, None),
            content_object_refs=decoded.content_object_refs,
            gap_codes=decoded.gap_codes,
        )


def test_the_skip_marker_is_cleared_after_a_failed_decode(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = JsonObject({"tool_name": "shell"})
    with pytest.raises(ProtocolValueError):
        observation_envelope_from_json(
            _mutated(session_commitment="/tmp/session.jsonl", structural_payload=payload)
        )
    marker = observation._PREVALIDATED_STRUCTURAL_PAYLOAD  # pyright: ignore[reportPrivateUsage]
    assert type(marker.get()) is object


def test_the_skip_marker_is_local_to_the_decoding_thread() -> None:
    seen: list[object] = []
    wire = _valid_wire()
    marker = observation._PREVALIDATED_STRUCTURAL_PAYLOAD  # pyright: ignore[reportPrivateUsage]
    original_post_init = ObservationEnvelope.__post_init__

    def observing() -> None:
        thread = threading.Thread(target=lambda: seen.append(marker.get()))
        thread.start()
        thread.join()

    def post_init(self: ObservationEnvelope) -> None:
        observing()
        original_post_init(self)

    ObservationEnvelope.__post_init__ = post_init  # type: ignore[method-assign]
    try:
        observation_envelope_from_json(wire)
    finally:
        ObservationEnvelope.__post_init__ = original_post_init  # type: ignore[method-assign]
    assert len(seen) == 1
    assert type(seen[0]) is object
