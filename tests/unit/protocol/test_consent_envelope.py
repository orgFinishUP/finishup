"""Consent envelopes: strict parsing, the canonical form and digest, and each field's order."""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from finishup.protocol.canonical import JsonValue
from finishup.protocol.consent_envelope import (
    ConsentEnvelope,
    EnvelopeError,
    Retention,
    canonical_bytes,
    compare,
    consentable,
    envelope_digest,
    envelope_from_json,
    envelope_to_json,
    precedes,
    retention_from_token,
    retention_to_json,
)

_IDENTITY = "sha256:" + "ab" * 32


def _document(**changes: Any) -> dict[str, JsonValue]:
    document: dict[str, Any] = {
        "schema": "yoetz.consent-envelope/1",
        "endpoint": {
            "kind": "https",
            "origin": "https://finishup.example:443/team",
            "identity_type": "tls_pin",
            "identity": _IDENTITY,
        },
        "principal": {"key_id": "key-1", "principal": "owner"},
        "key_scope": ["agent", "tasks"],
        "level": "L2",
        "required_min": "L1",
        "code_sync": {"methods": ["git_export"], "max_repo_bytes": 1000, "max_file_bytes": 100},
        "retention": {"kind": "days", "days": 30},
        "exclusions": [".env", "*.pem"],
        "review": {
            "ai_review": "server_policy",
            "provider_disclosure": "provider-a",
            "fallback_disclosure": None,
        },
        "disclosure_version": 2,
    }
    for key, value in changes.items():
        if "." in key:
            parent, name = key.split(".")
            document[parent] = {**document[parent], name: value}
        else:
            document[key] = value
    return document


def _envelope(**changes: Any) -> ConsentEnvelope:
    return envelope_from_json(_document(**changes))


# --- canonical form ---------------------------------------------------------------------------


def test_the_canonical_bytes_and_digest_are_fixed() -> None:
    envelope = _envelope()
    expected = (
        b'{"code_sync":{"max_file_bytes":100,"max_repo_bytes":1000,"methods":["git_export"]},'
        b'"disclosure_version":2,"endpoint":{"identity":"' + _IDENTITY.encode() + b'",'
        b'"identity_type":"tls_pin","kind":"https","origin":"https://finishup.example:443/team"},'
        b'"exclusions":["*.pem",".env"],"key_scope":["agent","tasks"],"level":"L2",'
        b'"principal":{"key_id":"key-1","principal":"owner"},"required_min":"L1",'
        b'"retention":{"days":30,"kind":"days"},'
        b'"review":{"ai_review":"server_policy","fallback_disclosure":null,'
        b'"provider_disclosure":"provider-a"},'
        b'"schema":"yoetz.consent-envelope/1"}'
    )
    assert canonical_bytes(envelope) == expected
    assert (
        envelope_digest(envelope)
        == "sha256:" + hashlib.sha256(b"yoetz/consent-envelope/v1\x00" + expected).hexdigest()
    )
    # The order members and set items arrive in changes nothing.
    shuffled = _document(key_scope=["tasks", "agent"], exclusions=[".env", "*.pem"])
    assert envelope_digest(envelope_from_json(dict(reversed(shuffled.items())))) == (
        envelope_digest(envelope)
    )
    assert envelope_from_json(canonical_bytes(envelope)) == envelope
    assert envelope_to_json(envelope_from_json(envelope_to_json(envelope))) == envelope_to_json(
        envelope
    )


def test_an_unknown_member_or_value_is_kept_named_and_never_consentable() -> None:
    known = _envelope()
    assert consentable(known)
    extra = envelope_from_json({**_document(), "telemetry": {"to": "elsewhere"}})
    nested = _envelope(**{"review.share_with": "everyone"})
    level = _envelope(level="L3")
    retention = _envelope(retention={"kind": "forever", "days": None})
    assert extra.unknown_paths == {"telemetry"}
    assert nested.unknown_paths == {"review.share_with"}
    assert level.unknown_paths == {"level"}
    assert retention.unknown_paths == {"retention.kind"}
    for envelope in (extra, nested, level, retention):
        assert not consentable(envelope)
        assert envelope_digest(envelope) != envelope_digest(known)
    # Nothing unknown is dropped from the canonical form.
    assert b'"telemetry":{"to":"elsewhere"}' in canonical_bytes(extra)
    assert b'"share_with":"everyone"' in canonical_bytes(nested)
    assert envelope_from_json(canonical_bytes(extra)) == extra


@pytest.mark.parametrize(
    ("document", "reason"),
    [
        ([], "envelope_not_object"),
        ({**_document(), "schema": "yoetz.consent-envelope/2"}, "envelope_schema_invalid"),
        ({k: v for k, v in _document().items() if k != "level"}, "envelope_field_missing"),
        (_document(level=2), "envelope_field_invalid"),
        (_document(key_scope=["agent", "agent"]), "envelope_field_invalid"),
        (_document(key_scope=["Agent Scope"]), "envelope_field_invalid"),
        (_document(exclusions=["bad\npattern"]), "envelope_field_invalid"),
        (_document(retention={"kind": "days", "days": 0}), "envelope_field_invalid"),
        (_document(retention={"kind": "task_close", "days": 3}), "envelope_field_invalid"),
        (_document(**{"endpoint.identity": None}), "envelope_field_invalid"),
        (_document(**{"endpoint.identity_type": "tls_system_ca"}), "envelope_field_invalid"),
        (_document(**{"endpoint.origin": "https://a b"}), "envelope_field_invalid"),
        (
            _document(
                review={
                    "ai_review": "none",
                    "provider_disclosure": "x",
                    "fallback_disclosure": None,
                }
            ),
            "envelope_field_invalid",
        ),
        # A fallback is the provider used when the first one fails: never one alone, and never
        # beside no review at all (ADR-052, review of layer 3: A1).
        (
            _document(
                review={
                    "ai_review": "server_policy",
                    "provider_disclosure": None,
                    "fallback_disclosure": "provider-b",
                }
            ),
            "envelope_field_invalid",
        ),
        (
            _document(
                review={
                    "ai_review": "none",
                    "provider_disclosure": None,
                    "fallback_disclosure": "x",
                }
            ),
            "envelope_field_invalid",
        ),
        (
            _document(review={"ai_review": "server_policy", "provider_disclosure": "provider-a"}),
            "envelope_field_missing",
        ),
        (_document(disclosure_version=0), "envelope_field_invalid"),
        (
            _document(code_sync={"methods": [], "max_repo_bytes": 1, "max_file_bytes": 1}),
            "envelope_field_invalid",
        ),
        ({**_document(), "Bad Member": 1}, "envelope_member_invalid"),
    ],
)
def test_a_malformed_envelope_is_refused_with_a_closed_reason(
    document: JsonValue, reason: str
) -> None:
    with pytest.raises(EnvelopeError) as raised:
        envelope_from_json(document)
    assert raised.value.reason == reason


def test_bytes_that_are_not_strict_json_are_refused() -> None:
    with pytest.raises(EnvelopeError) as raised:
        envelope_from_json(b'{"schema": 1.5}')
    assert raised.value.reason == "envelope_not_json"
    with pytest.raises(EnvelopeError) as too_large:
        envelope_from_json(b" " * 70_000)
    assert too_large.value.reason == "envelope_too_large"


# --- the order and the verdicts ---------------------------------------------------------------


def test_identical_envelopes_are_the_same() -> None:
    assert compare(_envelope(), _envelope()).verdict == "same"


@pytest.mark.parametrize(
    ("changes", "coverage_reduced"),
    [
        ({"level": "L1", "code_sync": None, "retention": None}, {"level", "code_sync"}),
        ({"key_scope": ["agent"]}, set[str]()),
        ({"code_sync.max_repo_bytes": 500}, {"code_sync"}),
        ({"code_sync": None}, {"code_sync"}),
        ({"retention": {"kind": "days", "days": 7}}, set[str]()),
        ({"retention": None}, set[str]()),
        ({"exclusions": [".env", "*.pem", "secrets/"]}, {"exclusions"}),
        (
            {
                "review": {
                    "ai_review": "none",
                    "provider_disclosure": None,
                    "fallback_disclosure": None,
                }
            },
            {"review"},
        ),
        ({"required_min": None}, set[str]()),
    ],
)
def test_a_current_envelope_that_sends_or_keeps_less_is_narrower(
    changes: dict[str, Any], coverage_reduced: set[str]
) -> None:
    consented, current = _envelope(), _envelope(**changes)
    result = compare(consented, current)
    assert result.verdict == "narrower"
    assert result.coverage_reduced == coverage_reduced
    assert precedes(current, consented)
    assert not precedes(consented, current)


@pytest.mark.parametrize(
    ("changes", "widened", "changed"),
    [
        # L1 to L2 widens: a copy of the code would be kept (never narrowing).
        ({"key_scope": ["agent", "tasks", "admin"]}, {"key_scope"}, set[str]()),
        ({"code_sync.max_file_bytes": 1000}, {"code_sync"}, set[str]()),
        ({"retention": {"kind": "until_forgotten", "days": None}}, {"retention"}, set[str]()),
        ({"exclusions": [".env"]}, {"exclusions"}, set[str]()),
        # Exact pattern strings only: '*.key' is not read as covering anything else.
        ({"exclusions": [".env", "*.key"]}, set[str](), {"exclusions"}),
        ({"key_scope": ["agent", "admin"]}, set[str](), {"key_scope"}),
        ({"retention": {"kind": "task_close", "days": None}}, set[str](), {"retention"}),
        ({"endpoint.origin": "https://other.example:443/team"}, set[str](), {"endpoint"}),
        ({"endpoint.identity": "sha256:" + "cd" * 32}, set[str](), {"endpoint"}),
        ({"principal": {"key_id": "key-2", "principal": "owner"}}, set[str](), {"principal"}),
        ({"disclosure_version": 3}, set[str](), {"disclosure_version"}),
        ({"review.provider_disclosure": "provider-b"}, set[str](), {"review"}),
        # Every provider is named: a fallback added, or the two swapped, is asked about again.
        ({"review.fallback_disclosure": "provider-b"}, set[str](), {"review"}),
        (
            {
                "review": {
                    "ai_review": "server_policy",
                    "provider_disclosure": "provider-b",
                    "fallback_disclosure": "provider-a",
                }
            },
            set[str](),
            {"review"},
        ),
        (
            {"code_sync": {"methods": ["other"], "max_repo_bytes": 1, "max_file_bytes": 1}},
            set[str](),
            {"code_sync"},
        ),
    ],
)
def test_a_wider_or_incomparable_envelope_is_asked_about_again(
    changes: dict[str, Any], widened: set[str], changed: set[str]
) -> None:
    consented, current = _envelope(), _envelope(**changes)
    result = compare(consented, current)
    assert (result.verdict, result.widened, result.changed) == ("ask_again", widened, changed)
    assert not precedes(current, consented)


def test_l1_to_l2_is_a_widening_and_l2_to_l1_a_narrowing_that_reduces_coverage() -> None:
    l1 = _envelope(level="L1", required_min=None, code_sync=None, retention=None)
    l2 = _envelope(required_min=None)
    up = compare(l1, l2)
    assert up.verdict == "ask_again"
    assert {"level", "code_sync", "retention"} <= up.widened
    down = compare(l2, l1)
    assert down.verdict == "narrower"
    assert "level" in down.coverage_reduced


def test_task_close_and_a_number_of_days_are_asked_about_again_both_ways() -> None:
    task_close = _envelope(retention={"kind": "task_close", "days": None})
    seven_days = _envelope(retention={"kind": "days", "days": 7})
    for consented, current in ((task_close, seven_days), (seven_days, task_close)):
        result = compare(consented, current)
        assert (result.verdict, result.changed) == ("ask_again", {"retention"})
    forgotten = _envelope(retention={"kind": "until_forgotten", "days": None})
    assert compare(forgotten, task_close).verdict == "narrower"
    assert compare(forgotten, seven_days).verdict == "narrower"


def test_a_server_requiring_more_than_the_level_agreed_is_level_unavailable() -> None:
    consented = _envelope(level="L1", required_min=None, code_sync=None, retention=None)
    current = _envelope(level="L1", required_min="L2", code_sync=None, retention=None)
    result = compare(consented, current)
    assert result.verdict == "level_unavailable"
    # Within the level agreed, a higher requirement is still asked about again.
    raised = _envelope(level="L2", required_min="L2")
    assert compare(_envelope(), raised).verdict == "ask_again"


def test_anything_unknown_asks_again_even_when_unchanged() -> None:
    unknown = envelope_from_json({**_document(), "telemetry": True})
    result = compare(unknown, unknown)
    assert (result.verdict, result.unknown) == ("ask_again", {"telemetry"})
    assert compare(_envelope(), unknown).verdict == "ask_again"
    assert compare(_envelope(), _envelope(level="L0")).unknown == {"level"}
    assert precedes(unknown, unknown)
    assert not precedes(unknown, _envelope())
    assert not precedes(_envelope(), unknown)


# --- the written retention token (``--retention`` and ``[server.code_copy]``) -----------------


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("task_close", Retention("task_close", None)),
        ("until_forgotten", Retention("until_forgotten", None)),
        ("days:1", Retention("days", 1)),
        ("days:30", Retention("days", 30)),
        ("days:36500", Retention("days", 36_500)),
    ],
)
def test_a_retention_token_names_a_retention_an_envelope_admits(
    token: str, expected: Retention
) -> None:
    retention = retention_from_token(token)
    assert retention == expected
    parsed = envelope_from_json(_document(retention=retention_to_json(retention)))
    assert parsed.retention == expected


@pytest.mark.parametrize(
    "token",
    [
        "",
        "days",
        "days:",
        "days:0",
        "days:07",
        "days:36501",
        "days:-1",
        "days:+1",
        "days: 1",
        "days:1 ",
        "days:1\n",
        "days:\u0661",
        "Days:1",
        "TASK_CLOSE",
        "task_close ",
        "forever",
        30,
        None,
    ],
)
def test_any_other_retention_token_is_refused_by_a_closed_reason(token: object) -> None:
    with pytest.raises(EnvelopeError) as refused:
        retention_from_token(token)
    assert refused.value.reason == "retention_token_invalid"
