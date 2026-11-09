"""The server profile 1.0.0: golden vectors, its digest, strict parsing and the envelope it gives."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.consent_envelope import EndpointIdentity, Retention, compare
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance
from finishup.protocol.server_profile import (
    PROFILE_DIGEST_DOMAIN,
    ProfileError,
    ServerProfile,
    envelope_for,
    profile_from_json,
    profile_to_json,
)
from finishup.protocol.server_profile_contract import ServerProfileContract

_CASE = json.loads(
    (Path(__file__).parents[3] / "fixtures/service/server-profile.case.json").read_bytes()
)
_VALID: list[dict[str, Any]] = _CASE["valid"]
_INVALID: list[dict[str, Any]] = _CASE["invalid"]
_ENDPOINT = EndpointIdentity(
    "ssh", "ssh://owner@devbox.example:22", "ssh_host_key", "sha256:" + "c" * 64
)


def _document(name: str) -> dict[str, Any]:
    return json.loads(json.dumps(next(case for case in _VALID if case["name"] == name)["document"]))


def _profile(name: str) -> ServerProfile:
    return profile_from_json(cast(JsonValue, _document(name)))


def _resealed(document: dict[str, Any]) -> dict[str, Any]:
    """``document`` with its digest recomputed, as a server whose offer changed would send it."""

    subset = {
        key: document[key] for key in ("levels", "code_sync", "retention", "exclusions", "review")
    }
    digest = (
        "sha256:" + hashlib.sha256(PROFILE_DIGEST_DOMAIN + canonical_encode(subset)).hexdigest()
    )
    document["profile_digest"] = digest
    document["profile_revision"] = {**document["profile_revision"], "profile_digest": digest}
    return document


@pytest.mark.parametrize("case", _VALID, ids=lambda case: case["name"])
def test_every_golden_profile_parses_to_its_digest_and_round_trips(case: dict[str, Any]) -> None:
    profile = profile_from_json(case["document"])

    subset = case["consent_subset_canonical"].encode("utf-8")
    assert profile.profile_digest == case["profile_digest"]
    assert profile.profile_digest == (
        "sha256:" + hashlib.sha256(b"yoetz/server-profile/v1\x00" + subset).hexdigest()
    )
    assert canonical_encode(profile_to_json(profile)) == canonical_encode(case["document"])
    validate_schema_instance("server-profile", "1.0.0", case["document"])
    ServerProfileContract.model_validate(case["document"])


@pytest.mark.parametrize("case", _INVALID, ids=lambda case: case["name"])
def test_every_rejection_vector_is_refused_with_its_reason(case: dict[str, Any]) -> None:
    with pytest.raises(ProfileError) as refused:
        profile_from_json(case["document"])
    assert refused.value.reason == case["reason"]
    if case["schema_valid"]:
        validate_schema_instance("server-profile", "1.0.0", case["document"])
    else:
        with pytest.raises(SchemaInstanceInvalid):
            validate_schema_instance("server-profile", "1.0.0", case["document"])
        with pytest.raises(ValidationError):
            ServerProfileContract.model_validate(case["document"])


def test_bytes_are_bounded_and_must_be_strict_json() -> None:
    with pytest.raises(ProfileError) as large:
        profile_from_json(b"{" + b" " * 70_000 + b"}")
    assert large.value.reason == "profile_too_large"
    with pytest.raises(ProfileError) as not_json:
        profile_from_json(b"{'schema_version': '1.0.0'}")
    assert not_json.value.reason == "profile_not_json"
    encoded = json.dumps(_document("l1_no_ai_review")).encode("utf-8")
    assert profile_from_json(encoded).levels.offered == ("L1",)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("edges",), ["ssh-control", "rest-1"]),
        (("edges",), []),
        (("levels", "offered"), ["L2", "L1"]),
        (("levels", "required_min"), "L2"),
        (("key", "scope"), "everything"),
        (("official",), 0),
        (("service_instance_id",), "svc_not-an-id"),
        (("release",), "latest"),
        (("profile_revision", "revision"), 0),
        (("profile_revision", "issuer"), "ABC"),
    ],
)
def test_a_malformed_member_refuses_the_profile(path: tuple[str, ...], value: object) -> None:
    document = _document("l1_no_ai_review")
    node = document
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value

    with pytest.raises(ProfileError):
        profile_from_json(cast(JsonValue, _resealed(document)))


def test_copy_members_are_present_exactly_when_level_two_is_offered() -> None:
    document = _document("l2_offered")
    document["levels"] = {"offered": ["L1"], "required_min": "L1"}
    with pytest.raises(ProfileError) as stray:
        profile_from_json(cast(JsonValue, _resealed(document)))
    assert stray.value.reason == "profile_member_invalid"

    document = _document("l1_no_ai_review")
    document["levels"] = {"offered": ["L1", "L2"], "required_min": "L1"}
    with pytest.raises(ProfileError) as missing:
        profile_from_json(cast(JsonValue, _resealed(document)))
    assert missing.value.reason == "profile_member_invalid"


def test_a_retention_default_must_be_one_of_its_options_and_options_sorted() -> None:
    document = _document("l2_offered")
    document["retention"]["default"] = {"kind": "days", "days": 30}
    with pytest.raises(ProfileError):
        profile_from_json(cast(JsonValue, _resealed(document)))
    document = _document("l2_offered")
    document["retention"]["options"].reverse()
    with pytest.raises(ProfileError):
        profile_from_json(cast(JsonValue, _resealed(document)))


def test_an_unknown_retention_kind_or_review_value_is_refused_not_kept() -> None:
    document = _document("l2_offered")
    document["retention"]["options"][0] = {"kind": "forever", "days": None}
    with pytest.raises(ProfileError) as retention:
        profile_from_json(cast(JsonValue, _resealed(document)))
    assert retention.value.reason == "profile_value_unknown"
    document = _document("l1_no_ai_review")
    document["review"] = {
        "ai_review": "always",
        "provider_disclosure": None,
        "fallback_disclosure": None,
    }
    with pytest.raises(ProfileError) as review:
        profile_from_json(cast(JsonValue, _resealed(document)))
    assert review.value.reason == "profile_value_unknown"


def test_the_level_one_envelope_carries_no_copy_and_the_servers_review() -> None:
    profile = _profile("l2_offered")

    envelope = envelope_for(
        profile, endpoint=_ENDPOINT, level="L1", retention=None, disclosure_version=3
    )

    assert envelope.level == "L1" and envelope.required_min == "L1"
    assert envelope.code_sync is None and envelope.retention is None
    assert envelope.exclusions == frozenset()
    assert envelope.review == profile.review
    assert envelope.principal.principal == "owner" and envelope.key_scope == {"operator"}
    assert envelope.endpoint is _ENDPOINT


def test_the_level_two_envelope_takes_an_offered_retention_only() -> None:
    profile = _profile("l2_offered")

    envelope = envelope_for(
        profile,
        endpoint=_ENDPOINT,
        level="L2",
        retention=Retention("days", 7),
        disclosure_version=3,
    )
    assert envelope.code_sync == profile.code_sync
    assert envelope.exclusions == profile.exclusions
    with pytest.raises(ProfileError) as retention:
        envelope_for(
            profile,
            endpoint=_ENDPOINT,
            level="L2",
            retention=Retention("days", 30),
            disclosure_version=3,
        )
    assert retention.value.reason == "profile_retention_not_offered"
    with pytest.raises(ProfileError) as level:
        envelope_for(
            _profile("l1_no_ai_review"),
            endpoint=_ENDPOINT,
            level="L2",
            retention=None,
            disclosure_version=3,
        )
    assert level.value.reason == "profile_level_not_offered"


def test_review_egress_appearing_asks_again_and_disappearing_narrows() -> None:
    def at_l1(name: str):  # noqa: ANN202 - local helper
        return envelope_for(
            _profile(name), endpoint=_ENDPOINT, level="L1", retention=None, disclosure_version=3
        )

    widened = compare(at_l1("l1_no_ai_review"), at_l1("l1_server_policy_review"))
    narrowed = compare(at_l1("l1_server_policy_review"), at_l1("l1_no_ai_review"))

    assert widened.verdict == "ask_again" and widened.widened == {"review"}
    assert narrowed.verdict == "narrower" and narrowed.coverage_reduced == {"review"}


def test_the_pure_parser_loads_no_pydantic() -> None:
    probe = (
        "import sys; import finishup.protocol.server_profile; "
        "sys.exit(1 if 'pydantic' in sys.modules else 0)"
    )
    assert subprocess.run([sys.executable, "-c", probe], check=False).returncode == 0
