"""The consent-envelope order is a partial order, and ``compare`` agrees with it and the digest."""

from __future__ import annotations

from typing import Any

from hypothesis import given
from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

from finishup.protocol.consent_envelope import (
    ConsentEnvelope,
    canonical_bytes,
    compare,
    envelope_digest,
    envelope_from_json,
    precedes,
)

_ORIGINS = ("https://a.example:443", "https://b.example:443")
_IDENTITIES = ("sha256:" + "ab" * 32, "sha256:" + "cd" * 32)


def _subset(items: tuple[str, ...], *, min_size: int = 0) -> SearchStrategy[list[str]]:
    return st.lists(st.sampled_from(items), unique=True, min_size=min_size, max_size=len(items))


def _envelopes() -> SearchStrategy[ConsentEnvelope]:
    code_sync = st.none() | st.fixed_dictionaries(
        {
            "methods": _subset(("git_export", "patch"), min_size=1),
            "max_repo_bytes": st.sampled_from((10, 100)),
            "max_file_bytes": st.sampled_from((1, 10)),
        }
    )
    retention = st.none() | st.sampled_from(
        (
            {"kind": "task_close", "days": None},
            {"kind": "days", "days": 7},
            {"kind": "days", "days": 30},
            {"kind": "until_forgotten", "days": None},
        )
    )
    review = st.sampled_from(
        (
            {"ai_review": "none", "provider_disclosure": None, "fallback_disclosure": None},
            {
                "ai_review": "server_policy",
                "provider_disclosure": "p1",
                "fallback_disclosure": None,
            },
            {
                "ai_review": "server_policy",
                "provider_disclosure": "p2",
                "fallback_disclosure": None,
            },
            {
                "ai_review": "server_policy",
                "provider_disclosure": "p1",
                "fallback_disclosure": "p2",
            },
        )
    )
    document: SearchStrategy[dict[str, Any]] = st.fixed_dictionaries(
        {
            "schema": st.just("yoetz.consent-envelope/1"),
            "endpoint": st.fixed_dictionaries(
                {
                    "kind": st.just("https"),
                    "origin": st.sampled_from(_ORIGINS),
                    "identity_type": st.just("tls_pin"),
                    "identity": st.sampled_from(_IDENTITIES),
                }
            ),
            "principal": st.fixed_dictionaries(
                {"key_id": st.sampled_from(("k1", "k2")), "principal": st.just("owner")}
            ),
            "key_scope": _subset(("agent", "tasks", "admin")),
            "level": st.sampled_from(("L1", "L2")),
            "required_min": st.sampled_from((None, "L1", "L2")),
            "code_sync": code_sync,
            "retention": retention,
            "exclusions": _subset((".env", "*.pem", "secrets/")),
            "review": review,
            "disclosure_version": st.sampled_from((1, 2)),
        }
    )
    return document.map(envelope_from_json)


@given(_envelopes())
def test_the_order_is_reflexive(envelope: ConsentEnvelope) -> None:
    assert precedes(envelope, envelope)


@given(_envelopes(), _envelopes())
def test_the_order_is_antisymmetric_up_to_canonical_bytes(
    first: ConsentEnvelope, second: ConsentEnvelope
) -> None:
    if precedes(first, second) and precedes(second, first):
        assert canonical_bytes(first) == canonical_bytes(second)


@given(_envelopes(), _envelopes(), _envelopes())
def test_the_order_is_transitive(
    first: ConsentEnvelope, second: ConsentEnvelope, third: ConsentEnvelope
) -> None:
    if precedes(first, second) and precedes(second, third):
        assert precedes(first, third)


@given(_envelopes(), _envelopes())
def test_compare_agrees_with_the_digest_and_the_order(
    consented: ConsentEnvelope, current: ConsentEnvelope
) -> None:
    result = compare(consented, current)
    if result.verdict == "level_unavailable":
        return
    assert (result.verdict == "same") == (envelope_digest(consented) == envelope_digest(current))
    if result.verdict == "narrower":
        assert precedes(current, consented)
        assert not precedes(consented, current)
    if result.verdict == "ask_again":
        assert not precedes(current, consented)
        assert result.widened or result.changed
