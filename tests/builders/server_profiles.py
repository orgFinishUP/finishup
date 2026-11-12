"""Server profiles and recorded consents for tests (ADR-052, layer 3).

``profile_document`` builds a valid ``server-profile`` 1.0.0 document (its digest computed as a
server would); ``fetched`` wraps one as a transport would hand it over, with the endpoint identity
the transport observed; ``consent_to`` records the owner's consent to it for a remote target, as
``finishup server add`` does after the typed confirmation. ``TEST_REVISION`` is the revision of the
default document, which the in-memory scripted service issues by default.
"""

from __future__ import annotations

import json
from typing import Any

from finishup.client import targets
from finishup.client.server_profile import (
    FetchedProfile,
    consent_envelope_for,
    record_consent,
    refresh_profile,
)
from finishup.client.targets import ServerTarget
from finishup.protocol.consent_envelope import CodeSync, Retention, ReviewEgress
from finishup.protocol.server_profile import (
    ProfileLevels,
    ProfileRetention,
    ServerProfileRevision,
    consent_subset,
    profile_digest,
)

__all__ = [
    "HOST_KEY",
    "TEST_ISSUER",
    "TEST_REVISION",
    "consent_to",
    "fetched",
    "profile_document",
    "refreshed",
]

TEST_ISSUER = "7" * 32
HOST_KEY = "sha256:" + "e" * 64


def profile_document(
    *,
    review: ReviewEgress | None = None,
    levels: ProfileLevels | None = None,
    revision: int = 1,
    issuer: str = TEST_ISSUER,
) -> dict[str, Any]:
    """A valid profile document; the default offers L1 with no AI review.

    A profile that offers L2 carries the copy members a server keeping a copy states.
    """

    chosen = levels or ProfileLevels(("L1",), "L1")
    copy = "L2" in chosen.offered
    subset = consent_subset(
        levels=chosen,
        code_sync=CodeSync(frozenset({"git-bundle-1"}), 1 << 30, 1 << 24) if copy else None,
        retention=ProfileRetention((Retention("days", 7),), Retention("days", 7)) if copy else None,
        exclusions=frozenset({".env*"}) if copy else None,
        review=review or ReviewEgress("none", None),
    )
    digest = profile_digest(subset)
    return {
        "schema_version": "1.0.0",
        "release": "0.3.0",
        "schema_manifest_digest": "sha256:" + "ab" * 32,
        "service_instance_id": "svc_01234567-89ab-4def-8123-456789abcdef",
        "key": {"id": None, "scope": "operator", "principal": "owner"},
        "edges": ["ssh-control"],
        **subset,
        "official": False,
        "profile_revision": {"issuer": issuer, "revision": revision, "profile_digest": digest},
        "profile_digest": digest,
    }


def _revision_of(document: dict[str, Any]) -> ServerProfileRevision:
    found = document["profile_revision"]
    return ServerProfileRevision(found["issuer"], found["revision"], found["profile_digest"])


TEST_REVISION = _revision_of(profile_document())


def fetched(
    record: ServerTarget,
    document: dict[str, Any] | None = None,
    *,
    identity: str | None = None,
    identity_type: str | None = None,
) -> FetchedProfile:
    """``document`` as ``record``'s transport would hand it over (SSH pins a host key; an
    HTTPS identity is a pin unless ``identity_type`` says otherwise)."""

    encoded = json.dumps(document or profile_document()).encode("utf-8")
    if record.kind == "ssh":
        return FetchedProfile(encoded, "ssh_host_key", identity or HOST_KEY)
    if identity is not None:
        return FetchedProfile(encoded, identity_type or "tls_pin", identity)
    return FetchedProfile(encoded, "tls_system_ca", None)


def consent_to(
    record: ServerTarget,
    document: dict[str, Any] | None = None,
    *,
    lock: bool = True,
    identity: str | None = None,
    identity_type: str | None = None,
    level: str = "L1",
    retention: Retention | None = None,
) -> ServerTarget:
    """Record the owner's consent to ``document`` at ``level`` (L1 by default; L2 with the
    ``retention`` chosen) for ``record``; the new record.

    ``lock`` takes the registry lock; pass False where the caller already holds it.
    ``identity`` is the endpoint identity the transport observed (an SSH target's default is
    ``HOST_KEY``).
    """

    profile = fetched(record, document, identity=identity, identity_type=identity_type)

    def write() -> ServerTarget:
        stored = targets.read_target(targets.target_root(record.target_id))
        assert stored is not None
        envelope, _profile = consent_envelope_for(stored, profile, level=level, retention=retention)
        return record_consent(stored, profile, envelope)

    if not lock:
        return write()
    with targets.registry_lock():
        return write()


def refreshed(record: ServerTarget, document: dict[str, Any], *, identity: str | None = None):  # noqa: ANN201
    """Record a newly fetched ``document`` for ``record`` (``refresh_profile``)."""

    with targets.registry_lock():
        return refresh_profile(record, fetched(record, document, identity=identity))
