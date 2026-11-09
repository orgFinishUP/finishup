"""The owner's consent to a server's profile, and the consent step of the gate (ADR-052).

Design v2 sections 2.3 and 8.2: the consent is recorded in ``target.json`` (``/2``) with the
consented envelope beside it; every admission compares it with the server's current profile,
admits the same or a narrower one under that profile's revision, refuses a level the owner did
not agree to (``server_level_unavailable``) and anything else (``server_profile_changed``). A
narrowing adjusts the stored consent, so a later widening asks again.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from builders.server_profiles import (
    TEST_ISSUER,
    TEST_REVISION,
    consent_to,
    profile_document,
    refreshed,
)
from builders.server_targets import ambient_home, open_remote_kinds
from finishup.client import targets
from finishup.client.authorization import gate
from finishup.client.server_profile import consent_verdict
from finishup.client.targets import ServerConsent, ServerTarget, TargetError
from finishup.config.paths import reset_selection_memo
from finishup.protocol.consent_envelope import ReviewEgress
from finishup.protocol.server_profile import ProfileLevels

_POLICY = ReviewEgress("server_policy", "openai")


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


@pytest.fixture(params=["ssh", "https"])
def remote(
    request: pytest.FixtureRequest, home: Path, monkeypatch: pytest.MonkeyPatch
) -> ServerTarget:
    del home
    open_remote_kinds(monkeypatch, request.param, consent=False)
    fields: dict[str, object] = (
        {"host": "lab.example", "port": 22}
        if request.param == "ssh"
        else {"base_url": "https://lab.example"}
    )
    with targets.registry_lock():
        record, _root = targets.new_remote_target("lab", request.param, **fields)  # pyright: ignore[reportArgumentType]
        targets.write_selection(record)
    reset_selection_memo()
    return record


def _phase(record: ServerTarget) -> str | None:
    try:
        gate(record)
    except TargetError as error:
        return error.reason
    return None


def _stored(record: ServerTarget) -> ServerTarget:
    stored = targets.read_target(targets.target_root(record.target_id))
    assert stored is not None
    return stored


# --- the record ---------------------------------------------------------------------------------


def test_a_local_target_record_stays_version_one_byte_for_byte(home: Path) -> None:
    del home
    with targets.registry_lock():
        record, root = targets.new_local_target("work")
    encoded = (root / "target.json").read_bytes()
    assert json.loads(encoded)["schema"] == "yoetz.server-target/1"
    assert set(json.loads(encoded)) == {"schema", "target_id", "name", "kind", "created_at"}
    assert record.consent is None


def test_a_consent_makes_a_version_two_record_with_an_exact_consent(
    remote: ServerTarget,
) -> None:
    root = targets.target_root(remote.target_id)
    assert json.loads((root / "target.json").read_bytes())["schema"] == "yoetz.server-target/1"

    consented = consent_to(remote)

    document = json.loads((root / "target.json").read_bytes())
    assert document["schema"] == "yoetz.server-target/2"
    assert document["disclosure_version"] == targets.DISCLOSURE_VERSION == 3
    consent = document["consent"]
    assert set(consent) == {
        "level",
        "profile_digest",
        "profile_revision",
        "retention",
        "envelope_digest",
        "adjusted",
    }
    assert consent["level"] == "L1" and consent["retention"] is None
    assert consent["adjusted"] is None
    assert consent["profile_revision"] == {"issuer": TEST_ISSUER, "revision": 1}
    assert consent["profile_digest"] == TEST_REVISION.profile_digest
    assert _stored(remote) == consented
    for name in ("config/consent-envelope.json", "state/server-profile.json"):
        assert (root / name).stat().st_mode & 0o077 == 0


@pytest.mark.parametrize(
    "edit",
    ["extra_member", "level_three", "retention_at_l1", "consent_on_version_one"],
)
def test_a_damaged_consent_makes_the_record_unreadable(remote: ServerTarget, edit: str) -> None:
    consent_to(remote)
    path = targets.target_root(remote.target_id) / "target.json"
    document = json.loads(path.read_bytes())
    if edit == "extra_member":
        document["consent"]["surprise"] = 1
    elif edit == "level_three":
        document["consent"]["level"] = "L3"
    elif edit == "retention_at_l1":
        document["consent"]["retention"] = {"kind": "days", "days": 7}
    else:
        document["schema"] = "yoetz.server-target/1"
    from finishup.protocol.canonical import canonical_encode

    path.write_bytes(canonical_encode(document) + b"\n")
    with pytest.raises(TargetError) as refused:
        targets.read_target(path.parent)
    assert refused.value.reason == "target_record_invalid"


def test_a_consent_validates_its_own_fields() -> None:
    digest = "sha256:" + "a" * 64
    with pytest.raises(TargetError):
        ServerConsent("L1", digest, "0" * 32, 1, "days", 7, digest)
    with pytest.raises(TargetError):
        ServerConsent("L2", digest, "0" * 32, 1, None, None, digest)
    with pytest.raises(TargetError):
        ServerConsent("L1", digest, "0" * 32, 1, None, None, digest, None, ("review",))
    with pytest.raises(TargetError):
        ServerConsent(
            "L1", digest, "0" * 32, 1, None, None, digest, "2026-11-09T00:00:00.000Z", ("x",)
        )


# --- the consent step ---------------------------------------------------------------------------


def test_no_consent_is_asked_again_after_the_kind_step(
    remote: ServerTarget, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _phase(remote) == "server_profile_changed"
    old = replace(remote, disclosure_version=2)
    assert _phase(old) == "target_reauthorization_required"
    # With the kind closed again, the kind is the first refusal: the consent's way on (``server
    # use NAME``) would refuse it too.
    open_remote_kinds(monkeypatch, consent=False)
    assert _phase(remote) == "target_root_is_remote"


def test_the_same_profile_is_admitted_under_its_revision(remote: ServerTarget) -> None:
    consented = consent_to(remote)

    assert gate(consented) == TEST_REVISION
    assert consent_verdict(consented).phase is None


@pytest.mark.parametrize(
    "damage", ["no_cache", "no_envelope", "tampered_envelope", "tampered_cache", "loose_mode"]
)
def test_a_missing_or_tampered_consent_file_asks_again(remote: ServerTarget, damage: str) -> None:
    consented = consent_to(remote)
    root = targets.target_root(remote.target_id)
    envelope = root / "config" / "consent-envelope.json"
    cache = root / "state" / "server-profile.json"
    if damage == "no_cache":
        cache.unlink()
    elif damage == "no_envelope":
        envelope.unlink()
    elif damage == "tampered_envelope":
        envelope.write_bytes(envelope.read_bytes().replace(b'"L1"', b'"L2"', 1))
    elif damage == "tampered_cache":
        cache.write_bytes(cache.read_bytes().replace(b'"none"', b'"server_policy"', 1))
    else:
        envelope.chmod(0o644)

    assert _phase(consented) == "server_profile_changed"


def test_a_server_that_now_sends_to_an_ai_provider_is_asked_about_again(
    remote: ServerTarget,
) -> None:
    consented = consent_to(remote)

    verdict = refreshed(consented, profile_document(review=_POLICY, revision=2))

    assert verdict.phase == "server_profile_changed"
    assert _phase(_stored(remote)) == "server_profile_changed"
    # The consent is left as the owner gave it: only they agree again.
    assert _stored(remote).consent == consented.consent


def test_a_narrower_profile_is_admitted_adjusted_and_a_widening_back_asks_again(
    remote: ServerTarget,
) -> None:
    consented = consent_to(remote, profile_document(review=_POLICY))

    verdict = refreshed(consented, profile_document(revision=2))

    assert verdict.phase is None and verdict.narrowed
    assert verdict.coverage_reduced == {"review"}
    adjusted = _stored(remote)
    assert adjusted.consent is not None
    assert adjusted.consent.revision == 2
    assert adjusted.consent.adjusted_at is not None
    assert adjusted.consent.coverage_reduced == ("review",)
    assert _phase(adjusted) is None
    # Back to what the owner once confirmed is a widening of what this computer conforms to now.
    assert refreshed(adjusted, profile_document(review=_POLICY, revision=3)).phase == (
        "server_profile_changed"
    )


def test_the_same_offer_under_a_new_revision_is_recorded_quietly(remote: ServerTarget) -> None:
    consented = consent_to(remote)

    verdict = refreshed(consented, profile_document(revision=5))

    assert verdict.phase is None and not verdict.narrowed
    stored = _stored(remote)
    assert stored.consent is not None
    assert (stored.consent.revision, stored.consent.adjusted_at) == (5, None)
    revision = gate(stored)
    assert revision is not None and revision.revision == 5


def test_a_revision_from_another_issuer_asks_again(remote: ServerTarget) -> None:
    consented = consent_to(remote)

    verdict = refreshed(consented, profile_document(issuer="9" * 32))

    assert verdict.phase == "server_profile_changed"


def test_a_server_requiring_a_level_above_the_one_agreed_is_refused_never_upgraded(
    remote: ServerTarget,
) -> None:
    consented = consent_to(remote)

    verdict = refreshed(
        consented, profile_document(levels=ProfileLevels(("L1", "L2"), "L2"), revision=2)
    )

    assert verdict.phase == "server_level_unavailable"
    assert _phase(_stored(remote)) == "server_level_unavailable"
    stored = _stored(remote)
    assert stored.consent is not None and stored.consent.level == "L1"


def test_a_server_now_also_offering_a_copy_changes_nothing_at_level_one(
    remote: ServerTarget,
) -> None:
    consented = consent_to(remote)

    verdict = refreshed(
        consented, profile_document(levels=ProfileLevels(("L1", "L2"), "L1"), revision=2)
    )

    assert verdict.phase is None and not verdict.narrowed


def test_another_endpoint_identity_asks_again(remote: ServerTarget) -> None:
    consented = consent_to(remote)

    verdict = refreshed(consented, profile_document(revision=2), identity="sha256:" + "9" * 64)

    assert verdict.phase == "server_profile_changed"


# --- a narrowing that stops part way (review of layer 3: B1) -------------------------------------


class _Stop:
    """Stops a refresh when it writes the file called ``name`` (a crash, as readers see it), while
    ``armed``; ``written`` names what it wrote before. Disarmed, every write goes through (never
    ``monkeypatch.undo()``: it would also restore this test's isolated home)."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
        from finishup.client import server_profile as module

        self.name = name
        self.armed = True
        self.written: list[str] = []
        real = module._write  # pyright: ignore[reportPrivateUsage]

        def write(path: Path, encoded: bytes) -> None:
            if self.armed:
                if path.name == self.name:
                    raise TargetError("target_root_unsafe")
                self.written.append(path.name)
            real(path, encoded)

        monkeypatch.setattr(module, "_write", write)


def test_a_narrowing_stopped_before_its_consent_is_committed_exposes_nothing_narrower(
    remote: ServerTarget, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Readers never admit the narrower revision under the broader consent: nothing of it is
    cached before the reduced consent is (D8)."""

    consented = consent_to(remote, profile_document(review=_POLICY))
    before = _stored(remote)
    stop = _Stop(monkeypatch, "consent-envelope.json")

    with pytest.raises(TargetError):
        refreshed(consented, profile_document(revision=2))

    verdict = consent_verdict(_stored(remote))
    assert verdict.phase is None and not verdict.narrowed
    assert verdict.revision is not None and verdict.revision.revision == 1
    assert _stored(remote) == before
    assert stop.written == []


def test_a_narrowing_stopped_after_its_consent_is_committed_never_lets_the_wider_offer_back(
    remote: ServerTarget, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reduced consent is committed first; until the narrower profile is cached, the older
    one is wider than it and refuses. Restoring the wider offer later asks the owner again; the
    narrower one is admitted under its own revision."""

    consented = consent_to(remote, profile_document(review=_POLICY))
    stop = _Stop(monkeypatch, "server-profile.json")

    with pytest.raises(TargetError):
        refreshed(consented, profile_document(revision=2))

    adjusted = _stored(remote)
    assert _phase(adjusted) == "server_profile_changed"
    assert adjusted.consent is not None
    assert (adjusted.consent.revision, adjusted.consent.coverage_reduced) == (2, ("review",))
    assert stop.written == ["consent-envelope.json"]
    stop.armed = False
    assert refreshed(adjusted, profile_document(review=_POLICY, revision=3)).phase == (
        "server_profile_changed"
    )
    again = refreshed(adjusted, profile_document(revision=2))
    assert again.phase is None and not again.narrowed
    revision = gate(_stored(remote))
    assert revision is not None and revision.revision == 2
