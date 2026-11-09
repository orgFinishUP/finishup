"""What this server offers a client elsewhere, and the profile revision it issues (ADR-052)."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any, cast

import pytest

from finishup.config.models import FinishUpConfig
from finishup.ports.control import ServiceState, ServiceStatus
from finishup.protocol.canonical import JsonValue
from finishup.protocol.consent_envelope import ReviewEgress
from finishup.protocol.schemas import validate_schema_instance
from finishup.protocol.server_profile import profile_from_json
from finishup.service.server_profile import (
    REVISION_FILE_NAME,
    ProfileRevisionStore,
    ServerProfileSource,
    offer_digest,
    review_offer,
)

_STATUS = ServiceStatus(
    protocol_version="1.0",
    service_version="0.3.0",
    service_instance_id="svc_00000000-0000-4000-8000-000000000001",
    service_generation="1",
    state=ServiceState.LOCKED,
    state_reason="vault_uninitialized",
    vault_mode="uninitialized",
    capabilities=(),
    session_monitor="unavailable",
)
_MANIFEST = "sha256:" + "f" * 64


def _provider_config(provider_id: str = "openai") -> FinishUpConfig:
    return FinishUpConfig.model_validate(
        {
            "profile": "local-openai",
            "provider": {
                "provider_id": provider_id,
                "endpoint_profile_id": "openai-responses",
                "endpoint_profile_version": "1.0.0",
                "model": "gpt-test",
                "capability_profile": "default",
            },
        }
    )


@pytest.fixture
def state(tmp_path: Path) -> Path:
    tmp_path.chmod(0o700)
    return tmp_path


def test_a_service_with_no_external_provider_offers_no_ai_review() -> None:
    for profile in ("strict-local", "test-fake", "release-probe"):
        config = FinishUpConfig.model_validate({"profile": profile})
        assert review_offer(config) == ReviewEgress("none", None)


def test_a_service_with_an_external_provider_states_server_policy_and_names_it() -> None:
    config = _provider_config()
    assert review_offer(config) == ReviewEgress("server_policy", "openai")
    assert offer_digest(config) != offer_digest(FinishUpConfig())


def test_the_first_start_issues_revision_one_under_a_new_issuer_in_an_owner_only_record(
    state: Path,
) -> None:
    store = ProfileRevisionStore(state / REVISION_FILE_NAME)

    revision = store.advance("sha256:" + "a" * 64)

    assert revision.revision == 1 and len(revision.issuer) == 32
    path = state / REVISION_FILE_NAME
    facts = path.lstat()
    assert stat.S_IMODE(facts.st_mode) == 0o600
    record = json.loads(path.read_bytes())
    assert record == {
        "schema": "yoetz.server-profile-revision/1",
        "issuer": revision.issuer,
        "revision": 1,
        "profile_digest": "sha256:" + "a" * 64,
    }


def test_the_same_offer_keeps_its_revision_and_a_new_offer_advances_it(state: Path) -> None:
    store = ProfileRevisionStore(state / REVISION_FILE_NAME)
    first = store.advance("sha256:" + "a" * 64)
    before = (state / REVISION_FILE_NAME).lstat()

    again = store.advance("sha256:" + "a" * 64)
    assert again == first
    after = (state / REVISION_FILE_NAME).lstat()
    assert (before.st_ino, before.st_mtime_ns) == (after.st_ino, after.st_mtime_ns)

    changed = store.advance("sha256:" + "b" * 64)
    assert (changed.issuer, changed.revision) == (first.issuer, 2)
    # Back to the first offer is a new revision too: a consent is bound to the whole triple.
    back = store.advance("sha256:" + "a" * 64)
    assert (back.issuer, back.revision, back.profile_digest) == (
        first.issuer,
        3,
        first.profile_digest,
    )


@pytest.mark.parametrize(
    "damage",
    ["garbage", "group_readable", "symlink", "wrong_schema", "not_canonical"],
)
def test_a_record_that_cannot_be_read_starts_again_under_a_new_issuer(
    state: Path, damage: str
) -> None:
    path = state / REVISION_FILE_NAME
    first = ProfileRevisionStore(path).advance("sha256:" + "a" * 64)
    body = path.read_bytes()
    if damage == "garbage":
        path.write_bytes(b"{not json\n")
    elif damage == "group_readable":
        path.chmod(0o640)
    elif damage == "symlink":
        target = state / "elsewhere.json"
        target.write_bytes(body)
        target.chmod(0o600)
        path.unlink()
        path.symlink_to(target)
    elif damage == "wrong_schema":
        path.write_bytes(body.replace(b"revision/1", b"revision/2"))
    else:
        path.write_bytes(json.dumps(json.loads(body), indent=1).encode() + b"\n")

    again = ProfileRevisionStore(path).advance("sha256:" + "a" * 64)

    assert again.issuer != first.issuer and again.revision == 1


def test_a_record_that_cannot_be_written_keeps_the_revision_in_memory(state: Path) -> None:
    folder = state / "readonly"
    folder.mkdir(mode=0o700)
    folder.chmod(0o500)
    try:
        revision = ProfileRevisionStore(folder / REVISION_FILE_NAME).advance("sha256:" + "a" * 64)
    finally:
        folder.chmod(0o700)
    assert revision.revision == 1
    assert not (folder / REVISION_FILE_NAME).exists()
    assert os.listdir(folder) == []


def test_the_served_profile_is_a_valid_document_whose_digest_recomputes(state: Path) -> None:
    source = ServerProfileSource.load(FinishUpConfig(), state)

    document = source.document(_STATUS, _MANIFEST)

    validate_schema_instance("server-profile", "1.0.0", cast(JsonValue, document))
    profile = profile_from_json(cast(JsonValue, document))
    assert profile.revision == source.revision
    assert profile.levels.offered == ("L1",) and profile.levels.required_min == "L1"
    assert (profile.code_sync, profile.retention, profile.exclusions) == (None, None, None)
    assert profile.official is False and profile.edges == ("ssh-control",)
    assert (profile.key.id, profile.key.scope, profile.key.principal) == (None, "operator", "owner")
    assert profile.release == "0.3.0"
    assert profile.service_instance_id == _STATUS.service_instance_id
    text = json.dumps(cast(Any, document))
    assert str(state) not in text


def test_a_restart_under_the_same_config_keeps_the_revision(state: Path) -> None:
    first = ServerProfileSource.load(FinishUpConfig(), state)
    second = ServerProfileSource.load(FinishUpConfig(), state)

    assert first.revision == second.revision
