"""What this server offers a client elsewhere, and the profile revision it issues (ADR-052)."""

from __future__ import annotations

import asyncio
import json
import os
import stat
import tomllib
from pathlib import Path
from typing import Any, cast

import pytest
from tests.builders.server_copy import release_l2

import finishup.service.daemon as daemon_module
from finishup.config.load import validate_config_mapping
from finishup.config.models import (
    ExternalRuntimeProfileConfig,
    FinishUpConfig,
    SemanticFallbackConfig,
)
from finishup.config.write import codex_subscription_runtime, fireworks_provider
from finishup.domain.code_exclusions import ALWAYS_EXCLUDED
from finishup.ports.control import ServiceState, ServiceStatus
from finishup.protocol.canonical import JsonValue
from finishup.protocol.consent_envelope import CodeSync, Retention, ReviewEgress
from finishup.protocol.schemas import validate_schema_instance
from finishup.protocol.server_profile import ProfileLevels, ServerProfile, profile_from_json
from finishup.service.server_profile import (
    REVISION_FILE_NAME,
    CodeCopyOffer,
    ProfileRevisionStore,
    ProfileUnavailable,
    ServerProfileSource,
    code_copy_offer,
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
    assert review_offer(config) == ReviewEgress("server_policy", "openai", None)
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


# --- every provider its review may send to (review of layer 3: A1) ------------------------------

_DIGEST = "sha256:" + "a" * 64


def _runtime() -> ExternalRuntimeProfileConfig:
    return codex_subscription_runtime(
        executable_path="/opt/codex/bin/codex",
        executable_sha256=_DIGEST,
        runtime_version="0.150.1",
        source_identity="openai-codex-npm-linux-x64-0.150.1",
        app_server_schema_sha256=_DIGEST,
        capability_cell_sha256=_DIGEST,
        isolated_config_sha256=_DIGEST,
        capability_profile="codex-evaluator/0.150.1/v1",
        capability_evidence_expires_at="2026-11-30T00:00:00Z",
        codex_home="/opt/codex/home",
        model="gpt-test",
        reasoning_effort="high",
    )


def _fireworks() -> FinishUpConfig:
    return FinishUpConfig(profile="local-openai", provider=fireworks_provider(model="m"))


def _codex() -> FinishUpConfig:
    return FinishUpConfig(profile="codex-subscription", external_runtime=_runtime())


def _paired(primary: str) -> FinishUpConfig:
    return FinishUpConfig(
        profile="codex-subscription" if primary == "codex_subscription" else "local-openai",
        provider=fireworks_provider(model="m"),
        external_runtime=_runtime(),
        semantic_fallback=SemanticFallbackConfig(primary=cast(Any, primary)),
    )


@pytest.mark.parametrize(
    ("primary", "first", "fallback"),
    [
        ("api_provider", "fireworks", "openai-codex"),
        ("codex_subscription", "openai-codex", "fireworks"),
    ],
)
def test_a_paired_review_names_the_provider_it_sends_to_first_and_its_fallback(
    primary: str, first: str, fallback: str
) -> None:
    assert review_offer(_fireworks()) == ReviewEgress("server_policy", "fireworks", None)
    assert review_offer(_codex()) == ReviewEgress("server_policy", "openai-codex", None)

    assert review_offer(_paired(primary)) == ReviewEgress("server_policy", first, fallback)


def test_pairing_a_fallback_changes_the_digest_and_a_restart_advances_the_revision(
    state: Path,
) -> None:
    """A consent made before a second provider was paired never matches what is offered after."""

    digests = {
        offer_digest(config)
        for config in (
            _fireworks(),
            _codex(),
            _paired("api_provider"),
            _paired("codex_subscription"),
        )
    }
    assert len(digests) == 4

    single = ServerProfileSource.load(_fireworks(), state)
    paired = ServerProfileSource.load(_paired("api_provider"), state)

    assert single.revision is not None and paired.revision is not None
    assert paired.revision.issuer == single.revision.issuer
    assert paired.revision.revision == single.revision.revision + 1
    assert paired.revision.profile_digest != single.revision.profile_digest
    document = paired.document(_STATUS, _MANIFEST)
    validate_schema_instance("server-profile", "1.0.0", cast(JsonValue, document))
    assert profile_from_json(cast(JsonValue, document)).review == ReviewEgress(
        "server_policy", "fireworks", "openai-codex"
    )


@pytest.mark.parametrize("provider_id", ["acme+beta", "a" * 200])
def test_a_provider_the_profile_cannot_name_exactly_offers_no_profile(
    state: Path, provider_id: str
) -> None:
    """Never a profile that understates: two such providers would look the same to a consent."""

    config = _provider_config(provider_id)
    with pytest.raises(ProfileUnavailable) as unavailable:
        review_offer(config)
    assert unavailable.value.reason == "review_provider_unrepresentable"
    with pytest.raises(ProfileUnavailable):
        offer_digest(config)
    recorded = ServerProfileSource.load(_fireworks(), state)
    before = (state / REVISION_FILE_NAME).read_bytes()

    source = ServerProfileSource.load(config, state)

    assert (source.review, source.revision) == (None, None)
    with pytest.raises(ProfileUnavailable):
        source.document(_STATUS, _MANIFEST)
    # Nothing is issued or recorded for it: the record keeps the last revision it stood for.
    assert (state / REVISION_FILE_NAME).read_bytes() == before
    assert ServerProfileSource.load(_fireworks(), state).revision == recorded.revision


# --- level L2: a code-copy offer, honoured only while L2 is released (ADR-054) ------------------

_OFFER = CodeCopyOffer(
    max_repo_bytes=1_048_576,
    max_file_bytes=65_536,
    retention=(Retention("task_close", None), Retention("days", 7)),
    retention_default=Retention("days", 7),
    exclusions=frozenset({"*.sqlite"}),
)


def test_a_released_code_copy_offer_states_l2_its_caps_retention_and_every_exclusion(
    state: Path,
) -> None:
    plain = ServerProfileSource.load(FinishUpConfig(), state)
    with release_l2():
        source = ServerProfileSource.load(FinishUpConfig(), state, _OFFER)
        document = source.document(_STATUS, _MANIFEST)
        assert source.keeps_copies
        assert offer_digest(FinishUpConfig(), _OFFER) != offer_digest(FinishUpConfig())
    validate_schema_instance("server-profile", "1.0.0", cast(JsonValue, document))
    profile = profile_from_json(json.dumps(document).encode())
    assert profile.levels.offered == ("L1", "L2") and profile.levels.required_min == "L1"
    assert profile.code_sync is not None and profile.code_sync.methods == {"git-bundle-1"}
    assert profile.code_sync.max_file_bytes == 65_536
    assert profile.retention is not None and profile.retention.default == Retention("days", 7)
    assert profile.exclusions is not None
    assert {"*.sqlite", ".env", "*.pem", "id_*"} <= profile.exclusions
    assert set(ALWAYS_EXCLUDED) <= profile.exclusions
    # A new offer is a new revision of the same issuer, so a consent made before asks again.
    assert plain.revision is not None and source.revision is not None
    assert source.revision.issuer == plain.revision.issuer
    assert source.revision.revision == plain.revision.revision + 1


def test_a_code_copy_offer_must_name_its_default_among_its_options() -> None:
    with pytest.raises(ValueError, match="code_copy_offer_invalid"):
        CodeCopyOffer(1_000, 10, (Retention("task_close", None),), Retention("days", 7))
    with pytest.raises(ValueError, match="code_copy_offer_invalid"):
        CodeCopyOffer(10, 1_000, (Retention("days", 7),), Retention("days", 7))


# --- config 1.4.0: the offer [server.code_copy] makes, and the service composed with it --------

_TABLE = """\
[server.code_copy]
enabled = true
max_repo_bytes = 2097152
max_file_bytes = 131072
retention = ["until_forgotten", "days:14", "task_close"]
retention_default = "days:14"
exclusions = ["*.sqlite", "fixtures/private/"]
"""
_DISABLED = _TABLE.replace("enabled = true", "enabled = false")
_TABLE_OFFER = CodeCopyOffer(
    max_repo_bytes=2_097_152,
    max_file_bytes=131_072,
    retention=(
        Retention("until_forgotten", None),
        Retention("days", 14),
        Retention("task_close", None),
    ),
    retention_default=Retention("days", 14),
    exclusions=frozenset({"*.sqlite", "fixtures/private/"}),
)


def _configured(text: str) -> FinishUpConfig:
    return validate_config_mapping(tomllib.loads(text))


def _states_the_table(profile: ServerProfile) -> None:
    """``profile`` offers L2 with exactly the table's caps, retention and exclusions."""

    assert profile.levels == ProfileLevels(("L1", "L2"), "L1")
    assert profile.code_sync == CodeSync(frozenset({"git-bundle-1"}), 2_097_152, 131_072)
    assert profile.retention is not None
    assert set(profile.retention.options) == set(_TABLE_OFFER.retention)
    assert len(profile.retention.options) == 3
    assert profile.retention.default == Retention("days", 14)
    # The server's own patterns together with the client's always-excluded list, nothing else.
    assert profile.exclusions == frozenset({"*.sqlite", "fixtures/private/", *ALWAYS_EXCLUDED})


def test_an_enabled_server_code_copy_table_is_exactly_the_offer() -> None:
    assert code_copy_offer(_configured(_TABLE)) == _TABLE_OFFER
    defaults = code_copy_offer(_configured("[server.code_copy]\nenabled = true\n"))
    assert defaults == CodeCopyOffer(
        max_repo_bytes=67_108_864,
        max_file_bytes=16_777_216,
        retention=(
            Retention("task_close", None),
            Retention("days", 30),
            Retention("until_forgotten", None),
        ),
        retention_default=Retention("days", 30),
    )


@pytest.mark.parametrize("text", ["", "[server]\n", "[server.code_copy]\n", _DISABLED])
def test_no_table_or_a_disabled_one_offers_nothing_and_keeps_the_profile_byte_for_byte(
    state: Path, text: str
) -> None:
    config = _configured(text)
    assert code_copy_offer(config) is None
    plain = ServerProfileSource.load(FinishUpConfig(), state)
    with release_l2():
        source = ServerProfileSource.load(config, state, code_copy_offer(config))
        assert not source.keeps_copies
        assert offer_digest(config, code_copy_offer(config)) == offer_digest(FinishUpConfig())
        assert source.document(_STATUS, _MANIFEST) == plain.document(_STATUS, _MANIFEST)
    # The same offer keeps the revision a consent was made under: nobody is asked again.
    assert source.revision == plain.revision


def test_a_released_table_offers_l2_with_exactly_its_terms(state: Path) -> None:
    config = _configured(_TABLE)
    plain = ServerProfileSource.load(FinishUpConfig(), state)
    with release_l2():
        source = ServerProfileSource.load(config, state, code_copy_offer(config))
        assert source.keeps_copies
        document = source.document(_STATUS, _MANIFEST)
    validate_schema_instance("server-profile", "1.0.0", cast(JsonValue, document))
    _states_the_table(profile_from_json(json.dumps(document).encode()))
    assert plain.revision is not None and source.revision is not None
    assert source.revision.issuer == plain.revision.issuer
    assert source.revision.revision == plain.revision.revision + 1


class _Listener:
    def __init__(self) -> None:
        self._closed = asyncio.Event()

    async def accept(self) -> object:
        await self._closed.wait()
        raise RuntimeError("closed")

    async def aclose(self) -> None:
        self._closed.set()


async def _composed(root: Path, config: FinishUpConfig) -> Any:  # noqa: ANN401
    """The packaged daemon's real composition under ``root``, with listeners that bind nothing."""

    metadata = root / "state"
    paths = daemon_module._ProductionPaths(  # pyright: ignore[reportPrivateUsage]
        root / "data",
        metadata / "service-generation.json",
        metadata / "unlock-throttle.json",
        metadata / "service.lock",
        metadata,
    )

    async def bind() -> _Listener:
        return _Listener()

    binders = daemon_module._ListenerBinders(  # pyright: ignore[reportPrivateUsage]
        cast(Any, bind), cast(Any, bind), cast(Any, bind)
    )
    return await daemon_module._production_composition(  # pyright: ignore[reportPrivateUsage]
        _config=config, _paths=paths, _binders=binders
    )


async def _close(composition: Any) -> None:  # noqa: ANN401
    copies = composition.workspace_hub.code_copies
    if copies is not None:
        copies.stop_expiry()
    daemon = daemon_module.ServiceDaemon(_composition=composition)
    await daemon.start()
    await daemon.close()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_the_service_takes_its_l2_offer_from_its_config_only_when_the_table_enables_it(
    tmp_path: Path,
) -> None:
    enabled = _configured(_TABLE)
    with release_l2():
        composed = await _composed(tmp_path / "released", enabled)
        try:
            source = composed.server_profile
            assert source.keeps_copies and source.code_copy == _TABLE_OFFER
            assert composed.workspace_hub.code_copies is not None
            _states_the_table(source.profile(_STATUS, _MANIFEST))
        finally:
            await _close(composed)

    digests: dict[str, str] = {}
    for name, config in (
        ("plain", FinishUpConfig()),
        ("absent", _configured("[server]\n")),
        ("disabled", _configured(_DISABLED)),
    ):
        with release_l2():
            composed = await _composed(tmp_path / name, config)
        try:
            source = composed.server_profile
            assert not source.keeps_copies, name
            assert composed.workspace_hub.code_copies is None, name
            profile = source.profile(_STATUS, _MANIFEST)
            assert profile.levels.offered == ("L1",), name
            assert (profile.code_sync, profile.retention, profile.exclusions) == (None, None, None)
            digests[name] = profile.profile_digest
        finally:
            await _close(composed)
    assert set(digests.values()) == {offer_digest(FinishUpConfig())}

    # The offer withdrawn later (the same state, the table disabled): the copies it left are
    # kept, listed, forgotten and expire, but nothing is synced or read from them.
    with release_l2():
        composed = await _composed(tmp_path / "released", _configured(_DISABLED))
    try:
        assert not composed.server_profile.keeps_copies
        retained = composed.workspace_hub.code_copies
        assert retained is not None and not retained.serving
    finally:
        await _close(composed)
