"""The service holds every remote connection to the profile revision its client consented to.

ADR-052, design v2 section 8.2: the server issues an authenticated profile revision; a remote
client's hello names the one it consented to, and the service refuses any other one before it
consumes any work (``server_profile_changed``): before the claim is keyed or an agent registered,
and, on a connection admitted earlier, before any request that does work. The structural methods
and ``server_profile`` itself are still answered, so a client can learn what changed. A local
connection names no revision and is never held to one.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hmac
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import cast

import pytest

from builders.workspace_agent_fake import fake_declaration
from finishup.config.models import FinishUpConfig, SemanticFallbackConfig
from finishup.config.write import codex_subscription_runtime, fireworks_provider
from finishup.domain.values import JsonObject
from finishup.ports.control import ControlClientKind, ControlError, ControlMethod, WorkspaceClaim
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.consent_envelope import ReviewEgress
from finishup.protocol.schemas import validate_schema_instance
from finishup.protocol.server_profile import (
    ServerProfileRevision,
    consent_subset,
    profile_digest,
    profile_from_json,
)
from finishup.service.control_protocol import ControlProtocolError, client_handshake
from finishup.service.daemon import ServiceDaemon
from finishup.service.server_profile import OFFERED_LEVELS, ServerProfileSource
from integration.service import test_daemon_clients as clients
from integration.service.test_claim_bound_sessions import (
    _ClaimClient,  # pyright: ignore[reportPrivateUsage]
    _pair,  # pyright: ignore[reportPrivateUsage]
)

pytestmark = pytest.mark.anyio

_NO_REVIEW = ReviewEgress("none", None)
_REVIEW = ReviewEgress("server_policy", "openai")


def _digest(review: ReviewEgress) -> str:
    return profile_digest(
        consent_subset(
            levels=OFFERED_LEVELS, code_sync=None, retention=None, exclusions=None, review=review
        )
    )


_REVISION = ServerProfileRevision("1" * 32, 3, _digest(_NO_REVIEW))
_NEXT = ServerProfileRevision("1" * 32, 4, _digest(_REVIEW))
_CLAIM = WorkspaceClaim("git_common_root", "sha256:" + "c" * 64, "sha256:" + "d" * 64)


def _source(revision: ServerProfileRevision) -> ServerProfileSource:
    return ServerProfileSource(_NO_REVIEW if revision == _REVISION else _REVIEW, revision)


@dataclasses.dataclass
class _Running:
    daemon: ServiceDaemon
    application: clients._Application  # pyright: ignore[reportPrivateUsage]
    served: list[asyncio.Task[None]]

    def issue(self, revision: ServerProfileRevision | None) -> None:
        """The service now issues ``revision`` (a profile changed at a restart, or later)."""

        composition = dataclasses.replace(
            self.daemon.composition,
            server_profile=None if revision is None else _source(revision),
        )
        self.daemon._composition = composition  # pyright: ignore[reportPrivateUsage]

    async def connect(
        self,
        *,
        claim: WorkspaceClaim | None,
        server_profile: ServerProfileRevision | None,
        agent: bool = False,
    ) -> _ClaimClient:
        client_stream, server_stream = _pair()
        self.served.append(
            asyncio.create_task(
                self.daemon._serve_control_connection(server_stream)  # pyright: ignore[reportPrivateUsage, reportArgumentType]
            )
        )
        session = await client_handshake(
            client_stream,  # pyright: ignore[reportArgumentType]
            ControlClientKind.CLI,
            "0.3.0",
            workspace_claim=claim,
            workspace_agent=fake_declaration() if agent else None,
            server_profile=server_profile,
        )
        client = _ClaimClient(client_stream, session, None)
        client.start()
        return client


class _MacKey:
    def mac(self, domain: bytes, message: bytes) -> str:
        return "hmac-sha256:" + hmac.digest(b"k" * 32, domain + message, "sha256").hex()


class _KeyedVault(clients._Vault):  # pyright: ignore[reportPrivateUsage]
    """The daemon tests' vault, able to key a workspace claim (its installation MAC)."""

    def installation_mac_handle(self, purpose: object) -> _MacKey:
        del purpose
        return _MacKey()


@asynccontextmanager
async def _running(revision: ServerProfileRevision | None) -> AsyncGenerator[_Running]:
    daemon, application, _vault, _listener = clients._daemon()  # pyright: ignore[reportPrivateUsage]
    keyed = dataclasses.replace(daemon.composition, vault=_KeyedVault())
    daemon._composition = keyed  # pyright: ignore[reportPrivateUsage]
    running = _Running(daemon, application, [])
    running.issue(revision)
    await daemon.start()
    try:
        yield running
    finally:
        for task in running.served:
            task.cancel()
        await asyncio.gather(*running.served, return_exceptions=True)
        await daemon.close()


def _check() -> object:
    return clients._check_body()  # pyright: ignore[reportPrivateUsage]


async def test_a_claim_bound_connection_under_the_current_revision_is_served() -> None:
    async with _running(_REVISION) as service:
        client = await service.connect(claim=_CLAIM, server_profile=_REVISION, agent=True)
        try:
            assert client.session.server_profile == _REVISION
            assert client.session.workspace_handle is not None
            assert service.daemon.composition.workspace_hub.has_agent(
                client.session.workspace_handle
            )
            await client.call(ControlMethod.CHECK, _check())
            assert len(service.application.check_requests) == 1
        finally:
            await client.close()


@pytest.mark.parametrize("presented", [_NEXT, None], ids=["stale", "none"])
async def test_another_revision_is_refused_before_the_claim_is_keyed_or_an_agent_registered(
    presented: ServerProfileRevision | None,
) -> None:
    async with _running(_REVISION) as service:
        with pytest.raises(ControlProtocolError) as refused:
            await service.connect(claim=_CLAIM, server_profile=presented, agent=True)
        assert refused.value.reason == "server_profile_changed"
        await asyncio.gather(*service.served, return_exceptions=True)
        hub = service.daemon.composition.workspace_hub
        assert hub._channels == {}  # pyright: ignore[reportPrivateUsage]
        assert service.application.check_requests == []


async def test_a_revision_issued_after_admission_refuses_work_but_still_answers_the_profile() -> (
    None
):
    async with _running(_REVISION) as service:
        client = await service.connect(claim=_CLAIM, server_profile=_REVISION, agent=True)
        try:
            service.issue(_NEXT)

            refused = await client.call(ControlMethod.CHECK, _check())
            assert isinstance(refused, ControlError)
            assert refused.reason == "server_profile_changed"
            assert service.application.check_requests == []

            answered = await client.call(ControlMethod.SERVER_PROFILE, JsonObject({}))
            profile = profile_from_json(canonical_encode(cast(JsonValue, answered)))
            assert profile.revision == _NEXT
            status = await client.call(ControlMethod.SERVICE_STATUS, JsonObject({}))
            assert not isinstance(status, ControlError)
        finally:
            await client.close()


async def test_a_local_connection_reads_the_profile_and_is_never_held_to_a_revision() -> None:
    async with _running(_REVISION) as service:
        client = await service.connect(claim=None, server_profile=None)
        try:
            assert client.session.server_profile is None
            answered = await client.call(ControlMethod.SERVER_PROFILE, JsonObject({}))
            document = canonical_encode(cast(JsonValue, answered))
            validate_schema_instance("server-profile", "1.0.0", cast(JsonValue, answered))
            assert profile_from_json(document).revision == _REVISION

            service.issue(_NEXT)
            await client.call(ControlMethod.CHECK, _check())
            assert len(service.application.check_requests) == 1
        finally:
            await client.close()


async def test_a_service_that_issues_no_revision_refuses_the_profile_method() -> None:
    async with _running(None) as service:
        client = await service.connect(claim=None, server_profile=None)
        try:
            refused = await client.call(ControlMethod.SERVER_PROFILE, JsonObject({}))
            assert isinstance(refused, ControlError)
            assert refused.reason == "method_forbidden"
        finally:
            await client.close()


# --- a review provider paired after the consent (review of layer 3: A1) -------------------------


def _paired_configs() -> tuple[FinishUpConfig, FinishUpConfig]:
    digest = "sha256:" + "a" * 64
    runtime = codex_subscription_runtime(
        executable_path="/opt/codex/bin/codex",
        executable_sha256=digest,
        runtime_version="0.150.1",
        source_identity="openai-codex-npm-linux-x64-0.150.1",
        app_server_schema_sha256=digest,
        capability_cell_sha256=digest,
        isolated_config_sha256=digest,
        capability_profile="codex-evaluator/0.150.1/v1",
        capability_evidence_expires_at="2026-11-30T00:00:00Z",
        codex_home="/opt/codex/home",
        model="gpt-test",
        reasoning_effort="high",
    )
    single = FinishUpConfig(profile="local-openai", provider=fireworks_provider(model="m"))
    paired = FinishUpConfig(
        profile="local-openai",
        provider=fireworks_provider(model="m"),
        external_runtime=runtime,
        semantic_fallback=SemanticFallbackConfig(primary="api_provider"),
    )
    return single, paired


async def test_a_hello_consented_before_a_fallback_provider_was_paired_is_refused(
    tmp_path: Path,
) -> None:
    """The server restarted with a Codex fallback paired to its Fireworks review: a client whose
    consent named only Fireworks is not admitted, and one under the new revision is."""

    tmp_path.chmod(0o700)
    single, paired = _paired_configs()
    consented = cast(ServerProfileRevision, ServerProfileSource.load(single, tmp_path).revision)
    restarted = ServerProfileSource.load(paired, tmp_path)
    current = cast(ServerProfileRevision, restarted.revision)
    assert current != consented
    async with _running(None) as service:
        service.daemon._composition = dataclasses.replace(  # pyright: ignore[reportPrivateUsage]
            service.daemon.composition, server_profile=restarted
        )
        with pytest.raises(ControlProtocolError) as refused:
            await service.connect(claim=_CLAIM, server_profile=consented, agent=True)
        assert refused.value.reason == "server_profile_changed"
        await asyncio.gather(*service.served, return_exceptions=True)
        assert service.daemon.composition.workspace_hub._channels == {}  # pyright: ignore[reportPrivateUsage]
        assert service.application.check_requests == []

        client = await service.connect(claim=_CLAIM, server_profile=current, agent=True)
        try:
            await client.call(ControlMethod.CHECK, _check())
            assert len(service.application.check_requests) == 1
            answered = await client.call(ControlMethod.SERVER_PROFILE, JsonObject({}))
            profile = profile_from_json(canonical_encode(cast(JsonValue, answered)))
            assert profile.review == ReviewEgress("server_policy", "fireworks", "openai-codex")
        finally:
            await client.close()


async def test_a_service_that_cannot_state_its_review_admits_no_remote_hello_and_no_profile() -> (
    None
):
    """A configuration the profile cannot state exactly offers none: every hello that names a
    revision or a claim is refused, and the profile is not answered; a local client is served."""

    async with _running(None) as service:
        service.daemon._composition = dataclasses.replace(  # pyright: ignore[reportPrivateUsage]
            service.daemon.composition, server_profile=ServerProfileSource(None, None)
        )
        with pytest.raises(ControlProtocolError) as refused:
            await service.connect(claim=_CLAIM, server_profile=_REVISION, agent=True)
        assert refused.value.reason == "server_profile_changed"
        # A claim named under no revision at all is not admitted either.
        with pytest.raises(ControlProtocolError):
            await service.connect(claim=_CLAIM, server_profile=None, agent=True)
        await asyncio.gather(*service.served, return_exceptions=True)
        assert service.daemon.composition.workspace_hub._channels == {}  # pyright: ignore[reportPrivateUsage]
        assert service.application.check_requests == []

        client = await service.connect(claim=None, server_profile=None)
        try:
            refused_profile = await client.call(ControlMethod.SERVER_PROFILE, JsonObject({}))
            assert isinstance(refused_profile, ControlError)
            assert refused_profile.reason == "method_forbidden"
            await client.call(ControlMethod.CHECK, _check())
            assert len(service.application.check_requests) == 1
        finally:
            await client.close()
