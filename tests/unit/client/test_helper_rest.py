"""The helper's REST upstream and the direct REST style (ADR-053, design v2 sections 3 and 8.4).

An HTTPS target's helper relays a local connection through the frame-to-REST mapping to the real
REST routes (a scripted backend, served over ``httpx``'s ASGI transport): the hello and calls reach
the server, a refused revision is named by the helper and the local connection ends unanswered.
Approach A's HTTPS lifecycle fixes are regressions here: the key is read off the event loop
(A-KEYRING-LOOP), a key stored or moved after the helper started takes effect (A-CRED-STALE). The
direct style dials its own REST stream and reads the key itself; with no key nothing is sent.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import threading
from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import httpx
import pytest

from builders.control_relay import RELAY_KEY, hello_frame, relay_binding_frame
from builders.rest_backend import STATUS, ScriptedRestBackend
from builders.server_profiles import TEST_REVISION, consent_to, profile_document
from builders.server_targets import ambient_home, open_remote_kinds
from finishup.adapters.control.unix_socket import (
    AuthenticatedUnixStream,
    LocalControlTransportError,
    authenticate_peer,
)
from finishup.client import rest_client, targets
from finishup.client.authorization import bump_credential_generation
from finishup.client.credentials import KeyringOrFileCredential
from finishup.client.helper import Helper, RestUpstream
from finishup.client.helper_status import read_helper_status, write_connection_style
from finishup.client.rest_client import RestTransport
from finishup.client.targets import ServerTarget
from finishup.ports.control import ControlClientKind, ControlError, ControlMethod
from finishup.protocol.server_profile import ServerProfileRevision
from finishup.rest.api_keys import ApiKeyStore
from finishup.rest.app import RestApp
from finishup.service.control_protocol import encode_control_frame

pytestmark = pytest.mark.anyio


@dataclass
class _Lab:
    record: ServerTarget
    root: Path
    backend: ScriptedRestBackend
    app: RestApp
    keys: ApiKeyStore
    key: str


def _store_key(record: ServerTarget, root: Path, key: str) -> None:
    location = KeyringOrFileCredential(record.target_id, root, recorded=record.credential).store(
        key
    )
    with targets.registry_lock():
        stored = targets.read_target(root)
        assert stored is not None
        targets.write_target(root, replace(stored, credential=location))


@pytest.fixture
def lab(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Lab]:
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.fail.Keyring")
    base = Path.home() / f".yz-helper-rest-{os.getpid()}-{id(object())}"
    base.mkdir(mode=0o700)
    try:
        with ambient_home(monkeypatch):
            open_remote_kinds(monkeypatch, "https", rest=True)
            with targets.registry_lock():
                record, root = targets.new_remote_target(
                    "web", "https", base_url="https://web.example"
                )
            document = profile_document()
            document["edges"] = ["rest-1"]
            consent_to(record, document)
            keys = ApiKeyStore(base / "rest")
            _key_record, key = keys.create("laptop", "agent")
            _store_key(record, root, key)
            record = targets.read_target(root)
            assert record is not None
            backend = ScriptedRestBackend()
            app = RestApp(backend, keys)
            original = RestTransport.for_target.__func__  # type: ignore[attr-defined]

            def for_target(
                cls: type[RestTransport],
                target: ServerTarget,
                *,
                key: str | None,
                transport: Any = None,
                consented: bool = False,
            ) -> RestTransport:
                del transport
                return original(
                    cls,
                    target,
                    key=key,
                    transport=httpx.ASGITransport(app=app.asgi()),
                    consented=consented,
                )

            monkeypatch.setattr(RestTransport, "for_target", classmethod(for_target))
            yield _Lab(record, root, backend, app, keys, key)
    finally:
        shutil.rmtree(base, ignore_errors=True)


def _pair() -> tuple[AuthenticatedUnixStream, AuthenticatedUnixStream]:
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    return (
        AuthenticatedUnixStream(left, authenticate_peer(left)),
        AuthenticatedUnixStream(right, authenticate_peer(right)),
    )


async def _no_refresh(_record: ServerTarget) -> None:
    return None


def _call_frame() -> bytes:
    from builders.control_relay import call_request

    request = call_request(1, ControlMethod.SERVICE_STATUS)
    return encode_control_frame(
        replace(
            request,
            service_instance_id=STATUS.service_instance_id,
            service_generation=STATUS.service_generation,
        )
    )


async def test_a_relayed_connection_reaches_the_rest_server_through_the_helper(lab: _Lab) -> None:
    helper = Helper(lab.root, lab.record, refresher=_no_refresh)
    client, local = _pair()
    relay = asyncio.create_task(helper._serve_local(local))  # pyright: ignore[reportPrivateUsage]
    try:
        async with asyncio.timeout(10):
            await client.send_all(hello_frame(server_profile=TEST_REVISION))
            assert await client.receive(65_536)  # the hello-result, from GET /v1/session
            await client.send_all(_call_frame())
            answered = await client.receive(65_536)
        assert b'"outcome":"ok"' in answered
        assert len(lab.backend.sessions) == 1 and len(lab.backend.calls) == 1
        status = read_helper_status(lab.root)
        assert status is not None and status.phase == "ready"
    finally:
        await client.aclose()
        await asyncio.wait_for(relay, timeout=10)
        await helper._upstream.close()  # pyright: ignore[reportPrivateUsage]


async def test_a_revision_the_server_refuses_is_named_by_the_helper(lab: _Lab) -> None:
    lab.backend.revision = ServerProfileRevision(TEST_REVISION.issuer, 7, "sha256:" + "c" * 64)
    helper = Helper(lab.root, lab.record, refresher=_no_refresh)
    client, local = _pair()
    relay = asyncio.create_task(helper._serve_local(local))  # pyright: ignore[reportPrivateUsage]
    try:
        async with asyncio.timeout(10):
            await client.send_all(hello_frame(server_profile=TEST_REVISION))
            assert await client.receive(65_536) == b""
            await relay
        status = read_helper_status(lab.root)
        assert status is not None
        assert (status.phase, status.reason) == ("unavailable", "server_profile_changed")
        assert lab.backend.calls == []
    finally:
        await client.aclose()
        await helper._upstream.close()  # pyright: ignore[reportPrivateUsage]


async def test_the_key_is_read_off_the_loop_so_a_blocked_store_never_freezes_the_helper(
    lab: _Lab, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A-KEYRING-LOOP: a locked keyring's prompt holds a worker thread, never the event loop."""

    release = threading.Event()
    entered = threading.Event()

    def blocked(_target_id: str) -> str:
        entered.set()
        release.wait(20)
        return lab.key

    monkeypatch.setattr(rest_client, "_read_key", blocked)
    upstream = RestUpstream(lab.root, lab.record, may_send=lambda: True)
    ensuring = asyncio.create_task(upstream.ensure())
    try:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 10
        while not entered.is_set():
            assert loop.time() < deadline
            await asyncio.sleep(0)
        ticks = 0
        stop = asyncio.Event()

        async def tick() -> None:
            nonlocal ticks
            while not stop.is_set():
                ticks += 1
                await asyncio.sleep(0)

        ticker = asyncio.create_task(tick())
        while ticks < 50:
            assert loop.time() < deadline
            await asyncio.sleep(0)
        assert not ensuring.done()
        stop.set()
        await ticker
    finally:
        release.set()
        await asyncio.wait_for(ensuring, timeout=10)
        await upstream.close()


async def test_a_key_stored_after_the_helper_started_takes_effect(lab: _Lab) -> None:
    """A-CRED-STALE: the owner's login moves the credential generation; the key is read again."""

    upstream = RestUpstream(lab.root, lab.record, may_send=lambda: True)
    try:
        await upstream.ensure()
        first = upstream._transport  # pyright: ignore[reportPrivateUsage]
        _record, newer = lab.keys.create("rotated", "agent")
        _store_key(lab.record, lab.root, newer)
        bump_credential_generation(lab.root)
        await upstream.ensure()
        second = upstream._transport  # pyright: ignore[reportPrivateUsage]
        assert second is not None and second is not first and first is not None
        assert first.closed
        assert second.headers()["authorization"] == f"Bearer {newer}"
    finally:
        await upstream.close()


async def test_the_direct_style_reads_the_key_itself_and_sends_nothing_without_one(
    lab: _Lab,
) -> None:
    from finishup.config.paths import selection_override
    from finishup.service.client import connect_service_on_demand

    write_connection_style(lab.root, "direct")
    with selection_override(lab.root):
        client = await connect_service_on_demand(ControlClientKind.CLI, timeout_seconds=10.0)
        try:
            status = await client.service_status()
            assert status.service_instance_id == STATUS.service_instance_id
            assert client.transport == "https"
        finally:
            await client.close()
        with targets.registry_lock():
            stored = targets.read_target(lab.root)
            assert stored is not None
            targets.write_target(lab.root, replace(stored, credential=None))
        before = len(lab.backend.sessions)
        with pytest.raises(ControlError) as refused:
            await connect_service_on_demand(ControlClientKind.CLI, timeout_seconds=10.0)
        assert refused.value.phase == "remote_auth_failed"
        assert len(lab.backend.sessions) == before


def _held_by_key(key: str) -> None:
    """The everyday FinishUP reports repository ``key`` allows no network use now, from a worktree
    other than any a relay serves (the one relayed was evicted from the record, or never listed)."""

    from finishup.client.everyday_policy import record_repository_report

    assert record_repository_report(key, "/work/elsewhere", no_network=True)


def _relay_hello() -> bytes:
    return hello_frame(agent=True, server_profile=TEST_REVISION)


async def test_a_relayed_rest_stream_sends_nothing_once_its_repository_is_held(
    lab: _Lab, monkeypatch: pytest.MonkeyPatch
) -> None:
    """B3: the helper binds each relayed connection, and its REST stream's own requests, to the
    repository key the client named for it: a hold of that repository that lands after the relay
    was admitted withholds the next request, though the record lists none of the relay's
    worktrees and the helper's target-wide admission still admits."""

    from collections.abc import Callable

    from finishup.client.rest_stream import RestControlStream

    bound: list[Callable[[], str | None]] = []
    original_bind = RestControlStream.bind

    def bind(self: RestControlStream, refusal: Callable[[], str | None]) -> None:
        bound.append(refusal)
        original_bind(self, refusal)

    monkeypatch.setattr(RestControlStream, "bind", bind)
    helper = Helper(lab.root, lab.record, refresher=_no_refresh)
    client, local = _pair()
    relay = asyncio.create_task(helper._serve_local(local))  # pyright: ignore[reportPrivateUsage]
    try:
        async with asyncio.timeout(10):
            await client.send_all(relay_binding_frame())
            await client.send_all(_relay_hello())
            assert await client.receive(65_536)  # admitted: session and agent registered
            assert [check() for check in bound] == [None]
            _held_by_key(RELAY_KEY)
            # The stream's own retries and polls ask this before they leave.
            assert [check() for check in bound] == ["repository_egress_held"]
            await client.send_all(_call_frame())
            answered = await client.receive(65_536)
        assert answered == b""
        assert lab.backend.calls == []
        assert len(lab.backend.agents) == 1
        # Only this relay ended: the helper's own admission still admits.
        assert helper._admitted() is not None  # pyright: ignore[reportPrivateUsage]
    finally:
        await client.aclose()
        await asyncio.wait_for(relay, timeout=10)
        await helper._upstream.close()  # pyright: ignore[reportPrivateUsage]


async def test_a_held_repository_is_refused_by_its_key_whatever_worktrees_its_record_lists(
    lab: _Lab,
) -> None:
    """B3: past the record's eight worktrees per repository, the oldest are dropped; the relay's
    check asks the repository's own key, so a relayed worktree the record no longer lists is held
    with it, and another repository's relay is not."""

    from finishup.client.everyday_policy import (
        MAX_WORKTREES_PER_REPORT,
        record_repository_report,
    )

    helper = Helper(lab.root, lab.record, refresher=_no_refresh)
    admission = helper._admitted()  # pyright: ignore[reportPrivateUsage]
    assert admission is not None
    relayed = admission.for_repository(RELAY_KEY)
    other = admission.for_repository("sha256:" + "0f" * 32)
    refusal = helper._relay_refusal  # pyright: ignore[reportPrivateUsage]
    assert refusal(admission, relayed) is None
    for index in range(MAX_WORKTREES_PER_REPORT + 2):
        assert record_repository_report(RELAY_KEY, f"/work/linked-{index}", no_network=True)
    assert refusal(admission, relayed) == "repository_egress_held"
    assert refusal(admission, other) is None
    assert refusal(admission, None) is None


async def test_a_relayed_hello_that_claims_a_workspace_without_its_repository_is_never_sent(
    lab: _Lab,
) -> None:
    """B3: a relay cannot be bound to a repository its client did not name: its hello is never
    forwarded, and nothing reaches the server."""

    helper = Helper(lab.root, lab.record, refresher=_no_refresh)
    client, local = _pair()
    relay = asyncio.create_task(helper._serve_local(local))  # pyright: ignore[reportPrivateUsage]
    try:
        async with asyncio.timeout(10):
            await client.send_all(_relay_hello())
            assert await client.receive(65_536) == b""
            await relay
        assert lab.backend.sessions == []
        assert lab.backend.agents == []
    finally:
        await client.aclose()
        await helper._upstream.close()  # pyright: ignore[reportPrivateUsage]


async def test_a_malformed_relay_binding_is_never_read_as_a_hello(lab: _Lab) -> None:
    helper = Helper(lab.root, lab.record, refresher=_no_refresh)
    client, local = _pair()
    relay = asyncio.create_task(helper._serve_local(local))  # pyright: ignore[reportPrivateUsage]
    try:
        async with asyncio.timeout(10):
            damaged = relay_binding_frame().replace(b"sha256:", b"sha512:")
            await client.send_all(damaged + _relay_hello())
            await relay
            try:
                answered = await client.receive(65_536)
            except LocalControlTransportError:
                answered = b""  # closed with the hello still unread: a reset, not an answer
            assert answered == b""
        assert lab.backend.sessions == []
    finally:
        await client.aclose()
        await helper._upstream.close()  # pyright: ignore[reportPrivateUsage]


async def test_the_rest_profile_refresh_asks_before_each_of_its_requests(lab: _Lab) -> None:
    """B2: the helper's background refresh stops between its requests once it may not send
    (here: the helper is stopping after discovery was asked)."""

    from finishup.client import helper as helper_module

    helper = Helper(lab.root, lab.record)
    asked: list[bool] = []
    original = helper._may_refresh_send  # pyright: ignore[reportPrivateUsage]

    def may_send() -> bool:
        allowed = original()
        asked.append(allowed)
        if len(asked) == 1:
            helper.request_stop("stop_requested")  # lands while discovery is answered
        return allowed

    with pytest.raises(helper_module.UpstreamUnavailable):
        await helper_module._refresh_over_rest(  # pyright: ignore[reportPrivateUsage]
            lab.record, may_send=may_send
        )
    assert asked == [True, False]
    assert lab.backend.sessions == []


# --- review fixes, second round -------------------------------------------------------------------


async def test_a_refresh_fetched_before_a_login_never_records_its_profile_for_the_new_key(
    lab: _Lab, monkeypatch: pytest.MonkeyPatch
) -> None:
    """C2: the owner's login lands while the helper's refresh is fetching with the previous key;
    the profile it fetched is never recorded for the key stored now (it would restore the
    previous key's consent eligibility), and a refresh with nothing changed still records."""

    from finishup.client import helper as helper_module
    from finishup.client import rest_discovery
    from finishup.client.server_profile import forget_cached_profile, read_cached_profile
    from finishup.client.targets import TargetError

    original = rest_discovery.fetch_profile_async
    login = {"now": True}

    async def fetched_then_login(record: ServerTarget, **options: Any) -> Any:
        fetched = await original(record, **options)
        if login["now"]:
            # What 'server login' does first, under the registry lock: the previous key's
            # profile is forgotten and the credential generation moves.
            with targets.registry_lock():
                forget_cached_profile(lab.root)
                assert bump_credential_generation(lab.root)
        return fetched

    monkeypatch.setattr(rest_discovery, "fetch_profile_async", fetched_then_login)
    refresh = helper_module._refresh_over_rest  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(TargetError) as changed:
        await refresh(lab.record, may_send=lambda: True)
    assert changed.value.reason == "server_authorization_changed"
    assert read_cached_profile(lab.root) is None
    login["now"] = False
    await refresh(lab.record, may_send=lambda: True)
    assert read_cached_profile(lab.root) is not None


async def test_the_refresh_sends_nothing_with_the_old_key_once_the_owner_logged_out(
    lab: _Lab, monkeypatch: pytest.MonkeyPatch
) -> None:
    """B2: a logout (the credential generation moving) between the refresh's requests withholds
    every later one: the profile request is never sent with the key read before it."""

    from finishup.client import helper as helper_module
    from finishup.client import rest_discovery
    from finishup.client.ssh_transport import UpstreamUnavailable

    profiles: list[int] = []
    original_profile = ScriptedRestBackend.profile

    async def counted(self: ScriptedRestBackend) -> Any:
        profiles.append(1)
        return await original_profile(self)

    monkeypatch.setattr(ScriptedRestBackend, "profile", counted)
    original_discover = rest_discovery.discover

    async def discover_then_logout(transport: RestTransport) -> Any:
        discovery = await original_discover(transport)
        assert bump_credential_generation(lab.root)  # 'server logout' lands now
        return discovery

    monkeypatch.setattr(rest_discovery, "discover", discover_then_logout)
    with pytest.raises(UpstreamUnavailable):
        await helper_module._refresh_over_rest(  # pyright: ignore[reportPrivateUsage]
            lab.record, may_send=lambda: True
        )
    assert profiles == []


async def test_the_refresh_asks_the_stop_epoch_before_each_request(lab: _Lab) -> None:
    """B2: a stop (``server logout``, ``disconnect``, ...) moves the target's stop epoch; the
    refresh asks it before each request, before the helper's next tick sees it."""

    from finishup.client import helper_status

    helper = Helper(lab.root, lab.record)
    may_send = helper._may_refresh_send  # pyright: ignore[reportPrivateUsage]
    assert may_send()
    assert helper_status._move_helper_epoch(lab.root)  # pyright: ignore[reportPrivateUsage]
    assert not may_send()


async def _refused_relay(helper: Helper, *, own: bool) -> bytes:
    client, local = _pair()
    relay = asyncio.create_task(helper._serve_local(local, own=own))  # pyright: ignore[reportPrivateUsage]
    try:
        async with asyncio.timeout(10):
            await client.send_all(hello_frame(server_profile=TEST_REVISION))
            answered = await client.receive(65_536)
            await relay
    finally:
        await client.aclose()
    return answered


async def test_a_refused_revision_is_named_to_each_client_after_the_agents_refusal(
    lab: _Lab,
) -> None:
    """Defect B (dogfood, 2026-11-11): once the helper's background agent was refused the old
    revision, a client's relay refused the same way was not named to the client, which retried
    until its deadline and read ``remote_unreachable``; it is named ``server_profile_changed``."""

    from finishup.service.client import _helper_failure  # pyright: ignore[reportPrivateUsage]

    lab.backend.revision = ServerProfileRevision(TEST_REVISION.issuer, 7, "sha256:" + "c" * 64)
    helper = Helper(lab.root, lab.record, refresher=_no_refresh)
    try:
        assert await _refused_relay(helper, own=True) == b""
        before = read_helper_status(lab.root)
        assert await _refused_relay(helper, own=False) == b""
        named = _helper_failure(lab.root, before)
    finally:
        await helper._upstream.close()  # pyright: ignore[reportPrivateUsage]
    assert named is not None and named.phase == "server_profile_changed"
    assert lab.backend.calls == []


@pytest.mark.parametrize("own", [True, False])
async def test_a_refused_revision_asks_for_the_profile_at_once(lab: _Lab, own: bool) -> None:
    """Defect B: over HTTPS the refusal of the old revision ends the relayed stream unanswered, so
    the helper's agent never saw the typed ``server_profile_changed`` an SSH relay passes on, and
    the profile was fetched again only at the ten-minute refresh: the consent never read
    ``changed``. The helper itself asks for the refresh (still at most every 30 s)."""

    fetched: list[str] = []

    async def refresher(record: ServerTarget) -> None:
        fetched.append(record.target_id)

    class Clock:
        now = 1_000.0

        def __call__(self) -> float:
            return self.now

    clock = Clock()
    helper = Helper(lab.root, lab.record, refresher=refresher, clock=clock)
    try:
        await helper._run_refresh()  # pyright: ignore[reportPrivateUsage]  # the start's fetch
        assert fetched == [lab.record.target_id]
        lab.backend.revision = ServerProfileRevision(TEST_REVISION.issuer, 7, "sha256:" + "c" * 64)
        clock.now += 31.0
        assert await _refused_relay(helper, own=own) == b""
        await helper.step()
        task = helper._refresh.task  # pyright: ignore[reportPrivateUsage]
        if task is not None:
            await asyncio.wait_for(task, timeout=10)
    finally:
        await helper._upstream.close()  # pyright: ignore[reportPrivateUsage]
        await helper._close_agents()  # pyright: ignore[reportPrivateUsage]
    assert fetched == [lab.record.target_id] * 2
