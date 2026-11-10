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

from builders.control_relay import hello_frame
from builders.rest_backend import STATUS, ScriptedRestBackend
from builders.server_profiles import TEST_REVISION, consent_to, profile_document
from builders.server_targets import ambient_home, open_remote_kinds
from finishup.adapters.control.unix_socket import AuthenticatedUnixStream, authenticate_peer
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


async def test_a_relayed_rest_stream_sends_nothing_once_its_repository_is_held(
    lab: _Lab, monkeypatch: pytest.MonkeyPatch
) -> None:
    """B3: the helper binds each relayed REST stream to the admission it was opened under and to
    the repository its hello claims; a hold that lands after the relay was admitted withholds the
    stream's next request, though the helper's target-wide admission still admits."""

    import base64
    from collections.abc import Mapping
    from typing import cast

    from finishup.client import repository_hold
    from finishup.client.workspace_claim import worktree_digest
    from finishup.service.control_protocol import decode_control_frame

    salt = base64.b64decode(str(lab.record.claim_salt))
    held: list[str] = []

    def held_now(_root: Path, _target: str) -> tuple[str, ...]:
        return tuple(held)

    monkeypatch.setattr(repository_hold, "held_worktrees", held_now)
    hello: dict[str, object] = dict(
        decode_control_frame(hello_frame(agent=True, server_profile=TEST_REVISION))
    )
    claim = dict(cast(Mapping[str, object], hello["workspace_claim"]))
    claim["worktree"] = worktree_digest("/work/held", salt)
    hello["workspace_claim"] = claim
    helper = Helper(lab.root, lab.record, refresher=_no_refresh)
    client, local = _pair()
    relay = asyncio.create_task(helper._serve_local(local))  # pyright: ignore[reportPrivateUsage]
    try:
        async with asyncio.timeout(10):
            await client.send_all(encode_control_frame(hello))
            assert await client.receive(65_536)  # admitted: session and agent registered
            held.append("/work/held")
            await client.send_all(_call_frame())
            answered = await client.receive(65_536)
        # The stream ends (its agent's next poll is withheld too) or answers the call as never
        # sent; either way nothing more of that repository reached the server.
        assert answered == b"" or b'"code":"service_unavailable"' in answered
        assert lab.backend.calls == []
        assert len(lab.backend.agents) == 1
    finally:
        await client.aclose()
        await asyncio.wait_for(relay, timeout=10)
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
