"""Identical fault vectors over direct REST, relay REST and SSH control (ADR-053, design v2 §8.4).

One scripted service (``builders.control_relay.ScriptedDaemon``) stands behind three transports a
``ServiceClient`` can use:

* ``ssh_control`` — control frames straight to the service (what an SSH stream carries);
* ``direct_rest`` — this client's own frame-to-REST mapping (``RestControlStream``) to the real REST
  routes, whose gateway backend re-enters the service as control connections;
* ``relay_rest`` — the target's helper relaying a local connection through the same mapping.

Each vector is run over all three and must end the same way: an answered call, a stale revision
refused before any work, a cancel that reaches the service after its call, a lapsed authorization
that ends the connection before anything more is sent, a server that cannot be reached.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

from builders.control_relay import (
    SERVICE_ID,
    SLOW_METHOD,
    ScriptedDaemon,
    call_request,
    memory_pair,
)
from builders.server_profiles import TEST_REVISION, consent_to, profile_document
from builders.server_targets import ambient_home, open_remote_kinds
from finishup.adapters.control.unix_socket import AuthenticatedUnixStream, authenticate_peer
from finishup.client import targets
from finishup.client.helper import Helper
from finishup.client.helper_status import read_helper_status
from finishup.client.rest_client import RestTransport
from finishup.client.rest_stream import RestControlStream
from finishup.client.ssh_transport import UpstreamUnavailable
from finishup.gateway.backend import ControlSocketBackend
from finishup.ports.control import ControlClientKind, ControlError, ControlMethod
from finishup.protocol.server_profile import ServerProfileRevision
from finishup.rest.api_keys import ApiKeyStore
from finishup.rest.app import RestApp
from finishup.service.client import ServiceClient, connect_service_via
from finishup.service.control_protocol import ControlStream

pytestmark = pytest.mark.anyio

TRANSPORTS = ("ssh_control", "direct_rest", "relay_rest")


class _Admission:
    """An admission whose refusal a vector turns on (the authorization's own checks are layer 2's)."""

    server_profile = TEST_REVISION

    def __init__(self) -> None:
        self.phase: str | None = None

    def refusal(self) -> str | None:
        return self.phase


class _AsgiUpstream:
    """The helper's REST upstream over ``httpx``'s ASGI transport (no socket)."""

    def __init__(self, app: RestApp, key: str, *, reachable: bool = True) -> None:
        self._app = app
        self._key = key
        self.reachable = reachable

    async def ensure(self) -> None:
        if not self.reachable:
            raise UpstreamUnavailable("remote_unreachable")

    async def open_stream(self) -> ControlStream:
        await self.ensure()
        transport = RestTransport(
            "https://lab.example",
            key=self._key,
            transport=httpx.ASGITransport(app=self._app.asgi()),
        )
        return RestControlStream(transport, owns_transport=True)

    async def start_remote_service(self) -> bool:
        return False

    async def close(self, seconds: float | None = None) -> None:
        return None

    async def zero_network(self) -> None:
        return None


@dataclass
class _World:
    daemon: ScriptedDaemon
    app: RestApp
    key: str
    record: targets.ServerTarget
    root: Path
    admission: _Admission
    reachable: bool = True

    def _served(self) -> Callable[[], Awaitable[ControlStream]]:
        async def connect() -> ControlStream:
            if not self.reachable:
                raise UpstreamUnavailable("remote_unreachable")
            client, server = memory_pair()
            self.daemon.serving.append(asyncio.create_task(self.daemon.serve(server)))
            return client

        return connect

    def dial(self, transport: str) -> Callable[[], Awaitable[ControlStream]]:
        if transport == "ssh_control":
            return self._served()
        if transport == "direct_rest":

            async def direct() -> ControlStream:
                rest = RestTransport(
                    "https://lab.example",
                    key=self.key,
                    transport=httpx.ASGITransport(app=self.app.asgi()),
                )
                if not self.reachable:
                    await rest.aclose()
                    rest = RestTransport("https://127.0.0.1:1", key=self.key)
                return RestControlStream(rest, owns_transport=True)

            return direct
        helper = Helper(
            self.root,
            self.record,
            upstream=_AsgiUpstream(self.app, self.key, reachable=self.reachable),
            refresher=_no_refresh,
        )

        async def relay() -> ControlStream:
            ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            local = AuthenticatedUnixStream(theirs, authenticate_peer(theirs))
            helper._spawn_relay(local, own=False)  # pyright: ignore[reportPrivateUsage]
            return AuthenticatedUnixStream(ours, authenticate_peer(ours))

        return relay

    async def connect(self, transport: str) -> ServiceClient:
        return await connect_service_via(
            self.dial(transport),
            ControlClientKind.CLI,
            workspace_binding=None,
            authorization=cast(Any, self.admission),
            transport="https" if transport != "ssh_control" else "ssh",
        )


async def _no_refresh(_record: targets.ServerTarget) -> None:
    return None


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> Iterator[_World]:
    base = Path.home() / f".yz-vectors-{os.getpid()}-{id(object())}"
    base.mkdir(mode=0o700)
    try:
        with ambient_home(monkeypatch):
            open_remote_kinds(monkeypatch, "https", rest=True)
            with targets.registry_lock():
                record, root = targets.new_remote_target(
                    "lab", "https", base_url="https://lab.example"
                )
            document = profile_document()
            document["edges"] = ["rest-1"]
            record = consent_to(record, document)
            keys = ApiKeyStore(base / "rest")
            _key_record, key = keys.create("vectors", "operator")
            daemon = ScriptedDaemon()
            world = _World(daemon, None, key, record, root, _Admission())  # type: ignore[arg-type]
            world.app = RestApp(ControlSocketBackend(connect=world._served()), keys)  # pyright: ignore[reportPrivateUsage]
            yield world
    finally:
        shutil.rmtree(base, ignore_errors=True)


def _status_call() -> Any:
    return call_request(3, ControlMethod.SERVICE_STATUS)


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_an_answered_call_is_the_same_answer(world: _World, transport: str) -> None:
    client = await world.connect(transport)
    try:
        result = await client.call(_status_call())
    finally:
        await client.close()
    assert (result.outcome, result.rpc_id) == ("ok", _status_call().rpc_id)
    assert result.service_instance_id == SERVICE_ID


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_a_stale_revision_is_refused_before_any_work(world: _World, transport: str) -> None:
    world.daemon.profile_revision = ServerProfileRevision(
        TEST_REVISION.issuer, 9, "sha256:" + "c" * 64
    )
    with pytest.raises(ControlError) as refused:
        await world.connect(transport)
    if transport == "relay_rest":
        # The local connection ends unanswered; the helper names why (layer 4 decision 18).
        status = read_helper_status(world.root)
        assert status is not None and status.reason == "server_profile_changed"
    else:
        assert refused.value.phase == "server_profile_changed"
    # No call frame ever reached the service: every connection it read held its hello only.
    assert all(len(world.daemon.received(index)) == 1 for index in range(len(world.daemon.inbound)))


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_a_cancel_reaches_the_service_after_its_call(world: _World, transport: str) -> None:
    client = await world.connect(transport)
    slow = replace(call_request(0x51F0, SLOW_METHOD))
    try:
        task = asyncio.create_task(client.call(slow))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 10

        def frames() -> list[bytes]:
            return [
                frame
                for index in range(len(world.daemon.inbound))
                for frame in world.daemon.received(index)
            ]

        while not any(
            b'"kind":"call"' in frame and slow.rpc_id.encode() in frame for frame in frames()
        ):
            assert loop.time() < deadline
            await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        while not any(b'"kind":"cancel"' in frame for frame in frames()):
            assert loop.time() < deadline
            await asyncio.sleep(0)
        seen = frames()
        call_at = next(
            i
            for i, frame in enumerate(seen)
            if slow.rpc_id.encode() in frame and b'"kind":"call"' in frame
        )
        cancel_at = next(i for i, frame in enumerate(seen) if b'"kind":"cancel"' in frame)
        assert call_at < cancel_at
    finally:
        await client.close()


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_a_lapsed_authorization_ends_the_connection_before_more_is_sent(
    world: _World, transport: str
) -> None:
    client = await world.connect(transport)
    try:
        assert (await client.call(_status_call())).outcome == "ok"
        sent_before = sum(len(world.daemon.received(i)) for i in range(len(world.daemon.inbound)))
        world.admission.phase = "server_authorization_changed"
        with pytest.raises(ControlError) as ended:
            await client.call(call_request(4, ControlMethod.SERVICE_STATUS))
        assert ended.value.phase == "server_authorization_changed"
        sent_after = sum(len(world.daemon.received(i)) for i in range(len(world.daemon.inbound)))
        assert sent_after == sent_before
    finally:
        await client.close()


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_a_server_that_cannot_be_reached_is_remote_unreachable(
    world: _World, transport: str
) -> None:
    world.reachable = False
    with pytest.raises(ControlError) as refused:
        await world.connect(transport)
    if transport == "relay_rest":
        status = read_helper_status(world.root)
        assert status is not None and status.reason == "remote_unreachable"
    else:
        assert refused.value.phase == "remote_unreachable"
    assert world.daemon.connections == 0
