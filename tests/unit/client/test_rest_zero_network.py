"""Approach C's REST connections under this computer's zero-network record (ADR-051 decision 8).

Every REST connection asks the shared connection check first (``targets.
require_current_authorization``): ``connect_rest_service`` and ``open_rest_http`` refuse a remote
target while this computer last reported a zero-network policy, before anything is dialled, and
``_connect_remote`` refuses with or without a workspace to claim, noting nothing and starting no
workspace agent or SSH master. An open ``RestServiceClient`` (the MCP bridge's, the terminal
interface's) reads the record before every request and at least once a second: it closes, cuts a
long-poll under way, sends no cancel, and names ``zero_network_remote_selected``.
"""

from __future__ import annotations

import asyncio
import base64
import shutil
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from builders.network_api import FakeService, key_store, make_api
from finishup.client import rest_client
from finishup.client.everyday_policy import record_reported_policy, remove_marker
from finishup.client.rest_client import RestEndpoint, connect_rest_service, open_rest_http
from finishup.client.targets import ServerTarget
from finishup.ports.control import ControlClientKind, ControlError, WorkspaceLocator
from finishup.service import client as service_client
from finishup.service.api_keys import ApiKeyStore
from finishup.service.http_api import NetworkApi

_ZERO = "zero_network_remote_selected"
_RECORD = ServerTarget(
    "t_0a1b2c3d",
    "lab",
    "https",
    "2026-11-05T00:00:00.000Z",
    base_url="https://api.test",
    claim_salt=base64.b64encode(b"\x01" * 32).decode("ascii"),
    authorized_at="2026-11-05T00:00:00.000Z",
    disclosure_version=1,
)
_SSH_RECORD = ServerTarget(
    "t_0a1b2c3e",
    "box",
    "ssh",
    "2026-11-05T00:00:00.000Z",
    user="srv",
    host="127.0.0.1",
    port=2222,
    remote_launcher="/opt/finishup/bin/finishup",
    claim_salt=base64.b64encode(b"\x02" * 32).decode("ascii"),
    authorized_at="2026-11-05T00:00:00.000Z",
    disclosure_version=1,
)
_LOCAL_PORT_RECORD = ServerTarget(
    "t_0a1b2c3f",
    "port",
    "local_port",
    "2026-11-05T00:00:00.000Z",
    base_url="https://127.0.0.1:8443",
    claim_salt=base64.b64encode(b"\x03" * 32).decode("ascii"),
    authorized_at="2026-11-05T00:00:00.000Z",
    disclosure_version=1,
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def keys() -> Iterator[ApiKeyStore]:
    base = Path.home() / f".yz-rzn-{id(object())}"
    base.mkdir(mode=0o700)
    try:
        yield key_store(base)
    finally:
        shutil.rmtree(base, ignore_errors=True)


class _Recording(httpx.AsyncBaseTransport):
    """The API in process, recording every request it is given."""

    def __init__(self, api: NetworkApi) -> None:
        self._inner = httpx.ASGITransport(app=api.asgi("https"))  # type: ignore[arg-type]
        self.sent: list[str] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.sent.append(f"{request.method} {request.url.path}")
        return await self._inner.handle_async_request(request)


def _endpoint(transport: httpx.AsyncBaseTransport, token: str) -> RestEndpoint:
    return RestEndpoint("https", "https://api.test", transport, token)


def _zero_network() -> None:
    assert record_reported_policy(zero_network=True)


def _phase(error: pytest.ExceptionInfo[ControlError]) -> tuple[str, str | None, bool]:
    return error.value.reason, error.value.phase, error.value.retryable


@pytest.mark.anyio
async def test_a_rest_connection_is_refused_before_anything_is_dialled(
    keys: ApiKeyStore,
) -> None:
    _record, token = keys.create("laptop", "agent")
    transport = _Recording(make_api(FakeService(), keys))
    _zero_network()

    with pytest.raises(ControlError) as refused:
        await connect_rest_service(
            ControlClientKind.CLI,
            record=_RECORD,
            root=Path("/x"),
            _endpoint=_endpoint(transport, token),
        )

    assert _phase(refused) == ("service_unavailable", _ZERO, True)
    assert transport.sent == []
    # The workspace agent's own HTTP client goes through the same check.
    with pytest.raises(ControlError) as agent_refused:
        open_rest_http(_RECORD, Path("/x"))
    assert _phase(agent_refused) == ("service_unavailable", _ZERO, True)
    # A permitting report connects.
    assert remove_marker()
    client = await connect_rest_service(
        ControlClientKind.CLI,
        record=_RECORD,
        root=Path("/x"),
        _endpoint=_endpoint(transport, token),
    )
    await client.close()
    assert transport.sent == ["GET /v1/server"]


@pytest.mark.anyio
async def test_a_stale_disclosure_is_refused_by_the_same_check(
    keys: ApiKeyStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.client import targets

    _record, token = keys.create("laptop", "agent")
    transport = _Recording(make_api(FakeService(), keys))
    # A later release shows a newer disclosure than the one the owner confirmed.
    monkeypatch.setattr(targets, "DISCLOSURE_VERSION", targets.DISCLOSURE_VERSION + 1)
    stale = _RECORD

    with pytest.raises(ControlError) as refused:
        await connect_rest_service(
            ControlClientKind.CLI,
            record=stale,
            root=Path("/x"),
            _endpoint=_endpoint(transport, token),
        )

    assert _phase(refused) == ("service_unavailable", "target_reauthorization_required", True)
    assert transport.sent == []


@pytest.mark.anyio
async def test_an_open_client_refuses_its_next_call_before_sending_it(keys: ApiKeyStore) -> None:
    _record, token = keys.create("laptop", "agent")
    transport = _Recording(make_api(FakeService(), keys))
    client = await connect_rest_service(
        ControlClientKind.MCP_BRIDGE,
        record=_RECORD,
        root=Path("/x"),
        _endpoint=_endpoint(transport, token),
    )
    try:
        _zero_network()
        with pytest.raises(ControlError) as refused:
            await client.service_status()
        assert _phase(refused) == ("service_unavailable", _ZERO, True)
        # It stays refused, with the same phase, never a generic closed connection.
        with pytest.raises(ControlError) as again:
            await client.service_status()
        assert _phase(again) == ("service_unavailable", _ZERO, True)
    finally:
        await client.close()
    assert transport.sent == ["GET /v1/server"]


@pytest.mark.anyio
async def test_a_long_poll_under_way_is_cut_within_a_second_and_nothing_more_is_sent(
    keys: ApiKeyStore,
) -> None:
    _record, token = keys.create("laptop", "operator")
    gate = asyncio.Event()
    api = make_api(FakeService(gate=gate), keys)
    transport = _Recording(api)
    client = await connect_rest_service(
        ControlClientKind.CLI,
        record=_RECORD,
        root=Path("/x"),
        _endpoint=_endpoint(transport, token),
    )
    try:
        call = asyncio.ensure_future(client.service_status())
        # The call is admitted and its answer is being waited for on the server.
        async with asyncio.timeout(10):
            while not any(sent.startswith("POST /v1/") for sent in transport.sent):
                await asyncio.sleep(0.01)
        _zero_network()
        started = asyncio.get_running_loop().time()
        with pytest.raises(ControlError) as cut:
            async with asyncio.timeout(5):
                await call
        elapsed = asyncio.get_running_loop().time() - started
        assert _phase(cut) == ("service_unavailable", _ZERO, True)
        assert elapsed < 1.5
        # No cancel of the abandoned operation, and nothing else, is sent.
        assert not any(sent.startswith("DELETE") for sent in transport.sent)
    finally:
        gate.set()
        await client.close()
        await api.close()


@pytest.mark.anyio
async def test_an_idle_open_client_closes_within_a_second_of_the_record(
    keys: ApiKeyStore,
) -> None:
    _record, token = keys.create("laptop", "agent")
    transport = _Recording(make_api(FakeService(), keys))
    client = await connect_rest_service(
        ControlClientKind.MCP_BRIDGE,
        record=_RECORD,
        root=Path("/x"),
        _endpoint=_endpoint(transport, token),
    )
    _zero_network()
    started = asyncio.get_running_loop().time()
    async with asyncio.timeout(5):
        while not client._closed:  # pyright: ignore[reportPrivateUsage]
            await asyncio.sleep(0.02)
    assert asyncio.get_running_loop().time() - started < 1.5
    with pytest.raises(ControlError) as refused:
        await client.service_status()
    assert _phase(refused) == ("service_unavailable", _ZERO, True)
    assert transport.sent == ["GET /v1/server"]
    await client.close()


@pytest.mark.anyio
@pytest.mark.parametrize("locator", [None, "/srv/me/repo"])
async def test_connect_service_refuses_a_remote_root_with_or_without_a_workspace(
    monkeypatch: pytest.MonkeyPatch, locator: str | None
) -> None:
    """The known gap: a connection with no workspace never asked the shared check."""

    ssh = _SSH_RECORD
    steps: list[str] = []

    def step(name: str) -> object:
        def record(*_args: object, **_kwargs: object) -> object:
            steps.append(name)
            raise AssertionError(name)

        return record

    async def connect(*_args: object, **_kwargs: object) -> object:
        steps.append("connect")
        raise AssertionError("connect")

    monkeypatch.setattr(service_client, "_remote_target", lambda: (ssh, Path("/x/t")))
    monkeypatch.setattr(rest_client, "connect_rest_service", connect)
    monkeypatch.setattr("finishup.client.agent.note_workspace", step("note"))
    monkeypatch.setattr("finishup.client.agent.ensure_agent", step("agent"))
    monkeypatch.setattr(
        "finishup.client.rest_runtime.SshTargetRuntime.ensure_master", step("master")
    )
    monkeypatch.setattr(service_client, "_spawn_service_process", step("spawn"))
    _zero_network()

    workspace = None if locator is None else WorkspaceLocator(locator)
    for connect_with in (
        service_client.connect_service(ControlClientKind.CLI, workspace_locator=workspace),
        service_client.connect_service_on_demand(
            ControlClientKind.UI, workspace_locator=workspace, timeout_seconds=2.0
        ),
    ):
        with pytest.raises(ControlError) as refused:
            await connect_with
        assert _phase(refused) == ("service_unavailable", _ZERO, True)
    assert steps == []


def test_the_refusal_is_typed_for_every_kind() -> None:
    _zero_network()
    for record in (_RECORD, _LOCAL_PORT_RECORD, _SSH_RECORD):
        with pytest.raises(ControlError) as refused:
            rest_client.require_connection_allowed(record)
        assert _phase(refused) == ("service_unavailable", _ZERO, True)


@pytest.mark.anyio
async def test_the_watch_never_keeps_a_dropped_client_alive(keys: ApiKeyStore) -> None:
    import gc
    import weakref

    _record, token = keys.create("laptop", "agent")
    transport = _Recording(make_api(FakeService(), keys))
    client = await connect_rest_service(
        ControlClientKind.MCP_BRIDGE,
        record=_RECORD,
        root=Path("/x"),
        _endpoint=_endpoint(transport, token),
    )
    watch = client._marker_watch  # pyright: ignore[reportPrivateUsage]
    assert watch is not None and not watch.done()
    dropped = weakref.ref(client)
    del client
    gc.collect()
    assert dropped() is None
    # The watch notices at its next tick and ends.
    async with asyncio.timeout(5):
        await watch
