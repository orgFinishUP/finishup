"""The REST edge's listener (ADR-053): TLS from the owner's files, bounds before any byte.

Real sockets on loopback with a throwaway CA: TLS is served with the owner's certificate and an
owner-only key, plain HTTP only behind a proxy on loopback, connections over the per-peer cap are
closed before TLS, an idle connection that never sends a request head is closed on its deadline,
and closing the listener closes the application first.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import ssl
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from builders.tls_material import TlsMaterial, make_tls
from finishup.rest import listener as listener_module
from finishup.rest.listener import ListenerError, RestListener, parse_listen

pytestmark = pytest.mark.anyio


@pytest.fixture
def tls() -> Iterator[TlsMaterial]:
    base = Path.home() / f".yz-rest-tls-{os.getpid()}-{id(object())}"
    try:
        yield make_tls(base)
    finally:
        shutil.rmtree(base, ignore_errors=True)


async def _hello(scope: dict[str, object], receive: object, send: object) -> None:
    del receive
    if scope.get("type") != "http":
        return
    sender = send  # type: ignore[assignment]
    await sender({"type": "http.response.start", "status": 200, "headers": []})  # type: ignore[operator]
    await sender({"type": "http.response.body", "body": b"ok"})  # type: ignore[operator]


class _State:
    def __init__(self) -> None:
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("127.0.0.1:0", ("127.0.0.1", 0)),
        ("[::1]:8443", ("::1", 8443)),
        ("localhost:1", ("localhost", 1)),
    ],
)
def test_listen_addresses_are_ip_literals_or_localhost(
    value: str, expected: tuple[str, int]
) -> None:
    address = parse_listen(value)
    assert (address.host, address.port) == expected
    assert address.loopback


@pytest.mark.parametrize("value", ["example.com:443", "127.0.0.1", "127.0.0.1:70000", ":443"])
def test_anything_else_is_refused(value: str) -> None:
    with pytest.raises(ListenerError, match="rest_listen_invalid"):
        parse_listen(value)


def test_plain_http_only_behind_a_proxy_on_loopback(tls: TlsMaterial) -> None:
    with pytest.raises(ListenerError, match="rest_tls_required"):
        RestListener.bind("127.0.0.1:0", tls_cert=None, tls_key=None, behind_proxy=False)
    with pytest.raises(ListenerError, match="rest_proxy_not_loopback"):
        RestListener.bind("0.0.0.0:0", tls_cert=None, tls_key=None, behind_proxy=True)
    with pytest.raises(ListenerError, match="rest_tls_unusable"):
        RestListener.bind(
            "127.0.0.1:0", tls_cert=tls.cert_file, tls_key=tls.key_file, behind_proxy=True
        )


def test_a_key_file_others_can_read_is_refused(tls: TlsMaterial) -> None:
    tls.key_file.chmod(0o644)
    with pytest.raises(ListenerError, match="rest_tls_unusable"):
        RestListener.bind(
            "127.0.0.1:0", tls_cert=tls.cert_file, tls_key=tls.key_file, behind_proxy=False
        )


async def test_tls_is_served_and_closing_closes_the_application_first(tls: TlsMaterial) -> None:
    listener = RestListener.bind(
        "127.0.0.1:0", tls_cert=tls.cert_file, tls_key=tls.key_file, behind_proxy=False
    )
    state = _State()
    await listener.start(_hello, state)  # type: ignore[arg-type]
    try:
        context = ssl.create_default_context(cafile=str(tls.ca_file))
        async with httpx.AsyncClient(verify=context, trust_env=False) as client:
            answer = await client.get(f"https://127.0.0.1:{listener.port}/")
            assert answer.status_code == 200 and answer.content == b"ok"
            assert "server" not in answer.headers and "date" not in answer.headers
        async with httpx.AsyncClient(trust_env=False) as plain:
            with pytest.raises(httpx.HTTPError):
                await plain.get(f"http://127.0.0.1:{listener.port}/")
    finally:
        await listener.close()
    assert state.closed


async def test_a_connection_over_the_per_peer_cap_is_closed_before_tls(
    tls: TlsMaterial,
) -> None:
    listener = RestListener.bind(
        "127.0.0.1:0",
        tls_cert=tls.cert_file,
        tls_key=tls.key_file,
        behind_proxy=False,
        tcp_limits=(4, 1),
    )
    await listener.start(_hello)  # type: ignore[arg-type]
    try:
        _first_reader, first = await asyncio.open_connection("127.0.0.1", listener.port)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 5
        while listener.open_connections < 1:
            assert loop.time() < deadline
            await asyncio.sleep(0)
        second_reader, second = await asyncio.open_connection("127.0.0.1", listener.port)
        closed = await asyncio.wait_for(second_reader.read(1), timeout=5)
        assert closed == b""
        first.close()
        second.close()
    finally:
        await listener.close()


async def test_a_connection_that_never_sends_a_request_head_is_closed_on_its_deadline(
    tls: TlsMaterial, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(listener_module, "REQUEST_HEAD_SECONDS", 0.3)
    listener = RestListener.bind(
        "127.0.0.1:0", tls_cert=tls.cert_file, tls_key=tls.key_file, behind_proxy=False
    )
    await listener.start(_hello)  # type: ignore[arg-type]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)
        # Never starts TLS: the head deadline (TLS included) closes it.
        assert await asyncio.wait_for(reader.read(1), timeout=10) == b""
        writer.close()
    finally:
        await listener.close()
