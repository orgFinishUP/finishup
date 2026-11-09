"""The one REST client library (ADR-053, design v2 sections 8.4 and 8.8): trust, bounds, the key.

Real TLS on loopback with a throwaway CA: the recorded CA is trusted and nothing else; a pin is
checked before any request byte (a mismatched pin reaches no route); this computer's system store
does not trust a private CA; a redirect is never followed; an answer past the bound is refused;
proxy variables are ignored; a target with no key sends nothing; the key is read off the event
loop from where the record says it lives now, and a store that blocks costs only the budget.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import threading
from collections.abc import AsyncIterator, Iterator, MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from builders.server_targets import ambient_home
from builders.tls_material import TlsMaterial, make_tls
from finishup.client import rest_client
from finishup.client.credentials import KeyringOrFileCredential
from finishup.client.rest_client import RestTransport, RestUnavailable, load_key, observed_identity
from finishup.client.targets import new_remote_target, read_target, registry_lock, write_target
from finishup.rest.listener import RestListener

pytestmark = pytest.mark.anyio


@dataclass
class _Server:
    port: int
    tls: TlsMaterial
    seen: list[str]

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.port}"


@pytest.fixture
def tls() -> Iterator[TlsMaterial]:
    base = Path.home() / f".yz-rest-client-{os.getpid()}-{id(object())}"
    try:
        yield make_tls(base)
    finally:
        shutil.rmtree(base, ignore_errors=True)


@pytest.fixture
async def server(tls: TlsMaterial) -> AsyncIterator[_Server]:
    seen: list[str] = []

    async def app(scope: MutableMapping[str, Any], receive: Any, send: Any) -> None:
        del receive
        if scope.get("type") != "http":
            return
        path = scope["path"]
        seen.append(path)
        headers: list[tuple[bytes, bytes]] = []
        status, body = 200, b"{}"
        if path == "/redirect":
            status, headers = 307, [(b"location", b"https://elsewhere.invalid/v1/server")]
        elif path == "/big":
            body = b"x" * 4_096
        elif path == "/headers":
            body = repr(sorted(scope["headers"])).encode()
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    listener = RestListener.bind(
        "127.0.0.1:0", tls_cert=tls.cert_file, tls_key=tls.key_file, behind_proxy=False
    )
    await listener.start(app)
    try:
        yield _Server(listener.port, tls, seen)
    finally:
        await listener.close()


async def test_the_recorded_ca_is_trusted_and_the_system_store_is_not(server: _Server) -> None:
    trusted = RestTransport(server.url, key="fuk_x", ca_file=str(server.tls.ca_file))
    try:
        answer = await trusted.request("GET", "/ok")
        assert answer.status == 200
    finally:
        await trusted.aclose()
    system = RestTransport(server.url, key="fuk_x")
    try:
        with pytest.raises(RestUnavailable) as refused:
            await system.request("GET", "/never")
        assert refused.value.reason == "remote_identity_changed"
    finally:
        await system.aclose()
    assert "/never" not in server.seen


async def test_a_pin_is_checked_before_any_request_byte(server: _Server) -> None:
    pinned = RestTransport(server.url, key="fuk_x", tls_pin=server.tls.pin)
    try:
        assert (await pinned.request("GET", "/pinned")).status == 200
    finally:
        await pinned.aclose()
    wrong = RestTransport(server.url, key="fuk_x", tls_pin="sha256:" + "0" * 64)
    try:
        with pytest.raises(RestUnavailable) as refused:
            await wrong.request("GET", "/unpinned")
        assert refused.value.reason == "remote_identity_changed"
    finally:
        await wrong.aclose()
    assert server.seen == ["/pinned"]


async def test_a_redirect_is_never_followed_and_a_large_answer_is_refused(
    server: _Server,
) -> None:
    transport = RestTransport(server.url, key="fuk_x", ca_file=str(server.tls.ca_file))
    try:
        with pytest.raises(RestUnavailable) as redirected:
            await transport.request("GET", "/redirect")
        assert redirected.value.reason == "remote_incompatible"
        with pytest.raises(RestUnavailable) as large:
            await transport.request("GET", "/big", limit=1_024)
        assert large.value.reason == "remote_incompatible"
    finally:
        await transport.aclose()
    assert server.seen == ["/redirect", "/big"]


async def test_proxy_variables_are_ignored(
    server: _Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    transport = RestTransport(server.url, key="fuk_x", ca_file=str(server.tls.ca_file))
    try:
        assert (await transport.request("GET", "/direct")).status == 200
    finally:
        await transport.aclose()


async def test_nothing_answers_is_unreachable() -> None:
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    transport = RestTransport(f"https://127.0.0.1:{port}", key="fuk_x")
    try:
        with pytest.raises(RestUnavailable) as refused:
            await transport.request("GET", "/")
        assert refused.value.reason == "remote_unreachable"
    finally:
        await transport.aclose()


def test_no_key_sends_nothing_and_a_missing_ca_file_verifies_nobody(tmp_path: Path) -> None:
    transport = RestTransport("https://127.0.0.1:1", key=None)
    with pytest.raises(RestUnavailable) as refused:
        transport.headers()
    assert refused.value.reason == "remote_auth_failed"
    assert "authorization" not in transport.headers(authenticated=False)
    with pytest.raises(RestUnavailable) as missing:
        RestTransport("https://127.0.0.1:1", key="k", ca_file=str(tmp_path / "absent.pem"))
    assert missing.value.reason == "remote_unreachable"


def test_the_observed_identity_is_the_pin_the_ca_digest_or_the_system_store(
    monkeypatch: pytest.MonkeyPatch, tls: TlsMaterial
) -> None:
    with ambient_home(monkeypatch):
        with registry_lock():
            pinned, _ = new_remote_target(
                "pinned", "https", base_url="https://a.example", tls_pin=tls.pin
            )
            anchored, _ = new_remote_target(
                "anchored", "https", base_url="https://b.example", ca_file=str(tls.ca_file)
            )
            system, _ = new_remote_target("system", "https", base_url="https://c.example")
        assert observed_identity(pinned) == ("tls_pin", tls.pin)
        kind, digest = observed_identity(anchored)
        assert kind == "tls_ca_file" and digest is not None and digest.startswith("sha256:")
        assert observed_identity(system) == ("tls_system_ca", None)


async def test_the_key_is_read_where_the_record_says_now_and_off_the_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.fail.Keyring")
    with ambient_home(monkeypatch):
        with registry_lock():
            record, root = new_remote_target("later", "https", base_url="https://d.example")
        with pytest.raises(RestUnavailable) as none_yet:
            await load_key(record.target_id)
        assert none_yet.value.reason == "remote_auth_failed"
        # A login after this process started: the next read finds the key (A-CRED-STALE).
        location = KeyringOrFileCredential(record.target_id, root, recorded=None).store(
            "fuk_0123456789ab_" + "A" * 43
        )
        with registry_lock():
            stored = read_target(root)
            assert stored is not None
            from dataclasses import replace

            write_target(root, replace(stored, credential=location))
        assert await load_key(record.target_id) == "fuk_0123456789ab_" + "A" * 43
        # A store that blocks (a locked keyring's prompt) costs this attempt its budget only.
        release = threading.Event()

        def blocked(_target_id: str) -> str:
            release.wait(10)
            return "never"

        monkeypatch.setattr(rest_client, "_read_key", blocked)
        ticks = 0

        async def tick() -> None:
            nonlocal ticks
            while True:
                ticks += 1
                await asyncio.sleep(0)

        ticker = asyncio.create_task(tick())
        try:
            with pytest.raises(RestUnavailable) as blocked_read:
                await load_key(record.target_id, seconds=0.2)
            assert blocked_read.value.reason == "remote_auth_failed"
            assert ticks > 10
        finally:
            release.set()
            ticker.cancel()
