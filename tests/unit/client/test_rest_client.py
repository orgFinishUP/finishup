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
from finishup.client.rest_client import RestTransport, RestUnavailable, load_key, load_trust
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
        assert load_trust(pinned).endpoint == ("tls_pin", tls.pin)
        kind, digest = load_trust(anchored).endpoint
        assert kind == "tls_ca_file" and digest is not None and digest.startswith("sha256:")
        assert load_trust(system).endpoint == ("tls_system_ca", None)


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


def test_a_key_read_that_never_returns_cannot_hold_the_process_open() -> None:
    """B4: a blocked store read (a locked keyring's prompt) is abandoned when its budget ends;
    neither ``asyncio.run``'s shutdown nor the interpreter's exit waits for it, so a direct-style
    hook still ends within its budget."""

    import subprocess
    import sys
    import time

    program = (
        "import asyncio, threading\n"
        "from finishup.client import rest_client\n"
        "rest_client._read_key = lambda _target: threading.Event().wait() or 'never'\n"
        "async def main():\n"
        "    try:\n"
        "        await rest_client.load_key('t_00000000', seconds=0.2)\n"
        "    except rest_client.RestUnavailable as error:\n"
        "        print(error.reason, flush=True)\n"
        "asyncio.run(main())\n"
    )
    started = time.monotonic()
    finished = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert finished.returncode == 0, finished.stderr
    assert finished.stdout.strip() == "remote_auth_failed"
    assert time.monotonic() - started < 15


async def test_a_replaced_ca_file_sends_nothing_until_the_owner_agrees_again(
    server: _Server, monkeypatch: pytest.MonkeyPatch, tls: TlsMaterial
) -> None:
    """B1 over real TLS: the owner consented to one CA; the file now holds another CA that does
    verify this server. A connection made on the owner's behalf compares the identity of the
    exact bytes it loaded with the consented one before any byte: nothing reaches the server."""

    import hashlib

    from builders.server_profiles import consent_to

    consented_ca = make_tls(tls.ca_file.parent / "consented").ca_file.read_bytes()
    with ambient_home(monkeypatch):
        anchor = Path.home() / "anchor-ca.pem"
        anchor.write_bytes(consented_ca)
        with registry_lock():
            record, _root = new_remote_target(
                "lab", "https", base_url=server.url, ca_file=str(anchor)
            )
        consent_to(
            record,
            identity="sha256:" + hashlib.sha256(consented_ca).hexdigest(),
            identity_type="tls_ca_file",
        )
        # Replaced: the server's own CA, which does verify it.
        anchor.write_bytes(server.tls.ca_file.read_bytes())
        with pytest.raises(RestUnavailable) as refused:
            RestTransport.for_target(record, key="fuk_0123456789ab_" + "A" * 43, consented=True)
        assert refused.value.reason == "remote_identity_changed"
        assert server.seen == []
        # The owner's own discovery (no consent bound yet) observes the CA it actually loaded.
        unbound = RestTransport.for_target(record, key=None)
        try:
            assert (await unbound.request("GET", "/discovered")).status == 200
            assert unbound.identity == (
                "tls_ca_file",
                "sha256:" + hashlib.sha256(server.tls.ca_file.read_bytes()).hexdigest(),
            )
        finally:
            await unbound.aclose()
        # Agreed again to the CA in the file now: the bound connection is made.
        consent_to(
            record,
            identity="sha256:" + hashlib.sha256(server.tls.ca_file.read_bytes()).hexdigest(),
            identity_type="tls_ca_file",
        )
        bound = RestTransport.for_target(record, key="fuk_0123456789ab_" + "A" * 43, consented=True)
        try:
            assert (await bound.request("GET", "/bound")).status == 200
        finally:
            await bound.aclose()
    assert server.seen == ["/discovered", "/bound"]


async def test_the_identity_is_the_bytes_the_tls_context_holds(
    server: _Server, monkeypatch: pytest.MonkeyPatch, tls: TlsMaterial
) -> None:
    """B1: the CA file is read once per transport: replacing it afterwards changes neither the
    trust that transport verifies with nor the identity it reports."""

    import hashlib

    other_ca = make_tls(tls.ca_file.parent / "other").ca_file.read_bytes()
    with ambient_home(monkeypatch):
        anchor = Path.home() / "anchor-ca.pem"
        anchor.write_bytes(server.tls.ca_file.read_bytes())
        with registry_lock():
            record, _root = new_remote_target(
                "lab", "https", base_url=server.url, ca_file=str(anchor)
            )
        transport = RestTransport.for_target(record, key=None)
        anchor.write_bytes(other_ca)
        try:
            assert (await transport.request("GET", "/same-trust")).status == 200
            assert transport.identity[1] == (
                "sha256:" + hashlib.sha256(server.tls.ca_file.read_bytes()).hexdigest()
            )
        finally:
            await transport.aclose()
        assert load_trust(record).identity == "sha256:" + hashlib.sha256(other_ca).hexdigest()


# --- review fixes, second round -------------------------------------------------------------------


def _trickle_stream() -> Any:
    import httpx

    class _Trickle(httpx.AsyncByteStream):
        """An answer whose body never ends, each piece arriving at once: no single read ever
        waits long, so only a bound on the whole request ends it."""

        def __init__(self) -> None:
            self.pieces = 0

        async def __aiter__(self) -> AsyncIterator[bytes]:
            while True:
                await asyncio.sleep(0)  # yields to the loop; no time passes on purpose
                self.pieces += 1
                yield b" "

    return _Trickle()


async def test_a_request_given_seconds_ends_within_them_whatever_each_read_takes() -> None:
    """B5: ``seconds`` is one absolute bound for the whole request (connect, send, every piece of
    the answer), never a bound per phase: an answer that keeps arriving in small pieces, each at
    once, is cut off as unreachable when the seconds are up."""

    import httpx

    trickle = _trickle_stream()

    async def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, stream=trickle)

    transport = RestTransport(
        "https://trickle.test", key=None, transport=httpx.MockTransport(handler)
    )
    loop = asyncio.get_running_loop()
    started = loop.time()
    try:
        with pytest.raises(RestUnavailable) as ended:
            async with asyncio.timeout(20):  # the test's own bound, far past the request's
                await transport.request(
                    "GET", "/v1/server", headers=transport.headers(authenticated=False), seconds=0.3
                )
    finally:
        await transport.aclose()
    assert ended.value.reason == "remote_unreachable"
    assert loop.time() - started < 10
    assert trickle.pieces > 0  # the answer was arriving all along


async def test_at_most_one_key_read_is_ever_outstanding_however_many_callers_time_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """B4: a blocked store read (a locked keyring's prompt) is the only read in flight: callers
    that time out meanwhile start no thread of their own, callers that wait get their own fresh
    read once it ends, and never two reads run at once."""

    release = threading.Event()
    guard = threading.Lock()
    reads = {"entered": 0, "active": 0, "peak": 0}

    def blocked(_target_id: str) -> str:
        with guard:
            reads["entered"] += 1
            reads["active"] += 1
            reads["peak"] = max(reads["peak"], reads["active"])
        try:
            release.wait(30)
            return "the key"
        finally:
            with guard:
                reads["active"] -= 1

    def readers() -> list[threading.Thread]:
        return [
            thread
            for thread in threading.enumerate()
            if thread.name == "finishup-key-read" and thread.is_alive()
        ]

    monkeypatch.setattr(rest_client, "_read_key", blocked)
    before = len(readers())
    loop = asyncio.get_running_loop()
    try:
        for _ in range(5):
            with pytest.raises(RestUnavailable) as failed:
                await load_key("t_00000000", seconds=0.1)
            assert failed.value.reason == "remote_auth_failed"
        assert reads["entered"] == 1
        assert len(readers()) == before + 1
        waiting = [asyncio.create_task(load_key("t_00000000", seconds=20)) for _ in range(3)]
        deadline = loop.time() + 10
        while True:
            outstanding = rest_client._reading  # pyright: ignore[reportPrivateUsage]
            if outstanding is not None and len(outstanding.waiters) >= 3:
                break
            assert loop.time() < deadline
            await asyncio.sleep(0)
        assert reads["entered"] == 1 and len(readers()) == before + 1
        release.set()
        assert await asyncio.wait_for(asyncio.gather(*waiting), timeout=20) == ["the key"] * 3
        assert reads["entered"] == 4
        assert reads["peak"] == 1
    finally:
        release.set()
