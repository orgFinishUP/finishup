"""The one REST client library of this client (ADR-053, design v2 section 8.4).

Every request this computer sends to a FinishUP server over HTTPS goes through ``RestTransport``:
the direct style's own connections (``client.rest_stream`` under a ``ServiceClient``), the
target's helper (its relay and its background agents), and discovery and profile fetches
(``client.rest_discovery``). One target, one trust rule, one way to fail:

* **TLS** as the owner recorded it: ``--tls-pin sha256:<hex>`` checks the leaf certificate's
  digest right after the handshake and before any request byte (the pin replaces chain and
  host-name validation, as the owner chose; approach A's pinned network backend), ``--ca-file``
  trusts that CA only (host name checked), and otherwise this computer's system store. A CA file
  that cannot be read sends nothing. The CA file is read **once** per transport (``load_trust``):
  the same bytes become the TLS context and the identity the transport reports, so the identity a
  consent binds is exactly the trust that verifies the server. Every connection made on the
  owner's behalf after the consent (``for_target(..., consented=True)``: the helper, the direct
  style, the profile refresh, a login check) compares that identity with the consented one before
  any byte is sent: a CA file replaced since is ``remote_identity_changed`` until the owner agrees
  again.
* **No proxies and no redirects**: proxy variables are ignored (the hop goes only where the
  record says) and a ``3xx`` is never followed, so no credential is ever carried elsewhere
  (design v2 section 8.8).
* **Bounded answers**: a body past the largest control frame (plus room for the envelope) is
  refused unread.
* **The key** is read off the event loop (a platform credential store can block, A-KEYRING-LOOP),
  one read at a time, from wherever the record says it lives now (A-CRED-STALE). A target with no
  key is ``remote_auth_failed`` before any byte is sent: that is the credential step of the shared
  gate (ADR-052 decision 1, step 6), made where the key is read.

Failures are ``RestUnavailable`` with a closed remote phase and never name the host, the URL or a
body: the TLS identity refused (``remote_identity_changed``), no connection
(``remote_unreachable``), the key refused (``remote_auth_failed``), not a FinishUP REST v1 server of
this contract (``remote_incompatible``), no service answering there
(``remote_service_not_running``).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import re
import ssl
import tempfile
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, cast

import httpcore
import httpx

from finishup.rest.contract import (
    HEADER_API_MANIFEST,
    HEADER_CLAIM,
    HEADER_CLIENT_KIND,
    HEADER_SERVER_PROFILE,
    MAX_WAIT_MS,
    current_api_manifest,
    encode_claim_header,
    encode_revision_header,
    parse_api_key,
    parse_rest_error,
)

if TYPE_CHECKING:
    from finishup.client.targets import ServerTarget
    from finishup.ports.control import ControlClientKind, WorkspaceClaim
    from finishup.protocol.server_profile import ServerProfileRevision

__all__ = [
    "MAX_RESPONSE_BYTES",
    "RestAnswer",
    "RestTransport",
    "RestUnavailable",
    "TlsTrust",
    "load_key",
    "load_trust",
]

# The largest control frame plus room for its envelope (the REST answer is the frame's body).
MAX_RESPONSE_BYTES: Final = 6_291_456 + 65_536
CONNECT_SECONDS: Final = 5.0
# A long-poll answers within ``MAX_WAIT_MS``; the read bound leaves room for the network.
_POLL_READ_SECONDS: Final = MAX_WAIT_MS / 1000 + 10.0
_REQUEST_READ_SECONDS: Final = 30.0
# A request given no deadline of its own still ends: its connect and read bounds, and this much
# for sending its body and receiving an answer in many small pieces.
_TRANSFER_SECONDS: Final = 30.0
_REASONS: Final = frozenset(
    {
        "remote_auth_failed",
        "remote_identity_changed",
        "remote_incompatible",
        "remote_service_not_running",
        "remote_unreachable",
    }
)
# The one key read in flight in this process (``load_key``), guarded by its lock.
_READ_LOCK: Final = threading.Lock()


class _KeyRead:
    """The one outstanding key read: callers that came while it runs wait for it to end."""

    __slots__ = ("waiters",)

    def __init__(self) -> None:
        self.waiters: list[tuple[asyncio.AbstractEventLoop, asyncio.Future[None]]] = []


_reading: _KeyRead | None = None


class RestUnavailable(Exception):
    """The server could not be reached or used; ``reason`` is one closed remote phase."""

    def __init__(self, reason: str) -> None:
        if reason not in _REASONS:
            raise ValueError("rest_unavailable_reason_invalid")
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class RestAnswer:
    """One answer: its status, the headers this client reads, its bounded body."""

    status: int
    headers: Mapping[str, str]
    body: bytes

    @property
    def rest_error(self) -> str | None:
        """The closed ``rest-error`` reason of a refusal; ``None`` for anything else."""

        return None if self.status < 400 else parse_rest_error(self.body)


# --- TLS trust -----------------------------------------------------------------------------------


class _PinnedStream(httpcore.AsyncNetworkStream):
    """A TCP stream whose TLS upgrade is refused unless the leaf certificate matches the pin."""

    def __init__(self, inner: httpcore.AsyncNetworkStream, pin: str) -> None:
        self._inner = inner
        self._pin = pin

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return await self._inner.read(max_bytes, timeout)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        await self._inner.write(buffer, timeout)

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        upgraded = await self._inner.start_tls(ssl_context, server_hostname, timeout)
        tls = upgraded.get_extra_info("ssl_object")
        leaf = tls.getpeercert(binary_form=True) if isinstance(tls, ssl.SSLObject) else None
        if not leaf or f"sha256:{hashlib.sha256(leaf).hexdigest()}" != self._pin:
            # Checked before any request byte: the key is never sent to an unpinned peer.
            await upgraded.aclose()
            raise httpcore.ConnectError("tls_pin_mismatch")
        return upgraded

    def get_extra_info(self, info: str) -> Any:
        return self._inner.get_extra_info(info)


class _PinnedBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, pin: str) -> None:
        self._inner = cast(httpcore.AsyncNetworkBackend, httpcore.AnyIOBackend())
        self._pin = pin

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        stream = await self._inner.connect_tcp(
            host, port, timeout=timeout, local_address=local_address, socket_options=socket_options
        )
        return _PinnedStream(stream, self._pin)

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise httpcore.ConnectError("tls_pin_requires_tcp")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class _PinnedTransport(httpx.AsyncHTTPTransport):
    def __init__(self, pin: str) -> None:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        super().__init__(verify=context, trust_env=False)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=context,
            max_connections=100,
            max_keepalive_connections=20,
            keepalive_expiry=5.0,
            network_backend=_PinnedBackend(pin),
        )


_MAX_CA_FILE_BYTES: Final = 1_048_576
_PEM_CERTIFICATE: Final = re.compile(
    rb"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n\t ]+-----END CERTIFICATE-----"
)
# Blocks OpenSSL reads from a CA file that a PEM ``cadata`` string cannot carry: OpenSSL's own
# trusted certificates (a certificate with its trust settings) and the older certificate label.
_OPENSSL_CA_BLOCK: Final = re.compile(rb"-----BEGIN (?:TRUSTED|X509) CERTIFICATE-----")


@dataclass(frozen=True, slots=True)
class TlsTrust:
    """The trust one transport verifies a server with, and the endpoint identity it observes
    (design v2 section 8.2): ``tls_pin`` and the pin, ``tls_ca_file`` and the ``sha256:`` of the
    CA file's bytes as read for ``context``, or ``tls_system_ca`` and ``None``."""

    identity_type: str
    identity: str | None
    context: ssl.SSLContext | None = None
    pin: str | None = None

    @property
    def endpoint(self) -> tuple[str, str | None]:
        return self.identity_type, self.identity


def _verifying(context: ssl.SSLContext) -> ssl.SSLContext:
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _ca_trust(ca_file: str, *, build: bool) -> TlsTrust:
    """One bounded read of the owner's CA file: its digest, and (``build``) a context holding
    exactly the certificates in those bytes."""

    try:
        with open(ca_file, "rb") as handle:  # noqa: PTH123 - the owner's own file
            data = handle.read(_MAX_CA_FILE_BYTES + 1)
    except OSError:
        # A CA file that was moved or is unreadable verifies nobody.
        raise RestUnavailable("remote_unreachable") from None
    if len(data) > _MAX_CA_FILE_BYTES:
        raise RestUnavailable("remote_unreachable")
    identity = "sha256:" + hashlib.sha256(data).hexdigest()
    if not build:
        return TlsTrust("tls_ca_file", identity)
    if _OPENSSL_CA_BLOCK.search(data):
        # OpenSSL's ``TRUSTED CERTIFICATE`` blocks (trust settings included) are read only from a
        # file: these exact bytes are handed to it through a private copy, never the path again.
        return TlsTrust("tls_ca_file", identity, _verifying(_context_from_ca_bytes(data)))
    blocks = _PEM_CERTIFICATE.findall(data)
    if not blocks:
        # A CA file that holds no certificate verifies nobody.
        raise RestUnavailable("remote_unreachable")
    try:
        context = ssl.create_default_context(cadata=b"\n".join(blocks).decode("ascii"))
    except (ssl.SSLError, ValueError):
        raise RestUnavailable("remote_unreachable") from None
    return TlsTrust("tls_ca_file", identity, _verifying(context))


def _context_from_ca_bytes(data: bytes) -> ssl.SSLContext:
    """A context trusting exactly what OpenSSL reads from ``data`` as a CA file: its
    certificates, OpenSSL's trusted certificates with their trust settings (a certificate whose
    settings reject server authentication verifies no server), and nothing else; never this
    computer's system store. The bytes go through an owner-only temporary file, removed at once.
    """

    try:
        descriptor, path = tempfile.mkstemp(prefix="finishup-ca-", suffix=".pem")
    except OSError:
        raise RestUnavailable("remote_unreachable") from None
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        return ssl.create_default_context(cafile=path)
    except (OSError, ssl.SSLError, ValueError):
        # Nothing OpenSSL can use as a CA (no certificate at all): it verifies nobody.
        raise RestUnavailable("remote_unreachable") from None
    finally:
        with contextlib.suppress(OSError):
            os.unlink(path)


def _trust_for(ca_file: str | None, tls_pin: str | None, *, build: bool = True) -> TlsTrust:
    if tls_pin is not None:
        return TlsTrust("tls_pin", tls_pin, pin=tls_pin)
    if ca_file is not None:
        return _ca_trust(ca_file, build=build)
    if not build:
        return TlsTrust("tls_system_ca", None)
    try:
        context = ssl.create_default_context()
    except (OSError, ssl.SSLError, ValueError):
        raise RestUnavailable("remote_unreachable") from None
    return TlsTrust("tls_system_ca", None, _verifying(context))


def load_trust(record: ServerTarget) -> TlsTrust:
    """The trust a connection under ``record`` verifies with, read now (see the module text).

    Raises ``RestUnavailable("remote_unreachable")`` when the CA file cannot be read or holds no
    certificate.
    """

    return _trust_for(record.ca_file, record.tls_pin)


def _transport(trust: TlsTrust) -> httpx.AsyncBaseTransport:
    if trust.pin is not None:
        return _PinnedTransport(trust.pin)
    return httpx.AsyncHTTPTransport(verify=cast(ssl.SSLContext, trust.context), trust_env=False)


def _is_identity_failure(error: BaseException) -> bool:
    """Whether the server's identity was refused (its certificate failed verification, or its
    leaf did not match the pin); any other TLS failure says nothing about who the server is."""

    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError) or "tls_pin_mismatch" in str(
            current.args[:1]
        ):
            return True
        current = current.__cause__ or current.__context__
    return False


# --- the key -------------------------------------------------------------------------------------


def _read_key(target_id: str) -> str:
    from finishup.client.credentials import CredentialError, KeyringOrFileCredential
    from finishup.client.targets import TargetError, read_target, target_root

    try:
        root = target_root(target_id)
        # The record is read again each time, so the key is looked for where it lives now
        # (A-CRED-STALE): a login after this process started, or one that moved it.
        record = read_target(root)
    except TargetError:
        raise RestUnavailable("remote_auth_failed") from None
    if record is None or record.credential is None:
        raise RestUnavailable("remote_auth_failed")
    try:
        return KeyringOrFileCredential(target_id, root, recorded=record.credential).read()
    except CredentialError:
        raise RestUnavailable("remote_auth_failed") from None


def _wake(waiter: asyncio.Future[None]) -> None:
    if not waiter.done():
        waiter.set_result(None)


def _end_read(read: _KeyRead) -> None:
    """The outstanding read ended (whatever it returned): the slot is free; wake its waiters."""

    global _reading
    with _READ_LOCK:
        if _reading is read:
            _reading = None
        waiters, read.waiters = read.waiters, []
    for loop, waiter in waiters:
        with contextlib.suppress(RuntimeError):  # that loop closed: nobody waits there any more
            loop.call_soon_threadsafe(_wake, waiter)


async def _take_read_slot(loop: asyncio.AbstractEventLoop, deadline: float) -> _KeyRead:
    """The read slot, once no other read is outstanding; ``remote_auth_failed`` at ``deadline``.

    While another read runs (a locked keyring's prompt, say), this caller waits for it to end
    within its own deadline and starts no thread of its own: at most one read is ever under way
    in this process, however many callers time out meanwhile.
    """

    global _reading
    while True:
        with _READ_LOCK:
            if _reading is None:
                _reading = _KeyRead()
                return _reading
            waiter: asyncio.Future[None] = loop.create_future()
            _reading.waiters.append((loop, waiter))
        left = deadline - loop.time()
        if left <= 0:
            raise RestUnavailable("remote_auth_failed")
        try:
            async with asyncio.timeout(left):
                await waiter
        except TimeoutError:
            raise RestUnavailable("remote_auth_failed") from None


async def load_key(target_id: str, *, seconds: float = 10.0) -> str:
    """The target's API key, read in a worker thread within ``seconds`` (A-KEYRING-LOOP).

    A store that does not answer in time (a locked keyring showing a prompt) is
    ``remote_auth_failed`` for this attempt; the event loop never waits on it. The read runs on a
    daemon thread of its own, never the loop's default executor: a read still blocked when the
    caller gives up is abandoned, so it can hold neither the loop's shutdown (``asyncio.run``
    joins its default executor) nor the interpreter's exit, and a hook ends within its budget.
    At most one read is outstanding in this process: a caller that comes while one runs waits for
    it to end within its own ``seconds`` (then reads afresh) and otherwise fails, so abandoned
    reads never accumulate threads.
    """

    loop = asyncio.get_running_loop()
    deadline = loop.time() + seconds
    slot = await _take_read_slot(loop, deadline)
    answer: asyncio.Future[str] = loop.create_future()

    def settle(value: str | None, failure: BaseException | None) -> None:
        if answer.done():
            return
        if failure is not None:
            answer.set_exception(failure)
        else:
            answer.set_result(cast(str, value))

    def read() -> None:
        try:
            value = _read_key(target_id)
        except BaseException as error:  # noqa: BLE001 - handed to the waiting loop
            failure: BaseException | None = error
            value = None
        else:
            failure = None
        finally:
            _end_read(slot)
        with contextlib.suppress(RuntimeError):  # the loop closed: nobody waits any more
            loop.call_soon_threadsafe(settle, value, failure)

    try:
        threading.Thread(target=read, name="finishup-key-read", daemon=True).start()
    except BaseException:
        _end_read(slot)
        raise
    try:
        async with asyncio.timeout(max(0.0, deadline - loop.time())):
            return await answer
    except TimeoutError:
        raise RestUnavailable("remote_auth_failed") from None


# --- the transport -------------------------------------------------------------------------------


class RestTransport:
    """One target's HTTPS client (see the module text)."""

    def __init__(
        self,
        base_url: str,
        *,
        key: str | None,
        ca_file: str | None = None,
        tls_pin: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        trust: TlsTrust | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._key = key
        # A transport handed in (a test's in-memory one) still reports the record's identity.
        self._trust = trust or _trust_for(ca_file, tls_pin, build=transport is None)
        self._client = httpx.AsyncClient(
            transport=transport or _transport(self._trust),
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(CONNECT_SECONDS, read=_REQUEST_READ_SECONDS),
            headers={"user-agent": "finishup"},
        )
        self._closed = False

    def __repr__(self) -> str:
        return "RestTransport(<redacted>)"

    @classmethod
    def for_target(
        cls,
        record: ServerTarget,
        *,
        key: str | None,
        transport: httpx.AsyncBaseTransport | None = None,
        consented: bool = False,
    ) -> RestTransport:
        """A transport under ``record``'s trust, read now.

        ``consented``: a connection made on the owner's behalf after the consent. The identity of
        the trust just loaded (the CA file's bytes in this context, the pin, the system store)
        must be the one the consented envelope names, else ``remote_identity_changed`` before any
        byte is sent; no consent at all is ``remote_identity_changed`` too (nothing to bind).
        """

        if record.base_url is None:
            raise RestUnavailable("remote_unreachable")
        trust = _trust_for(record.ca_file, record.tls_pin, build=transport is None)
        if consented:
            from finishup.client.server_profile import consented_endpoint_identity
            from finishup.client.targets import TargetError, target_root

            try:
                expected = consented_endpoint_identity(target_root(record.target_id))
            except TargetError:
                expected = None
            if expected is None or expected != trust.endpoint:
                raise RestUnavailable("remote_identity_changed")
        return cls(record.base_url, key=key, transport=transport, trust=trust)

    @property
    def key_id(self) -> str | None:
        """The id of the key this transport sends (``None`` without one)."""

        parsed = parse_api_key(self._key)
        return None if parsed is None else parsed.key_id

    @property
    def identity(self) -> tuple[str, str | None]:
        """The endpoint identity of the trust this transport verifies with (``TlsTrust``)."""

        return self._trust.endpoint

    @property
    def closed(self) -> bool:
        return self._closed

    def headers(
        self,
        *,
        revision: ServerProfileRevision | None = None,
        claim: WorkspaceClaim | None = None,
        client_kind: ControlClientKind | None = None,
        authenticated: bool = True,
    ) -> dict[str, str]:
        """The headers every ``/v1`` request carries: the key, the API manifest, the revision."""

        headers: dict[str, str] = {}
        if authenticated:
            if self._key is None:
                # No key: nothing is sent (the credential step, ADR-052).
                raise RestUnavailable("remote_auth_failed")
            headers["authorization"] = f"Bearer {self._key}"
            headers[HEADER_API_MANIFEST] = current_api_manifest()
        if revision is not None:
            headers[HEADER_SERVER_PROFILE] = encode_revision_header(revision)
        if claim is not None:
            headers[HEADER_CLAIM] = encode_claim_header(claim)
        if client_kind is not None:
            headers[HEADER_CLIENT_KIND] = client_kind.value
        return headers

    async def request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
        content: bytes | None = None,
        params: Mapping[str, str] | None = None,
        poll: bool = False,
        limit: int = MAX_RESPONSE_BYTES,
        seconds: float | None = None,
    ) -> RestAnswer:
        """One request; its answer bounded to ``limit`` bytes.

        ``poll`` gives a long-poll its longer read bound. ``seconds``, when given, is one absolute
        bound for the whole request (a caller's remaining deadline): the connect, the TLS
        handshake, sending the body and every piece of the answer together, never each phase on
        its own; without it the request still ends within its connect and read bounds plus
        ``_TRANSFER_SECONDS``. Raises ``RestUnavailable`` for a transport failure, a bound passed
        (``remote_unreachable``), a redirect or an answer past the bound; a ``rest-error`` refusal
        is an answer.
        """

        if self._closed:
            raise RestUnavailable("remote_unreachable")
        read = _POLL_READ_SECONDS if poll else _REQUEST_READ_SECONDS
        connect = CONNECT_SECONDS
        total = connect + read + _TRANSFER_SECONDS
        if seconds is not None:
            read = max(0.001, min(read, seconds))
            connect = max(0.001, min(connect, seconds))
            total = max(0.001, seconds)
        try:
            async with asyncio.timeout(total):
                return await self._exchange(
                    method,
                    path,
                    headers=headers,
                    content=content,
                    params=params,
                    limit=limit,
                    timeout=httpx.Timeout(connect, read=read),
                )
        except TimeoutError:
            raise RestUnavailable("remote_unreachable") from None

    async def _exchange(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str] | None,
        content: bytes | None,
        params: Mapping[str, str] | None,
        limit: int,
        timeout: httpx.Timeout,
    ) -> RestAnswer:
        try:
            async with self._client.stream(
                method,
                self._base_url + path,
                headers=dict(headers or {}),
                content=content,
                params=dict(params or {}),
                timeout=timeout,
            ) as response:
                if 300 <= response.status_code < 400:
                    # Never followed: a redirect would carry the key elsewhere (design v2 §8.8).
                    raise RestUnavailable("remote_incompatible")
                declared = response.headers.get("content-length")
                if declared is not None and (not declared.isdigit() or int(declared) > limit):
                    raise RestUnavailable("remote_incompatible")
                chunks: list[bytes] = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > limit:
                        raise RestUnavailable("remote_incompatible")
                    chunks.append(chunk)
                kept = {
                    name: value
                    for name, value in response.headers.items()
                    if name.lower().startswith("finishup-") or name.lower() == "location"
                }
                return RestAnswer(response.status_code, kept, b"".join(chunks))
        except RestUnavailable:
            raise
        except httpx.HTTPError as error:
            raise RestUnavailable(
                "remote_identity_changed" if _is_identity_failure(error) else "remote_unreachable"
            ) from None
        except (OSError, ssl.SSLError) as error:
            raise RestUnavailable(
                "remote_identity_changed" if _is_identity_failure(error) else "remote_unreachable"
            ) from None

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._client.aclose()
