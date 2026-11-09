"""The one REST client library of this client (ADR-053, design v2 section 8.4).

Every request this computer sends to a FinishUP server over HTTPS goes through ``RestTransport``:
the direct style's own connections (``client.rest_stream`` under a ``ServiceClient``), the
target's helper (its relay and its background agents), and discovery and profile fetches
(``client.rest_discovery``). One target, one trust rule, one way to fail:

* **TLS** as the owner recorded it: ``--tls-pin sha256:<hex>`` checks the leaf certificate's
  digest right after the handshake and before any request byte (the pin replaces chain and
  host-name validation, as the owner chose; approach A's pinned network backend), ``--ca-file``
  trusts that CA only (host name checked), and otherwise this computer's system store. A CA file
  that cannot be read sends nothing.
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
import hashlib
import ssl
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
    "load_key",
    "observed_identity",
]

# The largest control frame plus room for its envelope (the REST answer is the frame's body).
MAX_RESPONSE_BYTES: Final = 6_291_456 + 65_536
CONNECT_SECONDS: Final = 5.0
# A long-poll answers within ``MAX_WAIT_MS``; the read bound leaves room for the network.
_POLL_READ_SECONDS: Final = MAX_WAIT_MS / 1000 + 10.0
_REQUEST_READ_SECONDS: Final = 30.0
_REASONS: Final = frozenset(
    {
        "remote_auth_failed",
        "remote_identity_changed",
        "remote_incompatible",
        "remote_service_not_running",
        "remote_unreachable",
    }
)
_KEY_LOCK: Final = threading.Lock()


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


def _context_for(ca_file: str | None) -> ssl.SSLContext:
    """The verifying context: the recorded CA only, or this computer's system store."""

    try:
        context = (
            ssl.create_default_context()
            if ca_file is None
            else ssl.create_default_context(cafile=ca_file)
        )
    except (OSError, ssl.SSLError, ValueError):
        # A CA file that was moved, is unreadable or holds no certificate verifies nobody.
        raise RestUnavailable("remote_unreachable") from None
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _transport(ca_file: str | None, tls_pin: str | None) -> httpx.AsyncBaseTransport:
    if tls_pin is not None:
        return _PinnedTransport(tls_pin)
    return httpx.AsyncHTTPTransport(verify=_context_for(ca_file), trust_env=False)


def observed_identity(record: ServerTarget) -> tuple[str, str | None]:
    """The endpoint identity a connection under ``record``'s trust observes (design v2 §8.2).

    ``tls_pin`` and its pin; ``tls_ca_file`` and the ``sha256:`` of the CA file's bytes (the
    trust anchor the owner chose: replacing it changes the consent); ``tls_system_ca`` and none.
    Raises ``RestUnavailable`` when the CA file cannot be read.
    """

    if record.tls_pin is not None:
        return "tls_pin", record.tls_pin
    if record.ca_file is not None:
        try:
            with open(record.ca_file, "rb") as handle:  # noqa: PTH123 - the owner's own file
                data = handle.read(1_048_577)
        except OSError:
            raise RestUnavailable("remote_unreachable") from None
        if len(data) > 1_048_576:
            raise RestUnavailable("remote_unreachable")
        return "tls_ca_file", "sha256:" + hashlib.sha256(data).hexdigest()
    return "tls_system_ca", None


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

    with _KEY_LOCK:
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


async def load_key(target_id: str, *, seconds: float = 10.0) -> str:
    """The target's API key, read in a worker thread within ``seconds`` (A-KEYRING-LOOP).

    A store that does not answer in time (a locked keyring showing a prompt) is
    ``remote_auth_failed`` for this attempt; the event loop never waits on it.
    """

    try:
        async with asyncio.timeout(seconds):
            return await asyncio.to_thread(_read_key, target_id)
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
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._key = key
        self._client = httpx.AsyncClient(
            transport=transport or _transport(ca_file, tls_pin),
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
    ) -> RestTransport:
        if record.base_url is None:
            raise RestUnavailable("remote_unreachable")
        return cls(
            record.base_url,
            key=key,
            ca_file=record.ca_file,
            tls_pin=record.tls_pin,
            transport=transport,
        )

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
    ) -> RestAnswer:
        """One request; its answer bounded to ``limit`` bytes.

        ``poll`` gives a long-poll its longer read bound. Raises ``RestUnavailable`` for a transport
        failure, a redirect or an answer past the bound; a ``rest-error`` refusal is an answer.
        """

        if self._closed:
            raise RestUnavailable("remote_unreachable")
        timeout = httpx.Timeout(
            CONNECT_SECONDS, read=_POLL_READ_SECONDS if poll else _REQUEST_READ_SECONDS
        )
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
