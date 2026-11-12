"""The REST edge's TCP listeners: TLS, connection bounds and time bounds (ADR-053).

Both edges listen the same way (approach C's listener, A's serve rules), on the one address the
server owner gives ``finishup service rest run --listen HOST:PORT``:

* TLS 1.2+ with ``--tls-cert``/``--tls-key``; the key file must be the owner's and owner-only.
  Plain HTTP only with ``--behind-proxy`` and only on a loopback address, for a TLS-terminating
  proxy on the same host; plain HTTP anywhere else is refused before anything listens.
* Open connections are capped in total and per peer address (a connection over either cap is
  closed before TLS and before a byte is read); the caps shrink to a quarter of the descriptor
  budget the process gets.
* A connection completes TLS and sends a complete request head within ``REQUEST_HEAD_SECONDS`` of
  being accepted or answered, and a request's body arrives within ``REQUEST_BODY_SECONDS``;
  otherwise it is closed. A request being answered (a long-poll) has no such bound.
* No access log, no ``Server`` or ``Date`` header, no forwarded-for trust; uvicorn's own log lines
  (which may carry addresses and request lines) go nowhere.

``RestListener.bind`` binds before anything is served, so a listener that cannot be bound fails
with a closed reason; ``start`` serves an application on the running event loop; ``close`` stops
accepting, closes the application first (every long-poll is answered, every agent ends) and then
drops the connections left.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import os
import socket
import ssl
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Protocol, cast

from starlette.types import ASGIApp

if TYPE_CHECKING:
    import uvicorn

__all__ = [
    "KEEP_ALIVE_SECONDS",
    "MAX_TCP_CONNECTIONS",
    "MAX_TCP_CONNECTIONS_PER_PEER",
    "REQUEST_BODY_SECONDS",
    "REQUEST_HEAD_SECONDS",
    "ListenAddress",
    "ListenerError",
    "RestListener",
    "parse_listen",
]

MAX_TCP_CONNECTIONS: Final = 256
MAX_TCP_CONNECTIONS_PER_PEER: Final = 64
REQUEST_HEAD_SECONDS: Final = 10.0
REQUEST_BODY_SECONDS: Final = 120.0
# How long an idle keep-alive connection is held for a client's next request.
KEEP_ALIVE_SECONDS: Final = 30
_DESCRIPTOR_TARGET: Final = 4_096
_DESCRIPTOR_SHARE: Final = 4
_LISTEN_BACKLOG: Final = 128
_HTTP_SERVER_LOGGERS: Final = ("uvicorn", "uvicorn.error", "uvicorn.access", "uvicorn.asgi")
_REASONS: Final = frozenset(
    {
        "rest_listen_invalid",
        "rest_tls_required",
        "rest_tls_unusable",
        "rest_proxy_not_loopback",
        "rest_listener_unavailable",
    }
)


class ListenerError(Exception):
    """A listener this edge refuses or cannot bind; ``reason`` is a closed token."""

    def __init__(self, reason: str) -> None:
        if reason not in _REASONS:
            raise ValueError("rest_listener_reason_invalid")
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class ListenAddress:
    host: str
    port: int

    @property
    def loopback(self) -> bool:
        return self.host == "localhost" or ipaddress.ip_address(self.host).is_loopback


def parse_listen(value: str) -> ListenAddress:
    """``HOST:PORT`` or ``[V6]:PORT`` with an IP literal or ``localhost``; nothing else.

    Port 0 picks a free port (the conformance kit and tests).
    """

    if type(value) is not str or len(value) > 64:
        raise ListenerError("rest_listen_invalid")
    host, separator, port_text = value.rpartition(":")
    if not separator or not port_text.isascii() or not port_text.isdigit():
        raise ListenerError("rest_listen_invalid")
    port = int(port_text)
    if not 0 <= port <= 65_535:
        raise ListenerError("rest_listen_invalid")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host != "localhost":
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            raise ListenerError("rest_listen_invalid") from None
    return ListenAddress(host, port)


def _tls_context(cert: str, key: str) -> ssl.SSLContext:
    """A TLS 1.2+ server context; the key file must be the owner's and owner-only."""

    try:
        facts = Path(key).lstat()
    except OSError:
        raise ListenerError("rest_tls_unusable") from None
    if (
        not stat.S_ISREG(facts.st_mode)
        or facts.st_uid != os.geteuid()
        or stat.S_IMODE(facts.st_mode) & 0o077
    ):
        raise ListenerError("rest_tls_unusable")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.load_cert_chain(cert, key)
    except (OSError, ssl.SSLError):
        raise ListenerError("rest_tls_unusable") from None
    return context


def _bind_tcp(address: ListenAddress) -> socket.socket:
    host = "127.0.0.1" if address.host == "localhost" else address.host
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    # Name TCP explicitly: asyncio turns Nagle off (TCP_NODELAY) only for accepted sockets whose
    # protocol is IPPROTO_TCP, and an accepted socket inherits the listener's. With protocol 0
    # every TLS response waited on the client's delayed ACK, about 40 ms per request.
    raw = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    try:
        raw.set_inheritable(False)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            raw.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        raw.bind((host, address.port))
        raw.listen(_LISTEN_BACKLOG)
        raw.setblocking(False)
    except OSError:
        raw.close()
        raise ListenerError("rest_listener_unavailable") from None
    return raw


def _tcp_connection_budget(
    *,
    getrlimit: Callable[[int], tuple[int, int]] | None = None,
    setrlimit: Callable[[int, tuple[int, int]], None] | None = None,
) -> tuple[int, int]:
    """``(total, per peer address)`` open TCP connections, after raising the descriptor limit.

    The soft ``RLIMIT_NOFILE`` is raised toward ``_DESCRIPTOR_TARGET`` (never past the hard
    limit), and at most a quarter of what the service then has goes to the API's TCP connections,
    so a peer that fills them still leaves the control socket, the ledgers and the key file their
    descriptors.
    """

    import resource

    get = getrlimit or resource.getrlimit
    put = setrlimit or resource.setrlimit
    infinity = resource.RLIM_INFINITY
    try:
        soft, hard = get(resource.RLIMIT_NOFILE)
    except (OSError, ValueError):
        soft = hard = 256
    if soft != infinity and soft < _DESCRIPTOR_TARGET:
        wanted = _DESCRIPTOR_TARGET if hard == infinity else min(hard, _DESCRIPTOR_TARGET)
        if wanted > soft:
            try:
                put(resource.RLIMIT_NOFILE, (wanted, hard))
            except (OSError, ValueError):
                pass
            else:
                soft = wanted
    usable = _DESCRIPTOR_TARGET if soft == infinity else soft
    total = max(1, min(MAX_TCP_CONNECTIONS, usable // _DESCRIPTOR_SHARE))
    return total, max(1, min(MAX_TCP_CONNECTIONS_PER_PEER, total))


class _ConnectionGate:
    """The TCP listeners' open connections, in total and per peer address."""

    __slots__ = ("_members", "_per_peer", "per_peer_limit", "total_limit")

    def __init__(self, total_limit: int, per_peer_limit: int) -> None:
        if total_limit < 1 or per_peer_limit < 1:
            raise ValueError("connection_limit_invalid")
        self.total_limit = total_limit
        self.per_peer_limit = per_peer_limit
        self._per_peer: dict[str, int] = {}
        self._members: set[_GatedConnection] = set()

    @property
    def open(self) -> int:
        return len(self._members)

    def admit(self, peer: str, member: _GatedConnection) -> bool:
        held = self._per_peer.get(peer, 0)
        if len(self._members) >= self.total_limit or held >= self.per_peer_limit:
            return False
        self._per_peer[peer] = held + 1
        self._members.add(member)
        return True

    def release(self, peer: str, member: _GatedConnection) -> None:
        if member not in self._members:
            return
        self._members.discard(member)
        held = self._per_peer.get(peer, 0) - 1
        if held > 0:
            self._per_peer[peer] = held
        else:
            self._per_peer.pop(peer, None)

    def abort_all(self) -> None:
        """Close every connection still open (the listeners are stopping)."""

        for member in tuple(self._members):
            member.abort_connection()


class _GatedConnection(Protocol):
    def abort_connection(self) -> None: ...


def _peer_address(transport: asyncio.BaseTransport) -> str | None:
    peer = transport.get_extra_info("peername")
    if not isinstance(peer, tuple) or not peer:
        return None
    host = cast(tuple[object, ...], peer)[0]
    return host if isinstance(host, str) and host else None


def _tcp_protocol(gate: _ConnectionGate, tls: ssl.SSLContext | None) -> type[Any]:
    """uvicorn's h11 protocol behind the TCP listeners' admission and time bounds.

    The listener hands each accepted connection to this protocol before TLS: one over the gate's
    caps is aborted at once. An admitted one runs TLS itself (``loop.start_tls``) when the
    listener speaks it, then serves HTTP exactly as uvicorn does. Until a complete request head
    arrives — from acceptance, TLS included, and again after every answer — the connection lives
    at most ``REQUEST_HEAD_SECONDS``; a request's body must then arrive within
    ``REQUEST_BODY_SECONDS``. A request being answered has no bound here.
    """

    import h11
    from uvicorn.protocols.http.h11_impl import H11Protocol

    class _BoundedH11Protocol(H11Protocol):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self._peer: str | None = None
            self._raw: asyncio.BaseTransport | None = None
            self._serving = False
            self._deadline: asyncio.TimerHandle | None = None
            self._watching: object = None
            self._securing: asyncio.Task[None] | None = None
            # Bytes TLS decrypted with its last handshake flight, before ``start_tls`` handed the
            # secured transport back (at most one read).
            self._early: list[bytes] = []

        # --- admission and TLS ---------------------------------------------------------------

        def connection_made(self, transport: asyncio.BaseTransport) -> None:
            # Called once, by the listener, with the raw TCP transport.
            peer = _peer_address(transport)
            if peer is None or not gate.admit(peer, self):
                cast(asyncio.Transport, transport).abort()
                _note("connection_limit")
                return
            self._peer = peer
            self._raw = transport
            self._watch(h11.IDLE, REQUEST_HEAD_SECONDS)
            if tls is None:
                self._serve(cast(asyncio.Transport, transport))
                return
            # Nothing is read until TLS owns the connection.
            cast(asyncio.Transport, transport).pause_reading()
            self._securing = self.loop.create_task(
                self._secure(cast(asyncio.Transport, transport), tls)
            )

        async def _secure(self, raw: asyncio.Transport, context: ssl.SSLContext) -> None:
            try:
                secured = await self.loop.start_tls(
                    raw,
                    self,
                    context,
                    server_side=True,
                    ssl_handshake_timeout=REQUEST_HEAD_SECONDS,
                )
            except asyncio.CancelledError:
                self._drop()
                raise
            except Exception:
                self._drop()
                return
            if secured is None or self._peer is None:
                self._drop()
                return
            self._serve(secured)

        def _serve(self, transport: asyncio.Transport) -> None:
            self._serving = True
            super().connection_made(transport)
            early, self._early = self._early, []
            for chunk in early:
                self.data_received(chunk)

        def _drop(self) -> None:
            self._unwatch()
            self._early.clear()
            if self._raw is not None:
                cast(asyncio.Transport, self._raw).abort()
            self._release()

        def _release(self) -> None:
            if self._peer is not None:
                gate.release(self._peer, self)
                self._peer = None

        def abort_connection(self) -> None:
            self._drop()

        def connection_lost(self, exc: Exception | None) -> None:
            self._unwatch()
            self._release()
            if self._serving:
                self._serving = False
                super().connection_lost(exc)

        # --- request deadlines ---------------------------------------------------------------

        def data_received(self, data: bytes) -> None:
            if not self._serving:
                self._early.append(data)
                return
            super().data_received(data)
            self._follow()

        def on_response_complete(self) -> None:
            super().on_response_complete()
            self._follow()

        def _follow(self) -> None:
            """Watch what the peer owes next: a request head, a body, or nothing."""

            transport = cast(asyncio.Transport | None, self.transport)
            if transport is None or transport.is_closing():
                self._unwatch()
                return
            state = self.conn.their_state
            if state is h11.IDLE:
                self._watch(h11.IDLE, REQUEST_HEAD_SECONDS)
            elif state is h11.SEND_BODY:
                self._watch(h11.SEND_BODY, REQUEST_BODY_SECONDS)
            else:
                self._unwatch()

        def _watch(self, state: object, seconds: float) -> None:
            if self._watching is state and self._deadline is not None:
                return
            self._unwatch()
            self._watching = state
            self._deadline = self.loop.call_later(seconds, self._expire)

        def _unwatch(self) -> None:
            if self._deadline is not None:
                self._deadline.cancel()
                self._deadline = None
            self._watching = None

        def _expire(self) -> None:
            self._deadline = None
            _note("request_timeout")
            self._drop()

    return _BoundedH11Protocol


def _quiet_http_server_logs() -> None:
    """uvicorn's own log lines may carry addresses and request lines; FinishUP records closed
    tokens instead, so they go nowhere."""

    for name in _HTTP_SERVER_LOGGERS:
        logger = logging.getLogger(name)
        logger.handlers = [logging.NullHandler()]
        logger.propagate = False


# Listener-level refusals (a connection over a cap, a request head or body too slow) are counted
# here and written by the edge's audit; never an address.
_NOTES: dict[str, int] = {}
_NOTE_HOOK: list[Callable[[str], None]] = []


def _note(reason: str) -> None:
    _NOTES[reason] = _NOTES.get(reason, 0) + 1
    for hook in tuple(_NOTE_HOOK):
        with contextlib.suppress(Exception):
            hook(reason)


def _responding(connection: object) -> bool:
    """Whether a uvicorn connection is still sending a response (its cycle is not complete)."""

    cycle = getattr(connection, "cycle", None)
    return cycle is not None and not getattr(cycle, "response_complete", True)


class _Closable(Protocol):
    async def aclose(self) -> None: ...


class RestListener:
    """One bound TCP listener and the uvicorn server that serves it (see the module text)."""

    def __init__(
        self,
        raw: socket.socket,
        tls: ssl.SSLContext | None,
        *,
        tcp_limits: tuple[int, int],
    ) -> None:
        self._raw = raw
        self._tls = tls
        self._gate = _ConnectionGate(*tcp_limits)
        self._server: uvicorn.Server | None = None
        self._task: asyncio.Task[None] | None = None
        self._application: ASGIApp | None = None
        self._state: _Closable | None = None
        self._closed = False

    def __repr__(self) -> str:
        return "RestListener(<redacted>)"

    @classmethod
    def bind(
        cls,
        listen: str,
        *,
        tls_cert: Path | None,
        tls_key: Path | None,
        behind_proxy: bool,
        tcp_limits: tuple[int, int] | None = None,
    ) -> RestListener:
        """Validate the owner's choice and bind it; ``ListenerError`` before anything listens."""

        address = parse_listen(listen)
        tls: ssl.SSLContext | None = None
        if behind_proxy:
            if tls_cert is not None or tls_key is not None:
                raise ListenerError("rest_tls_unusable")
            if not address.loopback:
                raise ListenerError("rest_proxy_not_loopback")
        elif tls_cert is None or tls_key is None:
            raise ListenerError("rest_tls_required")
        else:
            tls = _tls_context(str(tls_cert), str(tls_key))
        raw = _bind_tcp(address)
        limits = tcp_limits or _tcp_connection_budget()
        return cls(raw, tls, tcp_limits=limits)

    @property
    def port(self) -> int:
        return int(self._raw.getsockname()[1])

    @property
    def scheme(self) -> str:
        return "http" if self._tls is None else "https"

    @property
    def open_connections(self) -> int:
        return self._gate.open

    async def start(self, application: ASGIApp, state: _Closable | None = None) -> None:
        """Serve ``application`` on this event loop until ``close``; ``state`` closes first."""

        import uvicorn

        if self._server is not None or self._closed:
            raise RuntimeError("rest_listener_already_started")
        _quiet_http_server_logs()
        self._application = application
        self._state = state
        config = uvicorn.Config(
            application,
            http=_tcp_protocol(self._gate, self._tls),
            ws="none",
            lifespan="off",
            log_config=None,
            access_log=False,
            proxy_headers=False,
            forwarded_allow_ips="",
            server_header=False,
            date_header=False,
            timeout_keep_alive=KEEP_ALIVE_SECONDS,
            timeout_graceful_shutdown=2,
        )
        config.load()
        server = uvicorn.Server(config)
        server.lifespan = config.lifespan_class(config)
        loop = asyncio.get_running_loop()
        protocol = cast(type[Any], config.http_protocol_class)

        def connection() -> asyncio.Protocol:
            return cast(
                asyncio.Protocol,
                protocol(
                    config=config,
                    server_state=server.server_state,
                    app_state=server.lifespan.state,
                    _loop=loop,
                ),
            )

        listening = await loop.create_server(connection, sock=self._raw, backlog=_LISTEN_BACKLOG)
        server.servers = [listening]
        server.started = True
        self._server = server
        self._task = asyncio.create_task(self._serve(server))

    async def _serve(self, server: uvicorn.Server) -> None:
        # ``Server.serve`` would replace the process's own signal handling; drive its parts here.
        await server.main_loop()
        await server.shutdown(sockets=[self._raw])

    async def close(self) -> None:
        """Stop accepting, close the application (answering every long-poll), then drop what is
        left: over TLS an idle pooled connection never closes on its own (A's gateway lesson)."""

        if self._closed:
            return
        self._closed = True
        server = self._server
        if server is not None:
            for listening in server.servers:
                listening.close()
        if self._state is not None:
            with contextlib.suppress(Exception):
                await self._state.aclose()
        if server is not None:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 1.0
            while loop.time() < deadline and any(
                _responding(connection) for connection in server.server_state.connections
            ):
                await asyncio.sleep(0.01)
            server.should_exit = True
            if self._task is not None:
                await asyncio.gather(self._task, return_exceptions=True)
        self._gate.abort_all()
        with contextlib.suppress(OSError):
            self._raw.close()


def add_note_hook(hook: Callable[[str], None]) -> None:
    """Have ``hook`` called with each listener-level refusal reason (the edge's audit)."""

    _NOTE_HOOK.append(hook)
