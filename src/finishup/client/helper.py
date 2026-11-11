"""``finishup helper run --target <id>``: the one background helper of a server elsewhere (design v2 §3).

One process per remote target (SSH, HTTPS or a port on this computer; ``state/helper.lock``), started on demand by a client that needs it,
never by ``service run``; it exits 15 minutes after its last client (a relayed connection or a
served registration) and is stopped by ``server disconnect``, ``remove``, ``use <other>`` and
``set --style`` through its target's stop epoch (``helper_status``: never a signal to a pid);
one spawned before such a stop never serves. Its roles:

1. **Relay** (the default style, U21): it serves ``<target root>/run/control.sock`` with the
   service's owner-only fences and peer-UID check, and carries each local connection over one
   channel of its OpenSSH master's ``-L`` forward into the server's owner-only control socket. It
   reads the hello (a hello naming a ``workspace_locator`` is never forwarded: a path on this
   computer never leaves it), and every later client frame is checked against the helper's own
   admission before it is forwarded (ADR-052, FR-2); frames from the server pass unparsed. A
   connection that claims a workspace names, before its hello and on this computer only, the
   repository key its own admission is bound to (``helper_status``'s relay binding): the relay,
   and a REST stream's own retries and polls, are then bound to that repository's hold
   (``ConnectionAuthorization.for_repository``), never to the worktrees a record lists. A hello
   that claims a workspace without it is never forwarded.
2. **Background workspace agent** per registration (``client.helper_registrations``, FR-1): a
   claim-bound connection whose agent declares ``role: background``, built through
   ``remote_workspace_binding`` under the helper's admission, so the repository hold is decided
   before the claim and the agent fences held repositories and answers nothing once its check
   lapses. It never counts as client activity and never starts the server's service. Each agent
   is opened under the target's record as it is then; when the owner's consent changes under
   the same profile revision (``server use NAME --level L2``: no lapse), every agent is opened
   again under the new record and the old one serves until its replacement is connected (at
   most 30 seconds), so an agent opened at L1 never stays the one the server asks to sync.
3. **Observation drain**: what this computer's hooks captured for each served workspace is
   delivered over its agent every 30 seconds, as its own task (never holding the tick or a stop),
   and once more, bounded, as the helper stops, never while this computer is zero-network.
4. **Profile cache and re-check** (design v2 sections 2.3 and 8.9): the server's profile is
   fetched (``client.ssh_discovery``) and recorded (``client.server_profile.refresh_profile``) at
   start, every 10 minutes while an upstream was used, when one of its own connections or a
   relayed one is refused ``server_profile_changed`` (over HTTPS the refusal ends the stream
   unanswered, so the helper asks itself) and when a client left the refresh marker; at most
   every 30 seconds.

**Admission (FR-3).** Everything above runs only under the helper's own admission through the
shared gate (``authorization.authorize_target``: pinned to its root, steps 2 to 5 and the
generation). A lapse (the owner's ``logout``/``remove`` credential bump, a consent or record
change, ADR-052 O8) ends every relayed connection and every agent; the next local connection is
admitted again. While this computer last reported a zero-network policy the helper relays nothing,
records ``zero_network_remote_selected``, asks its OpenSSH master to exit and stops at once.

Its status record (``client.helper_status``) names every outage with a closed phase, so a client
whose connection closed can say why; a client's own relay refused is recorded again for that
client even when the phase stands already (a background agent's earlier refusal). Nothing here logs or raises a path, host or name.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import functools
import os
import signal
import socket
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol, cast

from finishup import __version__
from finishup.adapters.control.unix_socket import (
    AuthenticatedUnixStream,
    EndpointKind,
    LocalControlTransportError,
    UnixEndpointListener,
    authenticate_peer,
    bind_control_listener,
    connect_owner_only_endpoint,
    remove_stale_endpoint,
)
from finishup.client.attribution import ConnectionTransport
from finishup.client.helper_status import (
    HELPER_IDLE_SECONDS,
    RELAY_BINDING_BYTES,
    ConnectionStyle,
    HelperLock,
    HelperLockBusy,
    HelperPhase,
    HelperStatus,
    helper_start_fence,
    new_status,
    now_stamp,
    read_connection_style,
    read_helper_epoch,
    read_helper_status,
    read_relay_binding,
    starts_relay_binding,
    take_profile_refresh_request,
    write_helper_status,
)
from finishup.client.ssh_transport import (
    SshMaster,
    UpstreamUnavailable,
    direct_remote_argv,
    ensure_direct_master,
    exit_master,
    open_direct_stream,
    require_host_key,
    run_ssh,
)
from finishup.client.targets import ServerTarget, TargetError
from finishup.service.control_protocol import (
    MAX_CONTROL_FRAME_BYTES,
    ControlProtocolError,
    ControlStream,
    encode_control_frame,
    read_control_frame,
)

if TYPE_CHECKING:
    from finishup.client.authorization import ConnectionAuthorization
    from finishup.client.helper_registrations import Registration, ServedWorkspace
    from finishup.client.rest_client import RestTransport
    from finishup.client.server_profile import FetchedProfile
    from finishup.service.client import ClientWorkspaceBinding, ServiceClient

__all__ = [
    "DRAIN_INTERVAL_SECONDS",
    "REFRESH_INTERVAL_SECONDS",
    "Helper",
    "HelperAgent",
    "RestUpstream",
    "Upstream",
    "run_helper",
]

# How often the helper delivers what this computer's hooks captured, per served workspace.
DRAIN_INTERVAL_SECONDS: Final = 30.0
# How often the helper fetches the server's profile again while an upstream is in use.
REFRESH_INTERVAL_SECONDS: Final = 600.0
# The fewest seconds between two profile fetches, whatever asked for them.
_REFRESH_MIN_SECONDS: Final = 30.0
# How often the registrations are read again even when their folder did not change.
_AGENT_SYNC_SECONDS: Final = 30.0
# How long an agent opened under an earlier consent keeps serving while its replacement connects.
_RETIRE_SECONDS: Final = 30.0
# The bound on closing the agents a new level replaces at once (``_replace_agents``).
_CLOSE_SECONDS: Final = 3.0
_HELLO_SECONDS: Final = 10.0
# One upstream attempt, from the master's start to the server's first answer to the hello: a
# server that accepts the channel and never answers ends the relay here, its stream closed.
_UPSTREAM_SETUP_SECONDS: Final = 30.0
_TICK_SECONDS: Final = 1.0
_PUMP_CHUNK: Final = 65_536
_FRAME_PREFIX: Final = 4
# One extra remote ``service start`` per this window at most, for a client's connection only.
_RESTART_WINDOW_SECONDS: Final = 30.0
# The last delivery as the helper stops is bounded, so a stop finishes within the stopper's wait.
_SHUTDOWN_DRAIN_SECONDS: Final = 2.0
# ``remote_unreachable`` is recorded again for clients at most this often while unchanged: a client
# keeps waiting and retrying on it (``service.client._connect_through_helper``), whatever the record
# says, so a fresh record changes no answer and a fast retry never makes a write and a diagnostic
# each. Every other refusal ends a waiting client's wait at its first fresh record, so each one is
# recorded for its client (a hook's short budget included).
_FRESH_STATUS_SECONDS: Final = 1.0
_COALESCED_FRESH: Final = frozenset({"remote_unreachable"})
_RECONNECT_MIN_SECONDS: Final = 0.5
_RECONNECT_MAX_SECONDS: Final = 30.0
_ZERO_NETWORK: Final = "zero_network_remote_selected"
_PROFILE_CHANGED: Final = "server_profile_changed"


type Dial = Callable[[], Awaitable[ControlStream]]


class Upstream(Protocol):
    """How the helper reaches the server's control endpoint (one fresh raw stream a call)."""

    async def ensure(self) -> None: ...

    async def open_stream(self) -> ControlStream: ...

    async def start_remote_service(self) -> bool: ...

    async def close(self) -> None: ...

    async def zero_network(self) -> None: ...


def _consented_host_key(root: Path) -> str | None:
    from finishup.client.server_profile import consented_host_key

    return consented_host_key(root)


class SshRelayUpstream:
    """The relay style: one warm master; each stream is one channel of its ``-L`` forward.

    The master is used only while it verified the host key the owner's consent names now
    (``SshMaster.ensure``), read again for every stream.
    """

    def __init__(self, root: Path, record: ServerTarget, *, ssh: str | None = None) -> None:
        self._master = SshMaster(root, record, ssh=ssh)
        self._root = root
        self._record = record

    async def ensure(self) -> None:
        await self._master.ensure(expected=_consented_host_key(self._root))

    async def open_stream(self) -> ControlStream:
        for attempt in range(2):
            await self._master.ensure(expected=_consented_host_key(self._root))
            try:
                return await connect_owner_only_endpoint(self._master.upstream_path)
            except LocalControlTransportError:
                # The master's forward is gone (a dropped connection): restart it once.
                await self._master.close()
                if attempt == 0:
                    continue
        raise UpstreamUnavailable("remote_unreachable")

    async def start_remote_service(self) -> bool:
        code = await self._master.run_remote(
            "service", "start", expected=_consented_host_key(self._root)
        )
        return code == 0

    async def close(self) -> None:
        await self._master.close()

    async def zero_network(self) -> None:
        await self._master.close()


class SshDirectUpstream:
    """The direct style: each stream is its own ``ssh -W`` through a ``ControlMaster=auto``.

    The master is OpenSSH's own (``ControlPersist``); the helper asks it to exit only when this
    computer turns zero-network (``server disconnect`` and the other stops ask it themselves).
    """

    def __init__(self, root: Path, record: ServerTarget, *, ssh: str | None = None) -> None:
        self._root = root
        self._record = record
        self._ssh = ssh

    def _executable(self) -> str:
        if self._ssh is None:
            from finishup.client import ssh_transport

            self._ssh = ssh_transport.resolve_ssh()
        return self._ssh

    async def ensure(self) -> None:
        return None

    async def open_stream(self) -> ControlStream:
        return await open_direct_stream(
            self._executable(),
            self._root,
            self._record,
            expected=_consented_host_key(self._root),
        )

    async def start_remote_service(self) -> bool:
        expected = _consented_host_key(self._root)
        await ensure_direct_master(self._executable(), self._root, self._record, expected=expected)
        code, _stdout, stderr = await run_ssh(
            direct_remote_argv(
                self._executable(), self._root, self._record, "service", "start", "--json"
            ),
            seconds=30.0,
        )
        require_host_key(stderr, expected)
        return code == 0

    async def close(self) -> None:
        return None

    async def zero_network(self) -> None:
        await exit_master(self._executable(), self._root, self._record)


class RestUpstream:
    """An HTTPS or ``local_port`` server's upstream (ADR-053): REST v1, either style.

    Each stream is a ``client.rest_stream.RestControlStream`` (the frame-to-REST mapping) over one
    warm ``RestTransport`` (TLS and keep-alive shared by every relayed connection). The key is read
    off the event loop (A-KEYRING-LOOP) from where the record says it lives now, again whenever
    the owner's credential generation moved (A-CRED-STALE); the transport is bound to the
    consented endpoint identity (its CA bytes or pin, ``RestTransport.for_target(consented=True)``)
    and made again whenever that consent changes; nothing is sent while ``may_send`` refuses
    (A-STOP-DELETE). The server's own edge starts its service, so this never does.
    """

    def __init__(self, root: Path, record: ServerTarget, *, may_send: Callable[[], bool]) -> None:
        self._root = root
        self._record = record
        self._may_send = may_send
        self._transport: RestTransport | None = None
        self._credential: object = None
        self._lock = asyncio.Lock()

    def _credential_stamp(self) -> object:
        from finishup.client.authorization import credential_generation_path

        try:
            facts = os.lstat(credential_generation_path(self._root))
        except OSError:
            return None
        return (facts.st_ino, facts.st_size, facts.st_mtime_ns)

    async def ensure(self) -> None:
        from finishup.client.rest_client import RestTransport, RestUnavailable, load_key
        from finishup.client.server_profile import consented_endpoint_identity

        async with self._lock:
            stamp = (self._credential_stamp(), consented_endpoint_identity(self._root))
            if self._transport is not None and not self._transport.closed:
                if stamp == self._credential:
                    return
                await self._transport.aclose()
                self._transport = None
            try:
                key = await load_key(self._record.target_id)
                self._transport = RestTransport.for_target(self._record, key=key, consented=True)
            except RestUnavailable as error:
                raise UpstreamUnavailable(error.reason) from None
            self._credential = stamp

    async def open_stream(self) -> ControlStream:
        from finishup.client.rest_stream import RestControlStream

        await self.ensure()
        assert self._transport is not None
        return RestControlStream(self._transport, may_send=self._may_send)

    async def start_remote_service(self) -> bool:
        return False

    async def close(self) -> None:
        async with self._lock:
            if self._transport is not None:
                await self._transport.aclose()
                self._transport = None

    async def zero_network(self) -> None:
        await self.close()


async def _stream_failure(stream: ControlStream) -> str | None:
    """The closed phase an upstream stream names for its own end, if it names one."""

    failure_phase = getattr(stream, "failure_phase", None)
    if failure_phase is None:
        return None
    try:
        phase = await failure_phase()
    except Exception:  # noqa: BLE001 - a stream that cannot say why names nothing
        return None
    return phase if type(phase) is str and phase in _UPSTREAM_PHASES else None


_UPSTREAM_PHASES: Final = frozenset(
    {
        "remote_auth_failed",
        "remote_identity_changed",
        "remote_incompatible",
        "remote_service_not_running",
        "remote_unreachable",
        "repository_egress_held",
        "server_authorization_changed",
        "server_profile_changed",
    }
)


class _Pushback:
    """A local stream's reads with the bytes already read put back in front (the first byte a
    relay reads to tell its repository binding from a hello)."""

    __slots__ = ("_data", "_stream")

    def __init__(self, stream: ControlStream, data: bytes) -> None:
        self._stream = stream
        self._data = data

    async def receive(self, max_bytes: int) -> bytes:
        if self._data:
            chunk, self._data = self._data[:max_bytes], self._data[max_bytes:]
            return chunk
        return await self._stream.receive(max_bytes)


async def _read_exactly(stream: ControlStream, count: int) -> bytes | None:
    data = bytearray()
    while len(data) < count:
        chunk = await stream.receive(count - len(data))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


async def _relay_start(stream: ControlStream) -> tuple[str | None, Mapping[str, object]] | None:
    """A relayed connection's repository binding (``None`` without one) and its hello; ``None``
    when neither can be read. Raises what ``read_control_frame`` raises."""

    first = await stream.receive(1)
    if not first:
        return None
    key: str | None = None
    if starts_relay_binding(first):
        rest = await _read_exactly(stream, RELAY_BINDING_BYTES - 1)
        key = None if rest is None else read_relay_binding(first + rest)
        if key is None:
            return None
        hello = await read_control_frame(stream)
    else:
        hello = await read_control_frame(cast(ControlStream, _Pushback(stream, first)))
    return key, hello


class _RelayEnded(Exception):
    """A relayed connection ended because its admission refused a frame."""


async def _wait(seconds: float) -> None:
    await asyncio.sleep(seconds)


async def _discard(stream: ControlStream) -> None:
    """Close ``stream``, whatever it raises; a cancellation still closes it first."""

    with contextlib.suppress(Exception):
        await asyncio.shield(stream.aclose())


class HelperAgent:
    """One served registration's background agent connection, kept and reconnected until closed.

    The connection carries the real ``WorkspaceAgentHandler`` (``role: background``) and is
    checked against the binding's own authorization (the helper's admission bound to the
    repository's hold) before every frame and on its watch. Before each attempt ``may_connect``
    (the binding's check and the target's record) is asked: once it refuses, the agent stops for
    good; the helper opens a new one if the registration is served again. It never starts the
    server's service.
    """

    __slots__ = (
        "_binding",
        "_client",
        "_closing",
        "_dial",
        "_drain",
        "_drain_lock",
        "_on_profile_changed",
        "_reconnect_wait",
        "_supervisor",
        "_transport",
        "registration",
    )

    def __init__(
        self,
        registration: Registration,
        binding: ClientWorkspaceBinding,
        drain: object,
        dial: Dial,
        *,
        transport: ConnectionTransport,
        on_profile_changed: Callable[[], None],
        reconnect_wait: Callable[[float], Awaitable[None]] = _wait,
    ) -> None:
        self.registration = registration
        self._binding = binding
        self._drain = drain
        self._dial = dial
        self._transport: ConnectionTransport = transport
        self._on_profile_changed = on_profile_changed
        self._reconnect_wait = reconnect_wait
        self._client: ServiceClient | None = None
        self._closing = False
        self._drain_lock = asyncio.Lock()
        self._supervisor: asyncio.Task[None] | None = None

    def __repr__(self) -> str:
        return "HelperAgent(<redacted>)"

    @property
    def alive(self) -> bool:
        return not self._closing and self._supervisor is not None and not self._supervisor.done()

    @property
    def client(self) -> ServiceClient | None:
        client = self._client
        return None if client is None or client.closed else client

    def start(self) -> None:
        if self._supervisor is None:
            self._supervisor = asyncio.create_task(self._supervise())

    def _may_connect(self) -> bool:
        check = self._binding.authorization
        try:
            return check is None or check.refusal() is None
        except Exception:  # noqa: BLE001 - a check that cannot be made connects nothing
            return False

    async def _supervise(self) -> None:
        from finishup.ports.control import ControlClientKind, ControlError
        from finishup.service.client import connect_service_via

        delay = _RECONNECT_MIN_SECONDS
        while not self._closing:
            if not self._may_connect():
                # Never connect again: the target was removed, its authorization changed or its
                # repository is held now (A-REMOVE-RACE; ADR-052).
                return
            try:
                client = await connect_service_via(
                    self._dial,
                    ControlClientKind.CLI,
                    workspace_binding=self._binding,
                    authorization=self._binding.authorization,
                    transport=self._transport,
                )
            except ControlError as error:
                if error.phase == _PROFILE_CHANGED:
                    self._on_profile_changed()
                await self._reconnect_wait(delay)
                delay = min(delay * 2, _RECONNECT_MAX_SECONDS)
                continue
            except Exception:  # noqa: BLE001 - unreachable or mid-restart: try again, bounded
                await self._reconnect_wait(delay)
                delay = min(delay * 2, _RECONNECT_MAX_SECONDS)
                continue
            delay = _RECONNECT_MIN_SECONDS
            self._client = client
            try:
                await client.wait_closed()
            finally:
                self._client = None
                with contextlib.suppress(Exception):
                    await client.close()
            if not self._closing:
                await self._reconnect_wait(_RECONNECT_MIN_SECONDS)

    async def drain(self, *, may_send: Callable[[], bool]) -> None:
        """Deliver this workspace's captured observations over the live connection, if any.

        Never raises; nothing is sent while ``may_send`` refuses (zero-network, a lapsed check).
        """

        client = self.client
        if client is None or not may_send() or not self._may_connect():
            return
        async with self._drain_lock:
            with contextlib.suppress(Exception):
                await cast("_Drain", self._drain).drain(client)

    async def aclose(self) -> None:
        self._closing = True
        supervisor, self._supervisor = self._supervisor, None
        if supervisor is not None:
            supervisor.cancel()
            await asyncio.gather(supervisor, return_exceptions=True)
        client, self._client = self._client, None
        if client is not None:
            with contextlib.suppress(Exception):
                await client.close()
        with contextlib.suppress(Exception):
            cast("_Drain", self._drain).close()


class _Drain(Protocol):
    async def drain(self, client: ServiceClient) -> object: ...

    def close(self) -> None: ...


type AgentOpener = Callable[
    [Path, ServerTarget, "Registration", "ConnectionAuthorization", Dial],
    Awaitable["HelperAgent | None"],
]


async def open_helper_agent(
    root: Path,
    record: ServerTarget,
    registration: Registration,
    admission: ConnectionAuthorization,
    dial: Dial,
    *,
    transport: ConnectionTransport,
    on_profile_changed: Callable[[], None],
) -> HelperAgent | None:
    """The background agent for ``registration``; ``None`` when it may not be served now.

    The binding is built again from the registration's worktree under the target's own salt and
    the helper's admission (the repository's hold decided before the claim); a binding whose claim
    is not the registration's (a moved folder, an edited record) is never served.
    """

    from finishup.adapters.workspace_root import RepositoryIdentityError
    from finishup.client.observation_outbox import ClientObservationDrain
    from finishup.client.remote_binding import remote_workspace_binding
    from finishup.ports.control import WorkspaceLocator

    try:
        salt = base64.b64decode(cast(str, record.claim_salt), validate=True)
    except (TypeError, ValueError, binascii.Error):
        return None
    locator = WorkspaceLocator(registration.worktree)
    try:
        binding = await remote_workspace_binding(
            locator,
            salt,
            serve_workspace=True,
            target=record,
            authorization=admission,
            role="background",
            code_sync=True,
        )
    except (RepositoryIdentityError, TargetError, ValueError, OSError):
        return None
    if binding.claim != registration.claim or binding.agent is None:
        return None
    # The root's own state, named: the drain's store reads run on executor threads.
    drain = ClientObservationDrain(locator, state=root / "state")
    agent = HelperAgent(
        registration,
        binding,
        drain,
        dial,
        transport=transport,
        on_profile_changed=on_profile_changed,
    )
    agent.start()
    return agent


@dataclass(slots=True)
class _Refresh:
    """When the profile was last fetched, and why the next fetch is due."""

    last: float | None = None
    requested: bool = True
    task: asyncio.Task[None] | None = None


type Refresher = Callable[[ServerTarget], Awaitable[None]]


async def _refresh_over_ssh(record: ServerTarget) -> None:
    """Fetch the server's profile over OpenSSH and record it under the registry lock, only while
    what it was fetched under still holds (``server_profile.FetchBasis``)."""

    from finishup.client.server_profile import fetch_basis, refresh_profile
    from finishup.client.ssh_discovery import fetch_profile_async
    from finishup.client.targets import registry_lock

    basis = fetch_basis(record)
    fetched: FetchedProfile = await fetch_profile_async(record)

    def record_it() -> None:
        with registry_lock():
            refresh_profile(record, fetched, basis=basis)

    await asyncio.to_thread(record_it)


async def _refresh_over_rest(
    record: ServerTarget, *, may_send: Callable[[], bool] | None = None
) -> None:
    """Fetch an HTTPS server's profile (``GET /v1/server``) and record it under the registry
    lock (ADR-053): over the consented trust only, asking ``may_send`` before each request.

    The credential generation is read before the key: every request asks that it has not moved
    since (a ``server login``, ``logout`` or ``remove`` meanwhile: the key read may be the old
    one, and nothing more is sent with it), and the profile is recorded only while it still has
    not, for the target it was fetched for (``FetchBasis``): never a profile answered to another
    key than the one stored now."""

    from finishup.client.authorization import credential_generation
    from finishup.client.rest_client import RestUnavailable
    from finishup.client.rest_discovery import fetch_profile_async
    from finishup.client.server_profile import fetch_basis, refresh_profile
    from finishup.client.targets import registry_lock, target_root

    basis = fetch_basis(record)
    root = target_root(record.target_id)

    def allowed() -> bool:
        if credential_generation(root) != basis.credential:
            return False
        return may_send is None or may_send()

    try:
        fetched: FetchedProfile = await fetch_profile_async(
            record, consented=True, may_send=allowed
        )
    except RestUnavailable as error:
        raise UpstreamUnavailable(error.reason) from None

    def record_it() -> None:
        with registry_lock():
            refresh_profile(record, fetched, basis=basis)

    await asyncio.to_thread(record_it)


_REST_KINDS: Final = frozenset({"https", "local_port"})


def _declares_code_sync(record: ServerTarget) -> bool:
    """Whether a background agent opened under ``record`` declares the code-sync operations
    (``remote_binding.remote_workspace_binding``: level L2 consented, L2 released)."""

    from finishup.protocol.server_copy import l2_released

    consent = record.consent
    return l2_released() and consent is not None and consent.level == "L2"


class Helper:
    """One remote target's helper: relay, background agents, drain, profile refresh, idle exit."""

    def __init__(
        self,
        root: Path,
        record: ServerTarget,
        *,
        style: ConnectionStyle = "relay",
        upstream: Upstream | None = None,
        idle_seconds: float = HELPER_IDLE_SECONDS,
        drain_interval: float = DRAIN_INTERVAL_SECONDS,
        refresh_interval: float = REFRESH_INTERVAL_SECONDS,
        agent_opener: AgentOpener | None = None,
        refresher: Refresher | None = None,
        tick: Callable[[], Awaitable[None]] | None = None,
        clock: Callable[[], float] = time.monotonic,
        ssh: str | None = None,
        setup_seconds: float = _UPSTREAM_SETUP_SECONDS,
        epoch: str | None = None,
    ) -> None:
        if record.kind != "ssh" and record.kind not in _REST_KINDS:
            raise ValueError("target_not_remote")
        self._setup_seconds = setup_seconds
        # The stop epoch this helper serves under (``helper_status``); a stop moves it.
        self._epoch = read_helper_epoch(root) if epoch is None else epoch
        self._root = root
        self._record = record
        self._style: ConnectionStyle = style
        if upstream is None:
            if record.kind in _REST_KINDS:
                upstream = RestUpstream(root, record, may_send=self._may_send)
            elif style == "relay":
                upstream = SshRelayUpstream(root, record, ssh=ssh)
            else:
                upstream = SshDirectUpstream(root, record, ssh=ssh)
        self._upstream = upstream
        self._idle_seconds = idle_seconds
        self._drain_interval = drain_interval
        self._refresh_interval = refresh_interval
        self._agent_opener = agent_opener
        self._refresher: Refresher = refresher or (
            functools.partial(_refresh_over_rest, may_send=self._may_refresh_send)
            if record.kind in _REST_KINDS
            else _refresh_over_ssh
        )
        self._tick = tick or (lambda: asyncio.sleep(min(_TICK_SECONDS, drain_interval)))
        self._clock = clock
        self._status: HelperStatus | None = read_helper_status(root)
        # When this process last wrote its status again for a client (``_write_status(fresh=)``,
        # ``_clock``); ``None`` when its last write was not one.
        self._fresh_written: float | None = None
        self._started_at = now_stamp()
        self._admission: ConnectionAuthorization | None = None
        self._active = 0
        self._last_activity = clock()
        self._last_upstream_use: float | None = None
        self._last_drain = clock()
        self._last_sync: float | None = None
        self._registrations_stamp: object = None
        self._agents: dict[tuple[object, ...], HelperAgent] = {}
        # Agents opened under an earlier consent, each with when it was replaced: they keep serving
        # until their replacement is connected, at most ``_RETIRE_SECONDS`` (defect A).
        self._retiring: dict[tuple[object, ...], tuple[HelperAgent, float]] = {}
        # The identity stamp of ``target.json`` when the record agents open under was last read.
        self._record_stamp: object = None
        self._served_count = 0
        self._delivery: asyncio.Task[None] | None = None
        self._refresh = _Refresh()
        self._relays: set[asyncio.Task[None]] = set()
        self._own_relays: set[asyncio.Task[None]] = set()
        self._tasks: set[asyncio.Task[None]] = set()
        self._stop = asyncio.Event()
        self._stop_reason = "stop_requested"
        self._last_restart = -_RESTART_WINDOW_SECONDS

    # -- status ------------------------------------------------------------------------------

    @property
    def stop_reason(self) -> str:
        return self._stop_reason

    def _write_status(self, phase: HelperPhase, reason: str | None, *, fresh: bool = False) -> None:
        """Record ``phase`` and ``reason``; an unchanged one is not written again unless ``fresh``.

        ``fresh`` (a client's own relay refused): written again even when unchanged, with its own
        correlation id, so the client that waits on this attempt sees a record made after it began
        (``service.client._helper_failure``) and names the refusal at once, instead of waiting out
        its deadline while a background agent's earlier refusal of the same reason stands.
        ``remote_unreachable``, on which a client keeps retrying anyway, is written again at most
        once every ``_FRESH_STATUS_SECONDS`` while unchanged (``_COALESCED_FRESH``). The
        generation moves only when the phase or the reason changes (``new_status``).
        """

        previous = self._status
        if (
            previous is not None
            and previous.started_at == self._started_at
            and previous.pid == os.getpid()
            and (previous.phase, previous.reason) == (phase, reason)
            and (
                not fresh
                or (
                    reason in _COALESCED_FRESH
                    and self._fresh_written is not None
                    and self._clock() - self._fresh_written < _FRESH_STATUS_SECONDS
                )
            )
        ):
            return
        correlation_id = None
        if phase == "unavailable" and reason is not None:
            from finishup.observability.logging import record_public_error_without_raising

            correlation_id = record_public_error_without_raising(
                component="client.helper", operation="helper_upstream", reason=reason
            )
        status = new_status(
            previous,
            phase,
            reason,
            correlation_id=correlation_id,
            started_at=self._started_at,
            style=self._style,
        )
        try:
            write_helper_status(self._root, status)
        except OSError:
            # The target folder is gone (``server remove``): nothing is made again.
            self.request_stop("target_removed")
            return
        self._status = status
        self._fresh_written = self._clock() if fresh else None

    def _name_refusal_again(self) -> None:
        """A client's relay refused under the helper's standing refusal: record it again for that
        client (``_write_status(fresh=True)``), so it is named at once, not after a deadline."""

        status = self._status
        if status is not None and status.phase == "unavailable" and status.reason is not None:
            self._write_status("unavailable", status.reason, fresh=True)

    # -- admission (FR-3) -----------------------------------------------------------------------

    def _admitted(self) -> ConnectionAuthorization | None:
        """The helper's admission now, admitting again after a lapse; ``None`` while refused.

        A refusal is recorded as the status's phase; zero-network stops the helper.
        """

        from finishup.client.authorization import authorize_target

        admission = self._admission
        if admission is not None and admission.refusal() is None:
            return admission
        if admission is not None:
            # Lapsed: every connection made under it ends (O8: the relay too).
            self._lapse(admission)
        try:
            from finishup.client.targets import read_target

            current = read_target(self._root)
            if current is None or current.target_id != self._record.target_id:
                self.request_stop("target_removed")
                return None
            admission = authorize_target(current)
        except TargetError as error:
            phase = error.reason
            if phase == _ZERO_NETWORK:
                self._refuse_zero_network()
                return None
            from finishup.protocol.errors import REMOTE_CONNECTION_PHASES

            self._write_status(
                "unavailable",
                phase if phase in REMOTE_CONNECTION_PHASES else "server_authorization_changed",
            )
            return None
        self._admission = admission
        return admission

    def _zero_network(self) -> bool:
        from finishup.client.everyday_policy import last_reported_zero_network

        try:
            return last_reported_zero_network() is not None
        except Exception:  # noqa: BLE001 - a record that cannot be read refuses nothing new
            return False

    def _refuse_zero_network(self) -> bool:
        """Stop when this computer last reported a zero-network policy; whether it did."""

        if not self._zero_network():
            return False
        if not (self._stop.is_set() and self._stop_reason == _ZERO_NETWORK):
            self._write_status("unavailable", _ZERO_NETWORK)
            self.request_stop(_ZERO_NETWORK)
        return True

    def _may_send(self) -> bool:
        if self._stop.is_set() and self._stop_reason == _ZERO_NETWORK:
            return False
        if self._zero_network():
            return False
        admission = self._admission
        return admission is not None and admission.refusal() is None

    # -- the relay -------------------------------------------------------------------------------

    def _end_relays(self) -> None:
        # The relay asking (an admission refused while it opens) ends by its own refusal; every
        # other one is cancelled.
        current = asyncio.current_task()
        for task in tuple(self._relays):
            if task is not current:
                task.cancel()

    def _lapse(self, admission: ConnectionAuthorization) -> None:
        """``admission`` no longer admits: end every relay made under it, then forget it.

        Every relay of the helper runs under its one current admission (a lapse ends them all
        before another is taken), so a refusal seen by one relay, by the refresh or by the
        watch ends every other one too, its server-to-client direction included (O8), and the
        next admission starts with none of them.
        """

        self._end_relays()
        if self._admission is admission:
            self._admission = None

    async def _dial_own(self) -> ControlStream:
        """A connection to this helper's relay that bypasses its endpoint (background agents).

        It is relayed exactly like a client's, but it is not client activity and never starts
        the server's service.
        """

        ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            relayed = AuthenticatedUnixStream(theirs, authenticate_peer(theirs))
            dialled = AuthenticatedUnixStream(ours, authenticate_peer(ours))
        except BaseException:
            ours.close()
            theirs.close()
            raise
        self._spawn_relay(relayed, own=True)
        return dialled

    def _spawn_relay(self, local: AuthenticatedUnixStream, *, own: bool) -> None:
        task = asyncio.create_task(self._serve_local(local, own=own))
        self._relays.add(task)
        task.add_done_callback(self._relays.discard)
        if own:
            # A background agent's relay: its end is where a REST stream's agent is unregistered
            # (``RestControlStream.aclose``), which a new level waits for (``_replace_agents``).
            self._own_relays.add(task)
            task.add_done_callback(self._own_relays.discard)

    def _may_forward(self, admission: ConnectionAuthorization) -> bool:
        """Whether something admitted under ``admission`` may leave this computer now.

        Asked again right before every hello and every remote ``service start`` the helper makes
        (the dial, the master and the service start all await, and the authorization may change
        meanwhile), and before every relayed frame.
        """

        if self._refuse_zero_network():
            return False
        if self._stop.is_set() and self._stop_reason == _ZERO_NETWORK:
            return False
        return admission.refusal() is None

    async def _open_channel(
        self,
        hello: bytes,
        admission: ConnectionAuthorization,
        *,
        restart: bool,
        bound: Callable[[], str | None] | None = None,
    ) -> tuple[ControlStream, bytes]:
        """One upstream stream with the hello sent, and the first answered bytes.

        With ``restart`` (a client's connection) a remote service that is not running is started
        once with the server's own launcher; a background agent's connection never starts it.
        ``admission`` is asked again right before the hello is sent and right before the remote
        service is started: a refusal then sends nothing (``_RelayEnded``).
        """

        for attempt in range(2):
            upstream, first = await self._attempt(hello, admission, bound)
            if first:
                return upstream, first
            named = await _stream_failure(upstream)
            await _discard(upstream)
            if named is not None and named != "remote_service_not_running":
                # The upstream named why it could not carry the hello (a REST server's refusal).
                raise UpstreamUnavailable(named)
            # sshd could not reach the server's endpoint: its service is not running.
            now = self._clock()
            if restart and attempt == 0 and now - self._last_restart >= _RESTART_WINDOW_SECONDS:
                if not self._may_forward(admission):
                    self._lapse(admission)
                    raise _RelayEnded
                self._last_restart = now
                if await self._upstream.start_remote_service():
                    continue
            break
        raise UpstreamUnavailable("remote_service_not_running")

    async def _attempt(
        self,
        hello: bytes,
        admission: ConnectionAuthorization,
        bound: Callable[[], str | None] | None = None,
    ) -> tuple[ControlStream, bytes]:
        """One bounded upstream attempt: the stream and the server's first answer (``b""``: none).

        The master's start, the channel's open, the hello and the first answer share one bound
        (``remote_unreachable`` past it); the stream it opened is closed on every failure and on
        a cancellation (the relay ending, a lapse, the helper stopping), never left behind.
        """

        upstream: ControlStream | None = None
        try:
            async with asyncio.timeout(self._setup_seconds):
                await self._upstream.ensure()
                upstream = await self._upstream.open_stream()
                bind = getattr(upstream, "bind", None)
                if bound is not None and callable(bind):
                    # A stream that sends on its own (REST: retries, long-polls, the agent's
                    # registration) asks this relay's own admission and repository first.
                    bind(bound)
                if not self._may_forward(admission):
                    self._lapse(admission)
                    raise _RelayEnded
                try:
                    await upstream.send_all(hello)
                    first = await upstream.receive(_PUMP_CHUNK)
                except (LocalControlTransportError, OSError):
                    first = b""
        except TimeoutError:
            if upstream is not None:
                await _discard(upstream)
            raise UpstreamUnavailable("remote_unreachable") from None
        except BaseException:
            if upstream is not None:
                await _discard(upstream)
            raise
        return upstream, first

    async def _serve_local(self, local: AuthenticatedUnixStream, *, own: bool = False) -> None:
        if not own:
            self._active += 1
            self._last_activity = self._clock()
        upstream: ControlStream | None = None
        try:
            if self._refuse_zero_network():
                return
            try:
                async with asyncio.timeout(_HELLO_SECONDS):
                    started = await _relay_start(local)
            except (TimeoutError, ControlProtocolError, LocalControlTransportError):
                return
            if started is None:
                return
            key, hello = started
            if (
                "connection_nonce" not in hello
                or hello.get("workspace_locator") is not None
                or hello.get("server_profile") is None
                or (hello.get("workspace_claim") is not None and key is None)
            ):
                # Not a hello, a hello naming a path on this computer, one bound to no consented
                # profile revision, or one claiming a workspace without naming the repository
                # its admission is bound to: never forwarded.
                return
            admission = self._admitted()
            if admission is None:
                if not own:
                    self._name_refusal_again()
                return
            # This relay's own repository: its hold, by the repository's key, withholds the
            # relay's frames and its REST stream's own requests (design v2 section 8.3).
            repository = None if key is None else admission.for_repository(key)
            try:
                upstream, first = await self._open_channel(
                    encode_control_frame(hello),
                    admission,
                    restart=not own,
                    bound=lambda: self._relay_refusal(admission, repository),
                )
            except UpstreamUnavailable as error:
                # A client waits on this attempt's own record; a background agent's refusal of the
                # same reason may already stand (defect B, dogfood 2026-11-11).
                self._write_status("unavailable", error.reason, fresh=not own)
                if error.reason == _PROFILE_CHANGED:
                    # A REST server refused the consented revision: the stream ended unanswered,
                    # so no client (the helper's own agents included) sees the typed refusal an
                    # SSH relay passes on. Fetch the profile again now (at most every 30 s) so the
                    # consent reads what changed (defect B).
                    self._profile_changed()
                return
            self._last_upstream_use = self._clock()
            self._write_status("ready", None)
            await local.send_all(first)
            await self._pump_both(local, upstream, admission, repository)
        except (asyncio.CancelledError, _RelayEnded):
            pass
        except Exception:  # noqa: BLE001 - a relay fault ends this connection only
            pass
        finally:
            # Counted first: a cancellation landing while the streams close never leaves the
            # helper believing a client is still connected.
            if not own:
                self._active -= 1
                self._last_activity = self._clock()
            if upstream is not None:
                with contextlib.suppress(Exception):
                    await upstream.aclose()
            with contextlib.suppress(Exception):
                await local.aclose()

    def _relay_refusal(
        self, admission: ConnectionAuthorization, repository: ConnectionAuthorization | None
    ) -> str | None:
        """What withholds a relayed stream's own next request (design v2 section 8.3).

        The admission the relay was opened under (zero-network, a lapse, the helper stopping:
        ``server_authorization_changed``), then the repository the client named for it: that
        admission bound to the repository's key (``ConnectionAuthorization.for_repository``), so
        a repository held or kept from this target now refuses with its own phase
        (``repository_egress_held``, ``repository_egress_kept``), whichever worktree the relay
        serves. The client checks its own repository before each frame it writes; this covers what
        a REST stream sends between them (a lost answer's resend, ``operation_limit`` retries,
        polls).
        """

        if not self._may_forward(admission) or not self._may_send():
            return "server_authorization_changed"
        if repository is not None:
            return repository.refusal()
        return None

    async def _pump_checked(
        self,
        source: ControlStream,
        sink: ControlStream,
        admission: ConnectionAuthorization,
        repository: ConnectionAuthorization | None = None,
    ) -> None:
        """Client to server, frame by frame: each frame is checked before it is forwarded, against
        the helper's admission and the relay's own repository."""

        buffer = bytearray()
        while chunk := await source.receive(_PUMP_CHUNK):
            buffer.extend(chunk)
            while len(buffer) >= _FRAME_PREFIX:
                size = int.from_bytes(buffer[:_FRAME_PREFIX], "big")
                if size == 0 or size > MAX_CONTROL_FRAME_BYTES:
                    raise _RelayEnded
                end = _FRAME_PREFIX + size
                if len(buffer) < end:
                    break
                if not self._may_forward(admission) or not self._may_send():
                    # What this connection was admitted under changed: nothing more is sent,
                    # over this relay or any other made under it.
                    self._lapse(admission)
                    raise _RelayEnded
                if repository is not None and repository.refusal() is not None:
                    # This relay's repository is held or kept now: this relay ends; the others,
                    # made for other repositories, go on.
                    raise _RelayEnded
                frame = bytes(buffer[:end])
                del buffer[:end]
                await sink.send_all(frame)
                self._last_upstream_use = self._clock()
        shutdown = getattr(sink, "shutdown_write", None)
        if shutdown is not None:
            with contextlib.suppress(Exception):
                await shutdown()

    async def _pump(self, source: ControlStream, sink: ControlStream) -> None:
        while chunk := await source.receive(_PUMP_CHUNK):
            await sink.send_all(chunk)
        shutdown = getattr(sink, "shutdown_write", None)
        if shutdown is not None:
            with contextlib.suppress(Exception):
                await shutdown()

    async def _pump_both(
        self,
        local: ControlStream,
        upstream: ControlStream,
        admission: ConnectionAuthorization,
        repository: ConnectionAuthorization | None = None,
    ) -> None:
        tasks = (
            asyncio.create_task(self._pump_checked(local, upstream, admission, repository)),
            asyncio.create_task(self._pump(upstream, local)),
        )
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _accept(self, listener: UnixEndpointListener) -> None:
        while not self._stop.is_set():
            try:
                stream = await listener.accept()
            except LocalControlTransportError as error:
                if error.reason == "listener_closed":
                    return
                continue
            self._spawn_relay(stream, own=False)

    # -- background agents ------------------------------------------------------------------------

    def _agent_dial(self) -> Dial:
        if self._style == "relay":
            return self._dial_own
        return self._upstream.open_stream

    def _registrations_changed(self) -> bool:
        from finishup.client.helper_registrations import registrations_dir

        try:
            facts = os.lstat(registrations_dir(self._record.target_id))
            stamp: object = (facts.st_ino, facts.st_mtime_ns, facts.st_ctime_ns)
        except (OSError, TargetError):
            stamp = None
        changed = stamp != self._registrations_stamp
        self._registrations_stamp = stamp
        return changed

    def _profile_changed(self) -> None:
        self._refresh.requested = True

    async def _sync_agents(self) -> None:
        """Open one agent for each workspace a registration serves now; close every other one.

        Every client process registers the workspace it worked in (each command its own
        registrant, with a lease), so a busy worktree has many registrations at once. They
        all name the same claim and worktree and are served under the same admission, so the
        helper keeps one background agent per workspace, not one per registration: a server
        bounds the agents one key may hold, and a client's own connections need room too.
        The registration that holds the workspace longest is the one served.
        """

        from finishup.client.helper_registrations import served_workspaces

        self._last_sync = self._clock()
        admission = self._admitted()
        served: tuple[ServedWorkspace, ...] = ()
        if admission is not None:
            try:
                served = await served_workspaces(self._record)
            except Exception:  # noqa: BLE001 - a read that fails serves nothing this round
                served = ()
        self._served_count = len(served)
        wanted: dict[tuple[object, str], Registration] = {}
        for item in served:
            key = (item.registration.claim, item.registration.worktree)
            held = wanted.get(key)
            if held is None or item.registration.expires_at > held.expires_at:
                wanted[key] = item.registration
        for key in tuple(self._agents):
            agent = self._agents[key]
            if key not in wanted or not agent.alive:
                del self._agents[key]
                await agent.aclose()
        if admission is None:
            return
        opener = self._agent_opener
        for key, registration in wanted.items():
            if key in self._agents:
                continue
            if opener is not None:
                agent = await opener(
                    self._root, self._record, registration, admission, self._agent_dial()
                )
            else:
                agent = await open_helper_agent(
                    self._root,
                    self._record,
                    registration,
                    admission,
                    self._agent_dial(),
                    transport="connector" if self._style == "relay" else "ssh",
                    on_profile_changed=self._profile_changed,
                )
            if agent is not None:
                self._agents[key] = agent
                if self._last_upstream_use is None:
                    self._last_upstream_use = self._clock()

    def _follow_consent(self) -> tuple[ServerTarget | None, bool]:
        """Take the target's record as it is now: the record before it when the owner's consent
        changed (else ``None``), and whether the record was read now.

        Every background agent is opened under the record (its consent decides, among others,
        whether it answers the server's code-sync calls, ADR-054). A consent the owner changed
        under the same profile revision (``finishup server use NAME --level L2``, another
        retention, the same level confirmed again) ends no connection, so the agents opened
        before it would go on under the old one: an L1 agent declares no code-sync operation and
        every sync is refused until the helper restarts (defect A of the 2026-11-11 dogfood).
        ``target.json`` is read again only when its identity stamp moved (one ``lstat`` a tick).
        """

        from finishup.client.authorization import consent_digest
        from finishup.client.targets import read_target
        from finishup.config.paths import SERVER_TARGET_FILE_NAME

        try:
            facts = os.lstat(self._root / SERVER_TARGET_FILE_NAME)
        except OSError:
            return None, False
        stamp = (facts.st_ino, facts.st_size, facts.st_mtime_ns, facts.st_ctime_ns)
        if stamp == self._record_stamp:
            return None, False
        self._record_stamp = stamp
        try:
            current = read_target(self._root)
        except TargetError:
            return None, False
        if current is None or current.target_id != self._record.target_id:
            return None, False
        previous = self._record
        self._record = current
        changed = consent_digest(current) != consent_digest(previous)
        return (previous if changed else None), True

    async def _follow(self) -> None:
        """Follow the owner's consent (``_follow_consent``, ``_replace_agents``), then say which
        consent the agents follow now (``helper_status.write_followed_consent``), once each
        agent that declared less than it is closed: ``server use`` waits for that after a new
        level, so its command ends only once no such agent is left for the server to ask."""

        from finishup.client.authorization import consent_digest
        from finishup.client.helper_status import write_followed_consent

        previous, read = self._follow_consent()
        retired = True if previous is None else await self._replace_agents(previous)
        if read and retired:
            write_followed_consent(self._root, consent_digest(self._record))

    async def _replace_agents(self, previous: ServerTarget) -> bool:
        """Every agent opened under the earlier consent (``previous``'s) is replaced.

        The next agent sync opens each one again under the record now, for each workspace whose
        registration the new consent still serves (a registration made under the earlier one is
        renewed by its registrant: a command at its next run, an MCP bridge within seconds). The
        old agent keeps serving until its replacement is connected (``_close_replaced``), so work
        in flight on it finishes and the server is never without one, except when the new consent
        declares the code-sync operations the old agent does not (level L2 chosen): that agent
        closes now, since the server would ask it, and refuse the sync at once
        (``operation_not_declared``), while it waits for an agent when none is there. A workspace
        replaced again before that closes its oldest agent at once.
        """

        now = self._clock()
        widened = _declares_code_sync(self._record) and not _declares_code_sync(previous)
        closing: list[HelperAgent] = []
        for key, agent in self._agents.items():
            older = self._retiring.pop(key, None)
            if older is not None:
                self._spawn_close(older[0])
            if widened:
                closing.append(agent)
            else:
                self._retiring[key] = (agent, now)
        self._agents.clear()
        self._last_sync = None
        if not closing:
            return True
        # Gone from the server before the helper says it follows the new consent (``_follow``):
        # each agent closed, then every background agent's relay ended, since a relayed REST
        # stream unregisters its agent as it ends (no other agent runs now: a new level closes
        # them all, and the next sync opens their replacements). Bounded, so a close that hangs
        # never holds the tick; one that does not finish in time is not acknowledged, and
        # ``server use`` then stops the helper instead.
        try:
            async with asyncio.timeout(_CLOSE_SECONDS):
                closed = await asyncio.gather(
                    *(agent.aclose() for agent in closing), return_exceptions=True
                )
                relays = tuple(self._own_relays)
                if relays:
                    await asyncio.wait(relays)
        except TimeoutError:
            return False
        return not any(isinstance(result, BaseException) for result in closed)

    async def _close_replaced(self) -> None:
        """Close each replaced agent whose replacement is connected, is not wanted, or that
        waited its bound."""

        now = self._clock()
        for key, (agent, since) in tuple(self._retiring.items()):
            replacement = self._agents.get(key)
            if (
                replacement is None
                or replacement.client is not None
                or not agent.alive
                or now - since >= _RETIRE_SECONDS
            ):
                del self._retiring[key]
                with contextlib.suppress(Exception):
                    await agent.aclose()

    def _spawn_close(self, agent: HelperAgent) -> None:
        task = asyncio.create_task(agent.aclose())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _close_agents(self) -> None:
        agents = (*self._agents.values(), *(agent for agent, _since in self._retiring.values()))
        self._agents.clear()
        self._retiring.clear()
        for agent in agents:
            with contextlib.suppress(Exception):
                await agent.aclose()

    # -- drain and refresh --------------------------------------------------------------------------

    async def _drain(self) -> None:
        """Deliver what this computer captured, over each served workspace's agent."""

        self._last_drain = self._clock()
        if self._refuse_zero_network():
            return
        for agent in tuple(self._agents.values()):
            await agent.drain(may_send=self._may_send)

    def _refresh_due(self) -> bool:
        state = self._refresh
        now = self._clock()
        if state.task is not None and not state.task.done():
            return False
        if state.last is not None and now - state.last < _REFRESH_MIN_SECONDS:
            return False
        if take_profile_refresh_request(self._root):
            state.requested = True
        if state.requested:
            return True
        used = self._last_upstream_use
        return (
            state.last is not None
            and now - state.last >= self._refresh_interval
            and used is not None
            and now - used < self._refresh_interval
        )

    def _may_refresh_send(self) -> bool:
        """Asked before each request of a REST profile refresh: not stopping (nor the target's
        stop epoch moved, which the next tick would see), not zero-network, and gate steps 2 to 4
        (``_may_refresh``) still pass. The refresh itself also asks that the credential
        generation has not moved since it began (``_refresh_over_rest``)."""

        if self._stop.is_set() or self._zero_network():
            return False
        if read_helper_epoch(self._root) != self._epoch:
            return False
        return self._may_refresh()

    def _may_refresh(self) -> bool:
        """Gate steps 2 to 4 only: the refresh is how the consent catches up with the server."""

        from finishup.client import authorization
        from finishup.client.targets import read_target, require_current_authorization

        try:
            current = read_target(self._root)
            require_current_authorization(current)
        except TargetError:
            return False
        return current is not None and current.kind in authorization.OPEN_REMOTE_KINDS

    async def _run_refresh(self) -> None:
        state = self._refresh
        state.last = self._clock()
        state.requested = False
        if not self._may_refresh():
            return
        from finishup.client.targets import read_target

        try:
            current = read_target(self._root)
            if current is None:
                return
            await self._refresher(current)
        except Exception:  # noqa: BLE001 - the cached profile stays; the next due fetch retries
            return
        # A refreshed consent or revision: connections admitted before it end, and the next one
        # is admitted again.
        admission = self._admission
        if admission is not None and admission.refusal() is not None:
            self._lapse(admission)

    def _start_refresh(self) -> None:
        self._refresh.task = asyncio.create_task(self._run_refresh())
        self._tasks.add(self._refresh.task)
        self._refresh.task.add_done_callback(self._tasks.discard)

    # -- lifetime -------------------------------------------------------------------------------------

    def request_stop(self, reason: str = "stop_requested") -> None:
        if not self._stop.is_set():
            self._stop_reason = reason
        self._stop.set()

    def _idle(self) -> bool:
        idle = self._clock() - self._last_activity
        return (
            self._active == 0
            and self._served_count == 0
            and not self._agents
            and idle >= self._idle_seconds
        )

    async def step(self) -> bool:
        """One tick of the helper's watch; whether it is stopping.

        Zero-network first (a stop, at once); a moved stop epoch (a stop); then the admission (a
        lapse ends every relay and every agent; a consent changed without a lapse opens every
        agent again under it, make before break); the registrations when their folder changed or
        every 30 seconds; the drain and the profile refresh when due, each as its own task (the
        refresh under gate steps 2 to 4 only, so it also runs while the consent refuses the
        cached profile); the idle exit.
        """

        if self._stop.is_set() or self._refuse_zero_network():
            return True
        if read_helper_epoch(self._root) != self._epoch:
            # A stop (``server disconnect``, ``remove``, ``use <other>``, ``set --style``, a
            # replacement) moved the epoch: no signal is ever sent to a helper.
            self.request_stop("stop_requested")
            return True
        admission = self._admitted()
        if self._stop.is_set():
            return True
        if admission is None:
            await self._close_agents()
        else:
            await self._follow()
        now = self._clock()
        if self._registrations_changed() or (
            self._last_sync is None or now - self._last_sync >= _AGENT_SYNC_SECONDS
        ):
            await self._sync_agents()
        if self._retiring:
            await self._close_replaced()
        if self._agents or self._served_count:
            # A served registration is a client: the helper stays while one is live.
            self._last_activity = now
        if any(agent.client is not None for agent in self._agents.values()):
            # A live agent connection uses the upstream (in the direct style its frames never
            # pass the relay that counts them), so the periodic profile refresh stays due.
            self._last_upstream_use = now
        delivering = self._delivery is not None and not self._delivery.done()
        if not delivering and now - self._last_drain >= self._drain_interval:
            # Its own task: the tick keeps checking zero-network and idleness every second, and
            # a stop cancels the pass instead of waiting for it (A-ZN-DRAIN).
            self._delivery = asyncio.create_task(self._drain())
        # Not under the admission: the refresh is how a consent that no longer admits the cached
        # profile (an interrupted narrowing, a changed offer) catches up, so it asks only gate
        # steps 2 to 4 (``_may_refresh``), and is asked first so a marker waits while it refuses.
        if self._may_refresh() and self._refresh_due():
            self._start_refresh()
        if self._idle():
            self.request_stop("idle_timeout")
        return self._stop.is_set()

    async def _watch(self) -> None:
        while not self._stop.is_set():
            await self._tick()
            if await self.step():
                return

    async def serve(self, listener: UnixEndpointListener | None) -> str:
        """Serve until stopped or idle; return the closed reason the process stopped for."""

        self._write_status("starting", None)
        running: list[asyncio.Task[None]] = []
        if listener is not None:
            running.append(asyncio.create_task(self._accept(listener)))
        running.append(asyncio.create_task(self._watch()))
        if self._admitted() is not None and self._style == "direct":
            self._write_status("ready", None)
        if self._may_refresh():
            self._start_refresh()
        try:
            await self._stop.wait()
        finally:
            if self._delivery is not None:
                running.append(self._delivery)
            for task in (*running, *self._tasks):
                task.cancel()
            await asyncio.gather(*running, *self._tasks, return_exceptions=True)
            zero_network = self._stop_reason == _ZERO_NETWORK
            if not zero_network and self._stop_reason != "target_removed":
                with contextlib.suppress(TimeoutError):
                    async with asyncio.timeout(_SHUTDOWN_DRAIN_SECONDS):
                        await self._drain()
            if listener is not None:
                with contextlib.suppress(Exception):
                    await listener.aclose()
            # Background agents first, so none dials again while the relays are torn down.
            await self._close_agents()
            self._end_relays()
            await asyncio.gather(*tuple(self._relays), return_exceptions=True)
            with contextlib.suppress(Exception):
                if zero_network:
                    await self._upstream.zero_network()
                else:
                    await self._upstream.close()
            if self._stop_reason != "target_removed":
                self._write_status("stopped", self._stop_reason)
        return self._stop_reason


async def _bind(lock: HelperLock) -> UnixEndpointListener:
    try:
        return await bind_control_listener()
    except LocalControlTransportError as error:
        if error.reason != "endpoint_exists":
            raise
    # A previous helper left the endpoint behind; only the lock holder clears it.
    await remove_stale_endpoint(EndpointKind.CONTROL, lock)
    return await bind_control_listener()


async def run_helper_process(
    root: Path, record: ServerTarget, *, idle_seconds: float, epoch: str | None = None
) -> int:
    """The helper process body: lock, fence, bind (relay), serve, release. Exit 0 also when one
    runs, and when a stop came after its spawner read ``epoch`` (it serves nothing then)."""

    from finishup.protocol.schemas import schema_manifest_digest

    lock = HelperLock(root)
    digest = schema_manifest_digest()
    try:
        # Under the epoch fence: a client replacing the helper it saw (``supersede_helper``)
        # either sees this one holding the target and decides again, or moved the epoch first,
        # which fences this start below.
        with helper_start_fence(root):
            lock.acquire(version=__version__, schema_manifest_digest=digest)
            # Read once, right after the lock: a stop before this read fences this start, one
            # after it is seen on the first tick.
            current = read_helper_epoch(root)
    except HelperLockBusy:
        return 0
    except OSError:
        lock.release()
        return 20
    try:
        if epoch is not None and current != epoch:
            with contextlib.suppress(OSError):
                write_helper_status(
                    root,
                    new_status(
                        read_helper_status(root),
                        "stopped",
                        "stop_requested",
                        started_at=now_stamp(),
                        style=read_connection_style(root),
                    ),
                )
            return 0
        style = read_connection_style(root)
        listener = await _bind(lock) if style == "relay" else None
        helper = Helper(root, record, style=style, idle_seconds=idle_seconds, epoch=current)
        loop = asyncio.get_running_loop()
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            with contextlib.suppress(NotImplementedError, RuntimeError):
                loop.add_signal_handler(number, helper.request_stop)
        await helper.serve(listener)
        return 0
    except LocalControlTransportError:
        with contextlib.suppress(OSError):
            write_helper_status(
                root,
                new_status(
                    read_helper_status(root), "stopped", "helper_failed", started_at=now_stamp()
                ),
            )
        return 20
    finally:
        lock.release()


def run_helper(
    target_id: str, *, idle_seconds: float = HELPER_IDLE_SECONDS, epoch: str | None = None
) -> int:
    """``finishup helper run --target ID``: serve one remote target in the foreground.

    ``ID`` must name an SSH, HTTPS or ``local_port`` target in this computer's server registry. An isolation variable or
    runtime pin naming another root refuses (exit 2): the helper never serves a root its process
    would not resolve. Exit 0 when it stopped (or another helper already serves the target), 20
    when its endpoint could not be bound. ``epoch`` is the stop epoch its spawner read
    (``helper_status.spawn_helper``): a stop since then ends it before it serves anything.
    """

    from finishup.client.targets import read_target, target_root
    from finishup.config.paths import PathSafetyError, isolated_root, selection_override

    try:
        root = target_root(target_id)
        record = read_target(root)
        if (
            record is None
            or (record.kind != "ssh" and record.kind not in _REST_KINDS)
            or record.target_id != target_id
        ):
            return 2
        explicit = isolated_root()
    except (TargetError, PathSafetyError, ValueError):
        return 2
    if explicit is not None and explicit != root:
        return 2
    # Every path this process resolves is the target's own: its endpoint, its records, and the
    # outside reads its agents answer (bound to this target's claim salt).
    with selection_override(root):
        return asyncio.run(run_helper_process(root, record, idle_seconds=idle_seconds, epoch=epoch))
