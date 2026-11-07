"""Approach B (direct dial): nothing more reaches a server elsewhere once this computer is zero-network.

ADR-051 decision 8, maintainer decision of 2026-11-07: this computer's zero-network policy and a
server on another machine, a port or the web are never in force together. Every long-lived client
process of this topology reads what this computer last reported (``client.everyday_policy``)
before each connection and each delivery, and at least once a second while it holds a connection;
once that says zero-network it closes what it holds, delivers nothing more and names
``zero_network_remote_selected``, whose fix is ``finishup server use local``. The seams here:

* every remote ``ServiceClient`` connection (the MCP bridge's, the agents', the terminal
  interface's): before every frame, and once a second while open;
* the HTTPS binding stream below it (``https`` and ``local_port`` targets): before every request,
  its own long-polls included, and its closing ``DELETE`` is never sent;
* the connect seam (``service.client._control_transport``) and the transports below it;
* the MCP bridge's background agent and its observation drain (``BridgeBackgroundWork``);
* ``finishup server connect NAME --agent`` (``run_foreground_agent``);
* the SSH master, which cannot read the record itself: the runtime starts none, and the clients
  that find the record ask it to exit (``direct_runtime.close_ssh_masters``);
* the words every surface says for it (the CLI, the terminal interface, the hooks).
"""

from __future__ import annotations

import asyncio
import subprocess
import threading
import time
from collections.abc import Buffer, Iterator, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import httpx
import pytest

import finishup.client.everyday_policy as everyday_policy
from builders.direct_dial import (
    FakeBindingGateway,
    StaticCredential,
    https_target,
    memory_pair,
    service_status,
)
from builders.server_targets import ambient_home
from finishup.adapters.control.unix_socket import AuthenticatedUnixStream
from finishup.cli.zero_network_selection import (
    _close_held_connections as _REAL_CLOSE_HELD_CONNECTIONS,  # pyright: ignore[reportPrivateUsage]
)
from finishup.client import agent_session, direct_runtime, targets
from finishup.client.agent_session import (
    AgentSessionError,
    BridgeBackgroundWork,
    run_foreground_agent,
)
from finishup.client.https_binding import open_binding_stream
from finishup.client.target_runtime import TargetRuntimeError
from finishup.client.transports import (
    HttpsTransport,
    SshTransport,
    TransportError,
    start_remote_service,
)
from finishup.config.paths import active_root, reset_selection_memo
from finishup.ports.control import (
    ControlClientKind,
    ControlError,
    ControlMethod,
    ProjectionRenderMode,
    WorkspaceClaim,
    WorkspaceLocator,
)
from finishup.protocol.canonical import canonical_encode
from finishup.service import client as service_client
from finishup.service.client import ClientWorkspaceBinding
from finishup.service.control_protocol import (
    ControlSession,
    ControlStream,
    read_control_frame,
    server_handshake,
)

_AT = datetime(2026, 11, 7, 9, 30, tzinfo=UTC)
_PHASE = "zero_network_remote_selected"
_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000081"
_HANDLE = "client:0123456789abcdef"
_BINDING = ClientWorkspaceBinding(
    WorkspaceClaim("directory", "sha256:" + "2" * 64, "sha256:" + "3" * 64)
)
_SUMMARY = (
    "this computer's FinishUP is set to make no network connections, so nothing was sent to the "
    "selected FinishUP server"
)
# "Within about a second": the one-second read, plus room for a loaded test machine.
_CLOSE_BOUND_SECONDS = 2.5


def _zero_network() -> None:
    assert everyday_policy.record_reported_policy(zero_network=True, now=_AT)


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


def _ssh_target(name: str = "lab", *, select: bool = True) -> tuple[targets.ServerTarget, Path]:
    with targets.registry_lock():
        record, root = targets.new_remote_target(
            name, "ssh", host=f"{name}.example", port=22, remote_launcher="/opt/fu/bin/finishup"
        )
        if select:
            targets.write_selection(record)
    reset_selection_memo()
    return record, root


# --- every remote connection: before each frame, and once a second while it is open -----------


class _Stream:
    """A remote control stream that records what is sent and never answers."""

    def __init__(self) -> None:
        self.peer_identity = object()
        self.sent: list[bytes] = []
        self.wrote = asyncio.Event()
        self._closed = asyncio.Event()

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    async def receive(self, max_bytes: int) -> bytes:
        del max_bytes
        await self._closed.wait()
        return b""

    async def send_all(self, data: Buffer) -> None:
        self.sent.append(bytes(data))
        self.wrote.set()

    async def aclose(self) -> None:
        self._closed.set()


def _client(stream: _Stream, transport: str) -> service_client.ServiceClient:
    session = ControlSession(
        protocol_version="1.0",
        client_kind=ControlClientKind.CLI,
        service_instance_id=_SERVICE_ID,
        service_generation="1",
        allowed_methods=tuple(sorted(ControlMethod, key=lambda method: method.value.encode())),
        peer_identity=stream.peer_identity,
        connection_nonce="0" * 64,
        workspace_binding="local_path" if transport == "unix" else "client_claim",
        workspace_handle=None if transport == "unix" else _HANDLE,
    )
    factory = service_client._connected_client  # pyright: ignore[reportPrivateUsage]
    return factory(
        cast(AuthenticatedUnixStream, stream),
        session,
        ControlClientKind.CLI,
        transport=transport,  # pyright: ignore[reportArgumentType]
    )


@pytest.mark.parametrize("transport", ["ssh", "https"])
def test_a_held_remote_connection_closes_within_a_second_of_the_record(transport: str) -> None:
    async def exercise() -> tuple[float, ControlError, ControlError]:
        stream = _Stream()
        client = _client(stream, transport)
        # A call already under way, waiting for its answer.
        call = asyncio.create_task(client.service_status())
        await stream.wrote.wait()
        _zero_network()
        started = time.monotonic()
        await asyncio.wait_for(client.wait_closed(), timeout=_CLOSE_BOUND_SECONDS + 1.0)
        elapsed = time.monotonic() - started
        assert stream.closed
        with pytest.raises(ControlError) as pending:
            await call
        # A later call on the closed connection names the same refusal, and sends nothing.
        sent = len(stream.sent)
        with pytest.raises(ControlError) as later:
            await client.service_status()
        assert len(stream.sent) == sent
        return elapsed, pending.value, later.value

    elapsed, pending, later = asyncio.run(exercise())
    assert elapsed < _CLOSE_BOUND_SECONDS
    for error in (pending, later):
        assert (error.reason, error.phase, error.retryable) == ("service_unavailable", _PHASE, True)


def test_a_remote_connection_sends_no_frame_once_the_record_says_zero_network() -> None:
    async def exercise() -> tuple[ControlError, list[bytes], bool]:
        stream = _Stream()
        client = _client(stream, "ssh")
        _zero_network()
        # Read before every frame: the call is refused before its first byte is written.
        with pytest.raises(ControlError) as refused:
            await client.service_status()
        return refused.value, stream.sent, client.closed

    refused, sent, closed = asyncio.run(exercise())
    assert (refused.reason, refused.phase) == ("service_unavailable", _PHASE)
    assert sent == []
    assert closed


def test_a_local_connection_never_reads_the_record() -> None:
    async def exercise() -> list[bytes]:
        stream = _Stream()
        client = _client(stream, "unix")
        _zero_network()
        call = asyncio.create_task(client.service_status())
        await stream.wrote.wait()
        assert not client.closed
        await client.close()
        await asyncio.gather(call, return_exceptions=True)
        return stream.sent

    # This computer's own service is never a server elsewhere: its frames go out as before.
    assert asyncio.run(exercise()) != []


# --- the HTTPS binding below a remote connection: no request, and no closing DELETE ------------

_SID = "S" * 43


class _AgentGateway(httpx.AsyncBaseTransport):
    """A gateway stand-in: it opens one agent session and holds its first frames long-poll.

    It records every request it receives. The first ``GET …/frames`` waits for ``release`` and
    answers ``204`` (no frame yet); later ones stay unanswered, as a quiet server's would.
    """

    def __init__(self) -> None:
        self.requests: list[tuple[str, str]] = []
        self.polling = asyncio.Event()
        self.release = asyncio.Event()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append((request.method, request.url.path))
        if request.method == "POST":
            location = f"/base/v1/sessions/{_SID}"
            return httpx.Response(201, headers={"Location": location}, content=b"{}")
        if request.method == "GET":
            if not self.polling.is_set():
                self.polling.set()
                await self.release.wait()
                return httpx.Response(204)
            await asyncio.Event().wait()
        return httpx.Response(204)


@pytest.mark.parametrize("zero_network", [True, False])
def test_the_binding_starts_no_request_and_deletes_nothing_once_zero_network(
    zero_network: bool,
) -> None:
    """An agent session's own frames long-poll reads the record before each request: once it
    says zero-network the stream ends naming why, and closing it sends no ``DELETE`` (the
    gateway forgets a session whose polls stopped). Otherwise the close deletes the session."""

    gateway = _AgentGateway()

    async def exercise() -> tuple[list[tuple[str, str]], str | None]:
        stream = await open_binding_stream(
            https_target(), StaticCredential(), http_transport=gateway
        )
        # The stream reads only these two keys of a hello: a nonce, and that it declares an agent.
        hello = canonical_encode({"connection_nonce": "9a" * 32, "workspace_agent": {}})
        await stream.send_all(len(hello).to_bytes(4, "big") + hello)
        assert await stream.receive(4 + len(b"{}")) == b"\x00\x00\x00\x02{}"
        await gateway.polling.wait()  # its frames long-poll is on the wire
        if zero_network:
            _zero_network()
        sent = len(gateway.requests)
        if zero_network:
            gateway.release.set()
            # The long-poll answered; the next one is refused before it starts, ending the stream.
            assert await asyncio.wait_for(stream.receive(), timeout=5.0) == b""
        phase = await stream.failure_phase()
        await stream.aclose()
        return gateway.requests[sent:], phase

    after, phase = asyncio.run(exercise())
    if zero_network:
        assert after == []
        assert phase == _PHASE
    else:
        assert after == [("DELETE", f"/base/v1/sessions/{_SID}")]


class _HoldFirstResultPoll(httpx.AsyncBaseTransport):
    """Records every request, and holds the first ``GET …/results/…`` until ``release``."""

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self.inner = inner
        self.requests: list[tuple[str, str]] = []
        self.polling = asyncio.Event()
        self.release = asyncio.Event()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append((request.method, request.url.path))
        if request.method == "GET" and "/results/" in request.url.path:
            if not self.polling.is_set():
                self.polling.set()
                await self.release.wait()
        return await self.inner.handle_async_request(request)


async def _quiet_server(stream: ControlStream) -> None:
    """A service that completes the handshake and then never answers a call."""

    await server_handshake(stream, stream.peer_identity, service_status())
    while True:
        try:
            await read_control_frame(stream, eof_reason="session_closed")
        except Exception:
            return


def test_a_held_https_call_polls_no_more_and_deletes_nothing_once_zero_network() -> None:
    """A call whose result is long-polled: once the record says zero-network, no further poll and
    no closing ``DELETE`` reaches the server, and the call fails naming the refusal."""

    async def upstream() -> ControlStream:
        gateway_end, server_end = memory_pair()
        asyncio.get_running_loop().create_task(_quiet_server(server_end))
        return gateway_end

    gateway = FakeBindingGateway(upstream)
    wire = _HoldFirstResultPoll(httpx.ASGITransport(app=gateway))

    async def exercise() -> tuple[list[tuple[str, str]], ControlError]:
        transport = HttpsTransport(
            https_target(), Path("/nonexistent"), credential=StaticCredential(), http_transport=wire
        )
        connect = service_client._connect_service_attempt  # pyright: ignore[reportPrivateUsage]
        client = await connect(
            ControlClientKind.CLI,
            workspace_locator=None,
            projection_render_mode=ProjectionRenderMode.MACHINE_READABLE,
            output_is_controlling_tty=False,
            timeout_seconds=5.0,
            transport=transport,
        )
        call = asyncio.create_task(client.service_status())
        await wire.polling.wait()  # the call was posted, and its result is being polled
        _zero_network()
        sent = len(wire.requests)
        wire.release.set()
        await asyncio.wait_for(client.wait_closed(), timeout=_CLOSE_BOUND_SECONDS + 1.0)
        with pytest.raises(ControlError) as refused:
            await call
        return wire.requests[sent:], refused.value

    after, refused = asyncio.run(exercise())
    assert after == []
    assert (refused.reason, refused.phase, refused.retryable) == (
        "service_unavailable",
        _PHASE,
        True,
    )


# --- the connect seam and the transports below it -----------------------------------------------


@pytest.fixture
def nothing_dialled(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    dialled: list[str] = []

    async def ssh_open(_argv: Sequence[str]) -> object:
        dialled.append("ssh")
        raise AssertionError("never dialled")

    async def https_open(*_args: object, **_kwargs: object) -> object:
        dialled.append("https")
        raise AssertionError("never dialled")

    def refuse(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("a remote root never starts or supersedes a local service")

    monkeypatch.setattr("finishup.client.transports.SshControlStream.open", ssh_open)
    monkeypatch.setattr("finishup.client.https_binding.open_binding_stream", https_open)
    monkeypatch.setattr(service_client, "_spawn_service_process", refuse)
    monkeypatch.setattr(service_client, "supersede_incompatible_service", refuse)
    return dialled


@pytest.mark.parametrize("with_workspace", [True, False])
def test_a_process_whose_selection_predates_zero_network_dials_nothing(
    home: Path, nothing_dialled: list[str], with_workspace: bool
) -> None:
    _record, root = _ssh_target()
    assert active_root() == root
    # This computer was made zero-network and the owner switched in another terminal, which
    # reset only its own memo: this process still resolves the remote root.
    _zero_network()
    with targets.registry_lock():
        targets.selection_path().unlink()
    assert active_root() == root
    workspace = home / "repo"
    workspace.mkdir()
    locator = WorkspaceLocator(str(workspace.resolve())) if with_workspace else None

    async def exercise() -> None:
        for connect in (service_client.connect_service, service_client.connect_service_on_demand):
            with pytest.raises(ControlError) as refused:
                await connect(ControlClientKind.CLI, workspace_locator=locator)
            error = refused.value
            assert (error.reason, error.phase, error.retryable) == (
                "service_unavailable",
                _PHASE,
                True,
            )

    asyncio.run(exercise())
    assert nothing_dialled == []
    assert not (root / "run" / "m").exists()


def test_the_transports_dial_nothing_and_start_no_remote_service(
    home: Path, nothing_dialled: list[str]
) -> None:
    ssh_record, ssh_root = _ssh_target()
    with targets.registry_lock():
        https_record, https_root = targets.new_remote_target(
            "web", "https", base_url="https://web.example"
        )
    _zero_network()

    async def exercise() -> list[str]:
        phases: list[str] = []
        for transport in (
            SshTransport(ssh_record, ssh_root),
            HttpsTransport(https_record, https_root),
        ):
            with pytest.raises(TransportError) as refused:
                await transport.connect()
            phases.append(refused.value.phase)
        with pytest.raises(TransportError) as refused:
            await start_remote_service(SshTransport(ssh_record, ssh_root), 5.0)
        phases.append(refused.value.phase)
        return phases

    assert asyncio.run(exercise()) == [_PHASE, _PHASE, _PHASE]
    assert nothing_dialled == []


# --- the SSH master ------------------------------------------------------------------------------


class _Runner:
    """Records each ``ssh`` argv the runtime runs; every run succeeds."""

    def __init__(self) -> None:
        self.argvs: list[list[str]] = []

    def __call__(self, argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        self.argvs.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, b"", b"")


def test_no_ssh_master_is_started_and_no_key_check_sent_while_zero_network(home: Path) -> None:
    _record, ssh_root = _ssh_target()
    with targets.registry_lock():
        _https, https_root = targets.new_remote_target(
            "web", "https", base_url="https://web.example"
        )
    _zero_network()
    runner = _Runner()

    with pytest.raises(TargetRuntimeError) as ssh_refused:
        direct_runtime.SshTargetRuntime(runner=runner).ensure_ready(ssh_root)
    with pytest.raises(TargetRuntimeError) as https_refused:
        direct_runtime.HttpsTargetRuntime().ensure_ready(https_root)

    for refused in (ssh_refused.value, https_refused.value):
        assert (refused.reason, refused.phase) == ("service_unavailable", _PHASE)
    assert runner.argvs == []
    assert not (ssh_root / "run" / "m").exists()


def test_every_ssh_master_this_client_holds_is_asked_to_exit(home: Path) -> None:
    first, first_root = _ssh_target("lab")
    second, second_root = _ssh_target("lab2", select=False)
    idle, _idle_root = _ssh_target("idle", select=False)
    with targets.registry_lock():
        _web, web_root = targets.new_remote_target("web", "https", base_url="https://web.example")
    for root in (first_root, second_root, web_root):
        (root / "run").mkdir(mode=0o700, exist_ok=True)
        (root / "run" / "m").touch(mode=0o600)
    runner = _Runner()
    runtime = direct_runtime.SshTargetRuntime(runner=runner)

    closed = direct_runtime.close_ssh_masters(runtime=runtime)

    # Only the SSH targets whose master socket exists, each by its own control path; the HTTPS
    # target holds no client process, and a target without a master is left alone.
    assert sorted(closed) == sorted((first.target_id, second.target_id))
    assert idle.target_id not in closed
    assert len(runner.argvs) == 2
    for argv in runner.argvs:
        assert argv[argv.index("-O") + 1] == "exit"
        assert any(argv[index - 1] == "-S" for index, _word in enumerate(argv) if index)
    assert direct_runtime.close_ssh_masters((first_root,), runtime=runtime) == (first.target_id,)


def test_recording_zero_network_here_asks_every_ssh_master_to_exit(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.cli import zero_network_selection as zero_network

    closes: list[tuple[Path, ...] | None] = []

    def close(roots: Sequence[Path] | None = None, **_kwargs: object) -> tuple[str, ...]:
        closes.append(None if roots is None else tuple(roots))
        return ()

    # The suite's stand-in keeps this step away from a real registry; the real step runs here,
    # in an ambient home of its own, with the masters' exit recorded instead of run.
    monkeypatch.setattr(zero_network, "_close_held_connections", _REAL_CLOSE_HELD_CONNECTIONS)
    monkeypatch.setattr(direct_runtime, "close_ssh_masters", close)

    def answer(egress: bool) -> dict[str, object]:
        policy = {"effective_scope": {"kind": "machine"}, "network_egress_permitted": egress}
        return {"policy": policy}

    assert zero_network.remember_reported_policy(answer(True)) is True
    assert closes == []
    assert zero_network.remember_reported_policy(answer(False)) is True
    assert closes == [None]


# --- the MCP bridge's background agent and its observation drain --------------------------------


class _Connection:
    """An agent connection double the server can close and the owner can close."""

    def __init__(self) -> None:
        self.workspace_handle: str | None = _HANDLE
        self._ended = asyncio.Event()
        self.closed_by_owner = False

    @property
    def closed(self) -> bool:
        return self._ended.is_set()

    async def wait_closed(self) -> None:
        await self._ended.wait()

    async def close(self) -> None:
        self.closed_by_owner = True
        self._ended.set()


class _Closed(list[tuple[Path, ...]]):
    """The roots whose SSH master a client asked to exit; ``asked`` is set at the first."""

    def __init__(self) -> None:
        super().__init__()
        self.asked = threading.Event()


@pytest.fixture
def masters_closed(monkeypatch: pytest.MonkeyPatch) -> _Closed:
    closed = _Closed()

    def close(roots: Sequence[Path] | None = None, **_kwargs: object) -> tuple[str, ...]:
        assert roots is not None, "a client closes only its own target's master"
        closed.append(tuple(roots))
        closed.asked.set()
        return ()

    monkeypatch.setattr(direct_runtime, "close_ssh_masters", close)
    return closed


def _background(
    dialled: list[_Connection], *, pending: bool, root: Path | None = None
) -> BridgeBackgroundWork:
    async def bind(_workspace: WorkspaceLocator) -> ClientWorkspaceBinding:
        return _BINDING

    async def dial(_binding: ClientWorkspaceBinding) -> _Connection:
        connection = _Connection()
        dialled.append(connection)
        return connection

    work = BridgeBackgroundWork(
        lease_seconds=600.0,
        drain_interval=30.0,
        connect=dial,
        binding_for=bind,
        pending=lambda _workspace: pending,
        root=root,
    )
    work.note_activity(WorkspaceLocator("/w/repo"))
    return work


def test_the_background_work_dials_nothing_while_zero_network(
    home: Path, masters_closed: _Closed
) -> None:
    _record, root = _ssh_target(select=False)
    dialled: list[_Connection] = []
    work = _background(dialled, pending=True, root=root)
    _zero_network()

    async def exercise() -> list[object]:
        passes = [await work.run_pass(), await work.run_pass()]
        # Read before every connection, not only at the start of a pass.
        held = await work._ensure_connection(WorkspaceLocator("/w/repo"))  # pyright: ignore[reportPrivateUsage]
        await work.aclose()
        return [*passes, held]

    first, second, held = asyncio.run(exercise())
    for item in (first, second):
        assert (item.connected, item.drained, item.refused) == (False, None, _PHASE)  # type: ignore[attr-defined]
    assert held is None
    assert dialled == []
    # The target's SSH master is asked to exit once for the change, not on every pass.
    assert masters_closed == [(root,)]


def test_a_held_background_connection_closes_within_a_second_and_delivers_nothing(
    home: Path, monkeypatch: pytest.MonkeyPatch, masters_closed: _Closed
) -> None:
    from finishup.client import observation_outbox

    drains: list[str] = []

    class _Drain:
        def __init__(self, _workspace: WorkspaceLocator) -> None:
            pass

        async def drain(self, _connection: object) -> object:
            drains.append("drain")
            return observation_outbox.ClientDrainSummary(delivery=None)  # type: ignore[call-arg]

        def close(self) -> None:
            pass

    monkeypatch.setattr(observation_outbox, "ClientObservationDrain", _Drain)
    dialled: list[_Connection] = []
    # Nothing waits, so the pass only keeps the connection for the lease.
    _record, root = _ssh_target(select=False)
    work = _background(dialled, pending=False, root=root)

    async def exercise() -> float:
        loop = asyncio.create_task(work.run())
        while not dialled:
            await asyncio.sleep(0)
        held = dialled[0]
        _zero_network()
        started = time.monotonic()
        await asyncio.wait_for(held.wait_closed(), timeout=_CLOSE_BOUND_SECONDS + 1.0)
        elapsed = time.monotonic() - started
        # No last delivery: the drain over the closed connection never ran.
        assert drains == []
        # The master is asked to exit off the event loop, right after the connection closed.
        assert await asyncio.to_thread(masters_closed.asked.wait, _CLOSE_BOUND_SECONDS)
        loop.cancel()
        await asyncio.gather(loop, return_exceptions=True)
        return elapsed

    assert asyncio.run(exercise()) < _CLOSE_BOUND_SECONDS
    assert dialled[0].closed_by_owner
    assert len(dialled) == 1
    assert masters_closed == [(root,)]


def test_captured_rows_are_never_delivered_while_zero_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.client import observation_outbox

    def never(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("nothing is delivered")

    monkeypatch.setattr(observation_outbox, "ClientObservationDrain", never)
    work = _background([], pending=True)
    connection = _Connection()
    _zero_network()

    async def exercise() -> object:
        # Read before every delivery: what hooks captured stays in this client's store.
        return await work._drain_over(WorkspaceLocator("/w/repo"), connection)  # pyright: ignore[reportPrivateUsage]

    assert asyncio.run(exercise()) is None


def test_the_background_work_serves_again_once_the_record_permits_it(
    masters_closed: _Closed,
) -> None:
    dialled: list[_Connection] = []
    work = _background(dialled, pending=False)
    _zero_network()

    async def exercise() -> list[bool]:
        refused = await work.run_pass()
        assert everyday_policy.record_reported_policy(zero_network=False, now=_AT)
        served = await work.run_pass()
        await work.aclose()
        return [refused.connected, served.connected]

    # The bridge's own calls go through again then too; nothing is held in between.
    assert asyncio.run(exercise()) == [False, True]
    assert len(dialled) == 1
    assert masters_closed == []  # no root: nothing to ask


# --- 'finishup server connect NAME --agent' -------------------------------------------------------


@pytest.fixture
def remote_root(home: Path) -> Path:
    del home
    _record, root = _ssh_target()
    return root


def test_the_foreground_agent_dials_nothing_while_zero_network(
    remote_root: Path, masters_closed: _Closed
) -> None:
    dialled: list[_Connection] = []

    async def bind(_workspace: WorkspaceLocator) -> ClientWorkspaceBinding:
        return _BINDING

    async def dial(_binding: ClientWorkspaceBinding) -> _Connection:
        dialled.append(_Connection())
        return dialled[-1]

    _zero_network()
    with pytest.raises(AgentSessionError) as refused:
        asyncio.run(
            run_foreground_agent(
                remote_root, WorkspaceLocator("/w/repo"), connect=dial, binding_for=bind
            )
        )

    assert (refused.value.reason, refused.value.phase) == ("service_unavailable", _PHASE)
    assert dialled == []
    assert masters_closed == [(remote_root,)]


def test_the_foreground_agents_held_connection_closes_within_a_second(
    remote_root: Path, masters_closed: _Closed
) -> None:
    dialled: list[_Connection] = []

    async def bind(_workspace: WorkspaceLocator) -> ClientWorkspaceBinding:
        return _BINDING

    async def dial(_binding: ClientWorkspaceBinding) -> _Connection:
        dialled.append(_Connection())
        return dialled[-1]

    async def exercise() -> tuple[float, AgentSessionError]:
        agent = asyncio.create_task(
            run_foreground_agent(
                remote_root, WorkspaceLocator("/w/repo"), connect=dial, binding_for=bind
            )
        )
        while not dialled:
            await asyncio.sleep(0)
        _zero_network()
        started = time.monotonic()
        with pytest.raises(AgentSessionError) as refused:
            await asyncio.wait_for(agent, timeout=_CLOSE_BOUND_SECONDS + 1.0)
        return time.monotonic() - started, refused.value

    elapsed, refused = asyncio.run(exercise())
    assert elapsed < _CLOSE_BOUND_SECONDS
    assert (refused.reason, refused.phase) == ("service_unavailable", _PHASE)
    # Closed by the agent itself, never dialled again.
    assert [connection.closed_by_owner for connection in dialled] == [True]
    assert masters_closed == [(remote_root,)]


def test_the_foreground_agent_ends_at_once_on_a_zero_network_refusal_after_serving(
    remote_root: Path, masters_closed: _Closed
) -> None:
    dialled: list[_Connection] = []
    sleeps: list[float] = []

    async def bind(_workspace: WorkspaceLocator) -> ClientWorkspaceBinding:
        return _BINDING

    async def dial(_binding: ClientWorkspaceBinding) -> _Connection:
        if dialled:
            # The connect seam read the record first: refused, retryable like any remote phase.
            raise ControlError("service_unavailable", retryable=True, phase=_PHASE)
        dialled.append(_Connection())
        dialled[-1]._ended.set()  # pyright: ignore[reportPrivateUsage]  (the server closed it)
        return dialled[-1]

    async def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        if len(sleeps) > 3:
            raise AssertionError("the agent kept dialling a refused target")

    with pytest.raises(AgentSessionError) as refused:
        asyncio.run(
            run_foreground_agent(
                remote_root,
                WorkspaceLocator("/w/repo"),
                connect=dial,
                binding_for=bind,
                sleep=sleep,
            )
        )

    # Never a retry loop against a refusal only the owner can lift.
    assert (refused.value.reason, refused.value.phase) == ("service_unavailable", _PHASE)
    assert len(sleeps) == 1  # the back-off after the server's own close only
    assert masters_closed == [(remote_root,)]


@pytest.mark.parametrize("selected", [True, False])
def test_server_connect_agent_says_what_closed_and_the_fix_for_that_server(
    home: Path, monkeypatch: pytest.MonkeyPatch, selected: bool
) -> None:
    from typer.testing import CliRunner

    from finishup.cli import app as cli

    record, _root = _ssh_target(select=selected)

    async def stopped(_root: Path, _locator: WorkspaceLocator) -> None:
        _zero_network()
        raise AgentSessionError("service_unavailable", phase=_PHASE)

    monkeypatch.setattr(agent_session, "run_foreground_agent", stopped)

    def ready(_self: object, _root: Path | None) -> None:
        return None

    monkeypatch.setattr("finishup.client.direct_runtime.SshTargetRuntime.ensure_ready", ready)
    monkeypatch.chdir(home)

    result = CliRunner().invoke(cli.app, ["server", "connect", "lab", "--agent"])

    assert result.exit_code == 2, result.output
    assert (
        f"Closed the workspace agent's connection to server target {record.target_id} (ssh)."
    ) in result.stderr
    # The fix for the server it served: switching for the selected one; for one nothing uses,
    # this computer's own policy (switching would change nothing).
    if selected:
        assert f"{_PHASE}: " in result.stderr
        assert "'finishup server use local'" in result.stderr
    else:
        assert "zero_network_in_force: " in result.stderr
        assert "'finishup privacy setup'" in result.stderr


# --- what every surface says --------------------------------------------------------------------


def test_the_cli_terminal_interface_and_hooks_say_why_and_the_one_fix(home: Path) -> None:
    from finishup.cli.bootstrap import control_failure
    from finishup.cli.hooks import StatusOutcome, unavailable_context
    from finishup.protocol.recovery import RECOVERY_DIRECTIVES
    from finishup.tui.runtime import _connect_failure  # pyright: ignore[reportPrivateUsage]

    _ssh_target()
    error = ControlError("service_unavailable", retryable=True, phase=_PHASE)
    directive = RECOVERY_DIRECTIVES["zero_network_local_server_required"]

    lines: list[str] = []
    control_failure(error, stderr_writer=lines.append)
    text = "\n".join(lines)
    assert text.splitlines()[0] == f"service_unavailable: {_PHASE}: {_SUMMARY}"
    assert directive.directive in text
    assert "could not be reached" not in text

    failure = _connect_failure(error)
    assert (failure.reason, failure.message) == (_PHASE, _SUMMARY)
    assert failure.details == (directive.directive,)

    context = unavailable_context(StatusOutcome("unavailable", remote_reason=_PHASE))
    assert context.startswith(
        "FinishUP refused the selected server's connection before anything was sent "
        f"({_PHASE}). {directive.directive}"
    )
    assert context.endswith(" Continuation: zero_network_local_server_required.")
    assert "could not serve" not in context
