"""What the real client reports when this installation's own service refuses its connection.

A service that is draining (a lock, a stop or a restart waiting on work in flight) or failed
accepts a connection and closes it at once, reading and answering nothing (#1481,
``test_control_connection_idle_bounds``). Before that close existed the refused connection stayed
open, the client waited out its five-second attempt and reported the retryable "accepted but
unresponsive" ``service_unavailable``; ``finishup service restart`` then waited for the singleton.

These tests drive the real client at a real daemon on its real socket and singleton stamp. They
pin that the client still ends there, without the wait, whichever of the close and the hello
comes first, and that every other unanswered hello keeps the classification it had: another
installation's holder, a holder whose stamp shows nothing, a stamp whose singleton lock nobody
holds (its holder exited and its pid was reused) beside a listener that is not that holder, and
a serving service that fails its own side of the handshake (#1040). A refusal that ends while the
client is asking about it (a lock that finishes draining) ends in a served connection.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import sys
import tempfile
from collections.abc import AsyncGenerator, Awaitable, Buffer, Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

import pytest

import finishup.cli.app as cli_app
import finishup.cli.bootstrap as cli_bootstrap
import finishup.mcp.server as bridge
import finishup.observability.diagnostics as diagnostics
import finishup.service.client as client_module
import finishup.service.daemon as daemon_module
from finishup import __version__
from finishup.adapters.control.unix_socket import (
    RUNTIME_DIRECTORY_MODE,
    AuthenticatedUnixStream,
    bind_control_listener,
    close_endpoint,
)
from finishup.adapters.repository_identity import RepositoryIdentityError
from finishup.cli.bootstrap import control_failure
from finishup.ports.control import (
    ControlClientKind,
    ControlError,
    RepositoryPrivacyContext,
    ServiceState,
    ServiceStatus,
    WorkspaceLocator,
)
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.schemas import schema_manifest_digest
from finishup.service.client import ServiceClient, connect_service, connect_service_on_demand
from finishup.service.daemon import ServiceComposition, ServiceDaemon
from finishup.service.lifecycle import ServiceLifecycle, probe_singleton_holder
from finishup.service.vault import VaultMode

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(
        not (sys.platform == "darwin" or sys.platform.startswith("linux")),
        reason="certified local peer APIs are macOS/Linux only",
    ),
]

_INSTANCE_ID = "svc_00000000-0000-4000-8000-000000001498"
_COMMITMENT = "sha256:" + "8" * 64
_FOREIGN_DIGEST = "sha256:" + "0" * 64
# Under the client's own five-second attempt: an answer that needs the silent wait this refusal
# used to cost fails here on the deadline.
_ANSWER_BOUND_SECONDS = 4.0

type _Order = Literal["hello_first", "close_first"]
type _Entry = Literal["bridge", "hook", "plain"]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Clock:
    def now_utc(self) -> datetime:
        return datetime(2026, 11, 24, tzinfo=UTC)

    def monotonic_seconds(self) -> float:
        return 10.0


class _GenerationStore:
    def advance(self, instance_id: str) -> int:
        assert instance_id == _INSTANCE_ID
        return 1


class _Capability:
    active = False


class _Monitor:
    capability = _Capability()

    async def start(self, callback: object) -> None:
        del callback

    async def close(self) -> None:
        return None


class _Vault:
    mode = VaultMode.OS_KEYRING
    generation = 1
    ready = True

    def installation_mac_handle(self, purpose: object) -> object:
        del purpose
        return object()

    async def lock(self) -> None:
        self.ready = False

    async def close(self) -> None:
        self.ready = False


class _Application:
    provider_credential_connected = False

    async def close(self) -> None:
        return None


class _ClientStream:
    """The client's end of one real connection; the first one reports its hello write."""

    def __init__(self, inner: AuthenticatedUnixStream, service: _Service, first: bool) -> None:
        self._inner = inner
        self._service = service
        self._first = first

    @property
    def peer_identity(self) -> object:
        return self._inner.peer_identity

    async def receive(self, max_bytes: int) -> bytes:
        return await self._inner.receive(max_bytes)

    async def send_all(self, data: Buffer) -> None:
        if not self._first:
            await self._inner.send_all(data)
            return
        if self._service.order == "close_first":
            # The daemon has finished with this connection before the hello is written.
            await self._service.first_handled.wait()
        try:
            await self._inner.send_all(data)
        finally:
            self._service.hello_written.set()

    async def aclose(self) -> None:
        await self._inner.aclose()


@dataclass
class _Service:
    """One real daemon on its real socket and stamp, and what the client did to it."""

    order: _Order
    lock_path: Path
    log_root: Path
    daemon: ServiceDaemon | None = None
    hello_written: asyncio.Event = field(default_factory=asyncio.Event)
    first_handled: asyncio.Event = field(default_factory=asyncio.Event)
    # Run by the daemon before it handles the second connection.
    before_second: Callable[[], Awaitable[None]] | None = None
    connections: int = 0
    handled: int = 0
    spawned: int = 0

    @property
    def lifecycle(self) -> ServiceLifecycle:
        assert self.daemon is not None
        return self.daemon.composition.lifecycle

    def records(self, component: str) -> list[dict[str, object]]:
        path = diagnostics.diagnostic_log_path(root=self.log_root)
        if not path.is_file():
            return []
        lines = path.read_text(encoding="ascii").splitlines()
        return [
            record
            for record in (json.loads(line) for line in lines if line)
            if record.get("component") == component
            and record.get("operation") == "control_handshake"
        ]

    def stamp(self, identity: dict[str, object] | None) -> None:
        """Replace the stamp's identity fields; the daemon keeps the flock on the same file."""

        if identity is None:
            self.lock_path.write_bytes(b"")
            return
        body = {"instance_id": _INSTANCE_ID, "pid": os.getpid(), **identity}
        self.lock_path.write_bytes(canonical_encode(cast(Any, body)) + b"\n")


@pytest.fixture
def runtime_directory(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Short in-tree socket directory: AF_UNIX paths bound under tmp_path are too long."""

    runtime = Path(tempfile.mkdtemp(prefix=".yctl-refuse-", dir=Path.cwd()))
    runtime.chmod(RUNTIME_DIRECTORY_MODE)
    monkeypatch.setattr(
        "finishup.adapters.control.unix_socket._runtime_directory",
        lambda: runtime,
    )
    try:
        yield runtime
    finally:
        shutil.rmtree(runtime)


def _instrument(
    service: _Service, monkeypatch: pytest.MonkeyPatch, *, spawn: Callable[[], object]
) -> None:
    """Point the client at this test's stamp and logs, and count its connections and spawns."""

    monkeypatch.setattr(diagnostics, "log_dir", lambda: service.log_root)
    monkeypatch.setattr(client_module, "_singleton_lock_path", lambda: service.lock_path)
    monkeypatch.setattr(client_module, "_system_git_below_minimum", lambda: False)
    # The CLI line names the stamped holder; this test's stamp, never the machine's own.
    monkeypatch.setattr(
        cli_bootstrap, "_singleton_holder_pid", lambda: probe_singleton_holder(service.lock_path)
    )

    async def must_not_supersede(**_kwargs: object) -> bool:
        raise AssertionError("this test's holder is the test process and is never signalled")

    monkeypatch.setattr(client_module, "_spawn_service_process", spawn)
    monkeypatch.setattr(client_module, "supersede_incompatible_service", must_not_supersede)

    real_connect = client_module.connect_control

    async def counted_connect() -> AuthenticatedUnixStream:
        inner = await real_connect()
        service.connections += 1
        return cast(
            AuthenticatedUnixStream, _ClientStream(inner, service, service.connections == 1)
        )

    monkeypatch.setattr(client_module, "connect_control", counted_connect)


@contextlib.asynccontextmanager
async def _running_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, order: _Order
) -> AsyncGenerator[_Service]:
    """A READY daemon whose first connection is ordered against the client's hello write.

    ``hello_first``: the daemon does not touch the first connection until the client's hello is
    in the socket. ``close_first``: the client does not write its hello until the daemon has
    finished with the connection. Later connections are not ordered.
    """

    log_root = tmp_path / "logs"
    log_root.mkdir()
    service = _Service(order=order, lock_path=tmp_path / "service.lock", log_root=log_root)

    def must_not_spawn() -> object:
        service.spawned += 1
        raise AssertionError("a second service must never be started beside a live holder")

    _instrument(service, monkeypatch, spawn=must_not_spawn)

    run_handler = ServiceDaemon._run_handler  # pyright: ignore[reportPrivateUsage]

    async def ordered_run_handler(
        self: ServiceDaemon, handler: Callable[[Any], Awaitable[None]], stream: Any
    ) -> None:
        service.handled += 1
        first = service.handled == 1
        if service.handled == 2 and service.before_second is not None:
            await service.before_second()
        if first and service.order == "hello_first":
            await service.hello_written.wait()
        try:
            await run_handler(self, handler, stream)
        finally:
            if first:
                service.first_handled.set()

    monkeypatch.setattr(ServiceDaemon, "_run_handler", ordered_run_handler)

    listener = await bind_control_listener()
    lifecycle = ServiceLifecycle(
        _Clock(),
        generation_store=_GenerationStore(),
        process_start_identity_commitment=_COMMITMENT,
        instance_id=_INSTANCE_ID,
        singleton_lock_path=service.lock_path,
    )
    daemon = ServiceDaemon(
        _composition=ServiceComposition(
            lifecycle=lifecycle,
            control_listener=listener,  # pyright: ignore[reportArgumentType]
            secret_ingress_listener=None,
            human_control_listener=None,
            human_control_service=None,
            session_monitor=_Monitor(),  # pyright: ignore[reportArgumentType]
            vault=_Vault(),  # pyright: ignore[reportArgumentType]
            application=_Application(),  # pyright: ignore[reportArgumentType]
        )
    )
    await daemon.start()
    assert lifecycle.state is ServiceState.READY
    service.daemon = daemon
    accept_task = asyncio.create_task(
        daemon._accept_loop(  # pyright: ignore[reportPrivateUsage]
            listener,  # pyright: ignore[reportArgumentType]
            daemon._serve_control_connection,  # pyright: ignore[reportPrivateUsage]
        )
    )
    try:
        yield service
        # The refusals and the client's extra connection left the accept loop serving.
        assert not accept_task.done()
    finally:
        accept_task.cancel()
        await asyncio.gather(accept_task, return_exceptions=True)
        await daemon.close()
        await close_endpoint(listener)  # pyright: ignore[reportArgumentType]


async def _attempt(entry: _Entry, locator: WorkspaceLocator | None) -> ServiceClient:
    """One real connection attempt through ``entry``, inside the answer bound."""

    async def attempt() -> ServiceClient:
        if entry == "bridge":
            # The MCP bridge: full start budget, allowed to supersede and to spawn.
            return await connect_service_on_demand(
                ControlClientKind.MCP_BRIDGE, workspace_locator=locator
            )
        if entry == "hook":
            # A consented hook: one second, primes an absent service, replaces nothing.
            return await connect_service_on_demand(
                ControlClientKind.CLI,
                workspace_locator=locator,
                timeout_seconds=1.0,
                supersede_incompatible=False,
            )
        # ``build_service_client``: every ordinary CLI command and ``service restart``.
        return await connect_service(ControlClientKind.CLI, workspace_locator=locator)

    return await asyncio.wait_for(attempt(), timeout=_ANSWER_BOUND_SECONDS)


async def _refused(entry: _Entry, locator: WorkspaceLocator | None) -> ControlError:
    """The error one real connection attempt ends with, inside the answer bound."""

    with pytest.raises(ControlError) as refused:
        await _attempt(entry, locator)
    return refused.value


def _classified(error: ControlError) -> tuple[str, bool, str | None, bool]:
    return (
        error.reason,
        error.retryable,
        error.phase,
        client_module.accepted_but_unresponsive(error),
    )


@pytest.mark.parametrize("refusing_state", [ServiceState.DRAINING, ServiceState.FAILED])
@pytest.mark.parametrize("order", ["hello_first", "close_first"])
@pytest.mark.parametrize("names_workspace", [False, True])
@pytest.mark.parametrize("entry", ["bridge", "hook", "plain"])
async def test_a_connection_its_own_service_refuses_is_retryable_at_once(
    runtime_directory: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    refusing_state: ServiceState,
    order: _Order,
    names_workspace: bool,
    entry: _Entry,
) -> None:
    """Draining or failed, hello or close first: retryable, no wait, no spawn, no retry loop."""

    del runtime_directory
    locator = WorkspaceLocator(os.fspath(tmp_path)) if names_workspace else None
    async with _running_service(tmp_path, monkeypatch, order) as service:
        await service.lifecycle.transition(refusing_state)

        error = await _refused(entry, locator)

        assert service.lifecycle.state is refusing_state
        # The retryable "accepted but unresponsive" result, as before the refusal closed the
        # connection: never the non-retryable failed handshake of a serving service.
        assert _classified(error) == ("service_unavailable", True, None, True)
        assert client_module.handshake_failure(error) is None
        assert service.spawned == 0
        # One attempt, not a poll: the hello, and when it named a workspace and was written,
        # one more hello that names none.
        asked_again = names_workspace and order == "hello_first"
        assert service.connections == (2 if asked_again else 1)
        assert service.handled == service.connections
        # A refusal is not a failed handshake: nothing is recorded as one on either side.
        assert service.records("service.client") == []
        assert service.records("service.daemon") == []

    # Every surface names a listening service to wait for, never a failed handshake.
    printed: list[str] = []
    assert control_failure(error, stderr_writer=printed.append) == 20
    assert printed[0].startswith("service_unavailable: a local service is listening but did not")
    assert "closed the connection" in printed[0]
    assert "service_handshake_failed" not in printed[0]
    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        error, request_id=None, operation="start"
    )
    public = cast(dict[str, Any], result.structuredContent)["error"]
    assert public["retryable"] is True
    assert public["safe_details"]["reason_code"] == "accepted_but_unresponsive"
    assert "closed the connection" in public["message"]


@pytest.mark.parametrize("entry", ["bridge", "hook", "plain"])
async def test_a_serving_service_that_fails_its_own_handshake_is_still_a_failed_handshake(
    runtime_directory: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entry: _Entry,
) -> None:
    """#1040: this installation's ready service closes a hello whose workspace it cannot resolve.

    It still answers a hello that names no workspace, so the close was not a refusal, and it
    closes the same hello sent once more: the client reports the non-retryable failed handshake
    and its diagnostic, exactly as before.
    """

    del runtime_directory

    async def failing_resolver(locator: WorkspaceLocator, key: object) -> RepositoryPrivacyContext:
        del locator, key
        raise RepositoryIdentityError("repository_identity_unavailable")

    monkeypatch.setattr(daemon_module, "resolve_repository_privacy_context", failing_resolver)
    async with _running_service(tmp_path, monkeypatch, "hello_first") as service:
        error = await _refused(entry, WorkspaceLocator(os.fspath(tmp_path)))

        assert service.lifecycle.state is ServiceState.READY
        assert _classified(error) == ("service_unavailable", False, "handshake", False)
        assert service.spawned == 0
        # The hello, one that names no workspace (answered), and the hello once more (closed
        # again): asked once, never polled.
        assert service.connections == 3
        (client_record,) = service.records("service.client")
        assert client_record["reason"] == "service_handshake_failed"
        assert client_record["correlation_id"] == error.correlation_id
        # The service failed the two handshakes that named the workspace, and recorded each.
        service_records = service.records("service.daemon")
        assert len(service_records) == 2
        for service_record in service_records:
            assert service_record["reason"] == "handshake_service_fault"
            assert service_record["reason_code"] == "repository_identity_unavailable"


@pytest.mark.parametrize("serving_state", [ServiceState.LOCKED, ServiceState.READY])
@pytest.mark.parametrize("entry", ["bridge", "hook", "plain"])
async def test_a_refusal_that_ends_while_the_client_asks_ends_in_a_served_connection(
    runtime_directory: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    serving_state: ServiceState,
    entry: _Entry,
) -> None:
    """A lock finishes draining after the service closed the hello and before it is asked again.

    The service answers the hello that names no workspace, so it is serving now. Its first close
    is not reported as a failed handshake: the client sends its own hello once more and is served.
    """

    del runtime_directory

    async def resolver(locator: WorkspaceLocator, key: object) -> RepositoryPrivacyContext:
        del locator, key
        return RepositoryPrivacyContext("hmac-sha256:" + "9" * 64, "directory")

    monkeypatch.setattr(daemon_module, "resolve_repository_privacy_context", resolver)
    async with _running_service(tmp_path, monkeypatch, "hello_first") as service:
        await service.lifecycle.transition(ServiceState.DRAINING)

        async def drained() -> None:
            # The lock's drain ends (DRAINING to LOCKED), and for READY the owner unlocks at once.
            await service.lifecycle.transition(ServiceState.LOCKED)
            if serving_state is ServiceState.READY:
                await service.lifecycle.transition(ServiceState.UNLOCKING)
                await service.lifecycle.transition(ServiceState.READY, vault_generation=1)

        service.before_second = drained

        client = await _attempt(entry, WorkspaceLocator(os.fspath(tmp_path)))
        try:
            assert service.lifecycle.state is serving_state
            # The refused hello, the hello that names no workspace, and the hello once more.
            assert service.connections == 3
            assert service.spawned == 0
            assert service.records("service.client") == []
            assert service.records("service.daemon") == []
            # The connection is served: its hello was answered by the service in that state.
            status = client.hello_service_status
            assert status is not None
            assert status.state is serving_state
        finally:
            await client.close()


@contextlib.asynccontextmanager
async def _listener_beside_a_stale_stamp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, order: _Order
) -> AsyncGenerator[_Service]:
    """A listener that is not the stamped holder, beside a stamp whose singleton lock is free.

    The stamp shows this installation's identity and a live pid (this test process, standing in
    for a pid reused after the holder that wrote it exited), and nobody holds the singleton lock.
    The listener closes every connection without answering: for the first, after the client's
    hello is written (``hello_first``) or before it is (``close_first``).
    """

    log_root = tmp_path / "logs"
    log_root.mkdir()
    service = _Service(order=order, lock_path=tmp_path / "service.lock", log_root=log_root)
    service.lock_path.touch(mode=0o600)
    service.stamp(
        {"schema_manifest_digest": schema_manifest_digest(), "service_version": __version__}
    )

    def spawn() -> object:
        # Starting the successor is how on-demand startup recovers from a stale stamp. Nothing is
        # started here; the failed start ends the attempt with the plain retryable result.
        service.spawned += 1
        raise OSError("not started by this test")

    _instrument(service, monkeypatch, spawn=spawn)
    listener = await bind_control_listener()

    async def close_each() -> None:
        while True:
            stream = await listener.accept()
            service.handled += 1
            first = service.handled == 1
            try:
                if first and order == "hello_first":
                    await service.hello_written.wait()
            finally:
                await stream.aclose()
                if first:
                    service.first_handled.set()

    closing = asyncio.create_task(close_each())
    try:
        yield service
    finally:
        closing.cancel()
        await asyncio.gather(closing, return_exceptions=True)
        await close_endpoint(listener)


@pytest.mark.parametrize("order", ["hello_first", "close_first"])
@pytest.mark.parametrize("names_workspace", [False, True])
@pytest.mark.parametrize("entry", ["bridge", "hook", "plain"])
async def test_a_stamp_whose_lock_nobody_holds_is_not_this_installation_refusing(
    runtime_directory: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    order: _Order,
    names_workspace: bool,
    entry: _Entry,
) -> None:
    """The stamp alone is not a live holder: the flock is. A free lock keeps today's results.

    An unanswered hello stays the non-retryable failed handshake, a failed hello write stays the
    plain retryable result, and on-demand startup still starts the successor.
    """

    del runtime_directory
    locator = WorkspaceLocator(os.fspath(tmp_path)) if names_workspace else None
    async with _listener_beside_a_stale_stamp(tmp_path, monkeypatch, order) as service:
        holder = client_module.service_holder_identity()
        assert holder is not None
        assert client_module._stamp_identity(holder) == "same"  # pyright: ignore[reportPrivateUsage]
        assert client_module._singleton_holder_lock_is_held() is False  # pyright: ignore[reportPrivateUsage]

        error = await _refused(entry, locator)

        # One connection: nothing more is asked of a listener the lock does not show as a holder.
        assert service.connections == 1
        if order == "hello_first":
            assert _classified(error) == ("service_unavailable", False, "handshake", False)
            assert service.spawned == 0
            (record,) = service.records("service.client")
            assert record["reason"] == "service_handshake_failed"
        else:
            assert _classified(error) == ("service_unavailable", True, None, False)
            assert service.spawned == (0 if entry == "plain" else 1)
            assert service.records("service.client") == []


@pytest.mark.parametrize(
    ("identity", "expected"),
    [
        # A validated field that differs shows another installation: its remedy is a restart.
        (
            {"schema_manifest_digest": _FOREIGN_DIGEST, "service_version": __version__},
            ("service_incompatible", True, None, False),
        ),
        (
            {"schema_manifest_digest": "own", "service_version": "0.0.1"},
            ("service_incompatible", True, None, False),
        ),
        # A stamp that shows nothing either way is never read as this installation refusing.
        ({}, ("service_unavailable", False, "handshake", False)),
        ({"service_version": __version__}, ("service_unavailable", False, "handshake", False)),
        (None, ("service_unavailable", False, "handshake", False)),
    ],
    ids=["other_digest", "other_version", "no_identity_keys", "digest_absent", "no_stamp"],
)
@pytest.mark.parametrize("order", ["hello_first", "close_first"])
async def test_a_holder_the_stamp_does_not_show_as_this_installation_keeps_its_classification(
    runtime_directory: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    identity: dict[str, object] | None,
    expected: tuple[str, bool, str | None, bool],
    order: _Order,
) -> None:
    """Only a stamp that shows this installation makes a closed connection a refusal."""

    del runtime_directory
    async with _running_service(tmp_path, monkeypatch, order) as service:
        await service.lifecycle.transition(ServiceState.DRAINING)
        if identity is not None and identity.get("schema_manifest_digest") == "own":
            identity = {**identity, "schema_manifest_digest": schema_manifest_digest()}
        service.stamp(identity)

        error = await _refused("plain", WorkspaceLocator(os.fspath(tmp_path)))

        if order == "close_first":
            # The hello write itself failed: the plain retryable transport result, as before.
            expected = ("service_unavailable", True, None, False)
        assert _classified(error) == expected
        # No second hello is spent on a holder that is not shown to be this installation.
        assert service.connections == 1


def _successor_status() -> ServiceStatus:
    return ServiceStatus(
        protocol_version="1.0",
        service_version=__version__,
        service_instance_id="svc_d8a497df-f110-4d87-89dd-8b0a45d9f980",
        service_generation="2",
        state=ServiceState.LOCKED,
        state_reason="none",
        vault_mode="uninitialized",
        capabilities=(),
        session_monitor="unavailable",
    )


class _Successor:
    async def service_status(self) -> ServiceStatus:
        return _successor_status()

    async def close(self) -> None:
        return None


@pytest.mark.parametrize("refusing_state", [ServiceState.DRAINING, ServiceState.FAILED])
@pytest.mark.parametrize("order", ["hello_first", "close_first"])
async def test_restart_waits_for_its_own_refusing_service_to_release_the_singleton(
    runtime_directory: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    refusing_state: ServiceState,
    order: _Order,
) -> None:
    """``finishup service restart`` waits for its own refusing service, then starts a successor.

    The holder cannot be asked to stop (it refuses the connection) and is never signalled (its
    stamp shows this installation). Restart goes on to wait for it to release the singleton, as
    it does for a service that accepted and stayed silent; it does not stop at a failed handshake.
    """

    del runtime_directory
    events: list[str] = []

    async def declines(
        *, deadline: float, replace_newer: bool = False, replace_legacy: bool = False
    ) -> bool:
        # What the real function answers for a holder stamped with this installation's identity.
        del deadline
        events.append(f"supersede:{replace_newer}:{replace_legacy}")
        return False

    async def released(pid: int, *, deadline: float) -> bool:
        del deadline
        events.append(f"released:{pid}")
        return True

    async def on_demand(kind: ControlClientKind, **kwargs: object) -> _Successor:
        del kind
        events.append(f"start:{kwargs.get('supersede_incompatible')}")
        return _Successor()

    async with _running_service(tmp_path, monkeypatch, order) as service:
        await service.lifecycle.transition(refusing_state)

        def holder_pid() -> int | None:
            return probe_singleton_holder(service.lock_path)

        monkeypatch.setattr(cli_app, "_singleton_holder_pid", holder_pid)
        monkeypatch.setattr(client_module, "supersede_incompatible_service", declines)
        monkeypatch.setattr(client_module, "wait_for_singleton_release", released)
        monkeypatch.setattr(client_module, "connect_service_on_demand", on_demand)

        exit_code = await asyncio.wait_for(
            cli_app._service_restart(False),  # pyright: ignore[reportPrivateUsage]
            timeout=_ANSWER_BOUND_SECONDS,
        )

        assert service.lifecycle.state is refusing_state
        assert service.connections == 1

    captured = capsys.readouterr()
    assert events == [f"released:{os.getpid()}", "start:False"], captured.err
    assert exit_code == 0
    assert "service_handshake_failed" not in captured.err
