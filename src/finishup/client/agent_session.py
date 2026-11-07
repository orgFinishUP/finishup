"""Where a direct-dial client answers its server's workspace calls (ADR-051, approach B).

In approach B the workspace agent runs inside the client processes themselves; there is no relay
or agent daemon on the client machine:

* **Per connection.** A process whose calls need the workspace while they run (a CLI workflow
  command, the terminal interface, the MCP bridge) connects with
  ``service.client.serving_workspace_binding``: its hello claims the workspace and offers the
  agent, and ``ServiceClient`` answers the server's ``workspace_call`` frames on that same
  connection. Short-lived processes (hooks) are claim-bound without an agent.
* **Background work.** Work that outlives a call (a semantic review after ``check`` returned,
  the verification of a row a hook delivered) needs an agent connection while no call runs. The
  MCP bridge, the long-lived client process of this approach, holds one
  (``BridgeBackgroundWork``): a claim-bound agent connection kept while the session is active
  and released ``AGENT_LEASE_SECONDS`` after its last activity, so the server's idle relock and
  idle stop still apply. Over that connection it delivers what hooks captured under the remote
  root and could not deliver themselves (the observation outbox and the legacy spool), with the
  shared ``ClientObservationDrain``.
* **CLI-only use.** ``finishup server connect NAME --agent`` keeps one agent connection to that
  target open in the foreground until interrupted (``run_foreground_agent``), for an owner who
  runs no MCP bridge.

The bridge's background connection never asks for a remote service to be started: it dials
without the on-demand start, so over SSH a stopped service stays stopped (an HTTPS gateway starts
its own service for any session it opens, as it does for every client). Failures are closed
reasons; no path, host or server text appears in an error or a log.

**Zero-network** (ADR-051 decision 8, maintainer decision of 2026-11-07). This computer's
zero-network policy and a server elsewhere are never in force together. Both long-lived loops here
read what this computer last reported (``client.everyday_policy``, a file read) before every
connection and every delivery, and at least once a second while they run. Once it says
zero-network they close the agent connection they hold, deliver nothing more (no last delivery of
captured observations), ask the target's SSH master to exit (``direct_runtime.close_ssh_masters``)
and name ``zero_network_remote_selected``, whose remedy is ``finishup server use local``: the
bridge's background work stays idle until the record says otherwise, and the foreground agent ends
with that reason.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, NoReturn, Protocol, cast

from finishup.ports.control import ControlClientKind, ControlError, WorkspaceLocator

if TYPE_CHECKING:
    from finishup.client.observation_outbox import (
        ClientDrainSummary,
        ClientObservationDrain,
        ObservationIngestClient,
    )
    from finishup.service.client import ClientWorkspaceBinding

__all__ = [
    "AGENT_LEASE_SECONDS",
    "DRAIN_INTERVAL_SECONDS",
    "ZERO_NETWORK_CHECK_SECONDS",
    "AgentConnection",
    "AgentSessionError",
    "BackgroundPass",
    "BridgeBackgroundWork",
    "capture_pending",
    "run_foreground_agent",
    "start_remote_background_work",
]

# The bridge keeps its background agent connection this long after its last activity (a tool
# call, or rows its drain delivered): the lease approach A's connector keeps too.
AGENT_LEASE_SECONDS: Final = 900.0
# How often the bridge looks for captured rows to deliver while nothing wakes it sooner.
DRAIN_INTERVAL_SECONDS: Final = 30.0
# Waits between reconnect attempts of a background or foreground agent connection.
_RECONNECT_BACKOFF_SECONDS: Final = (1.0, 2.0, 5.0, 15.0, 30.0)
# A connection that closes sooner than this (a draining server, an idle stop, a refusal after the
# hello) counts like a failed dial: the next dial waits its back-off instead of looping at once.
_STABLE_CONNECTION_SECONDS: Final = 10.0
# A held agent connection reads this computer's last reported policy at least this often.
ZERO_NETWORK_CHECK_SECONDS: Final = 1.0
_ZERO_NETWORK: Final = "zero_network_remote_selected"
# The bridge's target was removed (``server remove``): its background work stops for good.
_TARGET_REMOVED: Final = "target_removed"
_COMPONENT: Final = "client.agent_session"


class AgentSessionError(Exception):
    """A foreground agent could not serve: one closed reason and an optional closed phase."""

    __slots__ = ("phase", "reason")

    reason: str
    phase: str | None

    def __init__(self, reason: str, *, phase: str | None = None) -> None:
        self.reason = reason
        self.phase = phase
        super().__init__(reason if phase is None else f"{reason}:{phase}")


class AgentConnection(Protocol):
    """What the agent loops need of a connection; ``ServiceClient`` is the production one."""

    @property
    def closed(self) -> bool: ...

    @property
    def workspace_handle(self) -> str | None: ...

    async def wait_closed(self) -> None: ...

    async def close(self) -> None: ...


type AgentConnector = Callable[[ClientWorkspaceBinding], Awaitable[AgentConnection]]
type BindingFactory = Callable[[WorkspaceLocator], Awaitable[ClientWorkspaceBinding | None]]
type PendingProbe = Callable[[WorkspaceLocator], bool]


def _backoff(attempt: int) -> float:
    return _RECONNECT_BACKOFF_SECONDS[min(attempt, len(_RECONNECT_BACKOFF_SECONDS) - 1)]


def _record(operation: str, reason: str) -> None:
    from finishup.observability.logging import record_bounded_event_without_raising

    record_bounded_event_without_raising(component=_COMPONENT, operation=operation, reason=reason)


def _zero_network_reported() -> bool:
    """Whether this computer last reported a zero-network policy (a file read, never a service)."""

    from finishup.client.everyday_policy import last_reported_zero_network

    return last_reported_zero_network() is not None


async def _close_master(root: Path | None) -> None:
    """Ask ``root``'s SSH master to exit, off the event loop; nothing for any other kind."""

    if root is None:
        return
    from finishup.client.direct_runtime import close_ssh_masters

    await asyncio.to_thread(close_ssh_masters, (root,))


async def _hold(connection: AgentConnection, check_seconds: float) -> bool:
    """Wait until ``connection`` closes; ``True`` when this computer turned zero-network first.

    The record is read every ``check_seconds`` while the connection is held. The wait is
    cancelled, never the connection: the caller closes it.
    """

    waiter = asyncio.ensure_future(connection.wait_closed())
    try:
        while True:
            done, _pending = await asyncio.wait((waiter,), timeout=check_seconds)
            if done:
                return False
            if _zero_network_reported():
                return True
    finally:
        if not waiter.done():
            waiter.cancel()
        await asyncio.gather(waiter, return_exceptions=True)


async def _serving_binding(workspace: WorkspaceLocator) -> ClientWorkspaceBinding | None:
    from finishup.service.client import serving_workspace_binding

    return await serving_workspace_binding(workspace)


# -- the foreground agent (``finishup server connect NAME --agent``) ------------------------------


async def _connect_on_demand(binding: ClientWorkspaceBinding) -> AgentConnection:
    from finishup.service.client import connect_service_on_demand

    return await connect_service_on_demand(ControlClientKind.CLI, workspace_binding=binding)


async def run_foreground_agent(
    root: Path,
    workspace_locator: WorkspaceLocator,
    *,
    connect: AgentConnector | None = None,
    binding_for: BindingFactory | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    zero_network_check: float = ZERO_NETWORK_CHECK_SECONDS,
) -> None:
    """Serve this workspace's calls on one connection to the target at ``root`` until cancelled.

    ``finishup server connect NAME --agent`` runs this in the foreground, for owners who drive a
    remote target from the CLI only (no MCP bridge holds a connection for background work). The
    target is resolved as ``root`` for this block, whatever this process's selection names. When
    the server closes the connection (its idle bound, a restart) it is opened again after a short
    back-off, so while this runs the server counts it as a connected client.

    Raises ``AgentSessionError``: ``agent_not_applicable`` for a root that is not a remote target,
    ``workspace_agent_unavailable`` when the server bound no workspace handle (its vault is
    locked, say), or a closed control reason and remote phase: any failure of the first
    connection, and a non-retryable failure of a later one. ``service_unavailable`` with phase
    ``zero_network_remote_selected`` once this computer last reported a zero-network policy,
    read before every connection and every ``zero_network_check`` seconds while one is held: the
    connection is closed first, and the target's SSH master asked to exit (ADR-051 decision 8).
    """

    from finishup.config.paths import selection_override

    dial = connect if connect is not None else _connect_on_demand
    bind = binding_for if binding_for is not None else _serving_binding
    with selection_override(root):
        try:
            binding = await bind(workspace_locator)
        except ControlError as error:
            raise AgentSessionError(error.reason, phase=error.phase) from None
        if binding is None:
            raise AgentSessionError("agent_not_applicable")
        attempt = 0
        served = False
        while True:
            if _zero_network_reported():
                await _refuse_zero_network(root)
            try:
                connection = await dial(binding)
            except ControlError as error:
                if error.phase == _ZERO_NETWORK:
                    await _refuse_zero_network(root)
                if not served or not error.retryable:
                    raise AgentSessionError(error.reason, phase=error.phase) from None
                _record("foreground_agent", error.phase or error.reason)
                await sleep(_backoff(attempt))
                attempt += 1
                continue
            try:
                if connection.workspace_handle is None:
                    # The server derived no handle (its vault is locked, say): no call names us.
                    raise AgentSessionError("workspace_agent_unavailable")
                served = True
                opened = clock()
                zero_network = await _hold(connection, zero_network_check)
            finally:
                await connection.close()
            if zero_network:
                await _refuse_zero_network(root)
            _record("foreground_agent", "reconnecting")
            if clock() - opened < _STABLE_CONNECTION_SECONDS:
                await sleep(_backoff(attempt))
                attempt += 1
            else:
                attempt = 0


async def _refuse_zero_network(root: Path) -> NoReturn:
    """End the foreground agent: this computer last reported zero-network (ADR-051 decision 8)."""

    _record("foreground_agent", _ZERO_NETWORK)
    await _close_master(root)
    raise AgentSessionError("service_unavailable", phase=_ZERO_NETWORK)


# -- the bridge's background agent and drain ------------------------------------------------------


def capture_pending(workspace: WorkspaceLocator, state: Path | None = None) -> bool:
    """Whether hooks left rows or spooled records for ``workspace`` (a read-only probe).

    ``finishup.client.observation_outbox.capture_pending``; it creates nothing.
    """

    from finishup.client.observation_outbox import capture_pending as pending

    return pending(workspace, state=state)


async def _connect_running(binding: ClientWorkspaceBinding) -> AgentConnection:
    from finishup.service.client import connect_service

    # No on-demand start: background work never asks for a remote service to be started.
    return await connect_service(ControlClientKind.CLI, workspace_binding=binding)


@dataclass(frozen=True, slots=True)
class BackgroundPass:
    """What one background pass did: whether an agent connection is held, and any delivery.

    ``refused`` names why the pass held and delivered nothing, a closed reason
    (``zero_network_remote_selected``, or ``target_removed`` once the bridge's target was removed
    and the work has stopped for good), or is ``None``.
    """

    connected: bool
    drained: ClientDrainSummary | None = None
    refused: str | None = None


class BridgeBackgroundWork:
    """The MCP bridge's background agent connection and observation drain for a remote root.

    ``note_activity`` (each tool call) names the bridge's workspace and renews the lease; ``run``
    is the loop the bridge runs for its lifetime. Each pass, woken by activity or every
    ``drain_interval`` seconds:

    * while the lease runs, or while captured rows wait, one agent connection is kept (dialled
      again if the server closed it, after a back-off; never with the on-demand start);
    * rows waiting for this workspace are delivered over that connection, and delivered rows
      renew the lease (the server verifies them through this agent);
    * once the lease has run out and nothing waits, the connection is closed.

    A connection claims the workspace it was opened for. When the bridge names another workspace
    (a Cursor folder change, say), the next pass closes the connection that claims the earlier
    one and opens one that claims the new workspace before it delivers that workspace's rows.

    While this computer last reported a zero-network policy (read before every connection and
    every delivery, and every ``zero_network_check`` seconds while ``run`` waits) the work holds
    nothing and delivers nothing: it closes its connection and the drain, asks the SSH master of
    ``root`` (the bridge's target) to exit, records ``zero_network_remote_selected`` once, and
    each pass reports it as ``refused`` until the record says otherwise (ADR-051 decision 8).

    Once the record of ``root`` is gone or can no longer be read (``finishup server remove``), the
    work closes what it holds and stops for good: it never dials or delivers to a removed target,
    and the bridge's own connection reports the removal (``isolation_root_invalid``).
    """

    __slots__ = (
        "_attempt",
        "_binding_for",
        "_check",
        "_clock",
        "_connect",
        "_connection",
        "_connection_workspace",
        "_drain",
        "_drain_interval",
        "_last_activity",
        "_lease",
        "_pending",
        "_refused",
        "_retry_at",
        "_root",
        "_wake",
        "_workspace",
    )

    def __init__(
        self,
        *,
        lease_seconds: float = AGENT_LEASE_SECONDS,
        drain_interval: float = DRAIN_INTERVAL_SECONDS,
        connect: AgentConnector | None = None,
        binding_for: BindingFactory | None = None,
        pending: PendingProbe | None = None,
        clock: Callable[[], float] = time.monotonic,
        root: Path | None = None,
        zero_network_check: float = ZERO_NETWORK_CHECK_SECONDS,
    ) -> None:
        for bound in (lease_seconds, drain_interval, zero_network_check):
            if type(bound) is not float or not 0.0 < bound <= 86_400.0:
                raise ValueError("background_work_bound_invalid")
        self._lease = lease_seconds
        self._drain_interval = drain_interval
        self._connect = connect if connect is not None else _connect_running
        self._binding_for = binding_for if binding_for is not None else _serving_binding
        self._pending = pending if pending is not None else capture_pending
        self._clock = clock
        self._wake = asyncio.Event()
        self._workspace: WorkspaceLocator | None = None
        self._last_activity = clock()
        self._connection: AgentConnection | None = None
        # The workspace ``_connection`` claims: a connection serves only the one it was opened for.
        self._connection_workspace: WorkspaceLocator | None = None
        self._drain: ClientObservationDrain | None = None
        self._attempt = 0
        self._retry_at = 0.0
        self._root = root
        self._check = zero_network_check
        self._refused = False

    @property
    def connection(self) -> AgentConnection | None:
        """The live background agent connection, if one is held."""

        held = self._connection
        return None if held is None or held.closed else held

    def note_activity(self, workspace: WorkspaceLocator | None) -> None:
        """Renew the lease for ``workspace`` (the bridge's own) and wake the loop."""

        if type(workspace) is WorkspaceLocator and workspace != self._workspace:
            if self._workspace is not None:
                # The bridge now serves another workspace (a Cursor folder change, say).
                self._close_drain()
            self._workspace = workspace
        self._last_activity = self._clock()
        self._wake.set()

    async def run(self) -> None:
        """Run passes until cancelled; a failed pass is recorded by closed reason only."""

        try:
            while True:
                try:
                    if (await self.run_pass()).refused == _TARGET_REMOVED:
                        return
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    from finishup.observability.logging import (
                        record_unexpected_exception_without_raising,
                    )

                    record_unexpected_exception_without_raising(
                        exc, component=_COMPONENT, operation="background_pass_failed"
                    )
                await self._wait_for_next_pass()
        finally:
            await self.aclose()

    async def _wait_for_next_pass(self) -> None:
        """Wait for activity or the drain interval, reading the zero-network record each tick."""

        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._drain_interval
        while not self._wake.is_set():
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(min(remaining, self._check)):
                    await self._wake.wait()
            if not self._wake.is_set():
                # A connection held across the change closes within a tick of it.
                await self._enforce_zero_network()
        self._wake.clear()

    async def _enforce_zero_network(self) -> bool:
        """Close what this work holds while this computer last reported zero-network; whether so.

        Nothing is delivered on the way out. The SSH master of the bridge's target is asked to
        exit once per change, and the refusal is recorded once, by its closed reason.
        """

        if not _zero_network_reported():
            self._refused = False
            return False
        await self._release()
        self._close_drain()
        if not self._refused:
            self._refused = True
            _record("background_agent", _ZERO_NETWORK)
            await _close_master(self._root)
        return True

    def _target_removed(self) -> bool:
        """Whether the record of the bridge's target is gone or unreadable (a file read only)."""

        if self._root is None:
            return False
        from finishup.client.targets import TargetError, read_target

        try:
            return read_target(self._root) is None
        except TargetError:
            return True

    async def run_pass(self) -> BackgroundPass:
        """One pass: keep or release the agent connection, and deliver what waits."""

        if self._target_removed():
            # Removed under the bridge (A-REMOVE-RACE): nothing is dialled or sent to it again.
            await self.aclose()
            return BackgroundPass(False, refused=_TARGET_REMOVED)
        if await self._enforce_zero_network():
            return BackgroundPass(False, refused=_ZERO_NETWORK)
        workspace = self._workspace
        if workspace is None:
            return BackgroundPass(False)
        leased = self._clock() - self._last_activity < self._lease
        pending = await asyncio.to_thread(self._pending, workspace)
        if not leased and not pending:
            await self._release()
            return BackgroundPass(False)
        connection = await self._ensure_connection(workspace)
        if connection is None:
            if await self._enforce_zero_network():
                return BackgroundPass(False, refused=_ZERO_NETWORK)
            return BackgroundPass(False)
        if not pending:
            return BackgroundPass(True)
        summary = await self._drain_over(workspace, connection)
        if summary is None:
            await self._enforce_zero_network()
            return BackgroundPass(False, refused=_ZERO_NETWORK)
        if summary.delivery is not None and summary.delivery.acknowledged:
            # The server verifies what it accepted through this agent: keep it for that.
            self._last_activity = self._clock()
        return BackgroundPass(True, summary)

    async def _ensure_connection(self, workspace: WorkspaceLocator) -> AgentConnection | None:
        live = self.connection
        if live is not None and self._connection_workspace == workspace:
            return live
        # Closed by the server, or claiming a workspace the bridge no longer serves: its claim
        # would attribute this workspace's rows and calls to the earlier one.
        await self._release()
        now = self._clock()
        if now < self._retry_at:
            return None
        if _zero_network_reported():
            # Read before every connection: none is opened to a server elsewhere then.
            return None
        try:
            binding = await self._binding_for(workspace)
            if binding is None:
                # The bridge's root is not a remote target any more; there is nothing to serve.
                return None
            connection = await self._connect(binding)
        except ControlError as error:
            if error.phase == _ZERO_NETWORK:
                # The connect seam read the record after this work did: no back-off to wait out.
                return None
            self._retry_at = now + _backoff(self._attempt)
            self._attempt += 1
            _record("background_agent", error.phase or error.reason)
            return None
        self._attempt = 0
        self._retry_at = 0.0
        self._connection = connection
        self._connection_workspace = workspace
        return connection

    async def _drain_over(
        self, workspace: WorkspaceLocator, connection: AgentConnection
    ) -> ClientDrainSummary | None:
        """Deliver what waits for ``workspace``; ``None`` (nothing sent) while zero-network."""

        from finishup.client.observation_outbox import ClientObservationDrain

        if _zero_network_reported():
            # Read before every delivery: what hooks captured stays in this client's store.
            return None
        drain = self._drain
        if drain is None:
            drain = ClientObservationDrain(workspace)
            self._drain = drain
        # A ``ServiceClient``: the drain sends each row as ``observation_ingest`` on it.
        return await drain.drain(cast("ObservationIngestClient", connection))

    async def _release(self) -> None:
        connection, self._connection = self._connection, None
        self._connection_workspace = None
        if connection is not None:
            with contextlib.suppress(Exception):
                await connection.close()

    def _close_drain(self) -> None:
        drain, self._drain = self._drain, None
        if drain is not None:
            drain.close()

    async def aclose(self) -> None:
        """Close the background connection and the drain's worker pool."""

        await self._release()
        self._close_drain()


def start_remote_background_work() -> tuple[BridgeBackgroundWork, asyncio.Task[None]] | None:
    """Start the bridge's background work for a remote active root; ``None`` for a local root.

    A local root (the everyday server, an isolated root, a named local server) starts nothing,
    and a root whose record cannot be read starts nothing either: the bridge's own connection
    reports that refusal. The work serves no workspace until the bridge names it
    (``BridgeBackgroundWork.note_activity``).
    """

    from finishup.client.targets import TargetError, active_target_record
    from finishup.config.paths import PathSafetyError, active_root

    try:
        record = active_target_record()
        root = active_root()
    except (TargetError, PathSafetyError):
        return None
    if record is None or not record.is_remote:
        return None
    work = BridgeBackgroundWork(root=root)
    return work, asyncio.create_task(work.run())
