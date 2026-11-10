"""The runtime of an SSH target: ``finishup server connect|disconnect|test`` (ADR-051, ADR-052).

Registered for the ``ssh`` kind in ``client.target_runtime`` once SSH is open. Synchronous, like
every runtime: the CLI calls it outside its event loop, the terminal interface from a worker thread.

* ``ensure_ready`` admits the target through the shared gate (nothing is started or sent while
  it refuses), then connects as any client would (the relay style starts the target's helper; the
  direct style dials ``ssh -W`` and starts the helper for its background agents). It checks again
  every time, whatever the helper last recorded (A-CONNECT-STALE).
* ``stop`` stops the target's helper through its stop epoch (a pending start included, the lock
  proven free; no pid is signalled) and asks the target's OpenSSH master to exit through its
  control socket (never by pattern); a helper that does not release its lock in time is
  ``target_still_connected`` (``server remove`` then removes nothing).
* ``probe`` times status round trips over the real transport.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from finishup.client.target_runtime import (
    LocalTargetRuntime,
    ProbeResult,
    TargetRuntimeError,
    time_new_connections,
)
from finishup.client.targets import ServerTarget, TargetError, read_target

__all__ = [
    "SshTargetRuntime",
    "ensure_helper",
    "ensure_helper_for_direct_style",
    "register_for_background",
]

_START_SECONDS: Final = 30.0
_STOP_SECONDS: Final = 5.0
# The kinds a helper serves: SSH (layer 4), and HTTPS and ``local_port`` over REST (layer 5).
_HELPER_KINDS: Final = frozenset({"ssh", "https", "local_port"})


def _record(root: Path | None) -> tuple[ServerTarget, Path]:
    if root is None:
        raise TargetRuntimeError("target_record_invalid")
    try:
        record = read_target(root)
    except TargetError as error:
        raise TargetRuntimeError(error.reason) from None
    if record is None or record.kind not in _HELPER_KINDS:
        raise TargetRuntimeError("target_record_invalid")
    return record, root


def ensure_helper(root: Path, target_id: str) -> bool:
    """Start the helper of the SSH target at ``root`` unless one runs; whether one runs now.

    For a client that registered a workspace (its background agent) in the direct style, where no
    connection of its own passes the helper. Never raises.
    """

    from finishup.client.helper_status import helper_holder, spawn_helper

    try:
        if helper_holder(root) is not None:
            return True
        spawn_helper(root, target_id)
    except OSError:
        return False
    return True


def ensure_helper_for_direct_style(target_id: str) -> bool:
    """``ensure_helper`` for a target whose owner chose the direct style; ``False`` otherwise.

    In the relay style a client's connection already went through the running helper.
    """

    from finishup.client.helper_status import read_connection_style
    from finishup.client.targets import target_root

    try:
        root = target_root(target_id)
    except TargetError:
        return False
    if read_connection_style(root) != "direct":
        return False
    return ensure_helper(root, target_id)


def register_for_background(client: object, source: str) -> bool:
    """Register a claim-bound remote connection's workspace with its target's helper, once.

    For a short-lived client (a CLI command, ``source`` ``cli``): no renewal and no release when
    it exits, so the registration's lease (15 minutes) is the window in which the helper's
    background agent answers the work the server goes on with after the command returned. The
    helper is started when none runs (the direct style; the relay's already relayed the
    connection). Best effort and never raises: the connection works the same either way.
    """

    from finishup.client.authorization import ConnectionAuthorization
    from finishup.client.helper_registrations import RegistrationError, new_registrant, register

    workspace = getattr(client, "remote_workspace", None)
    authorization = getattr(client, "authorization", None)
    if workspace is None or type(authorization) is not ConnectionAuthorization:
        return False
    try:
        registration = register(
            authorization,
            workspace[0],
            workspace[1],
            registrant=new_registrant(),
            source=source,
        )
    except (RegistrationError, TargetError, OSError, ValueError):
        return False
    ensure_helper_for_direct_style(registration.target_id)
    return True


class SshTargetRuntime:
    """A server elsewhere reached through its helper: SSH (its helper, its OpenSSH master, and the
    server's service behind them) or HTTPS and ``local_port`` (its helper and its REST upstream;
    the server's own edge starts its service)."""

    __slots__ = ()

    def ensure_ready(self, root: Path | None) -> None:
        import anyio

        from finishup.client.authorization import authorize_target
        from finishup.client.helper_status import read_connection_style
        from finishup.config.paths import selection_override
        from finishup.ports.control import ControlClientKind, ControlError
        from finishup.service.client import connect_service_on_demand

        record, target_root = _record(root)
        try:
            authorize_target(record)
        except TargetError as error:
            raise TargetRuntimeError("service_unavailable", phase=error.reason) from None

        async def start() -> None:
            client = await connect_service_on_demand(
                ControlClientKind.CLI, workspace_locator=None, timeout_seconds=_START_SECONDS
            )
            await client.close()

        with selection_override(target_root):
            try:
                anyio.run(start)
            except ControlError as error:
                raise TargetRuntimeError(error.reason, phase=error.phase) from None
        if read_connection_style(target_root) == "direct":
            ensure_helper(target_root, record.target_id)

    def stop(self, root: Path | None) -> None:
        from finishup.client.helper_status import stop_helper
        from finishup.client.ssh_transport import UpstreamUnavailable, exit_master_now, resolve_ssh

        record, target_root = _record(root)
        if not stop_helper(target_root, timeout_seconds=_STOP_SECONDS):
            raise TargetRuntimeError("target_still_connected")
        if record.kind != "ssh":
            # An HTTPS or port target has no OpenSSH master: stopping its helper is the stop.
            return
        try:
            ssh = resolve_ssh()
        except UpstreamUnavailable:
            return
        # Synchronous: a stop may be asked from inside an event loop (a setup step's switch).
        exit_master_now(ssh, target_root, record)

    def probe(self, root: Path | None) -> ProbeResult:
        _record(root)
        return LocalTargetRuntime().probe(root)

    def time_new_connections(self, root: Path | None, count: int) -> tuple[int, ...]:
        _record(root)
        return time_new_connections(root, count)
