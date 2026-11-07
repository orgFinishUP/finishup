"""Target runtimes of the server-native network API: ``https``, ``local_port`` and ``ssh`` (ADR-051).

``finishup server connect|disconnect|test|status`` reach a remote target through these.

* ``https`` and ``local_port`` need no local process: ``ensure_ready`` reads ``GET /v1/server``
  with the stored key, ``probe`` times ``service_status`` calls, and ``stop`` ends this client's
  workspace agent for the target.
* ``ssh`` keeps one OpenSSH master per target (``<target root>/run/m``) that forwards
  ``<target root>/run/api.sock`` to the server's owner-only API socket — a Unix socket to a Unix
  socket, so the server opens no TCP port for SSH clients. The master runs with
  ``BatchMode=yes`` and ``StrictHostKeyChecking=yes`` (OpenSSH keeps the keys and
  ``known_hosts``), binds the local socket owner-only, and stops after 15 idle minutes or on
  ``ssh -O exit``. A remote service that stopped while idle is started again with the recorded
  absolute launcher (``service start``), never a bare ``finishup`` from the remote ``PATH``.
  Starting the master is serialized per target (``<target root>/run/m.lock``) and re-checked
  under that lock, so two clients never start two masters (a second ``-M`` that finds the control
  socket in place would run on as an ordinary session no ``-O exit`` reaches); a master that lost
  its forward gets it back through ``-O forward``; and every step runs within the caller's time
  budget. A master that could not reach the server is remembered briefly (``m.failed``), so the
  connections right after it fail at once instead of each waiting on ssh again.

Nothing here runs a shell on this machine or kills a process by name: the master is stopped
through its own control socket and the agent through its stop request file, never a signal.
ssh's own output is read only to choose a closed reason and is never shown or logged.

Every step that reaches the server (the master, a forward, the remote service start, a probe or a
connection) asks the shared connection check first (``targets.require_current_authorization``):
while this computer last reported a zero-network policy, or for a target confirmed under an older
disclosure, nothing is started or sent, and a probe is ``unavailable`` with that reason. Every
master has a supervisor, the target's workspace agent (``client.agent``): whatever makes a master
usable (``server connect``, ``test`` and ``status``, the terminal's ``/server``, a connection)
starts that agent when none runs, and the agent closes the master within about a second of this
computer's zero-network record. The command that records it closes every SSH target's master
itself as well (``close_ssh_masters``).
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import os
import re
import shlex
import stat
import subprocess
import time
from collections.abc import Generator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from finishup.client.target_runtime import (
    PROBE_SAMPLES,
    ProbeOutcome,
    ProbeResult,
    TargetRuntimeError,
)
from finishup.client.targets import ServerTarget, read_target
from finishup.protocol.canonical import JsonValue, strict_json_parse
from finishup.service.network_protocol import API_SOCKET_NAME

__all__ = [
    "MASTER_FAILURE_HOLD_SECONDS",
    "MASTER_SOCKET_NAME",
    "RestTargetRuntime",
    "SshEndpoint",
    "SshTargetRuntime",
    "close_ssh_masters",
    "close_ssh_transport",
    "discover_ssh_endpoint",
    "restore_ssh_transport",
    "ssh_command_prefix",
    "ssh_master_alive",
    "ssh_master_argv",
]

MASTER_SOCKET_NAME: Final = "m"
_MASTER_LOCK_NAME: Final = "m.lock"
_MASTER_FAILURE_NAME: Final = "m.failed"
# After a master that could not reach the server, connections fail at once for this long.
MASTER_FAILURE_HOLD_SECONDS: Final = 10.0
# The longest a TCP connection to the SSH server may take (``ConnectTimeout``).
_SSH_CONNECT_SECONDS: Final = 10
_LOCK_POLL_SECONDS: Final = 0.05
_SSH: Final = "ssh"
_MASTER_IDLE_SECONDS: Final = 900
_SSH_START_SECONDS: Final = 30.0
_SSH_CONTROL_SECONDS: Final = 10.0
_DISCOVERY_SECONDS: Final = 30.0
# Room for the owner to read OpenSSH's host-key question at ``server add`` and answer it (the
# bound approach A's and approach B's add use).
_CONFIRM_DISCOVERY_SECONDS: Final = 180.0
_MAX_DISCOVERY_BYTES: Final = 65_536
_MAX_PATH_TEXT: Final = 1_024
# Where a FinishUP launcher is commonly installed when ``server add`` was given none. The first
# executable one answers; a bare ``finishup`` from the remote PATH is never used (issue #604).
_LAUNCHER_CANDIDATES: Final = (
    '"$HOME/.local/bin/finishup"',
    "/usr/local/bin/finishup",
    "/opt/homebrew/bin/finishup",
)
_AUTH_FAILURE: Final = re.compile(rb"Permission denied|Too many authentication failures")
_HOST_KEY_FAILURE: Final = re.compile(
    rb"Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED|No .* host key is known"
)


@dataclass(frozen=True, slots=True)
class SshEndpoint:
    """What ``server add`` learned from the server: its API socket and its launcher."""

    api_socket: str
    launcher: str


def _destination_of(user: str | None, host: str) -> str:
    return host if user is None else f"{user}@{host}"


def _destination(record: ServerTarget) -> str:
    if record.host is None or record.port is None:
        raise TargetRuntimeError("remote_unreachable", phase="target_incomplete")
    return _destination_of(record.user, record.host)


def _socket_path_text(value: object) -> str:
    """An absolute socket path that ``ssh -L local:remote`` can carry (no ``:``)."""

    if (
        type(value) is not str
        or not value.startswith("/")
        or len(value) > _MAX_PATH_TEXT
        or ":" in value
        or any(ord(character) < 0x21 or ord(character) == 0x7F for character in value)
    ):
        raise TargetRuntimeError("remote_incompatible", phase="api_socket_invalid")
    return value


def _launcher_text(value: object) -> str:
    """An absolute launcher path reported by the server (spaces allowed, no control bytes)."""

    if (
        type(value) is not str
        or not value.startswith("/")
        or len(value) > _MAX_PATH_TEXT
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise TargetRuntimeError("remote_incompatible", phase="launcher_invalid")
    return value


def ssh_command_prefix(record: ServerTarget, root: Path) -> list[str]:
    """``ssh`` options shared by every connection of one target, through its master if any."""

    return [
        _SSH,
        "-S",
        os.fspath(root / "run" / MASTER_SOCKET_NAME),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-p",
        str(record.port),
    ]


def ssh_master_argv(
    record: ServerTarget, root: Path, *, connect_timeout: int = _SSH_CONNECT_SECONDS
) -> list[str]:
    """The fixed, secret-free argv of one target's OpenSSH master and its socket forward.

    ``connect_timeout`` (whole seconds, 1 to 10) bounds the TCP connection, so an unreachable
    host fails within the caller's budget instead of the system's.
    """

    if not 1 <= connect_timeout <= _SSH_CONNECT_SECONDS:
        raise ValueError("ssh_connect_timeout_invalid")
    if record.kind != "ssh":
        raise TargetRuntimeError("remote_unreachable", phase="target_incomplete")
    remote = _socket_path_text(record.remote_endpoint)
    local = os.fspath(root / "run" / API_SOCKET_NAME)
    if ":" in local:
        raise TargetRuntimeError("remote_unreachable", phase="target_root_unsupported")
    return [
        _SSH,
        "-f",
        "-N",
        "-M",
        "-S",
        os.fspath(root / "run" / MASTER_SOCKET_NAME),
        "-o",
        f"ControlPersist={_MASTER_IDLE_SECONDS}",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"ConnectTimeout={connect_timeout}",
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "StreamLocalBindMask=0177",
        "-o",
        "StreamLocalBindUnlink=yes",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
        "-p",
        str(record.port),
        "-L",
        f"{local}:{remote}",
        "--",
        _destination(record),
    ]


def _ssh_environment() -> dict[str, str]:
    """What ssh needs to find the owner's keys and agent, and nothing FinishUP-specific."""

    keep = ("HOME", "USER", "LOGNAME", "PATH", "SSH_AUTH_SOCK", "LANG", "LC_ALL", "TMPDIR")
    return {name: os.environ[name] for name in keep if name in os.environ}


def _host_key_unconfirmed(stderr: bytes) -> bool:
    """Whether OpenSSH refused a host key it does not know (never one that changed).

    Strict checking says "No … host key is known for …"; a declined or unanswerable question says
    only "Host key verification failed". A changed key says "REMOTE HOST IDENTIFICATION HAS
    CHANGED" and stays ``remote_identity_changed``.
    """

    if b"REMOTE HOST IDENTIFICATION HAS CHANGED" in stderr:
        return False
    return b"host key is known" in stderr or b"Host key verification failed" in stderr


def _ssh_failure(stderr: bytes) -> TargetRuntimeError:
    if _HOST_KEY_FAILURE.search(stderr):
        return TargetRuntimeError("remote_identity_changed", phase="ssh_host_key")
    if _AUTH_FAILURE.search(stderr):
        return TargetRuntimeError("remote_auth_failed", phase="ssh_authentication")
    return TargetRuntimeError("remote_unreachable", phase="ssh_connect")


def _run(
    argv: list[str], *, timeout: float, detaches: bool = False
) -> subprocess.CompletedProcess[bytes]:
    """Run ssh with a scrubbed environment; ``detaches`` for a master that backgrounds itself.

    A backgrounded master keeps its inherited output open for its whole life, so its stderr goes
    to an unnamed temporary file (read once, for a closed reason) instead of a pipe.
    """

    import tempfile

    try:
        if not detaches:
            return subprocess.run(  # noqa: S603 - fixed ssh argv; no shell on this machine
                argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                env=_ssh_environment(),
                timeout=timeout,
                check=False,
            )
        with tempfile.TemporaryFile() as stderr:
            completed = subprocess.run(  # noqa: S603 - fixed ssh argv; no shell on this machine
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stderr,
                env=_ssh_environment(),
                timeout=timeout,
                check=False,
                start_new_session=True,
            )
            stderr.seek(0)
            return subprocess.CompletedProcess(
                argv, completed.returncode, b"", stderr.read(_MAX_DISCOVERY_BYTES)
            )
    except FileNotFoundError:
        raise TargetRuntimeError("remote_unreachable", phase="ssh_missing") from None
    except subprocess.TimeoutExpired:
        raise TargetRuntimeError("remote_unreachable", phase="ssh_timeout") from None
    except OSError:
        raise TargetRuntimeError("remote_unreachable", phase="ssh_connect") from None


def _remote_command(remote_root: str | None, launcher: str | None, *arguments: str) -> str:
    """One remote command: the absolute launcher (or the probe for one) and fixed arguments.

    ``remote_root`` pins the server's isolated root through ``env``, so the command acts on that
    service whatever the remote login environment holds. Every value is shell-quoted.
    """

    pin = "" if remote_root is None else f"env FINISHUP_ISOLATED_ROOT={shlex.quote(remote_root)} "
    tail = " ".join(shlex.quote(argument) for argument in arguments)
    if launcher is not None:
        return f"{pin}{shlex.quote(launcher)} {tail}"
    candidates = " ".join(_LAUNCHER_CANDIDATES)
    return (
        f'for p in {candidates}; do if [ -x "$p" ]; then printf "%s\\n" "$p"; '
        f'exec {pin}"$p" {tail}; fi; done; exit 127'
    )


def discover_ssh_endpoint(
    *,
    user: str | None,
    host: str,
    port: int,
    remote_root: str | None,
    remote_launcher: str | None,
    confirm_host_key: bool = False,
) -> SshEndpoint:
    """Ask the server, over one SSH command, where its API socket is.

    Runs ``<launcher> service endpoint --json`` there (``--remote-launcher``, or the first common
    install path that exists). The answer must name an owner-only API socket: a server without
    ``[network] api_socket = true`` is refused with ``remote_incompatible`` (phase
    ``api_socket_unconfigured``).

    ``server add`` runs this only after the owner's typed confirmation on the trusted console,
    with ``confirm_host_key``: it is the one interactive ``ssh`` of the topology, as approach A's
    and approach B's ``server add`` are: ``StrictHostKeyChecking=ask`` with no master and no
    ``BatchMode``, so OpenSSH itself asks, on that terminal, to confirm a host key it does not know
    yet, and that answer is the ``known_hosts`` pin every later ``BatchMode`` connection checks.
    Password and keyboard-interactive login stay off, so the host key is the only question and the
    add proves the key authentication later connections need. Without ``confirm_host_key``
    nothing is asked (``StrictHostKeyChecking=yes``). Either way an unknown host key that was not
    confirmed (the owner declined OpenSSH's question or did not answer it in time) raises
    ``TargetRuntimeError("remote_host_key_unconfirmed")``; a changed one stays
    ``remote_identity_changed``.
    """

    launcher = remote_launcher
    command = _remote_command(remote_root, launcher, "service", "endpoint", "--json")
    trust = (
        [
            "-o",
            "StrictHostKeyChecking=ask",
            "-o",
            "ControlMaster=no",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-T",
        ]
        if confirm_host_key
        else ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes"]
    )
    argv = [
        _SSH,
        *trust,
        "-o",
        f"ConnectTimeout={_SSH_CONNECT_SECONDS}",
        "-p",
        str(port),
        "--",
        _destination_of(user, host),
        command,
    ]
    completed = _run(
        argv, timeout=_CONFIRM_DISCOVERY_SECONDS if confirm_host_key else _DISCOVERY_SECONDS
    )
    if completed.returncode == 255:
        if _host_key_unconfirmed(completed.stderr):
            raise TargetRuntimeError("remote_host_key_unconfirmed")
        raise _ssh_failure(completed.stderr)
    if completed.returncode == 127:
        raise TargetRuntimeError("remote_incompatible", phase="launcher_not_found")
    if completed.returncode != 0 or len(completed.stdout) > _MAX_DISCOVERY_BYTES:
        raise TargetRuntimeError("remote_incompatible", phase="endpoint_report_invalid")
    output = completed.stdout
    if launcher is None:
        first, _newline, output = output.partition(b"\n")
        try:
            launcher = _launcher_text(first.decode("utf-8"))
        except UnicodeDecodeError:
            raise TargetRuntimeError("remote_incompatible", phase="launcher_invalid") from None
    try:
        report = strict_json_parse(output.rstrip(b"\n"))
    except ValueError:
        raise TargetRuntimeError("remote_incompatible", phase="endpoint_report_invalid") from None
    if type(report) is not dict:
        raise TargetRuntimeError("remote_incompatible", phase="endpoint_report_invalid")
    document = cast(dict[str, JsonValue], report)
    if document.get("schema") != "yoetz.service-endpoint/1":
        raise TargetRuntimeError("remote_incompatible", phase="endpoint_report_invalid")
    network = document.get("network")
    if network == "config_invalid":
        # The server's own configuration cannot be read there; its owner repairs it.
        raise TargetRuntimeError("remote_incompatible", phase="server_config_invalid")
    if type(network) is not dict:
        raise TargetRuntimeError("remote_incompatible", phase="api_socket_unconfigured")
    api_socket = cast(dict[str, JsonValue], network).get("api_socket")
    if api_socket is None:
        raise TargetRuntimeError("remote_incompatible", phase="api_socket_unconfigured")
    return SshEndpoint(_socket_path_text(api_socket), launcher)


def _p95(samples: list[float]) -> int:
    ordered = sorted(samples)
    index = max(0, -(-95 * len(ordered) // 100) - 1)
    return round(ordered[index] * 1000)


def _record(root: Path | None) -> ServerTarget:
    if root is None:
        raise TargetRuntimeError("remote_unreachable", phase="target_incomplete")
    from finishup.client.targets import TargetError

    try:
        record = read_target(root)
    except TargetError:
        raise TargetRuntimeError("remote_unreachable", phase="target_incomplete") from None
    if record is None or not record.is_remote:
        raise TargetRuntimeError("remote_unreachable", phase="target_incomplete")
    return record


def _runtime_error(error: BaseException) -> TargetRuntimeError:
    from finishup.ports.control import ControlError

    if isinstance(error, TargetRuntimeError):
        return error
    if isinstance(error, ControlError):
        phase = error.phase
        from finishup.protocol.errors import REMOTE_CONNECTION_PHASES

        if error.reason == "service_unavailable" and phase in REMOTE_CONNECTION_PHASES:
            # A remote phase is the reason itself, the shared check's refusals included.
            return TargetRuntimeError(phase)
        return TargetRuntimeError(error.reason, phase=phase)
    return TargetRuntimeError("remote_unreachable", phase="timeout")


def _require_allowed(record: ServerTarget) -> None:
    """The shared connection check before any step that reaches ``record``'s server.

    Raises the closed ``TargetRuntimeError`` of a refusal (``zero_network_remote_selected``,
    ``target_reauthorization_required``), so ``_remote_phase`` keeps its name on every surface.
    """

    from finishup.client.targets import TargetError, require_current_authorization

    try:
        require_current_authorization(record)
    except TargetError as error:
        raise TargetRuntimeError(error.reason) from None


class RestTargetRuntime:
    """``https`` and ``local_port`` targets: nothing to start, a workspace agent to stop."""

    def ensure_ready(self, root: Path | None) -> None:
        record = _record(root)
        assert root is not None
        self._prepare(record, root)
        import anyio

        from finishup.client.rest_client import connect_rest_service
        from finishup.ports.control import ControlClientKind

        async def connect() -> None:
            with anyio.fail_after(_SSH_START_SECONDS):
                client = await connect_rest_service(ControlClientKind.CLI, record=record, root=root)
            await client.close()

        try:
            anyio.run(connect)
        except Exception as error:
            raise _runtime_error(error) from None

    def _prepare(self, record: ServerTarget, root: Path) -> None:
        """Make the transport usable before connecting (nothing for HTTPS)."""

        del record, root

    def stop(self, root: Path | None) -> None:
        """Stop the target's workspace agent, then its transport (``server disconnect``, a switch).

        The agent is asked through its owner-only request file and waited for (``stop_agent``);
        an agent that still holds its lock after that wait may still answer the server's reads
        of files here, so the stop says so (``service_unavailable``, phase ``agent_stop``)
        rather than reporting it stopped. The transport is torn down either way.
        """

        record = _record(root)
        assert root is not None
        from finishup.client.agent import agent_pid, stop_agent

        stop_agent(root)
        self._teardown(record, root)
        if agent_pid(root) is not None:
            raise TargetRuntimeError("service_unavailable", phase="agent_stop")

    def _teardown(self, record: ServerTarget, root: Path) -> None:
        del record, root

    def probe(self, root: Path | None) -> ProbeResult:
        try:
            record = _record(root)
            assert root is not None
            # The shared connection check first: nothing is sent to probe a target nothing may be
            # sent to now (the reason names why), and no SSH master is started for it.
            _require_allowed(record)
            self._prepare(record, root)
        except TargetRuntimeError as error:
            return ProbeResult("unavailable", reason=error.reason, phase=error.phase)
        import anyio

        from finishup.client.rest_client import connect_rest_service
        from finishup.ports.control import ControlClientKind, ControlError, ServiceState

        async def probe() -> ProbeResult:
            try:
                with anyio.fail_after(_SSH_START_SECONDS):
                    client = await connect_rest_service(
                        ControlClientKind.CLI, record=record, root=root
                    )
            except (ControlError, TimeoutError) as error:
                failure = _runtime_error(error)
                outcome: ProbeOutcome = (
                    "not_running"
                    if failure.reason == "remote_service_not_running"
                    else "unavailable"
                )
                return ProbeResult(outcome, reason=failure.reason, phase=failure.phase)
            samples: list[float] = []
            try:
                # The first call also loads this process's protocol validators, which a local
                # connection loads during its hello; that is not a round trip, so it is not one
                # of the samples (it read about 0.2 s against a 20 ms round trip in a real run).
                status = await client.service_status()
                for _sample in range(PROBE_SAMPLES):
                    started = time.monotonic()
                    status = await client.service_status()
                    samples.append(time.monotonic() - started)
            except ControlError as error:
                failure = _runtime_error(error)
                return ProbeResult("unavailable", reason=failure.reason, phase=failure.phase)
            finally:
                await client.close()
            assert status is not None
            return ProbeResult(
                "ready" if status.state is ServiceState.READY else "reachable",
                service_version=status.service_version,
                service_instance_id=status.service_instance_id,
                service_state=status.state.value,
                vault_mode=status.vault_mode,
                round_trip_p95_ms=_p95(samples),
                samples=len(samples),
            )

        return anyio.run(probe)


def _remaining(deadline: float, *, cap: float | None = None) -> float:
    """What is left of a budget, at most ``cap``; a spent budget is ssh's own timeout."""

    left = deadline - time.monotonic()
    if left <= 0:
        raise TargetRuntimeError("remote_unreachable", phase="ssh_timeout")
    return left if cap is None else min(left, cap)


def _supervise(root: Path) -> None:
    """Start the master's supervisor, the target's workspace agent, when none runs."""

    from finishup.client.agent import ensure_agent

    ensure_agent(root)


def _run_directory(root: Path) -> Path:
    from finishup.config.paths import PathSafetyError, ensure_owner_only_dir

    directory = root / "run"
    try:
        ensure_owner_only_dir(directory)
    except (OSError, PathSafetyError):
        raise TargetRuntimeError("remote_unreachable", phase="target_root_unsafe") from None
    return directory


@contextlib.contextmanager
def _master_lock(directory: Path, deadline: float) -> Generator[None]:
    """Hold ``run/m.lock``: one process at a time checks and starts this target's master."""

    try:
        descriptor = os.open(
            directory / _MASTER_LOCK_NAME,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
    except OSError:
        raise TargetRuntimeError("remote_unreachable", phase="target_root_unsafe") from None
    try:
        facts = os.fstat(descriptor)
        if not stat.S_ISREG(facts.st_mode) or facts.st_uid != os.geteuid():
            raise TargetRuntimeError("remote_unreachable", phase="target_root_unsafe")
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                time.sleep(min(_LOCK_POLL_SECONDS, _remaining(deadline)))
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _recent_failure(directory: Path) -> TargetRuntimeError | None:
    """The closed failure of a master start that could not reach the server moments ago."""

    path = directory / _MASTER_FAILURE_NAME
    try:
        facts = path.lstat()
    except OSError:
        return None
    if (
        not stat.S_ISREG(facts.st_mode)
        or facts.st_uid != os.geteuid()
        or facts.st_size > 128
        or not 0 <= time.time() - facts.st_mtime < MASTER_FAILURE_HOLD_SECONDS
    ):
        return None
    try:
        reason, _colon, phase = path.read_text(encoding="ascii").strip().partition(":")
        return TargetRuntimeError(reason, phase=phase or None)
    except (OSError, UnicodeDecodeError, ValueError):
        return None


def _note_failure(directory: Path, error: TargetRuntimeError) -> None:
    """Remember an unreachable server for ``MASTER_FAILURE_HOLD_SECONDS`` (closed tokens only)."""

    if error.reason != "remote_unreachable":
        return
    path = directory / _MASTER_FAILURE_NAME
    temporary = directory / f".{_MASTER_FAILURE_NAME}.{os.getpid()}.tmp"
    text = error.reason if error.phase is None else f"{error.reason}:{error.phase}"
    with contextlib.suppress(OSError):
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
        )
        try:
            os.write(descriptor, text.encode("ascii") + b"\n")
        finally:
            os.close(descriptor)
        os.replace(temporary, path)


def _clear_failure(directory: Path) -> None:
    with contextlib.suppress(FileNotFoundError):
        (directory / _MASTER_FAILURE_NAME).unlink()


def _remove_stale_control_socket(directory: Path) -> None:
    """Remove a control socket whose master no longer answers; refuse anything else there."""

    path = directory / MASTER_SOCKET_NAME
    try:
        facts = path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        raise TargetRuntimeError("remote_unreachable", phase="target_root_unsafe") from None
    if not stat.S_ISSOCK(facts.st_mode) or facts.st_uid != os.geteuid():
        raise TargetRuntimeError("remote_unreachable", phase="target_root_unsafe")
    with contextlib.suppress(FileNotFoundError):
        path.unlink()


class SshTargetRuntime(RestTargetRuntime):
    """``ssh`` targets: one OpenSSH master per target, forwarding the API socket."""

    def master_running(
        self, record: ServerTarget, root: Path, *, timeout: float = _SSH_CONTROL_SECONDS
    ) -> bool:
        argv = [*ssh_command_prefix(record, root), "-O", "check", "--", _destination(record)]
        if not (root / "run" / MASTER_SOCKET_NAME).exists():
            return False
        return _run(argv, timeout=timeout).returncode == 0

    def _prepare(self, record: ServerTarget, root: Path) -> None:
        # ``server connect`` and ``server test`` are the owner asking now: no remembered failure.
        self.ensure_master(record, root, honor_recent_failure=False)

    def ensure_master(
        self,
        record: ServerTarget,
        root: Path,
        *,
        timeout: float = _SSH_START_SECONDS,
        honor_recent_failure: bool = True,
        supervise: bool = True,
    ) -> None:
        """Make this target's master and its forward usable within ``timeout`` seconds.

        Under the target's master lock: a master that answers ``-O check`` with its forward in
        place is left alone, one that lost its forward gets it back with ``-O forward``, and only
        when none answers is a stale control socket removed and a master started. A start that
        could not reach the server is remembered for ``MASTER_FAILURE_HOLD_SECONDS``, and while
        ``honor_recent_failure`` the calls in that window fail at once with the same reason.

        A master this leaves running (found, started, or one whose forward could not be put
        back) is never left without its supervisor: the target's workspace agent is started when
        none runs (``client.agent.ensure_agent``), so this computer's zero-network record closes
        the master within about a second (ADR-051 decision 8). ``supervise`` is false only for a
        caller that is that agent, or that has just started it.
        """

        _require_allowed(record)
        deadline = time.monotonic() + timeout
        directory = _run_directory(root)
        if honor_recent_failure:
            remembered = _recent_failure(directory)
            if remembered is not None:
                raise remembered
        master_up = False
        try:
            with _master_lock(directory, deadline):
                if honor_recent_failure:
                    # Another process may have just failed (or succeeded) while this one waited.
                    remembered = _recent_failure(directory)
                    if remembered is not None:
                        raise remembered
                master_up = self.master_running(
                    record, root, timeout=_remaining(deadline, cap=_SSH_CONTROL_SECONDS)
                )
                if master_up and (directory / API_SOCKET_NAME).exists():
                    return
                try:
                    if master_up:
                        self._forward_again(record, root, deadline)
                    else:
                        _remove_stale_control_socket(directory)
                        self._start_master(record, root, deadline)
                        master_up = True
                except TargetRuntimeError as error:
                    _note_failure(directory, error)
                    raise
                _clear_failure(directory)
        finally:
            if master_up and supervise:
                _supervise(root)

    def _start_master(self, record: ServerTarget, root: Path, deadline: float) -> None:
        left = _remaining(deadline)
        argv = ssh_master_argv(
            record, root, connect_timeout=max(1, min(_SSH_CONNECT_SECONDS, int(left)))
        )
        completed = _run(argv, timeout=left, detaches=True)
        if completed.returncode != 0:
            raise _ssh_failure(completed.stderr)

    def _forward_again(self, record: ServerTarget, root: Path, deadline: float) -> None:
        """Add the API socket's forward back to a live master (never a second master)."""

        forward = ssh_master_argv(record, root)
        local_to_remote = forward[forward.index("-L") + 1]
        argv = [
            *ssh_command_prefix(record, root),
            "-O",
            "forward",
            "-L",
            local_to_remote,
            "--",
            _destination(record),
        ]
        completed = _run(argv, timeout=_remaining(deadline, cap=_SSH_CONTROL_SECONDS))
        if completed.returncode != 0:
            raise TargetRuntimeError("remote_unreachable", phase="ssh_forward")

    def start_remote_service(
        self, record: ServerTarget, root: Path, *, timeout: float = _SSH_START_SECONDS
    ) -> None:
        """Start an idle-stopped remote service once, through the master and its launcher."""

        _require_allowed(record)
        if record.remote_launcher is None:
            raise TargetRuntimeError("remote_service_not_running", phase="launcher_unknown")
        argv = [
            *ssh_command_prefix(record, root),
            "--",
            _destination(record),
            _remote_command(record.remote_root, record.remote_launcher, "service", "start"),
        ]
        completed = _run(argv, timeout=_remaining(time.monotonic() + timeout))
        if completed.returncode == 255:
            raise _ssh_failure(completed.stderr)
        if completed.returncode != 0:
            raise TargetRuntimeError("remote_service_not_running", phase="service_start_failed")

    def teardown(self, record: ServerTarget, root: Path) -> None:
        """Stop this target's master through its control socket and remove its forward."""

        self._teardown(record, root)

    def _teardown(self, record: ServerTarget, root: Path) -> None:
        if (root / "run" / MASTER_SOCKET_NAME).exists():
            argv = [*ssh_command_prefix(record, root), "-O", "exit", "--", _destination(record)]
            _run(argv, timeout=_SSH_CONTROL_SECONDS)
        _clear_failure(root / "run")
        forwarded = root / "run" / API_SOCKET_NAME
        try:
            facts = forwarded.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISSOCK(facts.st_mode) and facts.st_uid == os.geteuid():
            forwarded.unlink()


async def restore_ssh_transport(
    record: ServerTarget, root: Path, *, timeout: float = _SSH_START_SECONDS
) -> None:
    """Bring an SSH target's master and forward back for a background client (the agent).

    Nothing for any other kind. It never starts the remote service (only a caller the owner is
    waiting on does). A failure raises its closed ``TargetRuntimeError``; a recent one is
    remembered, so a background retry loop does not run ssh on every attempt.
    """

    if record.kind != "ssh":
        return
    # The agent is the master's supervisor: it does not start itself again.
    await asyncio.to_thread(
        SshTargetRuntime().ensure_master, record, root, timeout=timeout, supervise=False
    )


def close_ssh_masters(roots: Sequence[Path] | None = None) -> tuple[str, ...]:
    """Close the OpenSSH master of each SSH target; the generated ids of those asked to exit.

    ``roots`` names target roots (records of other kinds are skipped); ``None`` means every target
    in this computer's registry. Only a master this client started is asked, through its own
    control socket (``ssh -O exit``), never found by pattern or pid; a target with no control
    socket, or whose record cannot be read, is skipped, each on its own, so one damaged root never
    keeps the others' masters open. The command that records this computer's zero-network policy
    runs this (ADR-051 decision 8), beside each master's own supervisor. Never raises: a master
    that could not be closed is left to its supervisor, and the shared check refuses every new
    connection either way.
    """

    from finishup.client.targets import TargetError, servers_dir
    from finishup.config.paths import PathSafetyError

    if roots is None:
        try:
            chosen = tuple(
                Path(entry.path)
                for entry in os.scandir(servers_dir())
                if entry.is_dir(follow_symlinks=False)
            )
        except (OSError, PathSafetyError):
            return ()
    else:
        chosen = tuple(roots)
    runtime = SshTargetRuntime()
    closed: list[str] = []
    for root in chosen:
        try:
            record = read_target(root)
        except (TargetError, OSError, PathSafetyError):
            continue
        if record is None or record.kind != "ssh":
            continue
        if not (root / "run" / MASTER_SOCKET_NAME).exists():
            continue
        try:
            runtime.teardown(record, root)
        except (TargetRuntimeError, OSError):
            continue
        closed.append(record.target_id)
    return tuple(closed)


async def close_ssh_transport(record: ServerTarget, root: Path) -> None:
    """Close an SSH target's master through its control socket; nothing for any other kind.

    The workspace agent, the master's supervisor, runs this once this computer last reported a
    zero-network policy (ADR-051 decision 8). Never a signal, never by name.
    """

    if record.kind != "ssh":
        return
    await asyncio.to_thread(SshTargetRuntime().teardown, record, root)


async def ssh_master_alive(record: ServerTarget, root: Path) -> bool:
    """Whether an SSH target's master still answers on its control socket (never for others)."""

    if record.kind != "ssh":
        return False
    return await asyncio.to_thread(SshTargetRuntime().master_running, record, root)
