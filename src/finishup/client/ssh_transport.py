"""OpenSSH for an ``ssh`` server target: fixed argv, the relay's master, the direct stream.

An SSH server is reached through OpenSSH only (design v2 section 1, edge ``ssh``; ADR-051,
ADR-052). sshd connects to the server's own owner-only control socket as the login user, so the
server's peer-UID check passes unchanged; FinishUP stores no SSH key and never asks for a password:
keys, the agent and ``known_hosts`` stay with OpenSSH (ADR-008: SSH is owner-equivalent).

Two connection styles (design v2 section 1.2, U21):

* **relay** (the default): the target's helper keeps one warm master (``SshMaster``) whose
  ``-L <root>/run/upstream.sock:<remote control.sock>`` forward carries one channel per local
  connection;
* **direct** (an advanced option): each client process opens its own ``ssh -W <remote
  control.sock>`` stream (``SshControlStream``) through a ``ControlMaster=auto`` master at
  ``<root>/run/m`` that persists for 15 idle minutes (approach B's seam).

Every argv here is fixed and secret-free. Remote commands are the server's own ``finishup``
launcher (an absolute path recorded with the target, never a bare name resolved through the remote
``PATH``) with fixed arguments, pinned to the recorded remote root, each word shell-quoted because
sshd hands the command line to the remote login shell. Every ``ssh`` child runs with FinishUP's own
variables removed from its environment, so none can ride a ``SendEnv`` line to the server.

Failures are closed reasons (``protocol.errors.REMOTE_CONNECTION_PHASES``). OpenSSH's diagnostic
text is matched against fixed phrases only, to choose between them; the one value read from it is
the host key fingerprint OpenSSH itself verified (``observed_host_key``). It is never stored,
logged or shown otherwise.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import os
import re
import shlex
import shutil
import stat
import time
from collections import deque
from collections.abc import Buffer, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Final, NoReturn

from finishup.config.installation import socket_path_fits

if TYPE_CHECKING:
    from finishup.client.targets import ServerTarget

__all__ = [
    "CONTROL_PERSIST",
    "MASTER_NAME",
    "UPSTREAM_NAME",
    "RemotePeerIdentity",
    "SshControlStream",
    "SshMaster",
    "UpstreamUnavailable",
    "classify_ssh_failure",
    "control_argv",
    "destination",
    "direct_argv",
    "direct_remote_argv",
    "exit_master",
    "exit_master_now",
    "host_key_changed",
    "host_key_unconfirmed",
    "master_argv",
    "observed_host_key",
    "probe_argv",
    "remote_argv",
    "remote_command",
    "remote_command_line",
    "remove_owned_socket",
    "resolve_ssh",
    "run_ssh",
    "ssh_environment",
    "ssh_root_fits",
]

MASTER_NAME: Final = "m"
UPSTREAM_NAME: Final = "upstream.sock"
CONTROL_PERSIST: Final = "15m"
# OpenSSH binds a ControlPath at ``<path>.<16 random characters>`` and renames it into place.
_OPENSSH_TEMPORARY_SUFFIX: Final = 17
_MASTER_START_SECONDS: Final = 20.0
_REMOTE_COMMAND_SECONDS: Final = 30.0
_POLL_SECONDS: Final = 0.05
_STDERR_TAIL_BYTES: Final = 8_192
_MAX_RECEIVE_BYTES: Final = 65_536
_EXIT_WAIT_SECONDS: Final = 1.0
_TERMINATE_WAIT_SECONDS: Final = 0.5
_UNREACHABLE: Final = "remote_unreachable"
_REASONS: Final = frozenset(
    {
        "remote_auth_failed",
        "remote_identity_changed",
        "remote_incompatible",
        "remote_service_not_running",
        "remote_unreachable",
        "zero_network_remote_selected",
    }
)
_TRUST: Final = ("-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes")
_LIVENESS: Final = ("-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3")
# Fixed OpenSSH phrases, matched only to choose a closed reason.
_CHANGED_PHRASE: Final = b"REMOTE HOST IDENTIFICATION HAS CHANGED"
_IDENTITY_PHRASES: Final = (
    b"Host key verification failed",
    _CHANGED_PHRASE,
    b"host key is known",
)
_AUTH_PHRASES: Final = (
    b"Permission denied",
    b"Too many authentication failures",
    b"no mutual signature",
)
_NOT_RUNNING_PHRASES: Final = (
    b"Stdio forwarding request failed",
    b"open failed",
    b"Session open refused",
)
# ``debug1: Server host key: <type> SHA256:<43 base64 characters>``: the key OpenSSH verified.
_HOST_KEY_LINE: Final = re.compile(
    rb"^debug1: Server host key: ([A-Za-z0-9@._-]{1,64}) SHA256:([A-Za-z0-9+/]{43})\r?$",
    re.MULTILINE,
)


class UpstreamUnavailable(Exception):
    """The server could not be reached; ``reason`` is one closed remote connection phase."""

    def __init__(self, reason: str) -> None:
        if reason not in _REASONS:
            raise ValueError("upstream_reason_invalid")
        self.reason = reason
        super().__init__(reason)


def resolve_ssh() -> str:
    """The absolute ``ssh`` on this process's ``PATH``; ``remote_unreachable`` when there is none."""

    found = shutil.which("ssh")
    if found is None or not os.path.isabs(found):
        raise UpstreamUnavailable(_UNREACHABLE)
    return found


def ssh_environment() -> dict[str, str]:
    """The environment an ``ssh`` child gets: this process's, without FinishUP's own variables.

    OpenSSH needs the agent socket and the user's home; a FinishUP root variable must never ride a
    ``SendEnv`` line to the server, where it would pick a root the owner did not record.
    """

    from finishup.config.env import canonical_env_name

    return {name: value for name, value in os.environ.items() if canonical_env_name(name) is None}


def destination(record: ServerTarget) -> str:
    """``[user@]host`` for OpenSSH (``host`` and ``user`` were validated when recorded)."""

    if record.kind != "ssh" or record.host is None:
        raise ValueError("target_not_ssh")
    return record.host if record.user is None else f"{record.user}@{record.host}"


def _port(record: ServerTarget) -> str:
    if record.port is None:
        raise ValueError("target_not_ssh")
    return str(record.port)


def ssh_root_fits(root: Path) -> bool:
    """Whether the master's temporary bind path and the upstream socket fit ``sun_path``.

    The bound is the one ``server add`` checked the root against (``target_root_too_long``), so
    a root it accepted is never refused here.
    """

    master = root / "run" / MASTER_NAME
    return socket_path_fits(
        master, temporary_suffix_bytes=_OPENSSH_TEMPORARY_SUFFIX
    ) and socket_path_fits(root / "run" / UPSTREAM_NAME)


def _forward_path(text: str) -> str:
    # ``-L local:remote`` splits on ':'; a path that holds one, or whitespace, cannot be forwarded.
    if not text.startswith("/") or ":" in text or any(ord(c) <= 0x20 for c in text):
        raise UpstreamUnavailable(_UNREACHABLE)
    return text


def _endpoint(record: ServerTarget) -> str:
    if record.remote_endpoint is None:
        raise UpstreamUnavailable(_UNREACHABLE)
    return _forward_path(record.remote_endpoint)


def master_argv(ssh: str, root: Path, record: ServerTarget) -> tuple[str, ...]:
    """The relay master's exact argv: one warm connection, one stream-local forward."""

    local = _forward_path(str(root / "run" / UPSTREAM_NAME))
    return (
        ssh,
        "-M",
        "-S",
        str(root / "run" / MASTER_NAME),
        "-N",
        "-T",
        *_TRUST,
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "StreamLocalBindMask=0177",
        "-o",
        "StreamLocalBindUnlink=yes",
        *_LIVENESS,
        "-p",
        _port(record),
        "-L",
        f"{local}:{_endpoint(record)}",
        destination(record),
    )


def control_argv(ssh: str, root: Path, record: ServerTarget, operation: str) -> tuple[str, ...]:
    """``ssh -S <master> -O check|exit`` for this target's master (never by pattern)."""

    if operation not in {"check", "exit"}:
        raise ValueError("ssh_control_operation_invalid")
    return (
        ssh,
        "-S",
        str(root / "run" / MASTER_NAME),
        "-O",
        operation,
        "-p",
        _port(record),
        destination(record),
    )


def direct_argv(ssh: str, root: Path, record: ServerTarget) -> tuple[str, ...]:
    """One direct-style stream to the remote control endpoint (no secret, no shell).

    ``-W`` forwards standard input and output to the remote Unix socket over a channel of the
    shared ``ControlMaster=auto`` master (it implies ``-N``, ``-T`` and ``ExitOnForwardFailure``);
    the first stream leaves a master that persists for 15 idle minutes, so a later hook pays one
    channel open instead of a key exchange.
    """

    return (
        ssh,
        "-S",
        str(root / "run" / MASTER_NAME),
        "-o",
        "ControlMaster=auto",
        "-o",
        f"ControlPersist={CONTROL_PERSIST}",
        *_TRUST,
        *_LIVENESS,
        "-p",
        _port(record),
        "-W",
        _endpoint(record),
        destination(record),
    )


def remote_command_line(launcher: str, remote_root: str | None, *arguments: str) -> str:
    """One quoted remote command line, pinned to ``remote_root`` when the target names one."""

    from finishup.config.paths import ISOLATED_ROOT_ENV

    words = [launcher, *arguments]
    if remote_root is not None:
        words = ["env", f"{ISOLATED_ROOT_ENV}={remote_root}", *words]
    return shlex.join(words)


def remote_command(record: ServerTarget, *arguments: str) -> str:
    """The quoted remote command line: the recorded launcher, pinned to the remote root."""

    launcher = record.remote_launcher
    if launcher is None or not launcher.startswith("/"):
        raise UpstreamUnavailable("remote_service_not_running")
    return remote_command_line(launcher, record.remote_root, *arguments)


def remote_argv(ssh: str, root: Path, record: ServerTarget, *arguments: str) -> tuple[str, ...]:
    """A fixed remote command over the relay's running master, without a terminal."""

    return (
        ssh,
        "-S",
        str(root / "run" / MASTER_NAME),
        *_TRUST,
        "-T",
        "-p",
        _port(record),
        destination(record),
        "--",
        remote_command(record, *arguments),
    )


def direct_remote_argv(
    ssh: str, root: Path, record: ServerTarget, *arguments: str
) -> tuple[str, ...]:
    """A fixed remote command over the direct style's master (started when none runs)."""

    return (
        ssh,
        "-S",
        str(root / "run" / MASTER_NAME),
        "-o",
        "ControlMaster=auto",
        "-o",
        f"ControlPersist={CONTROL_PERSIST}",
        *_TRUST,
        "-T",
        "-p",
        _port(record),
        destination(record),
        "--",
        remote_command(record, *arguments),
    )


def probe_argv(
    ssh: str,
    *,
    user: str | None,
    host: str,
    port: int,
    command: str,
    ask: bool,
) -> tuple[str, ...]:
    """One discovery or profile command of ``server add``/``use`` and the helper's refresh.

    Never multiplexed (``ControlPath=none``) and verbose (``-v``), so the host key OpenSSH
    verified in this very connection can be read from its own line (``observed_host_key``). With
    ``ask`` (only on the owner's trusted console, after a strict attempt found the key unknown)
    OpenSSH itself asks to confirm a host key it does not know yet (``StrictHostKeyChecking=ask``);
    password and keyboard-interactive login stay off, so the host key is the only question and
    the add proves the key authentication every later ``BatchMode`` connection needs. Otherwise
    ``BatchMode`` with strict checking: nothing is asked and an unknown key is refused.
    """

    target = host if user is None else f"{user}@{host}"
    trust = (
        (
            "-o",
            "StrictHostKeyChecking=ask",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
        )
        if ask
        else _TRUST
    )
    return (
        ssh,
        "-v",
        "-o",
        "ControlPath=none",
        "-o",
        "ControlMaster=no",
        *trust,
        "-T",
        "-p",
        str(port),
        target,
        "--",
        command,
    )


def host_key_changed(stderr: bytes) -> bool:
    """Whether OpenSSH refused a host key that changed (never asked about: RE-7)."""

    return _CHANGED_PHRASE in stderr


def host_key_unconfirmed(stderr: bytes) -> bool:
    """Whether OpenSSH refused a host key it does not know, as opposed to one that changed.

    Strict checking says "No … host key is known for …"; a question the owner declined or did not
    answer says only "Host key verification failed". A changed key says "REMOTE HOST
    IDENTIFICATION HAS CHANGED", is never asked about, and stays ``remote_identity_changed``.
    """

    if host_key_changed(stderr):
        return False
    return b"host key is known" in stderr or b"Host key verification failed" in stderr


def classify_ssh_failure(returncode: int | None, stderr: bytes) -> str:
    """A closed reason for a failed OpenSSH run, chosen by fixed phrases only."""

    if any(phrase in stderr for phrase in _IDENTITY_PHRASES):
        return "remote_identity_changed"
    if any(phrase in stderr for phrase in _AUTH_PHRASES):
        return "remote_auth_failed"
    if any(phrase in stderr for phrase in _NOT_RUNNING_PHRASES):
        return "remote_service_not_running"
    del returncode
    return _UNREACHABLE


def observed_host_key(stderr: bytes) -> str | None:
    """The ``sha256:<hex>`` digest of the host key OpenSSH verified, from its own ``-v`` line.

    ``None`` when OpenSSH printed no such line, or more than one distinct key (never a guess).
    """

    found = {match.group(2) for match in _HOST_KEY_LINE.finditer(stderr)}
    if len(found) != 1:
        return None
    try:
        digest = base64.b64decode(found.pop() + b"=", validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(digest) != 32:
        return None
    return "sha256:" + digest.hex()


async def run_ssh(argv: Sequence[str], *, seconds: float) -> tuple[int | None, bytes, bytes]:
    """Run one fixed ``ssh`` argv to completion within ``seconds``: ``(code, stdout, stderr)``.

    ``code`` is ``None`` when it could not start or outlived its bound (it is then killed, by its
    own pid). Standard input is never the caller's; a host-key question OpenSSH asks (only with
    ``probe_argv(ask=True)``) is asked on the controlling terminal (``/dev/tty``), which the child
    shares with this process.
    """

    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=ssh_environment(),
            close_fds=True,
        )
    except OSError:
        return None, b"", b""
    try:
        async with asyncio.timeout(seconds):
            stdout, stderr = await process.communicate()
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        with contextlib.suppress(Exception):
            await process.wait()
        return None, b"", b""
    except BaseException:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        with contextlib.suppress(Exception):
            await asyncio.shield(process.wait())
        raise
    return process.returncode, stdout, stderr


def _owned_socket(path: Path) -> tuple[int, int] | None:
    """``(device, inode)`` of an owner-owned socket at ``path`` itself (never followed)."""

    try:
        facts = path.lstat()
    except OSError:
        return None
    if not stat.S_ISSOCK(facts.st_mode) or facts.st_uid != os.geteuid():
        return None
    return facts.st_dev, facts.st_ino


def remove_owned_socket(path: Path) -> None:
    """Unlink ``path`` when it is an owner-owned socket; anything else is left where it is.

    OpenSSH does not unlink a ``-L`` stream-local socket when the master exits, so every master
    that stops leaves ``upstream.sock`` behind; a master killed hard leaves its control socket.
    """

    if _owned_socket(path) is not None:
        with contextlib.suppress(FileNotFoundError):
            path.unlink()


async def exit_master(ssh: str, root: Path, record: ServerTarget) -> None:
    """Ask the master at ``<root>/run/m`` to exit through its control socket (never by pattern),
    then remove what it leaves behind. Bounded; never raises."""

    control = root / "run" / MASTER_NAME
    if _owned_socket(control) is not None:
        with contextlib.suppress(Exception):
            await run_ssh(control_argv(ssh, root, record, "exit"), seconds=2.0)
    for path in (control, root / "run" / UPSTREAM_NAME):
        remove_owned_socket(path)


def exit_master_now(ssh: str, root: Path, record: ServerTarget) -> None:
    """``exit_master`` for a caller with no event loop of its own, or inside one (synchronous).

    ``server use``, ``disconnect``, ``remove`` and ``set --style`` stop what this client runs for
    an SSH target from wherever they are called (a worker thread, a setup step inside an event
    loop). Bounded; never raises.
    """

    import subprocess

    control = root / "run" / MASTER_NAME
    if _owned_socket(control) is not None:
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            subprocess.run(  # noqa: S603 - fixed argv
                control_argv(ssh, root, record, "exit"),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=ssh_environment(),
                timeout=2.0,
                check=False,
            )
    for path in (control, root / "run" / UPSTREAM_NAME):
        remove_owned_socket(path)


class SshMaster:
    """The relay's OpenSSH master for one target, and the fixed commands it carries."""

    def __init__(self, root: Path, record: ServerTarget, *, ssh: str | None = None) -> None:
        if record.kind != "ssh":
            raise ValueError("target_not_ssh")
        self._root = root
        self._record = record
        self._ssh = ssh
        self._process: asyncio.subprocess.Process | None = None
        self._stderr: deque[bytes] = deque()
        self._stderr_task: asyncio.Task[None] | None = None
        self._lock = asyncio.Lock()

    @property
    def upstream_path(self) -> Path:
        return self._root / "run" / UPSTREAM_NAME

    @property
    def alive(self) -> bool:
        return self._process is not None and self._process.returncode is None

    def executable(self) -> str:
        if self._ssh is None:
            self._ssh = resolve_ssh()
        return self._ssh

    async def _drain_stderr(self, process: asyncio.subprocess.Process) -> None:
        stream = process.stderr
        if stream is None:
            return
        held = 0
        while chunk := await stream.read(1_024):
            self._stderr.append(chunk)
            held += len(chunk)
            while held > _STDERR_TAIL_BYTES and len(self._stderr) > 1:
                held -= len(self._stderr.popleft())

    async def ensure(self, *, deadline: float | None = None) -> None:
        """Start the master unless it runs; raise ``UpstreamUnavailable`` when it cannot.

        Bounded by ``_MASTER_START_SECONDS`` and by ``deadline`` (a monotonic time), whichever
        comes first; a master still starting when the bound passes is stopped.
        """

        async with self._lock:
            if self.alive and _owned_socket(self.upstream_path) is not None:
                return
            await self._stop_process()
            if not ssh_root_fits(self._root):
                raise UpstreamUnavailable(_UNREACHABLE)
            await exit_master(self.executable(), self._root, self._record)
            # Anything still at the forward's path was not this master's: readiness is a new
            # socket there, never the path existing.
            stale = _owned_socket(self.upstream_path)
            argv = master_argv(self.executable(), self._root, self._record)
            self._stderr.clear()
            try:
                process = await asyncio.create_subprocess_exec(
                    *argv,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                    env=ssh_environment(),
                    start_new_session=True,
                )
            except OSError:
                raise UpstreamUnavailable(_UNREACHABLE) from None
            self._process = process
            self._stderr_task = asyncio.create_task(self._drain_stderr(process))
            bound = time.monotonic() + _MASTER_START_SECONDS
            if deadline is not None:
                bound = min(bound, deadline)
            while time.monotonic() < bound:
                if process.returncode is not None:
                    break
                ready = _owned_socket(self.upstream_path)
                if ready is not None and ready != stale:
                    return
                await asyncio.sleep(_POLL_SECONDS)
            if process.returncode is None:
                await self._stop_process()
                raise UpstreamUnavailable(_UNREACHABLE)
            await asyncio.gather(self._stderr_task, return_exceptions=True)
            reason = classify_ssh_failure(process.returncode, b"".join(self._stderr))
            self._process = None
            raise UpstreamUnavailable(reason)

    async def run_remote(self, *arguments: str) -> int:
        """Run one fixed remote command over the master; its exit status (output discarded)."""

        await self.ensure()
        code, _stdout, _stderr = await run_ssh(
            remote_argv(self.executable(), self._root, self._record, *arguments),
            seconds=_REMOTE_COMMAND_SECONDS,
        )
        return 255 if code is None else code

    async def _stop_process(self) -> None:
        process = self._process
        self._process = None
        if process is not None and process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.terminate()
            try:
                async with asyncio.timeout(2.0):
                    await process.wait()
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
                await process.wait()
        task = self._stderr_task
        self._stderr_task = None
        if task is not None:
            await asyncio.gather(task, return_exceptions=True)

    async def close(self) -> None:
        """Ask the master to exit through its control socket, reap it, remove its forward."""

        if self.alive:
            with contextlib.suppress(Exception):
                await run_ssh(
                    control_argv(self.executable(), self._root, self._record, "exit"),
                    seconds=2.0,
                )
        async with self._lock:
            await self._stop_process()
            remove_owned_socket(self.upstream_path)
            remove_owned_socket(self._root / "run" / MASTER_NAME)


class RemotePeerIdentity:
    """Opaque, nonserializable peer of one direct stream; it names only the transport kind.

    The control session needs a peer object; a direct stream's real peer is the login the server
    authenticated, which this client never holds.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return "RemotePeerIdentity(ssh)"

    def __reduce__(self) -> NoReturn:
        raise TypeError("remote_peer_identity_not_serializable")


class SshControlStream:
    """One direct-style ``ssh -W`` child whose standard input and output carry the frames."""

    __slots__ = ("_closed", "_peer", "_process", "_stderr", "_stderr_task")

    def __init__(self, process: asyncio.subprocess.Process) -> None:
        self._process = process
        self._peer = RemotePeerIdentity()
        self._closed = False
        self._stderr = bytearray()
        self._stderr_task = asyncio.create_task(self._drain_stderr())

    @classmethod
    async def open(cls, argv: Sequence[str]) -> SshControlStream:
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=ssh_environment(),
                close_fds=True,
            )
        except OSError:
            raise UpstreamUnavailable(_UNREACHABLE) from None
        return cls(process)

    @property
    def peer_identity(self) -> RemotePeerIdentity:
        return self._peer

    @property
    def pid(self) -> int:
        return self._process.pid

    async def _drain_stderr(self) -> None:
        reader = self._process.stderr
        if reader is None:
            return
        with contextlib.suppress(Exception):
            while chunk := await reader.read(4_096):
                room = _STDERR_TAIL_BYTES - len(self._stderr)
                if room > 0:
                    self._stderr.extend(chunk[:room])

    async def receive(self, max_bytes: int = _MAX_RECEIVE_BYTES) -> bytes:
        if type(max_bytes) is not int or not 1 <= max_bytes <= _MAX_RECEIVE_BYTES:
            raise ValueError("receive_size_invalid")
        reader = self._process.stdout
        if self._closed or reader is None:
            return b""
        try:
            return await reader.read(max_bytes)
        except (OSError, ValueError):
            return b""

    async def send_all(self, data: Buffer) -> None:
        from finishup.adapters.control.unix_socket import LocalControlTransportError

        writer = self._process.stdin
        if self._closed or writer is None:
            raise LocalControlTransportError("connection_failed")
        view = memoryview(data)
        if view.ndim != 1 or not view.contiguous:
            raise TypeError("send_buffer_invalid")
        try:
            writer.write(view.tobytes())
            await writer.drain()
        except (OSError, RuntimeError):
            raise LocalControlTransportError("connection_failed") from None

    async def shutdown_write(self) -> None:
        """End what this stream sends (OpenSSH passes the end of input on to the server)."""

        writer = self._process.stdin
        if writer is not None and not self._closed:
            with contextlib.suppress(Exception):
                writer.close()

    async def _wait_exit(self, seconds: float) -> int | None:
        try:
            async with asyncio.timeout(seconds):
                return await self._process.wait()
        except TimeoutError:
            return None

    async def failure_phase(self) -> str | None:
        """Why this stream ended, once ``ssh`` exited (bounded); ``None`` when it ended cleanly.

        A stream the remote endpoint closed (the server answered or refused the hello) exits 0.
        """

        returncode = self._process.returncode
        if returncode is None:
            returncode = await self._wait_exit(_EXIT_WAIT_SECONDS)
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(_TERMINATE_WAIT_SECONDS):
                await asyncio.shield(self._stderr_task)
        if returncode is None or returncode <= 0:
            return None
        return classify_ssh_failure(returncode, bytes(self._stderr))

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        writer = self._process.stdin
        if writer is not None:
            with contextlib.suppress(Exception):
                writer.close()
        if self._process.returncode is None:
            # Only the child this stream spawned is signalled, by its own pid (AGENTS.md hazard 2).
            # The shared master is a separate process and stays up for the next stream.
            with contextlib.suppress(ProcessLookupError):
                self._process.terminate()
            if await self._wait_exit(_TERMINATE_WAIT_SECONDS) is None:
                with contextlib.suppress(ProcessLookupError):
                    self._process.kill()
                await self._wait_exit(_TERMINATE_WAIT_SECONDS)
        self._stderr_task.cancel()
        await asyncio.gather(self._stderr_task, return_exceptions=True)
