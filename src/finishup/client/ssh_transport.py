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

**The consented host key, on every new connection** (ADR-052). ``known_hosts`` decides whether
OpenSSH connects at all; the owner's consent is bound to one host key (the envelope's endpoint
identity, ``server_profile.consented_host_key``). So every OpenSSH connection FinishUP makes to a
target runs at ``LogLevel=DEBUG1`` and must print exactly that key in its ``Server host key`` line
before anything is sent over it: the relay's master before its forward is used, the direct
style's master before it is recorded, and a direct stream or remote command that made its own
connection (no master answered) before its first byte. A master is reused only as verified: the
relay's by the helper that started it, the direct style's by its owner-only record
(``state/ssh-master.json``: the key and the control socket it was verified with), made under a
lock (``state/ssh-master.lock``) so no stream rides a master nobody verified yet. Another key is
``remote_identity_changed``: nothing is sent, and the master is asked to exit.

Failures are closed reasons (``protocol.errors.REMOTE_CONNECTION_PHASES``). OpenSSH's diagnostic
text is matched against fixed phrases only, to choose between them; the one value read from it is
the host key fingerprint OpenSSH itself verified (``observed_host_key``). It is never stored,
logged or shown otherwise, except as the digest a verified master is recorded with.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import errno
import fcntl
import json
import os
import re
import secrets
import shlex
import shutil
import stat
import time
from collections import deque
from collections.abc import AsyncGenerator, Buffer, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Final, NoReturn, cast

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
    "direct_master_argv",
    "direct_remote_argv",
    "ensure_direct_master",
    "exit_master",
    "exit_master_now",
    "forwardable_path",
    "host_key_changed",
    "host_key_unconfirmed",
    "host_keys",
    "master_argv",
    "observed_host_key",
    "open_direct_stream",
    "probe_argv",
    "remote_argv",
    "remote_command",
    "remote_command_line",
    "remove_owned_socket",
    "require_host_key",
    "resolve_ssh",
    "run_ssh",
    "ssh_environment",
    "ssh_paths_usable",
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
# What one fixed remote command or probe may write on each stream before it is killed.
_MAX_OUTPUT_BYTES: Final = 65_536
_READ_CHUNK: Final = 8_192
_REAP_SECONDS: Final = 5.0
_EXIT_WAIT_SECONDS: Final = 1.0
_TERMINATE_WAIT_SECONDS: Final = 0.5
_UNREACHABLE: Final = "remote_unreachable"
_IDENTITY_CHANGED: Final = "remote_identity_changed"
_CHECK_SECONDS: Final = 2.0
_MASTER_RECORD_NAME: Final = "ssh-master.json"
_MASTER_RECORD_SCHEMA: Final = "yoetz.ssh-master/1"
_MASTER_LOCK_NAME: Final = "ssh-master.lock"
_MAX_MASTER_RECORD_BYTES: Final = 512
_MAX_LINE_BYTES: Final = 4_096
_REASONS: Final = frozenset(
    {
        "remote_auth_failed",
        "remote_identity_changed",
        "remote_incompatible",
        "remote_service_not_running",
        "remote_unreachable",
        # A REST upstream's server refused the consented revision (ADR-053): the helper names it.
        "server_profile_changed",
        "zero_network_remote_selected",
    }
)
_TRUST: Final = ("-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes")
_LIVENESS: Final = ("-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3")
# Every connection's own ``Server host key`` line (and a stream's multiplexing line) is printed at
# this level. Set as an option, never ``-v``: a master backgrounded by ``ControlPersist`` then
# leaves its standard error to ``/dev/null`` instead of holding the caller's pipe.
_DEBUG: Final = ("-o", "LogLevel=DEBUG1")
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
# ``debug1: mux_client_request_stdio_fwd: master session id: N``: a ``-W`` stream rides a master.
_MUX_STDIO_LINE: Final = re.compile(
    rb"^debug1: mux_client_request_stdio_fwd: master session id: [0-9]{1,10}\r?$"
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


# ``-L local:remote`` splits on ':', and OpenSSH expands ``%`` tokens and ``${VAR}`` in a forward's
# and a ControlPath's socket paths: a path holding any of them, or a control character, cannot be
# handed to it verbatim. A space can (the default root on macOS lives under "Application Support").
_UNFORWARDABLE: Final = frozenset(":%$")


def forwardable_path(text: str) -> bool:
    """Whether OpenSSH takes ``text`` as a socket path verbatim (absolute, none of ``:%$``, no
    control character); spaces are fine."""

    return text.startswith("/") and not any(
        character in _UNFORWARDABLE or ord(character) < 0x20 or ord(character) == 0x7F
        for character in text
    )


def ssh_paths_usable(root: Path, remote_endpoint: str | None = None) -> bool:
    """Whether every socket path OpenSSH is given for the target at ``root`` is taken verbatim.

    Its master's ControlPath and the relay's forward beneath ``root``, and the server's
    ``remote_endpoint`` when given. ``server add`` checks it before a target is recorded.
    """

    local = (root / "run" / MASTER_NAME, root / "run" / UPSTREAM_NAME)
    return all(forwardable_path(str(path)) for path in local) and (
        remote_endpoint is None or forwardable_path(remote_endpoint)
    )


def _forward_path(text: str) -> str:
    if not forwardable_path(text):
        raise UpstreamUnavailable(_UNREACHABLE)
    return text


def _control_path(root: Path) -> str:
    return _forward_path(str(root / "run" / MASTER_NAME))


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
        _control_path(root),
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
        *_DEBUG,
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
        _control_path(root),
        "-O",
        operation,
        "-p",
        _port(record),
        destination(record),
    )


def direct_argv(ssh: str, root: Path, record: ServerTarget) -> tuple[str, ...]:
    """One direct-style stream to the remote control endpoint (no secret, no shell).

    ``-W`` forwards standard input and output to the remote Unix socket over a channel of the
    target's verified master (``ensure_direct_master``; it implies ``-N``, ``-T`` and
    ``ExitOnForwardFailure``), so a later hook pays one channel open instead of a key exchange.
    ``ControlMaster=no``: a stream never becomes a master itself. When no master answers, OpenSSH
    connects on its own; its host key line is then checked before the stream is used
    (``SshControlStream.verify``).
    """

    return (
        ssh,
        "-S",
        _control_path(root),
        "-o",
        "ControlMaster=no",
        *_TRUST,
        *_LIVENESS,
        *_DEBUG,
        "-p",
        _port(record),
        "-W",
        _endpoint(record),
        destination(record),
    )


def direct_master_argv(ssh: str, root: Path, record: ServerTarget) -> tuple[str, ...]:
    """The direct style's master: it authenticates, then persists for 15 idle minutes.

    With ``ControlPersist`` and ``-N`` OpenSSH backgrounds the master once it listens and the
    command exits 0; its standard error (the host key line) is read to verify it first.
    """

    return (
        ssh,
        "-M",
        "-S",
        _control_path(root),
        "-o",
        f"ControlPersist={CONTROL_PERSIST}",
        "-N",
        "-T",
        *_TRUST,
        *_LIVENESS,
        *_DEBUG,
        "-p",
        _port(record),
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
        _control_path(root),
        "-o",
        "ControlMaster=no",
        *_TRUST,
        *_DEBUG,
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
    """A fixed remote command over the direct style's verified master (``ensure_direct_master``)."""

    return (
        ssh,
        "-S",
        _control_path(root),
        "-o",
        "ControlMaster=no",
        *_TRUST,
        *_DEBUG,
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


def _digest_of(fingerprint: bytes) -> str | None:
    try:
        digest = base64.b64decode(fingerprint + b"=", validate=True)
    except (binascii.Error, ValueError):
        return None
    return "sha256:" + digest.hex() if len(digest) == 32 else None


def host_keys(stderr: bytes) -> frozenset[str]:
    """Every distinct host key OpenSSH printed verifying a connection it made (``sha256:<hex>``).

    Empty when it made none of its own (it rode a master) or printed no such line.
    """

    found = (_digest_of(match.group(2)) for match in _HOST_KEY_LINE.finditer(stderr))
    return frozenset(key for key in found if key is not None)


def require_host_key(stderr: bytes, expected: str | None) -> None:
    """Refuse a connection OpenSSH made itself unless it verified exactly the consented key.

    ``remote_identity_changed`` when ``stderr`` names any other host key (or ``expected`` is
    ``None``). A run that printed none rode a master, which its caller verified.
    """

    keys = host_keys(stderr)
    if keys and (expected is None or keys != frozenset((expected,))):
        raise UpstreamUnavailable(_IDENTITY_CHANGED)


class _OutputExceeded(Exception):
    """One of a command's streams outgrew its bound while it was read."""


async def _read_bounded(reader: asyncio.StreamReader | None, limit: int, sink: bytearray) -> None:
    """Read ``reader`` to its end into ``sink``; ``_OutputExceeded`` past ``limit`` bytes."""

    if reader is None:
        return
    while chunk := await reader.read(_READ_CHUNK):
        if len(sink) + len(chunk) > limit:
            raise _OutputExceeded
        sink.extend(chunk)


async def run_ssh(
    argv: Sequence[str],
    *,
    seconds: float,
    stdout_limit: int = _MAX_OUTPUT_BYTES,
    stderr_limit: int = _MAX_OUTPUT_BYTES,
) -> tuple[int | None, bytes, bytes]:
    """Run one fixed ``ssh`` argv to completion within ``seconds``: ``(code, stdout, stderr)``.

    ``code`` is ``None`` when it could not start or outlived its bound (it is then killed, by its
    own pid, and reaped). Both streams are read as they arrive and bounded while they are read
    (64 KiB each by default): a command that writes more is killed and reaped at once and
    raises ``UpstreamUnavailable("remote_incompatible")`` (a launcher that is not this release's
    FinishUP), so a faulty or hostile one never fills this process's memory. Standard input is
    never the caller's; a host-key question OpenSSH asks (only with ``probe_argv(ask=True)``) is
    asked on the controlling terminal (``/dev/tty``), which the child shares with this process.
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
    stdout, stderr = bytearray(), bytearray()
    readers = (
        asyncio.create_task(_read_bounded(process.stdout, stdout_limit, stdout)),
        asyncio.create_task(_read_bounded(process.stderr, stderr_limit, stderr)),
    )
    try:
        async with asyncio.timeout(seconds):
            await asyncio.wait(readers, return_when=asyncio.FIRST_EXCEPTION)
            for reader in readers:
                if reader.done() and reader.exception() is not None:
                    raise _OutputExceeded
            await asyncio.gather(*readers)
            await process.wait()
    except TimeoutError:
        await _kill_and_reap(process, readers)
        return None, b"", b""
    except _OutputExceeded:
        await _kill_and_reap(process, readers)
        raise UpstreamUnavailable("remote_incompatible") from None
    except BaseException:
        await _kill_and_reap(process, readers)
        raise
    return process.returncode, bytes(stdout), bytes(stderr)


async def _discard(reader: asyncio.StreamReader | None) -> None:
    if reader is None:
        return
    with contextlib.suppress(Exception):
        while await reader.read(_READ_CHUNK):
            pass


async def _kill_and_reap(
    process: asyncio.subprocess.Process, readers: Sequence[asyncio.Task[None]] = ()
) -> None:
    """Kill ``process`` by its own pid and wait for it, a cancellation of the caller included.

    Its stream readers end; what is left in its pipes is read and dropped, so a pipe paused on
    an unread buffer still reaches its end and the wait finishes (bounded: a process that
    handed its pipe on keeps nothing waiting here). The system's child watcher reaps it once it
    exits, whatever this wait sees.
    """

    with contextlib.suppress(ProcessLookupError):
        process.kill()
    for reader in readers:
        reader.cancel()
    await asyncio.gather(*readers, return_exceptions=True)
    ending = asyncio.gather(_discard(process.stdout), _discard(process.stderr), process.wait())
    with contextlib.suppress(Exception):
        async with asyncio.timeout(_REAP_SECONDS):
            await asyncio.shield(ending)


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
    _forget_master(root)
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
    _forget_master(root)
    if _owned_socket(control) is not None:
        with contextlib.suppress(OSError, subprocess.SubprocessError, UpstreamUnavailable):
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


class _LineWatch:
    """OpenSSH's standard error, read line by line for the lines a connection is verified by.

    ``keys``: every distinct host key a ``Server host key`` line named; ``muxed``: a ``-W``
    stream's multiplexing line was printed (it rides a master). ``settled`` is set at the first
    of either, and when the stream ends.
    """

    __slots__ = ("_pending", "keys", "muxed", "settled")

    def __init__(self) -> None:
        self._pending = bytearray()
        self.keys: set[str] = set()
        self.muxed = False
        self.settled = asyncio.Event()

    def feed(self, chunk: bytes) -> None:
        self._pending.extend(chunk)
        while (end := self._pending.find(b"\n")) >= 0:
            self._line(bytes(self._pending[:end]))
            del self._pending[: end + 1]
        if len(self._pending) > _MAX_LINE_BYTES:
            # An endless line is no line OpenSSH prints for a connection: dropped unread.
            self._pending.clear()

    def _line(self, line: bytes) -> None:
        found = _HOST_KEY_LINE.match(line)
        if found is not None:
            key = _digest_of(found.group(2))
            if key is not None:
                self.keys.add(key)
                self.settled.set()
        elif _MUX_STDIO_LINE.match(line) is not None:
            self.muxed = True
            self.settled.set()

    def finish(self) -> None:
        self.settled.set()


# --- the direct style's verified master ---------------------------------------------------------


def _bounded(seconds: float, deadline: float | None) -> float:
    if deadline is None:
        return seconds
    return max(0.0, min(seconds, deadline - time.monotonic()))


def _master_record_path(root: Path) -> Path:
    return root / "state" / _MASTER_RECORD_NAME


def _read_master(root: Path) -> tuple[str, tuple[int, int]] | None:
    """``(host key, control socket identity)`` of the verified master record; ``None`` else.

    Owner-only, regular, never followed, bounded; anything else is no record (never trusted).
    """

    try:
        descriptor = os.open(
            _master_record_path(root), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        )
    except OSError:
        return None
    try:
        facts = os.fstat(descriptor)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != os.geteuid()
            or stat.S_IMODE(facts.st_mode) & 0o077
            or facts.st_size > _MAX_MASTER_RECORD_BYTES
        ):
            return None
        data = os.read(descriptor, _MAX_MASTER_RECORD_BYTES + 1)
    except OSError:
        return None
    finally:
        os.close(descriptor)
    try:
        parsed: object = json.loads(data)
    except ValueError:
        return None
    if type(parsed) is not dict:
        return None
    body = cast("dict[str, object]", parsed)
    key = body.get("host_key")
    socket_id = body.get("socket")
    if (
        set(body) != {"schema", "host_key", "socket"}
        or body.get("schema") != _MASTER_RECORD_SCHEMA
        or type(key) is not str
        or type(socket_id) is not list
    ):
        return None
    items = cast("list[object]", socket_id)
    device, inode = items if len(items) == 2 else (None, None)
    if type(device) is not int or type(inode) is not int:
        return None
    return key, (device, inode)


def _record_master(root: Path, key: str, socket_id: tuple[int, int]) -> None:
    """Record the verified master atomically (owner-only temp, fsync, rename); never raises."""

    path = _master_record_path(root)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    body = {"schema": _MASTER_RECORD_SCHEMA, "host_key": key, "socket": list(socket_id)}
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    try:
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
        )
        try:
            os.write(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
    except OSError:
        with contextlib.suppress(OSError):
            temporary.unlink()


def _forget_master(root: Path) -> None:
    with contextlib.suppress(OSError):
        _master_record_path(root).unlink()


@contextlib.asynccontextmanager
async def _master_lock(root: Path, deadline: float | None) -> AsyncGenerator[None]:
    """The target's master lock (``state/ssh-master.lock``), waited for within ``deadline``.

    Every process that verifies, starts or replaces the direct style's master holds it, so a
    master is recorded verified before any stream can ride it.
    """

    try:
        descriptor = os.open(
            root / "state" / _MASTER_LOCK_NAME,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
    except OSError:
        raise UpstreamUnavailable(_UNREACHABLE) from None
    try:
        facts = os.fstat(descriptor)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != os.geteuid()
            or stat.S_IMODE(facts.st_mode) & 0o077
        ):
            raise UpstreamUnavailable(_UNREACHABLE)
        bound = time.monotonic() + _bounded(_MASTER_START_SECONDS, deadline)
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in {errno.EWOULDBLOCK, errno.EAGAIN}:
                    raise UpstreamUnavailable(_UNREACHABLE) from None
            if time.monotonic() >= bound:
                raise UpstreamUnavailable(_UNREACHABLE)
            await asyncio.sleep(_POLL_SECONDS)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


async def ensure_direct_master(
    ssh: str,
    root: Path,
    record: ServerTarget,
    *,
    expected: str | None,
    deadline: float | None = None,
) -> None:
    """A running direct-style master that verified the consented host key ``expected``.

    Reused only when its control socket is the one recorded verified with ``expected`` and it
    answers ``-O check``; anything else at its path (an older master, one verified for another
    consent, a relay master, a stale socket) is asked to exit, and a new one is started, its host
    key line read and compared before it is recorded. Another key is ``remote_identity_changed``
    (the new master is asked to exit at once: nothing was sent over it). Raises
    ``UpstreamUnavailable``.
    """

    if expected is None:
        raise UpstreamUnavailable(_IDENTITY_CHANGED)
    if not ssh_root_fits(root):
        raise UpstreamUnavailable(_UNREACHABLE)
    control = root / "run" / MASTER_NAME
    async with _master_lock(root, deadline):
        current = _owned_socket(control)
        if current is not None and _read_master(root) == (expected, current):
            code, _stdout, _stderr = await run_ssh(
                control_argv(ssh, root, record, "check"),
                seconds=_bounded(_CHECK_SECONDS, deadline),
            )
            if code == 0:
                return
        await exit_master(ssh, root, record)
        code, _stdout, stderr = await run_ssh(
            direct_master_argv(ssh, root, record),
            seconds=_bounded(_MASTER_START_SECONDS, deadline),
        )
        if code != 0:
            # Whatever it left behind (a master that backgrounded before the bound) is asked to
            # exit; nothing was sent over it.
            await exit_master(ssh, root, record)
            reason = _UNREACHABLE if code is None else classify_ssh_failure(code, stderr)
            raise UpstreamUnavailable(reason)
        started = _owned_socket(control)
        if host_keys(stderr) != frozenset((expected,)) or started is None:
            await exit_master(ssh, root, record)
            raise UpstreamUnavailable(_IDENTITY_CHANGED if started is not None else _UNREACHABLE)
        _record_master(root, expected, started)


async def open_direct_stream(
    ssh: str,
    root: Path,
    record: ServerTarget,
    *,
    expected: str | None,
    deadline: float | None = None,
) -> SshControlStream:
    """One direct-style ``ssh -W`` stream, verified before it is handed back (see the module text).

    The master first (``ensure_direct_master``); then the stream, used only once OpenSSH said it
    rode that master or verified ``expected`` over a connection of its own.
    """

    await ensure_direct_master(ssh, root, record, expected=expected, deadline=deadline)
    stream = await SshControlStream.open(direct_argv(ssh, root, record))
    try:
        await stream.verify(expected, deadline=deadline)
    except BaseException:
        with contextlib.suppress(Exception):
            await asyncio.shield(stream.aclose())
        raise
    return stream


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
        self._watch = _LineWatch()
        # The consented host key the running master verified; ``None`` while none is verified.
        self._verified: str | None = None

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
        watch = self._watch
        try:
            while chunk := await stream.read(1_024):
                watch.feed(chunk)
                self._stderr.append(chunk)
                held += len(chunk)
                while held > _STDERR_TAIL_BYTES and len(self._stderr) > 1:
                    held -= len(self._stderr.popleft())
        finally:
            watch.finish()

    async def ensure(self, *, expected: str | None, deadline: float | None = None) -> None:
        """A running master that verified the consented host key ``expected``; else raise.

        A running master is reused only when it verified ``expected`` (the consent may have
        changed since it started); otherwise it is replaced. A new master is ready once its
        forward listens **and** its ``Server host key`` line named ``expected``; another key is
        ``remote_identity_changed`` and the master is stopped before anything is sent over it.
        Bounded by ``_MASTER_START_SECONDS`` and by ``deadline`` (a monotonic time); a master
        still starting when the bound passes, or when the caller is cancelled, is stopped.
        Raises ``UpstreamUnavailable``.
        """

        if expected is None:
            raise UpstreamUnavailable(_IDENTITY_CHANGED)
        async with self._lock:
            if (
                self.alive
                and self._verified == expected
                and _owned_socket(self.upstream_path) is not None
            ):
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
            self._watch = _LineWatch()
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
            try:
                await self._await_verified(process, stale, expected, deadline)
            except BaseException:
                # Not verified (another key, no key, a bound passed, a cancellation): the
                # master that started is stopped; nothing was sent over it.
                await asyncio.shield(self._stop_process())
                raise

    async def _await_verified(
        self,
        process: asyncio.subprocess.Process,
        stale: tuple[int, int] | None,
        expected: str,
        deadline: float | None,
    ) -> None:
        bound = time.monotonic() + _bounded(_MASTER_START_SECONDS, deadline)
        while time.monotonic() < bound:
            if process.returncode is not None:
                break
            keys = self._watch.keys
            if keys and keys != {expected}:
                raise UpstreamUnavailable(_IDENTITY_CHANGED)
            ready = _owned_socket(self.upstream_path)
            if ready is not None and ready != stale and keys == {expected}:
                self._verified = expected
                return
            await asyncio.sleep(_POLL_SECONDS)
        if process.returncode is None:
            listening = _owned_socket(self.upstream_path) not in {None, stale}
            # Listening, but it never named the consented key (a host certificate, a line this
            # OpenSSH does not print): never trusted.
            raise UpstreamUnavailable(_IDENTITY_CHANGED if listening else _UNREACHABLE)
        if self._stderr_task is not None:
            await asyncio.gather(self._stderr_task, return_exceptions=True)
        raise UpstreamUnavailable(classify_ssh_failure(process.returncode, b"".join(self._stderr)))

    async def run_remote(self, *arguments: str, expected: str | None) -> int:
        """Run one fixed remote command over the verified master; its exit status.

        Its output is discarded; a command that connected on its own (the master had just gone)
        and verified another host key is ``remote_identity_changed``.
        """

        await self.ensure(expected=expected)
        code, _stdout, stderr = await run_ssh(
            remote_argv(self.executable(), self._root, self._record, *arguments),
            seconds=_REMOTE_COMMAND_SECONDS,
        )
        require_host_key(stderr, expected)
        return 255 if code is None else code

    async def _stop_process(self, seconds: float = 2.0) -> None:
        process = self._process
        self._process = None
        self._verified = None
        if process is not None and process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.terminate()
            try:
                async with asyncio.timeout(seconds):
                    await process.wait()
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
                await process.wait()
        task = self._stderr_task
        self._stderr_task = None
        if task is not None:
            await asyncio.gather(task, return_exceptions=True)

    async def close(self, seconds: float | None = None) -> None:
        """Ask the master to exit through its control socket, reap it, remove its forward.

        Within about ``seconds`` when given (a stopping helper's share of its deadline): half
        for the exit request, the rest for the master to end before it is killed and reaped.
        Without it, two seconds each."""

        asking, ending = (2.0, 2.0) if seconds is None else (max(seconds, 0.2) / 2,) * 2
        if self.alive:
            with contextlib.suppress(Exception):
                await run_ssh(
                    control_argv(self.executable(), self._root, self._record, "exit"),
                    seconds=asking,
                )
        async with self._lock:
            await self._stop_process(ending)
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

    __slots__ = ("_closed", "_peer", "_process", "_stderr", "_stderr_task", "_watch")

    def __init__(self, process: asyncio.subprocess.Process) -> None:
        self._process = process
        self._peer = RemotePeerIdentity()
        self._closed = False
        self._stderr = bytearray()
        self._watch = _LineWatch()
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
        try:
            if reader is None:
                return
            with contextlib.suppress(Exception):
                while chunk := await reader.read(4_096):
                    self._watch.feed(chunk)
                    room = _STDERR_TAIL_BYTES - len(self._stderr)
                    if room > 0:
                        self._stderr.extend(chunk[:room])
        finally:
            self._watch.finish()

    async def verify(self, expected: str | None, *, deadline: float | None = None) -> None:
        """Return once this stream may carry a hello: it rode the verified master, or it made a
        connection of its own whose ``Server host key`` line named exactly ``expected``.

        ``remote_identity_changed`` for another key; the phase it ended with when it ended first;
        ``remote_unreachable`` when OpenSSH said neither within the bound. Raises
        ``UpstreamUnavailable``; nothing has been written to the stream.
        """

        try:
            async with asyncio.timeout(_bounded(_MASTER_START_SECONDS, deadline)):
                await self._watch.settled.wait()
        except TimeoutError:
            raise UpstreamUnavailable(_UNREACHABLE) from None
        keys = self._watch.keys
        if keys:
            if keys != {expected}:
                raise UpstreamUnavailable(_IDENTITY_CHANGED)
            return
        if self._watch.muxed:
            return
        phase: str | None = None
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(_bounded(_EXIT_WAIT_SECONDS, deadline)):
                phase = await self.failure_phase()
        raise UpstreamUnavailable(phase or _UNREACHABLE)

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
        """``ssh``'s exit status once it exited, or ``None`` while it still runs past ``seconds``.

        What is left on its output is read and dropped (a wait also waits for its pipes, and an
        unread one would never reach its end).
        """

        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(seconds):
                await asyncio.gather(_discard(self._process.stdout), self._process.wait())
        return self._process.returncode

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
        try:
            if self._process.returncode is None:
                # Only the child this stream spawned is signalled, by its own pid (AGENTS.md
                # hazard 2). The shared master is a separate process and stays up.
                with contextlib.suppress(ProcessLookupError):
                    self._process.terminate()
                if await self._wait_exit(_TERMINATE_WAIT_SECONDS) is None:
                    with contextlib.suppress(ProcessLookupError):
                        self._process.kill()
                    await self._wait_exit(_TERMINATE_WAIT_SECONDS)
        except BaseException:
            # The caller's deadline cancelled the close (``service.client`` bounds it): the child
            # is killed now and a task of its own waits for it, so it ends and is reaped whatever
            # the caller does next; this stream is closed either way.
            with contextlib.suppress(ProcessLookupError):
                self._process.kill()
            _finish_later(self._process, self._stderr_task)
            raise
        self._stderr_task.cancel()
        await asyncio.gather(self._stderr_task, return_exceptions=True)


# The waits a cancelled close left behind, held until each child ended (a task needs a reference).
_FINISHING: set[asyncio.Task[None]] = set()


def _finish_later(process: asyncio.subprocess.Process, stderr: asyncio.Task[None]) -> None:
    async def finish() -> None:
        try:
            await _kill_and_reap(process)
        finally:
            stderr.cancel()
            await asyncio.gather(stderr, return_exceptions=True)

    task = asyncio.get_running_loop().create_task(finish())
    _FINISHING.add(task)
    task.add_done_callback(_FINISHING.discard)
