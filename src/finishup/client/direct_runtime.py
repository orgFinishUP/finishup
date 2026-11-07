"""Target runtimes and server checks of the direct-dial topology (ADR-051, approach B).

``finishup server connect|disconnect|test|status`` reach a remote target through these runtimes
(``client.target_runtime`` registers them for ``ssh``, ``https`` and ``local_port``):

* **SSH.** ``ensure_ready`` starts (or reuses) the target's OpenSSH master at
  ``<root>/run/m`` with ``ssh -fN`` and the same trust options every stream uses, then connects on
  demand, which starts an idle-stopped remote service through the recorded launcher.
  ``stop`` asks that master to exit by its control path (``ssh -O exit``); nothing is ever found
  or signalled by pattern. ``probe`` times status round trips over the real transport.
* **HTTPS and localhost ports.** ``ensure_ready`` asks the gateway who it is
  (``GET /v1/server``) with the stored key; there is no client-side process, so ``stop`` has
  nothing to stop (the gateway expires idle sessions). ``probe`` is the same timed status probe.

``discover_ssh_endpoint`` is what ``server add ssh://…`` runs once the owner has authorized the
target: the server's own ``finishup service endpoint --json`` through the recorded launcher (or
one found at a fixed list of install paths, never a bare ``finishup`` on the remote ``PATH``). It
returns the remote control endpoint to record and checks that the server runs this client's
schema manifest. ``server add`` runs it only after the owner's typed confirmation on the trusted
console, with ``confirm_host_key``: it is the one interactive ``ssh`` of the topology, where
OpenSSH itself asks, on that terminal, to confirm a host key it does not know yet
(``StrictHostKeyChecking=ask``), as approach A's ``server add`` does, and that confirmation is the
pin every later ``BatchMode`` connection checks (``StrictHostKeyChecking=yes``). Without
``confirm_host_key`` it never asks. Either way a host key that was not confirmed is
``remote_host_key_unconfirmed``.

While this computer last reported a zero-network privacy policy (ADR-051 decision 8,
``client.everyday_policy``) ``ensure_ready`` starts nothing and sends nothing
(``zero_network_remote_selected``), and ``close_ssh_masters`` asks every SSH master this client
holds to exit: an OpenSSH master cannot read that record itself, so the client processes that
find it close the masters for it (the MCP bridge's background work and ``finishup server connect
NAME --agent`` every second while they run, and the command that records it).

Every failure is a ``TargetRuntimeError`` with closed tokens; OpenSSH's own diagnostics are
classified and dropped, never shown.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from finishup.client.target_runtime import ProbeResult, TargetRuntimeError, probe_service
from finishup.client.targets import ServerTarget, TargetError, read_target
from finishup.client.transports import (
    TransportError,
    classify_ssh_failure,
    ssh_control_argv,
    ssh_environment,
    ssh_master_argv,
)

__all__ = [
    "SSH_LAUNCHER_CANDIDATES",
    "HttpsTargetRuntime",
    "SshEndpoint",
    "SshTargetRuntime",
    "close_ssh_masters",
    "discover_ssh_endpoint",
    "ssh_master_present",
]

type _Runner = Callable[..., subprocess.CompletedProcess[bytes]]

_MASTER_SECONDS: Final = 30.0
_CONTROL_SECONDS: Final = 10.0
_PROBE_SECONDS: Final = 30.0
# Room for the owner to read OpenSSH's host-key question and answer it (approach A's bound).
_CONFIRM_PROBE_SECONDS: Final = 180.0
_START_SECONDS: Final = 30.0
_MAX_ENDPOINT_REPORT_BYTES: Final = 16_384
_MAX_PATH_TEXT: Final = 1_024
# Where a FinishUP launcher is installed by the documented install paths (``uv tool``, ``pipx``,
# Homebrew, a system package). The probe is one fixed remote script; it prints the first
# executable candidate and nothing else.
SSH_LAUNCHER_CANDIDATES: Final = (
    "$HOME/.local/bin/finishup",
    "/opt/homebrew/bin/finishup",
    "/usr/local/bin/finishup",
    "/usr/bin/finishup",
)
_LAUNCHER_PROBE: Final = (
    "for candidate in "
    + " ".join(f'"{candidate}"' for candidate in SSH_LAUNCHER_CANDIDATES)
    + '; do if [ -x "$candidate" ]; then printf "%s\\n" "$candidate"; exit 0; fi; done; exit 3'
)
_ENDPOINT_SCHEMA: Final = "yoetz.service-endpoint/1"


def _remote_record(root: Path | None, kinds: frozenset[str]) -> tuple[ServerTarget, Path]:
    if root is None:
        raise TargetRuntimeError("target_record_invalid")
    try:
        record = read_target(root)
    except TargetError as error:
        raise TargetRuntimeError(error.reason) from None
    if record is None or record.kind not in kinds:
        raise TargetRuntimeError("target_record_invalid")
    return record, root


def _refuse_zero_network() -> None:
    """Start or send nothing while this computer last reported zero-network (ADR-051 decision 8)."""

    from finishup.client.everyday_policy import last_reported_zero_network

    if last_reported_zero_network() is not None:
        raise TargetRuntimeError("service_unavailable", phase="zero_network_remote_selected")


def _run(runner: _Runner, argv: Sequence[str], seconds: float) -> tuple[int | None, bytes, bytes]:
    """Run one fixed ``ssh`` argv; ``None`` as the code when it outlived its bound or failed."""

    try:
        completed = runner(
            list(argv),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env=ssh_environment(),
            timeout=seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None, b"", b""
    except OSError:
        return None, b"", b""
    return completed.returncode, completed.stdout, completed.stderr


def _ssh_phase(code: int | None, stderr: bytes) -> str:
    return classify_ssh_failure(code, stderr) or "remote_unreachable"


def _host_key_unconfirmed(stderr: bytes) -> bool:
    """Whether OpenSSH refused a host key it does not know (not one that changed).

    Strict checking says "No … host key is known for …"; a declined or unanswerable question
    says only "Host key verification failed". A changed key says "REMOTE HOST IDENTIFICATION HAS
    CHANGED" and stays ``remote_identity_changed``.
    """

    if b"REMOTE HOST IDENTIFICATION HAS CHANGED" in stderr:
        return False
    return b"host key is known" in stderr or b"Host key verification failed" in stderr


def _command_phase(code: int | None, stderr: bytes) -> str:
    """Why a remote command failed: ``ssh`` itself (255, or no exit) or the server's command.

    Any other exit status is the remote command's own: the connection worked and the server did
    not answer as this release's FinishUP does.
    """

    if code is None or code == 255:
        return _ssh_phase(code, stderr)
    return "remote_incompatible"


def ssh_master_present(root: Path) -> bool:
    """Whether this client holds an OpenSSH master for the SSH target at ``root``.

    The master's control socket at ``<root>/run/m`` is there while it runs: OpenSSH removes it
    when the master exits, after its 15 idle minutes included. Nothing is run or signalled.
    """

    return (root / "run" / "m").exists()


class SshTargetRuntime:
    """An SSH target: its persistent OpenSSH master, and the remote service behind it."""

    __slots__ = ("_program", "_runner")

    _program: tuple[str, ...]
    _runner: _Runner

    def __init__(
        self, *, program: Sequence[str] = ("ssh",), runner: _Runner = subprocess.run
    ) -> None:
        self._program = tuple(program)
        self._runner = runner

    def ensure_ready(self, root: Path | None) -> None:
        record, target_root = _remote_record(root, frozenset({"ssh"}))
        _refuse_zero_network()
        code, _stdout, stderr = _run(
            self._runner,
            ssh_master_argv(record, target_root, program=self._program),
            _MASTER_SECONDS,
        )
        if code != 0:
            raise TargetRuntimeError("service_unavailable", phase=_ssh_phase(code, stderr))
        _ensure_service(target_root)

    def stop(self, root: Path | None) -> None:
        record, target_root = _remote_record(root, frozenset({"ssh"}))
        if not ssh_master_present(target_root):
            return
        code, _stdout, stderr = _run(
            self._runner,
            ssh_control_argv(record, target_root, "exit", program=self._program),
            _CONTROL_SECONDS,
        )
        if code != 0 and b"No such file" not in stderr and b"Connection refused" not in stderr:
            raise TargetRuntimeError("service_unavailable", phase=_ssh_phase(code, stderr))

    def probe(self, root: Path | None) -> ProbeResult:
        _remote_record(root, frozenset({"ssh"}))
        return probe_service(root)


class HttpsTargetRuntime:
    """An HTTPS or localhost-port target: the gateway answers; no client process runs."""

    __slots__ = ()

    def ensure_ready(self, root: Path | None) -> None:
        import anyio

        from finishup.client.credentials import CredentialError, KeyringOrFileCredential
        from finishup.client.https_binding import fetch_server_info

        record, target_root = _remote_record(root, frozenset({"https", "local_port"}))
        _refuse_zero_network()
        try:
            secret = KeyringOrFileCredential(
                record.target_id, target_root, recorded=record.credential
            ).read()
        except CredentialError:
            raise TargetRuntimeError("service_unavailable", phase="remote_auth_failed") from None

        async def check() -> None:
            await fetch_server_info(record, secret)

        try:
            anyio.run(check)
        except TransportError as error:
            raise TargetRuntimeError("service_unavailable", phase=error.phase) from None

    def stop(self, root: Path | None) -> None:
        # No client-side process holds anything for this target; the gateway closes a session's
        # upstream after 120 idle seconds.
        _remote_record(root, frozenset({"https", "local_port"}))

    def probe(self, root: Path | None) -> ProbeResult:
        _remote_record(root, frozenset({"https", "local_port"}))
        return probe_service(root)


def close_ssh_masters(
    roots: Sequence[Path] | None = None, *, runtime: SshTargetRuntime | None = None
) -> tuple[str, ...]:
    """Ask the OpenSSH master of each SSH target to exit; the generated ids of those asked.

    ``roots`` names target roots (records of other kinds are skipped); ``None`` means every SSH
    target in this computer's registry. Only a master this client started is asked, by its control
    path (``ssh -O exit``), never found by pattern; one that is gone, or a record that cannot be
    read, is skipped. Closing a master ends every stream any process of this client multiplexed
    through it. Never raises: this is how a client that found this computer zero-network closes
    what it holds (ADR-051 decision 8), and a failure to close leaves the connection check to
    refuse every new stream.
    """

    import os

    from finishup.client.targets import servers_dir
    from finishup.config.paths import PathSafetyError

    stopper = runtime if runtime is not None else SshTargetRuntime()
    if roots is None:
        # Each target root on its own: one damaged root never keeps the others' masters open.
        try:
            chosen = tuple(
                Path(entry.path)
                for entry in os.scandir(servers_dir())
                if entry.name.startswith("t_") and entry.is_dir(follow_symlinks=False)
            )
        except (OSError, PathSafetyError):
            return ()
    else:
        chosen = tuple(roots)
    closed: list[str] = []
    for root in chosen:
        try:
            record = read_target(root)
        except (TargetError, OSError, PathSafetyError):
            continue
        if record is None or record.kind != "ssh" or not ssh_master_present(root):
            continue
        try:
            stopper.stop(root)
        except TargetRuntimeError:
            continue
        closed.append(record.target_id)
    return tuple(closed)


def _ensure_service(root: Path) -> None:
    """Connect on demand under ``root``: an idle-stopped remote service is started once."""

    import anyio

    from finishup.config.paths import selection_override
    from finishup.ports.control import ControlClientKind, ControlError
    from finishup.service.client import connect_service_on_demand

    async def start() -> None:
        client = await connect_service_on_demand(
            ControlClientKind.CLI, workspace_locator=None, timeout_seconds=_START_SECONDS
        )
        await client.close()

    with selection_override(root):
        try:
            anyio.run(start)
        except ControlError as error:
            raise TargetRuntimeError(error.reason, phase=error.phase) from None


@dataclass(frozen=True, slots=True)
class SshEndpoint:
    """What ``server add ssh://…`` records: the remote endpoint and the launcher that found it.

    ``session_bound`` is true when the endpoint lives in a login session's runtime folder on an
    account without linger, so it disappears at the owner's last logout on the server.
    """

    endpoint: str
    launcher: str | None
    session_bound: bool


def _absolute(value: object) -> str | None:
    if (
        type(value) is not str
        or not value.startswith("/")
        or len(value) > _MAX_PATH_TEXT
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        return None
    return value


def _probe_argv(
    program: Sequence[str],
    user: str | None,
    host: str,
    port: int,
    command: str,
    *,
    confirm_host_key: bool = False,
) -> tuple[str, ...]:
    """The fixed ``server add`` probe argv; ``confirm_host_key`` lets OpenSSH ask on the console.

    Interactive, it is approach A's probe: ``StrictHostKeyChecking=ask`` and no master, with
    OpenSSH's own question on the owner's terminal; password and keyboard-interactive login stay
    off, so the only question is the host key and the add proves the key authentication every
    later ``BatchMode`` connection needs. Otherwise ``BatchMode`` with strict checking: nothing is
    asked and an unknown host key is refused.
    """

    destination = host if user is None else f"{user}@{host}"
    trust = (
        (
            "-o",
            "StrictHostKeyChecking=ask",
            "-o",
            "ControlMaster=no",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
        )
        if confirm_host_key
        else ("-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes")
    )
    return (
        *program,
        *trust,
        "-T",
        "-p",
        str(port),
        destination,
        "--",
        command,
    )


def discover_ssh_endpoint(
    *,
    user: str | None,
    host: str,
    port: int,
    remote_root: str | None,
    remote_launcher: str | None,
    program: Sequence[str] = ("ssh",),
    runner: _Runner = subprocess.run,
    confirm_host_key: bool = False,
) -> SshEndpoint:
    """Ask the server, over SSH, where its control endpoint is (after the owner authorized it).

    With a launcher (given or found at a fixed install path) the server's own
    ``service endpoint --json`` answers, pinned to ``remote_root`` when one is given; its manifest
    must be this client's (``remote_incompatible``). With no launcher but a remote root, the
    endpoint is ``<remote root>/run/control.sock`` and nothing runs remotely. With neither, the
    target cannot be reached: ``remote_service_not_running``.

    ``confirm_host_key`` (the owner's trusted console is present) lets OpenSSH ask, on that
    terminal, to confirm a host key it does not know yet. A host key that was not confirmed (no
    console to ask on, or the owner declined) is ``TargetRuntimeError("remote_host_key_unconfirmed")``;
    a changed one stays ``remote_identity_changed``.
    """

    import shlex

    from finishup.config.paths import ISOLATED_ROOT_ENV
    from finishup.protocol.schemas import schema_manifest_digest

    seconds = _CONFIRM_PROBE_SECONDS if confirm_host_key else _PROBE_SECONDS

    def probe(command: str) -> tuple[int | None, bytes, bytes]:
        argv = _probe_argv(program, user, host, port, command, confirm_host_key=confirm_host_key)
        code, stdout, stderr = _run(runner, argv, seconds)
        if code == 255 and _host_key_unconfirmed(stderr):
            raise TargetRuntimeError("remote_host_key_unconfirmed")
        return code, stdout, stderr

    launcher = remote_launcher
    if launcher is None:
        code, stdout, stderr = probe(_LAUNCHER_PROBE)
        if code == 0:
            launcher = _absolute(stdout.decode("utf-8", "replace").strip())
        elif code != 3:
            raise TargetRuntimeError("service_unavailable", phase=_command_phase(code, stderr))
    if launcher is None:
        if remote_root is None:
            raise TargetRuntimeError("service_unavailable", phase="remote_service_not_running")
        return SshEndpoint(f"{remote_root.rstrip('/')}/run/control.sock", None, False)
    words = [launcher, "service", "endpoint", "--json"]
    if remote_root is not None:
        words = ["env", f"{ISOLATED_ROOT_ENV}={remote_root}", *words]
    command = " ".join(shlex.quote(word) for word in words)
    code, stdout, stderr = probe(command)
    if code != 0:
        # A launcher the remote shell cannot run (126, 127) is not this release's FinishUP.
        raise TargetRuntimeError("service_unavailable", phase=_command_phase(code, stderr))
    if len(stdout) > _MAX_ENDPOINT_REPORT_BYTES:
        raise TargetRuntimeError("service_unavailable", phase="remote_incompatible")
    try:
        parsed: object = json.loads(stdout)
    except ValueError:
        raise TargetRuntimeError("service_unavailable", phase="remote_incompatible") from None
    if not isinstance(parsed, dict):
        raise TargetRuntimeError("service_unavailable", phase="remote_incompatible")
    report = cast(dict[str, object], parsed)
    endpoint = _absolute(report.get("endpoint"))
    if report.get("schema") != _ENDPOINT_SCHEMA or endpoint is None:
        raise TargetRuntimeError("service_unavailable", phase="remote_incompatible")
    if report.get("schema_manifest_digest") != schema_manifest_digest():
        raise TargetRuntimeError("service_unavailable", phase="remote_incompatible")
    # The endpoint disappears at the owner's last logout unless the account lingers.
    session_bound = (
        report.get("runtime_dir_session_bound") is True and report.get("linger") != "enabled"
    )
    return SshEndpoint(endpoint, launcher, session_bound)
