"""SSH discovery and the server profile of an SSH target (design v2 sections 2.1 and 2.3).

``finishup server add NAME ssh://[user@]host[:port]`` asks the server, over OpenSSH, where its
control endpoint is and what it offers, before the owner is asked anything:

1. the launcher: ``--remote-launcher``, or the first executable FinishUP launcher at a fixed list
   of install paths (``SSH_LAUNCHER_CANDIDATES``), never a bare ``finishup`` resolved through the
   remote ``PATH`` (approach B);
2. ``[env FINISHUP_ISOLATED_ROOT=<remote root>] <launcher> service endpoint --json``: the remote
   control endpoint, which must be served by this client's release (its schema manifest); and
3. ``... service profile --json``: the ``server-profile`` 1.0.0 document (it starts the server's
   service on demand there), with the host key OpenSSH verified in that very connection as the
   endpoint identity the consent is bound to (``ssh_transport.observed_host_key``).

Every probe runs with strict host-key checking first, asking nothing. Only when OpenSSH says it
does not know the host key, and the caller passed a ``HostKeyQuestion`` (the owner's trusted
console is present), is the owner told that OpenSSH will ask, and the probe runs once more letting
OpenSSH ask on that terminal (RE-7, RE-11). A key the owner declined is
``remote_host_key_unconfirmed``; a changed key is ``remote_identity_changed`` at once and is never
asked about; an unknown key with no console to ask on is ``trusted_console_required``.

``fetch_profile`` is the profile alone for a recorded target (``server use`` and the helper's
refresh); ``SshProfileSource`` registers it as the SSH ``client.server_profile.ProfileSource``.
Never imported or run on a hook's path (design v2 section 8.9).
"""

from __future__ import annotations

import asyncio
import contextvars
import json
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, cast

from finishup.client.server_profile import FetchedProfile
from finishup.client.ssh_transport import (
    UpstreamUnavailable,
    classify_ssh_failure,
    host_key_changed,
    host_key_unconfirmed,
    observed_host_key,
    probe_argv,
    remote_command_line,
    run_ssh,
)
from finishup.client.target_runtime import TargetRuntimeError

if TYPE_CHECKING:
    from finishup.client.targets import ServerTarget

__all__ = [
    "SSH_LAUNCHER_CANDIDATES",
    "HostKeyQuestion",
    "SshDiscovery",
    "SshProfileSource",
    "discover",
    "fetch_profile",
    "fetch_profile_async",
    "host_key_question",
]

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
_PROBE_SECONDS: Final = 30.0
# Room for the owner to read OpenSSH's host-key question and answer it (approach A's bound).
_ASK_SECONDS: Final = 180.0
# ``service profile`` may start the server's service first.
_PROFILE_SECONDS: Final = 60.0
_MAX_REPORT_BYTES: Final = 65_536
# OpenSSH's own verbose lines for one connection, and the launcher's diagnostics, fit well within.
_MAX_DIAGNOSTIC_BYTES: Final = 65_536
_MAX_PATH_TEXT: Final = 1_024
_SSH_FAILED: Final = 255


class HostKeyQuestion:
    """What the owner is told, on the trusted console, before OpenSSH asks about a host key."""

    __slots__ = ("_before",)

    def __init__(self, before: Callable[[], None]) -> None:
        self._before = before

    def before(self) -> None:
        self._before()


# The question the SSH profile source may ask (``host_key_question``), for this context only.
_QUESTION: contextvars.ContextVar[HostKeyQuestion | None] = contextvars.ContextVar(
    "finishup_ssh_host_key_question", default=None
)


@contextmanager
def host_key_question(question: HostKeyQuestion | None) -> Generator[None]:
    """Let ``SshProfileSource.fetch`` ask about an unknown host key inside this block."""

    token = _QUESTION.set(question)
    try:
        yield
    finally:
        _QUESTION.reset(token)


@dataclass(frozen=True, slots=True)
class SshDiscovery:
    """What ``server add ssh://…`` records, and the profile it shows the owner.

    ``session_bound`` is true when the endpoint lives in a login session's runtime folder on an
    account without linger, so it disappears at the owner's last logout on the server.
    """

    endpoint: str
    launcher: str
    session_bound: bool
    profile: FetchedProfile


def _refused(phase: str) -> TargetRuntimeError:
    return TargetRuntimeError("service_unavailable", phase=phase)


def _absolute(value: object) -> str | None:
    if (
        type(value) is not str
        or not value.startswith("/")
        or len(value) > _MAX_PATH_TEXT
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        return None
    return value


class _Prober:
    """One server's probes, asking about its host key at most once."""

    def __init__(
        self,
        *,
        ssh: str,
        user: str | None,
        host: str,
        port: int,
        question: HostKeyQuestion | None,
    ) -> None:
        self._ssh = ssh
        self._user = user
        self._host = host
        self._port = port
        self._question = question
        # Whether OpenSSH was let ask about this server's host key: at most once per discovery;
        # every later probe is strict again (the key is known once confirmed).
        self._asked = False
        self.identities: set[str | None] = set()

    async def run(self, command: str, *, seconds: float) -> tuple[int, bytes]:
        """``(exit status, stdout)`` of the remote ``command``; OpenSSH's own failures raise."""

        ask = False
        while True:
            argv = probe_argv(
                self._ssh,
                user=self._user,
                host=self._host,
                port=self._port,
                command=command,
                ask=ask,
            )
            try:
                code, stdout, stderr = await run_ssh(
                    argv,
                    seconds=_ASK_SECONDS if ask else seconds,
                    stdout_limit=_MAX_REPORT_BYTES + 1,  # the closing newline
                    stderr_limit=_MAX_DIAGNOSTIC_BYTES,
                )
            except UpstreamUnavailable as error:
                # It wrote more than any FinishUP of this release would: killed while it wrote.
                raise _refused(error.reason) from None
            if code is None:
                raise _refused("remote_unreachable")
            if code == _SSH_FAILED and host_key_changed(stderr):
                # RE-7: a changed key is never asked about.
                raise _refused("remote_identity_changed")
            if code == _SSH_FAILED and host_key_unconfirmed(stderr):
                if self._asked:
                    # OpenSSH asked and the owner declined (or did not answer in time), or the
                    # key confirmed a moment ago is unknown again: never asked twice.
                    raise TargetRuntimeError("remote_host_key_unconfirmed")
                if self._question is None:
                    raise TargetRuntimeError("trusted_console_required")
                ask = self._asked = True
                self._question.before()
                continue
            if code == _SSH_FAILED:
                raise _refused(classify_ssh_failure(code, stderr))
            self.identities.add(observed_host_key(stderr))
            return code, stdout

    def identity(self) -> str:
        """The one host key every probe of this server saw; ``remote_identity_changed`` else."""

        if len(self.identities) != 1:
            raise _refused("remote_identity_changed")
        identity = next(iter(self.identities))
        if identity is None:
            raise _refused("remote_identity_changed")
        return identity


async def _launcher(prober: _Prober, given: str | None) -> str:
    if given is not None:
        return given
    code, stdout = await prober.run(_LAUNCHER_PROBE, seconds=_PROBE_SECONDS)
    found = _absolute(stdout.decode("utf-8", "replace").strip()) if code == 0 else None
    if found is None:
        raise TargetRuntimeError("remote_launcher_not_found")
    return found


async def _endpoint(prober: _Prober, launcher: str, remote_root: str | None) -> tuple[str, bool]:
    from finishup.protocol.schemas import schema_manifest_digest

    code, stdout = await prober.run(
        remote_command_line(launcher, remote_root, "service", "endpoint", "--json"),
        seconds=_PROBE_SECONDS,
    )
    if code != 0 or len(stdout) > _MAX_REPORT_BYTES:
        # A launcher the remote shell cannot run (126, 127) is not this release's FinishUP.
        raise _refused("remote_incompatible")
    try:
        parsed: object = json.loads(stdout)
    except ValueError:
        raise _refused("remote_incompatible") from None
    if not isinstance(parsed, dict):
        raise _refused("remote_incompatible")
    report = cast(dict[str, object], parsed)
    endpoint = _absolute(report.get("endpoint"))
    if report.get("schema") != _ENDPOINT_SCHEMA or endpoint is None:
        raise _refused("remote_incompatible")
    if report.get("schema_manifest_digest") != schema_manifest_digest():
        raise _refused("remote_incompatible")
    session_bound = (
        report.get("runtime_dir_session_bound") is True and report.get("linger") != "enabled"
    )
    return endpoint, session_bound


async def _profile(prober: _Prober, launcher: str, remote_root: str | None) -> bytes:
    code, stdout = await prober.run(
        remote_command_line(launcher, remote_root, "service", "profile", "--json"),
        seconds=_PROFILE_SECONDS,
    )
    if code != 0:
        # The server's own refusal (its service could not start, or it offers no profile): what it
        # offers is unknown here, so nothing can be agreed to.
        raise _refused("remote_service_not_running" if code == 20 else "remote_incompatible")
    document = stdout.rstrip(b"\n")
    if not document or len(document) > _MAX_REPORT_BYTES:
        raise _refused("remote_incompatible")
    return document


def _ssh(ssh: str | None) -> str:
    from finishup.client import ssh_transport

    try:
        return ssh if ssh is not None else ssh_transport.resolve_ssh()
    except UpstreamUnavailable as error:
        raise _refused(error.reason) from None


async def discover_async(
    *,
    user: str | None,
    host: str,
    port: int,
    remote_root: str | None,
    remote_launcher: str | None,
    question: HostKeyQuestion | None,
    ssh: str | None = None,
) -> SshDiscovery:
    """Discover the server at ``[user@]host:port`` (see the module text)."""

    prober = _Prober(ssh=_ssh(ssh), user=user, host=host, port=port, question=question)
    launcher = await _launcher(prober, remote_launcher)
    endpoint, session_bound = await _endpoint(prober, launcher, remote_root)
    document = await _profile(prober, launcher, remote_root)
    return SshDiscovery(
        endpoint,
        launcher,
        session_bound,
        FetchedProfile(document, "ssh_host_key", prober.identity()),
    )


def discover(
    *,
    user: str | None,
    host: str,
    port: int,
    remote_root: str | None,
    remote_launcher: str | None,
    question: HostKeyQuestion | None,
    ssh: str | None = None,
) -> SshDiscovery:
    """``discover_async`` from a process with no running event loop (the CLI)."""

    return asyncio.run(
        discover_async(
            user=user,
            host=host,
            port=port,
            remote_root=remote_root,
            remote_launcher=remote_launcher,
            question=question,
            ssh=ssh,
        )
    )


async def fetch_profile_async(
    record: ServerTarget, *, question: HostKeyQuestion | None = None, ssh: str | None = None
) -> FetchedProfile:
    """The current profile of recorded SSH target ``record``, with its observed host key."""

    if record.kind != "ssh" or record.host is None or record.port is None:
        raise TargetRuntimeError("target_record_invalid")
    launcher = record.remote_launcher
    if launcher is None:
        raise TargetRuntimeError("remote_launcher_not_found")
    prober = _Prober(
        ssh=_ssh(ssh), user=record.user, host=record.host, port=record.port, question=question
    )
    document = await _profile(prober, launcher, record.remote_root)
    return FetchedProfile(document, "ssh_host_key", prober.identity())


def fetch_profile(
    record: ServerTarget, *, question: HostKeyQuestion | None = None, ssh: str | None = None
) -> FetchedProfile:
    """``fetch_profile_async`` from a process with no running event loop."""

    return asyncio.run(fetch_profile_async(record, question=question, ssh=ssh))


class SshProfileSource:
    """The SSH ``ProfileSource`` (``client.server_profile.PROFILE_SOURCES["ssh"]``).

    Asks about an unknown host key only inside ``host_key_question`` (the trusted console).
    """

    def fetch(self, record: ServerTarget) -> FetchedProfile:
        return fetch_profile(record, question=_QUESTION.get())
