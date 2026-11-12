"""Real OpenSSH carries an SSH server's helper, its direct style and its discovery (ADR-052).

Starts a private, unprivileged ``sshd`` on a free loopback port (key-only, this user, a throwaway
host key, its own config and ``authorized_keys`` in a 0700 folder beneath the real home), and
stops it by the PID it started. The only stand-in is a two-line ``ssh`` wrapper that adds
``-F <test config>`` (its identity and ``known_hosts``): OpenSSH reads ``~/.ssh`` from the password
database, not ``$HOME``, so a test cannot point it elsewhere any other way, and this keeps every
test off the account's own ``~/.ssh``. Exercised for real:

* the relay: the helper's OpenSSH master with its stream-local forward, carrying a scripted
  session byte for byte to a scripted service on the "server" socket;
* the direct style: one ``ssh -W`` stream through a ``ControlMaster=auto`` master, which
  ``server disconnect``'s ``-O exit`` ends;
* SSH discovery against a FinishUP server running from an isolated root on this computer (its own
  launcher, ``service endpoint --json`` and ``service profile --json``), with the host key
  OpenSSH verified as the endpoint identity;
* the host key: unknown and confirmed on a terminal (a pseudo-terminal answers OpenSSH's own
  question), unknown and declined, and changed (never asked about);
* the consented host key on every new connection (ADR-052, B1): the server's key rotates and
  ``known_hosts`` follows it, so OpenSSH connects; the relay's master and the direct style's are
  refused before any hello until the owner agrees to the new key, and a direct master verified
  for one consent is never ridden under another.

Skipped where ``ssh``, ``sshd`` or ``ssh-keygen`` is missing or ``sshd`` cannot start here.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import os
import pty
import pwd
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from builders.control_relay import ScriptedDaemon, memory_pair, run_scripted_session
from builders.server_profiles import TEST_REVISION
from builders.server_targets import ambient_home, open_remote_kinds
from finishup.adapters.control.unix_socket import AuthenticatedUnixStream, authenticate_peer
from finishup.client import targets
from finishup.client.targets import ServerTarget

_TOOLS = ("ssh", "sshd", "ssh-keygen")
_SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_LAUNCHER = Path(sys.executable).parent / "finishup"
pytestmark = pytest.mark.skipif(
    any(shutil.which(tool, path=_SYSTEM_PATH) is None for tool in _TOOLS),
    reason="OpenSSH client, server or ssh-keygen not installed",
)


def _tool(name: str) -> str:
    found = shutil.which(name, path=_SYSTEM_PATH)
    assert found is not None
    return found


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _real_home() -> Path:
    return Path(pwd.getpwuid(os.getuid()).pw_dir)


@dataclass(frozen=True, slots=True)
class Sshd:
    directory: Path
    port: int
    user: str
    ssh: str  # the wrapper: the real ssh with this test's config
    # The sshd processes this fixture started, newest last; each is stopped by its own PID.
    processes: list[subprocess.Popen[bytes]]

    def rotate_host_key(self) -> None:
        """The server's host key changes and this computer's ``known_hosts`` follows it.

        The listening sshd (the one this fixture started) is stopped by its PID and started
        again on the same port with a new host key; connections it accepted before keep their
        own processes, as on a real server. Then ``known_hosts`` names the new key only.
        """

        current = self.processes[-1]
        current.terminate()
        current.wait(timeout=10)
        for name in ("host_key", "host_key.pub"):
            (self.directory / name).unlink()
        subprocess.run(  # noqa: S603 - fixed test argv
            (
                _tool("ssh-keygen"),
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(self.directory / "host_key"),
            ),
            check=True,
        )
        self.processes.append(_start_sshd(self.directory, self.port))
        self.pin_host_key()

    def pin_host_key(self) -> None:
        key = (self.directory / "host_key.pub").read_text(encoding="utf-8").split()
        (self.directory / "known_hosts").write_text(
            f"[127.0.0.1]:{self.port} {key[0]} {key[1]}\n", encoding="utf-8"
        )

    def pin_another_host_key(self) -> None:
        other = self.directory / "other_key"
        subprocess.run(  # noqa: S603 - fixed test argv
            (_tool("ssh-keygen"), "-q", "-t", "ed25519", "-N", "", "-f", str(other)), check=True
        )
        key = (self.directory / "other_key.pub").read_text(encoding="utf-8").split()
        (self.directory / "known_hosts").write_text(
            f"[127.0.0.1]:{self.port} {key[0]} {key[1]}\n", encoding="utf-8"
        )

    def known_hosts(self) -> str:
        path = self.directory / "known_hosts"
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def host_key_identity(self) -> str:
        blob = base64.b64decode(
            (self.directory / "host_key.pub").read_text(encoding="utf-8").split()[1]
        )
        return "sha256:" + hashlib.sha256(blob).hexdigest()


@pytest.fixture
def sshd() -> Iterator[Sshd]:
    """A running private sshd and an ssh wrapper; stopped by the PID this fixture started."""

    user = pwd.getpwuid(os.getuid()).pw_name
    directory = Path(tempfile.mkdtemp(prefix=".yz-ssh-", dir=_real_home()))
    directory.chmod(0o700)
    keygen = _tool("ssh-keygen")
    for name in ("host_key", "client_key"):
        subprocess.run(  # noqa: S603 - fixed test argv
            (keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(directory / name)), check=True
        )
    (directory / "authorized_keys").write_bytes((directory / "client_key.pub").read_bytes())
    (directory / "authorized_keys").chmod(0o600)
    port = _free_port()
    (directory / "sshd_config").write_text(
        "\n".join(
            (
                f"Port {port}",
                "ListenAddress 127.0.0.1",
                f"HostKey {directory / 'host_key'}",
                f"AuthorizedKeysFile {directory / 'authorized_keys'}",
                f"PidFile {directory / 'sshd.pid'}",
                "PubkeyAuthentication yes",
                "PasswordAuthentication no",
                "KbdInteractiveAuthentication no",
                "UsePAM no",
                "StrictModes no",
                "AllowStreamLocalForwarding yes",
                "StreamLocalBindUnlink yes",
                "LogLevel ERROR",
                "",
            )
        ),
        encoding="utf-8",
    )
    (directory / "ssh_config").write_text(
        "\n".join(
            (
                "Host *",
                f"  IdentityFile {directory / 'client_key'}",
                "  IdentitiesOnly yes",
                f"  UserKnownHostsFile {directory / 'known_hosts'}",
                "  GlobalKnownHostsFile /dev/null",
                "",
            )
        ),
        encoding="utf-8",
    )
    bin_dir = directory / "bin"
    bin_dir.mkdir(mode=0o700)
    wrapper = bin_dir / "ssh"
    wrapper.write_text(
        f'#!/bin/sh\nexec {_tool("ssh")} -F {directory / "ssh_config"} "$@"\n', encoding="utf-8"
    )
    wrapper.chmod(0o700)
    processes: list[subprocess.Popen[bytes]] = []
    try:
        processes.append(_start_sshd(directory, port))
        yield Sshd(directory, port, user, str(wrapper), processes)
    finally:
        # Stopped by the PIDs this fixture started (never by a pattern).
        for server in processes:
            if server.poll() is None:
                server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
        shutil.rmtree(directory, ignore_errors=True)


def _start_sshd(directory: Path, port: int) -> subprocess.Popen[bytes]:
    """Start the private sshd and wait, bounded, until it listens (skip where it cannot run)."""

    server = subprocess.Popen(  # noqa: S603 - fixed test argv
        (_tool("sshd"), "-D", "-e", "-f", str(directory / "sshd_config")),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 10
    while True:
        if server.poll() is not None:
            pytest.skip("sshd cannot run in this environment")
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return server
        except OSError:
            if time.monotonic() > deadline:
                server.terminate()
                server.wait()
                pytest.skip("sshd did not start listening")
            time.sleep(0.05)


@pytest.fixture
def server_root() -> Iterator[Path]:
    """A FinishUP server root on this computer (an isolated root), its service stopped after."""

    root = Path(tempfile.mkdtemp(prefix=".yz-srv-", dir=_real_home()))
    root.chmod(0o700)
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("FINISHUP_", "YOETZ_"))
    }
    environment["FINISHUP_ISOLATED_ROOT"] = str(root)
    try:
        yield root
    finally:
        # The sanctioned stop of the service that root's own launcher started on demand.
        subprocess.run(  # noqa: S603 - this checkout's launcher, fixed arguments
            (str(_LAUNCHER), "service", "stop", "--json"),
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=60,
            check=False,
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            status = subprocess.run(  # noqa: S603 - this checkout's launcher, fixed arguments
                (str(_LAUNCHER), "service", "status", "--json"),
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=30,
                check=False,
            )
            if status.returncode != 0:
                break
        shutil.rmtree(root, ignore_errors=True)


def _ssh_record(sshd: Sshd, endpoint: Path) -> tuple[ServerTarget, Path]:
    with targets.registry_lock():
        _record, root = targets.new_remote_target(
            "lab",
            "ssh",
            user=sshd.user,
            host="127.0.0.1",
            port=sshd.port,
            remote_launcher=str(_LAUNCHER),
            remote_endpoint=str(endpoint),
        )
    stored = targets.read_target(root)
    assert stored is not None
    if stored.consent is not None:
        # The owner agreed to the key this server really has (the default test consent names
        # another), as 'server add' records the key OpenSSH verified.
        from builders.server_profiles import consent_to

        stored = consent_to(stored, identity=sshd.host_key_identity())
    return stored, root


async def _serve_unix(path: Path, daemon: ScriptedDaemon) -> asyncio.Task[None]:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    path.chmod(0o600)
    listener.listen(8)
    listener.setblocking(False)
    loop = asyncio.get_running_loop()

    async def accept() -> None:
        try:
            while True:
                connection, _ = await loop.sock_accept(listener)
                stream = AuthenticatedUnixStream(connection, authenticate_peer(connection))
                daemon.serving.append(asyncio.create_task(daemon.serve(stream)))
        finally:
            listener.close()

    return asyncio.create_task(accept())


async def _reference() -> list[bytes]:
    daemon = ScriptedDaemon()
    client, server = memory_pair()
    served = asyncio.create_task(daemon.serve(server))
    received = await run_scripted_session(client, server_profile=TEST_REVISION)
    await client.aclose()
    await served
    return received


def test_the_helper_relays_a_session_through_the_real_forward(
    sshd: Sshd, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.client.helper import Helper, SshRelayUpstream

    sshd.pin_host_key()
    expected = asyncio.run(_reference())
    with ambient_home(monkeypatch):
        open_remote_kinds(monkeypatch, "ssh")
        record, root = _ssh_record(sshd, sshd.directory / "d.sock")

        async def no_refresh(_record: ServerTarget) -> None:
            return None

        async def exercise() -> tuple[list[bytes], int, int]:
            daemon = ScriptedDaemon()
            accepting = await _serve_unix(sshd.directory / "d.sock", daemon)
            upstream = SshRelayUpstream(root, record, ssh=sshd.ssh)
            helper = Helper(root, record, upstream=upstream, refresher=no_refresh)
            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            client = AuthenticatedUnixStream(left, authenticate_peer(left))
            local = AuthenticatedUnixStream(right, authenticate_peer(right))
            relay = asyncio.create_task(helper._serve_local(local))  # pyright: ignore[reportPrivateUsage]
            try:
                async with asyncio.timeout(60):
                    received = await run_scripted_session(
                        client, server_profile=TEST_REVISION, relay=True
                    )
                    await client.shutdown_write()
                    await relay
                mode = (root / "run" / "upstream.sock").stat().st_mode & 0o777
                return received, daemon.connections, mode
            finally:
                await client.aclose()
                await upstream.close()
                accepting.cancel()
                await asyncio.gather(accepting, return_exceptions=True)

        received, connections, mode = asyncio.run(exercise())
        assert received == expected
        assert connections == 1 and mode == 0o600
        # The master stopped and its forward is gone: nothing is left behind.
        assert not (root / "run" / "upstream.sock").exists()
        assert not (root / "run" / "m").exists()


def test_a_target_root_and_an_endpoint_with_spaces_work_as_on_macos(
    sshd: Sshd, monkeypatch: pytest.MonkeyPatch
) -> None:
    """B2: macOS keeps FinishUP under "Application Support"; both styles work through it."""

    from finishup.client.helper import Helper, SshRelayUpstream
    from finishup.client.ssh_transport import exit_master_now, open_direct_stream

    sshd.pin_host_key()
    expected = asyncio.run(_reference())
    with ambient_home(monkeypatch) as home:
        spaced = home / "A S"
        spaced.mkdir(mode=0o700)
        monkeypatch.setenv("XDG_STATE_HOME", str(spaced))
        open_remote_kinds(monkeypatch, "ssh")
        endpoint = sshd.directory / "srv d" / "c.sock"
        endpoint.parent.mkdir(mode=0o700)
        record, root = _ssh_record(sshd, endpoint)
        assert " " in str(root) and " " in str(record.remote_endpoint)

        async def no_refresh(_record: ServerTarget) -> None:
            return None

        async def exercise() -> tuple[list[bytes], list[bytes]]:
            daemon = ScriptedDaemon()
            accepting = await _serve_unix(endpoint, daemon)
            upstream = SshRelayUpstream(root, record, ssh=sshd.ssh)
            try:
                helper = Helper(root, record, upstream=upstream, refresher=no_refresh)
                left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
                client = AuthenticatedUnixStream(left, authenticate_peer(left))
                local = AuthenticatedUnixStream(right, authenticate_peer(right))
                relay = asyncio.create_task(helper._serve_local(local))  # pyright: ignore[reportPrivateUsage]
                try:
                    async with asyncio.timeout(60):
                        relayed = await run_scripted_session(
                            client, server_profile=TEST_REVISION, relay=True
                        )
                        await client.shutdown_write()
                        await asyncio.wait((relay,), timeout=60)
                finally:
                    await client.aclose()
                    await upstream.close()
                stream = await open_direct_stream(
                    sshd.ssh, root, record, expected=sshd.host_key_identity()
                )
                try:
                    async with asyncio.timeout(60):
                        direct = await run_scripted_session(stream, server_profile=TEST_REVISION)
                finally:
                    await stream.aclose()
                return relayed, direct
            finally:
                accepting.cancel()
                await asyncio.gather(accepting, return_exceptions=True)

        try:
            relayed, direct = asyncio.run(exercise())
        finally:
            exit_master_now(sshd.ssh, root, record)
        assert relayed == expected and direct == expected
        assert not (root / "run" / "m").exists()


def test_the_direct_style_dials_ssh_w_through_one_control_master(
    sshd: Sshd, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.client.ssh_transport import exit_master_now, open_direct_stream

    sshd.pin_host_key()
    expected = asyncio.run(_reference())
    with ambient_home(monkeypatch):
        record, root = _ssh_record(sshd, sshd.directory / "d.sock")

        async def exercise() -> tuple[list[list[bytes]], int]:
            daemon = ScriptedDaemon()
            accepting = await _serve_unix(sshd.directory / "d.sock", daemon)
            sessions: list[list[bytes]] = []
            try:
                for _ in range(2):
                    stream = await open_direct_stream(
                        sshd.ssh, root, record, expected=sshd.host_key_identity()
                    )
                    try:
                        async with asyncio.timeout(60):
                            sessions.append(
                                await run_scripted_session(stream, server_profile=TEST_REVISION)
                            )
                    finally:
                        await stream.aclose()
                return sessions, daemon.connections
            finally:
                accepting.cancel()
                await asyncio.gather(accepting, return_exceptions=True)

        try:
            sessions, connections = asyncio.run(exercise())
            # The first stream left a persistent master; the second rode it.
            assert (root / "run" / "m").exists()
        finally:
            exit_master_now(sshd.ssh, root, record)
        assert sessions == [expected, expected] and connections == 2
        assert not (root / "run" / "m").exists()


def test_a_rotated_host_key_is_refused_before_any_hello_until_the_owner_agrees_again(
    sshd: Sshd, monkeypatch: pytest.MonkeyPatch
) -> None:
    """B1: ``known_hosts`` follows a rotated server key, so OpenSSH connects; FinishUP does not.

    The consent names the key the owner agreed to. After the rotation every new connection, the
    relay's master and the direct style's alike, verifies another key and is refused before
    any hello (the scripted service sees no new connection, the helper records
    ``remote_identity_changed``). Once the owner agrees to the new key it works again, and a
    direct master verified for that consent is never ridden under another.
    """

    from builders.server_profiles import consent_to
    from finishup.client.helper import Helper, SshRelayUpstream
    from finishup.client.helper_status import read_helper_status
    from finishup.client.ssh_transport import (
        UpstreamUnavailable,
        exit_master,
        exit_master_now,
        open_direct_stream,
    )

    sshd.pin_host_key()
    expected = asyncio.run(_reference())
    with ambient_home(monkeypatch):
        open_remote_kinds(monkeypatch, "ssh")
        record, root = _ssh_record(sshd, sshd.directory / "d.sock")
        before = sshd.host_key_identity()

        async def no_refresh(_record: ServerTarget) -> None:
            return None

        async def relayed(stored: ServerTarget) -> tuple[list[bytes] | bytes, str | None]:
            """One client session through a new helper's relay; its status reason after."""

            upstream = SshRelayUpstream(root, stored, ssh=sshd.ssh)
            helper = Helper(root, stored, upstream=upstream, refresher=no_refresh)
            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            client = AuthenticatedUnixStream(left, authenticate_peer(left))
            local = AuthenticatedUnixStream(right, authenticate_peer(right))
            relay = asyncio.create_task(helper._serve_local(local))  # pyright: ignore[reportPrivateUsage]
            try:
                async with asyncio.timeout(60):
                    try:
                        received: list[bytes] | bytes = await run_scripted_session(
                            client, server_profile=TEST_REVISION, relay=True
                        )
                    except Exception:  # noqa: BLE001 - the relay closed the hello unanswered
                        received = b""
                    await client.shutdown_write()
                    await asyncio.wait((relay,), timeout=60)
            finally:
                await client.aclose()
                await upstream.close()
            status = read_helper_status(root)
            return received, None if status is None else status.reason

        async def direct(expected_key: str) -> list[bytes] | str:
            try:
                stream = await open_direct_stream(sshd.ssh, root, record, expected=expected_key)
            except UpstreamUnavailable as error:
                return error.reason
            try:
                async with asyncio.timeout(60):
                    return await run_scripted_session(stream, server_profile=TEST_REVISION)
            finally:
                await stream.aclose()

        async def exercise() -> dict[str, object]:
            daemon = ScriptedDaemon()
            accepting = await _serve_unix(sshd.directory / "d.sock", daemon)
            seen: dict[str, object] = {}
            try:
                seen["direct_before"] = await direct(before)
                await exit_master(sshd.ssh, root, record)
                sshd.rotate_host_key()
                after = sshd.host_key_identity()
                assert after != before
                connections = daemon.connections
                seen["relay_rotated"] = await relayed(record)
                seen["direct_rotated"] = await direct(before)
                seen["sent_while_rotated"] = daemon.connections - connections
                # The owner agrees to the new key (as 'server use' records it after asking).
                agreed = consent_to(record, identity=after)
                seen["relay_agreed"] = await relayed(agreed)
                seen["direct_agreed"] = await direct(after)
                # A master verified for the new consent, under a consent naming the old key:
                # replaced and checked again, never ridden.
                connections = daemon.connections
                seen["direct_master_of_another_consent"] = await direct(before)
                seen["sent_under_another_consent"] = daemon.connections - connections
            finally:
                accepting.cancel()
                await asyncio.gather(accepting, return_exceptions=True)
            return seen

        try:
            seen = asyncio.run(exercise())
        finally:
            exit_master_now(sshd.ssh, root, record)
        assert seen["direct_before"] == expected
        assert seen["relay_rotated"] == (b"", "remote_identity_changed")
        assert seen["direct_rotated"] == "remote_identity_changed"
        assert seen["sent_while_rotated"] == 0
        assert seen["relay_agreed"] == (expected, None)
        assert seen["direct_agreed"] == expected
        assert seen["direct_master_of_another_consent"] == "remote_identity_changed"
        assert seen["sent_under_another_consent"] == 0
        assert not (root / "run" / "m").exists()


def test_discovery_reads_an_isolated_server_root_with_the_key_openssh_verified(
    sshd: Sshd, server_root: Path
) -> None:
    from finishup.client.ssh_discovery import discover
    from finishup.protocol.server_profile import profile_from_json

    sshd.pin_host_key()
    found = discover(
        user=sshd.user,
        host="127.0.0.1",
        port=sshd.port,
        remote_root=str(server_root),
        remote_launcher=str(_LAUNCHER),
        question=None,
        ssh=sshd.ssh,
    )
    assert found.endpoint == str(server_root / "run" / "control.sock")
    assert found.launcher == str(_LAUNCHER)
    assert (found.profile.identity_type, found.profile.identity) == (
        "ssh_host_key",
        sshd.host_key_identity(),
    )
    profile = profile_from_json(found.profile.document)
    assert profile.edges == ("ssh-control",)
    assert profile.levels.offered == ("L1",)


def test_a_changed_host_key_is_refused_and_never_asked_about(sshd: Sshd) -> None:
    from finishup.client.ssh_discovery import HostKeyQuestion, discover
    from finishup.client.target_runtime import TargetRuntimeError

    sshd.pin_another_host_key()
    asked: list[str] = []
    with pytest.raises(TargetRuntimeError) as raised:
        discover(
            user=sshd.user,
            host="127.0.0.1",
            port=sshd.port,
            remote_root=None,
            remote_launcher=str(_LAUNCHER),
            question=HostKeyQuestion(lambda: asked.append("asked")),
            ssh=sshd.ssh,
        )
    assert raised.value.phase == "remote_identity_changed"
    assert asked == []


_CHILD = """
import json, sys
from finishup.client.ssh_discovery import HostKeyQuestion, discover
from finishup.client.target_runtime import TargetRuntimeError
user, port, launcher, ssh, root = sys.argv[1:6]
def before():
    print("FINISHUP-ASKS-NEXT", flush=True)
try:
    found = discover(user=user, host="127.0.0.1", port=int(port), remote_root=root,
                     remote_launcher=launcher, question=HostKeyQuestion(before), ssh=ssh)
    print("RESULT " + json.dumps({"identity": found.profile.identity}), flush=True)
except TargetRuntimeError as error:
    print("RESULT " + json.dumps({"reason": error.reason, "phase": error.phase}), flush=True)
"""


def _discover_on_a_terminal(
    sshd: Sshd, server_root: Path, answer: bytes
) -> tuple[dict[str, object], str]:
    """Run discovery in a child whose controlling terminal is a pseudo-terminal this test drives:
    OpenSSH asks its host-key question there, and ``answer`` is typed in reply."""

    pid, master = pty.fork()
    if pid == 0:  # pragma: no cover - the child
        os.execv(  # noqa: S606 - this interpreter, fixed source
            sys.executable,
            [
                sys.executable,
                "-c",
                _CHILD,
                sshd.user,
                str(sshd.port),
                str(_LAUNCHER),
                sshd.ssh,
                str(server_root),
            ],
        )
    transcript = b""
    answered = False
    deadline = time.monotonic() + 120
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], max(0.0, deadline - time.monotonic()))
            if not ready:
                break
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            transcript += chunk
            if not answered and b"continue connecting" in transcript:
                os.write(master, answer + b"\n")
                answered = True
            if b"RESULT " in transcript and transcript.rstrip().endswith(b"}"):
                break
    finally:
        with contextlib.suppress(OSError):
            os.close(master)
        _done, _status = os.waitpid(pid, 0)
    text = transcript.decode("utf-8", "replace")
    line = next(line for line in text.splitlines() if line.startswith("RESULT "))
    return json.loads(line.removeprefix("RESULT ")), text


def test_an_unknown_host_key_is_confirmed_on_a_terminal_once(sshd: Sshd, server_root: Path) -> None:
    assert sshd.known_hosts() == ""
    result, transcript = _discover_on_a_terminal(sshd, server_root, b"yes")
    assert result == {"identity": sshd.host_key_identity()}
    # FinishUP said OpenSSH would ask, before OpenSSH asked, once.
    assert transcript.count("FINISHUP-ASKS-NEXT") == 1
    assert transcript.index("FINISHUP-ASKS-NEXT") < transcript.index("continue connecting")
    assert transcript.count("continue connecting") == 1
    # OpenSSH recorded the confirmed key, which every later strict connection checks.
    assert f"[127.0.0.1]:{sshd.port}" in sshd.known_hosts()


def test_a_declined_host_key_is_named_and_nothing_is_recorded(
    sshd: Sshd, server_root: Path
) -> None:
    result, transcript = _discover_on_a_terminal(sshd, server_root, b"no")
    assert result == {"reason": "remote_host_key_unconfirmed", "phase": None}
    assert transcript.count("continue connecting") == 1
    assert sshd.known_hosts() == ""
