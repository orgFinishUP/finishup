"""OpenSSH argv, failure classification, the observed host key and the direct stream (ADR-052).

The real OpenSSH runs in ``tests/capability/test_openssh_helper.py``; these pin every fixed argv
and every closed reason with stand-in programs (small shell scripts), never a network.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import os
import shutil
import stat
import tempfile
import time
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from builders.server_targets import ambient_home, short_home_base
from finishup.adapters.control.unix_socket import (
    LocalControlTransportError,
    connect_owner_only_endpoint,
)
from finishup.client import targets
from finishup.client.ssh_transport import (
    SshControlStream,
    SshMaster,
    UpstreamUnavailable,
    classify_ssh_failure,
    control_argv,
    direct_argv,
    direct_master_argv,
    direct_remote_argv,
    host_key_changed,
    host_key_unconfirmed,
    master_argv,
    observed_host_key,
    probe_argv,
    remote_argv,
    remote_command_line,
    run_ssh,
    ssh_environment,
)
from finishup.client.targets import ServerTarget

_KEY = "sha256:" + hashlib.sha256(b"the consented host key").hexdigest()


@pytest.fixture
def ssh_target(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[ServerTarget, Path]]:
    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, root = targets.new_remote_target(
                "lab",
                "ssh",
                user="owner",
                host="lab.example",
                port=2222,
                remote_root="/srv/fu",
                remote_launcher="/opt/finishup/bin/finishup",
            )
        record = replace(record, remote_endpoint="/srv/fu/run/control.sock")
        yield record, root


def test_the_relay_master_argv_is_fixed_and_secret_free(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    record, root = ssh_target
    assert master_argv("/usr/bin/ssh", root, record) == (
        "/usr/bin/ssh",
        "-M",
        "-S",
        f"{root}/run/m",
        "-N",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
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
        "-o",
        "LogLevel=DEBUG1",
        "-p",
        "2222",
        "-L",
        f"{root}/run/upstream.sock:/srv/fu/run/control.sock",
        "owner@lab.example",
    )
    assert control_argv("/usr/bin/ssh", root, record, "exit") == (
        "/usr/bin/ssh",
        "-S",
        f"{root}/run/m",
        "-O",
        "exit",
        "-p",
        "2222",
        "owner@lab.example",
    )
    with pytest.raises(ValueError, match="ssh_control_operation_invalid"):
        control_argv("/usr/bin/ssh", root, record, "stop")


def test_the_direct_argv_rides_one_verified_persistent_master(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    record, root = ssh_target
    # A stream never becomes a master; it prints how it reached the server (B1).
    assert direct_argv("/usr/bin/ssh", root, record) == (
        "/usr/bin/ssh",
        "-S",
        f"{root}/run/m",
        "-o",
        "ControlMaster=no",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
        "-o",
        "LogLevel=DEBUG1",
        "-p",
        "2222",
        "-W",
        "/srv/fu/run/control.sock",
        "owner@lab.example",
    )
    assert direct_master_argv("/usr/bin/ssh", root, record) == (
        "/usr/bin/ssh",
        "-M",
        "-S",
        f"{root}/run/m",
        "-o",
        "ControlPersist=15m",
        "-N",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
        "-o",
        "LogLevel=DEBUG1",
        "-p",
        "2222",
        "owner@lab.example",
    )
    remote = direct_remote_argv("/usr/bin/ssh", root, record, "service", "start", "--json")
    assert remote[3:5] == ("-o", "ControlMaster=no") and "LogLevel=DEBUG1" in remote
    assert remote[-2:] == (
        "--",
        "env FINISHUP_ISOLATED_ROOT=/srv/fu /opt/finishup/bin/finishup service start --json",
    )


def test_a_remote_endpoint_that_cannot_be_forwarded_is_refused(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    record, root = ssh_target
    # OpenSSH splits ``-L`` on ':' and expands '%' tokens and '${VAR}' in socket paths.
    for endpoint in (None, "/srv/a:b.sock", "/srv/a%hb.sock", "/srv/${HOME}.sock"):
        with pytest.raises(UpstreamUnavailable, match="remote_unreachable"):
            direct_argv("ssh", root, replace(record, remote_endpoint=endpoint))
        with pytest.raises(UpstreamUnavailable, match="remote_unreachable"):
            master_argv("ssh", root, replace(record, remote_endpoint=endpoint))


def test_socket_paths_with_spaces_are_handed_to_openssh_as_written(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    """B2: macOS keeps FinishUP under "~/Library/Application Support"; spaces are fine."""

    from finishup.client.ssh_transport import ssh_paths_usable

    record, _root = ssh_target
    # As under a macOS home's "Library/Application Support" (no account's path is named here).
    root = Path("/srv/Library/Application Support/finishup/servers/t_0000000a")
    endpoint = "/srv/Library/Application Support/finishup/run/control.sock"
    spaced = replace(record, remote_endpoint=endpoint)
    assert ssh_paths_usable(root, endpoint)
    master = master_argv("ssh", root, spaced)
    assert master[master.index("-S") + 1] == f"{root}/run/m"
    assert master[master.index("-L") + 1] == f"{root}/run/upstream.sock:{endpoint}"
    direct = direct_argv("ssh", root, spaced)
    assert direct[direct.index("-W") + 1] == endpoint
    for unusable in (Path("/srv/a%h/servers/t_0000000a"), Path("/srv/a:b/servers/t_0000000a")):
        assert not ssh_paths_usable(unusable)
        with pytest.raises(UpstreamUnavailable, match="remote_unreachable"):
            master_argv("ssh", unusable, record)
    assert not ssh_paths_usable(root, "/srv/${HOME}/control.sock")


def test_remote_commands_are_quoted_and_pinned_to_the_remote_root(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    record, root = ssh_target
    assert remote_command_line("/opt/my finishup/bin/finishup", None, "service", "profile") == (
        "'/opt/my finishup/bin/finishup' service profile"
    )
    assert remote_argv("ssh", root, record, "service", "start")[-1] == (
        "env FINISHUP_ISOLATED_ROOT=/srv/fu /opt/finishup/bin/finishup service start"
    )
    with pytest.raises(UpstreamUnavailable, match="remote_service_not_running"):
        remote_argv("ssh", root, replace(record, remote_launcher=None), "service", "start")


@pytest.mark.parametrize("ask", [False, True])
def test_a_probe_is_never_multiplexed_and_asks_only_when_told(ask: bool) -> None:
    argv = probe_argv("ssh", user=None, host="::1", port=22, command="true", ask=ask)
    assert argv[:6] == ("ssh", "-v", "-o", "ControlPath=none", "-o", "ControlMaster=no")
    assert argv[-4:] == ("22", "::1", "--", "true")
    if ask:
        assert "StrictHostKeyChecking=ask" in argv and "BatchMode=yes" not in argv
        assert "PasswordAuthentication=no" in argv and "KbdInteractiveAuthentication=no" in argv
    else:
        assert "StrictHostKeyChecking=yes" in argv and "BatchMode=yes" in argv
        assert "StrictHostKeyChecking=ask" not in argv


def test_the_environment_of_an_ssh_child_carries_no_finishup_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FINISHUP_ISOLATED_ROOT", "/elsewhere")
    monkeypatch.setenv("YOETZ_ISOLATED_ROOT", "/elsewhere")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/run/agent.sock")
    environment = ssh_environment()
    assert "FINISHUP_ISOLATED_ROOT" not in environment
    assert "YOETZ_ISOLATED_ROOT" not in environment
    assert environment["SSH_AUTH_SOCK"] == "/run/agent.sock"


@pytest.mark.parametrize(
    ("stderr", "reason"),
    [
        (b"Host key verification failed.\r\n", "remote_identity_changed"),
        (b"@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @\n", "remote_identity_changed"),
        (
            b"No ED25519 host key is known for [h]:22 and you have requested strict checking.\n",
            "remote_identity_changed",
        ),
        (b"owner@h: Permission denied (publickey).\r\n", "remote_auth_failed"),
        (
            b"channel 0: open failed: connect failed: No such file or directory\n",
            "remote_service_not_running",
        ),
        (
            b"stdio forwarding failed\nStdio forwarding request failed: Session open refused by peer\n",
            "remote_service_not_running",
        ),
        (b"ssh: connect to host h port 22: Connection refused\r\n", "remote_unreachable"),
        (b"", "remote_unreachable"),
    ],
)
def test_failures_are_classified_by_fixed_phrases_only(stderr: bytes, reason: str) -> None:
    assert classify_ssh_failure(255, stderr) == reason


def test_an_unknown_key_is_told_apart_from_a_changed_one() -> None:
    """RE-7: only an unknown host key is ever asked about; a changed one never is."""

    unknown = b"No ED25519 host key is known for [127.0.0.1]:2222 and you have requested strict checking.\nHost key verification failed.\n"
    declined = b"Host key verification failed.\n"
    changed = (
        b"@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed.\n"
    )
    assert host_key_unconfirmed(unknown) and not host_key_changed(unknown)
    assert host_key_unconfirmed(declined)
    assert host_key_changed(changed) and not host_key_unconfirmed(changed)
    assert not host_key_unconfirmed(b"Permission denied (publickey).\n")


def _fingerprint(blob: bytes) -> tuple[bytes, str]:
    digest = hashlib.sha256(blob).digest()
    return base64.b64encode(digest).rstrip(b"="), "sha256:" + digest.hex()


def test_the_observed_host_key_is_the_one_openssh_verified() -> None:
    printed, expected = _fingerprint(b"host key blob")
    other, _ = _fingerprint(b"another key")
    line = b"debug1: Server host key: ssh-ed25519 SHA256:" + printed + b"\r\n"
    noise = b"debug1: Authenticating to h:22 as 'owner'\ndebug1: kex: algorithm: x\n"
    assert observed_host_key(noise + line + noise) == expected
    # The same key printed twice is still one key.
    assert observed_host_key(line + line) == expected
    for stderr in (
        noise,
        b"",
        line + b"debug1: Server host key: ssh-rsa SHA256:" + other + b"\n",
        b"debug1: Server host key: ssh-ed25519 SHA256:short\n",
        b"note debug1: Server host key: ssh-ed25519 SHA256:" + printed + b"\n",
    ):
        assert observed_host_key(stderr) is None


def _script(directory: Path, name: str, body: str) -> str:
    path = directory / name
    path.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    path.chmod(0o700)
    return str(path)


def test_run_ssh_returns_the_code_and_both_streams_and_kills_one_past_its_bound(
    tmp_path: Path,
) -> None:
    talker = _script(tmp_path, "talker", 'echo out; echo "$FINISHUP_ISOLATED_ROOT" >&2; exit 7')
    sleeper = _script(tmp_path, "sleeper", "exec sleep 600")

    async def run() -> tuple[tuple[int | None, bytes, bytes], tuple[int | None, bytes, bytes]]:
        os.environ["FINISHUP_ISOLATED_ROOT"] = "/must-not-leak"
        try:
            first = await run_ssh((talker,), seconds=10.0)
        finally:
            del os.environ["FINISHUP_ISOLATED_ROOT"]
        second = await run_ssh((sleeper,), seconds=0.2)
        return first, second

    first, second = asyncio.run(run())
    assert first == (7, b"out\n", b"\n")
    assert second == (None, b"", b"")


def test_a_master_that_cannot_start_names_why(
    ssh_target: tuple[ServerTarget, Path], tmp_path: Path
) -> None:
    record, root = ssh_target
    refused = _script(
        tmp_path, "refused", 'echo "owner@h: Permission denied (publickey)." >&2; exit 255'
    )
    silent = _script(tmp_path, "silent", "exec sleep 600")

    async def run() -> tuple[str, str]:
        reasons: list[str] = []
        for program, deadline in ((refused, None), (silent, 0.3)):
            master = SshMaster(root, record, ssh=program)
            try:
                await master.ensure(
                    expected=_KEY,
                    deadline=None if deadline is None else time.monotonic() + deadline,
                )
            except UpstreamUnavailable as error:
                reasons.append(error.reason)
            finally:
                await master.close()
        return reasons[0], reasons[1]

    assert asyncio.run(run()) == ("remote_auth_failed", "remote_unreachable")
    assert not (root / "run" / "upstream.sock").exists()


def test_a_direct_stream_carries_bytes_both_ways_and_names_why_it_ended(tmp_path: Path) -> None:
    refused = _script(
        tmp_path,
        "refused",
        'echo "channel 0: open failed: connect failed: No such file or directory" >&2; exit 255',
    )

    async def run() -> tuple[bytes, str | None, str | None]:
        echo = await SshControlStream.open(("/bin/cat",))
        await echo.send_all(b"frame")
        received = await echo.receive(5)
        await echo.aclose()
        clean = await echo.failure_phase()
        failed = await SshControlStream.open((refused,))
        assert await failed.receive(10) == b""
        phase = await failed.failure_phase()
        await failed.aclose()
        return received, clean, phase

    received, clean, phase = asyncio.run(run())
    assert received == b"frame"
    assert clean is None
    assert phase == "remote_service_not_running"


def test_why_a_stream_ended_never_raises_the_cancellation_its_close_gave_its_stderr_reader(
    tmp_path: Path,
) -> None:
    """An OpenSSH master holds a multiplexed ``ssh -W`` client's stderr past that client's exit,
    so the close ends the stream's stderr reader by cancelling it. Asking why the stream ended
    afterwards (the handshake's refusal path does) names nothing; it never raises the reader's
    cancellation as its own (the ssh-direct-L1 matrix cell: a traceback, exit 1)."""

    holder_pid = tmp_path / "holder.pid"
    # The stand-in exits at the end of its input; a child of its own keeps its stderr open (as
    # the master does) and writes nothing else.
    client = _script(
        tmp_path,
        "muxed",
        f"sleep 30 </dev/null >/dev/null &\necho $! > {holder_pid}\nexec cat",
    )

    async def run() -> tuple[bool, str | None]:
        stream = await SshControlStream.open((client,))
        try:
            async with asyncio.timeout(10):
                while not holder_pid.exists() or not holder_pid.read_text().strip():
                    await asyncio.sleep(0.01)
            await stream.aclose()
            reader = stream._stderr_task  # pyright: ignore[reportPrivateUsage]
            return reader.cancelled(), await stream.failure_phase()
        finally:
            # The holder this test started is stopped by its own pid.
            with contextlib.suppress(ProcessLookupError, ValueError, OSError):
                os.kill(int(holder_pid.read_text().strip()), 9)

    cancelled, phase = asyncio.run(run())
    assert cancelled  # the case under test: the close ended the reader
    assert phase is None


def test_an_upstream_socket_is_reached_only_with_the_fixed_endpoint_fences() -> None:
    # A short base: CI's temporary folders are too deep for an AF_UNIX path.
    base = Path(tempfile.mkdtemp(prefix=".yz-st-", dir=short_home_base()))
    run_dir = base / "run"
    run_dir.mkdir(mode=0o700)
    path = run_dir / "upstream.sock"

    async def run() -> list[str]:
        reasons: list[str] = []
        try:
            await connect_owner_only_endpoint(path)
        except LocalControlTransportError as error:
            reasons.append(error.reason)
        server = await asyncio.start_unix_server(lambda r, w: w.close(), path=str(path))
        try:
            path.chmod(0o600)
            stream = await connect_owner_only_endpoint(path)
            await stream.aclose()
            reasons.append("connected")
            run_dir.chmod(0o755)
            try:
                await connect_owner_only_endpoint(path)
            except LocalControlTransportError as error:
                reasons.append(error.reason)
            run_dir.chmod(0o700)
            path.chmod(0o666)
            try:
                await connect_owner_only_endpoint(path)
            except LocalControlTransportError as error:
                reasons.append(error.reason)
        finally:
            server.close()
            await server.wait_closed()
        return reasons

    try:
        assert asyncio.run(run()) == [
            "endpoint_missing",
            "connected",
            "runtime_directory_unsafe",
            "endpoint_unsafe",
        ]
        assert stat.S_ISDIR(run_dir.stat().st_mode)
    finally:
        shutil.rmtree(base, ignore_errors=True)


def _key_line(blob: bytes) -> tuple[bytes, str]:
    printed, digest = _fingerprint(blob)
    return b"debug1: Server host key: ssh-ed25519 SHA256:" + printed + b"\n", digest


def test_only_the_consented_host_key_lets_a_connection_be_used() -> None:
    """B1: a connection OpenSSH made itself is used only when it verified the consented key."""

    from finishup.client.ssh_transport import host_keys, require_host_key

    line, consented = _key_line(b"consented")
    other_line, other = _key_line(b"rotated")
    assert host_keys(b"noise\n" + line + line) == {consented}
    require_host_key(line, consented)
    # None printed: it rode a master, which its caller verified.
    require_host_key(b"debug1: mux_client_request_session: master session id: 2\n", consented)
    for stderr, expected in (
        (other_line, consented),
        (line + other_line, consented),
        (line, None),
    ):
        with pytest.raises(UpstreamUnavailable, match="remote_identity_changed"):
            require_host_key(stderr, expected)
    assert host_keys(other_line) == {other}


_FAKE_MASTER = r"""
import os, signal, socket, sys
argv = sys.argv[1:]
state = os.environ["FAKE_MASTER_STATE"]
with open(os.path.join(state, "calls"), "a") as log:
    log.write(" ".join(argv) + "\n")
if "-O" in argv:
    sys.exit(0)
with open(os.path.join(state, "key"), "rb") as handle:
    key = handle.read()
if key:
    sys.stderr.buffer.write(b"debug1: Server host key: ssh-ed25519 SHA256:" + key + b"\n")
    sys.stderr.flush()
local = argv[argv.index("-L") + 1].split(":", 1)[0]
listener = socket.socket(socket.AF_UNIX)
listener.bind(local)
os.chmod(local, 0o600)
listener.listen(1)
signal.pause()
"""


@pytest.fixture
def fake_master(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[str, Path]]:
    """A stand-in relay master: prints the host key in ``key`` (if any), then listens on its
    ``-L`` socket until it is stopped (by the pid ``SshMaster`` spawned)."""

    import sys

    state = tmp_path / "master-state"
    state.mkdir()
    (state / "calls").write_text("")
    program = tmp_path / "ssh"
    program.write_text(f"#!{sys.executable}\n{_FAKE_MASTER}", encoding="utf-8")
    program.chmod(0o700)
    monkeypatch.setenv("FAKE_MASTER_STATE", str(state))
    yield str(program), state


def _masters_started(state: Path) -> int:
    return sum("-L" in line.split() for line in (state / "calls").read_text().splitlines())


@pytest.mark.parametrize("printed", ["consented", "rotated", "none"])
def test_the_relay_master_is_ready_only_once_it_verified_the_consented_key(
    ssh_target: tuple[ServerTarget, Path], fake_master: tuple[str, Path], printed: str
) -> None:
    """B1: a master that verified another key (the server's key rotated and ``known_hosts``
    updated, the consent unchanged), or named none, is stopped before anything uses it."""

    record, root = ssh_target
    program, state = fake_master
    _line, consented = _key_line(b"consented")
    printed_keys = {
        "consented": _fingerprint(b"consented")[0],
        "rotated": _fingerprint(b"rotated")[0],
        "none": b"",
    }
    (state / "key").write_bytes(printed_keys[printed])

    async def run() -> tuple[str | None, bool]:
        master = SshMaster(root, record, ssh=program)
        try:
            await master.ensure(expected=consented, deadline=time.monotonic() + 2.0)
        except UpstreamUnavailable as error:
            return error.reason, master.alive
        else:
            return None, master.alive
        finally:
            # Whatever happened, the stand-in this test started is stopped by its own pid.
            await master.close()

    reason, alive = asyncio.run(run())
    if printed == "consented":
        assert (reason, alive) == (None, True)
    else:
        assert (reason, alive) == ("remote_identity_changed", False)


def test_a_running_relay_master_is_reused_only_for_the_key_it_verified(
    ssh_target: tuple[ServerTarget, Path], fake_master: tuple[str, Path]
) -> None:
    """B1: after the owner agrees to another key, the running master is replaced and checked."""

    record, root = ssh_target
    program, state = fake_master
    (state / "key").write_bytes(_fingerprint(b"consented")[0])
    _line, consented = _key_line(b"consented")
    _line, rotated = _key_line(b"rotated")

    async def run() -> tuple[int, int, str | None]:
        master = SshMaster(root, record, ssh=program)
        try:
            await master.ensure(expected=consented)
            await master.ensure(expected=consented)
            reused = _masters_started(state)
            try:
                await master.ensure(expected=rotated, deadline=time.monotonic() + 2.0)
            except UpstreamUnavailable as error:
                return reused, _masters_started(state), error.reason
            return reused, _masters_started(state), None
        finally:
            await master.close()

    assert asyncio.run(run()) == (1, 2, "remote_identity_changed")


class _DirectOpenSsh:
    """A stand-in ``run_ssh`` for the direct style's master: ``-O check``/``exit`` and the master
    start, which binds a real socket at ``run/m`` (as OpenSSH's backgrounded master does) and
    prints the host key ``printed`` names."""

    def __init__(self, root: Path) -> None:
        import socket

        self.root = root
        self.socket = socket
        self.calls: list[str] = []
        self.printed = b""
        self.listener: object | None = None

    def _unbind(self) -> None:
        listener = self.listener
        if listener is not None:
            listener.close()  # type: ignore[attr-defined]
            self.listener = None
        (self.root / "run" / "m").unlink(missing_ok=True)

    async def __call__(self, argv: tuple[str, ...], *, seconds: float):  # noqa: ANN204
        if "-O" in argv:
            operation = argv[argv.index("-O") + 1]
            self.calls.append(operation)
            if operation == "exit":
                self._unbind()
            return (0 if self.listener is not None else 255), b"", b""
        self.calls.append("master")
        self._unbind()
        listener = self.socket.socket(self.socket.AF_UNIX)
        listener.bind(str(self.root / "run" / "m"))
        (self.root / "run" / "m").chmod(0o600)
        self.listener = listener
        return 0, b"", self.printed


def test_the_direct_master_is_recorded_only_once_it_verified_the_consented_key(
    ssh_target: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """B1: the direct style's master is verified when started, reused only as recorded, and
    replaced when the consent names another key; a rotated key is refused, nothing recorded."""

    from finishup.client import ssh_transport
    from finishup.client.ssh_transport import ensure_direct_master

    record, root = ssh_target
    openssh = _DirectOpenSsh(root)
    monkeypatch.setattr(ssh_transport, "run_ssh", openssh)
    consented_line, consented = _key_line(b"consented")
    rotated_line, rotated = _key_line(b"rotated")
    record_path = root / "state" / "ssh-master.json"

    async def ensure(expected: str | None) -> str | None:
        try:
            await ensure_direct_master("ssh", root, record, expected=expected)
        except UpstreamUnavailable as error:
            return error.reason
        return None

    async def run() -> None:
        try:
            openssh.printed = consented_line
            assert await ensure(consented) is None
            assert openssh.calls == ["master"]
            assert record_path.stat().st_mode & 0o777 == 0o600
            # Reused as recorded, once it answers.
            assert await ensure(consented) is None
            assert openssh.calls == ["master", "check"]
            # The owner agreed to another key: the running master is replaced and checked
            # again; the server still shows the old one, so it is refused and asked to exit.
            assert await ensure(rotated) == "remote_identity_changed"
            assert openssh.calls[2:] == ["exit", "master", "exit"]
            assert not record_path.exists() and openssh.listener is None
            # The server's key rotated (known_hosts updated), the consent unchanged.
            openssh.calls.clear()
            openssh.printed = rotated_line
            assert await ensure(consented) == "remote_identity_changed"
            assert openssh.calls == ["master", "exit"] and not record_path.exists()
            # A master nobody recorded (another process's, a relay's) is never ridden.
            openssh.calls.clear()
            openssh.printed = consented_line
            assert await ensure(consented) is None
            record_path.unlink()
            assert await ensure(consented) is None
            assert openssh.calls == ["master", "exit", "master"]
            # Nothing to verify against: refused before anything runs.
            openssh.calls.clear()
            assert await ensure(None) == "remote_identity_changed"
            assert openssh.calls == []
        finally:
            openssh._unbind()  # pyright: ignore[reportPrivateUsage]

    asyncio.run(run())


@pytest.mark.parametrize(
    ("printed", "reason"),
    [
        ("mux", None),
        ("consented", None),
        ("rotated", "remote_identity_changed"),
        ("refused", "remote_auth_failed"),
    ],
)
def test_a_direct_stream_is_used_only_once_openssh_said_how_it_reached_the_server(
    tmp_path: Path, printed: str, reason: str | None
) -> None:
    """B1: a ``-W`` stream rode the verified master (its multiplexing line), or verified the
    consented key over a connection of its own; anything else is never written to."""

    consented_printed, consented = _fingerprint(b"consented")
    rotated_printed, _rotated = _fingerprint(b"rotated")
    lines = {
        "mux": "debug1: mux_client_request_stdio_fwd: master session id: 2",
        "consented": f"debug1: Server host key: ssh-ed25519 SHA256:{consented_printed.decode()}",
        "rotated": f"debug1: Server host key: ssh-ed25519 SHA256:{rotated_printed.decode()}",
    }
    if printed == "refused":
        body = 'echo "owner@h: Permission denied (publickey)." >&2; exit 255'
    else:
        body = f'echo "{lines[printed]}" >&2; exec cat'
    program = _script(tmp_path, "w", body)

    async def run() -> str | None:
        stream = await SshControlStream.open((program,))
        try:
            await stream.verify(consented, deadline=time.monotonic() + 10.0)
        except UpstreamUnavailable as error:
            return error.reason
        finally:
            await stream.aclose()
        return None

    assert asyncio.run(run()) == reason


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_a_command_that_writes_too_much_is_killed_while_it_writes(
    tmp_path: Path, stream: str
) -> None:
    """B3: each stream is bounded as it is read; the writer is killed and reaped at once."""

    import sys

    progress = tmp_path / "progress"
    writer = tmp_path / "writer"
    target = "sys.stdout" if stream == "stdout" else "sys.stderr"
    writer.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        f"out = {target}.buffer\n"
        f"progress = open({str(progress)!r}, 'w')\n"
        "for written in range(1, 257):\n"
        "    out.write(b'x' * 16384)\n"
        "    out.flush()\n"
        "    progress.seek(0); progress.write(str(written)); progress.flush()\n"
        f"open({str(tmp_path / 'done')!r}, 'w').close()\n",
        encoding="utf-8",
    )
    writer.chmod(0o700)

    async def run() -> str:
        try:
            await run_ssh((str(writer),), seconds=60.0)
        except UpstreamUnavailable as error:
            return error.reason
        return "returned"

    assert asyncio.run(run()) == "remote_incompatible"
    # Four MiB were to be written; it was stopped a few chunks past the 64 KiB bound (what the
    # pipe still held), never allowed to finish.
    assert not (tmp_path / "done").exists()
    assert int(progress.read_text() or "0") < 32


def test_a_close_the_callers_deadline_cancels_still_ends_and_reaps_the_child(
    tmp_path: Path,
) -> None:
    """B4: ``service.client`` gives a close 50 ms; a child that outlives SIGTERM is killed anyway.

    The stand-in ``ssh -W`` ignores SIGTERM (as a stuck one can) and keeps its output open; the
    close is cancelled by the caller's bound long before the SIGKILL fallback was due.
    """

    from finishup.service.client import (
        _best_effort_close_stream,  # pyright: ignore[reportPrivateUsage]
    )

    # SIGTERM stays ignored across exec; the end of its input does not end it either.
    stubborn = _script(tmp_path, "stubborn", "trap '' TERM\necho started >&2\nexec sleep 600")

    async def run() -> tuple[int | None, int]:
        stream = await SshControlStream.open((stubborn,))
        pid = stream.pid
        try:
            async with asyncio.timeout(10):
                while b"started" not in bytes(stream._stderr):  # pyright: ignore[reportPrivateUsage]
                    await asyncio.sleep(0)
            # The real caller: it cancels a close that takes longer than its bound.
            await _best_effort_close_stream(stream)
            # Bounded, observing the child itself: killed and reaped by the stream's own task.
            async with asyncio.timeout(10):
                while stream._process.returncode is None:  # pyright: ignore[reportPrivateUsage]
                    await asyncio.sleep(0.01)
            async with asyncio.timeout(10):
                while Path(f"/proc/{pid}").exists():
                    await asyncio.sleep(0.01)
            return stream._process.returncode, pid  # pyright: ignore[reportPrivateUsage]
        finally:
            # Whatever happened, the child this test started is stopped by its own pid.
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, 9)

    returncode, _pid = asyncio.run(run())
    assert returncode == -9
