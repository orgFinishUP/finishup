"""OpenSSH argv, failure classification, the observed host key and the direct stream (ADR-052).

The real OpenSSH runs in ``tests/capability/test_openssh_helper.py``; these pin every fixed argv
and every closed reason with stand-in programs (small shell scripts), never a network.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import stat
import time
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from builders.server_targets import ambient_home
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


def test_the_direct_argv_rides_one_persistent_master(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    record, root = ssh_target
    assert direct_argv("/usr/bin/ssh", root, record) == (
        "/usr/bin/ssh",
        "-S",
        f"{root}/run/m",
        "-o",
        "ControlMaster=auto",
        "-o",
        "ControlPersist=15m",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
        "-p",
        "2222",
        "-W",
        "/srv/fu/run/control.sock",
        "owner@lab.example",
    )
    assert direct_remote_argv("/usr/bin/ssh", root, record, "service", "start", "--json")[-2:] == (
        "--",
        "env FINISHUP_ISOLATED_ROOT=/srv/fu /opt/finishup/bin/finishup service start --json",
    )


def test_a_remote_endpoint_that_cannot_be_forwarded_is_refused(
    ssh_target: tuple[ServerTarget, Path],
) -> None:
    record, root = ssh_target
    for endpoint in (None, "/srv/a:b.sock", "/srv/a b.sock"):
        with pytest.raises(UpstreamUnavailable, match="remote_unreachable"):
            direct_argv("ssh", root, replace(record, remote_endpoint=endpoint))
        with pytest.raises(UpstreamUnavailable, match="remote_unreachable"):
            master_argv("ssh", root, replace(record, remote_endpoint=endpoint))


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
                    deadline=None if deadline is None else time.monotonic() + deadline
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


def test_an_upstream_socket_is_reached_only_with_the_fixed_endpoint_fences(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
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

    assert asyncio.run(run()) == [
        "endpoint_missing",
        "connected",
        "runtime_directory_unsafe",
        "endpoint_unsafe",
    ]
    assert stat.S_ISDIR(run_dir.stat().st_mode)
