"""A refused test-instance disposal changes nothing, and no launcher is ever left unpinned (#1350).

Before the fix, ``scripts/provision_test_instance.py dispose`` removed the instance's state and its
runtime pin first and only then found a host session still holding a retained runtime: it refused
with ``runtime_in_use`` but left the launcher installed and unpinned, so that launcher ran ambient
and its next command reached the everyday install. Here a real snapshot is provisioned, its
service runs, and an MCP bridge started through its launcher is kept open, as a connected host
keeps it. Disposal must refuse with nothing stopped or removed: the launcher still pinned to the
same root, the root and its identity in place, the same service still serving. Once the bridge
closes, disposal removes everything, and the launcher path no longer exists.

Every process here runs with a private ``HOME`` and private XDG folders, so even a launcher that
lost its pin could reach nothing but this test's own folders. Like the rest of
``tests/packaging``, this spawns real CLIs under ``~/.yz-*`` and must not run concurrently with
another pytest run.
"""

from __future__ import annotations

import json
import os
import platform
import secrets
import selectors
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Final, cast

import pytest

_REPO_ROOT: Final = Path(__file__).resolve().parents[2]
_SCRIPT: Final = _REPO_ROOT / "scripts" / "provision_test_instance.py"
_XDG: Final = ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME")


def _is_advertised_host() -> bool:
    if sys.platform == "darwin":
        return platform.machine() == "arm64"
    if sys.platform.startswith("linux"):
        return platform.machine() in {"x86_64", "amd64"}
    return False


pytestmark = pytest.mark.skipif(
    not _is_advertised_host(),
    reason="only the v0.1 advertised macOS arm64 / manylinux_2_28 x86-64 cells are certified",
)


def _private_env(cell: Path) -> dict[str, str]:
    """The test's whole world: no isolation variable, and every ambient folder private."""

    cache = subprocess.run(["uv", "cache", "dir"], capture_output=True, timeout=15, check=False)
    env = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("FINISHUP_", "YOETZ_")) and not name.startswith("XDG_")
    }
    home = cell / "h"
    home.mkdir(mode=0o700)
    env["HOME"] = str(home)
    for name in _XDG:
        folder = home / name.lower()
        folder.mkdir(mode=0o700)
        env[name] = str(folder)
    run = cell / "r"
    run.mkdir(mode=0o700)
    env["XDG_RUNTIME_DIR"] = str(run)
    env["UV_CACHE_DIR"] = cache.stdout.decode("utf-8").strip()
    env["UV_PYTHON_DOWNLOADS"] = "never"
    return env


def _script(
    args: list[str], env: dict[str, str], timeout: int
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), *args],
        capture_output=True,
        timeout=timeout,
        env=env,
        check=False,
    )


def _json(launcher: Path, args: list[str], env: dict[str, str]) -> dict[str, object]:
    result = subprocess.run(
        [str(launcher), *args, "--json"], capture_output=True, timeout=60, env=env, check=False
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    return cast(dict[str, object], json.loads(result.stdout))


def _start_service(launcher: Path, env: dict[str, str]) -> subprocess.Popen[bytes]:
    proc = subprocess.Popen(
        [str(launcher), "service", "run"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"service exited during startup with {proc.returncode}")
        status = subprocess.run(
            [str(launcher), "service", "status", "--json"],
            capture_output=True,
            timeout=30,
            env=env,
            check=False,
        )
        if status.returncode == 0:
            return proc
        time.sleep(0.2)
    proc.terminate()
    raise AssertionError("service did not become reachable in time")


_BRIDGE_ANSWER_SECONDS = 120.0


def _open_bridge(
    launcher: Path,
    env: dict[str, str],
    cwd: Path,
    processes: list[subprocess.Popen[bytes]],
) -> subprocess.Popen[bytes]:
    """``mcp serve`` held open as a connected host holds it, once it has answered ``initialize``.

    The bridge joins ``processes`` before anything is read from it, so the test's cleanup stops
    it whatever happens next, and its answer is awaited to a bounded deadline.
    """

    proc = subprocess.Popen(
        [str(launcher), "mcp", "serve", "--host", "codex"],
        env=env,
        cwd=cwd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    processes.append(proc)
    assert proc.stdin is not None and proc.stdout is not None
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "dispose-in-use", "version": "1"},
        },
    }
    proc.stdin.write((json.dumps(message) + "\n").encode())
    proc.stdin.flush()
    with selectors.DefaultSelector() as selector:
        selector.register(proc.stdout, selectors.EVENT_READ)
        ready = selector.select(timeout=_BRIDGE_ANSWER_SECONDS)
    assert ready, "the bridge did not answer initialize in time"
    line = proc.stdout.readline()
    assert b'"result"' in line, line[:400]
    return proc


def _stop(proc: subprocess.Popen[bytes]) -> None:
    if proc.stdin is not None:
        proc.stdin.close()
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    if proc.stdout is not None:
        proc.stdout.close()


def test_a_disposal_refused_by_a_live_host_session_changes_nothing() -> None:
    parent = Path.home() / ".yz-dispose"
    parent.mkdir(mode=0o700, exist_ok=True)
    cell = parent / secrets.token_hex(3)
    cell.mkdir(mode=0o700)
    env = _private_env(cell)
    base = cell / "b"
    workdir = cell / "w"
    workdir.mkdir(mode=0o700)
    processes: list[subprocess.Popen[bytes]] = []
    try:
        created = _script(
            [
                "create",
                "--base",
                str(base),
                "--tag",
                "t",
                "--python",
                sys.executable,
                "--lifecycle",
                "disposable",
                "--expires-in",
                "2",
                "--allow-dirty",
                "--json",
            ],
            env,
            900,
        )
        assert created.returncode == 0, created.stderr.decode("utf-8", errors="replace")
        launcher = Path(cast(str, json.loads(created.stdout)["launcher"]))
        state = base / "t" / "state"

        service = _start_service(launcher, env)
        processes.append(service)
        bridge = _open_bridge(launcher, env, workdir, processes)
        before = _json(launcher, ["instance", "status"], env)
        assert (before["mode"], before["binding"]) == ("isolated", "runtime_pin")
        serving = _json(launcher, ["service", "status"], env)["service_instance_id"]

        refused = _script(["dispose", "--base", str(base), "--tag", "t", "--json"], env, 300)
        assert refused.returncode == 2
        assert refused.stderr.decode("utf-8").startswith("runtime_in_use:"), refused.stderr
        # Nothing was stopped or removed: still pinned to the same root, served by the same
        # service, and the launcher still at its path.
        assert launcher.is_file()
        assert (state / "state" / "instance-identity.json").is_file()
        after = _json(launcher, ["instance", "status"], env)
        assert (after["mode"], after["binding"]) == ("isolated", "runtime_pin")
        assert after["path_identity"] == before["path_identity"]
        assert after["installation_id"] == before["installation_id"]
        assert service.poll() is None
        assert _json(launcher, ["service", "status"], env)["service_instance_id"] == serving

        # A second refused disposal is the same refusal, still changing nothing.
        again = _script(["dispose", "--base", str(base), "--tag", "t"], env, 300)
        assert again.returncode == 2 and launcher.is_file()

        # Once the host session is closed, disposal stops the service and removes everything,
        # and the launcher path that hosts were registered with no longer exists.
        _stop(bridge)
        disposed = _script(["dispose", "--base", str(base), "--tag", "t", "--json"], env, 300)
        assert disposed.returncode == 0, disposed.stderr.decode("utf-8", errors="replace")
        outcome = json.loads(disposed.stdout)
        assert outcome["state"] == "removed" and outcome["launchers_withdrawn"] is True
        assert cast(dict[str, object], outcome["instance"])["service_stopped"] is True
        assert service.wait(timeout=60) is not None
        assert not launcher.exists() and not (base / "t").exists()
        absent = _script(["dispose", "--base", str(base), "--tag", "t", "--json"], env, 60)
        assert json.loads(absent.stdout) == {"tag": "t", "state": "absent", "disposed": False}
    finally:
        for proc in processes:
            _stop(proc)
        if (base / "t").exists():
            _script(["dispose", "--base", str(base), "--tag", "t"], env, 300)
        shutil.rmtree(cell, ignore_errors=True)
