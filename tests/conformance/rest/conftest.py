"""The REST server conformance kit's target: any URL, or this checkout's own edges (ADR-053).

Point the kit at any FinishUP REST v1 server with a test key:

* ``FINISHUP_REST_URL`` — the server's base URL (``https://host[:port][/base]``);
* ``FINISHUP_REST_KEY`` — an ``operator`` key; ``FINISHUP_REST_AGENT_KEY`` — an ``agent`` key
  (optional: the scope cases skip without it);
* ``FINISHUP_REST_CA_FILE`` or ``FINISHUP_REST_TLS_PIN`` — how to trust its certificate (else the
  system store).

Without ``FINISHUP_REST_URL`` the kit provisions, under a fresh 0700 folder beneath the home
directory, a throwaway CA, an isolated server root of this checkout with a passphrase vault (the
repository's pseudo-terminal ceremony), an operator and an agent key, and runs ``finishup service
rest run`` twice on free loopback ports — ``--edge gateway`` and ``--edge native`` — so every case
runs against both backends over real TLS. Every process it starts it stops by its own PID (and the
root's service with ``finishup service stop``); the folder is removed. Nothing touches the
developer's own FinishUP folders.
"""

from __future__ import annotations

import importlib.util
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

from builders.rest_kit import ProvisionedServer, RestTarget

_REPO = Path(__file__).resolve().parents[3]
_LAUNCHER = _REPO / ".venv" / "bin" / "finishup"


def _ceremony() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "dogfood_ci_ceremony", _REPO / "scripts" / "dogfood_ci" / "ceremony.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Registered before it runs: its dataclasses look their module up by name.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _server_env(root: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(Path.home()),
        "LANG": "C.UTF-8",
        "FINISHUP_ISOLATED_ROOT": str(root),
        "PYTHON_KEYRING_BACKEND": "keyring.backends.fail.Keyring",
    }


def _run(argv: list[str], root: Path, timeout: float = 120.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - this checkout's own launcher
        argv,
        env=_server_env(root),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


@pytest.fixture(scope="session")
def _provisioned() -> Iterator[ProvisionedServer | None]:  # pyright: ignore[reportUnusedFunction]
    if os.environ.get("FINISHUP_REST_URL"):
        yield None
        return
    if not _LAUNCHER.is_file():
        pytest.skip("this checkout has no launcher (.venv/bin/finishup): run 'uv sync' first")
    from builders.tls_material import make_tls

    base = Path(tempfile.mkdtemp(prefix=".yz-rest-kit-", dir=Path.home()))
    base.chmod(0o700)
    root = base / "srv"
    root.mkdir(mode=0o700)
    try:
        started = _run([str(_LAUNCHER), "service", "start", "--json"], root)
        assert started.returncode == 0, started.stdout + started.stderr
        ceremony = _ceremony()
        passphrase = secrets.token_urlsafe(24)
        result = ceremony.run_ceremony(
            [str(_LAUNCHER), "service", "initialize-passphrase", "--json"],
            [
                ceremony.Reply(r"Passphrase \(", passphrase),
                ceremony.Reply(r"Confirm passphrase", passphrase),
            ],
            env=_server_env(root),
            timeout=240,
        )
        assert result.exit_code == 0, "the passphrase ceremony failed"
        keys: dict[str, str] = {}
        for scope in ("operator", "agent"):
            path = base / f"{scope}.key"
            created = _run(
                [
                    str(_LAUNCHER),
                    "service",
                    "api-key",
                    "create",
                    "--label",
                    f"kit {scope}",
                    "--scope",
                    scope,
                    "--output-file",
                    str(path),
                ],
                root,
            )
            assert created.returncode == 0, created.stderr
            keys[scope] = path.read_text().strip()
        yield ProvisionedServer(
            base, root, keys["operator"], keys["agent"], make_tls(base / "tls"), passphrase
        )
    finally:
        _run([str(_LAUNCHER), "service", "stop", "--json"], root, timeout=60)
        shutil.rmtree(base, ignore_errors=True)


def _start_edge(provisioned: ProvisionedServer, edge: str) -> tuple[subprocess.Popen[bytes], int]:
    tls = provisioned.tls
    port = _free_port()
    process = subprocess.Popen(  # noqa: S603 - this checkout's own launcher
        [
            str(_LAUNCHER),
            "service",
            "rest",
            "run",
            "--edge",
            edge,
            "--listen",
            f"127.0.0.1:{port}",
            "--tls-cert",
            str(tls.cert_file),  # type: ignore[attr-defined]
            "--tls-key",
            str(tls.key_file),  # type: ignore[attr-defined]
        ],
        env=_server_env(provisioned.root),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 60
    while True:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return process, port
        except OSError:
            if process.poll() is not None:
                stderr = process.stderr.read().decode(errors="replace") if process.stderr else ""
                raise AssertionError(f"the {edge} edge did not start: {stderr[-500:]}") from None
            assert time.monotonic() < deadline, f"the {edge} edge did not listen"
            time.sleep(0.05)


def _stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


@pytest.fixture(
    scope="module",
    params=["gateway", "native"] if not os.environ.get("FINISHUP_REST_URL") else ["external"],
)
def rest_target(
    request: pytest.FixtureRequest, _provisioned: ProvisionedServer | None
) -> Iterator[RestTarget]:
    if _provisioned is None:
        yield RestTarget(
            "external",
            os.environ["FINISHUP_REST_URL"].rstrip("/"),
            os.environ["FINISHUP_REST_KEY"],
            os.environ.get("FINISHUP_REST_AGENT_KEY"),
            os.environ.get("FINISHUP_REST_CA_FILE"),
            os.environ.get("FINISHUP_REST_TLS_PIN"),
        )
        return
    edge = str(request.param)
    if edge == "native":
        # The native edge runs the service itself: the gateway's on-demand service stops first.
        _run([str(_LAUNCHER), "service", "stop", "--json"], _provisioned.root, timeout=60)
    process, port = _start_edge(_provisioned, edge)
    if edge == "native":
        # A service started afresh holds a locked passphrase vault: the owner unlocks it on the
        # server host's own terminal (the ceremony), so claims can be keyed.
        ceremony = _ceremony()
        unlocked = ceremony.run_ceremony(
            [str(_LAUNCHER), "service", "unlock", "--json"],
            [ceremony.Reply(r"Passphrase", _provisioned.passphrase)],
            env=_server_env(_provisioned.root),
            timeout=240,
        )
        assert unlocked.exit_code == 0, "the unlock ceremony failed"
    try:
        yield RestTarget(
            edge,
            f"https://127.0.0.1:{port}",
            _provisioned.operator_key,
            _provisioned.agent_key,
            str(_provisioned.tls.ca_file),  # type: ignore[attr-defined]
            None,
        )
    finally:
        _stop(process)
