"""Shared pieces of the real-network acceptance runs (docs/runbooks/acceptance-matrix.md).

Contributor tooling, never product code. Everything a run makes lives in one fresh owner-only
folder beneath the real home (``~/.yz-acc-*``; never ``/tmp``, which macOS resolves through a
symlink): a client home with private XDG folders, isolated FinishUP server roots, a private
unprivileged ``sshd``, throwaway TLS material. Every process a run starts is recorded and stopped
by its own PID (never by pattern); the helpers FinishUP starts are stopped through FinishUP's own
commands (``server disconnect``/``remove``, which move the helper's stop epoch). Nothing here reads
or writes ``~/.ssh``, the default FinishUP folders or the account's host registrations.

A ``Relay`` is a TCP pass-through this process runs in a thread in front of a server's port: it
counts the connections it accepts (the evidence that a refusal came before any dial) and can delay
every chunk by a fixed amount (the WAN gate's userspace fallback when no network namespace can be
made).
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import json
import os
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

REPO = Path(__file__).resolve().parents[2]
SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


def real_home() -> Path:
    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def load_module(name: str, path: Path) -> ModuleType:
    """Import a repository file by path (``scripts/`` and ``tests/builders`` are not packages)."""

    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, path
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # its dataclasses look their module up by name
    spec.loader.exec_module(module)
    return module


CEREMONY = load_module("acceptance_ceremony", REPO / "scripts" / "dogfood_ci" / "ceremony.py")
Reply = CEREMONY.Reply


def tool(name: str) -> str | None:
    return shutil.which(name, path=SYSTEM_PATH)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def wait_until(predicate: Callable[[], bool], *, seconds: float, interval: float = 0.1) -> bool:
    """Poll ``predicate`` (observed state, never a guess) until it holds or the bound passes."""

    deadline = time.monotonic() + seconds
    while True:
        if predicate():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)


def wait_listening(port: int, *, seconds: float, alive: Callable[[], bool]) -> bool:
    def listening() -> bool:
        if not alive():
            raise RuntimeError("process_exited_before_listening")
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
        except OSError:
            return False
        return True

    return wait_until(listening, seconds=seconds, interval=0.05)


def json_of(text: str) -> dict[str, Any]:
    """The result body of a ``--json`` CLI output (``{"result": ...}`` unwrapped), else ``{}``."""

    try:
        value = json.loads(text)
    except ValueError:
        return {}
    if not isinstance(value, dict):
        return {}
    inner = value.get("result")
    return inner if isinstance(inner, dict) else value


def now_rfc3339() -> str:
    moment = datetime.now(UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


# --- one run's folder and processes --------------------------------------------------------------


class Run:
    """One invocation: its owner-only base folder and every process it started."""

    def __init__(self, label: str, *, keep: bool = False) -> None:
        self.base = Path(tempfile.mkdtemp(prefix=".yz-acc-", dir=real_home()))
        self.base.chmod(0o700)
        self.label = label
        self.keep = keep
        self.processes: list[subprocess.Popen[bytes]] = []
        self.relays: list[Relay] = []
        self.secrets: list[str] = []
        self.finalizers: list[Callable[[], None]] = []

    def folder(self, name: str) -> Path:
        path = self.base / name
        path.mkdir(mode=0o700, exist_ok=True)
        return path

    def spawn(
        self,
        argv: list[str],
        *,
        env: dict[str, str],
        cwd: Path | None = None,
        stderr: Path | None = None,
        stdin: int = subprocess.DEVNULL,
        stdout: int = subprocess.DEVNULL,
    ) -> subprocess.Popen[bytes]:
        error = open(stderr, "ab") if stderr is not None else subprocess.DEVNULL  # noqa: SIM115
        try:
            process = subprocess.Popen(  # noqa: S603 - argv built from fixed tools and paths
                argv, env=env, cwd=cwd, stdin=stdin, stdout=stdout, stderr=error
            )
        finally:
            if stderr is not None:
                error.close()  # type: ignore[union-attr]
        self.processes.append(process)
        return process

    def redact(self, text: str) -> str:
        out = text.replace(str(self.base), "<base>").replace(str(real_home()), "<home>")
        for value in self.secrets:
            if value:
                out = out.replace(value, "<secret>")
        return out

    def stop(self, process: subprocess.Popen[bytes], *, seconds: float = 30.0) -> None:
        """Stop one process this run started, by its own PID."""

        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=seconds)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def close(self) -> None:
        for finalizer in reversed(self.finalizers):
            with contextlib.suppress(Exception):
                finalizer()
        for relay in self.relays:
            relay.stop()
        for process in reversed(self.processes):
            self.stop(process)
        if not self.keep:
            shutil.rmtree(self.base, ignore_errors=True)


def run_command(
    argv: list[str], *, env: dict[str, str], cwd: Path | None = None, timeout: float = 180
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(  # noqa: S603 - fixed launcher and arguments
            argv,
            env=env,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as expired:
        out = expired.stdout or ""
        err = expired.stderr or ""
        return subprocess.CompletedProcess(
            argv,
            124,
            out if isinstance(out, str) else out.decode(errors="replace"),
            (err if isinstance(err, str) else err.decode(errors="replace")) + "\n[timed out]",
        )


# --- a TCP relay that counts dials (and can delay) -----------------------------------------------


class Relay:
    """A TCP pass-through on 127.0.0.1 in a thread of this process; counts accepted connections.

    ``delay`` (seconds) holds every chunk that long before it is written on, in each direction,
    preserving order: a one-way latency, the WAN gate's userspace fallback.
    """

    def __init__(self, target_port: int, *, delay: float = 0.0) -> None:
        self.target_port = target_port
        self.delay = delay
        self.port = free_port()
        self.connections = 0
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._server: asyncio.Server | None = None
        self._thread = threading.Thread(target=self._main, name="acceptance-relay", daemon=True)
        self._thread.start()
        if not self._ready.wait(10):
            raise RuntimeError("relay_did_not_start")

    def _main(self) -> None:
        asyncio.set_event_loop(self._loop)

        async def start() -> None:
            self._server = await asyncio.start_server(self._accept, "127.0.0.1", self.port)
            self._ready.set()

        self._loop.run_until_complete(start())
        self._loop.run_forever()

    async def _pump(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        queue: asyncio.Queue[tuple[float, bytes]] = asyncio.Queue()

        async def write() -> None:
            while True:
                due, chunk = await queue.get()
                wait = due - time.monotonic()
                if wait > 0:
                    await asyncio.sleep(wait)
                if not chunk:
                    with contextlib.suppress(OSError):
                        if writer.can_write_eof():
                            writer.write_eof()
                    return
                writer.write(chunk)
                await writer.drain()

        task = asyncio.ensure_future(write())
        try:
            while True:
                chunk = await reader.read(65536)
                await queue.put((time.monotonic() + self.delay, chunk))
                if not chunk:
                    break
            await task
        except (OSError, asyncio.CancelledError):
            task.cancel()

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        try:
            up_reader, up_writer = await asyncio.open_connection("127.0.0.1", self.target_port)
        except OSError:
            writer.close()
            return
        try:
            await asyncio.gather(self._pump(reader, up_writer), self._pump(up_reader, writer))
        finally:
            for item in (writer, up_writer):
                with contextlib.suppress(Exception):
                    item.close()

    def stop(self) -> None:
        if not self._loop.is_running():
            return

        async def shut() -> None:
            if self._server is not None:
                self._server.close()
            for task in asyncio.all_tasks():
                if task is not asyncio.current_task():
                    task.cancel()

        with contextlib.suppress(Exception):
            asyncio.run_coroutine_threadsafe(shut(), self._loop).result(10)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(10)


def relay(run: Run, target_port: int, *, delay: float = 0.0) -> Relay:
    item = Relay(target_port, delay=delay)
    run.relays.append(item)
    return item


# --- a step recorder -------------------------------------------------------------------------------


@dataclass
class Step:
    name: str
    verdict: str  # pass | fail | skip | info
    detail: str
    transcript: str = ""


@dataclass
class Report:
    title: str
    steps: list[Step] = field(default_factory=list)
    started_at: str = field(default_factory=now_rfc3339)

    def add(self, name: str, ok: bool | None, detail: str, transcript: str = "") -> bool:
        verdict = "info" if ok is None else ("pass" if ok else "fail")
        self.steps.append(Step(name, verdict, detail, transcript))
        marker = {"pass": "PASS", "fail": "FAIL", "info": "info", "skip": "skip"}[verdict]
        print(f"[{self.title}] {marker} {name}: {detail}", flush=True)
        return bool(ok)

    def skip(self, name: str, detail: str) -> None:
        self.steps.append(Step(name, "skip", detail))
        print(f"[{self.title}] skip {name}: {detail}", flush=True)

    @property
    def verdict(self) -> str:
        verdicts = {step.verdict for step in self.steps}
        if "fail" in verdicts:
            return "fail"
        return "pass" if "pass" in verdicts else "skip"

    def to_json(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "started_at": self.started_at,
            "verdict": self.verdict,
            "steps": [step.__dict__ for step in self.steps],
        }


def verdict_of(steps: Iterable[dict[str, Any]]) -> str:
    """A cell's verdict from its recorded steps: any fail fails; else pass if any passed."""

    verdicts = {str(step.get("verdict")) for step in steps}
    if "fail" in verdicts:
        return "fail"
    return "pass" if "pass" in verdicts else "skip"


def excerpt(text: str, *, lines: int = 40, width: int = 600) -> str:
    kept = [
        line if len(line) <= width else f"{line[:width]}... ({len(line) - width} more characters)"
        for line in text.rstrip("\n").splitlines()
    ]
    if len(kept) <= lines:
        return "\n".join(kept)
    return "\n".join([*kept[:lines], f"... ({len(kept) - lines} more lines)"])


# --- the client: an ambient installation with private XDG folders ----------------------------------


class Client:
    """This computer: an unpinned launcher with its own XDG folders (never the default ones)."""

    def __init__(
        self, run: Run, launcher: Path, *, ssh_bin: Path | None = None, name: str = "cli"
    ) -> None:
        self.run = run
        self.launcher = launcher
        self.python = launcher.parent / "python"
        self.home = run.folder(name)
        for leaf in ("s", "c", "d", "k", "r"):
            (self.home / leaf).mkdir(mode=0o700, exist_ok=True)
        self.ssh_bin = ssh_bin
        self.work = run.folder("repo" if name == "cli" else f"repo-{name}")
        self.extra_env: dict[str, str] = {}

    def env(self) -> dict[str, str]:
        path = f"{self.ssh_bin}:/usr/bin:/bin" if self.ssh_bin else "/usr/bin:/bin"
        return {
            "PATH": path,
            "HOME": str(self.home),
            "LANG": "C.UTF-8",
            "TERM": "xterm",
            "NO_COLOR": "1",
            "XDG_STATE_HOME": str(self.home / "s"),
            "XDG_CONFIG_HOME": str(self.home / "c"),
            "XDG_DATA_HOME": str(self.home / "d"),
            "XDG_CACHE_HOME": str(self.home / "k"),
            "XDG_RUNTIME_DIR": str(self.home / "r"),
            "PYTHON_KEYRING_BACKEND": "keyring.backends.fail.Keyring",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            **self.extra_env,
        }

    def fu(self, *arguments: str, timeout: float = 180) -> subprocess.CompletedProcess[str]:
        return run_command(
            [str(self.launcher), *arguments], env=self.env(), cwd=self.work, timeout=timeout
        )

    def ceremony(self, arguments: list[str], replies: list[Any], *, timeout: float = 240) -> Any:
        return CEREMONY.run_ceremony(
            [str(self.launcher), *arguments],
            replies,
            cwd=self.work,
            env=self.env(),
            timeout=timeout,
        )

    def py(self, code: str, *args: str) -> subprocess.CompletedProcess[str]:
        return run_command(
            [str(self.python), "-c", code, *args], env=self.env(), cwd=self.work, timeout=120
        )

    def make_repository(self) -> None:
        env = self.env()
        subprocess.run(["git", "init", "-q", str(self.work)], env=env, check=True)  # noqa: S607
        (self.work / ".gitignore").write_text("*.log\n")
        (self.work / "README.md").write_text("acceptance\n")
        (self.work / "src").mkdir(exist_ok=True)
        (self.work / "src" / "app.py").write_text("print('hello')\n")
        subprocess.run(["git", "-C", str(self.work), "add", "-A"], env=env, check=True)  # noqa: S607
        subprocess.run(  # noqa: S603
            [
                "git",
                "-C",
                str(self.work),
                "-c",
                "user.name=acceptance",  # noqa: S607
                "-c",
                "user.email=acceptance@example.invalid",
                "commit",
                "-q",
                "-m",
                "init",
            ],
            env=env,
            check=True,
        )
        (self.work / ".env").write_text("TOKEN=not-for-the-server\n")
        (self.work / "notes.txt").write_text("untracked before the task\n")

    def servers_dir(self) -> Path:
        return self.home / "s" / "finishup" / "servers"

    def target_root(self, name: str) -> Path | None:
        folder = self.servers_dir()
        if not folder.exists():
            return None
        for path in folder.glob("t_*/target.json"):
            with contextlib.suppress(OSError, ValueError):
                if json.loads(path.read_text()).get("name") == name:
                    return path.parent
        return None


def helper_pid(root: Path | None) -> int | None:
    """The live helper's stamped pid for a target root (read-only; nothing is signalled)."""

    if root is None:
        return None
    try:
        stamp = json.loads((root / "state" / "helper.lock").read_text() or "{}")
    except (OSError, ValueError):
        return None
    pid = stamp.get("pid")
    if type(pid) is not int:
        return None
    try:
        os.kill(pid, 0)
    except OSError:
        return None
    return pid


# --- a server: an isolated FinishUP root ---------------------------------------------------------


CODE_COPY_CONFIG = (
    'schema_version = "1"\n\n[server.code_copy]\nenabled = true\n'
    'retention = ["task_close", "days:7", "until_forgotten"]\nretention_default = "days:7"\n'
    'exclusions = ["*.sqlite"]\n'
)


class Server:
    """An isolated FinishUP root on this computer playing the server (its own vault and keys)."""

    def __init__(self, run: Run, name: str, launcher: Path, *, code_copy: bool = True) -> None:
        self.run = run
        self.name = name
        self.launcher = launcher
        self.root = run.folder(name)
        self.passphrase = ""
        self.edge: subprocess.Popen[bytes] | None = None
        self.edge_kind = ""
        self.port = 0
        self.tls: Any = None
        if code_copy:
            config = self.root / "config"
            config.mkdir(mode=0o700, exist_ok=True)
            (config / "config.toml").write_text(CODE_COPY_CONFIG)
            (config / "config.toml").chmod(0o600)

    def env(self) -> dict[str, str]:
        return {
            "PATH": "/usr/bin:/bin",
            "HOME": str(real_home()),
            "LANG": "C.UTF-8",
            "NO_COLOR": "1",
            "FINISHUP_ISOLATED_ROOT": str(self.root),
            "PYTHON_KEYRING_BACKEND": "keyring.backends.fail.Keyring",
            # Never the default folders, even for a stray ambient read or diagnostic.
            "XDG_STATE_HOME": str(self.root.parent / "srv-xdg" / "s"),
            "XDG_CONFIG_HOME": str(self.root.parent / "srv-xdg" / "c"),
            "XDG_DATA_HOME": str(self.root.parent / "srv-xdg" / "d"),
            "XDG_CACHE_HOME": str(self.root.parent / "srv-xdg" / "k"),
        }

    def srv(self, *arguments: str, timeout: float = 120) -> subprocess.CompletedProcess[str]:
        return run_command([str(self.launcher), *arguments], env=self.env(), timeout=timeout)

    def ceremony(self, arguments: list[str], replies: list[Any], *, timeout: float = 240) -> Any:
        return CEREMONY.run_ceremony(
            [str(self.launcher), *arguments], replies, env=self.env(), timeout=timeout
        )

    def initialize_vault(self) -> bool:
        import secrets

        self.passphrase = secrets.token_urlsafe(24)
        self.run.secrets.append(self.passphrase)
        result = self.ceremony(
            ["service", "initialize-passphrase", "--json"],
            [
                Reply(r"Passphrase \(", self.passphrase),
                Reply(r"Confirm passphrase", self.passphrase),
            ],
        )
        if result.exit_code != 0:
            print(self.run.redact(result.transcript), file=sys.stderr)
        return result.exit_code == 0

    def vault_state(self) -> str | None:
        """The service's vault state (``locked``, ``ready``...), ``None`` while it does not answer."""

        status = self.srv("service", "status", "--json")
        if status.returncode != 0:
            return None
        return str(json_of(status.stdout).get("state"))

    def unlock(self) -> bool:
        """Wait (bounded) until the service answers, then unlock its vault if it is locked."""

        state: list[str | None] = [None]

        def answers() -> bool:
            state[0] = self.vault_state()
            return state[0] is not None

        if not wait_until(answers, seconds=60, interval=0.3):
            return False
        if state[0] != "locked":
            return True
        result = self.ceremony(
            ["service", "unlock", "--json"], [Reply(r"Passphrase", self.passphrase)]
        )
        return result.exit_code == 0 and self.vault_state() not in {None, "locked"}

    def api_key(self, label: str, scope: str = "operator") -> Path:
        path = self.root.parent / f"{self.name}-{label}.key"
        result = self.srv(
            "service",
            "api-key",
            "create",
            "--label",
            label,
            "--scope",
            scope,
            "--output-file",
            str(path),
        )
        assert result.returncode == 0, self.run.redact(result.stdout + result.stderr)
        self.run.secrets.append(path.read_text().strip())
        return path

    def service_running(self) -> bool:
        return self.srv("service", "status", "--json").returncode == 0

    def stop_service(self) -> bool:
        if self.edge_kind == "native":
            assert self.edge is not None
            self.run.stop(self.edge)
            return True
        self.srv("service", "stop", "--json")
        return wait_until(lambda: not self.service_running(), seconds=40, interval=0.3)

    def start_service(self) -> bool:
        if self.edge_kind == "native":
            self.start_edge("native", self.port, self.tls)
            return self.unlock()
        result = self.srv("service", "start", "--json")
        return result.returncode == 0 and self.unlock()

    def start_edge(self, edge: str, port: int, tls: Any) -> subprocess.Popen[bytes]:
        self.edge_kind = edge
        self.port = port
        self.tls = tls
        process = self.run.spawn(
            [
                str(self.launcher),
                "service",
                "rest",
                "run",
                "--edge",
                edge,
                "--listen",
                f"127.0.0.1:{port}",
                "--tls-cert",
                str(tls.cert_file),
                "--tls-key",
                str(tls.key_file),
            ],
            env=self.env(),
            stderr=self.root.parent / f"{self.name}-edge.stderr",
        )
        if not wait_listening(port, seconds=60, alive=lambda: process.poll() is None):
            raise RuntimeError("edge_did_not_listen")
        self.edge = process
        if edge == "native" and not wait_until(
            lambda: self.vault_state() is not None, seconds=60, interval=0.3
        ):
            # The native edge is the service: it answers its own control socket once ready.
            raise RuntimeError("native_service_did_not_answer")
        return process

    def new_profile_revision(self) -> bool:
        """The server's service restarts with a new profile revision (a new issuer): every
        client's consent names a revision it no longer issues (the changed-profile case)."""

        if not self.stop_service():
            return False
        (self.root / "state" / "server-profile-revision.json").unlink(missing_ok=True)
        return self.start_service()

    def copy_records(self) -> int:
        folder = self.root / "state" / "code-copies" / "copies"
        return len(list(folder.glob("*/copy.json"))) if folder.exists() else 0

    def copy_events(self, since: str) -> list[str]:
        """The server's bounded code-copy events since ``since`` (closed tokens), each once."""

        seen: dict[tuple[str, str, str], str] = {}
        for log in sorted(self.root.rglob("*.jsonl")):
            with contextlib.suppress(OSError):
                for line in log.read_text(errors="replace").splitlines():
                    if "code_copy" not in line:
                        continue
                    try:
                        record = json.loads(line)
                    except ValueError:
                        continue
                    stamp = str(record.get("timestamp", ""))
                    if stamp < since:
                        continue
                    key = (stamp, str(record.get("operation")), str(record.get("reason")))
                    seen[key] = f"{record.get('operation')} {record.get('reason')}"
        return [seen[key] for key in sorted(seen)]


# --- a private, unprivileged sshd ----------------------------------------------------------------


class Sshd:
    """A private sshd on a free loopback port, key-only, this user; stopped by its own PID."""

    def __init__(self, run: Run) -> None:
        self.run = run
        self.dir = run.folder("ssh")
        self.port = free_port()
        self.user = pwd.getpwuid(os.getuid()).pw_name
        keygen, sshd, ssh = tool("ssh-keygen"), tool("sshd"), tool("ssh")
        if keygen is None or sshd is None or ssh is None:
            raise RuntimeError("openssh_missing")
        for name in ("host_key", "client_key"):
            subprocess.run(  # noqa: S603
                [keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(self.dir / name)], check=True
            )
        (self.dir / "authorized_keys").write_bytes((self.dir / "client_key.pub").read_bytes())
        (self.dir / "authorized_keys").chmod(0o600)
        (self.dir / "sshd_config").write_text(
            "\n".join(
                (
                    f"Port {self.port}",
                    "ListenAddress 127.0.0.1",
                    f"HostKey {self.dir / 'host_key'}",
                    f"AuthorizedKeysFile {self.dir / 'authorized_keys'}",
                    f"PidFile {self.dir / 'sshd.pid'}",
                    "PubkeyAuthentication yes",
                    "PasswordAuthentication no",
                    "KbdInteractiveAuthentication no",
                    "UsePAM no",
                    "StrictModes no",
                    "AllowStreamLocalForwarding yes",
                    "StreamLocalBindUnlink yes",
                    "SetEnv PYTHON_KEYRING_BACKEND=keyring.backends.fail.Keyring",
                    "LogLevel VERBOSE",
                    "",
                )
            )
        )
        (self.dir / "ssh_config").write_text(
            "\n".join(
                (
                    "Host *",
                    f"  IdentityFile {self.dir / 'client_key'}",
                    "  IdentitiesOnly yes",
                    f"  UserKnownHostsFile {self.dir / 'known_hosts'}",
                    "  GlobalKnownHostsFile /dev/null",
                    "",
                )
            )
        )
        self.bin = self.dir / "bin"
        self.bin.mkdir(mode=0o700, exist_ok=True)
        wrapper = self.bin / "ssh"
        wrapper.write_text(f'#!/bin/sh\nexec {ssh} -F {self.dir / "ssh_config"} "$@"\n')
        wrapper.chmod(0o700)
        self.log = self.dir / "sshd.log"
        self.process = run.spawn(
            [sshd, "-D", "-e", "-E", str(self.log), "-f", str(self.dir / "sshd_config")],
            env={"PATH": SYSTEM_PATH},
        )
        if not wait_listening(self.port, seconds=15, alive=lambda: self.process.poll() is None):
            raise RuntimeError("sshd_did_not_listen")

    def count(self, needle: str) -> int:
        if not self.log.exists():
            return 0
        return self.log.read_text(errors="replace").count(needle)


# --- TLS -----------------------------------------------------------------------------------------


def make_tls(folder: Path) -> Any:
    module = load_module("acceptance_tls", REPO / "tests" / "builders" / "tls_material.py")
    return module.make_tls(folder)


# --- request documents ---------------------------------------------------------------------------

ACTOR = {"actor_id": "agent:acceptance", "actor_type": "logical_agent"}
CLIENT_ID = {"kind": "cooperative_agent", "version": "0.1.0", "integration": "local_cli"}


def base_request() -> dict[str, Any]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": f"req_{uuid.uuid4()}",
        "actor": ACTOR,
        "client": CLIENT_ID,
    }


def request_file(run: Run, kind: str, document: dict[str, Any]) -> Path:
    folder = run.folder("requests")
    path = folder / f"{kind}-{uuid.uuid4().hex[:8]}.json"
    path.write_text(json.dumps(document))
    return path


def start_document(work: Path, title: str) -> dict[str, Any]:
    return {
        **base_request(),
        "mode": "create_or_attach",
        "task_title": title,
        "workspace_ref": str(work),
        "external_ref": f"acc-{uuid.uuid4().hex[:8]}",
        "requested_view": "compact",
    }


@dataclass
class Task:
    session_id: str | None
    writer_id: str | None
    task_id: str | None

    @classmethod
    def from_result(cls, body: dict[str, Any]) -> Task:
        session = body.get("session") or {}
        task = body.get("task") or {}
        return cls(
            session.get("session_id") or body.get("session_id"),
            session.get("writer_id") or body.get("writer_id"),
            body.get("task_id") or task.get("task_id"),
        )

    @property
    def ok(self) -> bool:
        return bool(self.session_id and self.writer_id)


def frontier_of(status: dict[str, Any]) -> dict[str, Any] | None:
    """The head frontier a status result names (searched one level down for a wrapped body)."""

    for body in (status, *(v for v in status.values() if isinstance(v, dict))):
        for key in ("head_frontier", "frontier", "subject_frontier", "result_frontier"):
            value = body.get(key)
            if isinstance(value, dict) and "sequence" in value:
                return {"sequence": value["sequence"], "head_digest": value["head_digest"]}
    return None


# --- an MCP bridge driven over stdio (JSON-RPC lines), as a host drives it -------------------------


class Bridge:
    """``finishup mcp serve`` started like a host starts it (absolute launcher, the project folder
    as working directory), driven over stdio. Stopped by closing its stdin, then by its PID."""

    def __init__(self, run: Run, launcher: Path, env: dict[str, str], cwd: Path) -> None:
        import selectors

        self._selectors = selectors
        self.run = run
        self.process = run.spawn(
            [str(launcher), "mcp", "serve"],
            env=env,
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=run.base / f"bridge-{len(run.processes)}.stderr",
        )
        self.next_id = 0
        answer = self.rpc(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "acceptance-host", "version": "1"},
            },
        )
        if "result" not in answer:
            raise RuntimeError(f"bridge_initialize_failed: {answer}")
        self._write({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _write(self, message: dict[str, Any]) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write((json.dumps(message) + "\n").encode())
        self.process.stdin.flush()

    def rpc(self, method: str, params: dict[str, Any], *, seconds: float = 120) -> dict[str, Any]:
        self.next_id += 1
        self._write({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params})
        assert self.process.stdout is not None
        deadline = time.monotonic() + seconds
        with self._selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, self._selectors.EVENT_READ)
            while time.monotonic() < deadline:
                if not selector.select(max(0.0, deadline - time.monotonic())):
                    break
                line = self.process.stdout.readline()
                if not line:
                    return {"error": {"message": "bridge_exited"}}
                with contextlib.suppress(ValueError):
                    value = json.loads(line)
                    if isinstance(value, dict) and value.get("id") == self.next_id:
                        return value
        return {"error": {"message": "bridge_response_deadline"}}

    def tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """One tool call: ``{"ok": bool, "body": <structured result>, "text": <text>}``."""

        answer = self.rpc("tools/call", {"name": name, "arguments": arguments})
        result = answer.get("result") or {}
        text = "".join(
            str(item.get("text", ""))
            for item in result.get("content", [])
            if isinstance(item, dict)
        )
        body = result.get("structuredContent")
        if not isinstance(body, dict):
            body = json_of(text)
        ok = bool(result) and not result.get("isError") and body.get("ok", True) is not False
        return {"ok": ok, "body": body, "text": text, "error": answer.get("error")}

    def close(self) -> None:
        if self.process.stdin is not None:
            with contextlib.suppress(OSError):
                self.process.stdin.close()
        try:
            self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.run.stop(self.process)
        if self.process.stdout is not None:
            self.process.stdout.close()


def mcp_request(**fields: Any) -> dict[str, Any]:
    """A request document as an MCP host's agent sends it (the cooperative MCP integration)."""

    return {
        **base_request(),
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
        **fields,
    }
