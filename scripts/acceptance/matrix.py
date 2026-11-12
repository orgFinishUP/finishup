"""Run the design's compatibility matrix (v2 section 1.2) for real on this computer.

Usage (from a checkout, after ``uv sync``; both root variables unset)::

    uv run python scripts/acceptance/matrix.py run --cells 'ssh-*' --out <dir>
    uv run python scripts/acceptance/matrix.py report --out <dir> --markdown <file>
    uv run python scripts/acceptance/matrix.py list

Cells (``list`` prints them): ``local`` and ``named-local`` (L0 over the unix socket);
``ssh-{relay,direct}-{L1,L2}`` through a private ``sshd``; ``{port,https}-{gateway,native}-
{relay,direct}-{L1,L2}`` against this checkout's REST edges over real TLS; ``official``, the REST
conformance kit against a stand-in server (the official service is built in another repository;
``server add official`` names none in this release). Each remote cell adds a target (the
handshake and the consent on a pseudo-terminal), uses it, runs a claim-bound start, publish,
check and receipt, chooses L2 under the warm helper and back (an L1 cell: the command ends once
the helper follows it and the very next task syncs, then nothing does), proves the repository hold and zero network
refuse before any dial (the dial counter of a pass-through relay in front of the server, the
helper's lock, the export database). The HTTPS and port L2 cells then stop or lose the helper four
ways (``server disconnect``, ``server set --style direct``, ``server use local`` and back, the
helper killed), each followed by a task at once whose start is bounded and whose reads come from
the server's copy, never a stale one. Every remote cell warms the helper with a task and changes
the server's profile (the first call is refused typed within 10 s) and agrees again, has its server
narrow what it offers twice within 30 s (the first start after each is refused at most once,
``remote_profile_checking``, then served within seconds), logs out and in (HTTPS and port),
forgets the copy (L2), disconnects and removes. The two "warm helper" paths are the defects the 2026-11-11
dogfood found and the earlier matrix missed; the stopped-helper and narrowing steps are what the
macOS dogfood found. Every step is recorded with its verdict in ``<out>/<cell>.json``
and a transcript excerpt in ``<out>/<cell>.md``. Exit status 1 when any step failed.

See ``harness.py`` for what a run touches (one fresh 0700 folder beneath the home) and how it stops
what it started.
"""

from __future__ import annotations

import argparse
import contextlib
import fnmatch
import json
import os
import re
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import (  # noqa: E402
    REPO,
    Client,
    Relay,
    Reply,
    Report,
    Run,
    Server,
    Sshd,
    Task,
    base_request,
    excerpt,
    free_port,
    frontier_of,
    graceful_termination,
    helper_pid,
    json_of,
    make_tls,
    now_rfc3339,
    relay,
    request_file,
    run_command,
    start_document,
    typed_refusal,
    verdict_of,
    wait_until,
)


@dataclass(frozen=True)
class Cell:
    name: str
    kind: str  # local | named | ssh | port | https | official
    edge: str  # unix | ssh | gateway | native | rest
    style: str  # unix | relay | direct | -
    level: str  # L0 | L1 | L2 | as advertised

    @property
    def target(self) -> str:
        kind = {"ssh": "ssh", "port": "port", "https": "web"}[self.kind]
        edge = {"ssh": "", "gateway": "-gw", "native": "-nat"}[self.edge]
        return f"{kind}{edge}-{self.style[0]}{self.level[1]}"


def all_cells() -> list[Cell]:
    cells = [
        Cell("local", "local", "unix", "unix", "L0"),
        Cell("named-local", "named", "unix", "unix", "L0"),
    ]
    for style in ("relay", "direct"):
        for level in ("L1", "L2"):
            cells.append(Cell(f"ssh-{style}-{level}", "ssh", "ssh", style, level))
    for kind in ("port", "https"):
        for edge in ("gateway", "native"):
            for style in ("relay", "direct"):
                for level in ("L1", "L2"):
                    cells.append(Cell(f"{kind}-{edge}-{style}-{level}", kind, edge, style, level))
    cells.append(Cell("official", "official", "rest", "-", "as advertised"))
    return cells


def select(patterns: str) -> list[Cell]:
    wanted = [item.strip() for item in patterns.split(",") if item.strip()]
    return [cell for cell in all_cells() if any(fnmatch.fnmatch(cell.name, p) for p in wanted)]


# --- one invocation's world ------------------------------------------------------------------------


@dataclass
class Direct:
    """No relay: the server's own port (no dial count)."""

    port: int
    connections: int = 0


class World:
    """The client, the servers the selected cells need, and the dial counters in front of them."""

    def __init__(
        self, run: Run, launcher: Path, cells: list[Cell], *, relay_delay: float | None = 0.0
    ) -> None:
        """``relay_delay`` ``None`` dials the servers' own ports (no relay, no dial count): the
        WAN gate in a network namespace, where the namespace's loopback carries the delay."""

        self.run = run
        self.launcher = launcher
        self.relay_delay = relay_delay
        needs = {cell.edge for cell in cells}
        self.sshd: Sshd | None = None
        self.servers: dict[str, Server] = {}
        self.relays: dict[str, Relay | Direct] = {}
        self.keys: dict[str, dict[str, Path]] = {}
        self.tls: Any = None
        if "ssh" in needs:
            self.sshd = Sshd(run)
        self.client = Client(run, launcher, ssh_bin=self.sshd.bin if self.sshd else None)
        self.client.make_repository()
        # The L0 cells run on a computer of their own: once this computer's everyday
        # installation has a vault, a server elsewhere needs its live privacy policy (its service
        # running), which the remote cells' zero-network arming does not model.
        self.local_client = Client(run, launcher, name="cli-local")
        self.local_client.make_repository()
        self.active = self.client  # the computer the task steps run on
        self.client_vault = False
        if needs & {"gateway", "native", "rest"}:
            self.tls = make_tls(run.folder("tls"))
        if "ssh" in needs:
            assert self.sshd is not None
            server = Server(run, "srv-ssh", launcher)
            run.finalizers.append(server.stop_service)
            assert server.srv("service", "start", "--json").returncode == 0
            assert server.initialize_vault(), "ssh server vault"
            self.servers["ssh"] = server
            self.relays["ssh"] = self._relay(self.sshd.port)
        if needs & {"gateway", "rest"}:
            server = Server(run, "srv-gw", launcher)
            run.finalizers.append(server.stop_service)
            assert server.srv("service", "start", "--json").returncode == 0
            assert server.initialize_vault(), "gateway server vault"
            self.keys["gateway"] = {
                "operator": server.api_key("laptop"),
                "agent": server.api_key("agent", "agent"),
            }
            server.start_edge("gateway", free_port(), self.tls)
            self.servers["gateway"] = server
            self.relays["gateway"] = self._relay(server.port)
        if "native" in needs:
            server = Server(run, "srv-nat", launcher)
            server.start_edge("native", free_port(), self.tls)
            assert server.initialize_vault(), "native server vault"
            self.keys["native"] = {"operator": server.api_key("laptop")}
            self.servers["native"] = server
            self.relays["native"] = self._relay(server.port)
        run.finalizers.append(self.disconnect_all)

    def _relay(self, port: int) -> Relay | Direct:
        if self.relay_delay is None:
            return Direct(port)
        return relay(self.run, port, delay=self.relay_delay)

    def disconnect_all(self) -> None:
        listed = self.client.fu("server", "list", "--json")
        names: list[str] = []
        with contextlib.suppress(ValueError):
            document = json.loads(listed.stdout)
            for item in document.get("targets", []) if isinstance(document, dict) else []:
                if isinstance(item, dict) and item.get("kind") != "local":
                    names.append(str(item.get("name")))
        for name in names:
            self.client.fu("server", "disconnect", name)
        self.client.fu("service", "stop", "--json")
        self.local_client.fu("service", "stop", "--json")

    def dials(self, cell: Cell) -> int:
        return self.relays[cell.edge].connections

    def server(self, cell: Cell) -> Server:
        return self.servers[cell.edge]


# --- the steps -------------------------------------------------------------------------------------


def shown(world: World, result: subprocess.CompletedProcess[str]) -> str:
    text = result.stdout + (("\n[stderr]\n" + result.stderr) if result.stderr.strip() else "")
    return world.run.redact(excerpt(text))


def consent_replies(name: str) -> list[Any]:
    return [
        Reply(r"continue connecting", "yes", secret=False),
        Reply(r"Type local or listed", "listed", secret=False),
        Reply(r"Type the target name", name, secret=False),
    ]


def start_task(
    world: World, title: str, client: Client | None = None
) -> tuple[Task, subprocess.CompletedProcess[str]]:
    client = client or world.active
    path = request_file(world.run, "start", start_document(client.work, title))
    result = client.fu("start", "--input", str(path), "--json", timeout=240)
    return Task.from_result(json_of(result.stdout)), result


def status_of(world: World, task: Task) -> dict[str, Any]:
    document = {
        **base_request(),
        "session_id": task.session_id,
        "writer_id": task.writer_id,
        "view": "compact",
    }
    path = request_file(world.run, "status", document)
    return json_of(world.active.fu("status", "--input", str(path), "--json").stdout)


def task_round(world: World, report: Report, cell: Cell, title: str) -> Task | None:
    """start → publish → check → receipt, each its own step; the task or ``None``."""

    task, result = start_task(world, title)
    if not report.add(
        "start",
        task.ok,
        f"exit {result.returncode}; session named: {task.ok}",
        shown(world, result),
    ):
        return None
    frontier = frontier_of(status_of(world, task))
    publish = {
        **base_request(),
        "session_id": task.session_id,
        "writer_id": task.writer_id,
        "expected_frontier": frontier,
        "event_drafts": [
            {
                "event_id": f"evt_{uuid.uuid4()}",
                "schema": {"name": "plan_published", "version": "1.0.0"},
                "occurred_at": now_rfc3339(),
                "causal_parents": [],
                "payload": {"plan_version": 1, "summary": "Acceptance plan", "obligation_refs": []},
                "artifact_refs": [],
                "evidence_refs": [],
            }
        ],
    }
    result = world.active.fu(
        "publish-work", "--input", str(request_file(world.run, "publish", publish)), "--json"
    )
    body = json_of(result.stdout)
    report.add(
        "publish",
        result.returncode == 0 and body.get("ok", True) is not False,
        f"exit {result.returncode}",
        shown(world, result),
    )
    (world.active.work / "src" / "app.py").write_text(f"print('changed in {cell.name}')\n")
    check = {
        **base_request(),
        "session_id": task.session_id,
        "writer_id": task.writer_id,
        "expected_frontier": frontier_of(status_of(world, task)),
    }
    result = world.active.fu(
        "check", "--input", str(request_file(world.run, "check", check)), "--json", timeout=300
    )
    body = json_of(result.stdout)
    outcome = ((body.get("closure_readiness") or {}).get("predicted_receipt") or {}).get(
        "conclusion"
    )
    report.add(
        "check",
        result.returncode == 0,
        f"exit {result.returncode}; outcome {outcome}",
        shown(world, result),
    )
    receipt_step(world, report, cell, task, "receipt")
    return task


def receipt_json(
    world: World, task: Task
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    document = {
        **base_request(),
        "task_id": task.task_id,
        "session_id": task.session_id,
        "writer_id": task.writer_id,
        "expected_frontier": frontier_of(status_of(world, task)),
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }
    path = request_file(world.run, "receipt", document)
    result = world.active.fu("receipt", "--input", str(path), "--json", timeout=180)
    return result, json_of(result.stdout)


def receipt_step(world: World, report: Report, cell: Cell, task: Task, name: str) -> dict[str, Any]:
    result, body = receipt_json(world, task)
    member = body.get("evidence_provenance")
    reads = (member or {}).get("reads") or {} if isinstance(member, dict) else {}
    copy_reads = int(reads.get("server_copy_read") or 0) if isinstance(reads, dict) else 0
    if cell.level == "L2":
        ok = result.returncode == 0 and copy_reads > 0
        why = f"server_copy_read {copy_reads} (L2 reads the server's copy)"
    elif cell.level == "L1":
        ok = result.returncode == 0 and copy_reads == 0
        why = f"server_copy_read {copy_reads} (L1 reads through the workspace agent)"
    else:
        ok = result.returncode == 0
        why = "local receipt"
    report.add(
        name,
        ok,
        f"exit {result.returncode}; {why}",
        world.run.redact(json.dumps(member, indent=1))
        if member is not None
        else shown(world, result),
    )
    return body


HOLD_CODE = r"""
import asyncio, sys
from finishup.adapters.workspace_root import canonical_workspace_root
from finishup.client.everyday_policy import record_repository_report
from finishup.client.repository_hold import repository_key
from finishup.ports.control import WorkspaceLocator
root = asyncio.run(canonical_workspace_root(WorkspaceLocator(sys.argv[1])))
print(record_repository_report(repository_key(root), sys.argv[1], no_network=sys.argv[2] == "1"))
"""

ZERO_CODE = r"""
import sys
from finishup.client.everyday_policy import record_reported_policy, remove_marker
print(record_reported_policy(zero_network=True) if sys.argv[1] == "1" else remove_marker())
"""


def export_state(root: Path | None) -> tuple[int, float]:
    folder = (root or Path("/nonexistent")) / "state" / "code-export"
    files = [p for p in folder.rglob("*") if p.is_file()] if folder.exists() else []
    return len(files), max((p.stat().st_mtime for p in files), default=0.0)


def refusal_before_dial(
    world: World,
    report: Report,
    cell: Cell,
    name: str,
    token: str,
    arm: str,
    disarm: str,
    code: str,
) -> None:
    """``code`` armed (a hold or zero network), a start is refused with ``token`` before any dial."""

    client = world.client
    root = client.target_root(cell.target)
    client.fu("server", "disconnect", cell.target)
    wait_until(lambda: helper_pid(root) is None, seconds=15)
    armed = client.py(code, *arm.split())
    dials, export = world.dials(cell), export_state(root)
    task, result = start_task(world, f"{cell.name} {name}")
    text = result.stdout + result.stderr
    dialed = world.dials(cell) - dials
    helper = helper_pid(root)
    unchanged = export_state(root) == export
    ok = result.returncode != 0 and token in text and dialed == 0 and helper is None and unchanged
    report.add(
        name,
        ok,
        f"armed {armed.stdout.strip()}; exit {result.returncode}; `{token}` named: {token in text}; "
        f"new dials {dialed}; helper started: {helper is not None}; export database unchanged: "
        f"{unchanged}",
        shown(world, result),
    )
    client.py(code, *disarm.split())


def traffic(world: World, cell: Cell) -> dict[str, int]:
    """What reached a cell's server so far: the dials and the bytes toward it through its relay
    (bytes over a connection already open, a warm helper's, included) and, behind SSH, every
    channel the server's own ``sshd`` saw opened. The SSH master's keep-alives move bytes on
    their own every 15 seconds, so its bytes are not counted; its channels are."""

    seen: dict[str, int] = {"dials": world.dials(cell)}
    carrier = world.relays[cell.edge]
    if cell.kind == "ssh":
        assert world.sshd is not None
        seen["server_channels"] = world.sshd.channels()
    elif isinstance(carrier, Relay):
        seen["bytes_toward_server"] = carrier.bytes_up
    return seen


def sent_between(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    """What moved between two ``traffic`` readings (every count, also one only ``after`` has)."""

    return {key: after.get(key, 0) - before.get(key, 0) for key in sorted({*before, *after})}


def changed_profile(
    world: World, report: Report, cell: Cell, warm: tuple[int | None, str] | None = None
) -> None:
    client, server = world.client, world.server(cell)
    # The helper the warm step proved serving is the one the change meets, with an agent still
    # registered at the server right before the restart (defect B's path).
    same = True
    if warm is not None:
        registered, unregistered = agent_events(server, warm[1])
        same = (
            helper_pid(client.target_root(cell.target)) == warm[0]
            and registered - unregistered >= 1
        )
    restarted = server.new_profile_revision() and same
    began = time.monotonic()
    first = client.fu("service", "status", "--json", timeout=120)
    took = time.monotonic() - began
    # The first refusal is the one the server named (the hello's answer); every surface names it
    # typed at once (a warm HTTPS relay helper once made it wait out a 30 s deadline and read
    # remote_unreachable; the ssh-direct cells once printed a traceback). Until the profile is
    # fetched again what changed is not known here: remote_profile_checking (repeat the same
    # request); once the consent reads the change, remote_reconsent (ADR-052 decision 10).
    first_continuation = (json_of(first.stdout).get("recovery") or {}).get("continuation")
    seen = (
        typed_refusal(first, "server_profile_changed", "remote_profile_checking")
        or typed_refusal(first, "server_profile_changed", "remote_reconsent")
    ) and took < 10.0

    def consent_changed() -> bool:
        document = json_of(client.fu("server", "status", cell.target, "--json").stdout)
        state = ((document.get("target") or {}).get("consent") or {}).get("state")
        return state == "changed"

    changed = wait_until(consent_changed, seconds=120, interval=1.0)
    # Once the consent reads changed, the next call is refused here, before anything is sent:
    # no dial, nothing over the warm helper's connection, no channel on the server.
    before = traffic(world, cell)
    blocked = client.fu("service", "status", "--json", timeout=60)
    sent = sent_between(before, traffic(world, cell))
    refused = typed_refusal(blocked, "server_profile_changed", "remote_reconsent")
    quiet = not any(sent.values())
    report.add(
        "profile changed → refused",
        restarted and changed and seen and refused and quiet,
        f"warm helper still serving: {same}; server restarted with a new revision: {restarted}; "
        f"first call exit {first.returncode} "
        f"in {took:.1f} s (typed server_profile_changed, {first_continuation}, under 10 s: "
        f"{seen}); "
        "consent state changed: "
        f"{changed}; next call refused typed: {refused}; it sent nothing: {quiet} "
        f"({json.dumps(sent, sort_keys=True)})",
        shown(world, first) + "\n\n" + shown(world, blocked),
    )
    again = client.ceremony(
        ["server", "use", cell.target], [Reply(r"Type the target name", cell.target, secret=False)]
    )
    after = client.fu("service", "status", "--json", timeout=120)
    report.add(
        "re-consent",
        again.exit_code == 0 and after.returncode == 0,
        f"server use exit {again.exit_code}; next call exit {after.returncode}",
        world.run.redact(excerpt(again.transcript.replace("\r", ""), lines=30)),
    )


def agent_events(server: Server, since: str) -> tuple[int, int]:
    """How many workspace agents the server registered and unregistered since ``since`` (its
    bounded ``workspace_agent_registered``/``_unregistered`` events)."""

    registered = unregistered = 0
    for log in sorted(server.root.rglob("*.jsonl")):
        with contextlib.suppress(OSError):
            for line in log.read_text(errors="replace").splitlines():
                if "workspace_agent_" not in line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if str(record.get("timestamp", "")) < since:
                    continue
                if (record.get("operation"), record.get("reason")) == (
                    "workspace_agent_registered",
                    "registered",
                ):
                    registered += 1
                elif record.get("operation") == "workspace_agent_unregistered":
                    unregistered += 1
    return registered, unregistered


# A task's start right after this client stopped or lost what it ran for a target: bounded well
# under the server's 60-second prepare deadline (a stopped helper's agent once held the start's
# sync for all of it, and its reads were then answered from a stale copy: macOS dogfood).
STOPPED_START_SECONDS = 15.0
# After a narrowing the first start may be refused once (the server's refusal is the first news of
# it); the profile is then fetched within about 2 seconds and the start is served within this.
NARROWED_SERVED_SECONDS = 10.0
# How long a caller waits before it repeats a request refused remote_profile_checking ("repeat
# the same request in a few seconds").
REPEAT_SECONDS = 3.0


def publish_and_check(world: World, task: Task, label: str) -> subprocess.CompletedProcess[str]:
    """Publish a plan, change a file and check: the reads a receipt then counts."""

    publish = {
        **base_request(),
        "session_id": task.session_id,
        "writer_id": task.writer_id,
        "expected_frontier": frontier_of(status_of(world, task)),
        "event_drafts": [
            {
                "event_id": f"evt_{uuid.uuid4()}",
                "schema": {"name": "plan_published", "version": "1.0.0"},
                "occurred_at": now_rfc3339(),
                "causal_parents": [],
                "payload": {"plan_version": 1, "summary": "Acceptance plan", "obligation_refs": []},
                "artifact_refs": [],
                "evidence_refs": [],
            }
        ],
    }
    world.active.fu(
        "publish-work", "--input", str(request_file(world.run, "publish", publish)), "--json"
    )
    (world.active.work / "src" / "app.py").write_text(f"print('{label}')\n")
    check = {
        **base_request(),
        "session_id": task.session_id,
        "writer_id": task.writer_id,
        "expected_frontier": frontier_of(status_of(world, task)),
    }
    return world.active.fu(
        "check", "--input", str(request_file(world.run, "check", check)), "--json", timeout=300
    )


def copy_task(world: World, cell: Cell, label: str) -> tuple[bool, str, str]:
    """A task at once: its start within ``STOPPED_START_SECONDS``, then a check whose receipt
    counts reads of the server's copy and none of a stale one. The verdict, the detail and an
    excerpt."""

    began = time.monotonic()
    task, result = start_task(world, f"Acceptance {cell.name} {label}")
    took = time.monotonic() - began
    if not task.ok:
        return False, f"start exit {result.returncode} in {took:.1f} s", shown(world, result)
    checked = publish_and_check(world, task, f"{label} in {cell.name}")
    receipt, body = receipt_json(world, task)
    member = body.get("evidence_provenance")
    reads = (member.get("reads") or {}) if isinstance(member, dict) else {}
    copy = int(reads.get("server_copy_read") or 0) if isinstance(reads, dict) else 0
    stale = int(reads.get("stale_copy_read") or 0) if isinstance(reads, dict) else 0
    ok = (
        took < STOPPED_START_SECONDS
        and checked.returncode == 0
        and receipt.returncode == 0
        and copy > 0
        and stale == 0
    )
    detail = (
        f"start exit {result.returncode} in {took:.1f} s (bound {STOPPED_START_SECONDS:.0f} s); "
        f"check exit {checked.returncode}; receipt exit {receipt.returncode}; server_copy_read "
        f"{copy}; stale_copy_read {stale}"
    )
    transcript = (
        world.run.redact(json.dumps(member, indent=1))
        if member is not None
        else shown(world, receipt)
    )
    return ok, detail, transcript


def own_helper(root: Path | None, target_id: str) -> int | None:
    """The running helper's pid when its command line names this run's target (it is ours)."""

    pid = helper_pid(root)
    if pid is None:
        return None
    try:
        argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    except OSError:
        return None
    return pid if target_id.encode() in argv else None


def stopped_helper_tasks(world: World, report: Report, cell: Cell) -> None:
    """Four ways this client stops or loses what it runs for a server, each followed by a task at
    once (macOS dogfood: a stopped helper's REST agent stayed registered at the server, which sent
    the next start's sync to it and waited out the 60-second prepare deadline, then answered the
    task's reads from a stale copy). Each start is bounded by ``STOPPED_START_SECONDS``, its
    receipt counts reads of the server's copy and ``stale_copy_read 0``, and the server recorded
    no sync that ended ``deadline_exceeded`` or ``agent_disconnected``."""

    client, server = world.client, world.server(cell)
    name = cell.target
    root = client.target_root(name)
    target_id = "" if root is None else root.name

    def warm() -> bool:
        """The helper runs (a call starts it when the last step left none); its background agent
        registers on its first tick, which the caller leaves time for."""

        if own_helper(root, target_id) is None:
            client.fu("service", "status", "--json", timeout=120)
        return wait_until(lambda: own_helper(root, target_id) is not None, seconds=30)

    def use_again() -> str:
        other = client.fu("server", "use", "local")
        back = client.ceremony(
            ["server", "use", name], [Reply(r"Type the target name", name, secret=False)]
        )
        return f"server use local exit {other.returncode}; server use {name} exit {back.exit_code}"

    def set_direct() -> str:
        result = client.fu("server", "set", name, "--style", "direct")
        return f"server set --style direct exit {result.returncode}"

    def kill_helper() -> str:
        pid = own_helper(root, target_id)
        if pid is None:
            return "no helper of this run to kill"
        os.kill(pid, signal.SIGKILL)
        gone = wait_until(lambda: helper_pid(root) is None, seconds=10, interval=0.1)
        return f"helper killed (SIGKILL): {gone}"

    def disconnect() -> str:
        result = client.fu("server", "disconnect", name)
        return f"server disconnect exit {result.returncode}"

    triggers = [
        ("server disconnect", disconnect),
        ("server set --style direct", set_direct),
        ("server use local, then this server again", use_again),
        ("helper killed", kill_helper),
    ]
    for label, action in triggers:
        warmed = warm()
        time.sleep(2.0)  # the helper's background agent registers on its first tick
        since = now_rfc3339()
        done = action()
        ok, detail, transcript = copy_task(world, cell, label)
        events = server.copy_events(since)
        offline = [e for e in events if "deadline_exceeded" in e or "agent_disconnected" in e]
        report.add(
            f"{label} → task at once",
            warmed and ok and not offline,
            f"helper warm before: {warmed}; {done}; {detail}; copy events: "
            f"{', '.join(events) or 'none'}",
            transcript,
        )
        if label == "server set --style direct" and cell.style != "direct":
            client.fu("server", "set", name, "--style", cell.style)
    # The warm step that follows starts its own helper, as after the zero-network step before.
    client.fu("server", "disconnect", name)
    wait_until(lambda: helper_pid(root) is None, seconds=15)


def narrowed_twice(world: World, report: Report, cell: Cell) -> None:
    """The server narrows what it offers twice within 30 seconds (macOS dogfood: the second
    narrowing was refused on every call until 30 seconds after the helper's profile fetch for the
    first). After the first, the consent follows the new revision by itself; the second is ready
    less than 30 seconds after that fetch, and the first start after it may be refused once, typed
    ``server_profile_changed`` with ``remote_profile_checking`` (repeat the same request), never
    ``remote_reconsent``, then is served within ``NARROWED_SERVED_SECONDS`` of the server being
    ready, the consent following again by itself."""

    client, server = world.client, world.server(cell)
    config = server.root / "config" / "config.toml"
    root = client.target_root(cell.target)
    cache = None if root is None else root / "state" / "server-profile.json"

    def consented_revision() -> object:
        """The server profile revision the consent names now: a narrowing (or an offer that is
        the same for the consent) moves it without the owner."""

        with contextlib.suppress(OSError, ValueError, AttributeError, TypeError):
            assert root is not None
            return (json.loads((root / "target.json").read_text()).get("consent") or {}).get(
                "profile_revision"
            )
        return None

    def fetched_at() -> float | None:
        with contextlib.suppress(OSError):
            return None if cache is None else cache.stat().st_mtime
        return None

    def narrower(round_: int) -> bool:
        """One more exclusion (narrower), then the server's service restarted and unlocked."""

        text = config.read_text()
        match = re.search(r"^exclusions = \[(.*)\]$", text, re.MULTILINE)
        patterns = re.findall(r'"([^"]*)"', match.group(1)) if match else []
        patterns = sorted({*patterns, f"narrowed-{cell.name}-{round_}/"}, key=str.encode)
        listed = ", ".join(f'"{pattern}"' for pattern in patterns)
        config.write_text(
            re.sub(r"^exclusions = \[.*\]$", f"exclusions = [{listed}]", text, flags=re.MULTILINE)
        )
        if server.edge_kind == "native":
            return server.stop_service() and server.start_service()
        restarted = server.srv("service", "restart", "--json", timeout=180)
        return restarted.returncode == 0 and server.unlock()

    before = consented_revision()
    restarted = narrower(1)
    first = client.fu("service", "status", "--json", timeout=120)

    def moved_on() -> bool:
        now = consented_revision()
        return now is not None and now != before

    followed = wait_until(moved_on, seconds=30, interval=0.3)
    fetched = fetched_at()
    report.add(
        "narrowing 1 → the consent follows by itself",
        restarted and followed,
        f"server restarted narrower: {restarted}; first call exit {first.returncode}; the consent "
        f"followed the new revision by itself: {followed}",
        shown(world, first),
    )
    before = consented_revision()
    restarted = narrower(2)
    ready = time.monotonic()
    since_fetch = None if fetched is None else time.time() - fetched
    refusals: list[str] = []
    served: float | None = None
    last: subprocess.CompletedProcess[str] | None = None
    while time.monotonic() - ready < 30.0:
        task, last = start_task(world, f"Acceptance {cell.name} narrowed twice")
        if task.ok:
            served = time.monotonic() - ready
            break
        document = json_of(last.stdout)
        continuation = (document.get("recovery") or {}).get("continuation")
        refusals.append(f"{document.get('phase')}/{continuation}")
        # As remote_profile_checking's directive asks: the same request again in a few seconds
        # (in the direct style the helper's own fetch over SSH takes about 3 to 4 of them).
        time.sleep(REPEAT_SECONDS)
    checking = all(item == "server_profile_changed/remote_profile_checking" for item in refusals)
    after = consented_revision()
    moved = after is not None and after != before
    report.add(
        "narrowing 2 within 30 s → refused at most once, then served",
        restarted
        and since_fetch is not None
        and since_fetch < 30.0
        and served is not None
        and served <= NARROWED_SERVED_SECONDS
        and len(refusals) <= 1
        and checking
        and moved,
        f"server restarted narrower: {restarted}; ready "
        + (f"{since_fetch:.1f} s" if since_fetch is not None else "unknown time")
        + " after the helper's profile fetch for narrowing 1; refusals before the start was "
        + f"served: {refusals or 'none'}; served "
        + (f"{served:.1f} s after the server was ready" if served is not None else "never")
        + f" (bound {NARROWED_SERVED_SECONDS:.0f} s); the consent followed the new revision by "
        + f"itself: {moved}",
        shown(world, last) if last is not None else "",
    )


def warm_helper(world: World, report: Report, cell: Cell) -> tuple[int | None, str]:
    """Before the profile changes, a task's start warms the helper: its workspace is registered,
    the helper's background agent is connected to the server and its first profile fetch is done
    (defect B of the 2026-11-11 dogfood: a warm HTTPS relay helper read a changed profile as
    ``remote_unreachable`` after 31 s; the hold and zero-network steps before this one leave the
    helper stopped, so the matrix never saw it). Warm means, at the server, an agent still
    registered once the start's own one left (the helper's background agent), and, here, the
    profile cache written since the step began (a fetch landing after the restart would let the
    consent read changed before the first call and skip the warm path). The server's events name
    no agent's role, so which agent survived is inferred, and checked again right before the
    restart (``changed_profile``). The helper's pid and when the step began."""

    client, server = world.client, world.server(cell)
    root = client.target_root(cell.target)
    since = now_rfc3339()
    began = time.time()
    task, result = start_task(world, f"Acceptance {cell.name} warm")
    running = wait_until(lambda: helper_pid(root) is not None, seconds=30, interval=0.3)

    def background_agent() -> bool:
        registered, unregistered = agent_events(server, since)
        return registered >= 2 and unregistered >= 1 and registered - unregistered >= 1

    agent = wait_until(background_agent, seconds=60, interval=0.5)
    cache = None if root is None else root / "state" / "server-profile.json"

    def fetched() -> bool:
        with contextlib.suppress(OSError):
            return cache is not None and cache.stat().st_mtime >= began
        return False

    refreshed = wait_until(fetched, seconds=60, interval=0.5)
    pid = helper_pid(root)
    registered, unregistered = agent_events(server, since)
    report.add(
        "helper warmed by a task",
        task.ok and running and agent and refreshed and pid is not None,
        f"start exit {result.returncode}; helper running: {running}; the helper's background "
        f"agent registered at the server after the start's own left: {agent} ({registered} "
        f"registered, {unregistered} unregistered); first profile fetch done: {refreshed}",
        shown(world, result),
    )
    return pid, since


def level_switch(world: World, report: Report, cell: Cell) -> bool:
    """L2 chosen for a server in use at L1 while its helper runs takes effect at once (defect A of
    the 2026-11-11 dogfood: the helper's L1 agent stayed the one the server asked, so every sync
    was refused ``operation_not_declared`` until it restarted; the L2 cells consent at ``add``, so
    the matrix never saw it). ``server use --level`` ends once the running helper follows the new
    level, and the very next task syncs; back at L1 nothing syncs and the copy is forgotten.
    Whether the copy was made."""

    client, server = world.client, world.server(cell)
    root = client.target_root(cell.target)
    helper = helper_pid(root)
    up = client.ceremony(
        ["server", "use", cell.target, "--level", "L2", "--retention", "days:7"],
        [Reply(r"Type the target name", cell.target, secret=False)],
    )
    # The command ends once the helper that served at L1 follows the new level (or stopped it).
    followed = helper is not None and helper_pid(root) in {helper, None}
    since = now_rfc3339()
    copies = server.copy_records()
    task, result = start_task(world, f"Acceptance {cell.name} after L2")
    events = server.copy_events(since)
    synced = server.copy_records() > copies and any(
        event.startswith("code_copy_sync_synced") for event in events
    )
    made = report.add(
        "L1 → L2 under a warm helper syncs",
        up.exit_code == 0 and task.ok and followed and synced,
        f"server use --level L2 exit {up.exit_code}; the helper that served at L1 followed it "
        f"(same process: {helper_pid(root) == helper}): {followed}; start exit {result.returncode}; "
        f"server copy records {copies} → "
        f"{server.copy_records()}; copy events: {', '.join(events) or 'none'}",
        world.run.redact(excerpt(up.transcript.replace("\r", ""), lines=30)),
    )
    forgot = client.fu("server", "code", "forget", timeout=180)
    down = client.ceremony(
        ["server", "use", cell.target, "--level", "L1"],
        [Reply(r"Type the target name", cell.target, secret=False)],
    )
    since = now_rfc3339()
    task, result = start_task(world, f"Acceptance {cell.name} back at L1")
    events = server.copy_events(since)
    report.add(
        "back to L1: nothing synced",
        forgot.returncode == 0
        and down.exit_code == 0
        and task.ok
        and server.copy_records() == 0
        and not any(event.startswith("code_copy_sync_synced") for event in events),
        f"forget exit {forgot.returncode}; server use --level L1 exit {down.exit_code}; start exit "
        f"{result.returncode}; server copy records {server.copy_records()}; copy events: "
        f"{', '.join(events) or 'none'}",
        shown(world, forgot),
    )
    return made


def logout_login(world: World, report: Report, cell: Cell) -> None:
    client = world.client
    out = client.fu("server", "logout", cell.target)
    dials = world.dials(cell)
    refused = client.fu("service", "status", "--json", timeout=60)
    dialed = world.dials(cell) - dials
    report.add(
        "logout → refused",
        out.returncode == 0 and refused.returncode != 0 and dialed == 0,
        f"logout exit {out.returncode}; next call exit {refused.returncode}; new dials {dialed}",
        shown(world, refused),
    )
    key = world.keys[cell.edge]["operator"]
    back = client.fu("server", "login", cell.target, "--key-file", str(key))
    after = client.fu("service", "status", "--json", timeout=120)
    report.add(
        "login",
        back.returncode == 0 and after.returncode == 0,
        f"login exit {back.returncode}; next call exit {after.returncode}",
        shown(world, back),
    )


def forget(world: World, report: Report, cell: Cell, task: Task) -> None:
    client, server = world.client, world.server(cell)
    before = server.copy_records()
    result = client.fu("server", "code", "forget", timeout=180)
    after = server.copy_records()
    report.add(
        "forget",
        result.returncode == 0 and before >= 1 and after == 0,
        f"exit {result.returncode}; server copy records {before} → {after}",
        shown(world, result),
    )

    def marked() -> bool:
        member = receipt_json(world, task)[1].get("evidence_provenance")
        return isinstance(member, dict) and bool(member.get("content_forgotten"))

    report.add(
        "content forgotten marker",
        wait_until(marked, seconds=45, interval=1.0),
        "the task that read the copy names its forgotten content on its receipt",
    )


def effective_style(client: Client, name: str) -> str | None:
    """The connection style ``server status NAME --json`` reports for a target (what its next
    connection uses), ``None`` when it names none."""

    document = json_of(client.fu("server", "status", name, "--json").stdout)
    connection = (document.get("target") or {}).get("connection")
    style = connection.get("style") if isinstance(connection, dict) else None
    return style if isinstance(style, str) else None


def address_of(world: World, cell: Cell) -> list[str]:
    """``server add`` arguments after the name for a remote cell (through its relay)."""

    server = world.server(cell)
    port = world.relays[cell.edge].port
    if cell.kind == "ssh":
        assert world.sshd is not None
        return [
            f"ssh://{world.sshd.user}@127.0.0.1:{port}",
            "--remote-root",
            str(server.root),
            "--remote-launcher",
            str(server.launcher),
        ]
    elif cell.kind == "https":
        return [
            f"https://localhost:{port}",
            "--ca-file",
            str(world.tls.ca_file),
            "--key-file",
            str(world.keys[cell.edge]["operator"]),
        ]
    else:
        return [
            "--port",
            str(port),
            "--tls-pin",
            world.tls.pin,
            "--key-file",
            str(world.keys[cell.edge]["operator"]),
        ]


def remote_cell(world: World, cell: Cell) -> Report:
    report = Report(cell.name)
    client, server = world.client, world.server(cell)
    name = cell.target
    address = address_of(world, cell)
    level = ["--level", cell.level] + (["--retention", "days:7"] if cell.level == "L2" else [])
    dials = world.dials(cell)
    added = client.ceremony(["server", "add", name, *address, *level], consent_replies(name))
    root = client.target_root(name)
    consent: dict[str, Any] = {}
    if root is not None:
        with contextlib.suppress(OSError, ValueError):
            consent = json.loads((root / "target.json").read_text()).get("consent") or {}
    if not report.add(
        "add (handshake, consent)",
        added.exit_code == 0 and root is not None and consent.get("level") == cell.level,
        f"exit {added.exit_code}; consent level {consent.get('level')}; handshake dials "
        f"{world.dials(cell) - dials}",
        world.run.redact(excerpt(added.transcript.replace("\r", ""), lines=60)),
    ):
        return report
    if cell.style == "direct":
        result = client.fu("server", "set", name, "--style", "direct")
        style = effective_style(client, name)
        report.add(
            "style direct",
            result.returncode == 0 and style == "direct",
            f"exit {result.returncode}; effective style {style}",
            shown(world, result),
        )
    used = client.ceremony(
        ["server", "use", name], [Reply(r"Type the target name", name, secret=False)]
    )
    if not report.add(
        "use",
        used.exit_code == 0,
        f"exit {used.exit_code}",
        world.run.redact(excerpt(used.transcript.replace("\r", ""), lines=30)),
    ):
        return report
    result = client.fu("service", "status", "--json", timeout=120)
    document = json_of(client.fu("server", "status", name, "--json").stdout)
    connection = (document.get("target") or {}).get("connection")
    report.add(
        "connect",
        result.returncode == 0,
        f"exit {result.returncode}; helper running: {helper_pid(root) is not None}; "
        f"connection {json.dumps(connection, sort_keys=True)}",
        shown(world, result),
    )
    since = now_rfc3339()
    task = task_round(world, report, cell, f"Acceptance {cell.name}")
    switched = cell.level == "L1" and task is not None and level_switch(world, report, cell)
    if cell.level == "L2":
        events = server.copy_events(since)
        listed = client.fu("server", "code", "list")
        report.add(
            "sync",
            server.copy_records() >= 1 and any("sync" in e for e in events),
            f"server copy records {server.copy_records()}; copy events: "
            f"{', '.join(events) or 'none'}",
            shown(world, listed),
        )
    refusal_before_dial(
        world,
        report,
        cell,
        "hold refuses before any dial",
        "repository_egress_held",
        f"{client.work} 1",
        f"{client.work} 0",
        HOLD_CODE,
    )
    refusal_before_dial(
        world,
        report,
        cell,
        "zero network refuses before any dial",
        "zero_network_remote_selected",
        "1",
        "0",
        ZERO_CODE,
    )
    if cell.level == "L2" and cell.kind in {"https", "port"} and task is not None:
        stopped_helper_tasks(world, report, cell)
    warm = warm_helper(world, report, cell)
    changed_profile(world, report, cell, warm)
    narrowed_twice(world, report, cell)
    if cell.kind in {"https", "port"}:
        logout_login(world, report, cell)
    if cell.level == "L2" and task is not None:
        forget(world, report, cell, task)
    result = client.fu("server", "disconnect", name)
    gone = wait_until(lambda: helper_pid(root) is None, seconds=15)
    report.add(
        "disconnect",
        result.returncode == 0 and gone,
        f"exit {result.returncode}; helper stopped: {gone}",
        shown(world, result),
    )
    client.fu("server", "use", "local")
    removal = ["--forget-copies"] if cell.level == "L2" or switched else []
    result = client.fu("server", "remove", name, *removal, timeout=180)
    report.add(
        "remove",
        result.returncode == 0 and client.target_root(name) is None,
        f"exit {result.returncode}; target folder gone: {client.target_root(name) is None}",
        shown(world, result),
    )
    return report


def init_vault(world: World) -> tuple[bool, str]:
    """Start the selected local root's service and give it a passphrase vault (a ceremony)."""

    started = world.local_client.fu("service", "start", "--json", timeout=120)
    passphrase = os.urandom(18).hex()
    world.run.secrets.append(passphrase)
    result = world.local_client.ceremony(
        ["service", "initialize-passphrase", "--json"],
        [Reply(r"Passphrase \(", passphrase), Reply(r"Confirm passphrase", passphrase)],
    )
    text = f"service start exit {started.returncode}\n" + result.transcript.replace("\r", "")
    return started.returncode == 0 and result.exit_code == 0, world.run.redact(excerpt(text))


def client_vault(world: World) -> tuple[bool, str]:
    if world.client_vault:
        return True, ""
    ok, text = init_vault(world)
    world.client_vault = ok
    return ok, text


def local_cell(world: World, cell: Cell) -> Report:
    world.active = world.local_client
    try:
        return _local_cell(world, cell)
    finally:
        world.active = world.client


def _local_cell(world: World, cell: Cell) -> Report:
    report = Report(cell.name)
    client = world.local_client
    if cell.kind == "named":
        added = client.ceremony(
            ["server", "add", "lab", "--local"],
            [Reply(r"Type the target name", "lab", secret=False)],
        )
        report.add(
            "add named local",
            added.exit_code == 0,
            f"exit {added.exit_code}",
            world.run.redact(excerpt(added.transcript.replace("\r", ""))),
        )
        used = client.ceremony(
            ["server", "use", "lab"], [Reply(r"Type the target name", "lab", secret=False)]
        )
        report.add(
            "use",
            used.exit_code == 0,
            f"exit {used.exit_code}",
            world.run.redact(excerpt(used.transcript.replace("\r", ""))),
        )
        ok, text = init_vault(world)
        report.add("vault", ok, "the named server's own service and vault", text)
    else:
        ok, text = client_vault(world)
        report.add("vault", ok, "this computer's own service and vault", text)
    task_round(world, report, cell, f"Acceptance {cell.name}")
    for title, code, arm, disarm in (
        ("zero network keeps the local server", ZERO_CODE, "1", "0"),
        ("hold keeps the local server", HOLD_CODE, f"{client.work} 1", f"{client.work} 0"),
    ):
        client.py(code, *arm.split())
        task, result = start_task(world, f"{cell.name} {title}")
        report.add(
            title,
            task.ok,
            f"exit {result.returncode}: nothing leaves this computer, so nothing is refused",
            shown(world, result),
        )
        client.py(code, *disarm.split())
    stopped = client.fu("service", "stop", "--json")
    report.add(
        "service stop", stopped.returncode == 0, f"exit {stopped.returncode}", shown(world, stopped)
    )
    if cell.kind == "named":
        root = client.target_root("lab")
        client.fu("server", "use", "local")
        removed = client.fu("server", "remove", "lab")
        report.add(
            "remove",
            removed.returncode == 0 and (root is None or not root.exists()),
            f"exit {removed.returncode}",
            shown(world, removed),
        )
    return report


def official_cell(world: World, cell: Cell) -> Report:
    report = Report(cell.name)
    preset = world.client.ceremony(["server", "add", "official"], [])
    text = preset.transcript.replace("\r", "")
    report.add(
        "server add official",
        preset.exit_code != 0,
        f"exit {preset.exit_code}: this release names no official endpoint, so the preset "
        "refuses (U8: the official service is built in another repository)",
        world.run.redact(excerpt(text, lines=12)),
    )
    server = world.servers["gateway"]
    keys = world.keys["gateway"]
    env = {
        **os.environ,
        "FINISHUP_REST_URL": f"https://localhost:{world.relays['gateway'].port}",
        "FINISHUP_REST_KEY": keys["operator"].read_text().strip(),
        "FINISHUP_REST_AGENT_KEY": keys["agent"].read_text().strip(),
        "FINISHUP_REST_CA_FILE": str(world.tls.ca_file),
    }
    for name in ("FINISHUP_ISOLATED_ROOT", "YOETZ_ISOLATED_ROOT"):
        env.pop(name, None)
    kit = run_command(
        [
            str(world.launcher.parent / "python"),
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "tests/conformance/rest",
        ],
        env=env,
        cwd=REPO,
        timeout=540,
    )
    tail = kit.stdout.strip().splitlines()[-1:] or ["(no output)"]
    report.add(
        "conformance kit against a stand-in",
        kit.returncode == 0,
        f"exit {kit.returncode}; {tail[0]} (the kit pointed at a running server by URL, "
        f"as the official service's repository runs it; stand-in: gateway edge of "
        f"{server.name})",
        world.run.redact(excerpt(kit.stdout, lines=20)),
    )
    return report


def run_cells(cells: list[Cell], launcher: Path, out: Path, keep: bool) -> int:
    out.mkdir(parents=True, exist_ok=True)
    graceful_termination()
    run = Run("matrix", keep=keep)
    # Where this run's folder is, for an outer runner that must see its cleanup proven.
    (out / "run.json").write_text(json.dumps({"base": str(run.base)}))
    failed = 0
    try:
        world = World(run, launcher, cells)
        commit = subprocess.run(  # noqa: S603
            ["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        for cell in cells:
            began = time.monotonic()
            try:
                if cell.kind in {"local", "named"}:
                    report = local_cell(world, cell)
                elif cell.kind == "official":
                    report = official_cell(world, cell)
                else:
                    report = remote_cell(world, cell)
            except Exception as error:  # noqa: BLE001 - recorded as the cell's failure
                report = Report(cell.name)
                report.add(
                    "harness", False, f"{type(error).__name__}: {run.redact(str(error))[:300]}"
                )
            document = {
                **report.to_json(),
                "cell": cell.__dict__,
                "commit": commit,
                "seconds": round(time.monotonic() - began, 1),
            }
            failed += document["verdict"] == "fail"
            (out / f"{cell.name}.json").write_text(json.dumps(document, indent=1))
            (out / f"{cell.name}.md").write_text(cell_markdown(document))
    finally:
        problems = run.close()
        (out / "cleanup.json").write_text(
            json.dumps({"proven": not problems, "problems": problems}, indent=1)
        )
    return 1 if failed or problems else 0


def cell_markdown(document: dict[str, Any]) -> str:
    lines = [
        f"### {document['title']} — {document['verdict']} ({document['seconds']} s, "
        f"`{document['commit']}`)",
        "",
    ]
    for step in document["steps"]:
        lines.append(f"- **{step['verdict']}** {step['name']}: {step['detail']}")
        if step.get("transcript"):
            lines += [
                "",
                "  ```text",
                *("  " + line for line in step["transcript"].splitlines()),
                "  ```",
                "",
            ]
    return "\n".join(lines) + "\n"


STEP_COLUMNS = (
    ("add", ("add (handshake, consent)", "add named local", "vault")),
    ("use", ("use",)),
    ("task", ("start", "publish", "check", "receipt")),
    (
        "hold/zero-net",
        (
            "hold refuses before any dial",
            "zero network refuses before any dial",
            "zero network keeps the local server",
            "hold keeps the local server",
        ),
    ),
    ("re-consent", ("profile changed → refused", "re-consent")),
    ("logout", ("logout → refused", "login")),
    ("L2 sync/forget", ("sync", "forget", "content forgotten marker")),
    ("out", ("disconnect", "remove", "service stop")),
)


def report_markdown(out: Path) -> str:
    rows = [
        "| Cell | Edge | Style | Level | "
        + " | ".join(c for c, _ in STEP_COLUMNS)
        + " | Verdict | s |",
        "|" + "---|" * (len(STEP_COLUMNS) + 6),
    ]
    details: list[str] = []
    for cell in all_cells():
        path = out / f"{cell.name}.json"
        if not path.exists():
            rows.append(
                f"| {cell.name} | {cell.edge} | {cell.style} | {cell.level} | "
                + " | ".join("—" for _ in STEP_COLUMNS)
                + " | not run | |"
            )
            continue
        document = json.loads(path.read_text())
        steps = {step["name"]: step["verdict"] for step in document["steps"]}
        cells: list[str] = []
        for _, names in STEP_COLUMNS:
            got = [steps[n] for n in names if n in steps]
            cells.append("n/a" if not got else verdict_of({"verdict": v} for v in got))
        rows.append(
            f"| {cell.name} | {cell.edge} | {cell.style} | {cell.level} | "
            + " | ".join(cells)
            + f" | **{document['verdict']}** | {document['seconds']} |"
        )
        details.append((out / f"{cell.name}.md").read_text())
    return "\n".join(rows) + "\n\n" + "\n".join(details)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    run_p = sub.add_parser("run")
    run_p.add_argument("--cells", required=True, help="comma-separated names or globs")
    run_p.add_argument("--out", type=Path, required=True)
    run_p.add_argument("--launcher", type=Path, default=REPO / ".venv" / "bin" / "finishup")
    run_p.add_argument("--keep", action="store_true", help="keep the run's folder (debugging)")
    report_p = sub.add_parser("report")
    report_p.add_argument("--out", type=Path, required=True)
    report_p.add_argument("--markdown", type=Path)
    sub.add_parser("list")
    args = parser.parse_args(argv)
    if args.command == "list":
        for cell in all_cells():
            print(f"{cell.name}\t{cell.edge}\t{cell.style}\t{cell.level}")
        return 0
    if args.command == "report":
        text = report_markdown(args.out)
        if args.markdown:
            args.markdown.write_text(text)
        print(text)
        return 0
    for name in ("FINISHUP_ISOLATED_ROOT", "YOETZ_ISOLATED_ROOT"):
        if os.environ.get(name):
            parser.error(f"unset {name}: the client must be an ambient installation")
    cells = select(args.cells)
    if not cells:
        parser.error("no cell matches")
    return run_cells(cells, args.launcher.absolute(), args.out, args.keep)


if __name__ == "__main__":
    raise SystemExit(main())
