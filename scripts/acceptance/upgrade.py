"""An upgrade over a still-running older helper, MCP bridge and service (design v2 section 8.11).

Usage (from a checkout, after ``uv sync``; both root variables unset)::

    uv run python scripts/acceptance/upgrade.py --old f1e3f5707 --out <file.json>

Builds the older revision and this checkout's ``HEAD`` exactly as test instances are built
(``scripts/provision_test_instance.py create``: ``git archive``, ``uv build --no-sources``, a pinned
runtime per instance beneath ``~/.yz-l7i``, disposed at the end), then installs those two wheels the
way an everyday installation is upgraded: into one *unpinned* virtual environment per computer, the
newer wheel over the older one in place (``uv pip install --reinstall-package finishup``) while the
processes started from the older one keep running. Two such computers: a client (private XDG
folders) and an SSH server (an isolated root behind a private ``sshd``). A pinned instance cannot
play either: a client must be an ambient installation (``server add`` refuses under a pin), and an
instance is never upgraded in place (``runtime_provenance: drifted``).

Recorded, in order: the older client, helper, bridge and server working; the client upgraded under
them (what the older helper and bridge do next, and the newer CLI); the server upgraded and
restarted by its owner (``service restart``) and the owner agreeing again if asked; a newer bridge
reattaching to the task the older one started; the server's service restarted under an open bridge;
a request replayed with its ``request_id`` after a restart (recorded once); and the bridge following
a new selection (O1: the open remote connection ends ``server_authorization_changed``, the next
request reaches the newly selected server).
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import (  # noqa: E402
    REPO,
    Bridge,
    Client,
    Reply,
    Report,
    Run,
    Server,
    Sshd,
    Task,
    excerpt,
    frontier_of,
    graceful_termination,
    helper_pid,
    mcp_request,
    now_rfc3339,
    real_home,
    redact,
    run_command,
    tail,
    typed_refusal,
)

PROVISION = REPO / "scripts" / "provision_test_instance.py"


def provision(base: Path, tag: str, revision: str) -> Path:
    """Build ``revision`` as a disposable test instance; its wheel. ``HEAD`` may carry changes to
    files outside the package (this script itself while it is developed): ``--allow-dirty``
    records that as the instance's source state."""

    dirty = ["--allow-dirty"] if revision == "HEAD" else []
    result = run_command(
        [
            sys.executable,
            str(PROVISION),
            "create",
            "--base",
            str(base),
            "--tag",
            tag,
            "--checkout",
            str(REPO),
            "--revision",
            revision,
            "--lifecycle",
            "disposable",
            "--expires-in",
            "4",
            "--json",
            *dirty,
        ],
        env={**os.environ, "PATH": f"{Path(sys.executable).parent}:{os.environ['PATH']}"},
        timeout=580,
    )
    if result.returncode != 0:
        raise RuntimeError(f"provision {tag} failed: {tail(redact(result.stderr, base), 800)}")
    (wheel,) = (base / tag / "dist").glob("*.whl")
    return wheel


def dispose(base: Path, tag: str) -> None:
    run_command(
        [sys.executable, str(PROVISION), "dispose", "--base", str(base), "--tag", tag],
        env=dict(os.environ),
        timeout=120,
    )


def venv(path: Path, wheel: Path) -> Path:
    uv = shutil.which("uv")
    assert uv is not None
    subprocess.run([uv, "venv", "-q", "--python", sys.executable, str(path)], check=True)  # noqa: S603
    install(path, wheel)
    return path / "bin" / "finishup"


def install(path: Path, wheel: Path) -> subprocess.CompletedProcess[str]:
    uv = shutil.which("uv")
    assert uv is not None
    result = run_command(
        [
            uv,
            "pip",
            "install",
            "-q",
            "--python",
            str(path / "bin" / "python"),
            "--reinstall-package",
            "finishup",
            str(wheel),
        ],
        env=dict(os.environ),
        timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(f"install failed: {tail(redact(result.stderr, path), 800)}")
    return result


def manifest_digest(launcher: Path) -> str:
    out = run_command(
        [
            str(launcher.parent / "python"),
            "-c",
            "from finishup.protocol.schemas import schema_manifest_digest as d; print(d())",
        ],
        env={"PATH": "/usr/bin:/bin", "HOME": str(real_home())},
    )
    return out.stdout.strip()


def helper_stamp(root: Path | None) -> dict[str, Any]:
    """The helper's stamp (pid, manifest digest) and how its process was started (this run's own
    process tree: its argv and parent, read from ``/proc``)."""

    if root is None:
        return {}
    with contextlib.suppress(OSError, ValueError):
        stamp = json.loads((root / "state" / "helper.lock").read_text() or "{}")
        pid = stamp.get("pid")
        found: dict[str, Any] = {
            "pid": pid,
            "digest": str(stamp.get("schema_manifest_digest"))[:19],
            "alive": helper_pid(root) is not None,
        }
        with contextlib.suppress(OSError):
            argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            found["argv"] = [
                item.decode(errors="replace").replace(str(real_home()), "<home>")
                for item in argv[:4]
            ]
            found["ppid"] = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[1]
        return found
    return {}


def replaced_by(before: dict[str, Any], after: dict[str, Any], digest: str) -> bool:
    """Whether the helper ``before`` named was replaced by a live helper of ``digest``'s build: a
    replacement that failed (no helper, or the old one still there) is not one."""

    return (
        after.get("alive") is True
        and isinstance(after.get("pid"), int)
        and after.get("pid") != before.get("pid")
        and after.get("digest") == digest[:19]
    )


# How the older build's bridge (layer 4's) names a newer helper and server it cannot speak with:
# a structured ``SERVICE_UNAVAILABLE`` stating the installation mismatch. That build names no
# phase or continuation; a crash, a JSON-RPC error or a deadline is never this refusal.
OLDER_BRIDGE_MISMATCH = ("SERVICE_UNAVAILABLE", "belongs to a different FinishUP installation")


def older_bridge_refused(result: dict[str, Any], alive: bool) -> bool:
    """Whether the older bridge, still running, refused with its typed release mismatch."""

    body = result.get("body") or {}
    error = body.get("error") if isinstance(body, dict) else None
    if result.get("ok") or not alive or result.get("error") or not isinstance(error, dict):
        return False
    code, statement = OLDER_BRIDGE_MISMATCH
    return error.get("code") == code and statement in str(error.get("message"))


def recorded_once(
    before: int | None, after_first: int | None, after_replay: int | None, accepted: int
) -> bool:
    """A write and its replay after a restart: exactly one event accepted, the head one past its
    sequence before the write, and the same after the replay (nothing recorded twice)."""

    return (
        accepted == 1
        and isinstance(before, int)
        and after_first == before + 1
        and after_replay == after_first
    )


def brief(result: dict[str, Any]) -> str:
    body = result.get("body") or {}
    error = body.get("error") if isinstance(body, dict) else None
    if result.get("ok"):
        return "ok"
    if isinstance(error, dict):
        details = error.get("safe_details") or {}
        continuation = details.get("continuation")
        if isinstance(continuation, dict):
            continuation = continuation.get("id") or continuation.get("name")
        return (
            f"{error.get('code')} reason={details.get('reason')} phase={details.get('phase')} "
            f"continuation={continuation}: {str(error.get('message'))[:220]}"
        )
    return (result.get("text") or json.dumps(result.get("error")))[:300]


def scenario(report: Report, run: Run, old_wheel: Path, new_wheel: Path) -> None:
    sshd = Sshd(run)
    server_launcher = venv(run.base / "server-venv", old_wheel)
    client_launcher = venv(run.base / "client-venv", old_wheel)
    digests = {"old": manifest_digest(server_launcher)}
    server = Server(run, "srv", server_launcher, code_copy=False)
    run.finalizers.append(server.stop_service)
    begun = server.srv("service", "start", "--json")
    assert begun.returncode == 0, "server start: " + run.redact(begun.stdout + begun.stderr)[-600:]
    assert server.initialize_vault(), "server vault"
    client = Client(run, client_launcher, ssh_bin=sshd.bin)
    client.make_repository()

    def stop_local() -> None:
        # A bridge following the local selection starts this computer's own service on demand.
        client.fu("server", "use", "local")
        client.fu("service", "stop", "--json")

    run.finalizers.append(stop_local)

    # --- 1. everything older -----------------------------------------------------------------
    added = client.ceremony(
        [
            "server",
            "add",
            "lab",
            f"ssh://{sshd.user}@127.0.0.1:{sshd.port}",
            "--remote-root",
            str(server.root),
            "--remote-launcher",
            str(server_launcher),
        ],
        [
            Reply(r"continue connecting", "yes", secret=False),
            Reply(r"Type local or listed", "listed", secret=False),
            Reply(r"Type the target name", "lab", secret=False),
        ],
    )
    used = client.ceremony(
        ["server", "use", "lab"], [Reply(r"Type the target name", "lab", secret=False)]
    )
    root = client.target_root("lab")
    run.finalizers.append(lambda: client.fu("server", "disconnect", "lab"))
    report.add(
        "older: add and use an SSH server",
        added.exit_code == 0 and used.exit_code == 0,
        f"add exit {added.exit_code}, use exit {used.exit_code}",
    )
    external = f"acc-upgrade-{uuid.uuid4().hex[:8]}"
    start_args = {
        "mode": "create_or_attach",
        "task_title": "Upgrade acceptance",
        "workspace_ref": str(client.work),
        "external_ref": external,
        "requested_view": "compact",
    }
    old_bridge = Bridge(run, client_launcher, client.env(), client.work)
    started = old_bridge.tool("start", mcp_request(**start_args))
    task = Task.from_result(started["body"])
    task_id = task.task_id
    ids = {"session_id": task.session_id, "writer_id": task.writer_id}
    old_helper = helper_stamp(root)
    report.add(
        "older: the bridge starts a claim-bound task through the older helper",
        started["ok"] and bool(ids["session_id"]) and old_helper.get("alive") is True,
        f"start {brief(started)}; helper {old_helper}",
    )
    status_args = {**ids, "view": "compact"}

    # --- 2. the client upgraded in place under its running helper and bridge -----------------
    install(run.base / "client-venv", new_wheel)
    digests["new"] = manifest_digest(client_launcher)
    report.add(
        "client upgraded in place",
        digests["new"] != digests["old"],
        f"manifest digest {digests['old'][:19]} → {digests['new'][:19]}; older helper "
        f"still running: {helper_pid(root) == old_helper.get('pid')}; older bridge still "
        f"running: {old_bridge.process.poll() is None}",
    )
    first = old_bridge.tool("status", mcp_request(**status_args))
    report.add(
        "older bridge, older helper, older server (nothing new on the path yet)", None, brief(first)
    )
    cli = client.fu("service", "status", "--json", timeout=120)
    after_cli = helper_stamp(root)
    replaced = replaced_by(old_helper, after_cli, digests["new"])
    mismatch = typed_refusal(cli, "remote_incompatible", "remote_release_mismatch")
    report.add(
        "newer CLI against the older helper and older server",
        replaced and mismatch,
        f"exit {cli.returncode}; replaced by a live helper of the newer build: {replaced} "
        f"(now {after_cli}); refused typed remote_incompatible, continuation "
        f"remote_release_mismatch: {mismatch} (the newer helper's upstream is the older server)",
        run.redact(excerpt(cli.stdout + cli.stderr, lines=12)),
    )
    second = old_bridge.tool("status", mcp_request(**status_args))
    after_bridge = {**helper_stamp(root), "bridge_pid": old_bridge.process.pid}
    report.add(
        "older bridge after the newer CLI replaced its helper",
        None,
        f"{brief(second)}; helper now {after_bridge}",
    )
    third = old_bridge.tool("status", mcp_request(**status_args))
    report.add(
        "older bridge, again (does it flap the helper?)",
        None,
        f"{brief(third)}; helper now {helper_stamp(root)}",
    )

    # --- 3. the server upgraded in place and restarted by its owner ----------------------------
    install(run.base / "server-venv", new_wheel)
    restarted = server.srv("service", "restart", "--json", timeout=120)
    unlocked = server.unlock()
    report.add(
        "server upgraded in place; its owner restarts the service",
        restarted.returncode == 0 and unlocked,
        f"service restart exit {restarted.returncode}; vault unlocked again: {unlocked}",
        run.redact(excerpt(restarted.stdout + restarted.stderr, lines=8)),
    )
    cli = client.fu("service", "status", "--json", timeout=120)
    text = cli.stdout + cli.stderr
    reconsent = None
    if cli.returncode != 0 and "server_profile_changed" in text:
        again = client.ceremony(
            ["server", "use", "lab"], [Reply(r"Type the target name", "lab", secret=False)]
        )
        reconsent = again.exit_code
        cli = client.fu("service", "status", "--json", timeout=120)
    report.add(
        "newer CLI against the newer server",
        cli.returncode == 0,
        f"exit {cli.returncode}; the owner agreed again first: "
        f"{'not asked' if reconsent is None else f'exit {reconsent}'}",
        run.redact(excerpt(text, lines=10)),
    )
    fourth = old_bridge.tool("status", mcp_request(**status_args))
    alive = old_bridge.process.poll() is None
    report.add(
        "older bridge against the newer helper and server",
        older_bridge_refused(fourth, alive),
        f"{brief(fourth)}; bridge still running: {alive} (an older bridge must refuse with its "
        f"typed release mismatch, never work half-way, never crash)",
    )
    old_bridge.close()

    # --- 4. a newer bridge reattaches ----------------------------------------------------------
    bridge = Bridge(run, client_launcher, client.env(), client.work)
    attached = bridge.tool("start", mcp_request(**{**start_args, "mode": "attach"}))
    task = Task.from_result(attached["body"])
    report.add(
        "newer bridge reattaches to the task the older one started",
        attached["ok"] and task.task_id is not None and task.task_id == task_id,
        f"{brief(attached)}; same task: {task.task_id == task_id} (task named: "
        f"{task.task_id is not None})",
    )
    ids = {"session_id": task.session_id, "writer_id": task.writer_id}
    status_args = {**ids, "view": "compact"}

    # --- 5. the server's service restarted under an open bridge --------------------------------
    restarted = server.srv("service", "restart", "--json", timeout=120)
    unlocked = server.unlock()
    after = bridge.tool("status", mcp_request(**status_args))
    report.add(
        "server service restarted under an open bridge",
        restarted.returncode == 0 and unlocked and after["ok"],
        f"restart exit {restarted.returncode}; next bridge call {brief(after)}",
    )

    # --- 6. a request replayed by its request_id after a restart -------------------------------
    frontier = frontier_of(after["body"]) or {}
    if not frontier:
        report.add(
            "status names the head frontier",
            False,
            f"status body keys: {sorted(after['body'])[:20]}",
        )
    publish = mcp_request(
        **ids,
        expected_frontier=frontier,
        event_drafts=[
            {
                "event_id": f"evt_{uuid.uuid4()}",
                "schema": {"name": "plan_published", "version": "1.0.0"},
                "occurred_at": now_rfc3339(),
                "causal_parents": [],
                "payload": {"plan_version": 1, "summary": "Upgrade plan", "obligation_refs": []},
                "artifact_refs": [],
                "evidence_refs": [],
            }
        ],
    )
    once = bridge.tool("publish_work", publish)
    first_head = (frontier_of(bridge.tool("status", mcp_request(**status_args))["body"]) or {}).get(
        "sequence"
    )
    pid_before = server.service_pid()
    restarted = server.srv("service", "restart", "--json", timeout=120)
    unlocked = server.unlock()
    pid_after = server.service_pid()
    service_replaced = (
        restarted.returncode == 0 and unlocked and pid_after is not None and pid_after != pid_before
    )
    replay = bridge.tool("publish_work", publish)
    head = bridge.tool("status", mcp_request(**status_args))
    sequence = (frontier_of(head["body"]) or {}).get("sequence")
    accepted = once["body"].get("accepted_events")
    same = json.dumps(accepted, sort_keys=True) == json.dumps(
        replay["body"].get("accepted_events"), sort_keys=True
    )
    once_only = recorded_once(
        frontier.get("sequence"),
        first_head,
        sequence,
        len(accepted) if isinstance(accepted, list) else 0,
    )
    report.add(
        "a write replayed by its request_id after a restart is recorded once",
        once["ok"] and replay["ok"] and same and service_replaced and once_only,
        f"first {brief(once)}; service restarted and replaced: {service_replaced} (restart exit "
        f"{restarted.returncode}, unlocked {unlocked}, a new service process: "
        f"{pid_after is not None and pid_after != pid_before}); replay {brief(replay)}, same "
        f"accepted events: {same}; head sequence {frontier.get('sequence')} → {first_head} after "
        f"the write → {sequence} after the replay (exactly one event: {once_only})",
    )

    # --- 7. the bridge follows a new selection (O1) --------------------------------------------
    moved = client.fu("server", "use", "local")
    ended = bridge.tool("status", mcp_request(**status_args))
    follows = bridge.tool("status", mcp_request(**status_args))

    # This computer's own service answers once the bridge follows: it has no vault here, so it
    # names vault initialization. The request in flight when the selection moved (if any) ends
    # server_authorization_changed (outcome unknown); the connection may also have ended before
    # the next request, which then follows at once. Never may the remote answer after the move.
    def local(result: dict[str, Any]) -> bool:
        return "vault_initialization_required" in result["text"]

    report.add(
        "O1: after 'server use local' the open remote connection ends, the next request follows",
        moved.returncode == 0
        and not ended["ok"]
        and (local(ended) or "server_authorization_changed" in ended["text"])
        and local(follows),
        f"first {brief(ended)}; next {brief(follows)}",
    )
    back = client.ceremony(
        ["server", "use", "lab"], [Reply(r"Type the target name", "lab", secret=False)]
    )
    returned = bridge.tool("status", mcp_request(**status_args))
    returned_again = bridge.tool("status", mcp_request(**status_args))
    report.add(
        "back to the SSH server: the open bridge's next requests",
        None,
        f"server use exit {back.exit_code}; first {brief(returned)}; next {brief(returned_again)}",
    )
    bridge.close()
    # The O1 step started this computer's own service on the bridge's demand: stop it under the
    # local selection (the selection is the SSH server again by now).
    client.fu("server", "use", "local")
    client.fu("service", "stop", "--json")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--old", default="f1e3f5707")
    parser.add_argument("--new", default="HEAD")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--instances", type=Path, default=real_home() / ".yz-l7i")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--old-wheel", type=Path, help="reuse a wheel built from --old")
    parser.add_argument("--new-wheel", type=Path, help="reuse a wheel built from --new")
    args = parser.parse_args(argv)
    for name in ("FINISHUP_ISOLATED_ROOT", "YOETZ_ISOLATED_ROOT"):
        if os.environ.get(name):
            parser.error(f"unset {name}")
    args.instances.mkdir(mode=0o700, exist_ok=True)
    graceful_termination()
    run = Run("upgrade", keep=args.keep)
    report = Report("upgrade", redactor=run.redact)
    tags: list[str] = []
    began = time.monotonic()
    try:
        old_wheel = args.old_wheel or provision(args.instances, "old", args.old)
        if args.old_wheel is None:
            tags.append("old")
        new_wheel = args.new_wheel or provision(args.instances, "new", args.new)
        if args.new_wheel is None:
            tags.append("new")
        report.add(
            "provisioned test instances",
            True,
            f"old {args.old} ({old_wheel.name}), new {args.new} ({new_wheel.name})",
        )
        scenario(report, run, old_wheel, new_wheel)
    except Exception as error:  # noqa: BLE001 - recorded
        report.add("harness", False, f"{type(error).__name__}: {tail(run.redact(str(error)), 600)}")
    finally:
        problems = run.close()
        report.add(
            "cleanup proven (every process stopped, no lock held, folder removed)",
            not problems,
            "; ".join(problems) or "nothing left",
        )
        for tag in tags:
            dispose(args.instances, tag)
        with contextlib.suppress(OSError):
            args.instances.rmdir()
    document = {
        **report.to_json(),
        "seconds": round(time.monotonic() - began, 1),
        "old": args.old,
        "new": args.new,
    }
    args.out.write_text(json.dumps(document, indent=1))
    return 1 if report.verdict == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
