"""The WAN timing gate (design v2 section 8.9): the hook cold path and calls over an injected delay.

Usage (from a checkout, after ``uv sync``; both root variables unset)::

    uv run python scripts/acceptance/wan_gate.py --rtt-ms 100 --out <file.json>
    uv run python scripts/acceptance/wan_gate.py --rtt-ms 100 --mode proxy --out <file.json>
    uv run python scripts/acceptance/wan_gate.py render <file.json>...

``--mode netns`` (the default) runs the whole measurement in a new, unprivileged user and network
namespace (``unshare --user --map-root-user --net``) whose *own* loopback gets ``tc netem delay``
of half the round trip (every packet crosses it once per direction), then drops back to this
account's uid in a nested user namespace, so FinishUP runs as itself. No interface or queueing
discipline of this computer is touched: the namespace's loopback exists only inside it, and the
namespace ends with its last process. ``--mode proxy`` needs no namespace: a userspace relay in
this process holds every chunk for half the round trip in each direction (TCP itself then runs
over a fast loopback, so a handshake costs fewer delayed round trips than on a real WAN; the
report names the mode).

Measured, per style (``ssh`` relay and direct, ``https`` (gateway edge) relay and direct), after
a claim-bound task was started:

* ``warm_connect_status`` — a fresh process connects (its workspace claim) and asks one compact
  ``status``, as the required-mode startup gate does (``cli/startup_gate_probe.py``, bounded at
  0.65 s), with the relay's helper (and the SSH master) already up; gated at **650 ms p95**;
* ``warm_process`` — that whole process, interpreter start and imports included; gated at the
  hook pass budget, **3200 ms p95**;
* ``hook_cold_connect`` — after ``server disconnect`` (helper and master stopped), a hook's own
  path: ``connect_service_on_demand`` bounded by the hook's 1.0 s start budget
  (``_HOOK_SERVICE_START_BUDGET_SECONDS``); it must end within it (gated at **1150 ms p95**, the
  budget plus the close), served or failing open with a named phase, and the next call must be
  served (the helper it started keeps starting);
* ``cold_connect`` / ``cold_process`` — how long a cold connection takes to be served at all (no
  budget); reported, never gated: a cold start may fail open once;
* ``server test`` — the warm status round trip p95 it reports, and the slowest of its new
  processes' connection and status, which it compares with the startup gate's 650 ms.

Every number is reported; a style that misses a budget says so (a failed gate is a result, not an
error). ``render`` turns result files into the markdown table the runbook keeps.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shlex
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import (  # noqa: E402
    REPO,
    Reply,
    Run,
    Task,
    base_request,
    helper_pid,
    json_of,
    tool,
    wait_until,
)
from matrix import Cell, World, address_of, consent_replies, start_task  # noqa: E402

STYLES = (
    Cell("ssh-relay", "ssh", "ssh", "relay", "L1"),
    Cell("ssh-direct", "ssh", "ssh", "direct", "L1"),
    Cell("https-relay", "https", "gateway", "relay", "L1"),
    Cell("https-direct", "https", "gateway", "direct", "L1"),
)

# The gate. ``warm_connect_status``: the required startup gate's bound (0.65 s for connect and
# status). ``hook_cold_connect``: a hook's on-demand start budget (1.0 s) plus 150 ms for the
# close, the interpreter's teardown is not in it: the hook must end within it, served or failing
# open. ``warm_process``: the whole warm hook process, interpreter start included, within the
# 3.2 s pass budget. ``cold_connect`` (no budget: how long a cold helper takes to serve at all) is
# reported, never gated: a cold start is allowed to fail open once.
BUDGETS_MS = {"warm_connect_status": 650, "hook_cold_connect": 1150, "warm_process": 3200}
NEW_CONNECTION_LINE = re.compile(r"New connection and status: (\d+) ms at the slowest of (\d+)")
HOOK_START_BUDGET_S = 1.0

PROBE = r"""
import asyncio, json, sys, time
began = time.monotonic()
from finishup.ports.control import ControlClientKind, WorkspaceLocator
from finishup.protocol.models import StatusRequest
from finishup.service.client import connect_service, connect_service_on_demand
imported = time.monotonic()
budget = float(sys.argv[3])
async def main():
    out = {"import_ms": round((imported - began) * 1000, 1)}
    client = None
    start = time.monotonic()
    try:
        locator = WorkspaceLocator(sys.argv[1])
        if budget > 0:
            # A hook's path: the on-demand connect bounded by its budget (one deadline).
            client = await connect_service_on_demand(
                ControlClientKind.CLI, workspace_locator=locator, timeout_seconds=budget
            )
        else:
            client = await connect_service(ControlClientKind.CLI, workspace_locator=locator)
        out["connect_ms"] = round((time.monotonic() - start) * 1000, 1)
        call = time.monotonic()
        request = StatusRequest.model_validate(json.loads(sys.argv[2]))
        response = await client.status(request, deadline_ms=5000)
        out["status_ms"] = round((time.monotonic() - call) * 1000, 1)
        out["ok"] = getattr(response.root, "ok", None) is not False
    except Exception as error:
        out["error"] = f"{type(error).__name__}:{getattr(error, 'reason', '')}:{getattr(error, 'phase', '')}"
        out["failed_after_ms"] = round((time.monotonic() - start) * 1000, 1)
    finally:
        if client is not None:
            await client.close()
    print(json.dumps(out))
asyncio.run(main())
"""


# A fixed CPU workload in a fresh interpreter: the speed of this computer while a style was
# measured (its time and the probe's own ``import`` time move together with the load on it), so
# runs made at different times can be compared; it gates nothing.
CALIBRATION = "import time\nt = time.perf_counter()\nsum(i * i for i in range(2_000_000))\n" + (
    "print(round((time.perf_counter() - t) * 1000, 1))"
)


def calibration() -> float | None:
    """The median of three runs of ``CALIBRATION`` (milliseconds); ``None`` if it cannot run."""

    values: list[float] = []
    for _ in range(3):
        result = subprocess.run(  # noqa: S603 - this interpreter, a fixed program
            [sys.executable, "-I", "-c", CALIBRATION], capture_output=True, text=True, check=False
        )
        try:
            values.append(float(result.stdout.strip()))
        except ValueError:
            return None
    return statistics.median(values)


def revision() -> str:
    """This checkout's short commit, ``-dirty`` when its tracked files differ from it."""

    def git(*arguments: str) -> str:
        return subprocess.run(  # noqa: S603
            ["git", "-C", str(REPO), *arguments],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()

    head = git("rev-parse", "--short", "HEAD")
    return head + ("-dirty" if git("status", "--porcelain", "--untracked-files=no") else "")


def percentile(values: list[float], fraction: float) -> float | None:
    """The nearest-rank percentile (``fraction`` in (0, 1]); ``None`` for no values."""

    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, min(len(ordered), math.ceil(fraction * len(ordered))))
    return ordered[rank - 1]


def summary(values: list[float]) -> dict[str, float | int | None]:
    return {
        "n": len(values),
        "p50": percentile(values, 0.5),
        "p95": percentile(values, 0.95),
        "max": max(values) if values else None,
        "mean": round(statistics.fmean(values), 1) if values else None,
    }


def gate(result: dict[str, Any]) -> dict[str, Any]:
    """The verdict of one style's measurements against ``BUDGETS_MS`` (p95, every sample ok)."""

    checks: dict[str, Any] = {}
    for name, budget in BUDGETS_MS.items():
        measured = (result.get(name) or {}).get("p95")
        failures = int((result.get(name) or {}).get("failures") or 0)
        checks[name] = {
            "budget_ms": budget,
            "p95_ms": measured,
            "failures": failures,
            "pass": measured is not None and measured <= budget and failures == 0,
        }
    return {"checks": checks, "pass": all(item["pass"] for item in checks.values())}


def probe(world: World, task: Task, budget: float = 0.0) -> tuple[dict[str, Any], float]:
    request = {
        **base_request(),
        "session_id": task.session_id,
        "writer_id": task.writer_id,
        "view": "compact",
        "limit": "1",
    }
    began = time.monotonic()
    result = world.client.py(PROBE, str(world.client.work), json.dumps(request), str(budget))
    wall = round((time.monotonic() - began) * 1000, 1)
    lines = result.stdout.strip().splitlines()
    try:
        return json.loads(lines[-1]), wall
    except (IndexError, ValueError):
        return {"error": world.run.redact((result.stdout + result.stderr)[-300:])}, wall


def measure_style(world: World, cell: Cell, samples: int) -> dict[str, Any]:
    client = world.client
    name = cell.target
    added = client.ceremony(
        ["server", "add", name, *address_of(world, cell)], consent_replies(name)
    )
    if added.exit_code != 0:
        return {"error": "add_failed", "transcript": world.run.redact(added.transcript[-800:])}
    if cell.style == "direct":
        client.fu("server", "set", name, "--style", "direct")
    used = client.ceremony(
        ["server", "use", name], [Reply(r"Type the target name", name, secret=False)]
    )
    if used.exit_code != 0:
        return {"error": "use_failed"}
    task, started = start_task(world, f"WAN gate {cell.name}")
    if not task.ok:
        return {"error": "start_failed", "detail": world.run.redact(started.stderr[-600:])}
    root = client.target_root(name)
    out: dict[str, Any] = {}
    warm: list[float] = []
    parts: dict[str, list[float]] = {"import": [], "connect": [], "status": [], "process": []}
    warm_failures = 0
    for _ in range(samples):
        timing, wall = probe(world, task)
        if "error" in timing or not timing.get("ok"):
            warm_failures += 1
            out.setdefault("warm_errors", []).append(timing.get("error"))
            continue
        warm.append(timing["connect_ms"] + timing["status_ms"])
        for key in ("import", "connect", "status"):
            parts[key].append(timing[f"{key}_ms"])
        parts["process"].append(wall)
    out["warm_connect_status"] = {**summary(warm), "failures": warm_failures}
    out["warm_parts"] = {key: summary(values) for key, values in parts.items()}
    out["warm_process"] = {**summary(parts["process"]), "failures": warm_failures}
    # Cold: the helper and the SSH master stopped. First a hook's path (on demand, bounded by
    # the hook's 1.0 s start budget): it must end within that budget, served or failing open
    # with a named phase, and leave the helper starting for the next hook. Then the time until
    # a cold connection is served at all (no budget).
    hook: list[float] = []
    hook_served = 0
    recovered = 0
    cold: list[float] = []
    cold_process: list[float] = []
    cold_failures = 0
    phases: list[str] = []
    for _ in range(max(3, samples // 2)):
        client.fu("server", "disconnect", name)
        wait_until(lambda: helper_pid(root) is None, seconds=15)
        timing, _wall = probe(world, task, budget=HOOK_START_BUDGET_S)
        hook.append(float(timing.get("failed_after_ms") or timing.get("connect_ms") or 0.0))
        if timing.get("ok"):
            hook_served += 1
        else:
            phases.append(str(timing.get("error")))
        again, _ = probe(world, task)
        recovered += bool(again.get("ok"))
        client.fu("server", "disconnect", name)
        wait_until(lambda: helper_pid(root) is None, seconds=15)
        timing, wall = probe(world, task)
        if "error" in timing or not timing.get("ok"):
            cold_failures += 1
            out.setdefault("cold_errors", []).append(timing.get("error"))
            continue
        cold.append(timing["connect_ms"])
        cold_process.append(wall)
    out["hook_cold_connect"] = {
        **summary(hook),
        "failures": 0,
        "served_within_budget": hook_served,
        "failed_open_phases": sorted(set(phases)),
        "next_call_served": recovered,
    }
    out["cold_connect"] = {**summary(cold), "failures": cold_failures}
    out["cold_process"] = {**summary(cold_process), "failures": cold_failures}
    tested = client.fu("server", "test", name, timeout=120)
    document = json_of(client.fu("server", "status", name, "--json").stdout)
    probe_doc = document.get("probe") or {}
    measured = NEW_CONNECTION_LINE.search(tested.stdout)
    out["server_test"] = {
        "exit": tested.returncode,
        "round_trip_p95_ms": probe_doc.get("round_trip_p95_ms"),
        # What it compares with the startup gate's bound: a new process's connection and status.
        "new_connection_slowest_ms": int(measured.group(1)) if measured else None,
        "warned": "Warning:" in tested.stdout,
        "last_line": (tested.stdout.strip().splitlines() or [""])[-1],
    }
    out["gate"] = gate(out)
    client.fu("server", "disconnect", name)
    client.fu("server", "use", "local")
    client.fu("server", "remove", name)
    return out


def inside(args: argparse.Namespace) -> int:
    one_way = args.rtt_ms / 2000.0
    run = Run("wan")
    results: dict[str, Any] = {
        "mode": args.mode,
        "rtt_ms": args.rtt_ms,
        "samples": args.samples,
        "budgets_ms": BUDGETS_MS,
        "commit": revision(),
        "styles": {},
    }
    try:
        cells = [cell for cell in STYLES if cell.name in args.styles.split(",")]
        delay = None if args.mode == "netns" else one_way
        world = World(run, args.launcher, cells, relay_delay=delay)
        for cell in cells:
            began = time.monotonic()
            try:
                results["styles"][cell.name] = measure_style(world, cell, args.samples)
            except Exception as error:  # noqa: BLE001 - recorded as that style's result
                results["styles"][cell.name] = {"error": f"{type(error).__name__}: {error}"}
            results["styles"][cell.name]["seconds"] = round(time.monotonic() - began, 1)
            results["styles"][cell.name]["cpu_calibration_ms"] = calibration()
            print(cell.name, json.dumps(results["styles"][cell.name].get("gate")), flush=True)
    finally:
        run.close()
    args.out.write_text(json.dumps(results, indent=1))
    return 0


def in_namespace(args: argparse.Namespace) -> int:
    """Re-run this script inside a new user + network namespace with netem on its loopback."""

    unshare, ip, tc = tool("unshare"), tool("ip"), tool("tc")
    if unshare is None or ip is None or tc is None:
        print("netns mode needs unshare, ip and tc; use --mode proxy", file=sys.stderr)
        return 2
    inner = [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:], "--inside"]
    one_way_ms = args.rtt_ms / 2
    setup = f"{ip} link set lo up"
    if one_way_ms > 0:
        setup += f" && {tc} qdisc add dev lo root netem delay {one_way_ms}ms"
    script = (
        f"{setup} && exec {unshare} --user --map-user={os.getuid()} --map-group={os.getgid()} "
        + shlex.join(inner)
    )
    probe_run = subprocess.run(  # noqa: S603
        [unshare, "--user", "--map-root-user", "--net", "true"], check=False, capture_output=True
    )
    if probe_run.returncode != 0:
        print("this computer refuses unprivileged namespaces; use --mode proxy", file=sys.stderr)
        return 2
    return subprocess.run(  # noqa: S603
        [unshare, "--user", "--map-root-user", "--net", "sh", "-c", script], check=False
    ).returncode


def _server_test_cell(tested: dict[str, Any]) -> str:
    """The status round trip p95 and, when it said one, the slowest new connection and status
    (with whether it warned)."""

    cell = str(tested.get("round_trip_p95_ms"))
    slowest = tested.get("new_connection_slowest_ms")
    if isinstance(slowest, int):
        cell += f"; new {slowest}{' (warned)' if tested.get('warned') else ''}"
    return cell


def _ms(value: object) -> str:
    return f"{value:.0f}" if isinstance(value, (int, float)) else "–"


def render(paths: list[Path]) -> str:
    """A markdown table of WAN gate result files (one row per style and round trip)."""

    rows = [
        "| RTT | Mode | Commit | Style | warm connect+status p50/p95 (≤650) | connect / status p50 | "
        "warm process p95 (≤3200) | hook cold connect p50/p95 (≤1150), served / failed open as | "
        "cold served p50 | `server test` round trip p95; new connection slowest | "
        "import p50, CPU calibration | Gate |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for path in paths:
        document = json.loads(path.read_text())
        for style, result in document["styles"].items():
            if "error" in result:
                rows.append(
                    f"| {document['rtt_ms']:g} ms | {document['mode']} | {document.get('commit', '–')} | "
                    f"{style} | error: {result['error']} | | | | | | | fail |"
                )
                continue
            warm, process = result["warm_connect_status"], result["warm_process"]
            hook, cold = result["hook_cold_connect"], result["cold_connect"]
            phases = ", ".join(p.split(":")[-1] or "(none)" for p in hook["failed_open_phases"])
            parts = result.get("warm_parts") or {}
            connect = (parts.get("connect") or {}).get("p50")
            status = (parts.get("status") or {}).get("p50")
            imported = (parts.get("import") or {}).get("p50")
            rows.append(
                f"| {document['rtt_ms']:g} ms | {document['mode']} | {document.get('commit', '–')} | "
                f"{style} | {warm['p50']:.0f} / {warm['p95']:.0f} | {_ms(connect)} / {_ms(status)}"
                f" | {process['p95']:.0f} | "
                f"{hook['p50']:.0f} / {hook['p95']:.0f}, {hook['served_within_budget']}/{hook['n']}"
                f" served{', failed open: ' + phases if phases else ''}; next call served "
                f"{hook['next_call_served']}/{hook['n']} | {cold['p50']:.0f} | "
                f"{_server_test_cell(result['server_test'])} | "
                f"{_ms(imported)}, {_ms(result.get('cpu_calibration_ms'))} | "
                f"{'pass' if result['gate']['pass'] else 'fail'} |"
            )
    return "\n".join(rows) + "\n"


def main(argv: list[str] | None = None) -> int:
    if argv is None and sys.argv[1:2] == ["render"]:
        print(render([Path(item) for item in sys.argv[2:]]))
        return 0
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rtt-ms", type=float, default=100.0)
    parser.add_argument("--mode", choices=("netns", "proxy"), default="netns")
    parser.add_argument("--samples", type=int, default=15)
    parser.add_argument("--styles", default=",".join(cell.name for cell in STYLES))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--launcher", type=Path, default=REPO / ".venv" / "bin" / "finishup")
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    args.launcher = args.launcher.absolute()
    args.out = args.out.absolute()
    for name in ("FINISHUP_ISOLATED_ROOT", "YOETZ_ISOLATED_ROOT"):
        if os.environ.get(name):
            parser.error(f"unset {name}: the client must be an ambient installation")
    if args.mode == "netns" and not args.inside:
        return in_namespace(args)
    return inside(args)


if __name__ == "__main__":
    raise SystemExit(main())
