"""Host acceptance on this computer: Codex CLI, Claude Code and the Cursor agent against a test instance.

Usage (from a checkout, after ``uv sync``; both root variables unset)::

    uv run python scripts/acceptance/hosts.py --out <file.json>

Provisions a disposable test instance from ``HEAD`` (``scripts/provision_test_instance.py``; its
runtime pinned to its own root, so nothing it starts can reach another FinishUP), then, for each host
that is installed, in a scratch host home of its own (``CODEX_HOME``, ``CLAUDE_CONFIG_DIR`` and
``HOME``; never the account's own host configuration or user-scope registration):

* registers FinishUP's MCP server with the host's own CLI by the instance's **absolute** launcher
  (``codex mcp add``, ``claude mcp add --scope user``, Cursor's ``~/.cursor/mcp.json``);
* lets the host read it back and, where the host can without a model, start it: Claude Code's
  ``mcp list`` health check (the host spawns the bridge and completes the MCP handshake) and the
  Cursor agent's ``mcp list-tools`` (the host lists FinishUP's tools); Codex lists the
  registration (``codex mcp list``) but starts a server only inside a model session;
* feeds the instance's own hook commands each host's recorded payload shapes
  (``fixtures/observations/*``) the way the host runs them (one process, payload on stdin,
  the project as working directory) and records the exit status and output size;
* removes the registration.

What needs a model session (a real agent turn calling FinishUP's tools, the hooks firing from a
live session) needs the account's host credentials and is not run: see the runbook's gaps.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import REPO, Report, real_home, run_command  # noqa: E402
from upgrade import dispose  # noqa: E402

PROVISION = REPO / "scripts" / "provision_test_instance.py"
HOST_PATH = "/usr/local/bin:/usr/bin:/bin"


def fixture_payloads(name: str) -> list[tuple[str, dict[str, Any]]]:
    document = json.loads((REPO / "fixtures" / "observations" / name).read_text())
    hooks = document["input"]["hook"]
    return [(case["event"], case["payload"]) for case in hooks.values()]


def hook_run(argv: list[str], payload: dict[str, Any], env: dict[str, str], cwd: Path) -> str:
    completed = subprocess.run(  # noqa: S603 - the instance's own launcher
        argv,
        input=json.dumps(payload).encode(),
        env=env,
        cwd=cwd,
        capture_output=True,
        timeout=60,
        check=False,
    )
    return f"exit {completed.returncode}, {len(completed.stdout)} bytes out"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--base", type=Path, default=real_home() / ".yz-l7h")
    args = parser.parse_args(argv)
    report = Report("hosts")
    args.base.mkdir(mode=0o700, exist_ok=True)
    tag = "hosts"
    created = run_command(
        [
            sys.executable,
            str(PROVISION),
            "create",
            "--base",
            str(args.base),
            "--tag",
            tag,
            "--checkout",
            str(REPO),
            "--lifecycle",
            "disposable",
            "--expires-in",
            "2",
            "--json",
            "--allow-dirty",
        ],
        env=dict(os.environ),
        timeout=580,
    )
    if created.returncode != 0:
        report.add("provision", False, created.stderr[-600:])
        args.out.write_text(json.dumps(report.to_json(), indent=1))
        return 1
    launcher = args.base / tag / "runtime" / "bin" / "finishup"
    homes = args.base / "homes"
    shutil.rmtree(homes, ignore_errors=True)
    project = homes / "project"
    project.mkdir(mode=0o700, parents=True)
    subprocess.run(["git", "init", "-q", str(project)], check=True)  # noqa: S607
    hook_env = {"PATH": "/usr/bin:/bin", "HOME": str(homes), "LANG": "C.UTF-8"}
    try:
        status = json.loads(
            run_command([str(launcher), "instance", "status", "--json"], env=hook_env).stdout
            or "{}"
        )
        report.add(
            "test instance (pinned, disposable)",
            status.get("binding") == "runtime_pin" and status.get("mode") == "isolated",
            f"binding {status.get('binding')}, mode {status.get('mode')}, runtime provenance "
            f"{status.get('runtime_provenance')}",
        )
        versions = {
            name: run_command([path, "--version"], env={"PATH": HOST_PATH, "HOME": str(homes)})
            .stdout.strip()
            .splitlines()[:1]
            for name in ("codex", "claude", "cursor-agent")
            if (path := shutil.which(name, path=HOST_PATH))
        }
        report.add("hosts installed", None, json.dumps(versions))

        if "codex" in versions:
            env = {
                "PATH": HOST_PATH,
                "HOME": str(homes / "codex"),
                "CODEX_HOME": str(homes / "codex" / ".codex"),
                "LANG": "C.UTF-8",
            }
            (homes / "codex" / ".codex").mkdir(parents=True, mode=0o700)
            added = run_command(
                ["codex", "mcp", "add", "finishup", "--", str(launcher), "mcp", "serve"],
                env=env,
                cwd=project,
            )
            listed = run_command(["codex", "mcp", "list"], env=env, cwd=project)
            report.add(
                "Codex: MCP registration by absolute launcher",
                added.returncode == 0 and str(launcher) in listed.stdout,
                f"add exit {added.returncode}; list names the instance launcher: "
                f"{str(launcher) in listed.stdout} (Codex starts it only in a model session)",
            )
            rows = [
                hook_run(
                    [
                        str(launcher),
                        "hooks",
                        "observe",
                        "--event",
                        event,
                        "--workspace",
                        str(project),
                    ],
                    {**payload, "cwd": str(project)},
                    hook_env,
                    project,
                )
                for event, payload in fixture_payloads("codex-post-tool-outcomes-0.157.1.case.json")
            ]
            report.add(
                "Codex: hooks observe with recorded payloads",
                all(row.startswith("exit 0") for row in rows),
                "; ".join(rows),
            )
            removed = run_command(["codex", "mcp", "remove", "finishup"], env=env, cwd=project)
            report.add(
                "Codex: registration removed", removed.returncode == 0, f"exit {removed.returncode}"
            )

        if "claude" in versions:
            env = {
                "PATH": HOST_PATH,
                "HOME": str(homes / "claude"),
                "CLAUDE_CONFIG_DIR": str(homes / "claude" / ".claude"),
                "LANG": "C.UTF-8",
            }
            (homes / "claude" / ".claude").mkdir(parents=True, mode=0o700)
            added = run_command(
                [
                    "claude",
                    "mcp",
                    "add",
                    "--scope",
                    "user",
                    "finishup",
                    "--",
                    str(launcher),
                    "mcp",
                    "serve",
                ],
                env=env,
                cwd=project,
                timeout=90,
            )
            listed = run_command(["claude", "mcp", "list"], env=env, cwd=project, timeout=120)
            connected = "Connected" in listed.stdout and str(launcher) in listed.stdout
            report.add(
                "Claude Code: the host starts the bridge and completes the MCP handshake",
                added.returncode == 0 and connected,
                f"add exit {added.returncode}; `claude mcp list`: "
                f"{(listed.stdout.strip().splitlines() or [''])[-1].replace(str(launcher), '<instance launcher>')}",
            )
            rows = [
                hook_run(
                    [
                        str(launcher),
                        "hooks",
                        "claude-observe",
                        "--event",
                        event,
                        "--workspace",
                        str(project),
                    ],
                    {**payload, "cwd": str(project)},
                    hook_env,
                    project,
                )
                for event, payload in fixture_payloads("claude-code-bash-outcomes.case.json")
            ]
            report.add(
                "Claude Code: hooks claude-observe with recorded payloads",
                all(row.startswith("exit 0") for row in rows),
                "; ".join(rows),
            )
            removed = run_command(
                ["claude", "mcp", "remove", "--scope", "user", "finishup"],
                env=env,
                cwd=project,
                timeout=90,
            )
            report.add(
                "Claude Code: registration removed",
                removed.returncode == 0,
                f"exit {removed.returncode}",
            )

        if "cursor-agent" in versions:
            home = homes / "cursor"
            (home / ".cursor").mkdir(parents=True, mode=0o700)
            config = home / ".cursor" / "mcp.json"
            config.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "finishup": {"command": str(launcher), "args": ["mcp", "serve"]}
                        }
                    }
                )
            )
            env = {"PATH": HOST_PATH, "HOME": str(home), "LANG": "C.UTF-8"}
            listed = run_command(["cursor-agent", "mcp", "list"], env=env, cwd=project, timeout=120)
            tools = run_command(
                ["cursor-agent", "mcp", "list-tools", "finishup"], env=env, cwd=project, timeout=120
            )
            names = [line.split()[1] for line in tools.stdout.splitlines() if line.startswith("- ")]
            report.add(
                "Cursor agent: the host starts the bridge and lists FinishUP's tools",
                "ready" in listed.stdout and {"start", "check", "receipt"} <= set(names),
                f"`mcp list`: {listed.stdout.strip()[-60:]}; tools: {', '.join(names)}",
            )
            rows = [
                hook_run(
                    [
                        str(launcher),
                        "hooks",
                        "cursor-observe",
                        "--event",
                        event,
                        "--workspace",
                        str(project),
                    ],
                    {**payload, "cwd": str(project)},
                    hook_env,
                    project,
                )
                for event, payload in fixture_payloads("cursor-shell-outcomes.case.json")
            ]
            report.add(
                "Cursor agent: hooks cursor-observe with recorded payloads",
                all(row.startswith("exit 0") for row in rows),
                "; ".join(rows),
            )
            config.unlink()
            report.add(
                "Cursor agent: registration removed", not config.exists(), "mcp.json removed"
            )
        stopped = run_command([str(launcher), "service", "stop", "--json"], env=hook_env)
        report.add("instance service stopped", None, f"exit {stopped.returncode}")
    finally:
        dispose(args.base, tag)
        shutil.rmtree(homes, ignore_errors=True)
        with contextlib.suppress(OSError):
            args.base.rmdir()
    args.out.write_text(json.dumps(report.to_json(), indent=1))
    return 1 if report.verdict == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
