"""Wall-clock comparison of launcher entry points across checkouts; no service, vault or host.

Each named checkout must hold a synced ``.venv``. Every command runs through that checkout's
installed ``finishup`` launcher in a fresh process against one explicit isolated root, so this
measures interpreter start, imports and the command itself. Runs interleave the checkouts so
machine noise lands on both sides, and the table reports the minimum and median of ``--runs``.

Never pass a live state root: ``--root`` must be a private, owner-only directory that is not
under a shared temporary directory. The observe-hook rows run the commands as the host
registrations do, with each host's ordinary observation profile, in an unconsented workspace.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import time
from pathlib import Path

_ROOT_VARIABLES = ("FINISHUP_", "YOETZ_")
# The profile argument each host registration passes to its observe hook.
_CLAUDE_PROFILE = "claude-code-ordinary-observation-v1"
_CURSOR_PROFILE = "cursor-ordinary-observation-v1"


def _commands(workspace: Path) -> list[tuple[str, list[str], bytes]]:
    payload = json.dumps(
        {
            "session_id": "probe-1",
            "tool_name": "Bash",
            "tool_use_id": "call-1",
            "tool_input": {"command": "true"},
            "hook_event_name": "PreToolUse",
            "cwd": str(workspace),
        }
    ).encode()
    observe = ["--event", "PreToolUse", "--workspace", str(workspace)]
    post = ["--event", "PostToolUse", "--workspace", str(workspace)]
    claude = ["--observation-profile", _CLAUDE_PROFILE]
    cursor = ["--workspace", str(workspace), "--observation-profile", _CURSOR_PROFILE]
    return [
        ("--version", ["--version"], b""),
        ("version", ["version"], b""),
        ("version --json", ["version", "--json"], b""),
        ("--help", ["--help"], b""),
        ("status --help", ["status", "--help"], b""),
        ("service status (no service)", ["service", "status"], b""),
        ("claude-observe PreToolUse", ["hooks", "claude-observe", *observe, *claude], payload),
        ("claude-observe PostToolUse", ["hooks", "claude-observe", *post, *claude], payload),
        (
            "cursor-observe preToolUse",
            ["hooks", "cursor-observe", "--event", "preToolUse", *cursor],
            payload,
        ),
        (
            "cursor-observe postToolUse",
            ["hooks", "cursor-observe", "--event", "postToolUse", *cursor],
            payload,
        ),
        ("observe PreToolUse (codex)", ["hooks", "observe", *observe], payload),
        ("observe PostToolUse (codex)", ["hooks", "observe", *post], payload),
        ("hooks startup-context claude", ["hooks", "startup-context", "--host", "claude"], b""),
        (
            "hooks startup-gate claude",
            ["hooks", "startup-gate", "--host", "claude", "--event", "SessionStart"],
            payload,
        ),
    ]


def _run(checkout: Path, root: Path, workspace: Path, argv: list[str], stdin: bytes) -> float:
    environment = {
        name: value for name, value in os.environ.items() if not name.startswith(_ROOT_VARIABLES)
    }
    environment["FINISHUP_ISOLATED_ROOT"] = str(root)
    started = time.perf_counter()
    subprocess.run(
        [str(checkout / ".venv" / "bin" / "finishup"), *argv],
        input=stdin,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=environment,
        cwd=str(workspace),
        check=False,
    )
    return (time.perf_counter() - started) * 1000.0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Wall-clock comparison of launcher entry points across checkouts."
    )
    parser.add_argument("checkouts", nargs="+", type=Path, help="checkouts with a synced .venv")
    parser.add_argument("--root", required=True, type=Path, help="private isolated root")
    parser.add_argument("--runs", type=int, default=15)
    parser.add_argument("--json", type=Path, default=None, help="write the raw report here")
    arguments = parser.parse_args()

    checkouts = [checkout.resolve() for checkout in arguments.checkouts]
    root: Path = arguments.root.resolve()
    root.mkdir(mode=0o700, exist_ok=True)
    workspace = root / "workspace"
    workspace.mkdir(exist_ok=True)

    report: dict[str, dict[str, dict[str, float]]] = {}
    commands = _commands(workspace)
    for label, argv, stdin in commands:
        samples: dict[str, list[float]] = {str(checkout): [] for checkout in checkouts}
        for checkout in checkouts:  # one unmeasured run warms bytecode and the page cache
            _run(checkout, root, workspace, argv, stdin)
        for _ in range(arguments.runs):
            for checkout in checkouts:
                samples[str(checkout)].append(_run(checkout, root, workspace, argv, stdin))
        report[label] = {
            name: {"min_ms": min(values), "median_ms": statistics.median(values)}
            for name, values in samples.items()
        }

    width = max(len(label) for label, _, _ in commands)
    print(f"{'command':<{width}}  " + "  ".join(f"{c.name:>20}" for c in checkouts))
    print(f"{'':<{width}}  " + "  ".join(f"{'min / median ms':>20}" for _ in checkouts))
    for label, _, _ in commands:
        cells = [
            f"{report[label][str(c)]['min_ms']:8.1f} / {report[label][str(c)]['median_ms']:8.1f}"
            for c in checkouts
        ]
        line = f"{label:<{width}}  " + "  ".join(f"{cell:>20}" for cell in cells)
        if len(checkouts) == 2:
            first = report[label][str(checkouts[0])]["min_ms"]
            second = report[label][str(checkouts[1])]["min_ms"]
            line += f"  {first / second:6.2f}x"
        print(line)
    if arguments.json is not None:
        arguments.json.write_text(json.dumps(report, indent=1) + "\n")


if __name__ == "__main__":
    main()
