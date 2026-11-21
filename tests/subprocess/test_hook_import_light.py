"""Ordinary observation hooks answer without importing pydantic or the protocol models.

Each host tool call spawns one hook process, and the protocol-model graph costs about half a
second to import. Consented PreToolUse passes and every pass in an unconsented workspace never
build a protocol request, so they must not load it. The hermetic conftest rebases ``HOME`` so the
state these runs create is private to the case.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_HEAVY = ("pydantic", "finishup.protocol.models", "finishup.service.client", "finishup.cli.render")
_CLAUDE_PROFILE = "claude-code-ordinary-observation-v1"
_CURSOR_PROFILE = "cursor-ordinary-observation-v1"

_HOOK_PROBE = r"""
import atexit, json, sys
heavy = json.loads(sys.argv[1])
def report():
    print("LOADED=" + json.dumps(sorted(name for name in heavy if name in sys.modules)),
          file=sys.__stderr__)
atexit.register(report)
sys.argv = ["finishup", *sys.argv[2:]]
from finishup.cli.entry import main
main()
"""

_ENTRY = (
    "import sys; sys.argv=['finishup',*sys.argv[1:]]; from finishup.cli.entry import main; main()"
)


def _run_hook(workspace: Path, payload: dict[str, object], *args: str) -> tuple[list[str], bytes]:
    """Return the heavy modules the hook loaded and its stdout; the hook must exit 0."""

    completed = subprocess.run(  # noqa: S603 - fixed interpreter and probe source
        [sys.executable, "-c", _HOOK_PROBE, json.dumps(_HEAVY), *args],
        input=json.dumps(payload).encode(),
        capture_output=True,
        check=False,
        cwd=workspace,
        env=dict(os.environ),
    )
    stderr = completed.stderr.decode()
    assert completed.returncode == 0, stderr
    lines = [line for line in stderr.splitlines() if line.startswith("LOADED=")]
    assert lines, stderr
    return json.loads(lines[-1].removeprefix("LOADED=")), completed.stdout


@pytest.fixture
def workspaces() -> tuple[Path, Path]:
    base = Path.home()
    consented = base / "consented"
    unconsented = base / "unconsented"
    consented.mkdir(mode=0o700)
    unconsented.mkdir(mode=0o700)
    granted = subprocess.run(  # noqa: S603 - fixed interpreter and command
        [sys.executable, "-c", _ENTRY, "observe", "grant", "--workspace", str(consented)],
        capture_output=True,
        check=False,
        env=dict(os.environ),
    )
    assert granted.returncode == 0, granted.stderr.decode()
    return consented, unconsented


def _claude(workspace: Path, event: str) -> dict[str, object]:
    payload: dict[str, object] = {
        "session_id": "11111111-2222-3333-4444-555555555555",
        "cwd": str(workspace),
        "permission_mode": "default",
        "hook_event_name": event,
        "tool_name": "Bash",
        "tool_use_id": "toolu_01ABCDEF",
        "tool_input": {"command": "git status"},
    }
    if event == "PostToolUse":
        payload["tool_response"] = {"stdout": "clean", "stderr": "", "interrupted": False}
    return payload


def _claude_args(workspace: Path, event: str) -> tuple[str, ...]:
    return (
        "hooks",
        "claude-observe",
        "--workspace",
        str(workspace),
        "--event",
        event,
        "--observation-profile",
        _CLAUDE_PROFILE,
    )


def test_consented_claude_pretool_hook_stays_off_protocol_models(
    workspaces: tuple[Path, Path],
) -> None:
    consented, _ = workspaces
    loaded, stdout = _run_hook(
        consented, _claude(consented, "PreToolUse"), *_claude_args(consented, "PreToolUse")
    )
    assert loaded == []
    assert stdout == b"{}\n"


def test_consented_cursor_pretool_hook_stays_off_protocol_models(
    workspaces: tuple[Path, Path],
) -> None:
    consented, _ = workspaces
    payload: dict[str, object] = {
        "conversation_id": "c-1234",
        "generation_id": "g-1",
        "workspace_roots": [str(consented)],
        "hook_event_name": "preToolUse",
        "tool_name": "Shell",
        "tool_use_id": "call_1",
        "tool_input": {"command": "git status"},
    }
    loaded, stdout = _run_hook(
        consented,
        payload,
        "hooks",
        "cursor-observe",
        "--workspace",
        str(consented),
        "--event",
        "preToolUse",
        "--observation-profile",
        _CURSOR_PROFILE,
    )
    assert loaded == []
    assert stdout == b'{"permission":"allow"}\n'


def test_unconsented_hooks_stay_off_protocol_models(workspaces: tuple[Path, Path]) -> None:
    _, unconsented = workspaces
    claude, claude_stdout = _run_hook(
        unconsented,
        _claude(unconsented, "PostToolUse"),
        *_claude_args(unconsented, "PostToolUse"),
    )
    codex, codex_stdout = _run_hook(
        unconsented,
        {
            "session_id": "019a0000-0000-7000-8000-000000000001",
            "cwd": str(unconsented),
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_use_id": "call_x",
            "tool_input": {"command": "git status"},
        },
        "hooks",
        "observe",
        "--workspace",
        str(unconsented),
        "--event",
        "PreToolUse",
    )
    assert claude == []
    assert codex == []
    assert claude_stdout == b"{}\n"
    assert codex_stdout == b"{}\n"
