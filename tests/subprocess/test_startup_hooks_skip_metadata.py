"""Ordinary startup hook passes answer without reading distribution metadata.

``finishup.__version__`` is resolved on first read (see ``tests/unit/version``). The startup-gate
and startup-context hooks never report a version, so their ordinary answers must not load
``importlib.metadata``. The hermetic conftest rebases ``HOME`` onto a root the runtime accepts, so
these runs reach the ordinary branch rather than the unsafe-storage refusal; each case asserts the
ordinary answer as well as the absent import.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import cast

_HOOK_PROBE = r"""
import atexit, sys
def report():
    print("METADATA_LOADED" if "importlib.metadata" in sys.modules else "METADATA_ABSENT",
          file=sys.__stderr__)
atexit.register(report)
sys.argv = ["finishup", *sys.argv[1:]]
from finishup.cli.entry import main
main()
"""


def _run_hook(*args: str, cwd: Path, stdin: bytes = b"") -> tuple[dict[str, object], str]:
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and probe source
        [sys.executable, "-c", _HOOK_PROBE, *args],
        input=stdin,
        capture_output=True,
        check=False,
        cwd=cwd,
        env=dict(os.environ),
    )
    stderr = completed.stderr.decode()
    assert completed.returncode == 0, stderr
    return json.loads(completed.stdout), stderr


def _workspace() -> Path:
    # The home directory itself is refused as a workspace; a private child of it is ordinary.
    workspace = Path.home() / "workspace"
    workspace.mkdir(mode=0o700)
    return workspace


def test_startup_gate_hook_never_reads_distribution_metadata() -> None:
    workspace = _workspace()
    payload = {
        "session_id": "11111111-2222-3333-4444-555555555555",
        "cwd": str(workspace),
        "hook_event_name": "UserPromptSubmit",
        "prompt": "hello",
    }
    output, stderr = _run_hook(
        "hooks",
        "startup-gate",
        "--host",
        "claude",
        "--event",
        "UserPromptSubmit",
        cwd=workspace,
        stdin=json.dumps(payload).encode(),
    )

    # The ordinary turn reset, not the "could not safely advance this turn" refusal.
    assert "decision" not in output
    assert isinstance(output["hookSpecificOutput"], dict)
    hook_output = cast(dict[str, object], output["hookSpecificOutput"])
    assert hook_output["hookEventName"] == "UserPromptSubmit"
    context = hook_output["additionalContext"]
    assert isinstance(context, str)
    assert context.startswith("FinishUP required startup is active.")
    assert "METADATA_ABSENT" in stderr


def test_startup_context_hook_never_reads_distribution_metadata() -> None:
    output, stderr = _run_hook("hooks", "startup-context", "--host", "claude", cwd=_workspace())

    assert isinstance(output["hookSpecificOutput"], dict)
    hook_output = cast(dict[str, object], output["hookSpecificOutput"])
    assert hook_output["hookEventName"] == "SessionStart"
    context = hook_output["additionalContext"]
    assert isinstance(context, str)
    assert context.startswith("Use FinishUP for material multi-step")
    assert "METADATA_ABSENT" in stderr
