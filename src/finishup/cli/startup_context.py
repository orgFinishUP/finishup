"""Static host startup guidance, independent of observation and the service."""

from __future__ import annotations

import os
from typing import IO, BinaryIO, Literal

from finishup.cli.hook_io import claude_context_output, cursor_context_output, stdout_json

_GUIDANCE_DIRECTORY = "guidance"
_GUIDANCE_FILE = "agent-instructions.md"


def _open_guidance() -> IO[bytes]:
    """Open the packaged guidance exactly where ``importlib.resources`` would find it.

    ``finishup.resources`` is a namespace package. With one filesystem portion,
    ``resources.files(...).joinpath("guidance/agent-instructions.md")`` lists that directory,
    takes the entry named exactly ``guidance`` and joins the file name onto it; when there is
    no such entry, ``MultiplexedPath.joinpath`` falls back to joining the whole relative path
    onto the portion. Both give the same filesystem path, which the OS then resolves (so a
    case-insensitive filesystem may still find ``Guidance``). Doing the same with ``os`` skips
    importing ``importlib.resources`` (pathlib, zipfile and friends) on every SessionStart. Any other
    layout (several portions, a zip, a regular package) keeps the ``importlib.resources`` path.
    """

    import finishup.resources as package

    spec = package.__spec__
    portions = list(package.__path__)
    if (
        spec is not None
        and spec.origin is None
        and type(spec.loader).__name__ == "NamespaceLoader"
        and len(portions) == 1
        and type(portions[0]) is str
        and os.path.isdir(portions[0])
    ):
        base = portions[0]
        # importlib lists the portion first, so a listing failure surfaces from the same place.
        # Found or not, it then opens this same joined path through the OS.
        os.listdir(base)
        return open(os.path.join(base, _GUIDANCE_DIRECTORY, _GUIDANCE_FILE), "rb")  # noqa: SIM115
    from importlib import resources

    node = resources.files("finishup.resources").joinpath(f"{_GUIDANCE_DIRECTORY}/{_GUIDANCE_FILE}")
    return node.open("rb")


def handle_startup_context(
    *, host: Literal["claude", "cursor"], stdout: BinaryIO | None = None
) -> int:
    """Emit a cue without reading stdin, host identity, settings, vault, or ledger.

    This is a separate SessionStart command so observation consent, contention,
    or a failed observation process cannot suppress the cooperative workflow cue.
    It makes no activation or readiness assertion and never returns a decision.
    """

    if host not in {"claude", "cursor"}:
        raise ValueError("startup_context_host_invalid")
    # The shared guidance owns the materiality trigger. Read only a bounded
    # packaged prefix; the rest of the workflow remains an on-demand MCP read.
    try:
        with _open_guidance() as stream:
            prefix = stream.read(1_024).decode("utf-8", errors="ignore")
        cue = prefix.split("\n\n", 2)[1].strip()
        if "finishup://guidance/workflow.md" not in cue:
            raise ValueError("startup_context_guidance_incomplete")
    except (OSError, UnicodeError, IndexError, ValueError):
        cue = (
            "For material work, read finishup://guidance/workflow.md with read_guidance, "
            "then follow its current startup and recovery procedure before substantive work. "
            "Skip trivial questions or edits."
        )
    context = (
        cue + " Load deferred FinishUP tool schemas when needed. A hook mapping is not an accepted "
        "current-scope plan. In a new session, use a mapped session_id from the session context "
        "for start mode=attach; otherwise follow the workflow's task identity rules. After "
        "resume or compaction of already-started work, use held current session/writer ids for "
        "status instead of creating a sibling. Before substantive work, publish the current "
        "plan with its effective obligations. This cue does not activate FinishUP or grant "
        "observation, credentials, permissions, or semantic disclosure."
    )
    output = (
        claude_context_output("SessionStart", context)
        if host == "claude"
        else cursor_context_output("sessionStart", context)
    )
    stdout_json(output, stdout)
    return 0
