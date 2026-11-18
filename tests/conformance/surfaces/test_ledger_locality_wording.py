"""Agent-facing text never calls the FinishUP ledger local (ADR-051).

The ledger and the service that keeps it belong to the selected FinishUP server, which may be on
another machine, so shipped guidance, skills and tool descriptions name it the FinishUP ledger or
the task's ledger. ``local`` stays for what is local wherever the server is: local checks, the
local review mode, a local terminal.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from finishup.mcp.descriptors import TOOL_DESCRIPTORS

_REPO_ROOT: Final = Path(__file__).resolve().parents[3]
_LOCAL_LEDGER: Final = re.compile(r"\blocal (?:FinishUP |work )?ledger\b", re.IGNORECASE)


def _prose(path: Path) -> str:
    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))


def test_shipped_guidance_and_skills_never_call_the_ledger_local() -> None:
    sources = sorted((_REPO_ROOT / "guidance").glob("*.md"))
    sources += sorted((_REPO_ROOT / "skills").glob("**/SKILL.md"))
    assert sources
    for path in sources:
        assert _LOCAL_LEDGER.search(_prose(path)) is None, path.relative_to(_REPO_ROOT)
    workflow = _prose(_REPO_ROOT / "guidance" / "workflow.md")
    assert "Describe FinishUP ledger writes separately from product-file changes." in workflow


def test_tool_descriptions_never_call_the_ledger_local() -> None:
    for profile, descriptors in TOOL_DESCRIPTORS.items():
        for descriptor in descriptors:
            assert _LOCAL_LEDGER.search(descriptor.description) is None, (profile, descriptor.name)
