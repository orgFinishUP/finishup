"""Every regular expression the MCP bridge advertises compiles in ECMAScript unicode mode.

JSON Schema ``pattern`` values are ECMA-262, and a host compiles the tools' schemas with a
JavaScript engine: Cursor 3.27.22 dropped every FinishUP tool ("0 tools") because one pattern,
the receipt's ``agent_closing_prompt``, escaped spaces as ``\\ `` (Python's ``re.escape``), which a
unicode-mode engine refuses. The bridge's ``tools/list`` (each tool's ``inputSchema`` and
``outputSchema``, for every host and route profile) is checked two ways:

- ``builders.ecmascript_pattern``, a strict check of the unicode-mode grammar, always (its module
  text says what it does not catch);
- the real engine, ``node`` (``new RegExp(pattern, "u")``), wherever it is installed; under CI
  (``CI`` set) a missing ``node`` fails the test rather than skipping it.

The published receipt-result 1.3.0 and 1.4.0 schemas keep their shipped pattern (never advertised
by this build); every other schema under ``schemas/`` is held to the same rule.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest

from builders.ecmascript_pattern import ECMAPatternError, check_unicode_pattern
from finishup.domain.receipt_closing import (
    CLOSING_PROMPT_PATTERN,
    PUBLISHED_CLOSING_PROMPT_PATTERN,
)
from finishup.mcp.descriptors import McpRouteProfile
from finishup.mcp.server import McpHostProfile, build_bridge_runtime, list_tools

_REPOSITORY = Path(__file__).resolve().parents[3]
_HOSTS: tuple[McpHostProfile, ...] = ("generic", "codex", "claude", "cursor")
_ROUTES: tuple[McpRouteProfile, ...] = ("policy", "strict")
# Shipped in v0.3.0 and frozen: their bytes never change (a new version carries the fix).
_FROZEN = {
    (
        "operations/receipt-result-1.3.0.schema.json",
        "/$defs/success/properties/agent_closing_prompt",
    ),
    (
        "operations/receipt-result-1.4.0.schema.json",
        "/$defs/success/properties/agent_closing_prompt",
    ),
}


def _patterns(node: object, pointer: str = "") -> Iterator[tuple[str, str]]:
    """Every ``pattern`` value and ``patternProperties`` key beneath ``node``, with its pointer."""

    if isinstance(node, dict):
        for key, value in cast(dict[str, object], node).items():
            if key == "pattern" and isinstance(value, str):
                yield pointer, value
            elif key == "patternProperties" and isinstance(value, dict):
                properties = cast(dict[str, object], value)
                for expression in properties:
                    yield f"{pointer}/patternProperties", expression
                yield from _patterns(properties, f"{pointer}/{key}")
            else:
                yield from _patterns(value, f"{pointer}/{key}")
    elif isinstance(node, list):
        for index, value in enumerate(cast(list[object], node)):
            yield from _patterns(value, f"{pointer}/{index}")


def _advertised() -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for host in _HOSTS:
        for route in _ROUTES:
            runtime = build_bridge_runtime(host_profile=host, route_profile=route)
            for tool in asyncio.run(list_tools(runtime)):
                for member, schema in (
                    ("inputSchema", tool.inputSchema),
                    ("outputSchema", tool.outputSchema),
                ):
                    for pointer, pattern in _patterns(schema):
                        found.append((f"{host}/{route}/{tool.name}.{member}{pointer}", pattern))
    return found


def _refused(pattern: str) -> str | None:
    try:
        check_unicode_pattern(pattern)
    except ECMAPatternError as error:
        return str(error)
    return None


def test_every_advertised_pattern_follows_the_unicode_mode_grammar() -> None:
    advertised = _advertised()
    # Both members carry patterns, so both are checked.
    assert any(".inputSchema/" in where for where, _pattern in advertised)
    assert any(".outputSchema/" in where for where, _pattern in advertised)
    refused = {where: why for where, pattern in advertised if (why := _refused(pattern))}
    assert refused == {}


def test_every_advertised_pattern_compiles_in_a_javascript_engine() -> None:
    node = shutil.which("node")
    if node is None:
        if os.environ.get("CI"):
            pytest.fail("node is required under CI to compile the advertised patterns")
        pytest.skip("node is not installed here; the grammar check above still ran")
    patterns = sorted({pattern for _where, pattern in _advertised()})
    script = (
        "const ps = JSON.parse(require('fs').readFileSync(0, 'utf8'));"
        "const bad = ps.filter(p => { try { new RegExp(p, 'u'); return false; }"
        " catch (e) { return true; } });"
        "process.stdout.write(JSON.stringify(bad));"
    )
    completed = subprocess.run(  # noqa: S603 - fixed argv; patterns go through stdin
        [node, "-e", script],
        input=json.dumps(patterns),
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    assert json.loads(completed.stdout) == []


def test_every_schema_pattern_follows_the_unicode_mode_grammar_but_the_shipped_ones() -> None:
    refused: set[tuple[str, str]] = set()
    for path in sorted((_REPOSITORY / "schemas").rglob("*.schema.json")):
        relative = path.relative_to(_REPOSITORY / "schemas").as_posix()
        for pointer, pattern in _patterns(json.loads(path.read_text(encoding="utf-8"))):
            if _refused(pattern) is not None:
                refused.add((relative, pointer))
    assert refused == _FROZEN


def test_the_closing_line_accepts_exactly_what_the_shipped_pattern_accepted() -> None:
    """The fix only drops the escapes before spaces; both patterns accept the same strings."""

    import re

    assert PUBLISHED_CLOSING_PROMPT_PATTERN.replace("\\ ", " ") == CLOSING_PROMPT_PATTERN
    lead = "Tell the user in your final message: receipt conclusion "
    samples = [
        lead + "insufficient_coverage.",
        lead + "unresolved_findings_remain; reviewer notes: 3, not answered: 1.",
        lead + "no_unresolved_deterministic_findings; reviewer notes: 2, not answered: 0, "
        "declined: 1; name each note not answered or declined.",
        lead + "insufficient_coverage; name each note not answered or declined.",
        lead.replace(" ", "  ") + "insufficient_coverage.",
        lead + "insufficient_coverage",
        lead + "unknown.",
        lead + "insufficient_coverage; reviewer notes: 01, not answered: 0.",
        "tell the user in your final message: receipt conclusion insufficient_coverage.",
        lead + "insufficient_coverage.\n",
    ]
    for sample in samples:
        shipped = re.search(PUBLISHED_CLOSING_PROMPT_PATTERN, sample, re.ASCII) is not None
        now = re.search(CLOSING_PROMPT_PATTERN, sample, re.ASCII) is not None
        assert shipped == now, sample
