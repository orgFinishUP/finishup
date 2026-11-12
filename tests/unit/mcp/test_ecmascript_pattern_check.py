"""The unicode-mode grammar check the advertised-pattern test relies on agrees with a real engine.

Its verdicts are pinned here for the escapes and syntax that differ between Python's ``re`` and an
ECMAScript engine in unicode mode, and, where ``node`` is installed, compared with that engine.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from builders.ecmascript_pattern import ECMAPatternError, check_unicode_pattern

_ACCEPTED = (
    r"^[A-Za-z0-9._:-]{1,128}$",
    r"^[A-Za-z0-9][A-Za-z0-9._:/+\-]*$",
    r"^sha256:[0-9a-f]{64}$",
    r"^(?:0|[1-9][0-9]{0,18})$",
    r"^Tell the user\.$",
    r"\.",
    r"\/",
    r"/",
    r"[\b]",
    r"[\-]",
    r"\0",
    r"\x41",
    r"A",
    r"\u{1F600}",
    r"😀",
    r"\cA",
    r"\p{L}",
    r"(a)\1",
    r"(?<name>a)\k<name>",
    r"(?<=a)b",
    r"(?<!a)b",
    r"(?=a)",
    r"[\d-]",
    r"x{0}",
)
_REFUSED = (
    r"^Tell\ the\ user\.$",
    r"\_",
    r"\a",
    r"a{",
    r"}",
    r"]",
    r"a{2,1}",
    r"[\w-a]",
    r"[z-a]",
    r"(?<n>x)(?<n>y)",
    r"\1",
    r"\k<x>",
    r"(?=a)*",
    r"(?i:a)",
    r"\00",
    r"\x4",
    r"\u{110000}",
    r"\c1",
    r"a**",
    r"(",
    r")",
    r"[",
)


@pytest.mark.parametrize("pattern", _ACCEPTED)
def test_what_a_unicode_mode_engine_compiles_is_accepted(pattern: str) -> None:
    check_unicode_pattern(pattern)


@pytest.mark.parametrize("pattern", _REFUSED)
def test_what_a_unicode_mode_engine_refuses_is_refused(pattern: str) -> None:
    with pytest.raises(ECMAPatternError):
        check_unicode_pattern(pattern)


def test_the_check_agrees_with_a_javascript_engine_where_one_is_installed() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed here")
    patterns = [*_ACCEPTED, *_REFUSED]
    script = (
        "const ps = JSON.parse(require('fs').readFileSync(0, 'utf8'));"
        "process.stdout.write(JSON.stringify(ps.map(p => { try { new RegExp(p, 'u');"
        " return true; } catch (e) { return false; } })));"
    )
    completed = subprocess.run(  # noqa: S603 - fixed argv; patterns go through stdin
        [node, "-e", script],
        input=json.dumps(patterns),
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    engine = dict(zip(patterns, json.loads(completed.stdout), strict=True))
    assert engine == {pattern: pattern in _ACCEPTED for pattern in patterns}
