"""Rule PRIV-PATH-003 in ``scripts/scan_public_boundary.py`` blocks a Windows home path.

A maintainer's Windows home path must never reach a public artifact, whether it is written
literally (markdown, logs, text evidence) or escaped with doubled backslashes (JSON, source
code). The macOS and Linux siblings already match their literal forms.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Final

import pytest

_SCRIPT_PATH: Final = Path(__file__).resolve().parents[2] / "scripts" / "scan_public_boundary.py"

# Assembled at runtime so the boundary scan of this checkout does not flag the test itself.
_ONE: Final = "\\"
_TWO: Final = "\\\\"


@pytest.fixture(scope="module")
def scanner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("finishup_scan_public_boundary", _SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _windows_home(separator: str) -> str:
    return "C:" + separator + "Users" + separator + "alice" + separator + "proj"


@pytest.mark.parametrize(
    "body",
    [
        pytest.param("see " + _windows_home(_ONE) + "\n", id="literal"),
        pytest.param('{"path": "' + _windows_home(_TWO) + '"}\n', id="json-escaped"),
    ],
)
def test_windows_home_path_blocks_evidence_scan(
    scanner: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str], body: str
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "summary.md").write_text(body, encoding="utf-8")

    assert scanner.main(["--evidence-dir", str(evidence)]) == 1
    captured = capsys.readouterr()
    assert "PRIV-PATH-003" in captured.out + captured.err
    assert "PASS" not in captured.out
    assert "alice" not in captured.out + captured.err


def _findings(scanner: ModuleType, relative_path: str, data: bytes) -> set[str]:
    entry = scanner.FileEntry(relative_path=relative_path, size=len(data), data=data)
    findings = scanner.scan_bytes(entry, scanner.load_rules(), target_label="evidence")
    return {finding.rule_id for finding in findings}


@pytest.mark.parametrize("relative_path", ["summary.md", "capture.bin"], ids=["text", "bytes"])
@pytest.mark.parametrize("separator", [_ONE, _TWO], ids=["literal", "json-escaped"])
def test_windows_home_path_finding_names_the_rule(
    scanner: ModuleType, relative_path: str, separator: str
) -> None:
    data = ("see " + _windows_home(separator) + "\n").encode()
    assert "PRIV-PATH-003" in _findings(scanner, relative_path, data)


def test_text_without_a_drive_home_path_is_not_flagged(scanner: ModuleType) -> None:
    data = (
        "see C:Users and Users" + _ONE + "alice and xC:" + _ONE + "Users" + _ONE + "a\n"
    ).encode()
    assert "PRIV-PATH-003" not in _findings(scanner, "summary.md", data)
