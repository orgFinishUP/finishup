"""Evidence-directory enumeration in ``scripts/scan_public_boundary.py`` never follows a link.

Any entry the scanner cannot read as a regular file inside the evidence tree makes the scan
incomplete and blocking: a symlinked file, a symlinked directory at any depth, a symlinked
evidence root, or a non-regular entry such as a FIFO. A blocked scan names the reason and never
echoes the bytes behind the link.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType
from typing import Final

import pytest

_SCRIPT_PATH: Final = Path(__file__).resolve().parents[2] / "scripts" / "scan_public_boundary.py"

# Assembled at runtime so the boundary scan of this checkout does not flag the test itself.
_KEY_LABEL: Final = "RSA " + "PRIVATE " + "KEY"
_PRIVATE_KEY: Final = (
    f"-----BEGIN {_KEY_LABEL}-----\nMIIBOgIBAAJBAK\n-----END {_KEY_LABEL}-----\n"
).encode()


@pytest.fixture(scope="module")
def scanner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("finishup_scan_public_boundary", _SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _layout(tmp_path: Path) -> tuple[Path, Path]:
    private = tmp_path / "private"
    private.mkdir()
    (private / "id.pem").write_bytes(_PRIVATE_KEY)
    evidence = tmp_path / "evidence"
    (evidence / "sub").mkdir(parents=True)
    (evidence / "summary.txt").write_text("ok\n", encoding="utf-8")
    return private, evidence


def _assert_incomplete(
    scanner: ModuleType,
    evidence: Path,
    capsys: pytest.CaptureFixture[str],
    reason: str,
) -> None:
    assert scanner.main(["--evidence-dir", str(evidence)]) == 1
    captured = capsys.readouterr()
    assert f"FAIL ({reason})" in captured.err
    assert "incomplete scan" in captured.err
    assert "PASS" not in captured.out
    assert "MIIBOgIBAAJBAK" not in captured.out + captured.err


def test_clean_evidence_passes(
    scanner: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, evidence = _layout(tmp_path)
    assert scanner.main(["--evidence-dir", str(evidence)]) == 0
    assert "PASS" in capsys.readouterr().out


def test_symlinked_file_blocks(
    scanner: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    private, evidence = _layout(tmp_path)
    (evidence / "sub" / "id.pem").symlink_to(private / "id.pem")
    _assert_incomplete(scanner, evidence, capsys, "unscanned_evidence_entry")


def test_symlinked_directory_blocks(
    scanner: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    private, evidence = _layout(tmp_path)
    (evidence / "linked").symlink_to(private, target_is_directory=True)
    assert (evidence / "linked" / "id.pem").is_file()
    _assert_incomplete(scanner, evidence, capsys, "unscanned_evidence_entry")


def test_nested_symlinked_directory_blocks(
    scanner: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    private, evidence = _layout(tmp_path)
    (evidence / "sub" / "deeper").mkdir()
    (evidence / "sub" / "deeper" / "linked").symlink_to(private, target_is_directory=True)
    _assert_incomplete(scanner, evidence, capsys, "unscanned_evidence_entry")


def test_symlinked_evidence_root_blocks(
    scanner: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    private, _ = _layout(tmp_path)
    linked_root = tmp_path / "linked-evidence"
    linked_root.symlink_to(private, target_is_directory=True)
    _assert_incomplete(scanner, linked_root, capsys, "evidence_dir_missing")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs need a POSIX host")
def test_fifo_entry_blocks(
    scanner: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, evidence = _layout(tmp_path)
    os.mkfifo(evidence / "sub" / "pipe")
    _assert_incomplete(scanner, evidence, capsys, "unscanned_evidence_entry")


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="needs a non-root POSIX user"
)
def test_unreadable_directory_blocks(
    scanner: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, evidence = _layout(tmp_path)
    locked = evidence / "sub" / "locked"
    locked.mkdir()
    (locked / "id.pem").write_bytes(_PRIVATE_KEY)
    locked.chmod(0)
    try:
        _assert_incomplete(scanner, evidence, capsys, "unscanned_evidence_entry")
    finally:
        locked.chmod(0o700)
