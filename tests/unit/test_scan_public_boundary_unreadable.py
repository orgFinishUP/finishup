"""An unreadable target makes ``scripts/scan_public_boundary.py`` report an incomplete scan.

A truncated or corrupt archive, an unreadable tracked file, or a tracked name that is not UTF-8
is a bounded scan failure: the scanner names the reason for that target, still scans every other
target, still writes its report, and never dies with a traceback.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import os
import subprocess
import sys
import tarfile
import zipfile
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


def _payload() -> bytes:
    # Incompressible, deterministic bytes, so no compression-ratio limit fires first.
    return b"".join(hashlib.sha256(str(index).encode()).digest() for index in range(8192))


def _evidence_with_finding(tmp_path: Path) -> Path:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "id.pem").write_bytes(_PRIVATE_KEY)
    return evidence


def _assert_incomplete_and_continued(
    scanner: ModuleType,
    argv: list[str],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    reason: str,
) -> None:
    evidence = _evidence_with_finding(tmp_path)
    report = tmp_path / "out" / "report.json"
    code = scanner.main([*argv, "--evidence-dir", str(evidence), "--json-out", str(report)])
    captured = capsys.readouterr()
    assert code == 1
    assert f"FAIL ({reason})" in captured.err
    assert "incomplete scan" in captured.err
    # The evidence target after the unreadable one was still scanned and reported.
    assert f"{evidence}:id.pem (credential_private_key)" in captured.err
    assert report.is_file()
    assert "PASS" not in captured.out


def test_truncated_tar_gz_is_an_incomplete_scan(
    scanner: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        data = _payload()
        info = tarfile.TarInfo("pkg/payload.bin")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    whole = buffer.getvalue()
    broken = tmp_path / "pkg-1.0.tar.gz"
    broken.write_bytes(whole[: len(whole) // 2])
    _assert_incomplete_and_continued(
        scanner, ["--artifact", str(broken)], tmp_path, capsys, "archive_unreadable"
    )


def test_corrupt_deflate_zip_is_an_incomplete_scan(
    scanner: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("pkg/payload.bin", _payload())
    whole = bytearray(buffer.getvalue())
    with zipfile.ZipFile(io.BytesIO(bytes(whole))) as archive:
        info = archive.infolist()[0]
    # Corrupt the deflate stream itself; the central directory stays intact.
    data_start = info.header_offset + 30 + len(info.filename.encode()) + len(info.extra)
    for offset in range(data_start, data_start + 64):
        whole[offset] = 0xFF
    broken = tmp_path / "pkg-1.0-py3-none-any.whl"
    broken.write_bytes(bytes(whole))
    _assert_incomplete_and_continued(
        scanner, ["--artifact", str(broken)], tmp_path, capsys, "archive_unreadable"
    )


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def _source_tree(tmp_path: Path) -> Path:
    root = tmp_path / "source"
    root.mkdir()
    _git(root, "init", "-q")
    return root


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="needs a non-root POSIX user"
)
def test_unreadable_tracked_file_is_an_incomplete_scan(
    scanner: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _source_tree(tmp_path)
    locked = root / "locked.txt"
    locked.write_text("ok\n", encoding="utf-8")
    _git(root, "add", "locked.txt")
    locked.chmod(0)
    try:
        _assert_incomplete_and_continued(
            scanner, ["--source-tree", str(root)], tmp_path, capsys, "unscanned_tracked_entry"
        )
    finally:
        locked.chmod(0o600)


@pytest.mark.skipif(sys.platform != "linux", reason="needs a filesystem that keeps raw bytes")
def test_non_utf8_tracked_name_is_an_incomplete_scan(
    scanner: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _source_tree(tmp_path)
    name = b"caf\xe9.txt"
    Path(os.fsdecode(os.fsencode(root) + b"/" + name)).write_text("ok\n", encoding="utf-8")
    _git(root, "add", "-A")
    _assert_incomplete_and_continued(
        scanner, ["--source-tree", str(root)], tmp_path, capsys, "source_tree_listing_failed"
    )
