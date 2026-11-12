"""The owner's per-repository choices for a server copy (level L2, ADR-054)."""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest

from finishup.client.code_copy_settings import (
    CodeCopySettingsError,
    RepositoryCodeSettings,
    read_settings,
    settings_for,
    settings_path,
    update_settings,
)

TARGET = "t_0123abcd"
KEY = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
DIGEST = "sha256:" + "c" * 64


def test_choices_round_trip_and_an_empty_choice_leaves_the_record(tmp_path: Path) -> None:
    assert read_settings(tmp_path, TARGET) == {}
    update_settings(tmp_path, TARGET, KEY, lambda s: replace(s, level="L1"))
    update_settings(tmp_path, TARGET, KEY, lambda s: replace(s, exclude=("*.sqlite", "data/")))
    update_settings(tmp_path, TARGET, OTHER, lambda s: replace(s, allow=(("cfg/a.ini", DIGEST),)))
    found = read_settings(tmp_path, TARGET)
    assert found[KEY] == RepositoryCodeSettings(level="L1", exclude=("*.sqlite", "data/"))
    assert found[OTHER].allows("cfg/a.ini", DIGEST)
    assert not found[OTHER].allows("cfg/a.ini", "sha256:" + "d" * 64)
    assert settings_path(tmp_path).stat().st_mode & 0o077 == 0
    update_settings(tmp_path, TARGET, KEY, lambda _s: RepositoryCodeSettings())
    assert KEY not in read_settings(tmp_path, TARGET)
    assert settings_for(tmp_path, TARGET, KEY) == RepositoryCodeSettings()


def test_only_a_step_down_to_l1_can_be_recorded() -> None:
    with pytest.raises(CodeCopySettingsError):
        RepositoryCodeSettings(level="L2")  # type: ignore[arg-type]
    for exclude in (("/",), ("**",), ("a\x00",), ("b", "a")):
        with pytest.raises(CodeCopySettingsError):
            RepositoryCodeSettings(exclude=exclude)
    with pytest.raises(CodeCopySettingsError):
        RepositoryCodeSettings(allow=(("p", "md5:1"),))


def test_a_record_that_is_unsafe_malformed_or_another_target_s_is_refused(tmp_path: Path) -> None:
    update_settings(tmp_path, TARGET, KEY, lambda s: replace(s, level="L1"))
    path = settings_path(tmp_path)
    with pytest.raises(CodeCopySettingsError, match="code_copy_settings_invalid"):
        read_settings(tmp_path, "t_ffffffff")
    os.chmod(path, 0o644)
    with pytest.raises(CodeCopySettingsError, match="code_copy_settings_unsafe"):
        read_settings(tmp_path, TARGET)
    os.chmod(path, 0o600)
    path.write_bytes(path.read_bytes().replace(b'"L1"', b'"L2"'))
    with pytest.raises(CodeCopySettingsError, match="code_copy_settings_invalid"):
        read_settings(tmp_path, TARGET)
    # A record that cannot be read is never overwritten.
    with pytest.raises(CodeCopySettingsError):
        update_settings(tmp_path, TARGET, OTHER, lambda s: replace(s, level="L1"))
    path.unlink()
    path.symlink_to(tmp_path / "elsewhere.json")
    (tmp_path / "elsewhere.json").write_bytes(b"{}\n")
    with pytest.raises(CodeCopySettingsError, match="code_copy_settings_unsafe"):
        read_settings(tmp_path, TARGET)
