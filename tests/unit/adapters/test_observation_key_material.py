"""The observation key is created once and never replaced by a failed or invalid read.

Every workspace and session commitment is an HMAC under ``observation/key-material.bin``. A key
file that exists but cannot be read, or holds the wrong number of bytes, must surface a typed
storage error and stay byte-identical; only a truly absent key is created.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.protocol.errors import PublicErrorCode, PublicOperationError


def _key_path(state: Path) -> Path:
    return state / "observation" / "key-material.bin"


def _seeded(state: Path) -> tuple[bytes, str]:
    store = LocalObservationStore(_state=state)
    original = store.key_material()
    workspace = store.workspace_commitment(str(state))
    store.grant_consent(workspace)
    return original, workspace


def test_missing_key_is_created_once_and_then_stable(tmp_path: Path) -> None:
    assert LocalObservationStore(_state=tmp_path).existing_workspace_commitment("/w") is None
    first = LocalObservationStore(_state=tmp_path).key_material()
    assert len(first) == 32
    assert LocalObservationStore(_state=tmp_path).key_material() == first
    assert LocalObservationStore(_state=tmp_path).existing_workspace_commitment("/w") is not None


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-0 file")
def test_unreadable_existing_key_raises_and_is_not_rotated(tmp_path: Path) -> None:
    original, workspace = _seeded(tmp_path)
    key_path = _key_path(tmp_path)
    inode_before = key_path.stat().st_ino
    os.chmod(key_path, 0)
    try:
        fresh = LocalObservationStore(_state=tmp_path)
        with pytest.raises(PublicOperationError) as raised:
            fresh.key_material()
        assert raised.value.code is PublicErrorCode.STORAGE_UNSAFE
        with pytest.raises(PublicOperationError) as preview:
            fresh.existing_workspace_commitment(str(tmp_path))
        assert preview.value.code is PublicErrorCode.STORAGE_UNSAFE
        with pytest.raises(PublicOperationError):
            fresh.workspace_commitment(str(tmp_path))
    finally:
        os.chmod(key_path, 0o600)
    assert key_path.stat().st_ino == inode_before
    after = LocalObservationStore(_state=tmp_path)
    assert after.key_material() == original
    assert after.workspace_commitment(str(tmp_path)) == workspace
    assert after.consent_for(workspace) is not None


@pytest.mark.parametrize("payload", [b"", b"\x01" * 16, b"\x02" * 33])
def test_wrong_size_key_raises_and_is_left_untouched(tmp_path: Path, payload: bytes) -> None:
    _seeded(tmp_path)
    key_path = _key_path(tmp_path)
    key_path.write_bytes(payload)
    inode_before = key_path.stat().st_ino
    store = LocalObservationStore(_state=tmp_path)
    with pytest.raises(PublicOperationError) as raised:
        store.key_material()
    assert raised.value.code is PublicErrorCode.STORAGE_UNSAFE
    with pytest.raises(PublicOperationError):
        store.existing_workspace_commitment(str(tmp_path))
    assert key_path.stat().st_ino == inode_before
    assert key_path.read_bytes() == payload


def test_symlinked_key_raises_and_is_not_replaced(tmp_path: Path) -> None:
    original, _workspace = _seeded(tmp_path)
    key_path = _key_path(tmp_path)
    target = tmp_path / "elsewhere.bin"
    target.write_bytes(original)
    key_path.unlink()
    key_path.symlink_to(target)
    store = LocalObservationStore(_state=tmp_path)
    with pytest.raises(PublicOperationError) as raised:
        store.key_material()
    assert raised.value.code is PublicErrorCode.STORAGE_UNSAFE
    assert key_path.is_symlink()
    assert target.read_bytes() == original
