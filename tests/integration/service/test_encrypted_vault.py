from __future__ import annotations

import errno
import hmac
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from finishup.adapters.keys import encrypted_vault
from finishup.adapters.keys.encrypted_vault import (
    EncryptedVaultError,
    EncryptedVaultStore,
    VaultRecordKind,
)
from finishup.adapters.keys.secret_memory import LocalSecretMemory
from finishup.ports.secret_memory import SecretConsumer, SecretPurpose
from finishup.protocol.canonical import JsonValue, canonical_encode

_INSTALLATION_ID = "ins_00000000-0000-4000-8000-000000000001"
_TASK_ID = "tsk_00000000-0000-4000-8000-000000000002"
_BUNDLE_BINDING = {"task_id": _TASK_ID, "key_slot": "bmk-test"}
_CREDENTIAL_BINDING = {
    "provider_id": "openai",
    "model_id": "gpt-5",
    "endpoint_profile_id": "openai-default",
    "endpoint_profile_version": "1",
    "purpose": "review",
    "authorization_scope_digest": "sha256:" + "a" * 64,
    "purpose_digest": "sha256:" + "b" * 64,
}


def _capture(memory: LocalSecretMemory, value: bytes, purpose: SecretPurpose):
    return memory.capture(purpose, bytearray(value))


def test_records_round_trip_without_plaintext_or_independent_mac_key_records(
    tmp_path: Path,
) -> None:
    memory = LocalSecretMemory()
    root = b"r" * 32
    store = EncryptedVaultStore(tmp_path / "vault")
    store.initialize(_capture(memory, root, SecretPurpose.VAULT_ROOT_KEY))
    store.create_record(
        VaultRecordKind.VAULT_SENTINEL,
        {"installation_id": _INSTALLATION_ID},
        _capture(memory, b"sentinel-canary", SecretPurpose.VAULT_ROOT_KEY),
    )
    store.create_record(
        VaultRecordKind.BUNDLE_KEY,
        {"task_id": _TASK_ID, "key_slot": "bmk-test"},
        _capture(memory, b"bundle-master-key-canary-32byt!", SecretPurpose.VAULT_ROOT_KEY),
    )
    loaded = store.load_record(
        VaultRecordKind.BUNDLE_KEY,
        {"task_id": _TASK_ID, "key_slot": "bmk-test"},
    )
    assert loaded.consume(SecretConsumer.VAULT_ROOT, bytes) == b"bundle-master-key-canary-32byt!"

    disk = b"".join(path.read_bytes() for path in (tmp_path / "vault").iterdir())
    assert b"sentinel-canary" not in disk
    assert b"bundle-master-key-canary" not in disk
    assert b"catalog_lookup" not in disk
    assert b"log_correlation" not in disk
    assert b"privacy_audit" not in disk


def test_wrong_root_and_frame_tamper_fail_closed(tmp_path: Path) -> None:
    memory = LocalSecretMemory()
    vault_dir = tmp_path / "vault"
    store = EncryptedVaultStore(vault_dir)
    store.initialize(_capture(memory, b"a" * 32, SecretPurpose.VAULT_ROOT_KEY))
    store.create_record(
        VaultRecordKind.VAULT_SENTINEL,
        {"installation_id": _INSTALLATION_ID},
        _capture(memory, b"sentinel", SecretPurpose.VAULT_ROOT_KEY),
    )
    store.close()

    wrong = EncryptedVaultStore(vault_dir)
    with pytest.raises(EncryptedVaultError):
        wrong.initialize(_capture(memory, b"b" * 32, SecretPurpose.VAULT_ROOT_KEY))

    frame = next(vault_dir.glob("vrec_*.1.yzv"))
    data = bytearray(frame.read_bytes())
    data[-1] ^= 1
    frame.write_bytes(data)
    reopened = EncryptedVaultStore(vault_dir)
    with pytest.raises(EncryptedVaultError):
        reopened.initialize(_capture(memory, b"a" * 32, SecretPurpose.VAULT_ROOT_KEY))


def test_root_rotation_reencrypts_every_record_and_preserves_commitment_root(
    tmp_path: Path,
) -> None:
    memory = LocalSecretMemory()
    old_root = b"o" * 32
    new_root = b"n" * 32
    vault_dir = tmp_path / "vault"
    store = EncryptedVaultStore(vault_dir)
    store.initialize(_capture(memory, old_root, SecretPurpose.VAULT_ROOT_KEY))
    store.create_record(
        VaultRecordKind.VAULT_SENTINEL,
        {"installation_id": _INSTALLATION_ID},
        _capture(memory, b"sentinel", SecretPurpose.VAULT_ROOT_KEY),
    )
    store.create_record(
        VaultRecordKind.BUNDLE_KEY,
        {"task_id": _TASK_ID, "key_slot": "bmk-test"},
        _capture(memory, b"bundle-key", SecretPurpose.VAULT_ROOT_KEY),
    )
    before_mac_root = store.installation_mac_root().consume(SecretConsumer.VAULT_ROOT, bytes)

    prepared = store.prepare_root_rotation(
        _capture(memory, new_root, SecretPurpose.VAULT_ROOT_KEY),
        recovery_generation=2,
    )

    old_candidate = EncryptedVaultStore(prepared.stage)
    with pytest.raises(EncryptedVaultError):
        old_candidate.initialize(_capture(memory, old_root, SecretPurpose.VAULT_ROOT_KEY))

    rotated = EncryptedVaultStore(prepared.stage)
    rotated.initialize(_capture(memory, new_root, SecretPurpose.VAULT_ROOT_KEY))
    rotated.verify_sentinel({"installation_id": _INSTALLATION_ID})
    loaded = rotated.load_record(
        VaultRecordKind.BUNDLE_KEY,
        {"task_id": _TASK_ID, "key_slot": "bmk-test"},
    )
    assert loaded.consume(SecretConsumer.VAULT_ROOT, bytes) == b"bundle-key"
    assert (
        rotated.installation_mac_root().consume(SecretConsumer.VAULT_ROOT, bytes) == before_mac_root
    )
    parsed_wrapper: object = json.loads((prepared.stage / "vault-index.json").read_bytes())
    assert type(parsed_wrapper) is dict
    wrapper = cast(dict[str, object], parsed_wrapper)
    assert type(wrapper["index"]) is dict
    old_locator = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"yoetz/vault-internal-root/v1",
        info=b"yoetz/vault-record-locator/v1",
    ).derive(old_root)
    legacy_index_mac = (
        "hmac-sha256:"
        + hmac.digest(
            old_locator,
            b"yoetz/vault-record-index/v1\x00"
            + canonical_encode(cast(dict[str, JsonValue], wrapper["index"])),
            "sha256",
        ).hex()
    )
    assert wrapper["index_mac"] != legacy_index_mac

    disk = b"".join(path.read_bytes() for path in prepared.stage.iterdir())
    assert old_root not in disk
    assert new_root not in disk
    assert before_mac_root not in disk


def _fail_once(monkeypatch: pytest.MonkeyPatch, name: str, *, skip: int = 0) -> Callable[[], int]:
    """Make the vault module's ``name`` raise ENOSPC once, after ``skip`` successful calls."""

    real = getattr(encrypted_vault.os if name == "replace" else encrypted_vault, name)
    calls = {"n": 0}

    def flaky(*args: object) -> object:
        calls["n"] += 1
        if calls["n"] == skip + 1:
            raise OSError(errno.ENOSPC, "No space left on device")
        return real(*args)

    if name == "replace":
        monkeypatch.setattr(encrypted_vault.os, "replace", flaky)
    else:
        monkeypatch.setattr(encrypted_vault, name, flaky)
    return lambda: calls["n"]


def _record_frames(vault_dir: Path) -> list[str]:
    return sorted(path.name for path in vault_dir.glob("vrec_*.yzv"))


def test_create_after_failed_index_publish_is_retryable_and_leaves_no_frame(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    memory = LocalSecretMemory()
    vault_dir = tmp_path / "vault"
    store = EncryptedVaultStore(vault_dir)
    store.initialize(_capture(memory, b"r" * 32, SecretPurpose.VAULT_ROOT_KEY))
    calls = _fail_once(monkeypatch, "replace")

    with pytest.raises(EncryptedVaultError, match="io_failure"):
        store.create_record(
            VaultRecordKind.BUNDLE_KEY,
            _BUNDLE_BINDING,
            _capture(memory, b"first-attempt", SecretPurpose.VAULT_ROOT_KEY),
        )
    assert calls() == 1
    assert store.record_generation(VaultRecordKind.BUNDLE_KEY, _BUNDLE_BINDING) is None
    assert _record_frames(vault_dir) == []

    store.create_record(
        VaultRecordKind.BUNDLE_KEY,
        _BUNDLE_BINDING,
        _capture(memory, b"second-attempt", SecretPurpose.VAULT_ROOT_KEY),
    )
    loaded = store.load_record(VaultRecordKind.BUNDLE_KEY, _BUNDLE_BINDING)
    assert loaded.consume(SecretConsumer.VAULT_ROOT, bytes) == b"second-attempt"


def test_credential_replace_after_failed_index_publish_is_retryable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    memory = LocalSecretMemory()
    vault_dir = tmp_path / "vault"
    store = EncryptedVaultStore(vault_dir)
    store.initialize(_capture(memory, b"r" * 32, SecretPurpose.VAULT_ROOT_KEY))
    kind = VaultRecordKind.PROVIDER_CREDENTIAL
    store.create_record(
        kind,
        _CREDENTIAL_BINDING,
        _capture(memory, b"a" * 20, SecretPurpose.PROVIDER_CREDENTIAL),
    )
    frames_before = _record_frames(vault_dir)
    _fail_once(monkeypatch, "replace")

    with pytest.raises(EncryptedVaultError, match="io_failure"):
        store.replace_credential_record(
            _CREDENTIAL_BINDING,
            _capture(memory, b"b" * 20, SecretPurpose.PROVIDER_CREDENTIAL),
            expected_generation=1,
        )
    assert store.record_generation(kind, _CREDENTIAL_BINDING) == 1
    assert _record_frames(vault_dir) == frames_before

    store.replace_credential_record(
        _CREDENTIAL_BINDING,
        _capture(memory, b"c" * 20, SecretPurpose.PROVIDER_CREDENTIAL),
        expected_generation=1,
    )
    assert store.record_generation(kind, _CREDENTIAL_BINDING) == 2
    loaded = store.load_record(kind, _CREDENTIAL_BINDING)
    assert loaded.consume(SecretConsumer.VAULT_ROOT, bytes) == b"c" * 20


def test_reopened_vault_overwrites_a_frame_its_index_never_committed(tmp_path: Path) -> None:
    """A crash between the frame write and the index rename leaves only the frame behind."""

    memory = LocalSecretMemory()
    root = b"r" * 32
    vault_dir = tmp_path / "vault"
    store = EncryptedVaultStore(vault_dir)
    store.initialize(_capture(memory, root, SecretPurpose.VAULT_ROOT_KEY))
    index_before = (vault_dir / "vault-index.json").read_bytes()
    store.create_record(
        VaultRecordKind.BUNDLE_KEY,
        _BUNDLE_BINDING,
        _capture(memory, b"lost-attempt", SecretPurpose.VAULT_ROOT_KEY),
    )
    store.close()
    (vault_dir / "vault-index.json").write_bytes(index_before)

    reopened = EncryptedVaultStore(vault_dir)
    reopened.initialize(_capture(memory, root, SecretPurpose.VAULT_ROOT_KEY))
    assert reopened.record_generation(VaultRecordKind.BUNDLE_KEY, _BUNDLE_BINDING) is None
    reopened.create_record(
        VaultRecordKind.BUNDLE_KEY,
        _BUNDLE_BINDING,
        _capture(memory, b"retried", SecretPurpose.VAULT_ROOT_KEY),
    )
    reopened.close()

    again = EncryptedVaultStore(vault_dir)
    again.initialize(_capture(memory, root, SecretPurpose.VAULT_ROOT_KEY))
    loaded = again.load_record(VaultRecordKind.BUNDLE_KEY, _BUNDLE_BINDING)
    assert loaded.consume(SecretConsumer.VAULT_ROOT, bytes) == b"retried"


def test_uncommitted_frame_that_is_not_a_private_file_is_refused(tmp_path: Path) -> None:
    memory = LocalSecretMemory()
    root = b"r" * 32
    vault_dir = tmp_path / "vault"
    store = EncryptedVaultStore(vault_dir)
    store.initialize(_capture(memory, root, SecretPurpose.VAULT_ROOT_KEY))
    index_before = (vault_dir / "vault-index.json").read_bytes()
    store.create_record(
        VaultRecordKind.BUNDLE_KEY,
        _BUNDLE_BINDING,
        _capture(memory, b"lost-attempt", SecretPurpose.VAULT_ROOT_KEY),
    )
    store.close()
    (vault_dir / "vault-index.json").write_bytes(index_before)
    (frame,) = vault_dir.glob("vrec_*.1.yzv")
    os.link(frame, tmp_path / "second-name")

    reopened = EncryptedVaultStore(vault_dir)
    reopened.initialize(_capture(memory, root, SecretPurpose.VAULT_ROOT_KEY))
    with pytest.raises(EncryptedVaultError, match="unsafe_permissions"):
        reopened.create_record(
            VaultRecordKind.BUNDLE_KEY,
            _BUNDLE_BINDING,
            _capture(memory, b"retried", SecretPurpose.VAULT_ROOT_KEY),
        )
    assert frame.exists()


def test_frame_named_by_the_published_index_is_never_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The index rename landed but its directory sync failed: the frame stays committed."""

    memory = LocalSecretMemory()
    root = b"r" * 32
    vault_dir = tmp_path / "vault"
    store = EncryptedVaultStore(vault_dir)
    store.initialize(_capture(memory, root, SecretPurpose.VAULT_ROOT_KEY))
    # The frame publish syncs the directory once; the index publish syncs it second.
    _fail_once(monkeypatch, "_fsync_dir", skip=1)

    with pytest.raises(EncryptedVaultError, match="io_failure"):
        store.create_record(
            VaultRecordKind.BUNDLE_KEY,
            _BUNDLE_BINDING,
            _capture(memory, b"published", SecretPurpose.VAULT_ROOT_KEY),
        )
    with pytest.raises(EncryptedVaultError, match="record_exists"):
        store.create_record(
            VaultRecordKind.BUNDLE_KEY,
            _BUNDLE_BINDING,
            _capture(memory, b"overwrite", SecretPurpose.VAULT_ROOT_KEY),
        )
    store.close()

    reopened = EncryptedVaultStore(vault_dir)
    reopened.initialize(_capture(memory, root, SecretPurpose.VAULT_ROOT_KEY))
    loaded = reopened.load_record(VaultRecordKind.BUNDLE_KEY, _BUNDLE_BINDING)
    assert loaded.consume(SecretConsumer.VAULT_ROOT, bytes) == b"published"
