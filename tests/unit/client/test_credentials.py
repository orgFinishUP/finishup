"""Server-target credentials: platform store first, owner-only file otherwise, never echoed."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from builders.server_targets import ambient_home
from finishup.client.credentials import (
    SERVER_CREDENTIAL_SERVICE,
    CredentialError,
    KeyringOrFileCredential,
    read_key_file,
    validate_secret,
)
from finishup.client.targets import CredentialLocation

_KEY = "fuk_0123456789ab_" + "B" * 43
_TARGET = "t_0a1b2c3d"


class _Keyring:
    def __init__(self) -> None:
        self.entries: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.entries.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.entries[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        del self.entries[(service, username)]


@pytest.fixture
def root(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as home:
        target = home / _TARGET
        (target / "config").mkdir(parents=True, mode=0o700)
        target.chmod(0o700)
        yield target


def test_the_file_fallback_is_owner_only_and_reversible(root: Path) -> None:
    credential = KeyringOrFileCredential(_TARGET, root, recorded=None, platform=None)
    assert credential.store(_KEY) == "file"
    entry = root / "config" / "credential" / _TARGET
    assert entry.read_text(encoding="ascii") == _KEY
    assert entry.stat().st_mode & 0o777 == 0o600
    assert (root / "config" / "credential").stat().st_mode & 0o777 == 0o700
    assert credential.read() == _KEY
    assert credential.delete() is True
    assert not entry.exists()
    assert credential.location() is None
    assert credential.delete() is False


def test_the_platform_store_is_preferred_and_the_old_file_is_removed(root: Path) -> None:
    file_only = KeyringOrFileCredential(_TARGET, root, recorded=None, platform=None)
    assert file_only.store(_KEY) == "file"
    keyring = _Keyring()
    moved = KeyringOrFileCredential(_TARGET, root, recorded="file", platform=keyring)
    assert moved.store(_KEY) == "keyring"
    assert keyring.entries == {(SERVER_CREDENTIAL_SERVICE, _TARGET): _KEY}
    assert not (root / "config" / "credential" / _TARGET).exists()
    assert moved.read() == _KEY


def test_a_missing_credential_is_a_closed_reason(root: Path) -> None:
    credential = KeyringOrFileCredential(_TARGET, root, recorded=None, platform=None)
    with pytest.raises(CredentialError) as raised:
        credential.read()
    assert raised.value.reason == "credential_unavailable"
    recorded_keyring = KeyringOrFileCredential(_TARGET, root, recorded="keyring", platform=None)
    with pytest.raises(CredentialError) as unavailable:
        recorded_keyring.read()
    assert unavailable.value.reason == "credential_store_unavailable"


class _LockedKeyring:
    """A platform store that is present but cannot be used now (a locked keychain)."""

    def get_password(self, service: str, username: str) -> str | None:
        raise RuntimeError("locked", service, username)

    def set_password(self, service: str, username: str, password: str) -> None:
        del password
        raise RuntimeError("locked", service, username)

    def delete_password(self, service: str, username: str) -> None:
        raise RuntimeError("locked", service, username)


class _RefusingKeyring:
    """A platform store that is there but refuses every call (locked, denied, no keychain to
    write to); it records what it was asked."""

    def __init__(self) -> None:
        self.asked: list[str] = []

    def get_password(self, service: str, username: str) -> str | None:
        self.asked.append("get")
        raise RuntimeError("refused", service, username)

    def set_password(self, service: str, username: str, password: str) -> None:
        del password
        self.asked.append("set")
        raise RuntimeError("refused", service, username)

    def delete_password(self, service: str, username: str) -> None:
        self.asked.append("delete")
        raise RuntimeError("refused", service, username)


@pytest.mark.parametrize("recorded", [None, "file", "keyring"])
def test_a_platform_store_that_refuses_the_key_hands_it_to_the_owner_only_file(
    root: Path, recorded: CredentialLocation | None
) -> None:
    """On a Mac whose keychain could not take a key, ``server add`` and ``login`` failed with
    ``credential_store_unavailable``, though a file only the owner can read is the promised
    place where the platform store cannot keep it. Reading follows the recorded file and never
    asks the refusing store again."""

    if recorded == "file":
        KeyringOrFileCredential(_TARGET, root, recorded=None, platform=None).store("x" * 16)
    refusing = _RefusingKeyring()
    credential = KeyringOrFileCredential(_TARGET, root, recorded=recorded, platform=refusing)
    assert credential.store(_KEY) == "file"
    entry = root / "config" / "credential" / _TARGET
    assert entry.read_text(encoding="ascii") == _KEY
    assert entry.stat().st_mode & 0o777 == 0o600
    assert credential.location() == "file"
    assert credential.read() == _KEY
    assert KeyringOrFileCredential(_TARGET, root, recorded="file", platform=refusing).read() == _KEY
    # Asked once, to take the key; a key it held before is not asked about again.
    assert refusing.asked == ["set"]


def test_only_a_key_neither_store_can_keep_is_refused(root: Path) -> None:
    unwritable = root / "missing"  # the file store creates only its own folder, never parents
    for platform in (_RefusingKeyring(), None):
        credential = KeyringOrFileCredential(_TARGET, unwritable, recorded=None, platform=platform)
        with pytest.raises(CredentialError) as raised:
            credential.store(_KEY)
        assert raised.value.reason == "credential_store_unavailable"
        assert _KEY not in str(raised.value)
        assert credential.location() is None


def test_a_store_the_key_is_not_recorded_in_never_blocks_its_delete(root: Path) -> None:
    """SRV-4: a locked platform store blocked deleting a key kept in a file, and a target that
    never held a key. Only the recorded store's failure keeps the key (and says so)."""

    locked = _LockedKeyring()
    in_file = KeyringOrFileCredential(_TARGET, root, recorded=None, platform=None)
    assert in_file.store(_KEY) == "file"
    assert KeyringOrFileCredential(_TARGET, root, recorded="file", platform=locked).delete()
    assert not (root / "config" / "credential" / _TARGET).exists()
    assert not KeyringOrFileCredential(_TARGET, root, recorded=None, platform=locked).delete()
    with pytest.raises(CredentialError) as raised:
        KeyringOrFileCredential(_TARGET, root, recorded="keyring", platform=locked).delete()
    assert raised.value.reason == "credential_store_unavailable"


def test_a_recorded_platform_store_that_cannot_be_loaded_keeps_the_key_and_says_so(
    root: Path,
) -> None:
    """SRV-4: a key recorded in the platform store, on a machine where no platform store can be
    loaded now (a Linux desktop reached over SSH, with no D-Bus session), was skipped silently:
    ``logout`` then said no key was stored and ``remove`` said nothing about the key left
    behind. The recorded store decides, so the delete is refused and the key stays."""

    keyring = _Keyring()
    stored = KeyringOrFileCredential(_TARGET, root, recorded=None, platform=keyring)
    assert stored.store(_KEY) == "keyring"
    absent = KeyringOrFileCredential(_TARGET, root, recorded="keyring", platform=None)
    with pytest.raises(CredentialError) as raised:
        absent.delete()
    assert raised.value.reason == "credential_store_unavailable"
    assert absent.location() == "keyring"
    assert keyring.entries == {(SERVER_CREDENTIAL_SERVICE, _TARGET): _KEY}
    # A target that records no platform key is not refused by a store it never used.
    assert not KeyringOrFileCredential(_TARGET, root, recorded=None, platform=None).delete()


@pytest.mark.parametrize("secret", ["", "short", "has space in it here", "x" * 513, "é" * 20])
def test_secret_shape_is_checked_without_echo(secret: str) -> None:
    with pytest.raises(CredentialError) as raised:
        validate_secret(secret)
    assert raised.value.reason == "credential_invalid"
    assert secret not in str(raised.value) or not secret


def test_key_files_must_be_owner_only_regular_files(root: Path) -> None:
    key = root / "key"
    key.write_text(_KEY + "\n", encoding="ascii")
    key.chmod(0o600)
    assert read_key_file(key) == _KEY
    key.chmod(0o640)
    with pytest.raises(CredentialError) as raised:
        read_key_file(key)
    assert raised.value.reason == "credential_invalid"
    key.chmod(0o600)
    link = root / "link"
    os.symlink(key, link)
    with pytest.raises(CredentialError):
        read_key_file(link)
    with pytest.raises(CredentialError) as missing:
        read_key_file(root / "absent")
    assert missing.value.reason == "credential_unavailable"


def test_account_names_are_target_ids_only(root: Path) -> None:
    with pytest.raises(CredentialError):
        KeyringOrFileCredential("lab", root, recorded=None, platform=None)
    with pytest.raises(CredentialError):
        KeyringOrFileCredential(_TARGET, Path("relative"), recorded=None, platform=None)


def test_the_owner_file_store_keeps_its_auto_unlock_defaults() -> None:
    from finishup.adapters.keys.owner_file_store import OwnerOnlyFileCredentialStore

    store = OwnerOnlyFileCredentialStore(Path("/nonexistent/auto-unlock"))
    with pytest.raises(ValueError):
        store.set_password(SERVER_CREDENTIAL_SERVICE, "bundle-" + "0" * 64, "x")
