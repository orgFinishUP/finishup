"""Server-target credentials: where a target's API key lives on this client (ADR-051, section 6).

``CredentialSource`` is the pluggable interface; an OAuth source can implement it later.
``KeyringOrFileCredential`` keeps one target's key in the platform credential store under the
fixed service ``yoetz.server-credential.v1`` with the target id as the account, or — where no
platform store can take it (WSL 2, headless Linux, a macOS keychain that is missing or locked, a
store that refuses the write) — in an owner-only file beneath ``<target root>/config/credential/``.
``target.json`` records only which of the two holds it, and reading follows that record.

The key never appears in argv, the environment, ``target.json``, logs, or JSON output, and no
error carries it: every failure is a closed ``CredentialError`` reason. Same-user software can
still read the platform store or the file, as it can read today's auto-unlock secret; the claim
is interface parity — no surface an agent reaches reveals or switches the key.
"""

from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path
from typing import Final, Protocol, cast

from finishup.client.targets import CredentialLocation

__all__ = [
    "SERVER_CREDENTIAL_SERVICE",
    "CredentialError",
    "CredentialSource",
    "KeyringOrFileCredential",
    "read_key_file",
    "validate_secret",
]

# ADR-048 tag namespace; a frozen identifier once released.
SERVER_CREDENTIAL_SERVICE: Final = "yoetz.server-credential.v1"
# Platform stores this client accepts for a target key (the auto-unlock allowlist without the
# owner file, which is the explicit fallback below).
_PLATFORM_BACKENDS: Final = frozenset(
    {
        "keyring.backends.SecretService.Keyring",
        "keyring.backends.Windows.WinVaultKeyring",
        "keyring.backends.kwallet.DBusKeyring",
        "keyring.backends.libsecret.Keyring",
        "keyring.backends.macOS.Keyring",
    }
)
_MACOS_KEYCHAIN: Final = "keyring.backends.macOS.Keyring"
# Loaded by absolute path, never searched for, and only on macOS.
_SECURITY_FRAMEWORK: Final = "/System/Library/Frameworks/Security.framework/Security"
_CORE_FOUNDATION: Final = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
_KEYCHAIN_UNLOCKED: Final = 1  # kSecUnlockStateStatus, a SecKeychainStatus bit
_FILE_DIRECTORY: Final = Path("config") / "credential"
_ACCOUNT: Final = re.compile(r"^t_[0-9a-f]{8}$", re.ASCII)
# Printable ASCII without whitespace, bounded: covers ``fuk_<id>_<secret>`` keys and bearer
# tokens without ever echoing a rejected value.
_SECRET: Final = re.compile(r"^[\x21-\x7e]{16,512}$", re.ASCII)
_MAX_KEY_FILE_BYTES: Final = 1_024
_REASONS: Final = frozenset(
    {"credential_invalid", "credential_unavailable", "credential_store_unavailable"}
)


class CredentialError(Exception):
    """A bounded credential failure; ``reason`` is a closed token and never holds the secret."""

    reason: str

    def __init__(self, reason: str) -> None:
        if reason not in _REASONS:
            raise ValueError("credential_reason_invalid")
        self.reason = reason
        super().__init__(reason)


class CredentialSource(Protocol):
    """Where one server target's credential comes from."""

    @property
    def target_id(self) -> str: ...

    def location(self) -> CredentialLocation | None:
        """Which store holds the credential now, or ``None`` when none does."""
        ...

    def read(self) -> str:
        """Return the credential for the one process that dials; ``credential_unavailable``."""
        ...

    def store(self, secret: str) -> CredentialLocation:
        """Store (or replace) the credential and return where it went."""
        ...

    def delete(self) -> bool:
        """Remove the credential from every store; return whether one was removed."""
        ...


class _Backend(Protocol):
    def get_password(self, service: str, username: str) -> str | None: ...

    def set_password(self, service: str, username: str, password: str) -> None: ...

    def delete_password(self, service: str, username: str) -> None: ...


def validate_secret(secret: str) -> str:
    """Return ``secret`` when it has a key's shape; ``credential_invalid`` otherwise."""

    if type(secret) is not str or not _SECRET.match(secret):
        raise CredentialError("credential_invalid")
    return secret


def read_key_file(path: Path) -> str:
    """Read a key file once: a regular, owner-owned, owner-only (0600) file of one key line."""

    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise CredentialError("credential_unavailable") from None
    try:
        facts = os.fstat(descriptor)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != os.geteuid()
            or stat.S_IMODE(facts.st_mode) & 0o077
            or facts.st_size > _MAX_KEY_FILE_BYTES
        ):
            raise CredentialError("credential_invalid")
        data = os.read(descriptor, _MAX_KEY_FILE_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(data) > _MAX_KEY_FILE_BYTES:
        raise CredentialError("credential_invalid")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise CredentialError("credential_invalid") from None
    if text.endswith("\n"):
        text = text[:-1]
    if text.endswith("\r"):
        text = text[:-1]
    return validate_secret(text)


def _backend_id(backend: object) -> str:
    return f"{type(backend).__module__}.{type(backend).__qualname__}"


def _platform_backend() -> _Backend | None:
    """The first allowlisted platform credential store, or ``None`` when none is usable."""

    try:
        import keyring
        from keyring.backends.chainer import ChainerBackend

        loaded: object = keyring.get_keyring()
    except Exception:
        return None
    candidates: tuple[object, ...] = (
        tuple(loaded.backends) if isinstance(loaded, ChainerBackend) else (loaded,)
    )
    for candidate in candidates:
        if _backend_id(candidate) in _PLATFORM_BACKENDS:
            return cast(_Backend, candidate)
    return None


def _macos_keychain_ready() -> bool:
    """Whether macOS has a default keychain and it is unlocked, asked without user interaction.

    Adding an item where no default keychain can be found makes macOS show a dialog ("A keychain
    cannot be found to store ...") and wait for it; adding one to a locked keychain asks to unlock
    it. Neither may hold ``server add`` or ``server login``, which may run where nobody can answer
    (an SSH session) or under another ``HOME``. ``SecKeychainCopyDefault`` and
    ``SecKeychainGetStatus`` only read state and never ask. A failure at any step reads as not
    ready, so the key goes to the owner-only file instead.
    """

    if sys.platform != "darwin":
        return False
    try:
        import ctypes

        security = ctypes.CDLL(_SECURITY_FRAMEWORK)
        core_foundation = ctypes.CDLL(_CORE_FOUNDATION)
        copy_default = security.SecKeychainCopyDefault
        copy_default.argtypes = (ctypes.POINTER(ctypes.c_void_p),)
        copy_default.restype = ctypes.c_int32
        get_status = security.SecKeychainGetStatus
        get_status.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32))
        get_status.restype = ctypes.c_int32
        release = core_foundation.CFRelease
        release.argtypes = (ctypes.c_void_p,)
        release.restype = None
        keychain = ctypes.c_void_p()
        if copy_default(ctypes.byref(keychain)) != 0 or not keychain.value:
            return False  # no default keychain (errSecNoDefaultKeychain), or no reference
        try:
            status = ctypes.c_uint32(0)
            if get_status(keychain, ctypes.byref(status)) != 0:
                return False  # the default names a keychain that is not there, say
            return bool(status.value & _KEYCHAIN_UNLOCKED)
        finally:
            release(keychain)
    except Exception:
        return False


def _takes_a_key_without_asking(backend: _Backend) -> bool:
    """False only for the macOS keychain when it is missing or locked (``_macos_keychain_ready``)."""

    return _backend_id(backend) != _MACOS_KEYCHAIN or _macos_keychain_ready()


class KeyringOrFileCredential:
    """One target's API key in the platform store, or in an owner-only file beneath its root."""

    __slots__ = ("_platform", "_recorded", "_root", "_target_id")

    _platform: _Backend | None | bool
    _recorded: CredentialLocation | None
    _root: Path
    _target_id: str

    def __init__(
        self,
        target_id: str,
        target_root: Path,
        *,
        recorded: CredentialLocation | None,
        platform: _Backend | None | bool = True,
    ) -> None:
        """``recorded`` is ``target.json``'s ``credential``. ``platform=True`` discovers the
        platform store; tests pass a backend, or ``None`` for a machine without one."""

        if not _ACCOUNT.match(target_id) or not target_root.is_absolute():
            raise CredentialError("credential_invalid")
        self._target_id = target_id
        self._root = target_root
        self._recorded = recorded
        self._platform = platform

    @property
    def target_id(self) -> str:
        return self._target_id

    def _platform_store(self) -> _Backend | None:
        if self._platform is True:
            self._platform = _platform_backend()
        platform = self._platform
        return None if isinstance(platform, bool) else platform

    def _file_store(self) -> _Backend:
        from finishup.adapters.keys.owner_file_store import OwnerOnlyFileCredentialStore

        return OwnerOnlyFileCredentialStore(
            self._root / _FILE_DIRECTORY,
            service=SERVER_CREDENTIAL_SERVICE,
            account_pattern=_ACCOUNT,
        )

    def _store_for(self, location: CredentialLocation) -> _Backend:
        if location == "file":
            return self._file_store()
        backend = self._platform_store()
        if backend is None:
            raise CredentialError("credential_store_unavailable")
        return backend

    def location(self) -> CredentialLocation | None:
        return self._recorded

    def read(self) -> str:
        if self._recorded is None:
            raise CredentialError("credential_unavailable")
        try:
            value = self._store_for(self._recorded).get_password(
                SERVER_CREDENTIAL_SERVICE, self._target_id
            )
        except CredentialError:
            raise
        except Exception:
            raise CredentialError("credential_store_unavailable") from None
        if value is None:
            raise CredentialError("credential_unavailable")
        return validate_secret(value)

    def store(self, secret: str) -> CredentialLocation:
        """Store (or replace) the key; return where it went, for the caller to record.

        The platform store takes it when there is one and it accepts the write. Otherwise the
        owner-only file does: no platform store, a macOS keychain that is missing or locked
        (checked first and without asking the user, so no keychain dialog holds the command), or
        a store that refuses the write (locked, denied). Only a key the file cannot keep either
        is ``credential_store_unavailable``. Reading follows the location recorded.

        A key moved into the platform store leaves the file. A key the platform store held
        before stays there when the file takes the new one: that store was not usable, so it is
        not asked again. The next key it takes replaces it, and ``delete()`` tidies it when it
        can be used.
        """

        validate_secret(secret)
        location: CredentialLocation = "file"
        platform = self._platform_store()
        if platform is not None and _takes_a_key_without_asking(platform):
            try:
                platform.set_password(SERVER_CREDENTIAL_SERVICE, self._target_id, secret)
            except Exception:
                location = "file"
            else:
                location = "keyring"
        if location == "file":
            try:
                self._file_store().set_password(SERVER_CREDENTIAL_SERVICE, self._target_id, secret)
            except Exception:
                raise CredentialError("credential_store_unavailable") from None
        elif self._recorded == "file":
            self._delete_from("file")
        self._recorded = location
        return location

    def _delete_from(self, location: CredentialLocation) -> bool:
        try:
            store = self._store_for(location)
            if store.get_password(SERVER_CREDENTIAL_SERVICE, self._target_id) is None:
                return False
            store.delete_password(SERVER_CREDENTIAL_SERVICE, self._target_id)
        except CredentialError:
            return False
        except Exception:
            raise CredentialError("credential_store_unavailable") from None
        return True

    def delete(self) -> bool:
        """Delete the key; True when one was deleted.

        The recorded location decides: when its store cannot be used, ``credential_store_unavailable``
        is raised and the key stays there; a recorded platform store that cannot even be loaded
        now (a Linux desktop reached over SSH, with no D-Bus session) is such a store. The other
        location is only tidied, best effort (a key an interrupted ``login`` left there): a store
        this target's key is not recorded in (a locked platform store an SSH target or a key file
        never used) never blocks the delete.
        """

        removed = False
        locations: tuple[CredentialLocation, ...] = ("keyring", "file")
        for location in locations:
            if location == "keyring" and self._platform_store() is None:
                if self._recorded == "keyring":
                    raise CredentialError("credential_store_unavailable")
                continue
            try:
                removed = self._delete_from(location) or removed
            except CredentialError:
                if location == self._recorded:
                    raise
        self._recorded = None
        return removed
