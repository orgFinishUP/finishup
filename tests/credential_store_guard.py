"""No test reaches a platform credential store: keyring's fail backend, and a tripwire.

A platform store (the macOS keychain, Windows Credential Manager, a Freedesktop Secret Service or
KWallet) holds the developer's own keys. A test that let ``keyring`` discover one stored a test
target's API key in the login keychain, and on macOS under a private ``HOME`` each store showed a
dialog ("A keychain cannot be found to store ..."). Linux CI has no platform store, so it never
showed there.

``tests/conftest.py`` points ``PYTHON_KEYRING_BACKEND`` at keyring's fail backend before any
test runs, which every child process that inherits the environment follows too; a helper that
builds a child environment from scratch adds ``NO_PLATFORM_CREDENTIAL_STORE``. A test that
exercises the choice of a store injects a stand-in (``platform=`` objects, or a patched
``finishup.client.credentials._platform_backend``) instead. After each test the conftest fails
the test whose run left a platform store in keyring's process-wide cache.

Standard library only: the portable console-boundary job imports the root conftest without the
project's dependencies.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

__all__ = [
    "FAIL_BACKEND",
    "NO_PLATFORM_CREDENTIAL_STORE",
    "cached_platform_stores",
    "forget_cached_backend",
    "pin_fail_backend",
    "platform_stores_in",
]

FAIL_BACKEND: Final = "keyring.backends.fail.Keyring"
NO_PLATFORM_CREDENTIAL_STORE: Final[Mapping[str, str]] = MappingProxyType(
    {"PYTHON_KEYRING_BACKEND": FAIL_BACKEND}
)
# Every keyring module that reaches an operating-system store; any class in one counts.
_PLATFORM_MODULES: Final = frozenset(
    {
        "keyring.backends.SecretService",
        "keyring.backends.Windows",
        "keyring.backends.kwallet",
        "keyring.backends.libsecret",
        "keyring.backends.macOS",
    }
)
_CHAINER: Final = "keyring.backends.chainer.ChainerBackend"


def _class_name(backend: object) -> str:
    return f"{type(backend).__module__}.{type(backend).__qualname__}"


def platform_stores_in(backend: object) -> tuple[str, ...]:
    """The platform store classes ``backend`` is, or (a chainer) holds; empty when none."""

    name = _class_name(backend)
    if name == _CHAINER:
        members: tuple[object, ...] = tuple(getattr(backend, "backends", ()))
        return tuple(found for member in members for found in platform_stores_in(member))
    return (name,) if type(backend).__module__ in _PLATFORM_MODULES else ()


def cached_platform_stores() -> tuple[str, ...]:
    """The platform stores in keyring's process-wide cache; never imports or loads keyring."""

    core = sys.modules.get("keyring.core")
    loaded: object = getattr(core, "_keyring_backend", None)
    return () if loaded is None else platform_stores_in(loaded)


def forget_cached_backend() -> None:
    """Drop keyring's cached backend, so the next use loads the one the environment names."""

    core = sys.modules.get("keyring.core")
    if core is not None:
        core._keyring_backend = None  # pyright: ignore[reportAttributeAccessIssue]


def pin_fail_backend() -> None:
    """Make keyring load its fail backend in this process and every child that inherits it."""

    os.environ.update(NO_PLATFORM_CREDENTIAL_STORE)
    forget_cached_backend()
