"""No test reaches a platform credential store (``tests/credential_store_guard.py``).

On macOS a test that let keyring discover the login keychain stored a test target's API key there,
and under a private ``HOME`` each store showed a dialog. The suite pins keyring to its fail
backend for this process and every child that inherits the environment, and a tripwire fails a
test that leaves a platform store in keyring's process-wide cache.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import keyring
import keyring.core
import pytest
from keyring.backends import SecretService, Windows, chainer, fail, kwallet, libsecret, macOS, null
from tests.subprocess.helpers.child import (
    _minimal_environment,  # pyright: ignore[reportPrivateUsage]
)

from credential_store_guard import (
    FAIL_BACKEND,
    cached_platform_stores,
    forget_cached_backend,
    platform_stores_in,
)
from finishup.client import credentials

# A fresh interpreter reports which backend keyring loads from its environment, and which it uses.
_CHILD_PROBE = (
    "import json, keyring, keyring.core\n"
    "def name(backend):\n"
    "    return None if backend is None else "
    "f'{type(backend).__module__}.{type(backend).__qualname__}'\n"
    "print(json.dumps([name(keyring.core.load_env()), name(keyring.get_keyring())]))\n"
)


def _name(backend: object) -> str:
    return f"{type(backend).__module__}.{type(backend).__qualname__}"


def _child_backends(environment: dict[str, str], cwd: Path) -> list[str | None]:
    completed = subprocess.run(  # noqa: S603 - this interpreter, a fixed probe, no shell
        [sys.executable, "-I", "-c", _CHILD_PROBE],
        env=environment,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    return json.loads(completed.stdout)


def test_this_process_loads_only_keyring_fail_backend() -> None:
    assert os.environ["PYTHON_KEYRING_BACKEND"] == FAIL_BACKEND
    # Chosen by the environment, not found by searching this machine for a store.
    assert _name(keyring.core.load_env()) == FAIL_BACKEND
    assert _name(keyring.get_keyring()) == FAIL_BACKEND
    assert credentials._platform_backend() is None  # pyright: ignore[reportPrivateUsage]


def test_a_child_that_inherits_the_environment_loads_only_the_fail_backend(
    tmp_path: Path,
) -> None:
    assert _child_backends(dict(os.environ), tmp_path) == [FAIL_BACKEND, FAIL_BACKEND]


def test_a_child_given_the_minimal_test_environment_loads_only_the_fail_backend(
    tmp_path: Path,
) -> None:
    """The subprocess harness builds a child environment from scratch, so it adds the pin."""

    environment = _minimal_environment(tmp_path, {"PATH": os.environ.get("PATH", os.defpath)})
    assert environment["PYTHON_KEYRING_BACKEND"] == FAIL_BACKEND
    assert _child_backends(environment, tmp_path) == [FAIL_BACKEND, FAIL_BACKEND]


@pytest.mark.parametrize(
    "backend",
    [
        macOS.Keyring,
        Windows.WinVaultKeyring,
        SecretService.Keyring,
        libsecret.Keyring,
        kwallet.DBusKeyring,
    ],
)
def test_the_tripwire_names_every_platform_store(backend: type[object]) -> None:
    # Constructing a backend asks its store nothing; only its methods do.
    instance = backend()
    assert platform_stores_in(instance) == (_name(instance),)


def test_the_tripwire_ignores_the_stores_that_reach_nothing() -> None:
    assert platform_stores_in(fail.Keyring()) == ()
    assert platform_stores_in(null.Keyring()) == ()
    assert platform_stores_in(object()) == ()


def test_the_tripwire_looks_inside_a_chainer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(chainer.ChainerBackend, "backends", [fail.Keyring(), macOS.Keyring()])
    assert platform_stores_in(chainer.ChainerBackend()) == ("keyring.backends.macOS.Keyring",)
    monkeypatch.setattr(chainer.ChainerBackend, "backends", [fail.Keyring(), null.Keyring()])
    assert platform_stores_in(chainer.ChainerBackend()) == ()


def test_the_tripwire_reads_keyring_cache_and_forgets_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(keyring.core, "_keyring_backend", macOS.Keyring())
    assert cached_platform_stores() == ("keyring.backends.macOS.Keyring",)
    forget_cached_backend()
    assert cached_platform_stores() == ()
    # The next use loads the backend the environment names, never a platform store.
    assert _name(keyring.get_keyring()) == FAIL_BACKEND
