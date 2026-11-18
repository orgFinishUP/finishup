"""An owner-only ambient home for server-target tests (ADR-051).

Target roots live beneath the ambient state directory and the selection in the ambient config
directory, so each test gets its own owner-only home outside shared temp (the runtime refuses a
root under ``/tmp``), with every isolation-root variable unset and the selection memo reset.

A target root's longest endpoint must fit the ``sun_path`` bound the runtime enforces
(``target_root_too_long``). CI isolates ``$HOME`` beneath a long job temp directory, where a root
named after it may not fit; the home is then the account's own passwd home, which is as private.

This release registers no runtime for a remote kind (``ssh``, ``https``, ``local_port``): they are
closed. ``remote_runtime`` registers a stand-in for them, for one test, where a test exercises the
shared seams a later layer's runtime fills (a probe, a stop, a connect).
"""

from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Callable, Generator
from contextlib import contextmanager
from pathlib import Path

import pytest

from finishup.client import target_runtime, targets
from finishup.client.target_runtime import ProbeResult, TargetRuntime
from finishup.client.targets import ServerTarget
from finishup.config.installation import instance_root_fits
from finishup.config.paths import ISOLATED_ROOT_ENV_NAMES, reset_selection_memo

__all__ = [
    "StandInRuntime",
    "ambient_home",
    "open_remote_kinds",
    "record_remote_target",
    "remote_runtime",
    "short_home_base",
]

_PREFIX = ".yz-target-test-"
# The deepest root a test makes, ``<home>/<prefix><8 random>/state/finishup/servers/t_<8 hex>``:
# a ``local`` target's, held to the runtime's own instance bound, the strictest a target meets.
_DEEPEST_ROOT = Path("state", "finishup", "servers", "t_00000000")


def _fits(base: Path) -> bool:
    return instance_root_fits(base / f"{_PREFIX}00000000" / _DEEPEST_ROOT)


def short_home_base() -> Path:
    """``$HOME``, or the account's passwd home when an isolated ``$HOME`` is too long.

    Whichever is chosen holds a test's deepest target root within the runtime's socket bound.
    """

    candidates = [Path.home()]
    try:
        import pwd

        candidates.append(Path(pwd.getpwuid(os.getuid()).pw_dir))
    except (ImportError, KeyError):
        pass
    for base in candidates:
        if base.is_dir() and _fits(base):
            return base
    raise RuntimeError("no home directory is short enough for a server-target test root")


@contextmanager
def ambient_home(monkeypatch: pytest.MonkeyPatch) -> Generator[Path]:
    root = Path(tempfile.mkdtemp(prefix=_PREFIX, dir=short_home_base()))
    root.chmod(0o700)
    for name in ISOLATED_ROOT_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    for variable, leaf in (
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_STATE_HOME", "state"),
        ("XDG_DATA_HOME", "data"),
        ("XDG_CACHE_HOME", "cache"),
        ("XDG_RUNTIME_DIR", "run"),
    ):
        (root / leaf).mkdir(mode=0o700)
        monkeypatch.setenv(variable, str(root / leaf))
    reset_selection_memo()
    try:
        yield root
    finally:
        reset_selection_memo()
        shutil.rmtree(root, ignore_errors=True)


class StandInRuntime:
    """A runtime registered for the remote kinds by ``remote_runtime``; records every call.

    ``probe_result`` is what each probe answers; ``ready_error`` and ``stop_error``, when set,
    are raised by ``ensure_ready`` and ``stop``; ``new_connection_times`` is what
    ``time_new_connections`` answers (``new_connection_error``, when set, is raised instead).
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, Path | None]] = []
        self.probe_result = ProbeResult("unavailable", reason="remote_unreachable")
        self.ready_error: Exception | None = None
        self.stop_error: Exception | None = None
        self.new_connection_times: tuple[int, ...] = (40, 40, 40, 40, 40)
        self.new_connection_error: Exception | None = None

    def ensure_ready(self, root: Path | None) -> None:
        self.calls.append(("ensure_ready", root))
        if self.ready_error is not None:
            raise self.ready_error

    def stop(self, root: Path | None) -> None:
        self.calls.append(("stop", root))
        if self.stop_error is not None:
            raise self.stop_error

    def probe(self, root: Path | None) -> ProbeResult:
        self.calls.append(("probe", root))
        return self.probe_result

    def time_new_connections(self, root: Path | None, count: int) -> tuple[int, ...]:
        self.calls.append(("time_new_connections", root))
        if self.new_connection_error is not None:
            raise self.new_connection_error
        return self.new_connection_times[:count]

    @property
    def stops(self) -> list[Path | None]:
        return [root for call, root in self.calls if call == "stop"]


def remote_runtime(monkeypatch: pytest.MonkeyPatch) -> StandInRuntime:
    """Register one ``StandInRuntime`` for every remote kind, for this test only."""

    runtime = StandInRuntime()

    def load() -> TargetRuntime:
        return runtime

    loaders: dict[str, Callable[[], TargetRuntime]] = dict(
        target_runtime._RUNTIME_LOADERS  # pyright: ignore[reportPrivateUsage]
    )
    for kind in ("ssh", "https", "local_port"):
        loaders[kind] = load
    monkeypatch.setattr(target_runtime, "_RUNTIME_LOADERS", loaders)
    return runtime


def record_remote_target(name: str = "elsewhere") -> ServerTarget:
    """Record one server elsewhere (an ``https`` target) without selecting it.

    Its record alone switches the repository hold's reads and records on (ADR-052, the owner's
    answer O3); call it inside ``ambient_home``.
    """

    with targets.registry_lock():
        record, _root = targets.new_remote_target(
            name, "https", base_url="https://finishup.example"
        )
    return record


def _refuse_spawn(_root: Path, _target_id: str, *, epoch: str | None = None) -> object:
    del epoch
    raise PermissionError("helper_not_spawned_in_unit_tests")


def open_remote_kinds(
    monkeypatch: pytest.MonkeyPatch, *kinds: str, consent: bool = True, rest: bool = False
) -> None:
    """Open ``kinds`` to connections, in this process and for this test only.

    This release opens no remote kind (``client.authorization.OPEN_REMOTE_KINDS`` is empty, and an
    architecture test keeps it so); a test that exercises an admitted connection opens one here.

    ``rest`` keeps HTTPS and port targets on their REST transports (layer 5); without it they dial
    the target root's own endpoint in process, as the tests of layers 2 to 4 do.

    With ``consent`` (the default) every remote target recorded now or later in the test is
    consented to the default test profile (``builders.server_profiles``), as ``finishup server
    add`` records it after the owner's typed confirmation, so the gate's consent step (ADR-052)
    admits it with real records. A test of the consent itself passes ``consent=False``.
    """

    from finishup.client import authorization, helper_status
    from finishup.service import client as service_client

    assert set(kinds) <= targets.REMOTE_KINDS
    monkeypatch.setattr(authorization, "OPEN_REMOTE_KINDS", frozenset(kinds))
    if not rest:
        # An HTTPS or port target opened in process without a REST server dials the target
        # root's own endpoint, as before layer 5; a REST test passes ``rest=True``.
        monkeypatch.setattr(service_client, "_REST_KINDS", frozenset[str]())
    # A unit test never starts a real helper process (ADR-052): a client that would start one is
    # told it could not, unless the test stands in for the helper itself.
    monkeypatch.setattr(helper_status, "spawn_helper", _refuse_spawn)
    if not consent:
        return
    from builders.server_profiles import consent_to

    for record in targets.list_targets():
        if record.is_remote and record.consent is None:
            consent_to(record)
    original = targets.new_remote_target

    def consented(*args: object, **kwargs: object) -> tuple[ServerTarget, Path]:
        # Callers hold the registry lock around ``new_remote_target``, as ``server add`` does.
        record, root = original(*args, **kwargs)  # pyright: ignore[reportArgumentType]
        return consent_to(record, lock=False), root

    monkeypatch.setattr(targets, "new_remote_target", consented)
