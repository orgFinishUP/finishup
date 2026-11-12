"""The helper's owner-only records: status generations, the stamped lock, style, reaping (ADR-052)."""

from __future__ import annotations

import os
import signal
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

import finishup.client.helper_status as helper_status
from builders.server_targets import ambient_home
from finishup.client.helper_status import (
    HelperLock,
    HelperLockBusy,
    HelperStatus,
    helper_environment,
    helper_holder,
    new_status,
    read_connection_style,
    read_helper_status,
    request_profile_refresh,
    spawn_helper,
    stop_helper,
    take_profile_refresh_request,
    write_connection_style,
    write_helper_status,
)

_STARTED = "2026-11-09T12:00:00.000Z"
_DIGEST = "sha256:" + "a" * 64


@pytest.fixture
def root(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as home:
        target = home / "t_0000000a"
        target.mkdir(mode=0o700)
        (target / "state").mkdir(mode=0o700)
        (target / "config").mkdir(mode=0o700)
        yield target


def test_status_round_trips_and_moves_its_generation_only_on_a_change(root: Path) -> None:
    first = new_status(None, "starting", None, started_at=_STARTED, style="direct")
    assert first.generation == 1
    write_helper_status(root, first)
    assert read_helper_status(root) == first
    same = new_status(first, "starting", None, started_at=_STARTED)
    assert same.generation == 1
    ready = new_status(first, "ready", None, started_at=_STARTED)
    down = new_status(ready, "unavailable", "remote_unreachable", started_at=_STARTED)
    again = new_status(down, "unavailable", "remote_unreachable", started_at=_STARTED)
    lapsed = new_status(again, "unavailable", "server_authorization_changed", started_at=_STARTED)
    repaired = new_status(lapsed, "ready", None, started_at=_STARTED)
    assert [x.generation for x in (ready, down, again, lapsed, repaired)] == [2, 3, 3, 4, 5]
    assert (root / "state" / "helper-status.json").stat().st_mode & 0o777 == 0o600


def test_a_new_process_continues_the_roots_sequence() -> None:
    previous = HelperStatus(7, "stopped", "idle_timeout", None, 1, _STARTED)
    assert previous.pid != os.getpid()
    assert new_status(previous, "starting", None, started_at=_STARTED).generation == 8


@pytest.mark.parametrize(
    ("phase", "reason", "style"),
    [
        ("ready", "remote_unreachable", "relay"),
        ("unavailable", None, "relay"),
        ("unavailable", "lab.example unreachable", "relay"),
        ("stopped", "remote_unreachable", "relay"),
        ("listening", None, "relay"),
        ("ready", None, "tunnel"),
    ],
)
def test_status_holds_closed_tokens_only(phase: str, reason: str | None, style: str) -> None:
    with pytest.raises(ValueError, match="helper_status_invalid"):
        HelperStatus(1, phase, reason, None, os.getpid(), _STARTED, style)  # type: ignore[arg-type]


def test_an_unsafe_or_damaged_status_reads_as_none(root: Path) -> None:
    write_helper_status(root, new_status(None, "ready", None, started_at=_STARTED))
    path = root / "state" / "helper-status.json"
    path.chmod(0o644)
    assert read_helper_status(root) is None
    path.chmod(0o600)
    path.write_bytes(b'{"schema":"yoetz.helper-status/1"}\n')
    assert read_helper_status(root) is None
    path.unlink()
    os.mkfifo(path, 0o600)
    # A special file never blocks the read (a hook reads this record).
    assert read_helper_status(root) is None
    path.unlink()
    assert read_helper_status(root) is None


def test_a_status_is_never_written_where_the_target_folder_was_removed(root: Path) -> None:
    """A-REMOVE-RACE: a helper still ending never makes a removed target's folder again."""

    import shutil

    shutil.rmtree(root)
    with pytest.raises(OSError):
        write_helper_status(
            root, new_status(None, "stopped", "stop_requested", started_at=_STARTED)
        )
    with pytest.raises(OSError):
        spawn_helper(root, "t_0000000a")
    request_profile_refresh(root)
    assert not root.exists()


def test_the_lock_is_a_stamped_singleton(root: Path) -> None:
    lock = HelperLock(root)
    lock.acquire(version="0.1.0", schema_manifest_digest=_DIGEST)
    try:
        holder = helper_holder(root)
        assert holder is not None
        assert (holder.pid, holder.version, holder.schema_manifest_digest) == (
            os.getpid(),
            "0.1.0",
            _DIGEST,
        )
        with pytest.raises(HelperLockBusy):
            HelperLock(root).acquire(version="0.1.0", schema_manifest_digest=_DIGEST)
        lock.assert_held()
    finally:
        lock.release()
    assert helper_holder(root) is None
    with pytest.raises(RuntimeError):
        lock.assert_held()
    assert stop_helper(root) is True


def test_the_style_is_relay_unless_the_owner_chose_direct(root: Path) -> None:
    assert read_connection_style(root) == "relay"
    write_connection_style(root, "direct")
    assert read_connection_style(root) == "direct"
    path = root / "config" / "connection-style.json"
    assert path.stat().st_mode & 0o777 == 0o600
    path.chmod(0o644)
    # A record that is not owner-only is never trusted: the default style.
    assert read_connection_style(root) == "relay"
    path.chmod(0o600)
    path.write_bytes(b'{"schema":"yoetz.connection-style/1","style":"tunnel"}\n')
    assert read_connection_style(root) == "relay"
    write_connection_style(root, "relay")
    assert read_connection_style(root) == "relay"
    with pytest.raises(ValueError, match="connection_style_invalid"):
        write_connection_style(root, "tunnel")  # type: ignore[arg-type]


def test_the_refresh_marker_is_left_and_taken_once(root: Path) -> None:
    assert take_profile_refresh_request(root) is False
    request_profile_refresh(root)
    request_profile_refresh(root)
    marker = root / "state" / "profile-refresh-requested"
    assert marker.stat().st_mode & 0o777 == 0o600
    assert take_profile_refresh_request(root) is True
    assert take_profile_refresh_request(root) is False


def test_the_environment_carries_no_product_variable_or_secret(
    monkeypatch: pytest.MonkeyPatch, root: Path
) -> None:
    monkeypatch.setenv("FINISHUP_ISOLATED_ROOT", "/elsewhere")
    monkeypatch.setenv("YOETZ_ISOLATED_ROOT", "/elsewhere")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/run/agent.sock")
    environment = helper_environment()
    assert environment.get("SSH_AUTH_SOCK") == "/run/agent.sock"
    assert not {"FINISHUP_ISOLATED_ROOT", "YOETZ_ISOLATED_ROOT", "OPENAI_API_KEY"} & set(
        environment
    )
    # The XDG base directories travel so the helper resolves its client's registry.
    assert environment.get("XDG_STATE_HOME") == os.environ["XDG_STATE_HOME"]


def _process_state(pid: int) -> str | None:
    """The kernel's one-letter state of ``pid`` (``Z`` for a zombie), ``None`` once it is gone."""

    try:
        facts = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return None
    return facts.rsplit(")", 1)[1].split()[0]


@pytest.mark.skipif(not Path("/proc/self/stat").exists(), reason="reads the kernel's /proc")
def test_a_spawned_helper_that_another_process_stops_is_reaped_at_once(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RE-3: a bridge's helper stopped by a switch or zero-network never stays <defunct>.

    The spawning process drops the handle, as every caller does, and keeps running; the stop comes
    from elsewhere (here the test signals the one pid it spawned, as ``stop_helper`` signals the
    stamped one). The child must be reaped while this process lives, not when it exits.
    """

    def paused(_target_id: str, _epoch: str) -> tuple[str, ...]:
        return (sys.executable, "-c", "import signal; signal.pause()")

    monkeypatch.setattr(helper_status, "_helper_command", paused)
    process = spawn_helper(root, "t_0000000a")
    pid = process.pid
    del process
    assert _process_state(pid) not in {None, "Z"}
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 10.0
    state = _process_state(pid)
    while state is not None and time.monotonic() < deadline:
        # Bounded, observing the kernel's own record: the reaper thread runs ``waitpid`` on it.
        time.sleep(0.01)
        state = _process_state(pid)
    assert state is None, f"helper child left in state {state}"


def _hold_lock_stamped(root: Path, stamp: bytes) -> int:
    """Hold ``root``'s helper lock from this process with ``stamp`` as its content."""

    import fcntl

    descriptor = os.open(root / "state" / "helper.lock", os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.ftruncate(descriptor, 0)
    os.write(descriptor, stamp)
    return descriptor


def test_a_stop_never_signals_the_pid_a_stamp_names(root: Path) -> None:
    """A3: the stamped pid may belong to another process once the helper exited (pid reuse)."""

    import fcntl
    import json
    import subprocess

    from finishup.client.helper_status import read_helper_epoch

    # Another process of this user, which now has the pid an exited helper stamped.
    bystander = subprocess.Popen(  # noqa: S603 - this interpreter, fixed source
        (sys.executable, "-c", "import signal; signal.pause()")
    )
    stamp = {"pid": bystander.pid, "version": "0.1.0", "schema_manifest_digest": _DIGEST}
    descriptor = _hold_lock_stamped(root, json.dumps(stamp).encode() + b"\n")
    try:
        assert helper_holder(root) is not None
        before = read_helper_epoch(root)
        assert stop_helper(root, timeout_seconds=0.2) is False
        # The lock is still held, so the stop is not reported done; the stop was asked for
        # through the epoch, and the bystander was never signalled.
        assert read_helper_epoch(root) != before
        assert bystander.poll() is None
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
        # Stopped by the one pid this test started.
        bystander.terminate()
        bystander.wait(timeout=10)
    assert stop_helper(root, timeout_seconds=0.2) is True


def test_a_lock_held_under_an_unreadable_stamp_is_never_reported_stopped(root: Path) -> None:
    """A2: success means the lock was seen free, whatever its stamp says."""

    import fcntl

    descriptor = _hold_lock_stamped(root, b"not a stamp\n")
    try:
        assert helper_holder(root) is None
        assert stop_helper(root, timeout_seconds=0.2) is False
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
    assert stop_helper(root, timeout_seconds=0.2) is True


def test_a_spawned_helper_carries_the_epoch_its_spawner_read(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A2: the epoch read at spawn travels as ``--epoch``; every stop moves it."""

    from finishup.client.helper_status import read_helper_epoch, start_fenced

    seen: list[tuple[str, str]] = []
    original = helper_status._helper_command  # pyright: ignore[reportPrivateUsage]

    def command(target_id: str, epoch: str) -> tuple[str, ...]:
        seen.append((target_id, epoch))
        return (sys.executable, "-c", "pass")

    monkeypatch.setattr(helper_status, "_helper_command", command)
    assert read_helper_epoch(root) == "none"
    spawn_helper(root, "t_0000000a").wait(timeout=10)
    assert stop_helper(root, timeout_seconds=1.0) is True
    moved = read_helper_epoch(root)
    assert moved != "none" and len(moved) == 32
    spawn_helper(root, "t_0000000a").wait(timeout=10)
    assert seen == [("t_0000000a", "none"), ("t_0000000a", moved)]
    # The first spawn's helper, starting only now, is fenced; the second's is not; one started
    # by hand (no epoch) never is.
    assert start_fenced(root, "none") and not start_fenced(root, moved)
    assert not start_fenced(root, None)
    assert original("t_0000000a", moved)[-4:] == ("--target", "t_0000000a", "--epoch", moved)


def test_a_spawn_carries_the_epoch_its_caller_read_before_a_stop(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A client passes the epoch it read before its dial: a stop since then fences the helper."""

    from finishup.client.helper_status import read_helper_epoch, start_fenced

    seen: list[str] = []

    def command(_target_id: str, epoch: str) -> tuple[str, ...]:
        seen.append(epoch)
        return (sys.executable, "-c", "pass")

    monkeypatch.setattr(helper_status, "_helper_command", command)
    before = read_helper_epoch(root)
    assert stop_helper(root, timeout_seconds=1.0) is True
    spawn_helper(root, "t_0000000a", epoch=before).wait(timeout=10)
    assert seen == [before]
    assert start_fenced(root, before)


def _stamp_of(root: Path) -> helper_status.HelperStamp:
    holder = helper_holder(root)
    assert holder is not None
    return holder


def test_a_supersede_stops_exactly_the_holder_it_decided_about(root: Path) -> None:
    """Finding 3: the replacement is fenced to the holder identity it read. Another holder now
    (a newer helper that took the target meanwhile) is never stopped: nothing moves and the
    caller decides again. The holder decided about is stopped through the epoch, and the epoch
    this stop wrote is returned once the lock is free (the successor is spawned with it)."""

    import fcntl
    import json

    from finishup.client.helper_status import (
        HelperHolderChanged,
        read_helper_epoch,
        supersede_helper,
    )

    older = {"pid": os.getpid(), "version": "0.1.0", "schema_manifest_digest": _DIGEST}
    descriptor = _hold_lock_stamped(root, json.dumps(older).encode() + b"\n")
    decided = _stamp_of(root)
    # Another helper holds the target now (here the same pid, another build).
    os.ftruncate(descriptor, 0)
    os.lseek(descriptor, 0, os.SEEK_SET)
    newer = {**older, "schema_manifest_digest": "sha256:" + "b" * 64}
    os.write(descriptor, json.dumps(newer).encode() + b"\n")
    before = read_helper_epoch(root)
    try:
        with pytest.raises(HelperHolderChanged):
            supersede_helper(root, decided, timeout_seconds=0.2)
        assert read_helper_epoch(root) == before
        # The holder decided about: the stop is asked for; its lock is still held at the bound.
        assert supersede_helper(root, _stamp_of(root), timeout_seconds=0.2) is None
        assert read_helper_epoch(root) != before
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
    # Nothing holds it now: a supersede of a holder that ended is a changed holder, too.
    with pytest.raises(HelperHolderChanged):
        supersede_helper(root, decided, timeout_seconds=0.2)


def test_a_supersede_returns_the_epoch_it_wrote_once_the_lock_is_free(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.client.helper_status import read_helper_epoch, supersede_helper

    stamp = helper_status.HelperStamp(os.getpid(), "0.1.0", _DIGEST)
    lock = HelperLock(root)
    lock.acquire(version=stamp.version, schema_manifest_digest=stamp.schema_manifest_digest)
    original = helper_status._move_helper_epoch  # pyright: ignore[reportPrivateUsage]

    def move_and_exit(path: Path) -> str | None:
        token = original(path)
        lock.release()  # the helper reads the moved epoch on its tick and exits
        return token

    monkeypatch.setattr(helper_status, "_move_helper_epoch", move_and_exit)
    written = supersede_helper(root, stamp, timeout_seconds=1.0)
    assert written is not None and written == read_helper_epoch(root)


def test_a_supersede_waits_for_the_fence_within_its_bound_and_moves_nothing_past_it(
    root: Path,
) -> None:
    """While a helper is taking the lock (it holds the fence), a supersede does not decide; past
    its bound it gives up without moving the epoch."""

    from finishup.client.helper_status import (
        helper_start_fence,
        read_helper_epoch,
        supersede_helper,
    )

    stamp = helper_status.HelperStamp(os.getpid(), "0.1.0", _DIGEST)
    lock = HelperLock(root)
    lock.acquire(version=stamp.version, schema_manifest_digest=stamp.schema_manifest_digest)
    before = read_helper_epoch(root)
    try:
        with helper_start_fence(root):
            assert supersede_helper(root, stamp, timeout_seconds=0.2) is None
        assert read_helper_epoch(root) == before
        assert (root / "state" / "helper-epoch.lock").stat().st_mode & 0o777 == 0o600
    finally:
        lock.release()


def test_the_lock_is_seen_held_before_its_stamp_is_readable(root: Path) -> None:
    import fcntl

    from finishup.client.helper_status import helper_lock_held

    assert helper_lock_held(root) is False
    descriptor = _hold_lock_stamped(root, b"")
    try:
        assert helper_holder(root) is None
        assert helper_lock_held(root) is True
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
    assert helper_lock_held(root) is False


def test_the_refresh_marker_names_the_refused_revision_and_an_empty_one_names_none(
    root: Path,
) -> None:
    """A refused client names the revision its hello named (macOS dogfood), so the helper can
    tell a cache that is stale for sure; an older client's empty marker, or content that cannot be
    read, is still a request, naming none."""

    from builders.server_profiles import TEST_REVISION
    from finishup.client.helper_status import (
        ProfileRefreshRequest,
        take_named_profile_refresh_request,
    )

    marker = root / "state" / "profile-refresh-requested"
    assert take_named_profile_refresh_request(root) is None
    request_profile_refresh(root, TEST_REVISION)
    assert marker.stat().st_mode & 0o777 == 0o600
    assert take_named_profile_refresh_request(root) == ProfileRefreshRequest(TEST_REVISION)
    assert take_named_profile_refresh_request(root) is None
    request_profile_refresh(root)
    assert take_named_profile_refresh_request(root) == ProfileRefreshRequest(None)
    marker.write_bytes(b'{"schema":"yoetz.profile-refresh-request/1","server_profile":{}}\n')
    marker.chmod(0o600)
    assert take_named_profile_refresh_request(root) == ProfileRefreshRequest(None)
    request_profile_refresh(root, TEST_REVISION)
    assert take_profile_refresh_request(root) is True
