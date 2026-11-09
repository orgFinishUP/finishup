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

    def paused(_target_id: str) -> tuple[str, ...]:
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
