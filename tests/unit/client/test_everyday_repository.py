"""Asking this computer's everyday FinishUP about one repository's own policy (ADR-051 decision 8).

Maintainer decision of 2026-11-07, round 4. The live read connects to the running everyday
service (never on demand), records the machine-scope marker and the repository's report, and
records nothing it cannot tell apart: a forbidding composition while the machine row forbids too
is forgotten, and a read that fails records nothing. A setup view the service already gave a
client command is remembered without asking again. A session start asks only when the report is
missing or stale, on the everyday root or while a server elsewhere is selected.
"""

from __future__ import annotations

import asyncio
import math
import os
import subprocess
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import finishup.client.everyday_repository as everyday_repository
from builders.server_targets import ambient_home, record_remote_target
from finishup.client import targets
from finishup.client.everyday_policy import (
    ReportedPolicy,
    read_marker,
    read_repository_reports,
    record_reported_policy,
    record_repository_report,
    reports_path,
    repository_report,
)
from finishup.client.everyday_repository import (
    EverydayReads,
    classify_setup,
    read_everyday_repository,
    refresh_at_session_start,
    remember_repository_setup,
    report_needs_refresh,
    repository_key_for,
)
from finishup.config.paths import reset_selection_memo
from finishup.ports.control import ControlClientKind, ControlError, WorkspaceLocator

_AT = datetime(2026, 11, 7, 9, 30, tzinfo=UTC)
_STAMP = "2026-11-07T09:30:00.000Z"


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


def _git(*arguments: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=T", "-c", "user.email=t@finishup.invalid", *arguments],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"},
    )


@pytest.fixture
def elsewhere(home: Path) -> None:
    """A server elsewhere is recorded (not selected): the hold's reads are switched on (O3)."""

    record_remote_target()


@pytest.fixture
def repository(tmp_path: Path) -> str:
    path = tmp_path / "repository"
    path.mkdir()
    _git("-C", os.fspath(path), "init")
    return os.fspath(path.resolve())


def _setup(grant_state: str, permitted: bool) -> dict[str, object]:
    return {
        "schema_version": "2.0.0",
        "grant_state": grant_state,
        "composed_policy": {"network_egress_permitted": permitted},
    }


class _Client:
    def __init__(self, machine: bool, setup: object, calls: list[str]) -> None:
        self._machine = machine
        self._setup = setup
        self._calls = calls

    async def privacy_get_effective(self, request: object) -> object:
        self._calls.append("effective")
        return {"policy": {"network_egress_permitted": self._machine}}

    async def privacy_get_setup(self, request: object) -> object:
        self._calls.append("setup")
        return self._setup

    async def close(self) -> None:
        self._calls.append("close")


def _connector(
    machine: bool, setup: object, calls: list[str], *, fail: Exception | None = None
) -> object:
    async def connect(kind: ControlClientKind, *, workspace_locator: WorkspaceLocator) -> object:
        calls.append(f"connect:{kind.value}:{workspace_locator.path}")
        if fail is not None:
            raise fail
        return _Client(machine, setup, calls)

    return connect


def _read(locator: str, connect: object, **changes: object) -> EverydayReads:
    async def run() -> EverydayReads:
        return await read_everyday_repository(
            locator,
            connect=connect,  # type: ignore[arg-type]
            installation_exists=lambda: True,
            machine_request=lambda: {"scope": "machine"},  # type: ignore[arg-type, return-value]
            now=_AT,
            **changes,  # type: ignore[arg-type]
        )

    return asyncio.run(run())


def _key(locator: str) -> str:
    key = asyncio.run(repository_key_for(locator))
    assert key is not None
    return key


def test_a_granted_forbidding_repository_is_recorded_as_allowing_no_network_use(
    home: Path, elsewhere: None, repository: str
) -> None:
    calls: list[str] = []
    reads = _read(repository, _connector(True, _setup("granted", False), calls))
    assert reads == EverydayReads("network_permitted", "no_network")
    # One connection, bound to the repository's worktree, never on demand; always closed.
    assert calls == [f"connect:cli:{repository}", "effective", "setup", "close"]
    report = repository_report(_key(repository))
    assert report is not None and report.no_network and report.worktrees == (repository,)
    assert read_marker() == ReportedPolicy(False, _STAMP)


@pytest.mark.parametrize(
    "setup", [_setup("missing", False), _setup("missing", True), _setup("granted", True)]
)
def test_no_grant_or_a_permitting_grant_is_recorded_as_allowing_it(
    home: Path, elsewhere: None, repository: str, setup: dict[str, object]
) -> None:
    reads = _read(repository, _connector(True, setup, []))
    assert reads.repository == "network_permitted"
    report = repository_report(_key(repository))
    assert report is not None and report.no_network is False


def test_while_this_computer_forbids_all_network_use_the_entry_is_forgotten(
    home: Path, elsewhere: None, repository: str
) -> None:
    key = _key(repository)
    record_repository_report(key, repository, no_network=False, now=_AT)
    reads = _read(repository, _connector(False, _setup("granted", False), []))
    assert reads == EverydayReads("zero_network", "unreadable")
    # The grant cannot be told apart; the zero-network refusal governs, and the marker says so.
    assert repository_report(key) is None
    assert read_marker() == ReportedPolicy(True, _STAMP)


@pytest.mark.parametrize(
    "fail", [ControlError("service_unavailable", retryable=True), OSError("refused")]
)
def test_a_read_that_fails_records_nothing(home: Path, repository: str, fail: Exception) -> None:
    reads = _read(repository, _connector(True, None, [], fail=fail))
    assert reads == EverydayReads("unreadable", "unreadable")
    assert read_repository_reports() == "absent"
    assert read_marker() == "absent"


def test_a_slow_service_is_bounded_by_the_budget(home: Path, repository: str) -> None:
    async def slow(kind: ControlClientKind, *, workspace_locator: WorkspaceLocator) -> object:
        await asyncio.Event().wait()
        raise AssertionError("never answers")

    assert _read(repository, slow, budget_seconds=0.01).repository == "unreadable"
    assert read_repository_reports() == "absent"


def test_a_setup_view_that_cannot_be_classified_records_no_repository(
    home: Path, elsewhere: None, repository: str
) -> None:
    reads = _read(repository, _connector(True, {"grant_state": "granted"}, []))
    assert reads == EverydayReads("network_permitted", "unreadable")
    assert read_repository_reports() == "absent"
    assert classify_setup({"schema_version": "2.0.0", "grant_state": "odd"}) is None


def test_a_computer_never_set_up_has_no_policy_and_keeps_no_record(
    home: Path, elsewhere: None, repository: str
) -> None:
    record_reported_policy(zero_network=False, now=_AT)
    record_repository_report(_key(repository), repository, no_network=True, now=_AT)
    calls: list[str] = []

    async def run() -> EverydayReads:
        return await read_everyday_repository(
            repository,
            connect=_connector(True, None, calls),  # type: ignore[arg-type]
            installation_exists=lambda: False,
        )

    assert asyncio.run(run()) == EverydayReads("no_policy", "no_policy")
    assert calls == []
    assert read_marker() == "absent"
    assert read_repository_reports() == "absent"


def test_an_isolation_root_reads_and_records_nothing(
    home: Path, repository: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    isolated = home / "isolated"
    isolated.mkdir(mode=0o700)
    monkeypatch.setenv("FINISHUP_ISOLATED_ROOT", os.fspath(isolated))
    reset_selection_memo()
    calls: list[str] = []
    assert _read(repository, _connector(True, _setup("granted", False), calls)).repository == (
        "unreadable"
    )
    assert calls == []


def test_the_read_runs_against_the_everyday_installation_whatever_is_selected(
    home: Path, repository: str
) -> None:
    from finishup.config.paths import active_root

    with targets.registry_lock():
        record, _root = targets.new_remote_target(
            "web", "https", base_url="https://finishup.example"
        )
    targets.write_selection(record)
    roots: list[object] = []

    async def connect(kind: ControlClientKind, *, workspace_locator: WorkspaceLocator) -> object:
        roots.append(active_root())
        return _Client(True, _setup("granted", False), [])

    assert _read(repository, connect).repository == "no_network"
    # Inside the read this computer's own installation is used; outside it nothing changed.
    assert roots == [None]
    assert active_root() == targets.target_root(record.target_id)


# --- remembering a setup view a client command already received -------------------------------


def test_remembering_a_setup_view_on_the_everyday_root(
    home: Path, elsewhere: None, repository: str
) -> None:
    key = _key(repository)
    # No machine report yet: a forbidding grant cannot be told apart from the machine row.
    assert asyncio.run(remember_repository_setup(repository, _setup("granted", False))) is False
    assert repository_report(key) is None
    record_reported_policy(zero_network=False, now=_AT)
    assert asyncio.run(remember_repository_setup(repository, _setup("granted", False))) is True
    report = repository_report(key)
    assert report is not None and report.no_network
    assert asyncio.run(remember_repository_setup(repository, _setup("missing", True))) is True
    report = repository_report(key)
    assert report is not None and not report.no_network
    # While this computer last reported zero-network, a forbidding view forgets the entry.
    record_reported_policy(zero_network=True, now=_AT)
    assert asyncio.run(remember_repository_setup(repository, _setup("granted", False))) is True
    assert repository_report(key) is None


def test_a_setup_view_from_a_server_elsewhere_is_not_this_computers(
    home: Path, repository: str
) -> None:
    record_reported_policy(zero_network=False, now=_AT)
    with targets.registry_lock():
        record, _root = targets.new_remote_target(
            "web", "https", base_url="https://finishup.example"
        )
    targets.write_selection(record)
    reset_selection_memo()
    assert asyncio.run(remember_repository_setup(repository, _setup("granted", False))) is False
    assert read_repository_reports() == "absent"


# --- at session start ---------------------------------------------------------------------------


def test_a_report_is_refreshed_when_missing_old_or_older_than_the_machine_report(
    home: Path,
) -> None:
    key = "sha256:" + "a" * 64
    assert report_needs_refresh(key, now=_AT) is True
    record_repository_report(key, "/srv/app", no_network=True, now=_AT)
    assert report_needs_refresh(key, now=_AT + timedelta(minutes=1)) is False
    assert report_needs_refresh(key, now=_AT + timedelta(hours=25)) is True
    record_reported_policy(zero_network=False, now=_AT + timedelta(seconds=1))
    assert report_needs_refresh(key, now=_AT + timedelta(minutes=1)) is True


@pytest.fixture
def live(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, float]]:
    """The session start's live read, recorded; it reports the repository as forbidding."""

    asked: list[tuple[str, float]] = []

    async def read(
        locator: str, *, budget_seconds: float, lock_wait_seconds: float, key: str | None
    ) -> object:
        # The key the session start already derived is passed on, never derived again.
        assert key is not None and key == await repository_key_for(locator)
        # What is left of the half second (or the hook's budget) once the key was derived.
        asked.append((locator, math.ceil(budget_seconds * 10) / 10))
        # Now, not a fixed time: a report older than a day is asked about again.
        record_repository_report(key, locator, no_network=True)
        return EverydayReads("network_permitted", "no_network")

    monkeypatch.setattr(everyday_repository, "_live_read", read)
    return asked


def test_a_session_start_on_the_everyday_root_records_a_missing_report_once(
    home: Path, elsewhere: None, repository: str, live: list[tuple[str, float]]
) -> None:
    assert refresh_at_session_start(repository, budget_seconds=5.0) is True
    # Bounded to half a second whatever the hook has left.
    assert live == [(repository, 0.5)]
    assert refresh_at_session_start(repository, budget_seconds=5.0) is False
    assert len(live) == 1
    assert refresh_at_session_start(repository, budget_seconds=0.0) is False
    assert refresh_at_session_start(None, budget_seconds=5.0) is False


def test_a_session_start_with_a_server_elsewhere_asks_too_but_a_local_one_does_not(
    home: Path, repository: str, live: list[tuple[str, float]]
) -> None:
    with targets.registry_lock():
        local, _local_root = targets.new_local_target("work")
    targets.write_selection(local)
    reset_selection_memo()
    assert refresh_at_session_start(repository, budget_seconds=1.0) is False
    assert live == []
    with targets.registry_lock():
        remote, _remote_root = targets.new_remote_target(
            "lab", "ssh", user="owner", host="lab.example", port=22
        )
    targets.write_selection(remote)
    reset_selection_memo()
    assert refresh_at_session_start(repository, budget_seconds=0.2) is True
    assert live == [(repository, 0.2)]


def test_a_linked_worktree_of_a_reported_repository_is_recorded_without_asking(
    home: Path, elsewhere: None, repository: str, tmp_path: Path, live: list[tuple[str, float]]
) -> None:
    (Path(repository) / "f.txt").write_text("x\n", encoding="utf-8")
    _git("-C", repository, "add", "f.txt")
    _git("-C", repository, "commit", "-m", "one")
    linked = os.fspath((tmp_path / "linked").resolve())
    _git("-C", repository, "worktree", "add", linked, "-b", "other")
    assert refresh_at_session_start(repository, budget_seconds=1.0) is True
    assert refresh_at_session_start(linked, budget_seconds=1.0) is False
    assert len(live) == 1
    report = repository_report(_key(repository))
    assert report is not None and report.worktrees == (linked, repository)


def test_the_whole_session_start_pass_is_bounded_its_git_read_included(
    home: Path, repository: str, live: list[tuple[str, float]], monkeypatch: pytest.MonkeyPatch
) -> None:
    import threading

    async def never(_worktree: str) -> str | None:
        await asyncio.Event().wait()
        return None

    monkeypatch.setattr(everyday_repository, "repository_key_for", never)
    finished: list[bool] = []
    thread = threading.Thread(
        target=lambda: finished.append(refresh_at_session_start(repository, budget_seconds=0.05)),
        daemon=True,
    )
    thread.start()
    # A bounded wait on the pass itself: it ends by its own budget, long before this deadline.
    thread.join(timeout=10)
    assert finished == [False]
    assert live == []


# --- dormant until a server elsewhere is recorded (ADR-052, the owner's answer O3) -------------


def test_with_no_server_elsewhere_nothing_is_asked_or_recorded(
    home: Path, repository: str, live: list[tuple[str, float]]
) -> None:
    record_reported_policy(zero_network=False, now=_AT)
    assert targets.remote_target_recorded() is False
    assert refresh_at_session_start(repository, budget_seconds=5.0) is False
    assert asyncio.run(remember_repository_setup(repository, _setup("granted", False))) is False
    assert live == []
    assert not reports_path().exists()
    # A named local server is not a server elsewhere: still nothing.
    with targets.registry_lock():
        targets.new_local_target("work")
    assert targets.remote_target_recorded() is False
    assert refresh_at_session_start(repository, budget_seconds=5.0) is False
    assert live == []
    assert not reports_path().exists()


def test_with_no_server_elsewhere_the_shared_read_asks_and_records_nothing(
    home: Path, repository: str
) -> None:
    """The one read every surface uses (``server repositories list`` and ``status``, a privacy
    change, a session start) is dormant at its own boundary, not only where a caller checks."""

    calls: list[str] = []
    assert _read(repository, _connector(True, _setup("granted", False), calls)) == EverydayReads(
        "unreadable", "unreadable"
    )
    assert calls == []
    assert not reports_path().exists()
    assert read_marker() == "absent"
    # Not even the clean-up of a computer never set up runs while it is dormant.
    record_reported_policy(zero_network=False, now=_AT)

    async def never_set_up() -> EverydayReads:
        return await read_everyday_repository(
            repository,
            connect=_connector(True, {}, calls),  # type: ignore[arg-type]
            installation_exists=lambda: False,
        )

    assert asyncio.run(never_set_up()) == EverydayReads("unreadable", "unreadable")
    assert read_marker() == ReportedPolicy(False, _STAMP)
    assert calls == []


def test_the_first_server_elsewhere_switches_the_reads_on(
    home: Path, repository: str, live: list[tuple[str, float]]
) -> None:
    record_reported_policy(zero_network=False, now=_AT)
    assert refresh_at_session_start(repository, budget_seconds=5.0) is False
    record_remote_target()
    assert targets.remote_target_recorded() is True
    assert refresh_at_session_start(repository, budget_seconds=5.0) is True
    assert live == [(repository, 0.5)]
    report = repository_report(_key(repository))
    assert report is not None and report.no_network


def test_a_registry_that_cannot_be_examined_switches_the_reads_on(home: Path) -> None:
    # A remote record FinishUP wrote, later damaged: its presence was recorded first.
    record = record_remote_target()
    (targets.target_root(record.target_id) / "target.json").write_bytes(b"not a record")
    assert targets.remote_target_recorded() is True
    # A registry folder that is not one (a link to elsewhere) fails toward the hold too.
    servers = targets.servers_dir()
    moved = servers.with_name("servers-moved")
    servers.rename(moved)
    servers.symlink_to(moved)
    assert targets.remote_target_recorded() is True


def test_the_dormancy_check_is_a_bounded_presence_check(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A session start asks it: it reads no record and lists no folder, however many named local
    servers or leftover folders the registry holds (Codex review B4)."""

    with targets.registry_lock():
        for number in range(3):
            targets.new_local_target(f"work{number}")
    for number in range(40):
        (targets.servers_dir() / f"t_{number:08x}").mkdir(mode=0o700)

    def no_record_read(*_args: object) -> object:
        raise AssertionError("the dormancy check reads no record")

    def no_listing(*_args: object) -> object:
        raise AssertionError("the dormancy check lists no folder")

    with monkeypatch.context() as patch:
        patch.setattr(targets, "read_target", no_record_read)
        patch.setattr(targets.os, "scandir", no_listing)
        assert targets.remote_target_recorded() is False
    first = record_remote_target("first")
    second = record_remote_target("second")
    with monkeypatch.context() as patch:
        patch.setattr(targets, "read_target", no_record_read)
        patch.setattr(targets.os, "scandir", no_listing)
        assert targets.remote_target_recorded() is True
    # Removing one keeps it on; removing the last switches it off (the reports' way out).
    with targets.registry_lock():
        targets.remove_target_root(first)
    assert targets.remote_target_recorded() is True
    with targets.registry_lock():
        targets.remove_target_root(second)
    assert targets.remote_target_recorded() is False


def test_a_remote_record_is_never_written_before_its_presence(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The presence comes first: an add interrupted between the two fails toward the hold."""

    def interrupted(_path: Path, _encoded: bytes) -> None:
        raise OSError("interrupted")

    monkeypatch.setattr(targets, "_write_owner_only", interrupted)
    with pytest.raises(OSError), targets.registry_lock():
        targets.new_remote_target("lab", "https", base_url="https://lab.example")
    assert targets.remote_target_recorded() is True
    assert targets.list_targets() == ()
    # The owner's way back from that state: the next removal finds no remote record left.
    assert targets.reconcile_remote_presence() is False
    assert targets.remote_target_recorded() is False


# --- nothing on the session-start path waits on a special file (Codex review B3) ---------------


def _installation_marker() -> Path:
    from finishup.config.load import load_config
    from finishup.config.paths import bundle_root

    root = bundle_root(_data_dir=load_config({}, os.environ, None).storage.data_dir)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return root / "installation-state.json"


def _finishes(work: object, seconds: float = 10.0) -> list[object]:
    """Run ``work`` in a daemon thread; what it returned, or [] if it is still running."""

    import threading
    from collections.abc import Callable
    from typing import cast

    done: list[object] = []

    def run() -> None:
        done.append(cast(Callable[[], object], work)())

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    # A bounded wait on the work itself: it ends at once, long before this deadline.
    thread.join(timeout=seconds)
    return done


def _unblock(fifo: Path) -> None:
    """Give a reader that is waiting on ``fifo`` its end of file (only for a run that blocked)."""

    try:
        descriptor = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
    except OSError:
        return
    os.close(descriptor)


def test_a_special_file_as_the_installation_marker_never_blocks_the_live_read(
    home: Path, elsewhere: None, repository: str
) -> None:
    from finishup.cli.provider_status import MachineScopeError, machine_scope_request

    marker = _installation_marker()
    os.mkfifo(marker, 0o600)
    calls: list[str] = []
    try:

        def request() -> object:
            try:
                return machine_scope_request()
            except MachineScopeError as error:
                return error.reason

        assert _finishes(request) == ["installation_marker_invalid"]

        def session_start_read() -> object:
            return asyncio.run(
                read_everyday_repository(
                    repository,
                    budget_seconds=0.5,
                    connect=_connector(True, _setup("granted", False), calls),  # type: ignore[arg-type]
                    installation_exists=lambda: True,
                )
            )

        assert _finishes(session_start_read) == [EverydayReads("unreadable", "unreadable")]
        assert calls == []
    finally:
        _unblock(marker)
    # The other markers it refuses, each before reading what it holds.
    marker.unlink()
    with marker.open("wb") as handle:
        handle.truncate(64 * 1_024 * 1_024)  # sparse: nothing is written, and nothing read
    marker.chmod(0o600)
    with pytest.raises(MachineScopeError) as oversized:
        machine_scope_request()
    assert oversized.value.reason == "installation_marker_invalid"
    marker.unlink()
    target = marker.with_name("elsewhere.json")
    target.write_bytes(b"{}\n")
    marker.symlink_to(target)
    with pytest.raises(MachineScopeError) as linked:
        machine_scope_request()
    assert linked.value.reason == "installation_marker_invalid"
    marker.unlink()
    with pytest.raises(MachineScopeError) as missing:
        machine_scope_request()
    assert missing.value.reason == "installation_marker_missing"


def test_a_special_file_swapped_in_after_the_check_never_blocks_a_report_read(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Between the ``lstat`` check and the open, a FIFO takes the record's place: the open does
    not wait for a writer, and the record reads as unreadable."""

    record_repository_report("sha256:" + "a" * 64, "/srv/app", no_network=True, now=_AT)
    record_reported_policy(zero_network=False, now=_AT)
    paths = {reports_path(): reports_path().lstat()}
    from finishup.client.everyday_policy import marker_path

    paths[marker_path()] = marker_path().lstat()
    for path in paths:
        path.unlink()
        os.mkfifo(path, 0o600)
    real = Path.lstat

    def as_checked(self: Path) -> os.stat_result:
        return paths.get(self) or real(self)

    monkeypatch.setattr(Path, "lstat", as_checked)
    try:
        assert _finishes(read_repository_reports) == ["unreadable"]
        assert _finishes(read_marker) == ["unreadable"]
    finally:
        for path in paths:
            _unblock(path)
