"""What this computer's everyday FinishUP last said about each repository (ADR-051 decision 8).

Maintainer decision of 2026-11-07, round 4. Beside the zero-network marker, an owner-only record
keeps, per repository key, whether that repository's own grant allows no network use, since when
that stretch began, when it was reported, and the worktree tops it was reported from. It is
written and read only for the everyday installation; a record that cannot be read counts as no
record and the next report replaces it.
"""

from __future__ import annotations

import fcntl
import json
import os
import stat
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import finishup.client.everyday_policy as everyday_policy
from builders.server_targets import ambient_home
from finishup.client import targets
from finishup.client.everyday_policy import (
    MAX_REPORTED_REPOSITORIES,
    MAX_WORKTREES_PER_REPORT,
    RepositoryReport,
    forget_repository_reports,
    note_repository_worktree,
    read_repository_reports,
    record_repository_report,
    remove_repository_reports,
    reports_path,
    repository_report,
)
from finishup.config.paths import reset_selection_memo

_AT = datetime(2026, 11, 7, 9, 30, tzinfo=UTC)
_STAMP = "2026-11-07T09:30:00.000Z"
_KEY = "sha256:" + "a" * 64
_OTHER = "sha256:" + "b" * 64


def _key(number: int) -> str:
    return f"sha256:{number:064x}"


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """An owner-only ambient home; the record at its real place beneath it."""

    with ambient_home(monkeypatch) as root:
        monkeypatch.setattr(
            everyday_policy,
            "_location",
            everyday_policy._ambient_marker_path,  # pyright: ignore[reportPrivateUsage]
        )
        yield root


def test_the_record_is_canonical_owner_only_client_state_beside_the_marker(home: Path) -> None:
    assert record_repository_report(_KEY, "/srv/work/app", no_network=True, now=_AT) is True

    path = reports_path()
    assert path == home / "state" / "finishup" / "servers" / "everyday-repositories.json"
    assert path.parent == targets.servers_dir()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_bytes() == (
        b'{"repositories":[{"key":"' + _KEY.encode() + b'","no_network":true,'
        b'"no_network_since":"2026-11-07T09:30:00.000Z","reported_at":'
        b'"2026-11-07T09:30:00.000Z","worktrees":["/srv/work/app"]}],'
        b'"schema":"yoetz.everyday-repository-policy/1"}\n'
    )
    assert repository_report(_KEY) == RepositoryReport(
        _KEY, True, _STAMP, _STAMP, ("/srv/work/app",)
    )
    assert repository_report(_OTHER) is None


def test_the_no_network_stretch_starts_is_kept_and_ends(home: Path) -> None:
    later = _AT + timedelta(minutes=5)
    latest = _AT + timedelta(minutes=10)
    # Absent, then no network: the stretch starts now.
    record_repository_report(_KEY, "/srv/app", no_network=True, now=_AT)
    # No network again: the stretch it began is kept; only the report time moves.
    record_repository_report(_KEY, "/srv/app", no_network=True, now=later)
    kept = repository_report(_KEY)
    assert kept is not None
    assert (kept.no_network_since, kept.reported_at) == (_STAMP, "2026-11-07T09:35:00.000Z")
    # Network permitted: the stretch ends.
    record_repository_report(_KEY, "/srv/app", no_network=False, now=later)
    ended = repository_report(_KEY)
    assert ended is not None and ended.no_network is False and ended.no_network_since is None
    # No network once more: a new stretch, never the old one.
    record_repository_report(_KEY, "/srv/app", no_network=True, now=latest)
    again = repository_report(_KEY)
    assert again is not None and again.no_network_since == "2026-11-07T09:40:00.000Z"


def test_worktrees_join_the_front_deduplicated_and_capped(home: Path) -> None:
    for number in range(MAX_WORKTREES_PER_REPORT + 2):
        record_repository_report(_KEY, f"/srv/tree{number}", no_network=True, now=_AT)
    record_repository_report(_KEY, "/srv/tree5", no_network=True, now=_AT)
    report = repository_report(_KEY)
    assert report is not None
    assert report.worktrees == (
        "/srv/tree5",
        "/srv/tree9",
        "/srv/tree8",
        "/srv/tree7",
        "/srv/tree6",
        "/srv/tree4",
        "/srv/tree3",
        "/srv/tree2",
    )
    # A path too long to keep is not stored; the entry still records the report by key.
    record_repository_report(_KEY, "/" + "x" * 1_100, no_network=True, now=_AT)
    assert repository_report(_KEY) == report
    assert note_repository_worktree(_KEY, "/srv/linked") is True
    noted = repository_report(_KEY)
    assert noted is not None and noted.worktrees[0] == "/srv/linked"
    assert noted.no_network_since == report.no_network_since
    # A key with no entry is never created by a note, and a known worktree changes nothing.
    assert note_repository_worktree(_OTHER, "/srv/other") is False
    assert note_repository_worktree(_KEY, "/srv/tree3") is False


def test_past_the_bound_the_oldest_permitted_entry_goes_first_then_the_oldest(home: Path) -> None:
    start = _AT
    for number in range(MAX_REPORTED_REPOSITORIES):
        record_repository_report(
            _key(number),
            None,
            no_network=number != 7,
            now=start + timedelta(seconds=number),
        )
    newest = start + timedelta(hours=1)
    assert record_repository_report(_key(1_000), None, no_network=True, now=newest) is True
    reading = read_repository_reports()
    assert not isinstance(reading, str)
    keys = {report.key for report in reading}
    assert len(reading) == MAX_REPORTED_REPOSITORIES
    # The one entry that allowed network use went, though it was not the oldest.
    assert _key(7) not in keys and _key(0) in keys and _key(1_000) in keys
    assert record_repository_report(_key(1_001), None, no_network=True, now=newest) is True
    reading = read_repository_reports()
    assert not isinstance(reading, str)
    # With none left that allows network use, the oldest entry goes.
    assert _key(0) not in {report.key for report in reading}


def _write_raw(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


def _body(**changes: object) -> bytes:
    entry: dict[str, object] = {
        "key": _KEY,
        "no_network": True,
        "no_network_since": _STAMP,
        "reported_at": _STAMP,
        "worktrees": ["/srv/app"],
        **changes,
    }
    document = {"repositories": [entry], "schema": "yoetz.everyday-repository-policy/1"}
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode() + b"\n"


@pytest.mark.parametrize(
    "how",
    [
        "not_json",
        "not_canonical",
        "other_schema",
        "since_without_no_network",
        "no_since",
        "relative_worktree",
        "control_character",
        "group_readable",
        "too_large",
        "symlink",
        "foreign_owner",
    ],
)
def test_a_record_that_cannot_be_read_counts_as_none_and_the_next_report_replaces_it(
    home: Path, how: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = reports_path()
    valid = _body()
    if how == "not_json":
        _write_raw(path, b"{oops\n")
    elif how == "not_canonical":
        _write_raw(path, b" " + valid)
    elif how == "other_schema":
        _write_raw(path, valid.replace(b"policy/1", b"policy/2"))
    elif how == "since_without_no_network":
        _write_raw(path, _body(no_network=False))
    elif how == "no_since":
        _write_raw(path, _body(no_network_since=None))
    elif how == "relative_worktree":
        _write_raw(path, _body(worktrees=["srv/app"]))
    elif how == "control_character":
        _write_raw(path, _body(worktrees=["/srv/a\u0001pp"]))
    elif how == "group_readable":
        _write_raw(path, valid, mode=0o640)
    elif how == "too_large":
        _write_raw(path, b" " * (256 * 1_024 + 1))
    elif how == "symlink":
        elsewhere = path.parent / "elsewhere.json"
        _write_raw(elsewhere, valid)
        path.symlink_to(elsewhere)
    elif how == "foreign_owner":
        _write_raw(path, valid)
        real = os.geteuid()
        monkeypatch.setattr(everyday_policy.os, "geteuid", lambda: real + 1)

    assert read_repository_reports() == "unreadable"
    assert repository_report(_KEY) is None
    if how == "foreign_owner":
        monkeypatch.undo()
        monkeypatch.setattr(
            everyday_policy,
            "_location",
            everyday_policy._ambient_marker_path,  # pyright: ignore[reportPrivateUsage]
        )
        return
    assert record_repository_report(_OTHER, "/srv/other", no_network=False, now=_AT) is True
    reading = read_repository_reports()
    assert not isinstance(reading, str)
    assert [report.key for report in reading] == [_OTHER]
    assert not path.is_symlink()


def test_a_valid_hand_written_record_reads_back(home: Path) -> None:
    _write_raw(reports_path(), _body())
    assert repository_report(_KEY) == RepositoryReport(_KEY, True, _STAMP, _STAMP, ("/srv/app",))


def test_forgetting_and_removing(home: Path) -> None:
    record_repository_report(_KEY, "/srv/app", no_network=True, now=_AT)
    record_repository_report(_OTHER, "/srv/other", no_network=False, now=_AT)

    assert forget_repository_reports([_KEY]) is True
    assert repository_report(_KEY) is None and repository_report(_OTHER) is not None
    assert forget_repository_reports([_KEY]) is False
    # The last entry forgotten removes the file.
    assert forget_repository_reports([_OTHER]) is True
    assert read_repository_reports() == "absent"

    record_repository_report(_KEY, "/srv/app", no_network=True, now=_AT)
    assert remove_repository_reports() is True
    assert read_repository_reports() == "absent"
    assert remove_repository_reports() is False


def test_a_write_is_skipped_while_another_holds_the_lock(home: Path) -> None:
    record_repository_report(_KEY, "/srv/app", no_network=True, now=_AT)
    before = reports_path().read_bytes()
    lock = reports_path().with_name("everyday-repositories.lock")
    descriptor = os.open(lock, os.O_RDWR)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        assert (
            record_repository_report(
                _KEY, "/srv/app", no_network=False, now=_AT, lock_wait_seconds=0.01
            )
            is False
        )
    finally:
        os.close(descriptor)
    assert reports_path().read_bytes() == before


def test_an_isolation_root_neither_records_nor_reads_the_everyday_reports(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record_repository_report(_KEY, "/srv/app", no_network=True, now=_AT)
    before = reports_path().read_bytes()
    isolated = home / "isolated"
    isolated.mkdir(mode=0o700)
    monkeypatch.setenv("FINISHUP_ISOLATED_ROOT", str(isolated))
    reset_selection_memo()

    assert record_repository_report(_KEY, "/srv/app", no_network=False, now=_AT) is False
    assert forget_repository_reports([_KEY]) is False
    assert read_repository_reports() == "absent"
    assert repository_report(_KEY) is None

    monkeypatch.delenv("FINISHUP_ISOLATED_ROOT")
    reset_selection_memo()
    assert reports_path().read_bytes() == before
