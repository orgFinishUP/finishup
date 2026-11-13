"""What this computer's everyday FinishUP last reported about network use (ADR-051 decision 8).

Maintainer decision of 2026-11-07 ("remember"). This computer's zero-network state is its
everyday installation's effective machine-scope privacy policy, read from its running service.
While a FinishUP server on another machine, a port or the web is selected, that service is
usually stopped or locked, so the live answer cannot be had. Whenever the service does report the
policy to a client command on this computer (the zero-network check, ``privacy show``, and every
privacy change made here), the client records a small marker: whether the policy was zero-network,
and when. Surfaces read the live policy first and fall back to the marker, worded as "this
computer last reported"; the connection check reads only the marker, so no hook pays for a
service round trip.

The marker is ``<ambient state dir>/servers/everyday-policy.json`` (``SCHEMA``), an owner-only
regular file beside the server registry, outside the vault: client state of this computer's
everyday installation, independent of the selected server. It holds no path, name or policy
content, only ``zero_network`` (a boolean) and ``reported_at`` (an RFC 3339 UTC time in
milliseconds).

* Only the everyday installation keeps it. A process whose root an isolation variable or runtime
  pin decides reads and changes its own root's policy, so it neither records nor reads the
  marker.
* A marker that cannot be read (damaged, not owner-only, a link, too large) counts as no record:
  no surface claims the zero-network state from it and no connection is refused on it, and the
  next report replaces it. Nothing here ever raises: a marker that cannot be written leaves the
  previous one, or none.
* The way out: deleting FinishUP's per-user folders (uninstalling) removes it with the state
  folder, and the zero-network check removes it once the everyday installation no longer exists
  (its vault was never set up, or was removed).

**Repositories** (ADR-051 decision 8, maintainer decision of 2026-11-07, round 4). Beside the
marker, ``everyday-repositories.json`` (``REPORTS_SCHEMA``) records what this computer's everyday
FinishUP last said about each repository's own privacy policy: whether its grant allows no network
use (``no_network``), since when that stretch began (``no_network_since``, kept across consecutive
no-network reports, so an owner's choice for a repository binds to one such stretch), when it was
reported, and up to ``MAX_WORKTREES_PER_REPORT`` worktree tops it was reported from (owner-only
client state, for owner displays and for fencing; never sent anywhere). Each entry is keyed by a
client digest of the repository's canonical identity (``client.repository_hold.repository_key``),
so every linked worktree shares it. At most ``MAX_REPORTED_REPOSITORIES`` entries are kept: past
that the oldest entry whose policy allows network use goes first, then the oldest entry. Writes
take a dedicated lock with a bounded wait and are skipped when it is not taken; a record that
cannot be read counts as no record (nothing is held on it) and the next report replaces it. Only
the everyday installation keeps it, and the zero-network check removes it with the marker once
the everyday installation no longer exists.

This module imports only the standard library and lean SHARED modules, so a hook may import it.
"""

from __future__ import annotations

import fcntl
import os
import posixpath
import re
import secrets
import stat
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, cast

from finishup.config.installation import format_rfc3339_ms
from finishup.config.paths import (
    SERVERS_DIR_NAME,
    PathSafetyError,
    ambient_registry_dirs,
    ensure_owner_only_dir,
)
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse

__all__ = [
    "CLI_LOCK_WAIT_SECONDS",
    "HOOK_LOCK_WAIT_SECONDS",
    "MARKER_NAME",
    "MAX_REPORTED_REPOSITORIES",
    "MAX_WORKTREES_PER_REPORT",
    "MAX_REPORTS_BYTES",
    "MAX_WORKTREE_CHARS",
    "OVERFLOW_NAME",
    "OVERFLOW_SCHEMA",
    "REPORTS_NAME",
    "REPORTS_SCHEMA",
    "SCHEMA",
    "RepositoryReport",
    "ReportedPolicy",
    "everyday_scope",
    "forget_repository_reports",
    "last_reported_zero_network",
    "marker_path",
    "note_repository_worktree",
    "read_marker",
    "read_overflow",
    "read_repository_reports",
    "record_reported_policy",
    "record_repository_report",
    "remove_marker",
    "remove_repository_reports",
    "reports_path",
    "repository_report",
    "worktree_storable",
]

SCHEMA: Final = "yoetz.everyday-network-policy/1"
MARKER_NAME: Final = "everyday-policy.json"
_MAX_BYTES: Final = 512
_FIELDS: Final = frozenset({"schema", "zero_network", "reported_at"})
_TIMESTAMP: Final = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"
)

type MarkerReading = ReportedPolicy | Literal["absent", "unreadable"]


@dataclass(frozen=True, slots=True)
class ReportedPolicy:
    """What this computer's everyday FinishUP last reported: zero-network or not, and when."""

    zero_network: bool
    reported_at: str


def _ambient_marker_path() -> Path:
    _config, state = ambient_registry_dirs()
    return state / SERVERS_DIR_NAME / MARKER_NAME


# Where the marker lives; the test suite points it at a private folder of its own.
_location = _ambient_marker_path


def marker_path() -> Path:
    """``<ambient state dir>/servers/everyday-policy.json``."""

    return _location()


def _everyday_scope() -> bool:
    """Whether this process's FinishUP is the everyday one (no isolation variable or pin).

    A variable or pin that cannot be used still decides: it fails closed on its own path, and the
    marker is left alone.
    """

    from finishup.config.paths import isolated_root_variable, read_runtime_pin

    try:
        return isolated_root_variable() is None and read_runtime_pin() is None
    except PathSafetyError:
        return False


def everyday_scope() -> bool:
    """Whether this process's FinishUP is the everyday one (no isolation variable or pin); only
    then are this computer's records read or written. A variable or pin that cannot be used still
    decides (False)."""

    return _everyday_scope()


def record_reported_policy(*, zero_network: bool, now: datetime | None = None) -> bool:
    """Record what this computer's everyday FinishUP just reported; whether it was written.

    Call it only with the everyday installation's own effective machine-scope policy, as its
    service answered a client command. Atomic (an owner-only temporary file, flushed, renamed
    over the marker, so a damaged file or a link in its place is replaced, never followed).
    Never raises.
    """

    if type(zero_network) is not bool or not _everyday_scope():
        return False
    stamp = format_rfc3339_ms((now or datetime.now(UTC)).astimezone(UTC))
    body: dict[str, JsonValue] = {
        "schema": SCHEMA,
        "reported_at": stamp,
        "zero_network": zero_network,
    }
    try:
        path = marker_path()
        ensure_owner_only_dir(path.parent)
        _write_owner_only(path, canonical_encode(body) + b"\n")
    except (OSError, PathSafetyError, ValueError):
        return False
    return True


def _write_owner_only(path: Path, encoded: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
    )
    try:
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short_write")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def read_marker() -> MarkerReading:
    """The marker: what was last reported, ``absent``, or ``unreadable``. Never raises.

    ``absent`` too in a process whose root an isolation variable or runtime pin decides.
    """

    if not _everyday_scope():
        return "absent"
    try:
        path = marker_path()
        facts = path.lstat()
    except FileNotFoundError:
        return "absent"
    except (OSError, PathSafetyError):
        return "unreadable"
    if (
        not stat.S_ISREG(facts.st_mode)
        or facts.st_uid != os.geteuid()
        or stat.S_IMODE(facts.st_mode) & 0o077
        or facts.st_size > _MAX_BYTES
    ):
        return "unreadable"
    try:
        # Never blocks: a special file put in its place is refused, not waited on (a hook reads it).
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                return "unreadable"
            encoded = os.read(descriptor, _MAX_BYTES + 1)
        finally:
            os.close(descriptor)
        parsed = strict_json_parse(encoded)
    except (OSError, ValueError):
        return "unreadable"
    if not isinstance(parsed, dict):
        return "unreadable"
    fields = parsed
    zero_network = fields.get("zero_network")
    reported_at = fields.get("reported_at")
    if (
        frozenset(fields) != _FIELDS
        or fields.get("schema") != SCHEMA
        or type(zero_network) is not bool
        or type(reported_at) is not str
        or not _TIMESTAMP.match(reported_at)
    ):
        return "unreadable"
    return ReportedPolicy(zero_network, reported_at)


def last_reported_zero_network() -> ReportedPolicy | None:
    """The marker when it says this computer last reported zero-network; ``None`` otherwise.

    The connection check (``targets.require_current_authorization``) reads this: a file read
    only, never a service round trip. An absent or unreadable marker is ``None``.
    """

    reading = read_marker()
    if isinstance(reading, ReportedPolicy) and reading.zero_network:
        return reading
    return None


def remove_marker() -> bool:
    """Delete the marker; whether one was removed. A link is removed, never what it names.

    Anything but a file or a link is left in place. Never raises.
    """

    try:
        path = marker_path()
        facts = path.lstat()
    except (OSError, PathSafetyError):
        return False
    if not (stat.S_ISREG(facts.st_mode) or stat.S_ISLNK(facts.st_mode)):
        return False
    try:
        path.unlink()
    except OSError:
        return False
    return True


# --- what this computer's everyday FinishUP last said about each repository -------------------

REPORTS_SCHEMA: Final = "yoetz.everyday-repository-policy/1"
REPORTS_NAME: Final = "everyday-repositories.json"
_REPORTS_LOCK_NAME: Final = "everyday-repositories.lock"
MAX_REPORTED_REPOSITORIES: Final = 256
MAX_WORKTREES_PER_REPORT: Final = 8
# A worktree path longer than this is not stored: the hold still applies by key, but owner
# displays cannot show it and the workspace agent cannot fence it.
MAX_WORKTREE_CHARS: Final = 1_024
# The record's byte bound, which the writer keeps as well as the reader: an update that would pass
# it first drops the oldest entries whose policy allows network use, and otherwise is not written
# at all (the record keeps what it said, and the overflow is recorded): never a held entry dropped,
# never a record too large to read.
MAX_REPORTS_BYTES: Final = 256 * 1_024
_MAX_REPORTS_BYTES: Final = MAX_REPORTS_BYTES
# When an update last did not fit (``read_overflow``); cleared by the next update that does.
OVERFLOW_NAME: Final = "everyday-repositories-overflow.json"
OVERFLOW_SCHEMA: Final = "yoetz.everyday-repository-overflow/1"
_MAX_OVERFLOW_BYTES: Final = 256
_REPORT_FIELDS: Final = frozenset(
    {"key", "no_network", "no_network_since", "reported_at", "worktrees"}
)
_KEY: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
# Bounded waits for the record's lock: a hook pass never waits long; a CLI command may.
HOOK_LOCK_WAIT_SECONDS: Final = 0.05
CLI_LOCK_WAIT_SECONDS: Final = 2.0
_LOCK_POLL_SECONDS: Final = 0.005

type ReportsReading = tuple[RepositoryReport, ...] | Literal["absent", "unreadable"]


@dataclass(frozen=True, slots=True)
class RepositoryReport:
    """What this computer's everyday FinishUP last said about one repository's own policy.

    ``no_network`` is True when the repository's own grant allows no network use;
    ``no_network_since`` is when the current such stretch began (None while it allows network
    use); ``worktrees`` are the worktree tops it was reported from, most recent first.
    """

    key: str
    no_network: bool
    no_network_since: str | None
    reported_at: str
    worktrees: tuple[str, ...] = ()


def reports_path() -> Path:
    """``<ambient state dir>/servers/everyday-repositories.json``, beside the marker."""

    return marker_path().with_name(REPORTS_NAME)


def worktree_storable(worktree: object) -> bool:
    """Whether ``worktree`` is a path the record keeps: absolute, normal, no control characters,
    at most ``MAX_WORKTREE_CHARS``, and not the filesystem root."""

    return (
        type(worktree) is str
        and worktree.startswith("/")
        and worktree != "/"
        and len(worktree) <= MAX_WORKTREE_CHARS
        and posixpath.normpath(worktree) == worktree
        and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in worktree)
    )


def _timestamp(value: object) -> bool:
    return type(value) is str and _TIMESTAMP.match(value) is not None


def _decode_report(item: object) -> RepositoryReport | None:
    if not isinstance(item, dict):
        return None
    fields = cast(dict[str, object], item)
    key = fields.get("key")
    no_network = fields.get("no_network")
    since = fields.get("no_network_since")
    reported_at = fields.get("reported_at")
    worktrees = fields.get("worktrees")
    if (
        frozenset(fields) != _REPORT_FIELDS
        or type(key) is not str
        or not _KEY.match(key)
        or type(no_network) is not bool
        or not _timestamp(reported_at)
        or (since is not None if not no_network else not _timestamp(since))
        or type(worktrees) is not list
    ):
        return None
    paths = cast(list[object], worktrees)
    if (
        len(paths) > MAX_WORKTREES_PER_REPORT
        or not all(worktree_storable(path) for path in paths)
        or len(set(cast(list[str], paths))) != len(paths)
    ):
        return None
    return RepositoryReport(
        key,
        no_network,
        cast(str | None, since),
        cast(str, reported_at),
        tuple(cast(list[str], paths)),
    )


def _encode_reports(reports: Iterable[RepositoryReport]) -> bytes:
    ordered = sorted(reports, key=lambda report: report.key)
    body: dict[str, JsonValue] = {
        "schema": REPORTS_SCHEMA,
        "repositories": [
            {
                "key": report.key,
                "no_network": report.no_network,
                "no_network_since": report.no_network_since,
                "reported_at": report.reported_at,
                "worktrees": list(report.worktrees),
            }
            for report in ordered
        ],
    }
    return canonical_encode(body) + b"\n"


_EMPTY_RECORD_BYTES: Final = len(_encode_reports(()))


def _read_reports_file() -> ReportsReading:
    try:
        path = reports_path()
        facts = path.lstat()
    except FileNotFoundError:
        return "absent"
    except (OSError, PathSafetyError):
        return "unreadable"
    if (
        not stat.S_ISREG(facts.st_mode)
        or facts.st_uid != os.geteuid()
        or stat.S_IMODE(facts.st_mode) & 0o077
        or facts.st_size > _MAX_REPORTS_BYTES
    ):
        return "unreadable"
    try:
        # Never blocks: a special file put in its place is refused, not waited on (a hook reads it).
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                return "unreadable"
            chunks: list[bytes] = []
            remaining = _MAX_REPORTS_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        finally:
            os.close(descriptor)
        encoded = b"".join(chunks)
        if len(encoded) > _MAX_REPORTS_BYTES or not encoded.endswith(b"\n"):
            return "unreadable"
        parsed = strict_json_parse(encoded[:-1])
    except (OSError, ValueError):
        return "unreadable"
    if not isinstance(parsed, dict):
        return "unreadable"
    document = cast(dict[str, object], parsed)
    items = document.get("repositories")
    if (
        frozenset(document) != frozenset({"schema", "repositories"})
        or document.get("schema") != REPORTS_SCHEMA
        or type(items) is not list
        or len(cast(list[object], items)) > MAX_REPORTED_REPOSITORIES
    ):
        return "unreadable"
    reports: list[RepositoryReport] = []
    for item in cast(list[object], items):
        report = _decode_report(item)
        if report is None:
            return "unreadable"
        reports.append(report)
    if len({report.key for report in reports}) != len(reports):
        return "unreadable"
    # Exactly the canonical bytes this module writes: sorted, unique, canonical JSON.
    if _encode_reports(reports) != encoded:
        return "unreadable"
    return tuple(reports)


def read_repository_reports() -> ReportsReading:
    """Every recorded report, ``absent``, or ``unreadable``. Never raises.

    ``absent`` too in a process whose root an isolation variable or runtime pin decides: such a
    process keeps its own root's policy, not this computer's everyday one.
    """

    if not _everyday_scope():
        return "absent"
    return _read_reports_file()


def repository_report(key: str) -> RepositoryReport | None:
    """The report recorded for ``key``; ``None`` when none is, or the record cannot be read."""

    reading = read_repository_reports()
    if isinstance(reading, str):
        return None
    return next((report for report in reading if report.key == key), None)


class _LockNotTaken(Exception):
    pass


def _locked(wait_seconds: float, clock: Callable[[], float] = time.monotonic) -> int:
    """The record's lock descriptor, taken within ``wait_seconds``; raises when it is not."""

    lock = reports_path().with_name(_REPORTS_LOCK_NAME)
    ensure_owner_only_dir(lock.parent)
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        facts = os.fstat(descriptor)
        if not stat.S_ISREG(facts.st_mode) or facts.st_uid != os.geteuid():
            raise _LockNotTaken
        deadline = clock() + max(0.0, wait_seconds)
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return descriptor
            except BlockingIOError:
                if clock() >= deadline:
                    raise _LockNotTaken from None
                time.sleep(_LOCK_POLL_SECONDS)
    except BaseException:
        os.close(descriptor)
        raise


def _update_reports(
    change: Callable[[tuple[RepositoryReport, ...]], tuple[RepositoryReport, ...] | None],
    *,
    lock_wait_seconds: float,
    keep: str | None = None,
    now: datetime | None = None,
) -> bool:
    """Apply ``change`` to the current reports under the lock; whether a record was written.

    ``change`` returns the new reports, or None to leave the record as it is. A record that cannot
    be read is treated as empty, so the next report replaces it. The result is held to the
    reader's byte bound (``_fitted``; ``keep`` is the entry being recorded, never dropped to make
    room): one that cannot fit is not written, the record keeps what it said, and the overflow is
    recorded (``read_overflow``) until an update fits again. Never raises.
    """

    if not _everyday_scope():
        return False
    try:
        descriptor = _locked(lock_wait_seconds)
    except (_LockNotTaken, OSError, PathSafetyError):
        return False
    try:
        current = _read_reports_file()
        reports = () if isinstance(current, str) else current
        updated = change(reports)
        if updated is None:
            return False
        path = reports_path()
        if not updated:
            path.unlink(missing_ok=True)
            _overflow_path().unlink(missing_ok=True)
            return True
        encoded = _fitted(updated, keep)
        if encoded is None:
            _record_overflow(now)
            return False
        _write_owner_only(path, encoded)
        _overflow_path().unlink(missing_ok=True)
        return True
    except (OSError, PathSafetyError, ValueError):
        return False
    finally:
        os.close(descriptor)


def _fitted(reports: Iterable[RepositoryReport], keep: str | None) -> bytes | None:
    """The canonical record of ``reports`` within the byte bound, or None when it cannot fit.

    Past the bound the oldest entries whose policy allows network use go first (as past the
    count bound), never ``keep`` and never one that allows no network use: dropping a held entry
    would end its hold. None when only such entries are left and it still does not fit.
    """

    entries = sorted(reports, key=lambda report: report.key)
    sizes = {
        report.key: len(_encode_reports((report,))) - _EMPTY_RECORD_BYTES for report in entries
    }

    def total() -> int:
        return (
            _EMPTY_RECORD_BYTES
            + sum(sizes[report.key] for report in entries)
            + max(0, len(entries) - 1)
        )

    while total() > _MAX_REPORTS_BYTES:
        permitted = [report for report in entries if not report.no_network and report.key != keep]
        if not permitted:
            return None
        entries.remove(min(permitted, key=lambda report: (report.reported_at, report.key)))
    encoded = _encode_reports(entries)
    return encoded if len(encoded) <= _MAX_REPORTS_BYTES else None


def _overflow_path() -> Path:
    return reports_path().with_name(OVERFLOW_NAME)


def _record_overflow(now: datetime | None) -> None:
    """Record that an update did not fit; best effort (the record itself is already safe)."""

    stamp = format_rfc3339_ms((now or datetime.now(UTC)).astimezone(UTC))
    body: dict[str, JsonValue] = {"overflowed_at": stamp, "schema": OVERFLOW_SCHEMA}
    try:
        _write_owner_only(_overflow_path(), canonical_encode(body) + b"\n")
    except (OSError, PathSafetyError):
        pass


def read_overflow() -> str | None:
    """When an update of the reports last did not fit within their byte bound, or None.

    ``None`` too when nothing overflowed since the last update that fit, outside the everyday
    scope, and for a marker that cannot be read. Never raises; never blocks on a special file.
    """

    if not _everyday_scope():
        return None
    try:
        path = _overflow_path()
        facts = path.lstat()
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != os.geteuid()
            or stat.S_IMODE(facts.st_mode) & 0o077
            or facts.st_size > _MAX_OVERFLOW_BYTES
        ):
            return None
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                return None
            encoded = os.read(descriptor, _MAX_OVERFLOW_BYTES + 1)
        finally:
            os.close(descriptor)
        parsed = strict_json_parse(encoded.rstrip(b"\n"))
    except (OSError, PathSafetyError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    document = cast(dict[str, object], parsed)
    stamp = document.get("overflowed_at")
    if (
        frozenset(document) != frozenset({"overflowed_at", "schema"})
        or document.get("schema") != OVERFLOW_SCHEMA
        or not _timestamp(stamp)
        or canonical_encode(cast(JsonValue, document)) + b"\n" != encoded
    ):
        return None
    return cast(str, stamp)


def _evict(reports: list[RepositoryReport], keep: str) -> list[RepositoryReport]:
    """Past the bound, drop the oldest entry whose policy allows network use, then the oldest."""

    while len(reports) > MAX_REPORTED_REPOSITORIES:
        candidates = [report for report in reports if report.key != keep]
        permitted = [report for report in candidates if not report.no_network]
        pool = permitted or candidates
        oldest = min(pool, key=lambda report: (report.reported_at, report.key))
        reports.remove(oldest)
    return reports


def _merged_worktrees(previous: tuple[str, ...], worktree: str | None) -> tuple[str, ...]:
    if worktree is None or not worktree_storable(worktree):
        return previous
    return (worktree, *(item for item in previous if item != worktree))[:MAX_WORKTREES_PER_REPORT]


def record_repository_report(
    key: str,
    worktree: str | None,
    *,
    no_network: bool,
    now: datetime | None = None,
    lock_wait_seconds: float = CLI_LOCK_WAIT_SECONDS,
) -> bool:
    """Record what this computer's everyday FinishUP just said about repository ``key``.

    Call it only with the everyday installation's own answer for that repository's grant, as its
    service gave it to a client on this computer. A no-network report after a missing or
    permitting entry starts a new stretch (``no_network_since`` now); consecutive no-network
    reports keep it; a permitting report clears it. ``worktree`` (the top of the worktree it was
    reported from) joins the front of the entry's list. Returns whether the record was written;
    never raises. A lock not taken within ``lock_wait_seconds`` skips the write.
    """

    if type(key) is not str or not _KEY.match(key) or type(no_network) is not bool:
        return False
    stamp = format_rfc3339_ms((now or datetime.now(UTC)).astimezone(UTC))

    def change(reports: tuple[RepositoryReport, ...]) -> tuple[RepositoryReport, ...]:
        previous = next((report for report in reports if report.key == key), None)
        if not no_network:
            since = None
        elif previous is not None and previous.no_network and previous.no_network_since:
            since = previous.no_network_since
        else:
            since = stamp
        entry = RepositoryReport(
            key,
            no_network,
            since,
            stamp,
            _merged_worktrees(() if previous is None else previous.worktrees, worktree),
        )
        others = [report for report in reports if report.key != key]
        return tuple(_evict([*others, entry], key))

    return _update_reports(change, lock_wait_seconds=lock_wait_seconds, keep=key, now=now)


def note_repository_worktree(
    key: str, worktree: str, *, lock_wait_seconds: float = HOOK_LOCK_WAIT_SECONDS
) -> bool:
    """Add ``worktree`` to the existing entry for ``key`` (a linked worktree found to share it).

    Nothing else in the entry changes, and nothing is recorded for a key with no entry. Returns
    whether the record was written; never raises.
    """

    if type(key) is not str or not _KEY.match(key) or not worktree_storable(worktree):
        return False

    def change(reports: tuple[RepositoryReport, ...]) -> tuple[RepositoryReport, ...] | None:
        previous = next((report for report in reports if report.key == key), None)
        if previous is None or worktree in previous.worktrees:
            return None
        entry = replace(previous, worktrees=_merged_worktrees(previous.worktrees, worktree))
        return tuple(report if report.key != key else entry for report in reports)

    return _update_reports(change, lock_wait_seconds=lock_wait_seconds, keep=key)


def forget_repository_reports(
    keys: Iterable[str], *, lock_wait_seconds: float = CLI_LOCK_WAIT_SECONDS
) -> bool:
    """Drop the entries for ``keys``: what was said about them is no longer known to hold.

    For a repository whose own grant cannot be told apart now (this computer's policy forbids all
    network use), and for entries whose recorded worktrees are all gone. Returns whether the
    record was written; never raises.
    """

    wanted = frozenset(keys)

    def change(reports: tuple[RepositoryReport, ...]) -> tuple[RepositoryReport, ...] | None:
        kept = tuple(report for report in reports if report.key not in wanted)
        return None if len(kept) == len(reports) else kept

    return _update_reports(change, lock_wait_seconds=lock_wait_seconds)


def remove_repository_reports() -> bool:
    """Delete the whole record; whether one was removed. A link is removed, never what it names.

    For when the everyday installation no longer exists. Anything but a file or a link is left
    in place. The overflow record goes with it. Never raises.
    """

    try:
        _overflow_path().unlink(missing_ok=True)
    except (OSError, PathSafetyError):
        pass
    try:
        path = reports_path()
        facts = path.lstat()
    except (OSError, PathSafetyError):
        return False
    if not (stat.S_ISREG(facts.st_mode) or stat.S_ISLNK(facts.st_mode)):
        return False
    try:
        path.unlink()
    except OSError:
        return False
    return True
