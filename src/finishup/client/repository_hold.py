"""Hold a repository whose privacy policy here allows no network use from a server elsewhere.

ADR-051 decision 8, maintainer decision of 2026-11-07, round 4. While a FinishUP server on another
machine, a port or the web (``ssh``, ``https``, ``local_port``) is selected, a repository whose own
grant on this computer composes to no network egress is **held** from it by default: nothing of
that repository is sent to that server until the owner decides. The owner either allows that one
server to receive it anyway (``finishup server repositories add``, on the trusted console, after a
disclosure and the typed target name) or keeps it on this computer (``finishup server repositories
keep``, which only tightens, so an agent may run it; later sessions say it is kept and do not ask
again). ``finishup server repositories remove`` undoes either, and FinishUP asks again.

What this computer's everyday FinishUP last said about a repository is its report
(``client.everyday_policy``, keyed by ``repository_key``); the owner's choices are a per-target
record, ``<target root>/config/repositories.json`` (``OVERRIDES_SCHEMA``), beside ``folders.json``.
Each choice is bound to the target by location and ``target_id``, to the repository by its key,
and to the no-network stretch it was made in (``no_network_since``): if the repository's policy
here allows network use and later forbids it again, the old choice no longer applies
(``grant_changed``) and FinishUP asks again.

``decide`` reads both files (never a service, never a network) and never raises:

1. a process whose root an isolation variable or runtime pin decides is ``not_held``;
2. no report for the repository (none, or one that cannot be read) is ``not_reported``, which is
   not held: unknown is never held, as the zero-network marker is never claimed when unknown;
3. a report that its policy allows network use is ``not_held``;
4. a report that it allows no network use is ``held`` (cause ``not_allowed``), unless the owner's
   choice for it on this target, made in the same stretch, says otherwise: ``sent_anyway`` for an
   allow made under the current disclosure, ``kept`` for a keep. A choice from another stretch is
   ``held`` (cause ``grant_changed``); a record of choices that cannot be read is ``held``
   (fail closed: no allow applies).

The connection seam (``client.remote_binding.remote_workspace_binding``) calls
``require_sendable`` after the root is resolved and before anything is claimed, dialled or
started: ``held`` raises ``TargetError("repository_egress_held")`` and ``kept`` raises
``TargetError("repository_egress_kept")``, which every surface renders as a retryable remote
phase. Otherwise it returns the ``SendHold`` a long-lived holder re-checks. Generated ids, closed
tokens and fixed text only leave this module; paths and names appear on owner displays only.

This module imports only the standard library and lean SHARED modules, so a hook may import it;
the workspace-root adapter loads only when a key is derived.
"""

from __future__ import annotations

import hashlib
import os
import posixpath
import re
import secrets
import stat
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal, cast

from finishup.client.everyday_policy import (
    MAX_REPORTED_REPOSITORIES,
    MAX_WORKTREES_PER_REPORT,
    RepositoryReport,
    everyday_scope,
    read_repository_reports,
    reports_path,
    worktree_storable,
)
from finishup.config.installation import format_rfc3339_ms
from finishup.config.paths import PathSafetyError, ensure_owner_only_dir
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse

if TYPE_CHECKING:
    from finishup.adapters.workspace_root import CanonicalWorkspaceRoot
    from finishup.client.targets import ServerTarget

__all__ = [
    "CONTINUATION",
    "HELD",
    "HOLD_PHASES",
    "HOLD_RECHECK_SECONDS",
    "KEPT",
    "KEPT_CONTINUATION",
    "KEPT_SUMMARY",
    "MAX_ALLOWED_REPOSITORIES",
    "MAX_REPORTED_REPOSITORIES",
    "MAX_WORKTREES_PER_REPORT",
    "OVERRIDES_FILE_NAME",
    "OVERRIDES_SCHEMA",
    "REPOSITORY_SEND_DISCLOSURE_VERSION",
    "SUMMARY",
    "ClearOutcome",
    "HoldCause",
    "HoldDecision",
    "HoldState",
    "HookVariant",
    "RepositoryChoice",
    "RepositoryRecordError",
    "SendHold",
    "add_kept",
    "add_override",
    "clear_overrides",
    "decide",
    "held_worktrees",
    "hook_context",
    "overrides_path",
    "read_overrides",
    "remove_override",
    "repository_key",
    "require_sendable",
]

HELD: Final = "repository_egress_held"
KEPT: Final = "repository_egress_kept"
CONTINUATION: Final = "repository_send_decision_required"
KEPT_CONTINUATION: Final = "repository_kept_on_this_computer"
# The one-line summaries a client surface shows for the two phases, before the directive; the
# same shape as the zero-network summary, for every remote kind.
SUMMARY: Final = (
    "this repository's privacy policy on this computer allows no network use, so FinishUP "
    "refused this connection to the selected FinishUP server before anything from it was sent"
)
KEPT_SUMMARY: Final = (
    "this repository's work is kept on this computer, as its owner chose, so FinishUP refused "
    "this connection to the selected FinishUP server before anything from it was sent"
)
HOLD_PHASES: Final = frozenset({HELD, KEPT})

# The session-start text every host shows for a held or kept repository (ADR-051 decision 8):
# Codex, Claude Code and Cursor receive it byte-identical, for every remote kind alike. One shape
# for both phases, as for every remote phase: what FinishUP did, naming the phase; what that
# means for this session (``HookVariant``); what to do; then the continuation token. Fixed text:
# no path, name, host or URL.
type HookVariant = Literal["attach", "unconsented", "mapped"]
_HOOK_LEADS: Final[dict[str, str]] = {
    HELD: (
        "FinishUP held this repository's work (repository_egress_held): its privacy policy on "
        "this computer allows no network use and the selected FinishUP server is elsewhere"
    ),
    KEPT: (
        "FinishUP kept this repository's work on this computer (repository_egress_kept), as the "
        "user chose for the selected FinishUP server elsewhere"
    ),
}
# What the hold means for this session: an attach that was refused (observations are captured
# and wait in this computer's outbox), a session without observation consent (nothing is
# captured), or a session already mapped to a task on that server.
_HOOK_CONSEQUENCES: Final[dict[HookVariant, str]] = {
    "attach": (
        "so nothing from this repository was sent and no task was started; hook observations "
        "wait on this computer."
    ),
    "unconsented": "so nothing from this repository is sent to it.",
    "mapped": (
        "so this mapped session's task is not updated there and nothing more from this "
        "repository is sent; no live receipt can be promised."
    ),
}
_HOOK_RETRY: Final[dict[HookVariant, str]] = {
    "attach": "Then call start again.",
    "unconsented": "Then call start.",
    "mapped": "Then retry the same request.",
}


def hook_context(phase: str, variant: HookVariant) -> str:
    """The session-start text for a held or kept repository; the same on every host.

    ``variant`` names the session's state: ``attach`` (the hook's own start was refused),
    ``unconsented`` (no observation consent: nothing is captured) or ``mapped`` (a task on that
    server already serves the session). Raises ``ValueError`` for any other phase.
    """

    if phase not in HOLD_PHASES:
        raise ValueError("hold_phase_invalid")
    head = f"{_HOOK_LEADS[phase]}, {_HOOK_CONSEQUENCES[variant]}"
    if phase == HELD:
        return (
            f"{head} Ask the user once in this conversation whether to send this repository's "
            "work to that server anyway; that server's own privacy policy would then decide any "
            "AI-powered review of it. Only if they agree, they run 'finishup server repositories "
            "add' in their own terminal from this repository's folder (tell them which) and type "
            f"the server's name there; you cannot run it. {_HOOK_RETRY[variant]} If they decline, "
            "run 'finishup server repositories keep' from this repository's folder so FinishUP "
            "does not ask again, and continue without FinishUP for this repository. Never run "
            "'add', switch servers or change a privacy policy for the user. Continuation: "
            f"{CONTINUATION}."
        )
    return (
        f"{head} Continue without FinishUP for this repository and do not ask the user about "
        "sending it again. Only the user changes this, with 'finishup server repositories add' "
        "in their own terminal; never run it, switch servers or change a privacy policy for "
        f"them. Continuation: {KEPT_CONTINUATION}."
    )


OVERRIDES_SCHEMA: Final = "yoetz.server-repositories/1"
OVERRIDES_FILE_NAME: Final = "repositories.json"
MAX_ALLOWED_REPOSITORIES: Final = 64
# The version of what 'server repositories add' discloses before the owner allows a repository.
# A new version asks again: an allow made under an older one no longer applies.
REPOSITORY_SEND_DISCLOSURE_VERSION: Final = 1
# How often a long-lived holder (a cached connection, a background agent) re-checks its hold.
HOLD_RECHECK_SECONDS: Final = 1.0

_KEY_DOMAIN: Final = b"yoetz/everyday-repository/v1\x00"
_KEY: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_TARGET_ID: Final = re.compile(r"^t_[0-9a-f]{8}$")
_TIMESTAMP: Final = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"
)
_MAX_RECORD_BYTES: Final = 64 * 1_024
_SEND_FIELDS: Final = frozenset(
    {"choice", "decided_at", "disclosure_version", "key", "no_network_since", "worktree"}
)
_KEEP_FIELDS: Final = frozenset({"choice", "decided_at", "key", "no_network_since", "worktree"})
_REASONS: Final = frozenset(
    {
        "repositories_record_invalid",
        "repositories_record_unsafe",
        "repository_limit",
        "repository_invalid",
    }
)

type HoldState = Literal["held", "kept", "sent_anyway", "not_held", "not_reported"]
type HoldCause = Literal["not_allowed", "grant_changed"]
type Choice = Literal["send", "keep"]
type PolicyRead = Literal["live", "last_reported"]
type ClearOutcome = Literal["absent", "cleared", "repaired"]


class RepositoryRecordError(Exception):
    """A bounded failure of the choices record; ``reason`` is a closed token, never a path."""

    reason: str

    def __init__(self, reason: str) -> None:
        if reason not in _REASONS:
            raise ValueError("repository_reason_invalid")
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class RepositoryChoice:
    """The owner's choice for one repository on one target: ``send`` (allowed anyway, under
    disclosure ``disclosure_version``) or ``keep`` (kept on this computer), made at
    ``decided_at`` while the repository's no-network stretch began at ``no_network_since``."""

    key: str
    choice: Choice
    decided_at: str
    no_network_since: str
    worktree: str
    disclosure_version: int | None = None


@dataclass(frozen=True, slots=True)
class HoldDecision:
    """Whether one repository is held from one target, and why (closed tokens and times only).

    ``reported_at`` is when this computer's everyday FinishUP last reported the repository (None:
    never); ``decided_at`` when the owner's applying choice was made; ``policy_read`` is ``live``
    when the caller just asked this computer's FinishUP, ``last_reported`` otherwise.
    """

    state: HoldState
    cause: HoldCause | None = None
    reported_at: str | None = None
    decided_at: str | None = None
    policy_read: PolicyRead = "last_reported"

    @property
    def phase(self) -> str | None:
        """The remote phase a connection is refused with, or None when it may send."""

        if self.state == "held":
            return HELD
        if self.state == "kept":
            return KEPT
        return None


def repository_key(root: CanonicalWorkspaceRoot) -> str:
    """The client's key for one repository: every linked worktree and subfolder shares it.

    A digest of the canonical identity the everyday service keys its grant by
    (``workspace_identity_preimage``), under this record's own domain; never sent anywhere.
    """

    from finishup.adapters.workspace_root import workspace_identity_preimage

    digest = hashlib.sha256(_KEY_DOMAIN + workspace_identity_preimage(root)).hexdigest()
    return "sha256:" + digest


def overrides_path(root: Path) -> Path:
    """``<target root>/config/repositories.json``."""

    return root / "config" / OVERRIDES_FILE_NAME


# --- the choices record -------------------------------------------------------------------------


def _decode_choice(item: object) -> RepositoryChoice | None:
    if not isinstance(item, dict):
        return None
    fields = cast(dict[str, object], item)
    choice = fields.get("choice")
    key = fields.get("key")
    decided_at = fields.get("decided_at")
    since = fields.get("no_network_since")
    worktree = fields.get("worktree")
    version = fields.get("disclosure_version")
    expected = _SEND_FIELDS if choice == "send" else _KEEP_FIELDS if choice == "keep" else None
    if (
        expected is None
        or frozenset(fields) != expected
        or type(key) is not str
        or not _KEY.match(key)
        or type(decided_at) is not str
        or not _TIMESTAMP.match(decided_at)
        or type(since) is not str
        or not _TIMESTAMP.match(since)
        or not worktree_storable(worktree)
        or (choice == "send" and (type(version) is not int or version < 1))
    ):
        return None
    return RepositoryChoice(
        key,
        cast(Choice, choice),
        decided_at,
        since,
        cast(str, worktree),
        cast(int | None, version),
    )


def _encode(target_id: str, choices: tuple[RepositoryChoice, ...]) -> bytes:
    items: list[JsonValue] = []
    for choice in sorted(choices, key=lambda item: item.key):
        entry: dict[str, JsonValue] = {
            "choice": choice.choice,
            "decided_at": choice.decided_at,
            "key": choice.key,
            "no_network_since": choice.no_network_since,
            "worktree": choice.worktree,
        }
        if choice.choice == "send":
            entry["disclosure_version"] = choice.disclosure_version
        items.append(entry)
    document: dict[str, JsonValue] = {
        "schema": OVERRIDES_SCHEMA,
        "target_id": target_id,
        "repositories": items,
    }
    return canonical_encode(document) + b"\n"


def _decode(encoded: bytes, target_id: str) -> tuple[RepositoryChoice, ...]:
    try:
        if not encoded.endswith(b"\n"):
            raise ValueError("trailer")
        value = strict_json_parse(encoded[:-1])
    except ValueError:
        raise RepositoryRecordError("repositories_record_invalid") from None
    if type(value) is not dict:
        raise RepositoryRecordError("repositories_record_invalid")
    source = cast(dict[str, JsonValue], value)
    items = source.get("repositories")
    if (
        frozenset(source) != frozenset({"schema", "target_id", "repositories"})
        or source.get("schema") != OVERRIDES_SCHEMA
        or source.get("target_id") != target_id
        or type(items) is not list
        or len(cast(list[object], items)) > MAX_ALLOWED_REPOSITORIES
    ):
        raise RepositoryRecordError("repositories_record_invalid")
    choices: list[RepositoryChoice] = []
    for item in cast(list[object], items):
        choice = _decode_choice(item)
        if choice is None:
            raise RepositoryRecordError("repositories_record_invalid")
        choices.append(choice)
    found = tuple(choices)
    if len({choice.key for choice in found}) != len(found) or _encode(target_id, found) != encoded:
        raise RepositoryRecordError("repositories_record_invalid")
    return found


def _read_owner_only(path: Path) -> bytes | None:
    """The bytes of an owner-only regular file; ``None`` when absent; fail closed otherwise."""

    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError:
        raise RepositoryRecordError("repositories_record_unsafe") from None
    try:
        facts = os.fstat(descriptor)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != os.geteuid()
            or stat.S_IMODE(facts.st_mode) & 0o077
            or facts.st_size > _MAX_RECORD_BYTES
        ):
            raise RepositoryRecordError("repositories_record_unsafe")
        chunks: list[bytes] = []
        remaining = _MAX_RECORD_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError:
        raise RepositoryRecordError("repositories_record_unsafe") from None
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    if len(data) > _MAX_RECORD_BYTES:
        raise RepositoryRecordError("repositories_record_unsafe")
    return data


def _write(root: Path, target_id: str, choices: tuple[RepositoryChoice, ...]) -> None:
    """Atomically replace the record (owner-only temporary file, fsync, rename)."""

    path = overrides_path(root)
    try:
        ensure_owner_only_dir(path.parent)
    except PathSafetyError:
        raise RepositoryRecordError("repositories_record_unsafe") from None
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    encoded = _encode(target_id, choices)
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
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
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise RepositoryRecordError("repositories_record_unsafe") from None


def read_overrides(root: Path, target_id: str) -> tuple[RepositoryChoice, ...]:
    """The owner's choices for the target at ``root`` (``()`` when none were made).

    Raises ``RepositoryRecordError`` (``repositories_record_unsafe`` or
    ``repositories_record_invalid``) for a record that is not owner-only, a link, too large,
    malformed, or another target's.
    """

    encoded = _read_owner_only(overrides_path(root))
    if encoded is None:
        return ()
    return _decode(encoded, target_id)


def _record(
    root: Path,
    target_id: str,
    choice: RepositoryChoice,
) -> bool:
    if not _KEY.match(choice.key) or not worktree_storable(choice.worktree):
        raise RepositoryRecordError("repository_invalid")
    current = read_overrides(root, target_id)
    if choice in current:
        return False
    others = tuple(item for item in current if item.key != choice.key)
    if len(others) >= MAX_ALLOWED_REPOSITORIES:
        raise RepositoryRecordError("repository_limit")
    _write(root, target_id, (*others, choice))
    return True


def _now(now: datetime | None) -> str:
    return format_rfc3339_ms((now or datetime.now(UTC)).astimezone(UTC))


def add_override(
    root: Path,
    target_id: str,
    key: str,
    worktree: str,
    no_network_since: str,
    *,
    now: datetime | None = None,
) -> bool:
    """Record that the target at ``root`` receives repository ``key`` anyway, in the no-network
    stretch that began at ``no_network_since``, under the current disclosure. A keep for the
    same repository is replaced. Returns whether anything changed.

    Callers hold ``targets.registry_lock()`` and asked the owner on the trusted console. A damaged
    record is refused, never replaced: ``clear_overrides`` is its way out.
    """

    if not _TIMESTAMP.match(no_network_since):
        raise RepositoryRecordError("repository_invalid")
    current = _choice_for(root, target_id, key)
    if (
        current is not None
        and current.choice == "send"
        and current.no_network_since == no_network_since
        and current.disclosure_version == REPOSITORY_SEND_DISCLOSURE_VERSION
    ):
        return False
    return _record(
        root,
        target_id,
        RepositoryChoice(
            key,
            "send",
            _now(now),
            no_network_since,
            worktree,
            REPOSITORY_SEND_DISCLOSURE_VERSION,
        ),
    )


def add_kept(
    root: Path,
    target_id: str,
    key: str,
    worktree: str,
    no_network_since: str,
    *,
    now: datetime | None = None,
) -> bool:
    """Record that repository ``key`` is kept on this computer for the target at ``root``, in
    the no-network stretch that began at ``no_network_since``: FinishUP does not ask again. An
    allow for the same repository is replaced (this only tightens). Returns whether anything
    changed. Callers hold ``targets.registry_lock()``.
    """

    if not _TIMESTAMP.match(no_network_since):
        raise RepositoryRecordError("repository_invalid")
    current = _choice_for(root, target_id, key)
    if (
        current is not None
        and current.choice == "keep"
        and (current.no_network_since == no_network_since)
    ):
        return False
    return _record(
        root, target_id, RepositoryChoice(key, "keep", _now(now), no_network_since, worktree)
    )


def _choice_for(root: Path, target_id: str, key: str) -> RepositoryChoice | None:
    return next((item for item in read_overrides(root, target_id) if item.key == key), None)


def remove_override(
    root: Path, target_id: str, *, key: str | None = None, worktree: str | None = None
) -> tuple[RepositoryChoice, ...]:
    """Remove the owner's choices for repository ``key``, or for the recorded ``worktree``
    (compared in normal form: a moved or deleted repository); returns what was removed.

    Callers hold ``targets.registry_lock()``. A damaged record is refused: ``clear_overrides``.
    """

    current = read_overrides(root, target_id)
    wanted = None if worktree is None else posixpath.normpath(worktree)
    removed = tuple(
        item
        for item in current
        if (key is not None and item.key == key) or (wanted is not None and item.worktree == wanted)
    )
    if removed:
        _write(root, target_id, tuple(item for item in current if item not in removed))
    return removed


def clear_overrides(root: Path, target_id: str) -> ClearOutcome:
    """Remove every choice for the target at ``root``; the way back from a damaged record.

    ``absent`` when there was nothing to clear; ``cleared`` when a readable record held choices;
    ``repaired`` when a record that could not be read was replaced by an empty one (every
    reported repository that allows no network use is then held, as it already was). A link is
    replaced itself, never its target; anything but a file or a link is refused. Callers hold
    ``targets.registry_lock()``.
    """

    path = overrides_path(root)
    try:
        facts = path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return "absent"
    except OSError:
        raise RepositoryRecordError("repositories_record_unsafe") from None
    if not (stat.S_ISREG(facts.st_mode) or stat.S_ISLNK(facts.st_mode)):
        raise RepositoryRecordError("repositories_record_unsafe")
    try:
        current = read_overrides(root, target_id)
    except RepositoryRecordError:
        _write(root, target_id, ())
        return "repaired"
    if not current:
        return "absent"
    _write(root, target_id, ())
    return "cleared"


# --- deciding ------------------------------------------------------------------------------------

type _Signature = tuple[int, int, int, int, int] | None

_CACHE_LOCK: Final = threading.Lock()
_CACHE: dict[tuple[str, str], tuple[_Signature, object]] = {}


def _signature(path: Path) -> _Signature:
    try:
        facts = path.lstat()
    except OSError:
        return None
    return (facts.st_ino, facts.st_mtime_ns, facts.st_size, facts.st_mode, facts.st_uid)


def _cached[T](kind: str, path: Path, read: Callable[[], T]) -> T:
    """``read()``, reused while ``path`` keeps the same inode, time, size, mode and owner.

    Every write here and in ``client.everyday_policy`` renames a new file into place, so a rewrite
    always changes the signature; a once-a-second re-check costs two ``lstat`` calls.
    """

    signature = _signature(path)
    slot = (kind, os.fspath(path))
    with _CACHE_LOCK:
        found = _CACHE.get(slot)
        if found is not None and signature is not None and found[0] == signature:
            return cast(T, found[1])
    value = read()
    with _CACHE_LOCK:
        if len(_CACHE) > 64:
            _CACHE.clear()
        _CACHE[slot] = (signature, value)
    return value


def _reports() -> tuple[RepositoryReport, ...] | None:
    """The recorded reports, or None when there are none or they cannot be read."""

    try:
        path = reports_path()
    except (OSError, PathSafetyError):
        return None
    reading = _cached("reports", path, read_repository_reports)
    return None if isinstance(reading, str) else reading


def _choices(target_root: Path, target_id: str) -> tuple[RepositoryChoice, ...] | None:
    """The owner's choices for one target, or None when the record cannot be read."""

    def read() -> tuple[RepositoryChoice, ...] | None:
        try:
            return read_overrides(target_root, target_id)
        except RepositoryRecordError:
            return None

    return _cached(f"choices:{target_id}", overrides_path(target_root), read)


def _decision(
    report: RepositoryReport | None, choices: tuple[RepositoryChoice, ...] | None, key: str
) -> HoldDecision:
    if report is None:
        return HoldDecision("not_reported")
    if not report.no_network:
        return HoldDecision("not_held", reported_at=report.reported_at)
    if choices is None:
        return HoldDecision("held", "not_allowed", report.reported_at)
    choice = next((item for item in choices if item.key == key), None)
    if choice is None:
        return HoldDecision("held", "not_allowed", report.reported_at)
    if choice.no_network_since != report.no_network_since:
        return HoldDecision("held", "grant_changed", report.reported_at)
    if choice.choice == "keep":
        return HoldDecision("kept", reported_at=report.reported_at, decided_at=choice.decided_at)
    if choice.disclosure_version != REPOSITORY_SEND_DISCLOSURE_VERSION:
        return HoldDecision("held", "not_allowed", report.reported_at)
    return HoldDecision("sent_anyway", reported_at=report.reported_at, decided_at=choice.decided_at)


def decide(target_root: Path, target_id: str, key: str) -> HoldDecision:
    """Whether repository ``key`` is held from the remote target ``target_id`` at ``target_root``.

    File reads only, never a service; never raises (see the module text for the order).
    """

    try:
        if not everyday_scope():
            return HoldDecision("not_held")
        reports = _reports()
        report = (
            None if reports is None else next((item for item in reports if item.key == key), None)
        )
        choices = None
        if report is not None and report.no_network:
            choices = _choices(target_root, target_id) if _TARGET_ID.match(target_id) else None
        return _decision(report, choices, key)
    except Exception:  # noqa: BLE001 - a decision that cannot be made reads nothing new
        return HoldDecision("not_reported")


@dataclass(frozen=True, slots=True)
class SendHold:
    """One repository's hold on one remote target, re-read on every check.

    A connection keeps it for its life: ``held()`` is true while nothing of that repository may
    be sent to that target (held, or kept on this computer), and ``phase()`` names which. Each
    check reads two small owner-only files, cached by their signature.
    """

    target_root: Path
    target_id: str
    key: str

    def decision(self) -> HoldDecision:
        return decide(self.target_root, self.target_id, self.key)

    def phase(self) -> str | None:
        return self.decision().phase

    def held(self) -> bool:
        return self.phase() is not None

    def refusal(self) -> str | None:
        """The hold as a connection's authorization check (``service.client.AuthorizationCheck``)."""

        return self.phase()


def require_sendable(record: ServerTarget | None, root: CanonicalWorkspaceRoot) -> SendHold | None:
    """Refuse a connection that would send a held or kept repository to remote ``record``.

    Raises ``TargetError("repository_egress_held")`` or ``TargetError("repository_egress_kept")``;
    otherwise returns the ``SendHold`` a long-lived holder re-checks. ``None`` for a record that is
    not remote: a server on this computer applies this computer's own policy to the repository.
    """

    if record is None or not record.is_remote:
        return None
    from finishup.client.targets import TargetError, target_root

    hold = SendHold(target_root(record.target_id), record.target_id, repository_key(root))
    phase = hold.phase()
    if phase is not None:
        raise TargetError(phase)
    return hold


def held_worktrees(target_root: Path, target_id: str) -> tuple[str, ...]:
    """The recorded worktrees of every repository held or kept from that target, now.

    The workspace agent's fence against another repository's reads; a record that cannot be read
    fences nothing extra (unknown is not held). Never raises.
    """

    try:
        if not everyday_scope():
            return ()
        reports = _reports()
        if not reports:
            return ()
        choices = _choices(target_root, target_id) if _TARGET_ID.match(target_id) else None
        found: list[str] = []
        for report in reports:
            if report.no_network and _decision(report, choices, report.key).phase is not None:
                found.extend(report.worktrees)
        return tuple(dict.fromkeys(found))
    except Exception:  # noqa: BLE001 - a fence that cannot be read adds nothing
        return ()
