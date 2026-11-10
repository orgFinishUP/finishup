"""The server's store of repository copies, encrypted at rest (level L2; design v2 §4.3, §8.7, Q4, Q7).

A FinishUP server that keeps a copy of a client's repository keeps it here, under its state
directory, and nowhere else. Nothing reaches this store unless the server's owner enabled a
code-copy offer (``[server.code_copy]``) and a client's owner consented at level L2.

**Ownership (Q7).** One copy per (principal, repository): the principal the session was admitted
as (an API key's principal, or the owner for SSH) and the repository commitment the service keyed
from the client's claim. Both are kept only as domain-separated digests. Every operation names
both; another principal's copy is never listed, read or forgotten.

**Encryption at rest (§8.7, Q4).** Each copy has its own random 256-bit data key; every object,
every snapshot manifest and the copy's object index are AES-256-GCM frames under it, bound to the
copy and the object by their associated data. The data key is stored only wrapped (AES key wrap,
RFC 3394) by a key the vault holds for that copy (``CopyKeyring``): a locked vault reads and admits
nothing. The wrapping record is versioned (``yoetz.code-copy-wrap/1``). An upload being received is
staged encrypted under a key that lives only in this process's memory, so a crash leaves only
ciphertext no one can read, removed at the next start. Relocking the vault does not erase
plaintext a server owner already copied out of a running service; the docs say so.

**Admission (crash-safe).** ``begin_upload`` records the copy's forget epoch; ``append`` adds
chunks in order; ``commit`` decrypts the staged bundle, checks its digest, verifies it with the
same verifier the client's audit ran (``protocol.server_copy.verify_snapshot_bundle``) against the
objects this copy holds, checks the manifest against what was verified and against the revision and
claim the service names, applies the quotas (what they still allow is also the budget the pack's
objects may inflate to, checked before each is inflated), and publishes a new committed
**generation**: an admission journal (``admission.json``: the objects it creates, a new snapshot's
manifest, the next generation) first, then the objects, the manifest and the generation's own index
(``index.<n>.enc``), and the copy record naming that generation last (each to a temporary file,
fsynced, renamed). The record is the commit point: until it is written the previous generation (its
index, its ``stored_bytes``) is in force, and what the journal names is removed at once after a
failure and at the next start after a crash, so no byte is ever kept outside the quota accounting
and no later upload can treat an uncommitted object as held.

**Forget (§4.3, U20, §8.7).** ``forget`` first advances the copy's **epoch** in the tombstone record
(fsynced), so an upload begun before it is refused at ``commit`` (``code_copy_forgotten``), records
the pinned tasks' erasures (every one or none), then deletes the copy's folder durably: the record
with the wrapped key first (fsynced), then objects, manifests and index, then the ``copies`` folder
is fsynced, before the forget is acknowledged. Each record carries the epoch it was written under, so
a copy whose record is older than its tombstone (a forget a power loss or a failed deletion
interrupted, or one the erasure bound kept) is read by nothing and finished at start and at every
expiry run; no new copy is made over it. It is idempotent and its report says exactly what it
deleted and whether anything is left (``complete``); copies of the server's folder in backups its
owner made are not managed here (``backups: not_managed``). Derived excerpts kept in task records
(captured diffs, review excerpts) are not in this store.

**Expiry (§4.3, U11).** ``expire`` forgets copies whose retention ran out: ``days:N`` after N days
without a sync; ``task_close`` once every task pinned to the copy closed; ``until_forgotten`` never.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import shutil
import stat
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final, Literal, Protocol, cast

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from finishup.config.installation import format_rfc3339_ms, parse_rfc3339_ms
from finishup.domain.evidence_provenance import (
    EVIDENCE_PROVENANCE_TOKENS,
    EvidenceProvenance,
    EvidenceToken,
    evidence_provenance_from_json,
)
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.server_copy import (
    BundleLimits,
    CopyError,
    GitObject,
    Held,
    SnapshotManifest,
    held_from_json,
    held_to_json,
    manifest_digest,
    manifest_from_json,
    manifest_to_json,
    verify_snapshot_bundle,
)

__all__ = [
    "COPY_SCHEMA",
    "WRAP_SCHEMA",
    "CodeStore",
    "CodeStoreError",
    "CopyKeyring",
    "CopySummary",
    "ForgetReport",
    "ForgottenTask",
    "PendingErasure",
    "PinEntry",
    "StoreLimits",
    "UploadReceipt",
    "WrappedKey",
]

COPY_SCHEMA: Final = "yoetz.code-copy/1"
WRAP_SCHEMA: Final = "yoetz.code-copy-wrap/1"
_TOMBSTONE_SCHEMA: Final = "yoetz.code-copy-tombstones/1"
_ERASURE_SCHEMA: Final = "yoetz.code-copy-erasures/1"
_JOURNAL_SCHEMA: Final = "yoetz.code-copy-admission/1"
_JOURNAL: Final = "admission.json"
_PRINCIPAL_DOMAIN: Final = b"yoetz/code-copy-principal/v1\x00"
_REPOSITORY_DOMAIN: Final = b"yoetz/code-copy-repository/v1\x00"
_COPY_DOMAIN: Final = b"yoetz/code-copy-key/v1\x00"
_OBJECT_AAD: Final = b"yoetz/code-object/v1\x00"
_MANIFEST_AAD: Final = b"yoetz/code-snapshot/v1\x00"
_INDEX_AAD: Final = b"yoetz/code-index/v1\x00"
_STAGE_AAD: Final = b"yoetz/code-upload/v1\x00"
_FRAME_MAGIC: Final = b"FUC1"
_MAX_SNAPSHOTS: Final = 64
_MAX_HAVE: Final = 16
_MAX_PINS: Final = 1_024
# Forgotten tasks whose derived excerpts are still to be erased (bounded; see ``PendingErasure``).
_MAX_PENDING_ERASURES: Final = 4_096
_MAX_READ_COUNT: Final = 1_000_000_000
_MAX_UPLOADS: Final = 8
_UPLOAD_SECONDS: Final = 600.0
_TOMBSTONE_DAYS: Final = 2
_HEX40: Final = re.compile(r"^[0-9a-f]{40}$")
_HEX64: Final = re.compile(r"^[0-9a-f]{64}$")
_UPLOAD_ID: Final = re.compile(r"^[0-9a-f]{32}$")
_TASK_ID: Final = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_DIGEST: Final = re.compile(r"^sha256:[0-9a-f]{64}$")

type RetentionKind = Literal["task_close", "days", "until_forgotten"]


class CodeStoreError(Exception):
    """A refused store operation; ``reason`` is a closed token, never input text."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class WrappedKey:
    """A copy's data key wrapped by the vault's key for that copy (``yoetz.code-copy-wrap/1``)."""

    algorithm: Literal["aes-256-kw-rfc3394"]
    key_slot: str
    wrapped: bytes = field(repr=False)


class CopyKeyring(Protocol):
    """The vault's keys for copies: one per copy, created on first use, discarded on forget.

    ``wrap`` and ``unwrap`` raise ``CodeStoreError("vault_locked")`` while the vault is not
    ready; ``discard`` never raises.
    """

    def wrap(self, copy_id: str, data_key: bytes) -> WrappedKey: ...

    def unwrap(self, copy_id: str, wrapped: WrappedKey) -> bytes: ...

    def discard(self, copy_id: str) -> None: ...


@dataclass(frozen=True, slots=True)
class StoreLimits:
    """Caps from the server's offer: per file and per checkout (``code_sync``), and the storage
    quotas derived from them (per copy and per principal)."""

    max_file_bytes: int
    max_repo_bytes: int
    max_bundle_bytes: int = 67_108_864

    @property
    def copy_quota(self) -> int:
        return 4 * self.max_repo_bytes

    @property
    def principal_quota(self) -> int:
        return 16 * self.max_repo_bytes


@dataclass(frozen=True, slots=True)
class UploadReceipt:
    """What ``commit`` admitted."""

    snapshot: str
    manifest_digest: str
    new_bytes: int
    stored_bytes: int


@dataclass(frozen=True, slots=True)
class CopySummary:
    """One copy as ``finishup server code list`` shows it: no path, no name."""

    repository: str
    snapshots: int
    stored_bytes: int
    created_at: str
    last_sync_at: str | None
    retention_kind: RetentionKind
    retention_days: int | None


@dataclass(frozen=True, slots=True)
class PinEntry:
    """One task's pin in a copy (design v2 §8.6): the snapshot its later reads read, when the
    server last synced it for the task, whether the task's evidence is read from the copy
    (``served``), whether that snapshot was served while the client was offline (``stale``: the
    copy as last synced, so the reads that follow it are stale reads too), and how many of the
    task's evidence reads each source answered."""

    snapshot: str
    synced_at: str | None = None
    served: bool = False
    reads: Mapping[EvidenceToken, int] = field(default_factory=lambda: {})
    fenced: int = 0
    stale: bool = False

    def account(self) -> EvidenceProvenance:
        """The task's evidence account as this pin records it (no snapshot, no marker)."""

        return EvidenceProvenance(self.reads, self.fenced)


@dataclass(frozen=True, slots=True)
class ForgottenTask:
    """A task pinned to a copy that was forgotten, and its evidence account at that moment."""

    task_id: str
    account: EvidenceProvenance


@dataclass(frozen=True, slots=True)
class PendingErasure:
    """A forgotten task whose derived excerpts are still to be erased from its records (U20).

    Written, owner-only, before the copy is deleted; cleared once the task's records say the
    content was forgotten (``CodeStore.complete_erasure``), so a crash in between is retried."""

    forget_id: str
    reason: str
    task_id: str
    account: EvidenceProvenance
    forgotten_at: str


@dataclass(frozen=True, slots=True)
class ForgetReport:
    """Exactly what one ``forget`` deleted (U20); ``backups`` is always ``not_managed``.

    ``left`` counts what this forget could not finish yet: a copy kept because the erasure of
    its tasks' excerpts could not be recorded first (``code_copy_erasure_backlog``), or a deletion
    that failed. Such a forget is never complete (``complete``, on the wire): the copy stays
    fenced and is forgotten again by the next forget, and nothing it left reads as deleted.

    ``tasks`` names the tasks pinned to the copies deleted, for the erasure of what their records
    derived from them; it never crosses the wire (``to_json``), nor does ``keys``, the copies
    deleted (their checkouts go too)."""

    copies: int = 0
    snapshots: int = 0
    objects: int = 0
    bytes: int = 0
    reason: str = "owner"
    backups: str = "not_managed"
    tasks: tuple[ForgottenTask, ...] = ()
    left: int = 0
    keys: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return self.left == 0

    def plus(self, other: ForgetReport) -> ForgetReport:
        return ForgetReport(
            self.copies + other.copies,
            self.snapshots + other.snapshots,
            self.objects + other.objects,
            self.bytes + other.bytes,
            self.reason,
            tasks=(*self.tasks, *other.tasks),
            left=self.left + other.left,
            keys=(*self.keys, *other.keys),
        )

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "copies": self.copies,
            "snapshots": self.snapshots,
            "objects": self.objects,
            "bytes": self.bytes,
            "reason": self.reason,
            "backups": self.backups,
            "complete": self.complete,
        }


@dataclass(slots=True)
class _Upload:
    copy_key: str
    principal: str
    repository: str
    epoch: int
    size: int
    sha256: str
    manifest: bytes = field(repr=False)
    retention: tuple[RetentionKind, int | None]
    key: bytes = field(repr=False)
    received: int = 0
    started: float = 0.0


def _digest(domain: bytes, value: str) -> str:
    if type(value) is not str or not value or len(value) > 512:
        raise CodeStoreError("code_copy_owner_invalid")
    return hashlib.sha256(domain + value.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(UTC)


class CodeStore:
    """The copies a server keeps (see the module text). Thread-safe; every method is blocking."""

    __slots__ = ("_clock", "_keyring", "_limits", "_lock", "_root", "_tombstone_cache", "_uploads")

    def __init__(
        self,
        root: Path,
        keyring: CopyKeyring,
        limits: StoreLimits,
        *,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        self._root = root
        self._keyring = keyring
        self._limits = limits
        self._clock = clock
        self._lock = threading.RLock()
        self._uploads: dict[str, _Upload] = {}
        # The tombstone record as last read or written by this store (its only writer).
        self._tombstone_cache: dict[str, dict[str, JsonValue]] | None = None

    # --- layout -------------------------------------------------------------------------------

    def open(self) -> None:
        """Create the folders (owner-only, never through a link) and remove what a crash left:
        staged uploads and temporary files. Run once at service start."""

        with self._lock:
            for folder in (self._root, self._root / "copies", self._root / "uploads"):
                _private_directory(folder)
            for leftover in (self._root / "uploads").iterdir():
                _remove_file(leftover)
            self._tombstone_cache = None
            for copy in (self._root / "copies").iterdir():
                if not copy.is_dir() or copy.is_symlink():
                    continue
                for path in copy.rglob(".*.tmp"):
                    _remove_file(path)
            # A first admission that stopped before its record (never a copy), a deletion that
            # stopped part way, and a copy a forget already fenced (its epoch is older than its
            # tombstone's: a forget interrupted before its deletion was durable) all go now.
            self._reconcile()
            if "*" in self._tombstones():
                # Uploads live in memory only, so none is in flight at start: start again.
                document: dict[str, JsonValue] = {"schema": _TOMBSTONE_SCHEMA, "epochs": {}}
                self._write_tombstones(document)

    def _reconcile(self) -> ForgetReport:
        """Finish every forget a crash, a failed deletion or the erasure bound interrupted (see
        ``open``); also run by every expiry run. Called with the lock held."""

        report = ForgetReport(reason="reconciled")
        folder = self._root / "copies"
        if not folder.is_dir():
            return report
        for copy in sorted(folder.iterdir()):
            if not copy.is_dir() or copy.is_symlink() or not _HEX64.match(copy.name * 2):
                continue
            if not (copy / "copy.json").is_file():
                if _delete_folder(copy, folder):
                    report = report.plus(ForgetReport(reason="reconciled"))
                else:
                    report = report.plus(ForgetReport(reason="reconciled", left=1))
                continue
            data = _read_private(copy / "copy.json", 1_048_576)
            try:
                value = strict_json_parse(data or b"")
            except ValueError:
                continue
            if type(value) is not dict:
                continue
            record = cast(dict[str, JsonValue], value)
            copy_key = record.get("copy_key")
            if type(copy_key) is not str or not _HEX64.match(copy_key):
                continue
            if copy_key[:32] != copy.name:
                continue
            if self._forgotten(copy_key, record):
                found = self._forget_one(copy_key, "reconciled", advance=False)
                report = report.plus(replace(found, reason="reconciled"))
            else:
                # An admission that stopped before its record: back to the committed generation.
                self._recover(copy_key)
        return report

    def _copy_folder(self, copy_key: str) -> Path:
        return self._root / "copies" / copy_key[:32]

    def holds(self, copy_key: str) -> bool:
        """Whether the copy ``copy_key`` names exists (its record was written)."""

        return (self._copy_folder(copy_key) / "copy.json").is_file()

    def holds_folder(self, name: str) -> bool:
        """Whether the copy folder ``name`` (a copy key's first 32 hex) holds a copy: how a
        checkout found on disk is known to belong to a copy that is still kept."""

        if len(name) != 32 or not _HEX64.match(name * 2):
            return False
        return (self._root / "copies" / name / "copy.json").is_file()

    @staticmethod
    def repository_id(repository: str) -> str:
        """The digest a copy's record names ``repository`` by."""

        return _digest(_REPOSITORY_DOMAIN, repository)

    @staticmethod
    def copy_key(principal: str, repository: str) -> str:
        """The key of the copy of ``repository`` kept for ``principal``."""

        principal_id = _digest(_PRINCIPAL_DOMAIN, principal)
        repository_id = _digest(_REPOSITORY_DOMAIN, repository)
        return hashlib.sha256(
            _COPY_DOMAIN + principal_id.encode() + b"\x00" + repository_id.encode()
        ).hexdigest()

    # --- records ------------------------------------------------------------------------------

    def _read_record(
        self, copy_key: str, *, forgotten: bool = False
    ) -> dict[str, JsonValue] | None:
        """The copy's record, or None: no copy, or (unless ``forgotten``) a copy a forget
        already fenced whose deletion is not finished (reads, syncs and pins reject it)."""

        path = self._copy_folder(copy_key) / "copy.json"
        data = _read_private(path, 1_048_576)
        if data is None:
            return None
        try:
            value = strict_json_parse(data)
        except ValueError:
            raise CodeStoreError("code_copy_record_invalid") from None
        if type(value) is not dict:
            raise CodeStoreError("code_copy_record_invalid")
        record = cast(dict[str, JsonValue], value)
        if record.get("schema") != COPY_SCHEMA or record.get("copy_key") != copy_key:
            raise CodeStoreError("code_copy_record_invalid")
        if not forgotten and self._forgotten(copy_key, record):
            return None
        return record

    def _write_record(self, copy_key: str, record: dict[str, JsonValue]) -> None:
        _write_private(self._copy_folder(copy_key) / "copy.json", canonical_encode(record))

    def _tombstones(self) -> dict[str, dict[str, JsonValue]]:
        if self._tombstone_cache is not None:
            return self._tombstone_cache
        data = _read_private(self._root / "tombstones.json", 4_194_304)
        if data is None:
            self._tombstone_cache = {}
            return self._tombstone_cache
        try:
            value = cast(dict[str, JsonValue], strict_json_parse(data))
            if value.get("schema") != _TOMBSTONE_SCHEMA:
                raise ValueError("schema")
            epochs = cast(dict[str, dict[str, JsonValue]], value["epochs"])
            if type(epochs) is not dict:
                raise TypeError("epochs")
        except (ValueError, KeyError, TypeError, AttributeError):
            # A record that cannot be read fences every upload in flight: their epochs are lost.
            return {"*": {"epoch": secrets.randbelow(1 << 30) + 1}}
        self._tombstone_cache = epochs
        return epochs

    def _write_tombstones(self, document: dict[str, JsonValue]) -> None:
        self._tombstone_cache = None
        _write_private(self._root / "tombstones.json", canonical_encode(document))
        self._tombstone_cache = cast(dict[str, dict[str, JsonValue]], document["epochs"])

    def _forgotten(self, copy_key: str, record: Mapping[str, JsonValue]) -> bool:
        """Whether a forget fenced this copy after its record was written: its tombstone's epoch
        is newer than the record's (a record written before epochs were recorded: forgotten
        after its last sync). An unreadable tombstone record forgets nothing here."""

        epochs = self._tombstones()
        if "*" in epochs:
            return False
        tombstone = epochs.get(copy_key)
        if type(tombstone) is not dict:
            return False
        epoch = tombstone.get("epoch")
        if type(epoch) is not int:
            return False
        if "epoch" in record:
            return epoch > _record_epoch(record)
        stamp = record.get("last_sync_at") or record.get("created_at")
        forgotten_at = tombstone.get("forgotten_at")
        return type(stamp) is str and type(forgotten_at) is str and forgotten_at > stamp

    def _epoch(self, copy_key: str) -> int:
        epochs = self._tombstones()
        if "*" in epochs:
            return cast(int, epochs["*"]["epoch"])
        return cast(int, epochs.get(copy_key, {}).get("epoch", 0))

    def _advance_epoch(self, copy_key: str, reason: str, *, floor: int = 0) -> int:
        """The copy's next epoch, recorded (fsynced) before anything of it is deleted; never
        below ``floor`` (the record's own epoch, so a pruned tombstone never lowers it)."""

        epochs = {key: value for key, value in self._tombstones().items() if key != "*"}
        now = self._clock()
        cutoff = now - timedelta(days=_TOMBSTONE_DAYS)
        kept: dict[str, JsonValue] = {}
        for key, value in epochs.items():
            try:
                stamp = parse_rfc3339_ms(value.get("forgotten_at"))
            except ValueError:
                continue
            if stamp >= cutoff or key == copy_key:
                kept[key] = value
        previous = cast(dict[str, JsonValue], kept.get(copy_key, {}))
        epoch = max(cast(int, previous.get("epoch", 0)), floor) + 1
        kept[copy_key] = {
            "epoch": epoch,
            "forgotten_at": format_rfc3339_ms(now),
            "reason": reason,
        }
        document: dict[str, JsonValue] = {"schema": _TOMBSTONE_SCHEMA, "epochs": kept}
        self._write_tombstones(document)
        return epoch

    # --- keys and frames ----------------------------------------------------------------------

    def _data_key(self, copy_key: str, record: Mapping[str, JsonValue]) -> bytes:
        wrap = cast(dict[str, JsonValue], record["wrap"])
        if wrap.get("schema") != WRAP_SCHEMA or wrap.get("algorithm") != "aes-256-kw-rfc3394":
            raise CodeStoreError("code_copy_wrap_unknown")
        wrapped = WrappedKey(
            "aes-256-kw-rfc3394",
            cast(str, wrap["key_slot"]),
            bytes.fromhex(cast(str, wrap["wrapped"])),
        )
        key = self._keyring.unwrap(cast(str, record["copy_id"]), wrapped)
        if len(key) != 32:
            raise CodeStoreError("code_copy_wrap_unknown")
        return key

    @staticmethod
    def _seal(key: bytes, aad: bytes, plain: bytes) -> bytes:
        nonce = os.urandom(12)
        return _FRAME_MAGIC + nonce + AESGCM(key).encrypt(nonce, plain, aad)

    @staticmethod
    def _open_frame(key: bytes, aad: bytes, frame: bytes) -> bytes:
        if len(frame) < 32 or frame[:4] != _FRAME_MAGIC:
            raise CodeStoreError("code_copy_corrupt")
        try:
            return AESGCM(key).decrypt(frame[4:16], frame[16:], aad)
        except InvalidTag:
            raise CodeStoreError("code_copy_corrupt") from None

    def _index(
        self, copy_key: str, key: bytes, record: Mapping[str, JsonValue]
    ) -> dict[str, list[JsonValue]]:
        """The object index of the record's committed generation (never one an admission that
        did not commit wrote)."""

        generation = _generation(record)
        path = self._copy_folder(copy_key) / _index_name(generation)
        frame = _read_private(path, 1 << 30)
        if frame is None:
            return {}
        plain = self._open_frame(key, _index_aad(copy_key, generation), frame)
        return cast(dict[str, list[JsonValue]], strict_json_parse(plain))

    def _recover(self, copy_key: str) -> bool:
        """Bring the copy's folder back to its committed generation (``_admit``): what an
        admission that stopped before its record (a crash, a failure) added goes, and what one
        that committed left to clean up is cleaned up. True when nothing is left to recover."""

        folder = self._copy_folder(copy_key)
        record = self._read_record(copy_key, forgotten=True)
        if record is None:
            return True
        committed = _generation(record)
        journal_path = folder / _JOURNAL
        data = _read_private(journal_path, 16_777_216)
        if data is not None:
            try:
                journal = cast(dict[str, JsonValue], strict_json_parse(data))
                if journal.get("schema") != _JOURNAL_SCHEMA:
                    raise ValueError("schema")
                target = journal["generation"]
                created = journal["objects"]
                snapshot = journal["snapshot"]
                if (
                    type(target) is not int
                    or type(created) is not list
                    or (snapshot is not None and type(snapshot) is not str)
                ):
                    raise TypeError("journal")
            except (ValueError, KeyError, TypeError, AttributeError):
                return False  # which additions were uncommitted is not known: nothing is trusted
            if target > committed:
                for oid in cast(list[JsonValue], created):
                    if type(oid) is str and _HEX40.match(oid):
                        _remove_file(folder / "objects" / oid)
                if snapshot is not None and snapshot not in cast(list[str], record["snapshots"]):
                    if _HEX40.match(snapshot):
                        _remove_file(folder / "snapshots" / f"{snapshot}.enc")
        keep = _index_name(committed)
        for path in folder.iterdir():
            if path.name.startswith("index.") and path.name.endswith(".enc") and path.name != keep:
                _remove_file(path)
        _drop_manifests(folder, record)
        try:
            for below in (folder / "objects", folder / "snapshots", folder):
                if below.is_dir():
                    _fsync_directory(below)
            if data is not None:
                os.unlink(journal_path)
                _fsync_directory(folder)
        except OSError:
            return False
        return True

    # --- uploads ------------------------------------------------------------------------------

    def epoch(self, principal: str, repository: str) -> int:
        """The copy's forget epoch now (it advances with every forget of the copy)."""

        with self._lock:
            return self._epoch(self.copy_key(principal, repository))

    def have(self, principal: str, repository: str) -> tuple[str, ...]:
        """The newest snapshot commits this copy holds (the have-set a sync is made against)."""

        with self._lock:
            record = self._read_record(self.copy_key(principal, repository))
            if record is None:
                return ()
            snapshots = cast(list[str], record["snapshots"])
            return tuple(snapshots[-_MAX_HAVE:])

    def begin_upload(
        self,
        principal: str,
        repository: str,
        *,
        manifest: bytes,
        size: int,
        sha256: str,
        retention: tuple[RetentionKind, int | None],
        epoch: int | None = None,
    ) -> str:
        """Start receiving a bundle of ``size`` bytes; its id.

        ``epoch`` is the copy's forget epoch when the sync began (``epoch``, read before the
        client was asked to prepare): a forget since then refuses the upload now
        (``code_copy_forgotten``). Without one, the epoch is recorded now.
        """

        if type(size) is not int or not 0 < size <= self._limits.max_bundle_bytes:
            raise CodeStoreError("code_copy_too_large")
        if type(sha256) is not str or not _DIGEST.match(sha256):
            raise CodeStoreError("code_upload_invalid")
        kind, days = retention
        if kind not in {"task_close", "days", "until_forgotten"} or (
            (kind == "days") != (isinstance(days, int) and 0 <= days <= 36_500)
        ):
            raise CodeStoreError("code_upload_invalid")
        copy_key = self.copy_key(principal, repository)
        with self._lock:
            self._expire_uploads()
            current = self._epoch(copy_key)
            if epoch is not None and epoch != current:
                raise CodeStoreError("code_copy_forgotten")
            if len(self._uploads) >= _MAX_UPLOADS:
                raise CodeStoreError("code_upload_busy")
            upload_id = secrets.token_hex(16)
            self._uploads[upload_id] = _Upload(
                copy_key=copy_key,
                principal=principal,
                repository=repository,
                epoch=current,
                size=size,
                sha256=sha256,
                manifest=manifest,
                retention=retention,
                key=AESGCM.generate_key(bit_length=256),
                started=self._clock().timestamp(),
            )
            _write_private(self._root / "uploads" / f"{upload_id}.part", b"")
            return upload_id

    def _expire_uploads(self) -> None:
        now = self._clock().timestamp()
        for upload_id, upload in list(self._uploads.items()):
            if now - upload.started > _UPLOAD_SECONDS:
                self._drop_upload(upload_id)

    def _drop_upload(self, upload_id: str) -> None:
        self._uploads.pop(upload_id, None)
        _remove_file(self._root / "uploads" / f"{upload_id}.part")

    def _upload(self, upload_id: str, principal: str, repository: str) -> _Upload:
        upload = self._uploads.get(upload_id) if _UPLOAD_ID.match(upload_id or "") else None
        if upload is None or upload.copy_key != self.copy_key(principal, repository):
            raise CodeStoreError("code_upload_unknown")
        return upload

    def append(
        self, upload_id: str, principal: str, repository: str, offset: int, chunk: bytes
    ) -> int:
        """Stage the next ``chunk`` (encrypted) at ``offset``; the bytes received so far."""

        with self._lock:
            upload = self._upload(upload_id, principal, repository)
            if offset != upload.received or not chunk or upload.received + len(chunk) > upload.size:
                self._drop_upload(upload_id)
                raise CodeStoreError("code_upload_out_of_order")
            frame = self._seal(
                upload.key, _STAGE_AAD + upload_id.encode() + str(offset).encode(), chunk
            )
            path = self._root / "uploads" / f"{upload_id}.part"
            descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.write(descriptor, len(frame).to_bytes(4, "big") + frame)
            finally:
                os.close(descriptor)
            upload.received += len(chunk)
            return upload.received

    def _staged(self, upload_id: str, upload: _Upload) -> bytes:
        data = _read_private(self._root / "uploads" / f"{upload_id}.part", 1 << 31)
        if data is None:
            raise CodeStoreError("code_upload_unknown")
        chunks: list[bytes] = []
        position = 0
        offset = 0
        while position < len(data):
            length = int.from_bytes(data[position : position + 4], "big")
            frame = data[position + 4 : position + 4 + length]
            chunk = self._open_frame(
                upload.key, _STAGE_AAD + upload_id.encode() + str(offset).encode(), frame
            )
            chunks.append(chunk)
            offset += len(chunk)
            position += 4 + length
        return b"".join(chunks)

    def commit(
        self,
        upload_id: str,
        principal: str,
        repository: str,
        *,
        revision: tuple[str, int, str],
        worktree: str,
    ) -> UploadReceipt:
        """Verify and admit a fully received upload (see the module text)."""

        with self._lock:
            upload = self._upload(upload_id, principal, repository)
            try:
                return self._commit(upload_id, upload, revision=revision, worktree=worktree)
            finally:
                self._drop_upload(upload_id)

    def _commit(
        self, upload_id: str, upload: _Upload, *, revision: tuple[str, int, str], worktree: str
    ) -> UploadReceipt:
        if upload.received != upload.size:
            raise CodeStoreError("code_upload_incomplete")
        bundle = self._staged(upload_id, upload)
        if "sha256:" + hashlib.sha256(bundle).hexdigest() != upload.sha256:
            raise CodeStoreError("code_upload_digest_mismatch")
        try:
            manifest = manifest_from_json(upload.manifest)
        except CopyError as error:
            raise CodeStoreError("code_manifest_invalid") from error
        if (manifest.issuer, manifest.revision, manifest.profile_digest) != revision:
            raise CodeStoreError("server_profile_changed")
        if manifest.worktree != worktree:
            raise CodeStoreError("code_manifest_mismatch")
        if self._epoch(upload.copy_key) != upload.epoch:
            raise CodeStoreError("code_copy_forgotten")
        record = self._read_record(upload.copy_key)
        if record is None and os.path.lexists(self._copy_folder(upload.copy_key)):
            # What a forget fenced (or a deletion left) goes before a new copy is made there.
            left = self._forget_one(upload.copy_key, "reconciled", advance=False).left
            if left or os.path.lexists(self._copy_folder(upload.copy_key)):
                raise CodeStoreError("code_copy_erasure_backlog")
        if record is not None:
            if not self._recover(upload.copy_key):
                raise CodeStoreError("code_copy_record_invalid")
            key = self._data_key(upload.copy_key, record)
            return self._admit(
                upload, manifest, bundle, record, key, self._index(upload.copy_key, key, record)
            )
        record, key = self._new_copy(upload.copy_key, upload.principal, upload.repository)
        try:
            return self._admit(upload, manifest, bundle, record, key, {})
        except BaseException:
            # Nothing of a copy that was never admitted stays: its folder and its vault key.
            shutil.rmtree(self._copy_folder(upload.copy_key), ignore_errors=True)
            self._keyring.discard(cast(str, record["copy_id"]))
            raise

    def _admit(
        self,
        upload: _Upload,
        manifest: SnapshotManifest,
        bundle: bytes,
        record: dict[str, JsonValue],
        key: bytes,
        index: dict[str, list[JsonValue]],
    ) -> UploadReceipt:

        def have(oid: str) -> Held | None:
            entry = index.get(oid)
            return None if entry is None else held_from_json(entry)

        # What the copy's and the principal's quotas still allow bounds the bytes the pack may
        # inflate to, checked before each object is inflated (a hostile pack never allocates
        # more than the quota it would be refused for afterwards).
        budget = max(
            0,
            min(
                self._limits.copy_quota - cast(int, record["stored_bytes"]),
                self._limits.principal_quota - self._principal_bytes(upload.principal),
            ),
        )
        try:
            verified = verify_snapshot_bundle(
                bundle,
                have=have,
                limits=BundleLimits(
                    max_file_bytes=self._limits.max_file_bytes,
                    max_bundle_bytes=self._limits.max_bundle_bytes,
                    max_inflated_bytes=budget,
                ),
            )
        except CopyError as error:
            if error.reason == "pack_over_budget":
                raise CodeStoreError("code_copy_over_quota") from error
            raise CodeStoreError("code_bundle_invalid") from error
        if (
            verified.snapshot != manifest.snapshot
            or verified.base != manifest.base
            or verified.tree != manifest.tree
            or verified.base_tree != manifest.base_tree
            or verified.tree_bytes != manifest.bytes
            or verified.tree_files != manifest.files
        ):
            raise CodeStoreError("code_manifest_mismatch")
        if verified.tree_bytes > self._limits.max_repo_bytes:
            raise CodeStoreError("code_copy_too_large")
        stored = cast(int, record["stored_bytes"])
        if stored + verified.new_bytes > self._limits.copy_quota:
            raise CodeStoreError("code_copy_over_quota")
        if (
            self._principal_bytes(upload.principal) + verified.new_bytes
            > self._limits.principal_quota
        ):
            raise CodeStoreError("code_copy_over_quota")
        folder = self._copy_folder(upload.copy_key)
        objects_folder = folder / "objects"
        _private_directory(objects_folder)
        _private_directory(folder / "snapshots")
        # A committed generation is published atomically: the journal names what this admission
        # adds (objects it creates, a new snapshot's manifest, the next index) before any of it
        # is written, and the record naming the new generation is the commit point; until then
        # the previous generation is in force, and ``_recover`` removes the additions.
        generation = _generation(record) + 1
        known = manifest.snapshot in cast(list[str], record["snapshots"])
        created: list[JsonValue] = [
            oid for oid in sorted(verified.objects) if not (objects_folder / oid).exists()
        ]
        journal: dict[str, JsonValue] = {
            "schema": _JOURNAL_SCHEMA,
            "generation": generation,
            "objects": created,
            "snapshot": None if known else manifest.snapshot,
        }
        _write_private(folder / _JOURNAL, canonical_encode(journal))
        encoded = canonical_encode(manifest_to_json(manifest))
        sealed = self._seal(
            key, _MANIFEST_AAD + upload.copy_key.encode() + manifest.snapshot.encode(), encoded
        )
        try:
            for oid, item in verified.objects.items():
                self._write_object(upload.copy_key, key, objects_folder, item)
                index[oid] = held_to_json(verified.held[oid])
            if not known:
                _write_private(folder / "snapshots" / f"{manifest.snapshot}.enc", sealed)
            _write_private(
                folder / _index_name(generation),
                self._seal(
                    key,
                    _index_aad(upload.copy_key, generation),
                    canonical_encode(cast(JsonValue, index)),
                ),
            )
            snapshots = [
                item for item in cast(list[str], record["snapshots"]) if item != manifest.snapshot
            ]
            snapshots.append(manifest.snapshot)
            kind, days = upload.retention
            record.update(
                {
                    "snapshots": cast(JsonValue, _window(snapshots, record)),
                    "stored_bytes": stored + verified.new_bytes,
                    "objects": len(index),
                    "last_sync_at": format_rfc3339_ms(self._clock()),
                    "retention": {"kind": kind, "days": days},
                    "epoch": max(_record_epoch(record), upload.epoch),
                    "generation": generation,
                }
            )
            self._write_record(upload.copy_key, record)
        except BaseException:
            try:
                self._recover(upload.copy_key)
            except CodeStoreError:
                pass  # the journal stays: the next admission or the next start rolls it back
            raise
        try:
            if known:
                # A snapshot synced again: its manifest's metadata, once the generation committed.
                _write_private(folder / "snapshots" / f"{manifest.snapshot}.enc", sealed)
            self._recover(upload.copy_key)  # the superseded index and the journal go
        except CodeStoreError:
            pass  # committed; what is left to clean is cleaned by the next admission or start
        return UploadReceipt(
            manifest.snapshot,
            manifest_digest(manifest),
            verified.new_bytes,
            stored + verified.new_bytes,
        )

    def _write_object(self, copy_key: str, key: bytes, folder: Path, item: GitObject) -> None:
        path = folder / item.oid
        if path.exists():
            return
        aad = _OBJECT_AAD + copy_key.encode() + b"\x00" + item.oid.encode()
        _write_private(path, self._seal(key, aad, item.kind.encode() + b"\x00" + item.data))

    def _new_copy(
        self, copy_key: str, principal: str, repository: str
    ) -> tuple[dict[str, JsonValue], bytes]:
        """A new copy's record and data key; written only once its first snapshot is admitted."""

        copy_id = secrets.token_hex(16)
        key = AESGCM.generate_key(bit_length=256)
        wrapped = self._keyring.wrap(copy_id, key)
        _private_directory(self._copy_folder(copy_key))
        record: dict[str, JsonValue] = {
            "schema": COPY_SCHEMA,
            "copy_key": copy_key,
            "copy_id": copy_id,
            "principal": _digest(_PRINCIPAL_DOMAIN, principal),
            "repository": _digest(_REPOSITORY_DOMAIN, repository),
            "created_at": format_rfc3339_ms(self._clock()),
            "last_sync_at": None,
            "retention": {"kind": "until_forgotten", "days": None},
            "snapshots": [],
            "pins": {},
            "stored_bytes": 0,
            "objects": 0,
            "wrap": {
                "schema": WRAP_SCHEMA,
                "algorithm": wrapped.algorithm,
                "key_slot": wrapped.key_slot,
                "wrapped": wrapped.wrapped.hex(),
            },
        }
        return record, key

    def _records(self, *, forgotten: bool = False) -> list[tuple[str, dict[str, JsonValue]]]:
        """Every copy's record (with ``forgotten``, also those a forget fenced)."""

        found: list[tuple[str, dict[str, JsonValue]]] = []
        folder = self._root / "copies"
        if not folder.is_dir():
            return found
        for copy in sorted(folder.iterdir()):
            data = _read_private(copy / "copy.json", 1_048_576) if copy.is_dir() else None
            if data is None:
                continue
            try:
                record = cast(dict[str, JsonValue], strict_json_parse(data))
            except ValueError:
                continue
            copy_key = record.get("copy_key")
            if type(copy_key) is str and _HEX64.match(copy_key) and copy.name == copy_key[:32]:
                if forgotten or not self._forgotten(copy_key, record):
                    found.append((copy_key, record))
        return found

    def _principal_bytes(self, principal: str) -> int:
        principal_id = _digest(_PRINCIPAL_DOMAIN, principal)
        return sum(
            cast(int, record["stored_bytes"])
            for _key, record in self._records(forgotten=True)
            if record.get("principal") == principal_id
        )

    # --- reads --------------------------------------------------------------------------------

    def snapshot(self, principal: str, repository: str, snapshot: str) -> SnapshotManifest:
        """The manifest of one snapshot this copy holds."""

        return self._snapshot(self.copy_key(principal, repository), snapshot)

    def snapshot_by_key(self, copy_key: str, snapshot: str) -> SnapshotManifest | None:
        """``snapshot`` of the copy ``copy_key`` names, or None when it is not held (any more)."""

        try:
            return self._snapshot(copy_key, snapshot)
        except CodeStoreError:
            return None

    def task_entry(self, principal: str, task_id: str) -> tuple[str, PinEntry] | None:
        """The copy ``task_id`` is pinned to (its key) and its pin, or None: the copy kept for
        ``principal`` whose pin of the task names the newest sync."""

        principal_id = _digest(_PRINCIPAL_DOMAIN, principal)
        found: tuple[str, PinEntry] | None = None
        with self._lock:
            for copy_key, record in self._records():
                if record.get("principal") != principal_id:
                    continue
                pins = record.get("pins")
                entry = (
                    _pin_entry(cast(dict[str, JsonValue], pins).get(task_id))
                    if type(pins) is dict
                    else None
                )
                if entry is None:
                    continue
                if found is None or (entry.synced_at or "") > (found[1].synced_at or ""):
                    found = (copy_key, entry)
        return found

    def _snapshot(self, copy_key: str, snapshot: str) -> SnapshotManifest:
        with self._lock:
            record = self._read_record(copy_key)
            if record is None or snapshot not in cast(list[str], record["snapshots"]):
                raise CodeStoreError("code_snapshot_unknown")
            key = self._data_key(copy_key, record)
            frame = _read_private(
                self._copy_folder(copy_key) / "snapshots" / f"{snapshot}.enc", 1 << 20
            )
            if frame is None:
                raise CodeStoreError("code_snapshot_unknown")
            plain = self._open_frame(
                key, _MANIFEST_AAD + copy_key.encode() + snapshot.encode(), frame
            )
            try:
                return manifest_from_json(plain)
            except CopyError:
                raise CodeStoreError("code_copy_corrupt") from None

    def read_object(self, principal: str, repository: str, oid: str) -> GitObject:
        """One object of this copy, decrypted and verified by its id."""

        if not _HEX40.match(oid):
            raise CodeStoreError("code_object_unknown")
        with self._lock:
            copy_key = self.copy_key(principal, repository)
            record = self._read_record(copy_key)
            if record is None:
                raise CodeStoreError("code_copy_unknown")
            key = self._data_key(copy_key, record)
            frame = _read_private(self._copy_folder(copy_key) / "objects" / oid, 1 << 31)
            if frame is None:
                raise CodeStoreError("code_object_unknown")
        plain = self._open_frame(
            key, _OBJECT_AAD + copy_key.encode() + b"\x00" + oid.encode(), frame
        )
        kind, _nul, data = plain.partition(b"\x00")
        item = GitObject(cast(Literal["blob", "tree", "commit"], kind.decode("ascii")), data)
        if item.oid != oid:
            raise CodeStoreError("code_copy_corrupt")
        return item

    def pin(
        self,
        principal: str,
        repository: str,
        task_id: str,
        snapshot: str,
        *,
        synced_at: str | None = None,
        served: bool | None = None,
        stale: bool | None = None,
    ) -> None:
        """Pin ``task_id``'s later reads to ``snapshot`` (design v2 §8.6); its counts stay."""

        if not _TASK_ID.match(task_id):
            raise CodeStoreError("code_pin_invalid")
        with self._lock:
            copy_key = self.copy_key(principal, repository)
            record = self._read_record(copy_key)
            if record is None or snapshot not in cast(list[str], record["snapshots"]):
                raise CodeStoreError("code_snapshot_unknown")
            pins = cast(dict[str, JsonValue], record["pins"])
            if task_id not in pins and len(pins) >= _MAX_PINS:
                raise CodeStoreError("code_pin_invalid")
            entry = _pin_entry(pins.get(task_id)) or PinEntry(snapshot)
            pins[task_id] = _pin_json(
                PinEntry(
                    snapshot,
                    synced_at if synced_at is not None else entry.synced_at,
                    entry.served if served is None else served,
                    entry.reads,
                    entry.fenced,
                    entry.stale if stale is None else stale,
                )
            )
            # A snapshot past the recent window that no pin names any more leaves now.
            record["snapshots"] = cast(
                JsonValue, _window(cast(list[str], record["snapshots"]), record)
            )
            self._write_record(copy_key, record)
            _drop_manifests(self._copy_folder(copy_key), record)

    def pinned(self, principal: str, repository: str, task_id: str) -> str | None:
        entry = self.pin_entry(principal, repository, task_id)
        return None if entry is None else entry.snapshot

    def pin_entry(self, principal: str, repository: str, task_id: str) -> PinEntry | None:
        """``task_id``'s pin in this copy, or None (no copy, or the task never synced to it)."""

        with self._lock:
            record = self._read_record(self.copy_key(principal, repository))
            if record is None:
                return None
            return _pin_entry(cast(dict[str, JsonValue], record["pins"]).get(task_id))

    def task_ids(self, principal: str, repository: str) -> tuple[str, ...]:
        """The tasks pinned to this copy, in id order."""

        with self._lock:
            record = self._read_record(self.copy_key(principal, repository))
            if record is None:
                return ()
            return tuple(sorted(cast(dict[str, JsonValue], record["pins"])))

    def add_reads(
        self,
        principal: str,
        repository: str,
        deltas: Mapping[str, tuple[Mapping[EvidenceToken, int], int]],
    ) -> None:
        """Add evidence reads to pinned tasks' counts: ``{task: ({token: n}, fenced)}``.

        A task not pinned to the copy, or a copy that is gone, takes nothing (its reads were not
        evidence from this copy's repository at level L2); counts are capped, never wrapped.
        """

        with self._lock:
            copy_key = self.copy_key(principal, repository)
            record = self._read_record(copy_key)
            if record is None:
                return
            pins = cast(dict[str, JsonValue], record["pins"])
            changed = False
            for task_id, (reads, fenced) in deltas.items():
                entry = _pin_entry(pins.get(task_id))
                if entry is None:
                    continue
                merged: dict[EvidenceToken, int] = {
                    token: min(_MAX_READ_COUNT, entry.reads.get(token, 0) + reads.get(token, 0))
                    for token in EVIDENCE_PROVENANCE_TOKENS
                }
                pins[task_id] = _pin_json(
                    PinEntry(
                        entry.snapshot,
                        entry.synced_at,
                        entry.served,
                        merged,
                        min(_MAX_READ_COUNT, entry.fenced + fenced),
                        entry.stale,
                    )
                )
                changed = True
            if changed:
                self._write_record(copy_key, record)

    def latest(self, principal: str, repository: str) -> SnapshotManifest | None:
        """The manifest of the newest snapshot this copy holds, or None."""

        with self._lock:
            record = self._read_record(self.copy_key(principal, repository))
            if record is None or not record["snapshots"]:
                return None
            newest = cast(list[str], record["snapshots"])[-1]
        return self.snapshot(principal, repository, newest)

    def manifest_with_base(
        self, principal: str, repository: str, base: str
    ) -> SnapshotManifest | None:
        """The newest snapshot whose synthetic base commit is ``base``, or None: how a task whose
        base was read from the copy names its original base commit to the client."""

        if not _HEX40.match(base):
            return None
        with self._lock:
            record = self._read_record(self.copy_key(principal, repository))
            if record is None:
                return None
            snapshots = list(reversed(cast(list[str], record["snapshots"])))
        for snapshot in snapshots:
            manifest = self.snapshot(principal, repository, snapshot)
            if manifest.base == base:
                return manifest
        return None

    def copies(self, principal: str) -> tuple[CopySummary, ...]:
        """Every copy kept for ``principal``, without a path or name (one a forget fenced but
        could not finish deleting yet too: it is still there)."""

        principal_id = _digest(_PRINCIPAL_DOMAIN, principal)
        with self._lock:
            summaries: list[CopySummary] = []
            for _key, record in self._records(forgotten=True):
                if record.get("principal") != principal_id:
                    continue
                retention = cast(dict[str, JsonValue], record["retention"])
                summaries.append(
                    CopySummary(
                        repository=cast(str, record["repository"]),
                        snapshots=len(cast(list[str], record["snapshots"])),
                        stored_bytes=cast(int, record["stored_bytes"]),
                        created_at=cast(str, record["created_at"]),
                        last_sync_at=cast(str | None, record["last_sync_at"]),
                        retention_kind=cast(RetentionKind, retention["kind"]),
                        retention_days=cast(int | None, retention["days"]),
                    )
                )
            return tuple(summaries)

    # --- forget and expiry --------------------------------------------------------------------

    def forget(
        self, principal: str, repository: str | None = None, *, reason: str = "owner"
    ) -> ForgetReport:
        """Forget ``repository``'s copy for ``principal`` (every copy of the principal when
        ``None``): tombstone first, then delete (see the module text). Idempotent."""

        with self._lock:
            if repository is not None:
                keys = [self.copy_key(principal, repository)]
            else:
                principal_id = _digest(_PRINCIPAL_DOMAIN, principal)
                keys = [
                    key
                    for key, record in self._records(forgotten=True)
                    if record.get("principal") == principal_id
                ]
            # An upload in flight for a copy that does not exist yet is fenced as well.
            for upload in self._uploads.values():
                if upload.principal == principal and (
                    repository is None or upload.repository == repository
                ):
                    keys.append(upload.copy_key)
            report = ForgetReport(reason=reason)
            for copy_key in sorted(set(keys)):
                report = report.plus(self._forget_one(copy_key, reason))
            for upload_id, upload in list(self._uploads.items()):
                if upload.copy_key in keys:
                    self._drop_upload(upload_id)
            return report

    def _forget_one(self, copy_key: str, reason: str, *, advance: bool = True) -> ForgetReport:
        """Tombstone (unless ``advance`` is False: finishing a forget already fenced), record the
        pinned tasks' erasures, then delete durably (see ``_delete_folder``)."""

        folder = self._copy_folder(copy_key)
        try:
            record = self._read_record(copy_key, forgotten=True)
        except CodeStoreError:
            record = None
        if advance:
            epoch = self._advance_epoch(copy_key, reason, floor=_record_epoch(record))
        else:
            epoch = self._epoch(copy_key)
        if not os.path.lexists(folder):
            return ForgetReport(reason=reason)
        objects = (
            sum(1 for _ in (folder / "objects").iterdir()) if (folder / "objects").is_dir() else 0
        )
        snapshots = 0 if record is None else len(cast(list[str], record["snapshots"]))
        stored = 0 if record is None else cast(int, record["stored_bytes"])
        tasks: list[ForgottenTask] = []
        if record is not None:
            for task_id, value in sorted(cast(dict[str, JsonValue], record["pins"]).items()):
                entry = _pin_entry(value)
                if entry is not None and _TASK_ID.match(task_id):
                    tasks.append(ForgottenTask(task_id, entry.account()))
        if tasks:
            # Before anything is deleted: the tasks whose records still hold excerpts derived
            # from this copy, so their erasure is retried after a crash (U20). Every one of them
            # or none: when they cannot all be recorded, the copy stays (fenced) and the forget
            # says it is not complete; it never deletes what it could not account for.
            # The forget's id is the copy's and its epoch's, so finishing it after a crash
            # records the same erasures again (idempotent), never a second forget's.
            try:
                self._remember_erasures(_forget_id(record, epoch), reason, tasks)
            except CodeStoreError:
                return ForgetReport(reason=reason, left=1)
        if record is not None:
            self._keyring.discard(cast(str, record["copy_id"]))
        if not _delete_folder(folder, self._root / "copies"):
            # Fenced, its record (and wrapped key) gone first if that much went: what is left
            # is retried by the next forget, expiry run or start; nothing reads as deleted.
            return ForgetReport(reason=reason, tasks=tuple(tasks), left=1, keys=(copy_key,))
        return ForgetReport(
            1, snapshots, objects, stored, reason, tasks=tuple(tasks), keys=(copy_key,)
        )

    # --- the erasure of what task records derived from a forgotten copy (U20) -----------------

    def _erasures(self) -> list[dict[str, JsonValue]]:
        data = _read_private(self._root / "erasures.json", 16_777_216)
        if data is None:
            return []
        try:
            value = cast(dict[str, JsonValue], strict_json_parse(data))
            if value.get("schema") != _ERASURE_SCHEMA:
                raise ValueError("schema")
            return list(cast(list[dict[str, JsonValue]], value["pending"]))
        except (ValueError, KeyError, TypeError, AttributeError):
            raise CodeStoreError("code_copy_record_invalid") from None

    def _write_erasures(self, pending: list[dict[str, JsonValue]]) -> None:
        document: dict[str, JsonValue] = {
            "schema": _ERASURE_SCHEMA,
            "pending": cast(JsonValue, pending),
        }
        _write_private(self._root / "erasures.json", canonical_encode(document))

    def _remember_erasures(self, forget_id: str, reason: str, tasks: list[ForgottenTask]) -> None:
        """Record every one of ``tasks`` as pending erasure, or none of them: past the bound
        (``_MAX_PENDING_ERASURES``, e.g. while a locked vault keeps erasures from completing)
        this raises ``code_copy_erasure_backlog`` and writes nothing."""

        try:
            pending = self._erasures()
        except CodeStoreError:
            pending = []  # an unreadable record is replaced; its tasks were erased or lost
        recorded = {(row.get("forget_id"), row.get("task_id")) for row in pending}
        tasks = [task for task in tasks if (forget_id, task.task_id) not in recorded]
        if not tasks:
            return
        if len(pending) + len(tasks) > _MAX_PENDING_ERASURES:
            raise CodeStoreError("code_copy_erasure_backlog")
        now = format_rfc3339_ms(self._clock())
        for task in tasks:
            pending.append(
                {
                    "forget_id": forget_id,
                    "reason": reason,
                    "task_id": task.task_id,
                    "account": cast(JsonValue, task.account.to_json()),
                    "forgotten_at": now,
                }
            )
        self._write_erasures(pending)

    def pending_erasures(self) -> tuple[PendingErasure, ...]:
        """Forgotten tasks whose records are still to say their content was forgotten."""

        with self._lock:
            try:
                rows = self._erasures()
            except CodeStoreError:
                return ()
        found: list[PendingErasure] = []
        for row in rows:
            try:
                task_id = cast(str, row["task_id"])
                if not _TASK_ID.match(task_id):
                    continue
                found.append(
                    PendingErasure(
                        cast(str, row["forget_id"]),
                        cast(str, row["reason"]),
                        task_id,
                        evidence_provenance_from_json(row["account"]),
                        cast(str, row["forgotten_at"]),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
        return tuple(found)

    def complete_erasure(self, forget_id: str, task_id: str) -> None:
        """The task's records now say its content was forgotten: drop it from the pending list."""

        with self._lock:
            try:
                rows = self._erasures()
            except CodeStoreError:
                return
            kept = [
                row
                for row in rows
                if not (row.get("forget_id") == forget_id and row.get("task_id") == task_id)
            ]
            if len(kept) != len(rows):
                self._write_erasures(kept)

    def expire(self, *, task_closed: Callable[[str], bool]) -> ForgetReport:
        """Forget every copy whose retention ran out (``days:N``; ``task_close``).

        ``task_closed`` is asked with the store's lock released: it may wait for the service's
        event loop, which may itself be waiting for this lock (a forget, a pending-erasure read),
        and asking under the lock would stall both until the question timed out. A
        ``task_close`` copy is forgotten only when the tasks pinned to it are, once the lock is
        taken again, exactly the ones that were all found closed.
        """

        now = self._clock()
        report = ForgetReport(reason="expired")
        candidates: list[tuple[str, frozenset[str]]] = []
        with self._lock:
            # A forget left unfinished (the erasure bound, a failed deletion) is tried again.
            report = report.plus(self._reconcile())
            for copy_key, record in self._records():
                retention = cast(dict[str, JsonValue], record["retention"])
                kind = retention.get("kind")
                if kind == "days":
                    stamp = record.get("last_sync_at") or record.get("created_at")
                    try:
                        last = parse_rfc3339_ms(stamp)
                    except ValueError:
                        last = now
                    if now - last >= timedelta(days=cast(int, retention["days"])):
                        report = report.plus(self._forget_one(copy_key, "expired"))
                elif kind == "task_close":
                    pins = frozenset(cast(dict[str, JsonValue], record["pins"]))
                    if pins:
                        candidates.append((copy_key, pins))
        due = [(key, pins) for key, pins in candidates if all(task_closed(task) for task in pins)]
        if not due:
            return report
        with self._lock:
            for copy_key, pins in due:
                try:
                    record = self._read_record(copy_key)
                except CodeStoreError:
                    continue
                if record is None or frozenset(cast(dict[str, JsonValue], record["pins"])) != pins:
                    continue  # a task read the copy meanwhile: asked again at the next run
                report = report.plus(self._forget_one(copy_key, "expired"))
        return report


def _window(snapshots: list[str], record: Mapping[str, JsonValue]) -> list[str]:
    """The snapshots a copy keeps, oldest first: the newest ``_MAX_SNAPSHOTS`` and every one a
    task's pin still names (its reviewer and offline reads read it; design v2 §8.6), whatever
    its age. A snapshot leaves only once it is past the window and no pin names it."""

    pins = record.get("pins")
    pinned = {
        entry.snapshot
        for value in (cast(dict[str, JsonValue], pins).values() if type(pins) is dict else ())
        if (entry := _pin_entry(value)) is not None
    }
    recent = set(snapshots[-_MAX_SNAPSHOTS:])
    return [item for item in snapshots if item in recent or item in pinned]


def _drop_manifests(folder: Path, record: Mapping[str, JsonValue]) -> None:
    """Remove the manifests of the snapshots the record no longer names (best effort: they are
    unread from then on, and the next admission or start tries again)."""

    named = {f"{item}.enc" for item in cast(list[str], record.get("snapshots", []))}
    below = folder / "snapshots"
    try:
        found = [path for path in below.iterdir() if path.name.endswith(".enc")]
    except OSError:
        return
    for path in found:
        if path.name not in named:
            _remove_file(path)


def _generation(record: Mapping[str, JsonValue] | None) -> int:
    """The committed generation a copy's record names (0: written before generations, whose
    index is ``index.enc``)."""

    generation = None if record is None else record.get("generation")
    return generation if type(generation) is int and generation >= 0 else 0


def _index_name(generation: int) -> str:
    return "index.enc" if generation == 0 else f"index.{generation}.enc"


def _index_aad(copy_key: str, generation: int) -> bytes:
    if generation == 0:
        return _INDEX_AAD + copy_key.encode()
    return _INDEX_AAD + copy_key.encode() + b"\x00" + str(generation).encode()


def _record_epoch(record: Mapping[str, JsonValue] | None) -> int:
    """The forget epoch a copy's record was written under (0 before epochs were recorded)."""

    epoch = None if record is None else record.get("epoch")
    return epoch if type(epoch) is int and epoch >= 0 else 0


def _forget_id(record: Mapping[str, JsonValue] | None, epoch: int) -> str:
    """One forget of one copy: its random copy id and the epoch the forget fenced it at."""

    copy_id = "" if record is None else str(record.get("copy_id", ""))
    return hashlib.sha256(
        f"yoetz/code-copy-forget/v1\x00{copy_id}\x00{epoch}".encode()
    ).hexdigest()[:32]


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _delete_folder(folder: Path, parent: Path) -> bool:
    """Delete a copy's folder durably; True once it is gone and that is on disk.

    The record goes first, with the wrapped data key in it, and that removal is fsynced, so
    what may be left is ciphertext no key opens; then the rest, then the parent folder is
    fsynced, so a power loss never brings back a copy whose forget was acknowledged."""

    try:
        os.unlink(folder / "copy.json")
    except FileNotFoundError:
        pass
    except OSError:
        return False
    try:
        if os.path.lexists(folder):
            _fsync_directory(folder)
        shutil.rmtree(folder, ignore_errors=True)
        if os.path.lexists(folder):
            return False
        _fsync_directory(parent)
    except OSError:
        return False
    return True


# --- pins ------------------------------------------------------------------------------------------


def _pin_entry(value: object) -> PinEntry | None:
    """A pin as recorded: a snapshot id alone (as first written) or the full entry."""

    if type(value) is str:
        return PinEntry(value) if _HEX40.match(value) else None
    if type(value) is not dict:
        return None
    fields = cast(dict[str, JsonValue], value)
    snapshot = fields.get("snapshot")
    synced_at = fields.get("synced_at")
    served = fields.get("served", False)
    reads = fields.get("reads", {})
    fenced = fields.get("fenced", 0)
    stale = fields.get("stale", False)
    if (
        type(stale) is not bool
        or type(snapshot) is not str
        or not _HEX40.match(snapshot)
        or (synced_at is not None and type(synced_at) is not str)
        or type(served) is not bool
        or type(reads) is not dict
        or type(fenced) is not int
        or not 0 <= fenced <= _MAX_READ_COUNT
    ):
        return None
    counts: dict[EvidenceToken, int] = {}
    for token in EVIDENCE_PROVENANCE_TOKENS:
        count = cast(dict[str, JsonValue], reads).get(token, 0)
        if type(count) is not int or not 0 <= count <= _MAX_READ_COUNT:
            return None
        counts[token] = count
    return PinEntry(snapshot, synced_at, served, counts, fenced, stale)


def _pin_json(entry: PinEntry) -> dict[str, JsonValue]:
    return {
        "snapshot": entry.snapshot,
        "synced_at": entry.synced_at,
        "served": entry.served,
        "reads": {token: entry.reads.get(token, 0) for token in EVIDENCE_PROVENANCE_TOKENS},
        "fenced": entry.fenced,
        "stale": entry.stale,
    }


# --- files ------------------------------------------------------------------------------------------


def _private_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, exist_ok=True)
    except OSError:
        raise CodeStoreError("code_store_unsafe") from None
    facts = os.lstat(path)
    if not stat.S_ISDIR(facts.st_mode) or facts.st_uid != os.geteuid():
        raise CodeStoreError("code_store_unsafe")
    if stat.S_IMODE(facts.st_mode) & 0o077:
        os.chmod(path, 0o700)


def _read_private(path: Path, limit: int) -> bytes | None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError:
        raise CodeStoreError("code_store_unsafe") from None
    try:
        facts = os.fstat(descriptor)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != os.geteuid()
            or stat.S_IMODE(facts.st_mode) & 0o077
            or facts.st_size > limit
        ):
            raise CodeStoreError("code_store_unsafe")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1 << 20):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_private(path: Path, data: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    try:
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
        )
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(descriptor, view) :]
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
        _remove_file(temporary)
        raise CodeStoreError("code_store_unsafe") from None


def _remove_file(path: Path) -> None:
    try:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path, ignore_errors=True)
        else:
            path.unlink(missing_ok=True)
    except OSError:
        pass
