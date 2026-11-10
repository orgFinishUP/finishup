"""The service's side of level L2: pull a sanitized snapshot from the helper into the copy store.

Design v2 §4.2 and Q6 (ADR-054). A server that keeps copies (its profile offers L2, which needs a
code-copy offer and L2 released) pulls a snapshot at an evidence-consuming boundary: the task base
(``read_task_base``) and a check (``capture``/``capture_metadata``). ``CodeCopies.sync_blocking``
runs in the worker thread of the read it precedes:

1. it knows the workspace handle's repository commitment only from a claim this service keyed
   (``remember``); a handle it never keyed is not synced;
2. one sync per repository at a time: a caller that finds one running waits for its outcome
   (coalesced), within its own bound;
3. it asks the handle's agent ``code_sync_prepare`` with the copy's have-set and the revision it
   issues now (the hub asks only an agent that declares it: the helper's background agent), then
   reads the bundle in chunks into the store's encrypted staging, and commits it, which verifies it
   exactly as the client's audit did and binds it to the revision and the claim's worktree;
4. a task's sync pins the snapshot to the task (design v2 §8.6), named by the task's id (the
   ``evidence_task_scope`` its reads run in).

Every outcome is a closed token, recorded as a bounded event; a sync that fails, is refused or
finds no helper never fails the read it precedes, which goes on as at level L1 (the client's agent
answers, attested). Nothing here runs while the service keeps no copies.

**Reads from the copy (design v2 §4.1, §8.6; plan D2–D7).** ``git_view`` decides, for a git
read of a claim-bound workspace at an evidence boundary (the task base, a check), whether the read
is served from the copy: it syncs first, then serves the snapshot the sync named (fresh), or the
task's pinned snapshot when the sync found no client (``stale``, the client is offline). A refused
sync (the hold, zero network, consent, revision) never falls back to the copy. A task keeps one
source: a task whose base was read from the client keeps its git reads with the client, so
commit identities never mix. ``reader_view`` serves a reviewer's read of a task whose evidence the
copy served, from the snapshot the task is pinned to (no sync). ``checkout`` hands the read a
materialized checkout of that snapshot (``service.code_checkout``).

**Provenance (plan D10).** Every routed read of a task pinned to a copy is counted for the task
by where it was answered (``domain.evidence_provenance`` tokens), with the outside reads the
client fenced (ADR-052 O7); ``provenance`` gives the task's account. Counts are buffered and
written to the copy's record at each sync, account, forget and expiry.

**Forget, expiry and the erasure of derived excerpts (U20, plan D14–D15).** ``forget`` and the
expiry (``days:N``, ``task_close`` once every pinned task's work is no longer open) delete the
copy and its checkout; the store first records, owner-only, the pinned tasks whose records still
hold excerpts derived from it. ``attach_erasure`` gives the callable that erases them from a
task's records; it runs off the caller's thread for each pending task and the entry is cleared
only once it returns True, so an erasure interrupted by a crash runs again at the next start.

``VaultCopyKeyring`` wraps each copy's data key under the vault's authority: the key-encryption
key of a copy is the vault's installation MAC over the copy id under its own domain
(``yoetz/code-copy-kek/v1``), so it exists only while the vault is unlocked and is never stored.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Generator, Iterable
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal, cast

from cryptography.hazmat.primitives import keywrap

from finishup.config.installation import format_rfc3339_ms
from finishup.domain.evidence_provenance import (
    EVIDENCE_PROVENANCE_TOKENS,
    CopySnapshotRef,
    EvidenceAccountIncomplete,
    EvidenceProvenance,
    EvidenceToken,
)
from finishup.observability.logging import record_bounded_event_without_raising
from finishup.ports.change_capture import evidence_bindings
from finishup.ports.workspace_agent import (
    MAX_CODE_SYNC_CHUNK_BYTES,
    CodeSyncPrepareArguments,
    CodeSyncPrepared,
    CodeSyncReadArguments,
    WorkspaceAgentUnavailable,
    WorkspaceOperation,
)
from finishup.service.code_store import (
    CodeStore,
    CodeStoreError,
    ForgetReport,
    PendingErasure,
    WrappedKey,
)

if TYPE_CHECKING:
    from finishup.ports.change_capture import TaskChangeBase
    from finishup.ports.keys import MacKeyHandle
    from finishup.protocol.server_copy import SnapshotManifest
    from finishup.protocol.server_profile import ServerProfileRevision
    from finishup.service.code_checkout import CopyCheckouts
    from finishup.service.workspace_hub import WorkspaceAgentHub

__all__ = [
    "CODE_COPY_KEK_MAC_DOMAIN",
    "COPY_PRINCIPAL",
    "OFFLINE_REASONS",
    "CodeCopies",
    "CopyView",
    "SyncOutcome",
    "VaultCopyKeyring",
]

CODE_COPY_KEK_MAC_DOMAIN: Final = b"yoetz/code-copy-kek/v1\x00"
# The claim the service keyed is already namespaced by the caller's principal (an API key's at
# the REST edge, the owner's over SSH), so its commitment separates principals' copies (Q7). The
# principal itself does not reach the service over the control channel yet, so every upload of a
# claim remembered without an ``account`` is charged to this one shared namespace: the store's
# principal quota is then a server-wide bound (ADR-054, an honest limit).
COPY_PRINCIPAL: Final = "claim"
_PREPARE_SECONDS: Final = 60.0
_READ_SECONDS: Final = 30.0
_COMPONENT: Final = "service.code_copy"
_EXPIRY_SECONDS: Final = 600.0
# The sync's answers that the client is not there: the copy as last synced serves the read.
OFFLINE_REASONS: Final = frozenset(
    {"no_agent", "agent_disconnected", "hub_unavailable", "deadline_exceeded"}
)
# Buffered evidence counts are written to the copy's record past this many (and at each sync).
_FLUSH_EVERY: Final = 32


class VaultCopyKeyring:
    """Each copy's key-encryption key, derived by the vault and never stored (see the module)."""

    __slots__ = ("_mac",)

    def __init__(self, mac: Callable[[], MacKeyHandle]) -> None:
        self._mac = mac

    def _kek(self, copy_id: str) -> bytes:
        try:
            tagged = self._mac().mac(CODE_COPY_KEK_MAC_DOMAIN, copy_id.encode("ascii"))
        except Exception:  # noqa: BLE001 - a vault that cannot derive is a locked vault
            raise CodeStoreError("vault_locked") from None
        return bytes.fromhex(tagged.removeprefix("hmac-sha256:"))

    def wrap(self, copy_id: str, data_key: bytes) -> WrappedKey:
        wrapped = keywrap.aes_key_wrap(self._kek(copy_id), data_key)
        return WrappedKey("aes-256-kw-rfc3394", "installation-mac:code-copy-kek/v1", wrapped)

    def unwrap(self, copy_id: str, wrapped: WrappedKey) -> bytes:
        try:
            return keywrap.aes_key_unwrap(self._kek(copy_id), wrapped.wrapped)
        except keywrap.InvalidUnwrap:
            raise CodeStoreError("code_copy_wrap_unknown") from None

    def discard(self, copy_id: str) -> None:
        # Nothing of the key is stored: forgetting the copy deletes the wrapped data key.
        _ = copy_id


@dataclass(frozen=True, slots=True)
class SyncOutcome:
    """What one sync did: ``synced`` (``snapshot`` named), ``unchanged`` or a closed refusal.

    ``subject_state`` is the subject-state commitment the client returned with this sync's
    manifest (design v2 §8.6), also when nothing was uploaded: staging an edit changes it
    without changing the sanitized snapshot, whose stored manifest keeps the earlier one."""

    outcome: Literal["synced", "unchanged", "refused", "unavailable"]
    reason: str | None = None
    snapshot: str | None = None
    synced_at: str | None = None
    subject_state: str | None = None


@dataclass(frozen=True, slots=True)
class CopyView:
    """The snapshot of a copy one read is served from (``stale``: the client was offline, so
    the copy as last synced, at ``synced_at``)."""

    commitment: str
    manifest: SnapshotManifest
    stale: bool
    synced_at: str | None

    @property
    def token(self) -> EvidenceToken:
        return "stale_copy_read" if self.stale else "server_copy_read"


@dataclass(frozen=True, slots=True)
class _Claim:
    commitment: str
    worktree: str | None
    # The authenticated principal its uploads are charged to (the store's principal quota);
    # None: not known to this service (see ``COPY_PRINCIPAL``), the shared namespace is charged.
    account: str | None = None


class _Flight:
    __slots__ = ("done", "outcome")

    def __init__(self) -> None:
        self.done = threading.Event()
        self.outcome: SyncOutcome | None = None


class CodeCopies:
    """Pulls snapshots into the copy store and serves reads from it (see the module text)."""

    __slots__ = (
        "_buffered",
        "_checkouts",
        "_claims",
        "_draining",
        "_erase",
        "_expiry",
        "_flights",
        "_hub",
        "_lock",
        "_pending",
        "_revision",
        "_serving",
        "_store",
        "_task_closed",
    )

    def __init__(
        self,
        store: CodeStore,
        hub: WorkspaceAgentHub,
        revision: Callable[[], ServerProfileRevision | None],
        *,
        checkouts: CopyCheckouts | None = None,
        serving: bool = True,
    ) -> None:
        # ``serving`` False: the server's owner withdrew the offer, so nothing is synced or read
        # from the copies it still keeps; they can still be listed, forgotten and expire.
        self._serving = serving
        self._store = store
        self._hub = hub
        self._revision = revision
        self._checkouts = checkouts
        self._lock = threading.Lock()
        self._claims: dict[str, _Claim] = {}
        self._flights: dict[str, _Flight] = {}
        self._expiry = threading.Event()
        # Evidence counts not yet written: {commitment: {task: ({token: n}, fenced)}}.
        self._pending: dict[str, dict[str, tuple[dict[EvidenceToken, int], int]]] = {}
        self._buffered = 0
        self._task_closed: Callable[[str], bool] = _never_closed
        self._erase: Callable[[PendingErasure], bool] | None = None
        self._draining = threading.Lock()

    @property
    def serving(self) -> bool:
        """Whether this service syncs and reads copies (its profile offers L2) or only keeps,
        lists, forgets and expires the ones an earlier offer left."""

        return self._serving

    @property
    def store(self) -> CodeStore:
        return self._store

    @property
    def checkouts(self) -> CopyCheckouts | None:
        return self._checkouts

    def remember(
        self,
        handle: str | None,
        commitment: str,
        worktree: str | None,
        *,
        account: str | None = None,
    ) -> None:
        """A claim this service keyed: ``handle`` names that repository's commitment, and
        ``account`` the authenticated principal its uploads are charged to, when known."""

        if handle is None:
            return
        with self._lock:
            if len(self._claims) >= 4_096 and handle not in self._claims:
                self._claims.pop(next(iter(self._claims)))
            self._claims[handle] = _Claim(commitment, worktree, account)

    def commitment_of(self, handle: str) -> str | None:
        with self._lock:
            claim = self._claims.get(handle)
        return None if claim is None else claim.commitment

    # --- sync -------------------------------------------------------------------------------

    def sync_blocking(
        self,
        handle: str,
        *,
        purpose: Literal["base", "check"],
        base_commit: str | None = None,
        task_id: str | None = None,
    ) -> SyncOutcome:
        """Sync ``handle``'s repository now, from a worker thread (coalesced, bounded)."""

        if not self._serving:
            return SyncOutcome("refused", "server_level_unavailable")
        with self._lock:
            claim = self._claims.get(handle)
            if claim is None:
                return SyncOutcome("unavailable", "workspace_not_keyed")
            flight = self._flights.get(claim.commitment)
            owner = flight is None
            if flight is None:
                flight = _Flight()
                self._flights[claim.commitment] = flight
        if not owner:
            flight.done.wait(_PREPARE_SECONDS + 4 * _READ_SECONDS)
            outcome = flight.outcome or SyncOutcome("unavailable", "code_sync_busy")
            if outcome.snapshot is not None and outcome.outcome in {"synced", "unchanged"}:
                self._pin(claim, task_id, outcome.snapshot)
            return outcome
        try:
            outcome = self._sync(handle, claim, purpose, base_commit, task_id)
        except Exception:  # noqa: BLE001 - a sync never fails the read it precedes
            outcome = SyncOutcome("unavailable", "internal_error")
        finally:
            with self._lock:
                self._flights.pop(claim.commitment, None)
        flight.outcome = outcome
        flight.done.set()
        record_bounded_event_without_raising(
            component=_COMPONENT,
            operation="code_copy_sync_" + outcome.outcome,
            reason=outcome.reason or outcome.outcome,
        )
        self.flush()
        return outcome

    def _sync(
        self,
        handle: str,
        claim: _Claim,
        purpose: Literal["base", "check"],
        base_commit: str | None,
        task_id: str | None,
    ) -> SyncOutcome:
        revision = self._revision()
        if revision is None:
            return SyncOutcome("refused", "server_profile_changed")
        # Read before the client is asked: a forget from now on fences this sync (§8.7).
        epoch = self._store.epoch(COPY_PRINCIPAL, claim.commitment)
        have = tuple(sorted(self._store.have(COPY_PRINCIPAL, claim.commitment)))
        arguments = CodeSyncPrepareArguments(
            workspace=handle,
            purpose=purpose,
            have=have,
            base_commit=base_commit,
            issuer=revision.issuer,
            revision=revision.revision,
            profile_digest=revision.profile_digest,
        )
        try:
            prepared: CodeSyncPrepared = self._hub.call_blocking(
                handle,
                WorkspaceOperation.CODE_SYNC_PREPARE,
                arguments,
                timeout_seconds=_PREPARE_SECONDS,
            )
        except WorkspaceAgentUnavailable as exc:
            reason = exc.agent_reason or exc.reason
            kind: Literal["refused", "unavailable"] = "refused" if exc.refused else "unavailable"
            return SyncOutcome(kind, reason)
        manifest = prepared.manifest
        now = format_rfc3339_ms(datetime.now(UTC))
        if prepared.unchanged:
            # Nothing to upload, but the sync happened: the stored manifest's metadata, the
            # retention and the sync time are refreshed, under the epoch the sync began with.
            from finishup.protocol.canonical import canonical_encode as encode
            from finishup.protocol.server_copy import manifest_to_json as to_json

            try:
                self._store.refresh(
                    COPY_PRINCIPAL,
                    claim.commitment,
                    manifest=encode(to_json(manifest)),
                    retention=(prepared.retention_kind, prepared.retention_days),
                    epoch=epoch,
                    revision=(revision.issuer, revision.revision, revision.profile_digest),
                    worktree=claim.worktree or "",
                )
            except CodeStoreError as error:
                if error.reason == "code_snapshot_unknown":
                    return SyncOutcome("unavailable", "code_snapshot_unknown")
                return SyncOutcome("refused", error.reason)
            self._pin(claim, task_id, manifest.snapshot, now)
            return SyncOutcome("unchanged", None, manifest.snapshot, now, manifest.subject_state)
        assert prepared.sync_id is not None and prepared.sha256 is not None  # noqa: S101
        from finishup.protocol.canonical import canonical_encode
        from finishup.protocol.server_copy import manifest_to_json

        try:
            upload = self._store.begin_upload(
                COPY_PRINCIPAL,
                claim.commitment,
                manifest=canonical_encode(manifest_to_json(manifest)),
                size=prepared.size,
                sha256=prepared.sha256,
                retention=(prepared.retention_kind, prepared.retention_days),
                epoch=epoch,
                account=claim.account,
            )
            offset = 0
            while offset < prepared.size:
                length = min(MAX_CODE_SYNC_CHUNK_BYTES, prepared.size - offset)
                chunk: bytes = self._hub.call_blocking(
                    handle,
                    WorkspaceOperation.CODE_SYNC_READ,
                    CodeSyncReadArguments(handle, prepared.sync_id, offset, length),
                    timeout_seconds=_READ_SECONDS,
                )
                if len(chunk) != length:
                    return SyncOutcome("unavailable", "code_upload_out_of_order")
                offset = self._store.append(upload, COPY_PRINCIPAL, claim.commitment, offset, chunk)
            self._store.commit(
                upload,
                COPY_PRINCIPAL,
                claim.commitment,
                revision=(revision.issuer, revision.revision, revision.profile_digest),
                worktree=claim.worktree or "",
            )
        except WorkspaceAgentUnavailable as exc:
            # A chunk the helper refuses (the owner narrowed what may leave since the prepare,
            # ``client.code_sync``) is a refusal as at the prepare: nothing of it is admitted.
            chunk_kind: Literal["refused", "unavailable"] = (
                "refused" if exc.refused else "unavailable"
            )
            return SyncOutcome(chunk_kind, exc.agent_reason or exc.reason)
        except CodeStoreError as error:
            return SyncOutcome("refused", error.reason)
        self._pin(claim, task_id, manifest.snapshot, now)
        return SyncOutcome("synced", None, manifest.snapshot, now, manifest.subject_state)

    def _pin(
        self, claim: _Claim, task_id: str | None, snapshot: str, synced_at: str | None = None
    ) -> None:
        if task_id is None:
            return
        try:
            self._store.pin(
                COPY_PRINCIPAL, claim.commitment, task_id, snapshot, synced_at=synced_at
            )
        except CodeStoreError:
            return

    # --- reads from the copy (plan D2-D7) ---------------------------------------------------

    def _manifest(self, commitment: str, snapshot: str) -> SnapshotManifest | None:
        try:
            return self._store.snapshot(COPY_PRINCIPAL, commitment, snapshot)
        except CodeStoreError:
            return None

    def git_view(
        self,
        handle: str,
        *,
        purpose: Literal["base", "check"],
        base: TaskChangeBase | None,
        task_id: str | None,
    ) -> tuple[CopyView | None, TaskChangeBase | None]:
        """Sync before an evidence boundary's git read, then say whether the copy serves it.

        Returns the view and the base the read diffs against there (the pinned snapshot's own
        sanitized base when it has the same original base as the task's), or ``(None, None)``
        when the client's agent answers: a workspace this service never keyed, a task whose base
        the client read, a refused sync, or no snapshot to read.
        """

        with self._lock:
            claim = self._claims.get(handle)
        if claim is None:
            return None, None
        commitment = claim.commitment
        copy_base: SnapshotManifest | None = None
        original: str | None = None
        if base is not None:
            if base.object_format == "sha1":
                try:
                    copy_base = self._store.manifest_with_base(
                        COPY_PRINCIPAL, commitment, base.commit
                    )
                except CodeStoreError:
                    copy_base = None
            original = base.commit if copy_base is None else _original(copy_base)
        outcome = self.sync_blocking(handle, purpose=purpose, base_commit=original, task_id=task_id)
        if base is not None and copy_base is None:
            # The task's base came from the client: its git reads stay there (one source).
            self._unserve(commitment, task_id)
            _bind(commitment, task_id, None)
            return None, None
        view = self._view_for(commitment, outcome, task_id)
        if view is None:
            # From now on the client's agent answers this task's reads, the reviewer's too.
            self._unserve(commitment, task_id)
            _bind(commitment, task_id, None)
            return None, None
        effective = base
        if base is not None and copy_base is not None:
            if view.manifest.original_base == copy_base.original_base:
                effective = replace(base, commit=view.manifest.base)
        if task_id is not None:
            self._serve(commitment, task_id, view)
            # This job's later reads (its review's included) read this snapshot (§8.6).
            _bind(commitment, task_id, view)
        return view, effective

    def _view_for(
        self, commitment: str, outcome: SyncOutcome, task_id: str | None
    ) -> CopyView | None:
        if outcome.outcome in {"synced", "unchanged"} and outcome.snapshot is not None:
            manifest = self._manifest(commitment, outcome.snapshot)
            if manifest is None:
                return None
            return CopyView(commitment, manifest, False, outcome.synced_at)
        if outcome.outcome != "unavailable" or outcome.reason not in OFFLINE_REASONS:
            # Refused (the hold, zero network, consent, revision) or failed: never the copy.
            return None
        entry = (
            None if task_id is None else self._store.pin_entry(COPY_PRINCIPAL, commitment, task_id)
        )
        if entry is not None:
            manifest = self._manifest(commitment, entry.snapshot)
            synced_at = entry.synced_at
        else:
            try:
                manifest = self._store.latest(COPY_PRINCIPAL, commitment)
            except CodeStoreError:
                manifest = None
            synced_at = None
        if manifest is None:
            return None
        return CopyView(commitment, manifest, True, synced_at or manifest.synced_at)

    def _serve(self, commitment: str, task_id: str, view: CopyView) -> None:
        """The task's evidence is read from the copy from now on (its pin says ``served``)."""

        try:
            self._store.pin(
                COPY_PRINCIPAL,
                commitment,
                task_id,
                view.manifest.snapshot,
                served=True,
                stale=view.stale,
            )
        except CodeStoreError:
            return

    def _unserve(self, commitment: str, task_id: str | None) -> None:
        if task_id is None:
            return
        try:
            entry = self._store.pin_entry(COPY_PRINCIPAL, commitment, task_id)
            if entry is not None and entry.served:
                self._store.pin(COPY_PRINCIPAL, commitment, task_id, entry.snapshot, served=False)
        except CodeStoreError:
            return

    def reader_view(self, handle: str, task_id: str | None) -> CopyView | None:
        """The pinned snapshot a reviewer's read of ``task_id`` reads, when the copy served the
        task's evidence (no sync: a review reads what its check read); else None.

        A task the copy serves whose pinned snapshot cannot be read (its pin or manifest is
        unreadable, or this service no longer reads its copies) raises ``WorkspaceAgentUnavailable``
        (``code_copy_unavailable``): the client's live bytes never stand in for the snapshot the
        task's evidence was read from (design v2 §8.6)."""

        if task_id is None:
            return None
        with self._lock:
            claim = self._claims.get(handle)
        if claim is None:
            return None
        bound = _bound(claim.commitment, task_id)
        if bound is not _UNBOUND:
            # This evidence job already read (or captured) a snapshot: it keeps reading it, even
            # if another job of the task moved the task's pin meanwhile (design v2 §8.6).
            return cast("CopyView | None", bound)
        try:
            entry = self._store.pin_entry(COPY_PRINCIPAL, claim.commitment, task_id)
        except CodeStoreError:
            raise _copy_unavailable() from None
        if entry is None or not entry.served:
            _bind(claim.commitment, task_id, None, first=True)
            return None
        manifest = self._manifest(claim.commitment, entry.snapshot) if self._serving else None
        if manifest is None:
            raise _copy_unavailable()
        # A reviewer's read reads what its check read: stale when that check was served while
        # the client was offline.
        view = CopyView(claim.commitment, manifest, entry.stale, entry.synced_at)
        _bind(claim.commitment, task_id, view, first=True)
        return view

    def pinned_manifest(self, handle: str, task_id: str | None) -> SnapshotManifest | None:
        """The snapshot ``task_id`` is pinned to in ``handle``'s copy (served or not), or None."""

        if task_id is None:
            return None
        with self._lock:
            claim = self._claims.get(handle)
        if claim is None:
            return None
        try:
            entry = self._store.pin_entry(COPY_PRINCIPAL, claim.commitment, task_id)
        except CodeStoreError:
            return None
        return None if entry is None else self._manifest(claim.commitment, entry.snapshot)

    @contextmanager
    def checkout(self, view: CopyView, *, commits: Iterable[str] = ()) -> Generator[Path]:
        """The materialized checkout of ``view``'s snapshot, held for the caller's reads."""

        if self._checkouts is None:
            raise CodeStoreError("code_checkout_unavailable")
        with self._checkouts.checkout(
            COPY_PRINCIPAL, view.commitment, view.manifest, commits=commits
        ) as folder:
            yield folder

    # --- provenance (plan D10) --------------------------------------------------------------

    def count(
        self, handle: str, task_id: str | None, token: EvidenceToken, *, fenced: int = 0
    ) -> None:
        """Count one evidence read of ``task_id`` answered by ``token``'s source (and the outside
        reads the client fenced). Only a task pinned to the copy keeps it (``add_reads``)."""

        if task_id is None or token not in EVIDENCE_PROVENANCE_TOKENS:
            return
        with self._lock:
            claim = self._claims.get(handle)
            if claim is None:
                return
            tasks = self._pending.setdefault(claim.commitment, {})
            reads, held = tasks.get(task_id, ({}, 0))
            reads[token] = reads.get(token, 0) + 1
            tasks[task_id] = (reads, held + max(0, int(fenced)))
            self._buffered += 1
            due = self._buffered >= _FLUSH_EVERY
        if due:
            self.flush()

    def flush(self) -> None:
        """Write the buffered evidence counts to the copies' records."""

        with self._lock:
            pending = self._pending
            self._pending = {}
            self._buffered = 0
        for commitment, tasks in pending.items():
            try:
                self._store.add_reads(COPY_PRINCIPAL, commitment, tasks)
            except CodeStoreError:
                continue

    def provenance(self, task_id: str) -> EvidenceProvenance | None:
        """``task_id``'s evidence account in the copy it is pinned to, or None (no copy).

        Raises ``EvidenceAccountIncomplete`` when the pin's durable marker says the copy served
        some of the task's evidence but no read from the copy is counted (the counts were lost
        before they were written): the account then cannot say where the evidence was read."""

        self.flush()
        try:
            found = self._store.task_entry(COPY_PRINCIPAL, task_id)
        except CodeStoreError:
            return None
        if found is None:
            return None
        commitment_key, entry = found
        if entry.copy_used and not entry.account().read_from_copy:
            raise EvidenceAccountIncomplete()
        snapshot = None
        if entry.synced_at is not None:
            manifest = self._store.snapshot_by_key(commitment_key, entry.snapshot)
            if manifest is not None:
                snapshot = CopySnapshotRef(entry.synced_at, manifest.tree)
        return EvidenceProvenance(entry.reads, entry.fenced, snapshot)

    # --- expiry, forget and erasure (plan D14-D15) -------------------------------------------

    def attach_task_closed(self, closed: Callable[[str], bool]) -> threading.Thread:
        """Whether a task's work is no longer open (``task_close`` retention); unknown = open.

        Attached once the service is ready, after the expiry its start ran could tell no task
        closed: an expiry runs again now, off the caller's thread (the predicate asks the
        service loop), so a ``task_close`` copy due while the service was down or locked goes at
        once rather than at the next ten-minute run. The thread is returned for tests to join.
        """

        self._task_closed = closed
        thread = threading.Thread(
            target=self.expire_now, name="finishup-code-copy-expiry-ready", daemon=True
        )
        thread.start()
        return thread

    def attach_erasure(self, erase: Callable[[PendingErasure], bool]) -> None:
        """The callable that records in a forgotten task's records that its content was
        forgotten and erases what they derived from the copy; True once done. It is run off the
        caller's thread for every pending task, now and after every forget or expiry."""

        self._erase = erase
        self._drain_erasures_soon()

    def _closed(self, task_id: str) -> bool:
        try:
            return self._task_closed(task_id) is True
        except Exception:  # noqa: BLE001 - unknown is open: the copy stays
            return False

    def expire_now(self) -> ForgetReport:
        """Forget every copy whose retention ran out (design v2 §4.3): ``days:N`` after N days
        without a sync, ``task_close`` once no task pinned to it is open."""

        self.flush()
        try:
            report = self._store.expire(task_closed=self._closed)
        except CodeStoreError as error:
            record_bounded_event_without_raising(
                component=_COMPONENT, operation="code_copy_expiry", reason=error.reason
            )
            return ForgetReport(reason="expired")
        if report.copies:
            record_bounded_event_without_raising(
                component=_COMPONENT, operation="code_copy_expiry", reason="expired"
            )
        # Every run, so a checkout whose removal failed earlier is tried again.
        self._after_forget()
        return report

    def start_expiry(self, every_seconds: float = _EXPIRY_SECONDS) -> None:
        """Run the expiry now and then every ``every_seconds`` in a daemon thread, until
        ``stop_expiry``; erasures a crash left pending run again too."""

        self.expire_now()
        self._drain_erasures_soon()

        def loop() -> None:
            while not self._expiry.wait(every_seconds):
                self.expire_now()
                self._drain_erasures_soon()

        threading.Thread(target=loop, name="finishup-code-copy-expiry", daemon=True).start()

    def stop_expiry(self) -> None:
        self._expiry.set()

    def forget(self, commitment: str) -> ForgetReport:
        """Forget the copy of the repository ``commitment`` names (``code_forget``)."""

        self.flush()
        report = self._store.forget(COPY_PRINCIPAL, commitment)
        # Its checkout is plaintext: not complete while any of it is left (retried by the orphan
        # sweep after every forget and expiry run, and at start).
        if self._checkouts is not None and not self._checkouts.discard(
            self._store.copy_key(COPY_PRINCIPAL, commitment)
        ):
            report = replace(report, left=report.left + 1)
        self._after_forget()
        return report

    def _after_forget(self) -> None:
        if self._checkouts is not None and self._checkouts.discard_orphans():
            record_bounded_event_without_raising(
                component=_COMPONENT, operation="code_copy_checkout_cleanup", reason="pending"
            )
        self._drain_erasures_soon()

    def _drain_erasures_soon(self) -> None:
        if self._erase is None or not self._store.pending_erasures():
            return
        threading.Thread(
            target=self.drain_erasures, name="finishup-code-copy-erasure", daemon=True
        ).start()

    def drain_erasures(self) -> int:
        """Run the attached erasure for every pending task once; how many completed."""

        erase = self._erase
        if erase is None or not self._draining.acquire(blocking=False):
            return 0
        done = 0
        try:
            for pending in self._store.pending_erasures():
                try:
                    completed = erase(pending) is True
                except Exception:  # noqa: BLE001 - retried at the next forget, expiry or start
                    completed = False
                if completed:
                    self._store.complete_erasure(pending.forget_id, pending.task_id)
                    done += 1
                record_bounded_event_without_raising(
                    component=_COMPONENT,
                    operation="code_copy_erasure",
                    reason="erased" if completed else "pending",
                )
        finally:
            self._draining.release()
        return done


def _never_closed(_task_id: str) -> bool:
    return False


# What an evidence job's reads are bound to (``ports.change_capture.evidence_bindings``).
_UNBOUND: Final = object()


def _bound(commitment: str, task_id: str) -> object:
    bindings = evidence_bindings()
    if bindings is None:
        return _UNBOUND
    return bindings.get(("code_copy", commitment, task_id), _UNBOUND)


def _bind(
    commitment: str, task_id: str | None, view: CopyView | None, *, first: bool = False
) -> None:
    """Bind the current evidence job's reads of ``task_id`` to ``view`` (None: the client).

    A sync that serves the job rebinds it; a reviewer read binds only the job's first."""

    bindings = evidence_bindings()
    if bindings is None or task_id is None:
        return
    key = ("code_copy", commitment, task_id)
    if first:
        bindings.setdefault(key, view)
    else:
        bindings[key] = view


def _copy_unavailable() -> WorkspaceAgentUnavailable:
    """A read of a task pinned to a copy that the copy cannot serve: the typed gap, never the
    client's live bytes (``code_copy_unavailable``)."""

    record_bounded_event_without_raising(
        component=_COMPONENT, operation="code_copy_read_failed", reason="code_copy_read_failed"
    )
    return WorkspaceAgentUnavailable("code_copy_unavailable")


def _original(manifest: SnapshotManifest) -> str | None:
    """The original base commit a copy base stands for (None: the repository had no commit)."""

    if set(manifest.original_base) == {"0"}:
        return None
    return manifest.original_base
