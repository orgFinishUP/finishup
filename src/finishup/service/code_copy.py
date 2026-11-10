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
4. a task's sync pins the snapshot to the task (design v2 §8.6).

Every outcome is a closed token, recorded as a bounded event; a sync that fails, is refused or
finds no helper never fails the read it precedes, which goes on as at level L1 (the client's agent
answers, attested). Nothing here runs while the service keeps no copies.

``VaultCopyKeyring`` wraps each copy's data key under the vault's authority: the key-encryption
key of a copy is the vault's installation MAC over the copy id under its own domain
(``yoetz/code-copy-kek/v1``), so it exists only while the vault is unlocked and is never stored.
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Literal

from cryptography.hazmat.primitives import keywrap

from finishup.observability.logging import record_bounded_event_without_raising
from finishup.ports.workspace_agent import (
    MAX_CODE_SYNC_CHUNK_BYTES,
    CodeSyncPrepareArguments,
    CodeSyncPrepared,
    CodeSyncReadArguments,
    WorkspaceAgentUnavailable,
    WorkspaceOperation,
)
from finishup.service.code_store import CodeStore, CodeStoreError, ForgetReport, WrappedKey

if TYPE_CHECKING:
    from finishup.ports.keys import MacKeyHandle
    from finishup.protocol.server_profile import ServerProfileRevision
    from finishup.service.workspace_hub import WorkspaceAgentHub

__all__ = [
    "CODE_COPY_KEK_MAC_DOMAIN",
    "COPY_PRINCIPAL",
    "CodeCopies",
    "SyncOutcome",
    "VaultCopyKeyring",
]

CODE_COPY_KEK_MAC_DOMAIN: Final = b"yoetz/code-copy-kek/v1\x00"
# The claim the service keyed is already namespaced by the caller's principal (an API key's at
# the REST edge, the owner's over SSH), so its commitment separates principals (Q7).
COPY_PRINCIPAL: Final = "claim"
_PREPARE_SECONDS: Final = 60.0
_READ_SECONDS: Final = 30.0
_COMPONENT: Final = "service.code_copy"
_EXPIRY_SECONDS: Final = 600.0


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
    """What one sync did: ``synced`` (``snapshot`` named), ``unchanged`` or a closed refusal."""

    outcome: Literal["synced", "unchanged", "refused", "unavailable"]
    reason: str | None = None
    snapshot: str | None = None
    synced_at: str | None = None


@dataclass(frozen=True, slots=True)
class _Claim:
    commitment: str
    worktree: str | None


class _Flight:
    __slots__ = ("done", "outcome")

    def __init__(self) -> None:
        self.done = threading.Event()
        self.outcome: SyncOutcome | None = None


class CodeCopies:
    """Pulls snapshots into the copy store (see the module text)."""

    __slots__ = ("_claims", "_expiry", "_flights", "_hub", "_lock", "_revision", "_store")

    def __init__(
        self,
        store: CodeStore,
        hub: WorkspaceAgentHub,
        revision: Callable[[], ServerProfileRevision | None],
    ) -> None:
        self._store = store
        self._hub = hub
        self._revision = revision
        self._lock = threading.Lock()
        self._claims: dict[str, _Claim] = {}
        self._flights: dict[str, _Flight] = {}
        self._expiry = threading.Event()

    @property
    def store(self) -> CodeStore:
        return self._store

    def remember(self, handle: str | None, commitment: str, worktree: str | None) -> None:
        """A claim this service keyed: ``handle`` names that repository's commitment."""

        if handle is None:
            return
        with self._lock:
            if len(self._claims) >= 4_096 and handle not in self._claims:
                self._claims.pop(next(iter(self._claims)))
            self._claims[handle] = _Claim(commitment, worktree)

    def commitment_of(self, handle: str) -> str | None:
        with self._lock:
            claim = self._claims.get(handle)
        return None if claim is None else claim.commitment

    def sync_blocking(
        self,
        handle: str,
        *,
        purpose: Literal["base", "check"],
        base_commit: str | None = None,
        task_id: str | None = None,
    ) -> SyncOutcome:
        """Sync ``handle``'s repository now, from a worker thread (coalesced, bounded)."""

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
            return flight.outcome or SyncOutcome("unavailable", "code_sync_busy")
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
        if prepared.unchanged:
            if manifest.snapshot not in self._store.have(COPY_PRINCIPAL, claim.commitment):
                return SyncOutcome("unavailable", "code_snapshot_unknown")
            self._pin(claim, task_id, manifest.snapshot)
            return SyncOutcome("unchanged", None, manifest.snapshot, manifest.synced_at)
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
            return SyncOutcome("unavailable", exc.agent_reason or exc.reason)
        except CodeStoreError as error:
            return SyncOutcome("refused", error.reason)
        self._pin(claim, task_id, manifest.snapshot)
        return SyncOutcome("synced", None, manifest.snapshot, manifest.synced_at)

    def _pin(self, claim: _Claim, task_id: str | None, snapshot: str) -> None:
        if task_id is None:
            return
        try:
            self._store.pin(COPY_PRINCIPAL, claim.commitment, _task_key(task_id), snapshot)
        except CodeStoreError:
            return

    def expire_now(self) -> ForgetReport:
        """Forget every copy whose retention ran out (design v2 §4.3). A ``task_close`` copy
        needs the tasks pinned to it, which only reads from the copy pin: none is due yet."""

        try:
            report = self._store.expire(task_closed=lambda _task: False)
        except CodeStoreError as error:
            record_bounded_event_without_raising(
                component=_COMPONENT, operation="code_copy_expiry", reason=error.reason
            )
            return ForgetReport(reason="expired")
        if report.copies:
            record_bounded_event_without_raising(
                component=_COMPONENT, operation="code_copy_expiry", reason="expired"
            )
        return report

    def start_expiry(self, every_seconds: float = _EXPIRY_SECONDS) -> None:
        """Run the expiry now and then every ``every_seconds`` in a daemon thread, until
        ``stop_expiry``."""

        self.expire_now()

        def loop() -> None:
            while not self._expiry.wait(every_seconds):
                self.expire_now()

        threading.Thread(target=loop, name="finishup-code-copy-expiry", daemon=True).start()

    def stop_expiry(self) -> None:
        self._expiry.set()

    def forget(self, commitment: str) -> ForgetReport:
        """Forget the copy of the repository ``commitment`` names (``code_forget``)."""

        return self._store.forget(COPY_PRINCIPAL, commitment)


def _task_key(task_id: str) -> str:
    """A pin's key: the task id's digest (the store keeps no ledger id in plaintext)."""

    return hashlib.sha256(b"yoetz/code-copy-pin/v1\x00" + task_id.encode()).hexdigest()[:64]
