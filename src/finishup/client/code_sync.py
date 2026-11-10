"""The helper's answer to the server's code-sync calls (level L2; design v2 §4.2, Q6, FR-7; ADR-054).

Only the target's helper builds one of these, for a background agent of a repository the owner
agreed to keep a copy of, and only while level L2 is released: a hook, an MCP bridge or a CLI
command never declares the two operations, so the server never asks them (the hub sends an
operation only to an agent that declares it).

``prepare`` checks, in this order and **before anything is read for the export** (FR-7):

1. level L2 is released in this process;
2. the connection's own admission still holds (``own_authorization``: generations, credential,
   the consent's identity, the repository's hold as admitted);
3. the gate again on the record as it is now (``client.authorization.gate``): zero network, the
   current disclosure, the kind, the consent verdict, the repository's hold;
4. the owner consented at L2 (the consented envelope's level), and the revision the server names
   is the one that consent admits (else ``server_profile_changed``: the server changed what it
   offers since the owner agreed);
5. the repository is not kept at L1 by the owner's per-repository choice, and that record can be
   read (fail closed).

Only then does it run the sanitized exporter (``client.code_export``) with the policy the owner
consented to (the envelope's caps and exclusions, the owner's per-repository list and allowed
contents) and keep the bundle in this process's memory for ``read`` (one per worktree, two minutes).
Each refusal is a closed token the server records as a gap; nothing is retried here.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Literal, Protocol

from finishup.client.code_copy_settings import CodeCopySettingsError, settings_for
from finishup.client.code_export import (
    ExportDatabase,
    ExportPolicy,
    ExportRefused,
    ExportRequest,
    export_snapshot,
)
from finishup.client.targets import ServerTarget, TargetError, read_target, target_root
from finishup.client.workspace_agent import CodeSyncRefused
from finishup.ports.workspace_agent import (
    CodeSyncPrepareArguments,
    CodeSyncPrepared,
    CodeSyncReadArguments,
)
from finishup.protocol.server_copy import l2_released

__all__ = ["CodeSyncRefused", "CodeSyncResponder", "export_folder", "subject_state_digest"]

_PREPARED_SECONDS: Final = 120.0
_NOT_CONSENTED: Final = "code_copy_not_consented"
_REFUSALS: Final = frozenset(
    {
        "repository_egress_held",
        "repository_egress_kept",
        "zero_network_remote_selected",
        "server_profile_changed",
        "server_authorization_changed",
    }
)
_UNAVAILABLE: Final = frozenset({"code_copy_too_large"})


class _Check(Protocol):
    def refusal(self) -> str | None: ...


def export_folder(target_id: str, repository_key: str) -> Path:
    """``<target root>/state/code-export/<digest of the repository key>``."""

    digest = hashlib.sha256(
        b"yoetz/code-export-folder/v1\x00" + repository_key.encode()
    ).hexdigest()
    return target_root(target_id) / "state" / "code-export" / digest[:32]


@dataclass(slots=True)
class _Prepared:
    sync_id: str
    bundle: bytes = field(repr=False)
    expires: float


# The helper may run several background agents for one worktree (one per registration), and the
# hub sends each call to the newest live one: a bundle prepared by one is read through another.
# So prepared bundles and export databases are kept per (target, repository) for the process,
# never per agent; at most one prepared bundle per repository.
_SHARED_LOCK: Final = threading.Lock()
_PREPARED: Final[dict[tuple[str, str], _Prepared]] = {}
_DATABASES: Final[dict[tuple[str, str], ExportDatabase]] = {}
_EXPORTS: Final[dict[tuple[str, str], threading.Lock]] = {}


def _shared_lock(key: tuple[str, str]) -> threading.Lock:
    with _SHARED_LOCK:
        return _EXPORTS.setdefault(key, threading.Lock())


class CodeSyncResponder:
    """Answers ``code_sync_prepare``/``code_sync_read`` for one claimed worktree (see the module
    text). Thread-safe: one export runs at a time; a later prepare replaces the bundle kept."""

    __slots__ = ("_check", "_clock", "_key", "_repository_key", "_root", "_target_id", "_worktree")

    def __init__(
        self,
        *,
        target_id: str,
        repository_key: str,
        root: Path,
        worktree: str,
        check: _Check | None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._target_id = target_id
        self._repository_key = repository_key
        self._root = root
        self._worktree = worktree
        self._check = check
        self._clock = clock
        self._key = (target_id, repository_key)

    # --- the gate (FR-7) ------------------------------------------------------------------------

    def _admitted(self, arguments: CodeSyncPrepareArguments) -> ServerTarget:
        """Every check of the module text, before anything is read; the record as it is now."""

        if not l2_released():
            raise CodeSyncRefused(_NOT_CONSENTED)
        if self._check is not None:
            refusal = self._check.refusal()
            if refusal is not None:
                raise CodeSyncRefused(
                    refusal if refusal in _REFUSALS else "server_authorization_changed"
                )
        from finishup.client.authorization import gate
        from finishup.client.server_profile import read_consented_envelope

        root = target_root(self._target_id)
        try:
            record = read_target(root)
            if record is None or record.target_id != self._target_id:
                raise CodeSyncRefused("server_authorization_changed")
            revision = gate(record, repository_key=self._repository_key)
        except TargetError as error:
            reason = error.reason
            raise CodeSyncRefused(
                reason if reason in _REFUSALS else "server_authorization_changed"
            ) from None
        consent = record.consent
        if consent is None or consent.level != "L2":
            raise CodeSyncRefused(_NOT_CONSENTED)
        envelope = read_consented_envelope(root, consent)
        if envelope is None or envelope.level != "L2" or envelope.code_sync is None:
            raise CodeSyncRefused(_NOT_CONSENTED)
        named = (arguments.issuer, arguments.revision, arguments.profile_digest)
        if (
            revision is None
            or (revision.issuer, revision.revision, revision.profile_digest) != named
        ):
            raise CodeSyncRefused("server_profile_changed")
        try:
            owner = settings_for(root, self._target_id, self._repository_key)
        except CodeCopySettingsError:
            raise CodeSyncRefused(_NOT_CONSENTED) from None
        if owner.level == "L1":
            raise CodeSyncRefused(_NOT_CONSENTED)
        return record

    # --- the two operations ---------------------------------------------------------------------

    def _policy(
        self, record: ServerTarget
    ) -> tuple[ExportPolicy, Literal["task_close", "days", "until_forgotten"], int | None]:
        """The export policy the owner consented to, and the retention chosen."""

        from finishup.client.server_profile import read_consented_envelope

        root = target_root(self._target_id)
        consent = record.consent
        envelope = None if consent is None else read_consented_envelope(root, consent)
        if consent is None or envelope is None or envelope.code_sync is None:
            raise CodeSyncRefused(_NOT_CONSENTED)
        try:
            owner = settings_for(root, self._target_id, self._repository_key)
        except CodeCopySettingsError:
            raise CodeSyncRefused(_NOT_CONSENTED) from None
        policy = ExportPolicy(
            server=tuple(sorted(envelope.exclusions)),
            owner=owner,
            max_file_bytes=envelope.code_sync.max_file_bytes,
            max_repo_bytes=envelope.code_sync.max_repo_bytes,
        )
        kind = consent.retention_kind or "until_forgotten"
        if kind not in {"task_close", "days", "until_forgotten"}:
            raise CodeSyncRefused(_NOT_CONSENTED)
        return policy, kind, consent.retention_days  # type: ignore[return-value]

    def prepare(self, arguments: CodeSyncPrepareArguments) -> CodeSyncPrepared:
        with _shared_lock(self._key):
            # Every check first (FR-7): nothing is read, written or built before they pass.
            record = self._admitted(arguments)
            policy, kind, days = self._policy(record)
            try:
                with _SHARED_LOCK:
                    database = _DATABASES.get(self._key)
                if database is None or not database.present:
                    database = ExportDatabase(export_folder(self._target_id, self._repository_key))
                    with _SHARED_LOCK:
                        _DATABASES[self._key] = database
                prepared = export_snapshot(
                    ExportRequest(
                        root=self._root,
                        purpose=arguments.purpose,
                        have=arguments.have,
                        issuer=arguments.issuer,
                        revision=arguments.revision,
                        profile_digest=arguments.profile_digest,
                        worktree=self._worktree,
                        subject_state=subject_state_digest(self._root),
                        base_commit=arguments.base_commit,
                    ),
                    policy,
                    database,
                    gate=_already_admitted,
                )
            except ExportRefused as refused:
                raise CodeSyncRefused(
                    refused.reason if refused.reason in _UNAVAILABLE else "code_export_failed"
                ) from None
            if prepared.unchanged:
                with _SHARED_LOCK:
                    _PREPARED.pop(self._key, None)
                return CodeSyncPrepared(True, None, prepared.manifest, 0, None, kind, days)
            sync_id = secrets.token_hex(16)
            with _SHARED_LOCK:
                _PREPARED[self._key] = _Prepared(
                    sync_id, prepared.bundle, self._clock() + _PREPARED_SECONDS
                )
            database.remember_sent(prepared.manifest.snapshot, prepared.ref_number)
            return CodeSyncPrepared(
                False, sync_id, prepared.manifest, len(prepared.bundle), prepared.sha256, kind, days
            )

    def read(self, arguments: CodeSyncReadArguments) -> bytes:
        with _SHARED_LOCK:
            prepared = _PREPARED.get(self._key)
            if (
                prepared is None
                or prepared.sync_id != arguments.sync_id
                or self._clock() > prepared.expires
                or arguments.offset >= len(prepared.bundle)
            ):
                raise CodeSyncRefused("code_sync_unknown")
            return prepared.bundle[arguments.offset : arguments.offset + arguments.length]

    def forget_local(self) -> None:
        """Delete this repository's export database (the copy was forgotten, or L2 → L1)."""

        with _shared_lock(self._key), _SHARED_LOCK:
            _PREPARED.pop(self._key, None)
            database = _DATABASES.pop(self._key, None) or ExportDatabase(
                export_folder(self._target_id, self._repository_key)
            )
            database.remove()


def subject_state_digest(root: Path) -> str | None:
    """The worktree's subject-state commitment, as the server's approved-check flow digests the
    subject state this computer's agent captures for it (``GIT_STRUCTURAL_V1``: its tree and diff
    digests), so a check run here can be compared with the snapshot the server read (design v2
    §8.6); None when it cannot be captured. Runs only after every check of ``prepare``."""

    from finishup.adapters.git_subject_state import GitSubjectStateAdapter, open_local_workspace
    from finishup.domain.values import JsonObject
    from finishup.ports.subject_state import SubjectStateCaptureCommand, SubjectStateFormat
    from finishup.protocol.canonical import canonical_digest

    try:
        handle = open_local_workspace(root, admitted_home_project=True)
        result = GitSubjectStateAdapter().capture(
            SubjectStateCaptureCommand(handle, SubjectStateFormat.GIT_STRUCTURAL_V1)
        )
    except Exception:  # noqa: BLE001 - an uncapturable subject state is no commitment
        return None
    state = result.subject_state
    if state is None:
        return None
    return canonical_digest(
        JsonObject({"tree_digest": state.tree_digest, "diff_digest": state.diff_digest})
    )


def _already_admitted() -> None:
    """The responder ran every check before calling the exporter."""
