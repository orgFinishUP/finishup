"""The service's side of level L2: pulling snapshots into the copy store (design v2 §4.2; ADR-054)."""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest
from tests.builders.server_copy import manifest_for, snapshot_objects

from finishup.ports.change_capture import TaskChangeBase
from finishup.ports.workspace_agent import (
    CodeSyncPrepareArguments,
    CodeSyncPrepared,
    CodeSyncReadArguments,
    WorkspaceAgentUnavailable,
    WorkspaceOnlyArguments,
    WorkspaceOperation,
)
from finishup.protocol.server_profile import ServerProfileRevision
from finishup.service import vault as vault_module
from finishup.service.code_copy import CODE_COPY_KEK_MAC_DOMAIN, CodeCopies, VaultCopyKeyring
from finishup.service.code_store import CodeStore, CodeStoreError, StoreLimits
from finishup.service.workspace_routing import RoutedChangeCapture

HANDLE = "client:0123456789abcdef"
COMMITMENT = "commitment-of-the-claim"
WORKTREE = "sha256:" + "c" * 64
REVISION = ServerProfileRevision("a" * 32, 2, "sha256:" + "b" * 64)
TRIPLE = (REVISION.issuer, REVISION.revision, REVISION.profile_digest)


class FakeMac:
    def __init__(self) -> None:
        self.key = os.urandom(32)
        self.locked = False

    def mac(self, domain: bytes, message: bytes) -> str:
        import hmac

        if self.locked:
            raise RuntimeError("vault_locked")
        assert domain == CODE_COPY_KEK_MAC_DOMAIN
        return "hmac-sha256:" + hmac.digest(self.key, domain + message, "sha256").hex()


_MAC = FakeMac()


class FakeHub:
    """Answers the two sync operations as the helper's agent would, from a prepared snapshot."""

    def __init__(self, bundle: bytes, prepared: CodeSyncPrepared) -> None:
        self.bundle = bundle
        self.prepared = prepared
        self.calls: list[str] = []
        self.refusal: WorkspaceAgentUnavailable | None = None
        self.gate: threading.Event | None = None
        self.code_copies: object = None

    def call_blocking(
        self,
        handle: str,
        operation: WorkspaceOperation,
        arguments: object,
        *,
        timeout_seconds: float,
    ) -> object:
        assert handle == HANDLE and timeout_seconds > 0
        self.calls.append(operation.value)
        if operation is WorkspaceOperation.CODE_SYNC_PREPARE:
            assert isinstance(arguments, CodeSyncPrepareArguments)
            self.named = (arguments.issuer, arguments.revision)
            if self.gate is not None:
                self.gate.wait(10)
            if self.refusal is not None:
                raise self.refusal
            return self.prepared
        if operation is WorkspaceOperation.CODE_SYNC_READ:
            assert isinstance(arguments, CodeSyncReadArguments)
            return self.bundle[arguments.offset : arguments.offset + arguments.length]
        assert isinstance(arguments, WorkspaceOnlyArguments)
        return TaskChangeBase("sha1", "d" * 40)


def _copies(tmp_path: Path, *, unchanged: bool = False) -> tuple[CodeCopies, FakeHub, CodeStore]:
    snap = snapshot_objects({"a.py": b"a\n"}, {"a.py": b"b\n", "c.py": b"c\n"})
    bundle = snap.bundle()
    manifest = manifest_for(snap, revision=TRIPLE, worktree=WORKTREE)
    prepared = (
        CodeSyncPrepared(True, None, manifest, 0, None, "days", 7)
        if unchanged
        else CodeSyncPrepared(
            False,
            "f" * 32,
            manifest,
            len(bundle),
            "sha256:" + __import__("hashlib").sha256(bundle).hexdigest(),
            "days",
            7,
        )
    )
    hub = FakeHub(bundle, prepared)
    store = CodeStore(
        tmp_path / "code-copies",
        VaultCopyKeyring(lambda: _MAC),
        StoreLimits(max_file_bytes=65_536, max_repo_bytes=1 << 20),
    )
    store.open()
    copies = CodeCopies(store, hub, lambda: REVISION)  # type: ignore[arg-type]
    hub.code_copies = copies
    return copies, hub, store


def test_a_handle_this_service_never_keyed_is_never_synced(tmp_path: Path) -> None:
    copies, hub, _store = _copies(tmp_path)
    outcome = copies.sync_blocking(HANDLE, purpose="base")
    assert (outcome.outcome, outcome.reason) == ("unavailable", "workspace_not_keyed")
    assert hub.calls == []


def test_a_sync_stores_the_snapshot_and_names_the_revision(tmp_path: Path) -> None:
    copies, hub, store = _copies(tmp_path)
    copies.remember(HANDLE, COMMITMENT, WORKTREE)
    outcome = copies.sync_blocking(HANDLE, purpose="check")
    assert outcome.outcome == "synced" and outcome.snapshot == hub.prepared.manifest.snapshot
    assert store.have("claim", COMMITMENT) == (hub.prepared.manifest.snapshot,)
    (summary,) = store.copies("claim")
    assert (summary.retention_kind, summary.retention_days) == ("days", 7)
    assert hub.calls[0] == "code_sync_prepare" and set(hub.calls[1:]) == {"code_sync_read"}


def test_a_helper_refusal_stores_nothing_and_is_named(tmp_path: Path) -> None:
    copies, hub, store = _copies(tmp_path)
    copies.remember(HANDLE, COMMITMENT, WORKTREE)
    hub.refusal = WorkspaceAgentUnavailable("agent_refused", "repository_egress_held")
    outcome = copies.sync_blocking(HANDLE, purpose="check")
    assert (outcome.outcome, outcome.reason) == ("refused", "repository_egress_held")
    assert store.copies("claim") == () and hub.calls == ["code_sync_prepare"]
    hub.refusal = WorkspaceAgentUnavailable("operation_not_declared")
    assert copies.sync_blocking(HANDLE, purpose="check").reason == "operation_not_declared"


def test_a_snapshot_for_another_worktree_or_revision_is_refused(tmp_path: Path) -> None:
    copies, _hub, store = _copies(tmp_path)
    copies.remember(HANDLE, COMMITMENT, "sha256:" + "9" * 64)
    assert copies.sync_blocking(HANDLE, purpose="check").reason == "code_manifest_mismatch"
    copies = CodeCopies(
        store, _hub, lambda: ServerProfileRevision("a" * 32, 3, REVISION.profile_digest)
    )  # type: ignore[arg-type]
    copies.remember(HANDLE, COMMITMENT, WORKTREE)
    assert copies.sync_blocking(HANDLE, purpose="check").reason == "server_profile_changed"
    assert store.copies("claim") == ()


def test_concurrent_syncs_of_one_repository_are_one_pull(tmp_path: Path) -> None:
    copies, hub, _store = _copies(tmp_path)
    copies.remember(HANDLE, COMMITMENT, WORKTREE)
    hub.gate = threading.Event()
    outcomes: list[object] = []
    first = threading.Thread(
        target=lambda: outcomes.append(copies.sync_blocking(HANDLE, purpose="check"))
    )
    first.start()
    while not hub.calls:
        threading.Event().wait(0.01)
    second = threading.Thread(
        target=lambda: outcomes.append(copies.sync_blocking(HANDLE, purpose="check"))
    )
    second.start()
    hub.gate.set()
    first.join(10)
    second.join(10)
    assert hub.calls.count("code_sync_prepare") == 1
    assert [getattr(item, "outcome") for item in outcomes] == ["synced", "synced"]


def test_an_unchanged_snapshot_must_already_be_held(tmp_path: Path) -> None:
    copies, _hub, _store = _copies(tmp_path, unchanged=True)
    copies.remember(HANDLE, COMMITMENT, WORKTREE)
    assert copies.sync_blocking(HANDLE, purpose="check").reason == "code_snapshot_unknown"


def test_a_routed_task_base_syncs_the_copy_first_and_still_reads_from_the_agent(
    tmp_path: Path,
) -> None:
    copies, hub, store = _copies(tmp_path)
    copies.remember(HANDLE, COMMITMENT, WORKTREE)
    routed = RoutedChangeCapture(object(), hub)  # type: ignore[arg-type]
    base = routed.read_task_base(HANDLE)
    assert base == TaskChangeBase("sha1", "d" * 40)
    assert hub.calls[0] == "code_sync_prepare" and hub.calls[-1] == "read_task_base"
    assert store.have("claim", COMMITMENT)


def test_copy_keys_are_derived_by_the_vault_per_copy_and_never_without_it() -> None:
    mac = FakeMac()
    keyring = VaultCopyKeyring(lambda: mac)
    data_key = os.urandom(32)
    wrapped = keyring.wrap("1" * 32, data_key)
    assert keyring.unwrap("1" * 32, wrapped) == data_key
    with pytest.raises(CodeStoreError, match="code_copy_wrap_unknown"):
        keyring.unwrap("2" * 32, wrapped)
    mac.locked = True
    with pytest.raises(CodeStoreError, match="vault_locked"):
        keyring.unwrap("1" * 32, wrapped)
    domains = vault_module._INSTALLATION_DOMAINS  # pyright: ignore[reportPrivateUsage]
    assert CODE_COPY_KEK_MAC_DOMAIN in domains[vault_module.MacKeyPurpose.CATALOG_LOOKUP]


# --- the code_copy control method (status, forget) --------------------------------------------------

_CLAIM_COMMITMENT = "hmac-sha256:" + "4" * 64


def _daemon(copies: object) -> object:
    from types import SimpleNamespace

    return SimpleNamespace(
        _composition=SimpleNamespace(workspace_hub=SimpleNamespace(code_copies=copies))
    )


def _code_copy(copies: object, action: str, *, kind: str = "cli", claim: bool = True) -> object:
    from types import SimpleNamespace

    from finishup.ports.control import ControlClientKind, RepositoryPrivacyContext
    from finishup.service.daemon import ServiceDaemon

    context = RepositoryPrivacyContext(
        commitment=_CLAIM_COMMITMENT,
        identity_kind="client_claim" if claim else "directory",
        workspace_handle=HANDLE if claim else None,
    )
    return ServiceDaemon._code_copy(  # pyright: ignore[reportPrivateUsage]
        _daemon(copies),  # type: ignore[arg-type]
        SimpleNamespace(body={"action": action}),  # type: ignore[arg-type]
        context,
        ControlClientKind(kind),
    )


def test_code_copy_answers_only_a_claim_of_a_service_that_keeps_copies(tmp_path: Path) -> None:
    from finishup.ports.control import ControlError

    copies, _hub, _store = _copies(tmp_path)
    for case in (
        lambda: _code_copy(None, "status"),
        lambda: _code_copy(copies, "status", claim=False),
        lambda: _code_copy(copies, "forget", kind="mcp_bridge"),
    ):
        with pytest.raises(ControlError, match="method_forbidden"):
            case()
    with pytest.raises(ControlError, match="frame_invalid"):
        _code_copy(copies, "delete")


def test_code_copy_status_and_forget_say_exactly_what_is_kept_and_deleted(tmp_path: Path) -> None:
    from finishup.protocol.schemas import validate_schema_instance

    copies, _hub, _store = _copies(tmp_path)
    assert _code_copy(copies, "status") == {"action": "status", "copy": None, "forgot": None}
    copies.remember(HANDLE, _CLAIM_COMMITMENT, WORKTREE)
    assert copies.sync_blocking(HANDLE, purpose="check").outcome == "synced"
    status = _code_copy(copies, "status")
    assert status["copy"]["snapshots"] == 1  # type: ignore[index]
    assert status["copy"]["retention"] == {"kind": "days", "days": 7}  # type: ignore[index]
    forgot = _code_copy(copies, "forget")
    assert forgot["forgot"]["copies"] == 1 and forgot["forgot"]["backups"] == "not_managed"  # type: ignore[index]
    assert forgot["forgot"]["objects"] > 0 and forgot["forgot"]["bytes"] > 0  # type: ignore[index]
    again = _code_copy(copies, "forget")
    assert again["forgot"] == {  # type: ignore[index]
        "copies": 0,
        "snapshots": 0,
        "objects": 0,
        "bytes": 0,
        "backups": "not_managed",
    }
    assert _code_copy(copies, "status")["copy"] is None  # type: ignore[index]
    for body in (status, forgot):
        validate_schema_instance(
            "control-result",
            "2.10.0",
            {
                "protocol_version": "1.0",
                "rpc_id": "rpc_12345678-1234-4123-8123-123456789abc",
                "service_instance_id": "svc_12345678-1234-4123-8123-123456789abc",
                "service_generation": "1",
                "method": "code_copy",
                "outcome": "ok",
                "body": body,
            },
        )
