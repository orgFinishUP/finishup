"""The service's side of level L2: pulling snapshots into the copy store (design v2 §4.2; ADR-054)."""

from __future__ import annotations

import os
import threading
from dataclasses import replace
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
        self.chunk_refusal: WorkspaceAgentUnavailable | None = None
        self.gate: threading.Event | None = None
        self.code_copies: object = None
        self.handles = {HANDLE}
        self.prepares: list[tuple[str, str | None]] = []
        self.entered = threading.Event()
        self.worktrees: dict[str, str] = {}

    def call_blocking(
        self,
        handle: str,
        operation: WorkspaceOperation,
        arguments: object,
        *,
        timeout_seconds: float,
    ) -> object:
        assert handle in self.handles and timeout_seconds > 0
        self.calls.append(operation.value)
        if operation is WorkspaceOperation.CODE_SYNC_PREPARE:
            assert isinstance(arguments, CodeSyncPrepareArguments)
            self.named = (arguments.issuer, arguments.revision)
            self.prepares.append((handle, arguments.base_commit))
            self.entered.set()
            if self.gate is not None:
                self.gate.wait(10)
            if self.refusal is not None:
                raise self.refusal
            if handle in self.worktrees:
                manifest = replace(self.prepared.manifest, worktree=self.worktrees[handle])
                return replace(self.prepared, manifest=manifest)
            return self.prepared
        if operation is WorkspaceOperation.CODE_SYNC_READ:
            assert isinstance(arguments, CodeSyncReadArguments)
            if self.chunk_refusal is not None and arguments.offset > 0:
                raise self.chunk_refusal
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
    copies = CodeCopies(store, hub, lambda: REVISION)  # type: ignore[arg-type]  # pyright: ignore[reportArgumentType]
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


def test_copies_an_offer_left_are_kept_listed_and_forgotten_but_never_synced_or_read(
    tmp_path: Path,
) -> None:
    """The server's owner withdrew the offer: its copies are neither synced nor read, and can
    still be listed, forgotten and expire (no one-way door)."""

    copies, hub, store = _copies(tmp_path)
    copies.remember(HANDLE, COMMITMENT, WORKTREE)
    assert copies.sync_blocking(HANDLE, purpose="check").outcome == "synced"
    retained = CodeCopies(store, hub, lambda: REVISION, serving=False)  # type: ignore[arg-type]  # pyright: ignore[reportArgumentType]
    retained.remember(HANDLE, COMMITMENT, WORKTREE)
    calls = len(hub.calls)
    refused = retained.sync_blocking(HANDLE, purpose="check", task_id="tsk_kept")
    assert (refused.outcome, refused.reason) == ("refused", "server_level_unavailable")
    assert len(hub.calls) == calls  # the client was never asked
    assert not retained.serving and copies.serving
    assert retained.reader_view(HANDLE, "tsk_kept") is None
    assert len(store.copies("claim")) == 1
    report = retained.forget(COMMITMENT)
    assert (report.copies, report.snapshots) == (1, 1)
    assert store.copies("claim") == ()


def test_a_helper_refusal_stores_nothing_and_is_named(tmp_path: Path) -> None:
    copies, hub, store = _copies(tmp_path)
    copies.remember(HANDLE, COMMITMENT, WORKTREE)
    hub.refusal = WorkspaceAgentUnavailable("agent_refused", "repository_egress_held")
    outcome = copies.sync_blocking(HANDLE, purpose="check")
    assert (outcome.outcome, outcome.reason) == ("refused", "repository_egress_held")
    assert store.copies("claim") == () and hub.calls == ["code_sync_prepare"]
    hub.refusal = WorkspaceAgentUnavailable("operation_not_declared")
    assert copies.sync_blocking(HANDLE, purpose="check").reason == "operation_not_declared"


def test_a_chunk_the_helper_refuses_after_the_prepare_is_a_refusal_and_admits_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """C1: the owner narrowed what may leave after the prepare; the helper refuses the chunk."""

    from finishup.service import code_copy

    monkeypatch.setattr(code_copy, "MAX_CODE_SYNC_CHUNK_BYTES", 64)
    copies, hub, store = _copies(tmp_path)
    copies.remember(HANDLE, COMMITMENT, WORKTREE)
    assert hub.prepared.size > 64
    hub.chunk_refusal = WorkspaceAgentUnavailable("agent_refused", "code_copy_not_consented")
    outcome = copies.sync_blocking(HANDLE, purpose="check", task_id="tsk_narrowed")
    assert (outcome.outcome, outcome.reason) == ("refused", "code_copy_not_consented")
    assert store.copies("claim") == () and hub.calls.count("code_sync_read") == 2
    assert copies.git_view(HANDLE, purpose="check", base=None, task_id="tsk_narrowed") == (
        None,
        None,
    )


def test_an_unchanged_sync_refreshes_the_copy_s_retention_and_sync_time(tmp_path: Path) -> None:
    """C2: the consent changed from until_forgotten to days:7 while the tree stayed the same."""

    copies, hub, store = _copies(tmp_path)
    copies.remember(HANDLE, COMMITMENT, WORKTREE)
    hub.prepared = replace(hub.prepared, retention_kind="until_forgotten", retention_days=None)
    assert copies.sync_blocking(HANDLE, purpose="check").outcome == "synced"
    (before,) = store.copies("claim")
    assert before.retention_kind == "until_forgotten"
    hub.prepared = CodeSyncPrepared(
        True,
        None,
        replace(hub.prepared.manifest, subject_state="sha256:" + "5" * 64),
        0,
        None,
        "days",
        7,
    )
    outcome = copies.sync_blocking(HANDLE, purpose="check")
    assert outcome.outcome == "unchanged"
    (after,) = store.copies("claim")
    assert (after.retention_kind, after.retention_days) == ("days", 7)
    assert (after.last_sync_at or "") >= (before.last_sync_at or "")
    stored = store.snapshot("claim", COMMITMENT, outcome.snapshot or "")
    assert stored.subject_state == "sha256:" + "5" * 64
    # A manifest that is not the held snapshot's is refused, never stored.
    hub.prepared = replace(hub.prepared, manifest=replace(hub.prepared.manifest, files=99))
    refused = copies.sync_blocking(HANDLE, purpose="check")
    assert (refused.outcome, refused.reason) == ("refused", "code_manifest_mismatch")


def test_a_snapshot_for_another_worktree_or_revision_is_refused(tmp_path: Path) -> None:
    copies, _hub, store = _copies(tmp_path)
    copies.remember(HANDLE, COMMITMENT, "sha256:" + "9" * 64)
    assert copies.sync_blocking(HANDLE, purpose="check").reason == "code_manifest_mismatch"
    copies = CodeCopies(
        store,
        _hub,  # type: ignore[arg-type]  # pyright: ignore[reportArgumentType]
        lambda: ServerProfileRevision("a" * 32, 3, REVISION.profile_digest),
    )
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


@pytest.mark.parametrize("differs", ["worktree", "base"])
def test_a_pull_under_way_answers_only_the_same_worktree_and_base(
    tmp_path: Path, differs: str
) -> None:
    """C3: linked worktrees share the repository's commitment; one waits, then pulls its own."""

    other_handle = "client:fedcba9876543210"
    other_worktree = "sha256:" + "d" * 64 if differs == "worktree" else WORKTREE
    other_base = "e" * 40 if differs == "base" else None
    copies, hub, _store = _copies(tmp_path)
    hub.handles.add(other_handle)
    hub.worktrees[other_handle] = other_worktree
    copies.remember(HANDLE, COMMITMENT, WORKTREE)
    copies.remember(other_handle, COMMITMENT, other_worktree)
    hub.gate = threading.Event()
    outcomes: dict[str, object] = {}
    first = threading.Thread(
        target=lambda: outcomes.setdefault(
            "first", copies.sync_blocking(HANDLE, purpose="check", task_id="tsk_first")
        )
    )
    first.start()
    assert hub.entered.wait(10)
    second = threading.Thread(
        target=lambda: outcomes.setdefault(
            "second",
            copies.sync_blocking(
                other_handle, purpose="check", base_commit=other_base, task_id="tsk_second"
            ),
        )
    )
    second.start()
    hub.gate.set()
    first.join(10)
    second.join(10)
    # One at a time, and the second made its own pull from its own worktree's agent.
    assert hub.prepares == [(HANDLE, None), (other_handle, other_base)]
    assert [getattr(outcomes[name], "outcome") for name in ("first", "second")] == [
        "synced",
        "synced",
    ]
    assert outcomes["second"] is not outcomes["first"]


def _base_view_under_deadline(copies: CodeCopies, seconds: float, task_id: str) -> object:
    """``git_view`` for a task-start base inside a control call with ``seconds`` left."""

    import asyncio

    from finishup.service.workspace_hub import workspace_call_deadline

    async def call() -> object:
        with workspace_call_deadline(asyncio.get_running_loop().time() + seconds):
            return await asyncio.to_thread(
                copies.git_view, HANDLE, purpose="base", base=None, task_id=task_id
            )

    return asyncio.run(call())


def _wait_for(condition: object, seconds: float = 10.0) -> bool:
    finished = threading.Event()
    deadline = threading.Event()
    timer = threading.Timer(seconds, deadline.set)
    timer.start()
    try:
        while not deadline.is_set():
            if condition():  # type: ignore[operator]
                finished.set()
                break
            deadline.wait(0.02)
    finally:
        timer.cancel()
    return finished.is_set()


@pytest.mark.parametrize("seconds", [3.0, 1.0])
def test_a_task_start_base_never_awaits_a_sync_past_its_call_s_deadline(
    tmp_path: Path, seconds: float
) -> None:
    """C4 (design v2 §8.9): a SessionStart hook gives its start five seconds; a sync that cannot
    finish within them goes on in the background and the client's agent reads the base."""

    copies, hub, store = _copies(tmp_path)
    copies.remember(HANDLE, COMMITMENT, WORKTREE)
    hub.gate = threading.Event()  # the helper is still scanning and bundling
    view = _base_view_under_deadline(copies, seconds, "tsk_hooked")
    # Returned while the sync was still under way: never a stale or older snapshot either.
    assert view == (None, None)
    assert not hub.gate.is_set() and store.copies("claim") == ()
    hub.gate.set()
    # The sync finished in the background: the copy is current and the task is pinned to it,
    # its reads staying with the client (the base was read there).
    assert _wait_for(lambda: store.pin_entry("claim", COMMITMENT, "tsk_hooked") is not None)
    entry = store.pin_entry("claim", COMMITMENT, "tsk_hooked")
    assert entry is not None and entry.snapshot == hub.prepared.manifest.snapshot
    assert not entry.served


def test_a_task_start_base_sync_that_finishes_in_time_is_read_from_the_copy(
    tmp_path: Path,
) -> None:
    copies, _hub, _store = _copies(tmp_path)
    copies.remember(HANDLE, COMMITMENT, WORKTREE)
    view, _effective = _base_view_under_deadline(copies, 30.0, "tsk_in_time")  # type: ignore[misc]
    assert view is not None and not view.stale  # type: ignore[union-attr]


def test_an_unchanged_snapshot_must_already_be_held(tmp_path: Path) -> None:
    copies, _hub, _store = _copies(tmp_path, unchanged=True)
    copies.remember(HANDLE, COMMITMENT, WORKTREE)
    assert copies.sync_blocking(HANDLE, purpose="check").reason == "code_snapshot_unknown"


def test_a_routed_task_base_syncs_first_and_without_a_checkout_reads_from_the_agent(
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
    assert forgot["forgot"]["complete"] is True  # type: ignore[index]
    assert forgot["forgot"]["objects"] > 0 and forgot["forgot"]["bytes"] > 0  # type: ignore[index]
    again = _code_copy(copies, "forget")
    assert again["forgot"] == {  # type: ignore[index]
        "copies": 0,
        "snapshots": 0,
        "objects": 0,
        "bytes": 0,
        "backups": "not_managed",
        "complete": True,
    }
    assert _code_copy(copies, "status")["copy"] is None  # type: ignore[index]
    for body in (status, forgot):
        validate_schema_instance(
            "control-result",
            "2.10.0",
            {  # pyright: ignore[reportArgumentType]
                "protocol_version": "1.0",
                "rpc_id": "rpc_12345678-1234-4123-8123-123456789abc",
                "service_instance_id": "svc_12345678-1234-4123-8123-123456789abc",
                "service_generation": "1",
                "method": "code_copy",
                "outcome": "ok",
                "body": body,
            },
        )


def test_a_forget_while_the_helper_prepares_fences_that_sync(tmp_path: Path) -> None:
    copies, hub, store = _copies(tmp_path)
    copies.remember(HANDLE, COMMITMENT, WORKTREE)
    original = hub.call_blocking

    def forget_meanwhile(
        handle: str, operation: WorkspaceOperation, arguments: object, *, timeout_seconds: float
    ) -> object:
        answer = original(handle, operation, arguments, timeout_seconds=timeout_seconds)
        if operation is WorkspaceOperation.CODE_SYNC_PREPARE:
            # The owner forgets while the helper was building the snapshot.
            store.forget("claim", COMMITMENT)
        return answer

    hub.call_blocking = forget_meanwhile  # type: ignore[method-assign]
    outcome = copies.sync_blocking(HANDLE, purpose="check")
    assert (outcome.outcome, outcome.reason) == ("refused", "code_copy_forgotten")
    assert store.copies("claim") == ()


def test_a_task_start_sync_left_on_a_stale_helper_agent_completes_at_the_newer_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """macOS dogfood: a helper stopped (or was replaced or killed) without its agent being unregistered at
    the server; a task started at once sends the sync's prepare to that agent, which nobody
    answers. The successor helper's agent registers a moment later: the prepare goes on there,
    the sync completes long before the prepare's deadline, and the task reads the copy it made
    (not the copy as last synced, nor this computer)."""

    import asyncio

    from finishup.ports.control import WorkspaceAgentDeclaration, WorkspaceCall, WorkspaceReply
    from finishup.ports.workspace_agent import WORKSPACE_OPERATION_NAMES, operation_spec
    from finishup.service import code_copy as code_copy_module
    from finishup.service.workspace_hub import (
        WorkspaceAgentChannel,
        WorkspaceAgentHub,
        WorkspaceCallWriter,
    )

    # Bounds a regression's wait; the takeover itself happens within a second.
    monkeypatch.setattr(code_copy_module, "_PREPARE_SECONDS", 8.0)
    _copies_unused, helper, store = _copies(tmp_path)
    declaration = WorkspaceAgentDeclaration(
        tuple(sorted(WORKSPACE_OPERATION_NAMES, key=str.encode)), 6_291_456, role="background"
    )

    async def run() -> tuple[object, list[str], list[str], float]:
        hub = WorkspaceAgentHub(inline_wait_seconds=2.0, background_wait_seconds=2.0)
        copies = CodeCopies(store, hub, lambda: REVISION)
        copies.remember(HANDLE, COMMITMENT, WORKTREE)
        stale: list[str] = []
        fresh: list[str] = []

        async def silent(call: WorkspaceCall) -> None:
            stale.append(call.operation)

        holder: list[WorkspaceAgentChannel] = []

        async def answering(call: WorkspaceCall) -> None:
            fresh.append(call.operation)
            spec = operation_spec(call.operation)
            assert spec is not None
            value = helper.call_blocking(
                HANDLE,
                WorkspaceOperation(call.operation),
                spec.decode_arguments(call.arguments),
                timeout_seconds=1.0,
            )
            reply = WorkspaceReply(
                "workspace_reply", "1.0", call.call_id, "ok", spec.encode_result(value), None
            )
            asyncio.get_running_loop().call_soon(hub.deliver, holder[0], reply)

        async def register(writer: WorkspaceCallWriter) -> WorkspaceAgentChannel:
            return await hub.register(
                handle=HANDLE,
                declaration=declaration,
                service_instance_id="svc_00000000-0000-4000-8000-000000000054",
                service_generation="7",
                writer=writer,
                worktree=WORKTREE,
            )

        older = await register(silent)
        loop = asyncio.get_running_loop()
        began = loop.time()
        start = asyncio.ensure_future(
            asyncio.to_thread(copies.git_view, HANDLE, purpose="base", base=None, task_id="tsk_u5")
        )
        while not stale:
            assert loop.time() - began < 5.0, "the prepare never reached the stale agent"
            await asyncio.sleep(0.01)
        holder.append(await register(answering))
        view = await start
        took = loop.time() - began
        assert older.pending_count == 0 and not older.closed
        return view, stale, fresh, took

    (view, _effective), stale, fresh, took = asyncio.run(run())  # type: ignore[misc]
    assert stale == ["code_sync_prepare"]
    assert fresh[:1] == ["code_sync_prepare"] and set(fresh[1:]) == {"code_sync_read"}
    assert view is not None and not view.stale  # type: ignore[union-attr]
    assert view.manifest.snapshot == helper.prepared.manifest.snapshot  # type: ignore[union-attr]
    assert took < 4.0
