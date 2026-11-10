"""Level L2 reads: the server reads a claim-bound task's evidence from its copy (design v2 §4.1,
§8.6; ADR-054), on real repositories through the real exporter, verifier, store and adapters."""

from __future__ import annotations

import hashlib
import hmac
import os
import stat
from pathlib import Path
from typing import Any, cast

import pytest
from tests.builders.server_copy import git

from finishup.adapters.approved_checks import (
    ApprovedCheckCommand,
    ApprovedCheckOutcome,
    ApprovedCheckStatus,
    approved_check_result_digest,
)
from finishup.adapters.git_change_capture import GitChangeCaptureAdapter
from finishup.application.observation_check_policy import parse_observation_check_policy
from finishup.client.code_copy_settings import RepositoryCodeSettings
from finishup.client.code_export import (
    ExportDatabase,
    ExportPolicy,
    ExportRequest,
    export_snapshot,
)
from finishup.client.code_sync import subject_state_digest
from finishup.ports.approved_checks import ApprovedCheckResult
from finishup.ports.change_capture import (
    CheckChangeCapture,
    TaskChangeBase,
    evidence_task_scope,
)
from finishup.ports.workspace_agent import (
    ApprovedCheckRun,
    CaptureArguments,
    CodeSyncPrepareArguments,
    CodeSyncPrepared,
    CodeSyncReadArguments,
    OutsideInputsRead,
    WorkspaceAgentUnavailable,
    WorkspaceOperation,
)
from finishup.protocol.server_profile import ServerProfileRevision
from finishup.service.code_checkout import CopyCheckouts
from finishup.service.code_copy import CODE_COPY_KEK_MAC_DOMAIN, CodeCopies, VaultCopyKeyring
from finishup.service.code_store import CodeStore, StoreLimits
from finishup.service.workspace_hub import WorkspaceAgentHub
from finishup.service.workspace_routing import (
    ClientWorkspaceReads,
    RoutedChangeCapture,
    RoutedObservationWorkspace,
)

HANDLE = "client:0123456789abcdef"
COMMITMENT = "commitment-of-the-claim"
WORKTREE = "sha256:" + "c" * 64
REVISION = ServerProfileRevision("a" * 32, 1, "sha256:" + "b" * 64)
POLICY = ExportPolicy(
    server=(), owner=RepositoryCodeSettings(), max_file_bytes=65_536, max_repo_bytes=1 << 20
)
AWS_KEY = b"aws_access_key_id = AKIA" + b"ABCDEFGHIJKLMNOP" + b"\n"
TASK = "task_one"
OPENED = "rws_" + "0" * 32


class _Mac:
    def __init__(self) -> None:
        self.key = os.urandom(32)

    def mac(self, domain: bytes, message: bytes) -> str:
        assert domain == CODE_COPY_KEK_MAC_DOMAIN
        return "hmac-sha256:" + hmac.digest(self.key, domain + message, "sha256").hex()


class ClientHub:
    """The client in process: the helper's sync over the real exporter, and every other read
    answered by the local adapters on the client's repository, as its workspace agent would."""

    def __init__(self, root: Path, export: Path) -> None:
        self.root = root
        self.database = ExportDatabase(export)
        self.calls: list[str] = []
        self.offline = False
        self.refusal: str | None = None
        self.bundle = b""
        self.code_copies: object = None
        self.local = GitChangeCaptureAdapter(admitted_home_project=True)
        self.run_result: ApprovedCheckResult | None = None

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
        if self.offline:
            raise WorkspaceAgentUnavailable("no_agent")
        if operation is WorkspaceOperation.CODE_SYNC_PREPARE:
            assert isinstance(arguments, CodeSyncPrepareArguments)
            if self.refusal is not None:
                raise WorkspaceAgentUnavailable("agent_refused", self.refusal)
            prepared = export_snapshot(
                ExportRequest(
                    root=self.root,
                    purpose=arguments.purpose,
                    have=arguments.have,
                    issuer=arguments.issuer,
                    revision=arguments.revision,
                    profile_digest=arguments.profile_digest,
                    worktree=WORKTREE,
                    subject_state=subject_state_digest(self.root),
                    base_commit=arguments.base_commit,
                ),
                POLICY,
                self.database,
                gate=lambda: None,
            )
            if prepared.unchanged:
                return CodeSyncPrepared(True, None, prepared.manifest, 0, None, "task_close", None)
            self.database.remember_sent(prepared.manifest.snapshot, prepared.ref_number)
            self.bundle = prepared.bundle
            return CodeSyncPrepared(
                False,
                "f" * 32,
                prepared.manifest,
                len(prepared.bundle),
                prepared.sha256,
                "task_close",
                None,
            )
        if operation is WorkspaceOperation.CODE_SYNC_READ:
            assert isinstance(arguments, CodeSyncReadArguments)
            return self.bundle[arguments.offset : arguments.offset + arguments.length]
        root = os.fspath(self.root)
        if operation is WorkspaceOperation.READ_TASK_BASE:
            return self.local.read_task_base(root)
        if operation is WorkspaceOperation.CAPTURE:
            assert isinstance(arguments, CaptureArguments)
            return self.local.capture(root, arguments.base)
        if operation is WorkspaceOperation.READ_TEXT_BENEATH:
            return (b"from the client\n", 16)
        if operation is WorkspaceOperation.READ_OUTSIDE_INPUTS:
            return OutsideInputsRead((), ())
        if operation is WorkspaceOperation.OPEN_WORKSPACE:
            return OPENED
        if operation is WorkspaceOperation.RUN_APPROVED_CHECK:
            assert self.run_result is not None
            return ApprovedCheckRun(self.run_result, None, False)
        raise AssertionError(operation)


def _repository(tmp_path: Path, files: dict[str, bytes]) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "a real message")
    return root


def _service(tmp_path: Path, root: Path) -> tuple[ClientHub, CodeCopies, RoutedChangeCapture]:
    hub = ClientHub(root, tmp_path / "export")
    (tmp_path / "state").mkdir(mode=0o700)
    mac = _Mac()
    store = CodeStore(
        tmp_path / "state" / "code-copies",
        VaultCopyKeyring(lambda: mac),  # type: ignore[arg-type,return-value]  # pyright: ignore[reportArgumentType,reportReturnType]
        StoreLimits(max_file_bytes=65_536, max_repo_bytes=1 << 20),
    )
    store.open()
    checkouts = CopyCheckouts(tmp_path / "state" / "code-copies" / "checkouts", store)
    checkouts.sweep()
    copies = CodeCopies(
        store,
        cast(WorkspaceAgentHub, hub),
        lambda: REVISION,
        checkouts=checkouts,
    )
    copies.remember(HANDLE, COMMITMENT, WORKTREE)
    hub.code_copies = copies
    routed = RoutedChangeCapture(
        GitChangeCaptureAdapter(admitted_home_project=True), cast(WorkspaceAgentHub, hub)
    )
    return hub, copies, routed


def _changed(capture: CheckChangeCapture) -> set[str]:
    return {
        line.split(" b/", 1)[1]
        for line in capture.text.decode().splitlines()
        if line.startswith("diff --git ")
    }


def _client_only(hub: ClientHub) -> list[str]:
    return [call for call in hub.calls if not call.startswith("code_sync_")]


def test_a_task_base_and_its_capture_are_read_from_the_copy_as_the_client_reads_them(
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path, {"a.py": b"a = 1\n", "b.py": b"b = 1\n", "lib/c.py": b"c\n"})
    (root / "notes.txt").write_bytes(b"untracked before the task\n")
    hub, copies, routed = _service(tmp_path, root)
    client_base = GitChangeCaptureAdapter().read_task_base(os.fspath(root))
    with evidence_task_scope(TASK):
        base = routed.read_task_base(HANDLE)
        (root / "a.py").write_bytes(b"a = 2\n")
        (root / "b.py").unlink()
        (root / "new.py").write_bytes(b"new\n")
        capture = routed.capture(HANDLE, base)
    expected = GitChangeCaptureAdapter().capture(os.fspath(root), client_base)
    # Served by the copy: the client's agent was only asked to sync.
    assert _client_only(hub) == []
    assert _changed(capture) == _changed(expected) == {"a.py", "b.py", "new.py"}
    assert (capture.tracked_files, capture.untracked_files) == (
        expected.tracked_files,
        expected.untracked_files,
    )
    # The base is the copy's synthetic base, never the client's commit (no ancestry crossed).
    pinned = copies.pinned_manifest(HANDLE, TASK)
    assert pinned is not None and base.commit != client_base.commit
    assert capture.base_commit == pinned.base
    account = copies.provenance(TASK)
    assert account is not None and account.count("server_copy_read") == 2
    assert account.snapshot is not None and account.snapshot.tree == pinned.tree


def test_a_held_out_file_never_reads_as_changed_or_deleted(tmp_path: Path) -> None:
    root = _repository(tmp_path, {"app.py": b"ok\n", "settings.py": b"debug = True\n"})
    (root / ".env").write_bytes(b"TOKEN=x\n")
    hub, _copies, routed = _service(tmp_path, root)
    with evidence_task_scope(TASK):
        base = routed.read_task_base(HANDLE)
        # A secret appears in a tracked file: it is held out of both trees from now on.
        (root / "settings.py").write_bytes(b"debug = True\n" + AWS_KEY)
        (root / ".env").write_bytes(b"TOKEN=y\n")
        (root / "app.py").write_bytes(b"changed\n")
        capture = routed.capture(HANDLE, base)
    assert _changed(capture) == {"app.py"}
    assert b"AKIA" not in capture.text and b"TOKEN" not in capture.text
    assert _client_only(hub) == []


def test_an_untracked_file_present_at_task_start_stays_baseline_across_checks(
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path, {"a.py": b"a\n"})
    (root / "scratch.txt").write_bytes(b"predates the task\n")
    _hub, _copies, routed = _service(tmp_path, root)
    with evidence_task_scope(TASK):
        base = routed.read_task_base(HANDLE)
        assert {item.path for item in base.untracked} == {"scratch.txt"}
        (root / "a.py").write_bytes(b"a2\n")
        first = routed.capture(HANDLE, base)
        (root / "later.py").write_bytes(b"later\n")
        second = routed.capture(HANDLE, base)
    assert _changed(first) == {"a.py"}
    assert _changed(second) == {"a.py", "later.py"}


def test_a_task_whose_base_the_client_read_keeps_every_git_read_with_the_client(
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path, {"a.py": b"a\n"})
    hub, copies, routed = _service(tmp_path, root)
    client_base = GitChangeCaptureAdapter().read_task_base(os.fspath(root))
    (root / "a.py").write_bytes(b"b\n")
    with evidence_task_scope(TASK):
        capture = routed.capture(HANDLE, client_base)
    assert "capture" in hub.calls  # the client's agent answered
    assert capture.base_commit == client_base.commit
    assert copies.reader_view(HANDLE, TASK) is None
    account = copies.provenance(TASK)
    assert account is not None
    assert (account.count("server_copy_read"), account.count("client_attested_read")) == (0, 1)


def test_an_offline_client_s_reads_come_from_the_copy_as_last_synced_and_checks_fail(
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path, {"a.py": b"a\n"})
    hub, copies, routed = _service(tmp_path, root)
    with evidence_task_scope(TASK):
        base = routed.read_task_base(HANDLE)
        (root / "a.py").write_bytes(b"synced\n")
        routed.capture(HANDLE, base)
        synced = copies.provenance(TASK)
        hub.offline = True
        (root / "a.py").write_bytes(b"never synced\n")
        stale = routed.capture(HANDLE, base)
    assert b"+synced" in stale.text and b"never synced" not in stale.text
    account = copies.provenance(TASK)
    assert account is not None and synced is not None
    assert account.count("stale_copy_read") == 1
    assert account.snapshot == synced.snapshot  # the sync time of the copy read
    # An approved check needs the client: it is the typed gap, never a pass.
    policy = parse_observation_check_policy(
        b'format = "yoetz.approved-check-policy/1"\n\n[[checks]]\nid = "smoke"\n'
        b'argv = ["/usr/bin/true"]\ntimeout_seconds = 10\nnetwork = false\n'
    )
    (approval,) = policy.checks
    hub.offline = False
    access = RoutedObservationWorkspace(cast(WorkspaceAgentHub, hub), cast(Any, None))
    handle = access.open(HANDLE)
    hub.offline = True
    runner = access.runner({approval.approval_commitment: approval})
    with evidence_task_scope(TASK), pytest.raises(WorkspaceAgentUnavailable) as raised:
        runner.run(ApprovedCheckCommand(handle, approval, "sha256:" + "3" * 64))
    assert raised.value.reason == "no_agent"


def test_a_reviewer_read_after_an_offline_check_is_a_stale_read_and_a_fresh_sync_ends_it(
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path, {"src/a.py": b"synced\n"})
    hub, copies, routed = _service(tmp_path, root)
    state = os.fspath(tmp_path / "state")
    reads = ClientWorkspaceReads(cast(WorkspaceAgentHub, hub), HANDLE)
    with evidence_task_scope(TASK):
        base = routed.read_task_base(HANDLE)
        hub.offline = True
        routed.capture(HANDLE, base)
        read = reads.read_text_beneath(HANDLE, "src/a.py", excluded=(state,), expired=lambda: False)
    assert read == (b"synced\n", 7)
    account = copies.provenance(TASK)
    assert account is not None
    # The capture and the reviewer's read both read the copy as last synced.
    assert (account.count("stale_copy_read"), account.count("server_copy_read")) == (2, 1)
    hub.offline = False
    with evidence_task_scope(TASK):
        routed.capture(HANDLE, base)
        reads.read_text_beneath(HANDLE, "src/a.py", excluded=(state,), expired=lambda: False)
    account = copies.provenance(TASK)
    assert account is not None
    assert (account.count("stale_copy_read"), account.count("server_copy_read")) == (2, 3)


def test_a_refused_sync_never_reads_the_copy(tmp_path: Path) -> None:
    root = _repository(tmp_path, {"a.py": b"a\n"})
    hub, copies, routed = _service(tmp_path, root)
    with evidence_task_scope(TASK):
        base = routed.read_task_base(HANDLE)
        assert copies.reader_view(HANDLE, TASK) is not None
        hub.refusal = "repository_egress_held"
        (root / "a.py").write_bytes(b"b\n")
        # The client's agent answers (a held client refuses it there, as at level L1).
        routed.capture(HANDLE, base)
        reads = ClientWorkspaceReads(cast(WorkspaceAgentHub, hub), HANDLE)
        text = reads.read_text_beneath(HANDLE, "a.py", excluded=(), expired=lambda: False)
    assert "capture" in hub.calls and "read_text_beneath" in hub.calls
    assert text == (b"from the client\n", 16)
    assert copies.reader_view(HANDLE, TASK) is None


def test_reviewer_reads_beneath_the_root_come_from_the_pinned_snapshot_and_are_counted(
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path, {"src/a.py": b"pinned\n"})
    (root / "outside.txt").write_bytes(b"x\n")
    hub, copies, routed = _service(tmp_path, root)
    state = os.fspath(tmp_path / "state")
    with evidence_task_scope(TASK):
        routed.read_task_base(HANDLE)
        (root / "src" / "a.py").write_bytes(b"changed after the pin\n")
        reads = ClientWorkspaceReads(cast(WorkspaceAgentHub, hub), HANDLE)
        text = reads.read_text_beneath(HANDLE, "src/a.py", excluded=(state,), expired=lambda: False)
        listing = reads.list_beneath(HANDLE, "src", excluded=(state,), expired=lambda: False)
        hidden = reads.list_beneath(HANDLE, "", excluded=(state,), expired=lambda: False)
        test = reads.read_declared_test(HANDLE + "/src/a.py", excluded=(state,))
        reads.read_outside_inputs(("/srv",), ("/srv/x",))
    assert text == (b"pinned\n", 7) and test == b"pinned\n"
    assert listing == ((("a.py", False),), False)
    assert hidden is not None and ".git" not in {name for name, _ in hidden[0]}
    assert _client_only(hub) == ["read_outside_inputs"]
    account = copies.provenance(TASK)
    assert account is not None
    assert (account.count("server_copy_read"), account.count("outside_read")) == (5, 1)


def test_the_checkout_is_owner_only_never_follows_a_link_and_forget_removes_it(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_bytes(b"outside the repository\n")
    root = _repository(tmp_path, {"a.py": b"a\n"})
    (root / "link").symlink_to(outside / "secret.txt")
    (root / "dir").mkdir()
    (root / "dir" / "x.py").write_bytes(b"x\n")
    hub, copies, routed = _service(tmp_path, root)
    with evidence_task_scope(TASK):
        routed.read_task_base(HANDLE)
        reads = ClientWorkspaceReads(cast(WorkspaceAgentHub, hub), HANDLE)
        assert reads.read_text_beneath(HANDLE, "link", excluded=(), expired=lambda: False) is None
        # The directory becomes a link to a folder outside: the checkout never writes through it.
        (root / "dir" / "x.py").unlink()
        (root / "dir").rmdir()
        (root / "dir").symlink_to(outside)
        (root / "a.py").write_bytes(b"b\n")
        base = routed.read_task_base(HANDLE)
        routed.capture(HANDLE, base)
        assert (tmp_path / "state" / "code-copies" / "checkouts").is_dir()
        # And back to a folder: the link is replaced, never written through.
        (root / "dir").unlink()
        (root / "dir").mkdir()
        (root / "dir" / "x.py").write_bytes(b"y\n")
        routed.read_task_base(HANDLE)
    folders = list((tmp_path / "state" / "code-copies" / "checkouts").iterdir())
    assert len(folders) == 1
    checkout = folders[0]
    assert stat.S_IMODE(checkout.stat().st_mode) == 0o700
    assert stat.S_IMODE((checkout / "a.py").stat().st_mode) == 0o600
    assert (checkout / "link").is_symlink() and not (checkout / "dir").is_symlink()
    assert (checkout / "dir" / "x.py").read_bytes() == b"y\n"
    assert sorted(path.name for path in outside.iterdir()) == ["secret.txt"]
    report = copies.forget(COMMITMENT)
    assert report.copies == 1 and [task.task_id for task in report.tasks] == [TASK]
    assert not checkout.exists()
    (pending,) = copies.store.pending_erasures()
    assert pending.task_id == TASK and pending.reason == "owner"
    assert pending.account.count("server_copy_read") >= 1


def test_an_approved_check_of_another_subject_than_the_pinned_snapshot_is_never_a_pass(
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path, {"a.py": b"a\n"})
    hub, copies, routed = _service(tmp_path, root)
    policy = parse_observation_check_policy(
        b'format = "yoetz.approved-check-policy/1"\n\n[[checks]]\nid = "smoke"\n'
        b'argv = ["/usr/bin/true"]\ntimeout_seconds = 10\nnetwork = false\n'
    )
    (approval,) = policy.checks

    def passed(subject: str) -> ApprovedCheckResult:
        return ApprovedCheckResult(
            ApprovedCheckStatus.PASSED,
            ApprovedCheckOutcome.SUCCESS,
            0,
            None,
            0,
            subject,
            approval.approval_commitment,
            approved_check_result_digest(
                ApprovedCheckStatus.PASSED,
                ApprovedCheckOutcome.SUCCESS,
                0,
                None,
                0,
                subject,
                approval.approval_commitment,
                5,
            ),
            5,
        )

    access = RoutedObservationWorkspace(cast(WorkspaceAgentHub, hub), cast(Any, None))
    handle = access.open(HANDLE)
    runner = access.runner({approval.approval_commitment: approval})
    cast(Any, runner).bind_evidence_task(TASK)
    with evidence_task_scope(TASK):
        routed.read_task_base(HANDLE)
    subject = subject_state_digest(root)
    assert subject is not None
    hub.run_result = passed(subject)
    same = runner.run(ApprovedCheckCommand(handle, approval, subject))
    assert same.status is ApprovedCheckStatus.PASSED
    # The tree the check ran on is not the snapshot the server read: stale, never a pass.
    other = "sha256:" + hashlib.sha256(b"another subject").hexdigest()
    hub.run_result = passed(other)
    mismatch = runner.run(ApprovedCheckCommand(handle, approval, other))
    assert (mismatch.status, mismatch.outcome) == (
        ApprovedCheckStatus.STALE,
        ApprovedCheckOutcome.SUBJECT_STATE_MISMATCH,
    )
    pinned = copies.pinned_manifest(HANDLE, TASK)
    assert pinned is not None and pinned.subject_state == subject
    account = copies.provenance(TASK)
    assert account is not None and account.count("client_check") == 2


def test_task_close_retention_expires_once_no_pinned_task_is_open(tmp_path: Path) -> None:
    root = _repository(tmp_path, {"a.py": b"a\n"})
    _hub, copies, routed = _service(tmp_path, root)
    with evidence_task_scope(TASK):
        routed.read_task_base(HANDLE)
    with evidence_task_scope("task_two"):
        routed.read_task_base(HANDLE)
    closed: set[str] = set()
    copies.attach_task_closed(closed.__contains__)
    assert copies.expire_now().copies == 0
    closed.add(TASK)
    assert copies.expire_now().copies == 0
    closed.add("task_two")
    report = copies.expire_now()
    assert report.copies == 1 and report.reason == "expired"
    assert {task.task_id for task in report.tasks} == {TASK, "task_two"}
    assert {item.reason for item in copies.store.pending_erasures()} == {"expired"}

    def broken(_task: str) -> bool:
        raise RuntimeError("catalog unavailable")

    copies.attach_task_closed(broken)  # unknown is open: nothing expires
    with evidence_task_scope(TASK):
        routed.read_task_base(HANDLE)
    assert copies.expire_now().copies == 0


def test_a_pending_erasure_is_cleared_only_once_its_task_says_so(tmp_path: Path) -> None:
    root = _repository(tmp_path, {"a.py": b"a\n"})
    _hub, copies, routed = _service(tmp_path, root)
    with evidence_task_scope(TASK):
        routed.read_task_base(HANDLE)
    copies.forget(COMMITMENT)
    seen: list[str] = []
    answers = [False, True]

    def erase(pending: object) -> bool:
        seen.append(cast(Any, pending).task_id)
        return answers.pop(0)

    copies._erase = erase  # pyright: ignore[reportPrivateUsage]  # attached without the thread
    assert copies.drain_erasures() == 0 and copies.store.pending_erasures()
    assert copies.drain_erasures() == 1 and copies.store.pending_erasures() == ()
    assert seen == [TASK, TASK]


def test_reads_without_a_task_are_neither_pinned_nor_counted(tmp_path: Path) -> None:
    root = _repository(tmp_path, {"a.py": b"a\n"})
    hub, copies, routed = _service(tmp_path, root)
    base = routed.read_task_base(HANDLE)
    assert isinstance(base, TaskChangeBase)
    assert copies.provenance(TASK) is None
    assert copies.store.task_ids("claim", COMMITMENT) == ()
    assert _client_only(hub) == []


def test_a_write_beneath_the_checkout_never_goes_through_a_link_left_in_its_way(
    tmp_path: Path,
) -> None:
    from finishup.protocol.server_copy import MODE_REGULAR
    from finishup.service import code_checkout

    checkout = tmp_path / "checkout"
    checkout.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.mkdir()
    (checkout / "dir").symlink_to(outside)
    root = os.open(checkout, os.O_RDONLY | os.O_DIRECTORY)
    try:
        code_checkout._write_beneath(root, b"dir/x.py", MODE_REGULAR, b"x\n")  # pyright: ignore[reportPrivateUsage]
    finally:
        os.close(root)
    assert list(outside.iterdir()) == []
    assert not (checkout / "dir").is_symlink()
    assert (checkout / "dir" / "x.py").read_bytes() == b"x\n"
