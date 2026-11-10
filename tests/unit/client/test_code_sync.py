"""The helper's answer to the server's code-sync calls (level L2; design v2 §4.2, FR-7; ADR-054)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from tests.builders.server_copy import git, release_l2
from tests.builders.server_profiles import consent_to, profile_document
from tests.builders.server_targets import ambient_home, open_remote_kinds, record_remote_target

from finishup.adapters.workspace_root import canonical_workspace_root
from finishup.client.code_copy_settings import update_settings
from finishup.client.code_sync import CodeSyncResponder, export_folder
from finishup.client.everyday_policy import record_reported_policy, record_repository_report
from finishup.client.repository_hold import repository_key
from finishup.client.targets import ServerTarget, registry_lock, target_root
from finishup.client.workspace_agent import CodeSyncRefused, WorkspaceAgentHandler
from finishup.domain.values import JsonObject
from finishup.ports.control import WorkspaceCall, WorkspaceLocator
from finishup.ports.workspace_agent import (
    CodeSyncPrepareArguments,
    CodeSyncReadArguments,
    operation_spec,
)
from finishup.protocol.consent_envelope import Retention
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.server_copy import BundleLimits, verify_snapshot_bundle
from finishup.protocol.server_profile import ProfileLevels

_HANDLE = "client:0123456789abcdef"
_WORKTREE = "sha256:" + "c" * 64
_SYNC = {"code_sync_prepare", "code_sync_read"}


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    (root / "app.py").write_bytes(b"print('hello')\n")
    (root / ".env").write_bytes(b"TOKEN=1\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "first")
    (root / "app.py").write_bytes(b"print('changed')\n")
    return root


@pytest.fixture
def l2_target(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[ServerTarget, dict[str, Any]]]:
    with ambient_home(monkeypatch):
        open_remote_kinds(monkeypatch, "https", consent=False)
        document = profile_document(levels=ProfileLevels(("L1", "L2"), "L1"))
        record = consent_to(
            record_remote_target(), document, level="L2", retention=Retention("days", 7)
        )
        yield record, document


def _key(root: Path) -> str:
    return repository_key(asyncio.run(canonical_workspace_root(WorkspaceLocator(str(root)))))


def _arguments(document: dict[str, Any], **changes: object) -> CodeSyncPrepareArguments:
    revision = document["profile_revision"]
    values: dict[str, object] = {
        "workspace": _HANDLE,
        "purpose": "base",
        "have": (),
        "base_commit": None,
        "issuer": revision["issuer"],
        "revision": revision["revision"],
        "profile_digest": revision["profile_digest"],
    }
    values.update(changes)
    return CodeSyncPrepareArguments(**values)  # type: ignore[arg-type]


def _responder(record: ServerTarget, root: Path, **options: object) -> CodeSyncResponder:
    return CodeSyncResponder(
        target_id=record.target_id,
        repository_key=_key(root),
        root=root,
        worktree=_WORKTREE,
        check=None,
        **options,  # type: ignore[arg-type]
    )


def _refused(responder: CodeSyncResponder, arguments: CodeSyncPrepareArguments) -> str:
    with pytest.raises(CodeSyncRefused) as raised:
        responder.prepare(arguments)
    return raised.value.reason


# --- who declares the operations ------------------------------------------------------------------


def test_no_agent_but_one_given_a_responder_ever_declares_the_sync(repository: Path) -> None:
    locator = WorkspaceLocator(str(repository))
    assert not _SYNC & set(WorkspaceAgentHandler(locator).declaration.operations)
    assert not _SYNC & set(
        WorkspaceAgentHandler(locator, operations=_SYNC | {"capture"}).declaration.operations
    )
    background = WorkspaceAgentHandler(locator, role="background", code_sync=object())  # type: ignore[arg-type]
    assert _SYNC <= set(background.declaration.operations)
    with pytest.raises(ValueError, match="workspace_agent_code_sync_role_invalid"):
        WorkspaceAgentHandler(locator, code_sync=object())  # type: ignore[arg-type]
    spec = operation_spec("code_sync_prepare")
    assert spec is not None
    call = WorkspaceCall(
        kind="workspace_call",
        protocol_version="1.0",
        call_id=new_id(IdKind.CONTROL_RPC),
        service_instance_id="svc_01234567-89ab-4def-8123-456789abcdef",
        service_generation="1",
        operation="code_sync_prepare",
        arguments=JsonObject(spec.encode_arguments(_arguments(profile_document()))),
        deadline_ms=30_000,
    )
    reply = WorkspaceAgentHandler(locator).answer(call, workspace_handle=_HANDLE)
    assert (reply.outcome, reply.reason) == ("refused", "operation_not_declared")


# --- the gate runs before anything is read (FR-7) ---------------------------------------------------


@pytest.mark.parametrize(
    ("condition", "reason"),
    [
        ("held", "repository_egress_held"),
        ("zero_network", "zero_network_remote_selected"),
        ("owner_l1", "code_copy_not_consented"),
        ("other_revision", "server_profile_changed"),
    ],
)
def test_every_refusal_comes_before_any_export(
    l2_target: tuple[ServerTarget, dict[str, Any]],
    repository: Path,
    condition: str,
    reason: str,
) -> None:
    record, document = l2_target
    arguments = _arguments(document)
    key = _key(repository)
    if condition == "held":
        record_repository_report(key, str(repository), no_network=True)
    elif condition == "zero_network":
        record_reported_policy(zero_network=True)
    elif condition == "owner_l1":
        with registry_lock():
            update_settings(
                target_root(record.target_id),
                record.target_id,
                key,
                lambda settings: type(settings)(level="L1"),
            )
    else:
        arguments = _arguments(document, revision=document["profile_revision"]["revision"] + 1)
    with release_l2():
        assert _refused(_responder(record, repository), arguments) == reason
    assert not export_folder(record.target_id, key).exists()


def test_a_target_consented_at_l1_is_never_synced(
    monkeypatch: pytest.MonkeyPatch, repository: Path
) -> None:
    with ambient_home(monkeypatch):
        open_remote_kinds(monkeypatch, "https", consent=False)
        document = profile_document(levels=ProfileLevels(("L1", "L2"), "L1"))
        record = consent_to(record_remote_target(), document)
        with release_l2():
            assert _refused(_responder(record, repository), _arguments(document)) == (
                "code_copy_not_consented"
            )


# --- an admitted sync ---------------------------------------------------------------------------------


def test_an_admitted_sync_is_read_back_in_chunks_and_holds_the_consented_policy(
    l2_target: tuple[ServerTarget, dict[str, Any]], repository: Path
) -> None:
    record, document = l2_target
    clock = [0.0]
    responder = _responder(record, repository, clock=lambda: clock[0])
    with release_l2():
        prepared = responder.prepare(_arguments(document))
    assert not prepared.unchanged and prepared.sync_id is not None
    assert (prepared.retention_kind, prepared.retention_days) == ("days", 7)
    assert prepared.manifest.lists["excluded"] == (".env",)
    chunks: list[bytes] = []
    for offset in range(0, prepared.size, 100):
        chunks.append(responder.read(CodeSyncReadArguments(_HANDLE, prepared.sync_id, offset, 100)))
    bundle = b"".join(chunks)
    assert len(bundle) == prepared.size
    verified = verify_snapshot_bundle(
        bundle, have=lambda _o: None, limits=BundleLimits(max_file_bytes=1 << 24)
    )
    assert verified.snapshot == prepared.manifest.snapshot
    with pytest.raises(CodeSyncRefused, match="code_sync_unknown"):
        responder.read(CodeSyncReadArguments(_HANDLE, "f" * 32, 0, 10))
    clock[0] += 121
    with pytest.raises(CodeSyncRefused, match="code_sync_unknown"):
        responder.read(CodeSyncReadArguments(_HANDLE, prepared.sync_id, 0, 10))
    assert export_folder(record.target_id, _key(repository)).is_dir()
    responder.forget_local()
    assert not export_folder(record.target_id, _key(repository)).exists()
    _ = json


def test_a_bundle_prepared_by_one_agent_is_read_through_another_of_the_same_worktree(
    l2_target: tuple[ServerTarget, dict[str, Any]], repository: Path
) -> None:
    """The helper runs one background agent per registration; the hub asks the newest."""

    record, document = l2_target
    first = _responder(record, repository)
    second = _responder(record, repository)
    with release_l2():
        prepared = first.prepare(_arguments(document))
    assert prepared.sync_id is not None
    chunk = second.read(CodeSyncReadArguments(_HANDLE, prepared.sync_id, 0, prepared.size))
    assert len(chunk) == prepared.size
    # The export folder removed from elsewhere ('server code forget') is made again, never reused.
    first.forget_local()
    with release_l2():
        again = second.prepare(_arguments(document))
    assert not again.unchanged and export_folder(record.target_id, _key(repository)).is_dir()
