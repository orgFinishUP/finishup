"""Rule R: with a server elsewhere, a start names only the worktree its connection serves.

The owner chose rule R (run u8, 2026-11-12) for a FinishUP server on another machine: the
connection's own folder decides the repository and the worktree, as on ``main``, and
``workspace_ref`` never selects which repository is disclosed. A start whose absolute
``workspace_ref`` names another repository, another worktree of the same repository, or a folder
that is no repository or does not exist is refused in the client, typed
(``workspace_ref_not_served``), before it is sent. A subfolder of the served worktree, a symlinked
spelling of it and, on a case-insensitive file system, a spelling that differs only by case are
the served worktree: folders are compared by file identity, never as strings. A connection bound
by a local path, or not bound, is ``main``'s L0 behaviour: its request is sent exactly as written.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from finishup.client.workspace_ref import (
    WorkspaceRefNotServed,
    names_served_workspace,
    portable_start_request,
    portable_workspace_ref,
    start_request_for_connection,
)
from finishup.ports.control import WorkspaceBinding, WorkspaceLocator
from finishup.protocol.errors import PublicErrorCode
from finishup.protocol.models import StartRequest

_HANDLE = "client:0123456789abcdef"


def _git(*arguments: str) -> None:
    subprocess.run(  # noqa: S603 - fixed argv
        [
            "git",
            "-c",
            "user.name=FinishUP Test",
            "-c",
            "user.email=test@finishup.invalid",
            *arguments,
        ],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"},
    )


def _repository(path: Path) -> Path:
    path.mkdir(parents=True)
    _git("-C", os.fspath(path), "init", "-q")
    (path / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    _git("-C", os.fspath(path), "add", "tracked.txt")
    _git("-C", os.fspath(path), "commit", "-q", "-m", "initial")
    return path


@pytest.fixture
def layout(tmp_path: Path) -> dict[str, Path]:
    served = _repository(tmp_path / "proj")
    subfolder = served / "src" / "deeper"
    subfolder.mkdir(parents=True)
    other = _repository(tmp_path / "other")
    _git("-C", os.fspath(served), "branch", "feature")
    linked = tmp_path / "proj-feature"
    _git("-C", os.fspath(served), "worktree", "add", "-q", os.fspath(linked), "feature")
    alias = tmp_path / "alias"
    alias.symlink_to(served, target_is_directory=True)
    plain = tmp_path / "plain"
    plain.mkdir()
    # A repository nested inside the served one (a vendored checkout or a submodule) is another
    # repository even though its path lies under the served worktree.
    nested = _repository(served / "vendor" / "nested")
    a_file = served / "tracked.txt"
    return {
        "served": served,
        "subfolder": subfolder,
        "other": other,
        "linked": linked,
        "alias": alias,
        "plain": plain,
        "nested": nested,
        "missing": tmp_path / "missing",
        "file": a_file,
    }


def _start(workspace_ref: str | None) -> StartRequest:
    body: dict[str, object] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": "req_00000000-0000-4000-8000-000000000042",
        "actor": {"actor_id": "harness:mcp", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
        "mode": "create_or_attach",
        "task_title": "Remote task",
        "requested_view": "compact",
    }
    if workspace_ref is not None:
        body["workspace_ref"] = workspace_ref
        body["external_ref"] = "host-session:1"
    return StartRequest.model_validate(body)


def _claim_bound(workspace_ref: str | None, serving: Path | str | None) -> str | None:
    return portable_workspace_ref(
        workspace_ref,
        workspace_binding="client_claim",
        workspace_handle=_HANDLE,
        serving=None if serving is None else os.fspath(serving),
    )


@pytest.mark.parametrize("named", ["served", "subfolder", "alias"])
@pytest.mark.parametrize("serving", ["served", "subfolder", "alias"])
def test_the_served_worktree_in_any_spelling_is_sent_as_the_handle(
    layout: dict[str, Path], named: str, serving: str
) -> None:
    # A connection made from a subfolder serves its worktree, so either side may be a subfolder.
    assert names_served_workspace(os.fspath(layout[named]), os.fspath(layout[serving]))
    assert _claim_bound(os.fspath(layout[named]), layout[serving]) == _HANDLE
    # A trailing separator or a dot segment is the same folder.
    assert _claim_bound(os.fspath(layout[named]) + "/./", layout[serving]) == _HANDLE


@pytest.mark.parametrize("named", ["other", "linked", "plain", "nested", "missing", "file"])
def test_any_other_folder_is_refused_typed_before_anything_is_sent(
    layout: dict[str, Path], named: str
) -> None:
    """Another repository; another worktree of the served repository (#1346: identity is not
    recomputed, only the worktree compared); a folder that is no repository; a repository nested
    under the served worktree; a path that does not exist; a file."""

    with pytest.raises(WorkspaceRefNotServed) as raised:
        _claim_bound(os.fspath(layout[named]), layout["served"])
    refusal = raised.value
    assert refusal.code is PublicErrorCode.INVALID_REQUEST
    assert refusal.retryable is False
    assert dict(refusal.safe_details) == {
        "continuation": "workspace_folder_run_required",
        "field": "/workspace_ref",
        "reason_code": "workspace_ref_not_served",
    }
    # Nothing user-controlled travels: neither folder's path appears anywhere in the refusal.
    text = repr(refusal) + refusal.message + repr(dict(refusal.safe_details))
    for path in layout.values():
        assert os.fspath(path) not in text
        assert path.name not in {"proj", "other"} or f"/{path.name}" not in text
    assert not names_served_workspace(os.fspath(layout[named]), os.fspath(layout["served"]))


def test_the_rule_holds_in_both_directions_between_a_checkout_and_its_linked_worktree(
    layout: dict[str, Path],
) -> None:
    with pytest.raises(WorkspaceRefNotServed):
        _claim_bound(os.fspath(layout["served"]), layout["linked"])
    with pytest.raises(WorkspaceRefNotServed):
        _claim_bound(os.fspath(layout["linked"]), layout["served"])
    assert _claim_bound(os.fspath(layout["linked"]), layout["linked"]) == _HANDLE


def test_a_held_repository_named_from_an_unheld_folder_and_the_reverse_are_refused(
    layout: dict[str, Path],
) -> None:
    """Which repository is held changes nothing here: the client never names, reads or syncs
    another repository for a start, so the refusal comes before any hold is consulted."""

    with pytest.raises(WorkspaceRefNotServed):
        _claim_bound(os.fspath(layout["other"]), layout["served"])
    with pytest.raises(WorkspaceRefNotServed):
        _claim_bound(os.fspath(layout["served"]), layout["other"])


def test_a_case_variant_is_the_served_folder_only_where_the_file_system_folds_case(
    layout: dict[str, Path],
) -> None:
    served = layout["served"]
    variant = served.parent / served.name.upper()
    folds_case = variant.exists() and os.path.samefile(variant, served)
    if folds_case:
        # macOS APFS by default: the same folder, so served.
        assert _claim_bound(os.fspath(variant), served) == _HANDLE
        return
    # A case-sensitive file system: no such folder, or another one; refused either way.
    with pytest.raises(WorkspaceRefNotServed):
        _claim_bound(os.fspath(variant), served)
    variant.mkdir()
    with pytest.raises(WorkspaceRefNotServed):
        _claim_bound(os.fspath(variant), served)


def test_a_connection_that_names_no_served_folder_refuses_every_path(
    layout: dict[str, Path],
) -> None:
    with pytest.raises(WorkspaceRefNotServed):
        _claim_bound(os.fspath(layout["served"]), None)
    with pytest.raises(WorkspaceRefNotServed):
        _claim_bound(os.fspath(layout["served"]), layout["missing"])


@pytest.mark.parametrize("value", [None, "label", "relative/path", _HANDLE])
def test_a_value_that_is_no_absolute_path_is_left_for_the_server_to_judge(
    layout: dict[str, Path], value: str | None
) -> None:
    """Unchanged by rule R: the server accepts only this connection's handle, or no workspace."""

    assert _claim_bound(value, layout["other"]) == value


@pytest.mark.parametrize("binding", ["none", "local_path"])
def test_l0_sends_any_folder_as_written_as_main_does(layout: dict[str, Path], binding: str) -> None:
    """``main``'s L0 behaviour, pinned where rule R is nearest: a local or unbound connection
    sends ``workspace_ref`` exactly as written, even when it names another repository than the
    folder the client runs in (``main`` reads git evidence from the connection's folder and the
    reviewer's files from the named one; that mix-up is issue #1349 for ``main``)."""

    request = _start(os.fspath(layout["other"]))
    for serving in (os.fspath(layout["served"]), None):
        assert (
            portable_start_request(
                request,
                workspace_binding=cast(WorkspaceBinding, binding),
                workspace_handle=None,
                serving=serving,
            )
            is request
        )
    connection = SimpleNamespace(workspace_binding=binding, workspace_handle=None)
    assert (
        start_request_for_connection(
            request, connection, serving=WorkspaceLocator(os.fspath(layout["served"]))
        )
        is request
    )


def test_the_connection_path_takes_the_folder_it_serves_and_the_bridge_says_so(
    layout: dict[str, Path],
) -> None:
    bound = SimpleNamespace(workspace_binding="client_claim", workspace_handle=_HANDLE)
    serving = WorkspaceLocator(os.fspath(layout["subfolder"]))
    sent = start_request_for_connection(_start(os.fspath(layout["served"])), bound, serving=serving)
    assert sent.workspace_ref == _HANDLE
    with pytest.raises(WorkspaceRefNotServed) as raised:
        start_request_for_connection(
            _start(os.fspath(layout["other"])), bound, serving=serving, surface="bridge"
        )
    # An agent behind an MCP bridge cannot restart it in another folder: it is told to say so
    # and carry on without FinishUP for that folder, not to run anything from there.
    assert raised.value.safe_details["continuation"] == "workspace_not_served_tell_user"
    assert "host started" in raised.value.message
