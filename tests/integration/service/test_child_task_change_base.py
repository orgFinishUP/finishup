"""A child task keeps its own task-start change base (ADR-031 decision 3).

A start that creates a task records HEAD as that task's base before its result returns, and that
includes a delegated child and a child created by parent registration. The base belongs to the
child, never to the parent whose session admitted it, and it is the repository state when the
child was created, not when its handle was later attached.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import cast

import pytest

from builders.multi_agent import MultiAgentService, multi_agent_service
from finishup.adapters.repository_identity import resolve_repository_privacy_context
from finishup.application.start import StartInternalResult
from finishup.ports.change_capture import TaskChangeBaseStorePort, decode_task_change_base
from finishup.ports.control import RepositoryPrivacyContext, WorkspaceLocator
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.keys import MacKeyPurpose
from finishup.ports.runtime import RouteAccess, RouteCommand
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import StartRequest

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "PATH": os.defpath,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
}


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ("git", *args), cwd=repo, check=True, env=_ENV, capture_output=True, text=True
    ).stdout.strip()


def _commit(repo: Path, name: str) -> str:
    (repo / name).write_text(f"{name}\n")
    _git(repo, "add", name)
    _git(repo, "commit", "--quiet", "-m", name)
    return _git(repo, "rev-parse", "HEAD")


def _repository(tmp_path: Path) -> tuple[Path, str]:
    repo = (tmp_path / "repo").resolve()
    repo.mkdir(mode=0o700)
    _git(repo, "init", "--quiet")
    return repo, _commit(repo, "a.txt")


def _request(workspace: Path, title: str, mode: str, **extra: object) -> StartRequest:
    body: dict[str, object] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": new_id(IdKind.REQUEST),
        "mode": mode,
        "task_title": title,
        "workspace_ref": str(workspace),
        "external_ref": title.lower().replace(" ", "-"),
        "actor": {"actor_id": "harness:child-base", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.3.0",
            "integration": "cooperative_mcp",
        },
        "requested_view": "compact",
    }
    body.update(extra)
    return StartRequest.model_validate(body)


async def _context(service: MultiAgentService, repo: Path) -> RepositoryPrivacyContext:
    lookup = service.vault.installation_mac_handle(MacKeyPurpose.CATALOG_LOOKUP)
    return await resolve_repository_privacy_context(WorkspaceLocator(str(repo)), lookup)


async def _base_commit(service: MultiAgentService, result: StartInternalResult) -> str | None:
    """The commit of the task-start base kept for the task ``result`` names, or ``None``."""

    app = service.app
    runtime = await app.runtime.route(
        RouteCommand(
            result.session_id,
            result.writer_id,
            RouteAccess.WRITE,
            frozenset({RuntimeCapability.WRITE}),
        )
    )
    try:
        assert runtime.task_id == result.task_id
        ref = await cast(TaskChangeBaseStorePort, runtime.ledger).load_task_change_base()
        if ref is None:
            return None
        data = b"".join([chunk async for chunk in runtime.objects.open_verified(ref)])
        return decode_task_change_base(data).commit
    finally:
        await app.runtime.release(runtime)


async def test_a_delegated_child_keeps_the_base_of_its_delegation(tmp_path: Path) -> None:
    repo, first = _repository(tmp_path)
    async with multi_agent_service(tmp_path / "state") as service:
        context = await _context(service, repo)
        parent = await service.app.start(
            _request(repo, "Parent task", "create"), repository_privacy_context=context
        )
        assert parent.outcome == "created"
        assert await _base_commit(service, parent) == first

        delegated_at = _commit(repo, "b.txt")
        delegated = await service.app.start(
            _request(repo, "Child task", "delegate", session_id=parent.session_id),
            repository_privacy_context=context,
        )
        assert delegated.outcome == "delegated"
        assert delegated.task_id != parent.task_id
        handle = delegated.as_wire()["attach_handle"]

        # Work done after the delegation, before the child attaches, belongs in its change.
        _commit(repo, "c.txt")
        attached = await service.app.start(
            _request(repo, "Child task", "attach", attach_handle=handle),
            repository_privacy_context=context,
        )
        assert attached.task_id == delegated.task_id

        assert await _base_commit(service, attached) == delegated_at
        # The parent keeps its own base; the delegation never moved it.
        assert await _base_commit(service, parent) == first


async def test_a_parent_registered_child_keeps_its_own_base(tmp_path: Path) -> None:
    repo, first = _repository(tmp_path)
    async with multi_agent_service(tmp_path / "state") as service:
        context = await _context(service, repo)
        parent = await service.app.start(
            _request(repo, "Parent task", "create"), repository_privacy_context=context
        )
        registered_at = _commit(repo, "b.txt")
        child = await service.app.start(
            _request(repo, "Self child", "create", parent_session_id=parent.session_id),
            repository_privacy_context=context,
        )
        assert child.task_id != parent.task_id

        assert await _base_commit(service, child) == registered_at
        assert await _base_commit(service, parent) == first


async def test_a_reattach_never_records_a_later_base(tmp_path: Path) -> None:
    repo, first = _repository(tmp_path)
    async with multi_agent_service(tmp_path / "state") as service:
        context = await _context(service, repo)
        created = await service.app.start(
            _request(repo, "Solo task", "create"), repository_privacy_context=context
        )
        _commit(repo, "b.txt")
        again = await service.app.start(
            _request(repo, "Solo task", "attach", session_id=created.session_id),
            repository_privacy_context=context,
        )
        assert again.outcome == "attached"
        assert again.task_id == created.task_id
        assert await _base_commit(service, again) == first
