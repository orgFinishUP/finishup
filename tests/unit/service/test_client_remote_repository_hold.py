"""Approach A: nothing of a held repository reaches a server elsewhere (ADR-051 decision 8).

Maintainer decision of 2026-11-07, round 4. A repository whose privacy policy on this computer
allows no network use is held from a server on another machine, a port or the web until the
owner decides. The decision is made in the shared binding seam, so both connect paths of
``service.client`` refuse with the retryable phase ``repository_egress_held`` (or
``repository_egress_kept`` once the owner kept it here) before anything is dialled, a connector
is started or a claim is recorded; the connector opens no background agent for it either.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from builders.server_targets import ambient_home
from finishup.adapters.workspace_root import canonical_workspace_root
from finishup.client import targets
from finishup.client.everyday_policy import record_repository_report
from finishup.client.repository_hold import add_kept, add_override, repository_key
from finishup.config.paths import active_root, reset_selection_memo, selection_override
from finishup.ports.control import ControlClientKind, ControlError, WorkspaceLocator
from finishup.service import client as service_client

_AT = datetime(2026, 11, 7, 9, 30, tzinfo=UTC)
_STAMP = "2026-11-07T09:30:00.000Z"


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


@pytest.fixture(params=["ssh", "https", "local_port"])
def remote(home: Path, request: pytest.FixtureRequest) -> Path:
    kind = request.param
    with targets.registry_lock():
        if kind == "ssh":
            record, root = targets.new_remote_target(
                "lab", "ssh", host="lab.example", port=22, remote_launcher="/opt/fu/bin/finishup"
            )
        elif kind == "https":
            record, root = targets.new_remote_target(
                "web", "https", base_url="https://finishup.example"
            )
        else:
            record, root = targets.new_remote_target(
                "port", "local_port", base_url="https://127.0.0.1:8443"
            )
        targets.write_selection(record)
    reset_selection_memo()
    assert active_root() == root
    return root


@pytest.fixture
def nothing_dialled(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    started: list[str] = []

    def spawn(_root: Path) -> None:
        started.append("connector")

    def refuse(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("a remote root never starts or supersedes a local service")

    async def dial() -> object:
        started.append("dial")
        raise OSError("never dialled")

    monkeypatch.setattr("finishup.client.connector_status.spawn_connector", spawn)
    monkeypatch.setattr(service_client, "connect_control", dial)
    monkeypatch.setattr(service_client, "_spawn_service_process", refuse)
    monkeypatch.setattr(service_client, "supersede_incompatible_service", refuse)
    return started


def _workspace(remote: Path) -> WorkspaceLocator:
    directory = (remote.parent / "repo").resolve()
    directory.mkdir(exist_ok=True)
    return WorkspaceLocator(str(directory))


def _report_no_network(workspace: WorkspaceLocator) -> str:
    key = repository_key(asyncio.run(canonical_workspace_root(workspace)))
    assert record_repository_report(key, workspace.path, no_network=True, now=_AT)
    return key


def _refused_phase(workspace: WorkspaceLocator) -> list[tuple[str, str | None, bool]]:
    async def exercise() -> list[tuple[str, str | None, bool]]:
        found: list[tuple[str, str | None, bool]] = []
        for connect in (service_client.connect_service, service_client.connect_service_on_demand):
            with pytest.raises(ControlError) as refused:
                await connect(ControlClientKind.CLI, workspace_locator=workspace)
            error = refused.value
            found.append((error.reason, error.phase, error.retryable))
        return found

    return asyncio.run(exercise())


def test_a_held_repository_sends_nothing_on_either_connect_path(
    remote: Path, nothing_dialled: list[str]
) -> None:
    workspace = _workspace(remote)
    _report_no_network(workspace)

    assert _refused_phase(workspace) == [
        ("service_unavailable", "repository_egress_held", True),
        ("service_unavailable", "repository_egress_held", True),
    ]
    assert nothing_dialled == []
    assert not (remote / "state" / "claimed-workspaces").exists()


def test_a_kept_repository_is_refused_as_kept(remote: Path, nothing_dialled: list[str]) -> None:
    workspace = _workspace(remote)
    key = _report_no_network(workspace)
    with targets.registry_lock():
        add_kept(remote, remote.name, key, workspace.path, _STAMP)

    assert {phase for _reason, phase, _retry in _refused_phase(workspace)} == {
        "repository_egress_kept"
    }
    assert nothing_dialled == []


def test_an_allowed_repository_connects(remote: Path, nothing_dialled: list[str]) -> None:
    workspace = _workspace(remote)
    key = _report_no_network(workspace)
    assert {phase for _reason, phase, _retry in _refused_phase(workspace)} == {
        "repository_egress_held"
    }
    assert nothing_dialled == []
    with targets.registry_lock():
        add_override(remote, remote.name, key, workspace.path, _STAMP)

    async def exercise() -> None:
        # The stand-in endpoint fails the dial itself: reaching it is the point.
        with pytest.raises((OSError, ControlError)):
            await service_client.connect_service(ControlClientKind.CLI, workspace_locator=workspace)

    asyncio.run(exercise())
    assert "dial" in nothing_dialled


def test_the_connector_opens_no_background_agent_for_a_held_repository(remote: Path) -> None:
    from finishup.client.claimed_workspaces import record_claimed_workspace
    from finishup.client.connector_agent import open_connector_agent
    from finishup.client.remote_binding import binding_for_active_root

    workspace = _workspace(remote)

    async def claim() -> object:
        with selection_override(remote):
            return await binding_for_active_root(workspace, serve_workspace=False)

    claimed = asyncio.run(claim())
    assert claimed is not None
    assert record_claimed_workspace(remote, claimed.claim, workspace) is True  # type: ignore[attr-defined]
    _report_no_network(workspace)

    async def dial() -> object:
        raise AssertionError("nothing is dialled for a held repository")

    async def open_agent() -> object:
        with selection_override(remote):
            return await open_connector_agent(remote, claimed.claim, dial)  # type: ignore[attr-defined]

    assert asyncio.run(open_agent()) is None
