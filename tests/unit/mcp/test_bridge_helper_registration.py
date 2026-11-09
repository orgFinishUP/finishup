"""The MCP bridge registers its claimed workspace with the target's helper (ADR-052, §8.5).

A bridge connected claim-bound to a server elsewhere (a kind opened in process here; none is open
in this release) registers the workspace its agent serves, so the helper of layer 4 can answer
that server's background work for it; closing the connection releases it, and so does Cursor's
roots-changed retirement, which keeps the helper from serving the old roots. A bridge on a local
server registers nothing.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest

import finishup.mcp.server as bridge
from builders.control_relay import ScriptedDaemon, scripted_service
from builders.server_targets import ambient_home, open_remote_kinds
from finishup.client import targets
from finishup.client.helper_registrations import registrations_dir
from finishup.config.paths import reset_selection_memo
from finishup.ports.control import WorkspaceLocator
from finishup.protocol.canonical import JsonValue
from finishup.protocol.ids import IdKind, new_id
from finishup.service import client as service_client

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


@pytest.fixture
def workspace(tmp_path: Path) -> str:
    folder = tmp_path / "project"
    folder.mkdir()
    return os.fspath(folder.resolve())


@pytest.fixture
def daemon(monkeypatch: pytest.MonkeyPatch) -> ScriptedDaemon:
    def refuse(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("no service is started or superseded in this test")

    def never_older(_client: object) -> bool:
        return False

    monkeypatch.setattr(service_client, "_spawn_service_process", refuse)
    monkeypatch.setattr(service_client, "supersede_incompatible_service", refuse)
    monkeypatch.setattr(service_client, "_serves_older_package", never_older)
    return scripted_service(monkeypatch)


def _status() -> dict[str, JsonValue]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": new_id(IdKind.REQUEST),
        "actor": {"actor_id": "harness:mcp", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
        "session_id": "ses_00000000-0000-4000-8000-000000000001",
        "writer_id": "wri_00000000-0000-4000-8000-000000000001",
        "view": "compact",
        "limit": "10",
    }


def _registrations(record: targets.ServerTarget) -> list[dict[str, object]]:
    import json

    folder = registrations_dir(record.target_id)
    if not folder.exists():
        return []
    return [json.loads(path.read_bytes()) for path in sorted(folder.iterdir())]


def _remote(monkeypatch: pytest.MonkeyPatch) -> targets.ServerTarget:
    open_remote_kinds(monkeypatch, "https")
    with targets.registry_lock():
        record, _root = targets.new_remote_target("web", "https", base_url="https://web.example")
        targets.write_selection(record)
    reset_selection_memo()
    return record


@pytest.mark.parametrize("host", ["claude", "cursor"])
async def test_a_claim_bound_bridge_registers_its_workspace_and_releases_it_on_close(
    home: Path,
    workspace: str,
    daemon: ScriptedDaemon,
    monkeypatch: pytest.MonkeyPatch,
    host: str,
) -> None:
    del home, daemon
    record = _remote(monkeypatch)
    runtime = bridge.build_bridge_runtime(
        host_profile=cast(bridge.McpHostProfile, host),
        workspace_locator=WorkspaceLocator(workspace),
    )

    await bridge.dispatch_status(_status(), runtime)

    (registration,) = _registrations(record)
    assert registration["worktree"] == workspace
    assert registration["source"] == ("mcp_roots" if host == "cursor" else "mcp_bridge")
    assert registration["server_profile"] is not None
    await bridge.close_bridge_runtime(runtime)
    assert _registrations(record) == []


async def test_cursors_roots_changing_releases_what_the_bridge_registered(
    home: Path, workspace: str, daemon: ScriptedDaemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    del home, daemon
    record = _remote(monkeypatch)
    runtime = bridge.build_bridge_runtime(
        host_profile="cursor", workspace_locator=WorkspaceLocator(workspace)
    )
    await bridge.dispatch_status(_status(), runtime)
    assert len(_registrations(record)) == 1

    await bridge._invalidate_cursor_workspace_binding(runtime)  # pyright: ignore[reportPrivateUsage]

    assert _registrations(record) == []


async def test_a_bridge_on_a_local_server_registers_nothing(
    home: Path, workspace: str, daemon: ScriptedDaemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    del home, daemon, monkeypatch
    runtime = bridge.build_bridge_runtime(
        host_profile="claude", workspace_locator=WorkspaceLocator(workspace)
    )

    await bridge.dispatch_status(_status(), runtime)

    assert not targets.servers_dir().exists() or list(targets.servers_dir().glob("t_*")) == []
    assert bridge._HELPER_REGISTRATIONS == {}  # pyright: ignore[reportPrivateUsage]
    await bridge.close_bridge_runtime(runtime)
