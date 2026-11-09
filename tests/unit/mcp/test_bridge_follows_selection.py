"""A running MCP bridge follows a changed selection only off a server elsewhere (ADR-052, O1).

The owner's answer O1: a claim-bound connection to a server elsewhere ends with
``server_authorization_changed`` once the selection, the server's record or its key changes; the
bridge then forgets the root it started with and follows the current selection on its next
connection, for the same request. A switch between servers on this computer is unchanged: the
bridge keeps the connection it has (a local connection is never checked, O2).

The real connection seam runs throughout; only the server is a scripted stand-in reached over an
in-memory stream. Remote kinds are opened in process (none is open in this release).
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest

import finishup.mcp.server as bridge
from builders.control_relay import ScriptedDaemon, as_json, scripted_service
from builders.server_targets import ambient_home, open_remote_kinds
from finishup.client import targets
from finishup.client.authorization import bump_credential_generation
from finishup.config.paths import active_root, reset_selection_memo
from finishup.ports.control import WorkspaceLocator
from finishup.protocol.canonical import JsonValue
from finishup.protocol.ids import IdKind, new_id
from finishup.service import client as service_client


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

    monkeypatch.setattr(service_client, "_spawn_service_process", refuse)
    monkeypatch.setattr(service_client, "supersede_incompatible_service", refuse)

    # The scripted service reports an old package version; it is never retired here.
    def never_older(_client: object) -> bool:
        return False

    monkeypatch.setattr(service_client, "_serves_older_package", never_older)
    return scripted_service(monkeypatch)


@pytest.fixture
def dialled(daemon: ScriptedDaemon, monkeypatch: pytest.MonkeyPatch) -> list[Path | None]:
    """The root each dial was made for, as this process resolved it at that moment."""

    roots: list[Path | None] = []
    serve = service_client.connect_control

    async def dial() -> object:
        roots.append(active_root())
        return await serve()

    monkeypatch.setattr(service_client, "connect_control", dial)
    return roots


def _status(request_id: str) -> dict[str, JsonValue]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": request_id,
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


def _code(result: object) -> str:
    structured = cast(dict[str, object], getattr(result, "structuredContent"))
    return cast(str, cast(dict[str, object], structured["error"])["code"])


def _last_hello(daemon: ScriptedDaemon) -> dict[str, JsonValue]:
    return as_json(daemon.received(-1)[0])


def _switch_to_everyday_elsewhere() -> None:
    """``finishup server use local`` in another process: the selection file goes, and this
    process's own memory of its root is untouched (``clear_selection`` would reset it here)."""

    targets.selection_path().unlink()


async def _cleanup(runtime: bridge.BridgeRuntime) -> None:
    client = runtime._slot.client  # pyright: ignore[reportPrivateUsage]
    if client is not None:
        await bridge._close_client(client)  # pyright: ignore[reportPrivateUsage]


def _remote(name: str = "web") -> targets.ServerTarget:
    with targets.registry_lock():
        record, _root = targets.new_remote_target(name, "https", base_url=f"https://{name}.example")
    return record


@pytest.mark.anyio
@pytest.mark.parametrize("change", ["selection", "credential"])
async def test_a_bridge_on_a_server_elsewhere_follows_the_new_selection(
    home: Path,
    workspace: str,
    daemon: ScriptedDaemon,
    dialled: list[Path | None],
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    open_remote_kinds(monkeypatch, "https")
    record = _remote()
    remote_root = targets.target_root(record.target_id)
    targets.write_selection(record)
    reset_selection_memo()
    runtime = bridge.build_bridge_runtime(
        host_profile="claude", workspace_locator=WorkspaceLocator(workspace)
    )
    # The scripted server answers every workflow call with its vault locked.
    assert _code(await bridge.dispatch_status(_status(new_id(IdKind.REQUEST)), runtime)) == (
        "VAULT_LOCKED"
    )
    assert set(dialled) == {remote_root}
    assert "workspace_claim" in _last_hello(daemon)
    before = len(dialled)

    if change == "selection":
        # The owner switches back to this computer's everyday server, from another process.
        _switch_to_everyday_elsewhere()
        expected_root, expected_hello = None, "workspace_locator"
    else:
        # The owner logs out: the same server, under whatever key is current.
        assert bump_credential_generation(remote_root)
        expected_root, expected_hello = remote_root, "workspace_claim"

    assert _code(await bridge.dispatch_status(_status(new_id(IdKind.REQUEST)), runtime)) == (
        "VAULT_LOCKED"
    )
    # Every connection after the change follows the current selection.
    assert dialled[before:] and set(dialled[before:]) == {expected_root}
    assert expected_hello in _last_hello(daemon)
    await _cleanup(runtime)


@pytest.mark.anyio
async def test_a_switch_between_servers_on_this_computer_keeps_the_bridge_as_before(
    home: Path, workspace: str, daemon: ScriptedDaemon, dialled: list[Path | None]
) -> None:
    with targets.registry_lock():
        record, local_root = targets.new_local_target("work")
    targets.write_selection(record)
    reset_selection_memo()
    runtime = bridge.build_bridge_runtime(
        host_profile="claude", workspace_locator=WorkspaceLocator(workspace)
    )
    assert _code(await bridge.dispatch_status(_status(new_id(IdKind.REQUEST)), runtime)) == (
        "VAULT_LOCKED"
    )
    _switch_to_everyday_elsewhere()
    assert _code(await bridge.dispatch_status(_status(new_id(IdKind.REQUEST)), runtime)) == (
        "VAULT_LOCKED"
    )
    # The bridge keeps the server it started with: every dial is still the named local root.
    assert dialled and set(dialled) == {local_root}
    assert "workspace_locator" in _last_hello(daemon)
    await _cleanup(runtime)
