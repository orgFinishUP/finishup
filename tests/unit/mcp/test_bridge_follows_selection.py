"""A running MCP bridge follows a changed selection only off a server elsewhere (ADR-052, O1).

The owner's answer O1: a claim-bound connection to a server elsewhere ends with
``server_authorization_changed`` once the selection, the server's record or its key changes; the
bridge then forgets the root it started with and follows the current selection on its next
request. A request already sent over the connection that ended is never sent again: the server
selected now may be another one (ADR-051: no replay across targets), so its outcome stays unknown
and the agent is told so. A switch between servers on this computer is unchanged: the bridge
keeps the connection it has (a local connection is never checked, O2).

The real connection seam runs throughout; only the server is a scripted stand-in reached over an
in-memory stream. Remote kinds are opened in process (none is open in this release).
"""

from __future__ import annotations

import asyncio
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


def _calls(daemon: ScriptedDaemon, method: str) -> int:
    """How many calls of ``method`` the scripted service received, on every connection."""

    count = 0
    for connection in range(daemon.connections):
        for payload in daemon.received(connection)[1:]:
            frame = as_json(payload)
            count += frame.get("kind") == "call" and frame.get("method") == method
    return count


def _error(result: object) -> dict[str, object]:
    structured = cast(dict[str, object], getattr(result, "structuredContent"))
    return cast(dict[str, object], structured["error"])


@pytest.mark.anyio
@pytest.mark.parametrize("change", ["selection", "credential"])
async def test_a_request_under_way_when_the_authorization_changes_is_never_sent_again(
    home: Path,
    workspace: str,
    daemon: ScriptedDaemon,
    dialled: list[Path | None],
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    """The request was sent to server A; while it was under way the owner selected another
    server (or logged out). Resending it on the new connection could run it twice, once on each
    server: it is not resent, its outcome is reported unknown, and the next request follows."""

    open_remote_kinds(monkeypatch, "https")
    record = _remote()
    remote_root = targets.target_root(record.target_id)
    targets.write_selection(record)
    reset_selection_memo()
    tick = asyncio.Event()

    async def recheck() -> None:
        # The watch's interval, released by the test once the request is under way.
        await tick.wait()
        tick.clear()

    monkeypatch.setattr(service_client, "_recheck_after_interval", recheck)
    runtime = bridge.build_bridge_runtime(
        host_profile="claude", workspace_locator=WorkspaceLocator(workspace)
    )
    daemon.hold_calls = True
    under_way = asyncio.create_task(
        bridge.dispatch_status(_status(new_id(IdKind.REQUEST)), runtime)
    )
    async with asyncio.timeout(10):
        await daemon.held.wait()
    if change == "selection":
        _switch_to_everyday_elsewhere()
        expected_root, expected_hello = None, "workspace_locator"
    else:
        assert bump_credential_generation(remote_root)
        expected_root, expected_hello = remote_root, "workspace_claim"
    tick.set()
    async with asyncio.timeout(10):
        result = await under_way

    error = _error(result)
    assert error["code"] == "SERVICE_UNAVAILABLE"
    assert error["safe_details"] == {
        "continuation": "server_connection_renew",
        "phase": "server_authorization_changed",
        "reason_code": "service_unavailable",
    }
    # Sent once, over the connection it was sent on; no other connection was made for it.
    assert dialled == [remote_root]
    assert _calls(daemon, "status") == 1

    # The next request follows the current selection (O1).
    daemon.hold_calls = False
    assert _code(await bridge.dispatch_status(_status(new_id(IdKind.REQUEST)), runtime)) == (
        "VAULT_LOCKED"
    )
    assert dialled[1:] and set(dialled[1:]) == {expected_root}
    assert expected_hello in _last_hello(daemon)
    assert _calls(daemon, "status") == 2
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


@pytest.mark.anyio
async def test_a_request_id_sent_to_one_server_is_never_sent_to_another(
    home: Path,
    workspace: str,
    daemon: ScriptedDaemon,
    dialled: list[Path | None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Review of layer 2 (A1): an agent that repeats a request (the same ``request_id``) after
    the owner selected another server is refused before it is sent: it may be recorded on the
    first server, so its outcome there is unknown. A new request follows the selection."""

    open_remote_kinds(monkeypatch, "https")
    record = _remote()
    remote_root = targets.target_root(record.target_id)
    targets.write_selection(record)
    reset_selection_memo()
    runtime = bridge.build_bridge_runtime(
        host_profile="claude", workspace_locator=WorkspaceLocator(workspace)
    )
    repeated = new_id(IdKind.REQUEST)
    assert _code(await bridge.dispatch_status(_status(repeated), runtime)) == "VAULT_LOCKED"
    # The same request again, on the same server: a replay, sent as before.
    assert _code(await bridge.dispatch_status(_status(repeated), runtime)) == "VAULT_LOCKED"
    assert _calls(daemon, "status") == 2
    # The owner returns to this computer's everyday server; the connection to A ends.
    _switch_to_everyday_elsewhere()
    assert _code(await bridge.dispatch_status(_status(new_id(IdKind.REQUEST)), runtime)) == (
        "VAULT_LOCKED"
    )
    sent = _calls(daemon, "status")
    result = await bridge.dispatch_status(_status(repeated), runtime)
    error = _error(result)
    assert error["code"] == "SERVICE_UNAVAILABLE"
    assert cast(dict[str, object], error["safe_details"])["phase"] == (
        "server_authorization_changed"
    )
    # Never sent to the server selected now.
    assert _calls(daemon, "status") == sent
    assert dialled[0] == remote_root and dialled[-1] is None
    await _cleanup(runtime)
