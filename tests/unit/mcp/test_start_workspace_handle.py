"""The MCP bridge sends a claim-bound connection's handle in place of a start's workspace path.

Rule R (run u8): only a path naming the worktree the bridge serves (the folder its host started it
in, or Cursor's bound root) becomes the handle. A start naming any other folder is refused typed
before it is sent, with a continuation an agent behind a bridge can follow (tell the user, carry
on without FinishUP for that folder); the bridge's connection keeps serving its own folder.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import cast

import pytest

import finishup.mcp.server as bridge
from finishup.ports.control import ControlError, WorkspaceLocator
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import StartRequest, StartResult

_REQUEST = "req_00000000-0000-4000-8000-000000000051"
_HANDLE = "client:0123456789abcdef"
_PATH = "/srv/dev/private-project"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _repository(path: Path) -> Path:
    path.mkdir(parents=True)
    subprocess.run(  # noqa: S603 - fixed argv
        ["git", "init", "-q", os.fspath(path)],
        check=True,
        env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"},
    )
    return path


@pytest.fixture
def folders(tmp_path: Path) -> dict[str, Path]:
    """``proj`` is the folder the host started the bridge in; ``other`` is another repository."""

    proj = _repository(tmp_path / "private-project")
    (proj / "src").mkdir()
    return {"proj": proj, "other": _repository(tmp_path / "other-project")}


def _runtime(folders: dict[str, Path], host: bridge.McpHostProfile = "generic") -> object:
    return bridge.build_bridge_runtime(
        host_profile=host, workspace_locator=WorkspaceLocator(os.fspath(folders["proj"]))
    )


def _start_body(
    workspace_ref: Path | str = _PATH, request_id: str = _REQUEST
) -> dict[str, JsonValue]:
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
        "mode": "create",
        "task_title": "Remote task",
        "requested_view": "compact",
        "workspace_ref": os.fspath(workspace_ref),
        "external_ref": "host-session:1",
    }


class _Client:
    """Records the request it was sent, then answers with a non-retryable control error."""

    def __init__(self, binding: str, handle: str | None) -> None:
        self.workspace_binding = binding
        self.workspace_handle = handle
        self.sent: list[StartRequest] = []

    async def connect(self) -> None:
        return None

    async def start(self, request: StartRequest, *, deadline_ms: int | None = None) -> StartResult:
        del deadline_ms
        self.sent.append(request)
        raise ControlError("invalid_request")

    async def close(self) -> None:
        return None


def _wire(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, client: _Client) -> None:
    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)

    async def on_demand(_kind: object, **_kwargs: object) -> object:
        return client

    monkeypatch.setattr(
        bridge,
        "connect_service_on_demand",
        cast(Callable[[object], Awaitable[object]], on_demand),
    )


@pytest.mark.anyio
async def test_a_claim_bound_start_sends_the_handle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, folders: dict[str, Path]
) -> None:
    client = _Client("client_claim", _HANDLE)
    _wire(monkeypatch, tmp_path, client)
    await bridge.dispatch_start(
        _start_body(folders["proj"]), cast(bridge.BridgeRuntime, _runtime(folders))
    )
    (sent,) = client.sent
    assert sent.workspace_ref == _HANDLE
    assert sent.request_id == _REQUEST


def _refusal(result: object) -> dict[str, object]:
    assert getattr(result, "isError") is True
    structured = cast(dict[str, object], getattr(result, "structuredContent"))
    return cast(dict[str, object], structured["error"])


@pytest.mark.anyio
@pytest.mark.parametrize("host", ["generic", "codex", "claude", "cursor"])
async def test_two_tasks_naming_different_folders_on_one_bridge(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    folders: dict[str, Path],
    host: bridge.McpHostProfile,
) -> None:
    """A host started the bridge in one checkout while the agent worked in another (the Mac's
    case): the start naming the other checkout is refused typed and nothing is sent for it; a
    start naming the bridge's own folder, before and after, is sent as the handle."""

    client = _Client("client_claim", _HANDLE)
    _wire(monkeypatch, tmp_path, client)
    runtime = cast(bridge.BridgeRuntime, _runtime(folders, host))
    await bridge.dispatch_start(_start_body(folders["proj"]), runtime)
    refused = await bridge.dispatch_start(
        _start_body(folders["other"], "req_00000000-0000-4000-8000-000000000052"), runtime
    )
    await bridge.dispatch_start(
        _start_body(folders["proj"] / "src", "req_00000000-0000-4000-8000-000000000053"), runtime
    )
    assert [request.request_id for request in client.sent] == [
        _REQUEST,
        "req_00000000-0000-4000-8000-000000000053",
    ]
    assert {request.workspace_ref for request in client.sent} == {_HANDLE}
    error = _refusal(refused)
    assert (error["code"], error["retryable"]) == ("INVALID_REQUEST", False)
    assert error["safe_details"] == {
        "continuation": "workspace_not_served_tell_user",
        "field": "/workspace_ref",
        "reason_code": "workspace_ref_not_served",
    }
    text = repr(refused)
    assert "Tell the user, and carry on without FinishUP for that folder" in text
    for path in folders.values():
        assert os.fspath(path) not in text


@pytest.mark.anyio
async def test_a_local_start_is_sent_as_written(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, folders: dict[str, Path]
) -> None:
    """``main``'s L0 behaviour: a local bridge sends any folder as written (issue #1349)."""

    client = _Client("local_path", None)
    _wire(monkeypatch, tmp_path, client)
    await bridge.dispatch_start(
        _start_body(folders["other"]), cast(bridge.BridgeRuntime, _runtime(folders))
    )
    (sent,) = client.sent
    assert sent.workspace_ref == os.fspath(folders["other"])


@pytest.mark.anyio
async def test_without_a_handle_nothing_is_sent_and_the_locked_server_is_named(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, folders: dict[str, Path]
) -> None:
    """A claim the server could not key at hello (its vault was locked) is ``vault_locked``.

    Nothing is sent, the stale connection is discarded so a fresh hello binds the claim once the
    vault is unlocked, and the agent is never told to set a handle it cannot see.
    """

    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    clients: list[_Client] = []

    async def on_demand(_kind: object, **_kwargs: object) -> object:
        clients.append(_Client("client_claim", None))
        return clients[-1]

    monkeypatch.setattr(
        bridge,
        "connect_service_on_demand",
        cast(Callable[[object], Awaitable[object]], on_demand),
    )
    runtime = cast(bridge.BridgeRuntime, _runtime(folders))
    result = await bridge.dispatch_start(_start_body(folders["proj"]), runtime)
    assert clients and all(client.sent == [] for client in clients)
    assert getattr(result, "isError") is True
    structured = cast(dict[str, object], getattr(result, "structuredContent"))
    error = cast(dict[str, object], structured["error"])
    assert error["code"] == "VAULT_LOCKED"
    assert "workspace_ref_not_portable" not in repr(result)
    assert "workspace_handle_required" not in repr(result)
    assert "private-project" not in repr(result)

    # Once the server is unlocked, the next start reconnects and its hello binds the claim.
    async def unlocked(_kind: object, **_kwargs: object) -> object:
        clients.append(_Client("client_claim", _HANDLE))
        return clients[-1]

    monkeypatch.setattr(
        bridge,
        "connect_service_on_demand",
        cast(Callable[[object], Awaitable[object]], unlocked),
    )
    await bridge.dispatch_start(_start_body(folders["proj"]), runtime)
    (sent,) = clients[-1].sent
    assert sent.workspace_ref == _HANDLE


class _CheckingClient:
    """A claim-bound connection whose ``check`` the server answers, or refuses ``vault_locked``."""

    def __init__(self, handle: str | None) -> None:
        self.workspace_binding = "client_claim"
        self.workspace_handle = handle
        self.checks = 0
        self.closed = False

    async def connect(self) -> None:
        return None

    async def check(self, request: object, **_kwargs: object) -> object:
        del request
        self.checks += 1
        if self.workspace_handle is None:
            # The server's answer on a connection whose claim it could not key at hello.
            raise ControlError("vault_locked", retryable=True)
        raise ControlError("invalid_request")

    async def close(self) -> None:
        self.closed = True


@pytest.mark.anyio
async def test_a_task_call_on_a_connection_without_a_handle_replaces_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """ADR-051: the server answers every task call on a claim-bound connection with no handle
    ``vault_locked``; the bridge discards that connection, and the next call's fresh hello gets a
    handle, instead of every later call failing on the same connection."""

    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    clients = [_CheckingClient(None), _CheckingClient(_HANDLE)]
    connected: list[_CheckingClient] = []

    async def on_demand(_kind: object, **_kwargs: object) -> object:
        connected.append(clients[len(connected)])
        return connected[-1]

    monkeypatch.setattr(
        bridge,
        "connect_service_on_demand",
        cast(Callable[[object], Awaitable[object]], on_demand),
    )
    body: dict[str, JsonValue] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _REQUEST,
        "actor": {"actor_id": "harness:mcp", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
        "session_id": "ses_00000000-0000-4000-8000-000000000052",
        "writer_id": "wri_00000000-0000-4000-8000-000000000053",
        "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
        "mode": "deterministic_only",
    }
    runtime = bridge.build_bridge_runtime()
    try:
        first = await bridge.dispatch_check(body, runtime)
        error = cast(dict[str, object], cast(dict[str, object], first.structuredContent)["error"])
        assert error["code"] == "VAULT_LOCKED"
        assert error["retryable"] is True
        assert clients[0].closed  # the connection with no handle is not kept
        await bridge.dispatch_check(body, runtime)
    finally:
        await bridge.close_bridge_runtime(runtime)
    assert connected == clients
    assert (clients[0].checks, clients[1].checks) == (1, 1)
