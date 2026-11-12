"""The MCP bridge holds a repository whose policy here allows no network use (ADR-051, ADR-052).

Maintainer decision of 2026-11-07, round 4. While a server elsewhere is selected, every MCP tool
of a held repository returns the same retryable result before anything is claimed or dialled:
``SERVICE_UNAVAILABLE`` naming the phase and its continuation in ``safe_details``, as every
authorization refusal does; a kept repository returns its own. The bridge latches the result like
any availability refusal, and its one quiet probe clears the latch once the owner allows the
repository, so the agent repeats the same request without restarting its session. Once the
repository is held again, the next request is refused with the phase and nothing new is dialled
(a connection the bridge kept ends at its reuse check; see test_bridge_follows_selection and the
service tests for the watch).

The real connection seam runs throughout; only the server is a scripted stand-in reached over an
in-memory stream. No remote kind is open in this release: the kinds are opened in process.

Ported from round 5's ``tests/unit/mcp/test_repository_hold_mcp.py`` (``2fa87ef2a``) onto the
layer-2 seam instead of approach A's connector.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from typing import Any, cast

import pytest

import finishup.mcp.server as bridge
from builders.control_relay import ScriptedDaemon, scripted_service
from builders.server_targets import ambient_home, open_remote_kinds
from finishup.client import targets
from finishup.client.everyday_policy import record_repository_report, repository_report
from finishup.client.everyday_repository import repository_key_for
from finishup.client.repository_hold import add_kept, add_override, remove_override
from finishup.config.paths import reset_selection_memo
from finishup.ports.control import WorkspaceLocator
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import REASON_CODE_CONTINUATIONS
from finishup.protocol.ids import IdKind, new_id
from finishup.service import client as service_client

_HELD = "repository_egress_held"
_KEPT = "repository_egress_kept"
_SESSION = "ses_00000000-0000-4000-8000-000000000001"
_WRITER = "wri_00000000-0000-4000-8000-000000000001"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        open_remote_kinds(monkeypatch, "ssh", "https", "local_port")
        yield root


@pytest.fixture
def workspace(tmp_path: Path) -> str:
    folder = tmp_path / "project"
    folder.mkdir()
    return os.fspath(folder.resolve())


@pytest.fixture
def daemon(monkeypatch: pytest.MonkeyPatch) -> ScriptedDaemon:
    """The server, reached over an in-memory stream; no service is started or superseded."""

    def refuse(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("no service is started or superseded in this test")

    def never_older(_client: object) -> bool:
        return False

    monkeypatch.setattr(service_client, "_spawn_service_process", refuse)
    monkeypatch.setattr(service_client, "supersede_incompatible_service", refuse)
    monkeypatch.setattr(service_client, "_serves_older_package", never_older)
    return scripted_service(monkeypatch)


def _envelope(request_id: str) -> dict[str, JsonValue]:
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
    }


def _mapped(request_id: str) -> dict[str, JsonValue]:
    return {
        **_envelope(request_id),
        "session_id": _SESSION,
        "writer_id": _WRITER,
        "expected_frontier": {"sequence": "1", "head_digest": "sha256:" + "0" * 64},
    }


def _start(request_id: str) -> dict[str, JsonValue]:
    return {
        **_envelope(request_id),
        "mode": "create",
        "task_title": "Held work",
        "requested_view": "compact",
    }


def _status(request_id: str) -> dict[str, JsonValue]:
    body = {key: value for key, value in _mapped(request_id).items() if key != "expected_frontier"}
    return {**body, "view": "compact", "limit": "10"}


def _publish(request_id: str) -> dict[str, JsonValue]:
    return {
        **_mapped(request_id),
        "event_drafts": [
            {
                "event_id": "evt_00000000-0000-4000-8000-000000000002",
                "schema": {"name": "result_recorded", "version": "1.0.0"},
                "occurred_at": "2026-01-01T00:00:00.000Z",
                "causal_parents": [],
                "payload": {
                    "result_id": "res_00000000-0000-4000-8000-000000000001",
                    "action_id": "act_00000000-0000-4000-8000-000000000001",
                    "outcome": "success",
                },
                "artifact_refs": [],
                "evidence_refs": [],
            }
        ],
    }


def _check(request_id: str) -> dict[str, JsonValue]:
    return {**_mapped(request_id), "mode": "semantic_required"}


def _respond(request_id: str) -> dict[str, JsonValue]:
    return {
        **_mapped(request_id),
        "finding_id": "fnd_00000000-0000-4000-8000-000000000001",
        "finding_frontier": {"sequence": "1", "head_digest": "sha256:" + "0" * 64},
        "disposition": "rejected",
        "reason": "Not an issue.",
        "evidence_refs": [],
    }


def _receipt(request_id: str) -> dict[str, JsonValue]:
    return {
        **_mapped(request_id),
        "task_id": "tsk_00000000-0000-4000-8000-000000000001",
        "format": "json",
        "include": "summary",
        "redaction_profile": "full_local",
    }


type Dispatch = Callable[[dict[str, JsonValue], Any], Awaitable[object]]
_TOOLS: list[tuple[str, Dispatch, Callable[[str], dict[str, JsonValue]]]] = [
    ("start", bridge.dispatch_start, _start),
    ("publish_work", bridge.dispatch_publish_work, _publish),
    ("check", bridge.dispatch_check, _check),
    ("respond", bridge.dispatch_respond, _respond),
    ("status", bridge.dispatch_status, _status),
    ("receipt", bridge.dispatch_receipt, _receipt),
]


def _select(kind: str) -> targets.ServerTarget:
    with targets.registry_lock():
        if kind == "ssh":
            record, _root = targets.new_remote_target(
                "privbox", "ssh", user="owner", host="lab.example", port=22
            )
        elif kind == "https":
            record, _root = targets.new_remote_target(
                "privbox", "https", base_url="https://finishup.example"
            )
        else:
            record, _root = targets.new_remote_target(
                "privbox", "local_port", base_url="https://127.0.0.1:9443"
            )
    targets.write_selection(record)
    reset_selection_memo()
    return record


def _key(workspace: str) -> str:
    key = asyncio.run(repository_key_for(workspace))
    assert key is not None
    return key


def _since(key: str) -> str:
    report = repository_report(key)
    assert report is not None and report.no_network_since is not None
    return report.no_network_since


def _error(result: object) -> dict[str, object]:
    structured = cast(dict[str, object], getattr(result, "structuredContent"))
    assert getattr(result, "isError") is True
    return cast(dict[str, object], structured["error"])


def _assert_held(error: dict[str, object], phase: str, *, inherited: bool = False) -> None:
    assert error["code"] == "SERVICE_UNAVAILABLE"
    assert error["retryable"] is True
    details = cast(dict[str, object], error["safe_details"])
    assert details["reason_code"] == "service_unavailable"
    assert details["phase"] == phase
    assert details["continuation"] == REASON_CODE_CONTINUATIONS[phase]
    assert ("availability_inherited" in details) is inherited
    message = cast(str, error["message"])
    assert f"({phase})" in message and "service run" not in message


@pytest.mark.parametrize("phase", [_HELD, _KEPT])
@pytest.mark.parametrize(("tool", "dispatch", "body"), _TOOLS, ids=[tool[0] for tool in _TOOLS])
@pytest.mark.parametrize("kind", ["ssh", "https", "local_port"])
def test_every_tool_of_a_held_repository_returns_its_phase_and_dials_nothing(
    home: Path,
    workspace: str,
    daemon: ScriptedDaemon,
    kind: str,
    tool: str,
    dispatch: Dispatch,
    body: Callable[[str], dict[str, JsonValue]],
    phase: str,
) -> None:
    record = _select(kind)
    key = _key(workspace)
    assert record_repository_report(key, workspace, no_network=True)
    if phase == _KEPT:
        with targets.registry_lock():
            add_kept(
                targets.target_root(record.target_id), record.target_id, key, workspace, _since(key)
            )

    async def run() -> object:
        runtime = bridge.build_bridge_runtime(
            host_profile="codex", workspace_locator=WorkspaceLocator(workspace)
        )
        return await dispatch(body(new_id(IdKind.REQUEST)), runtime)

    _assert_held(_error(asyncio.run(run())), phase)
    # Nothing was claimed, dialled or started.
    assert daemon.connections == 0


@pytest.mark.anyio
async def test_the_latch_clears_once_allowed_and_a_held_again_connection_ends(
    home: Path, workspace: str, daemon: ScriptedDaemon
) -> None:
    record = _select("https")
    root = targets.target_root(record.target_id)
    key = await repository_key_for(workspace)
    assert key is not None
    assert record_repository_report(key, workspace, no_network=True)
    runtime = bridge.build_bridge_runtime(
        host_profile="claude", workspace_locator=WorkspaceLocator(workspace)
    )
    first = new_id(IdKind.REQUEST)

    # Held: the first start is refused and latched; a later tool inherits the same phase after
    # its quiet probe meets the same refusal. Nothing reached the server.
    _assert_held(_error(await bridge.dispatch_start(_start(first), runtime)), _HELD)
    inherited = _error(await bridge.dispatch_status(_status(new_id(IdKind.REQUEST)), runtime))
    _assert_held(inherited, _HELD, inherited=True)
    assert daemon.connections == 0

    # The owner allows it on their terminal ('server repositories add').
    with targets.registry_lock():
        add_override(root, record.target_id, key, workspace, _since(key))

    # The same request identity goes through: it reaches the server, whose answer it carries.
    repeated = _error(await bridge.dispatch_start(_start(first), runtime))
    # (The scripted server answers every workflow call with its vault locked.)
    assert repeated["code"] == "VAULT_LOCKED"
    assert daemon.connections >= 1
    later = _error(await bridge.dispatch_status(_status(new_id(IdKind.REQUEST)), runtime))
    assert later["code"] == "VAULT_LOCKED"
    assert "availability_inherited" not in cast(dict[str, object], later["safe_details"])
    slot = runtime._slot  # pyright: ignore[reportPrivateUsage]
    assert slot.availability is None
    connections = daemon.connections

    # Held again ('server repositories remove'): the next request is refused with the phase and
    # no new connection is dialled for it.
    with targets.registry_lock():
        assert remove_override(root, record.target_id, key=key)
    _assert_held(
        _error(await bridge.dispatch_status(_status(new_id(IdKind.REQUEST)), runtime)), _HELD
    )
    assert daemon.connections == connections
    await asyncio.gather(*daemon.serving, return_exceptions=True)
