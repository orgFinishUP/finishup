"""The MCP bridge registers its claimed workspace with the target's helper (ADR-052, §8.5).

A bridge connected claim-bound to a server elsewhere (a kind opened in process here; none is open
in this release) registers the workspace its agent serves, so the helper of layer 4 can answer
that server's background work for it; closing the connection releases it, and so does Cursor's
roots-changed retirement, which keeps the helper from serving the old roots. A bridge on a local
server registers nothing.
"""

from __future__ import annotations

import asyncio
import os
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

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


# --- the connection renews its own registration (review of layer 3: C3) ------------------------


class _LeaseClock:
    """The bridge's renewal wait, injected: each ``release`` lets one wait end; ``waiting`` is
    set whenever the renewal task waits. No time passes in the test."""

    def __init__(self) -> None:
        self.ticks = asyncio.Semaphore(0)
        self.waiting = asyncio.Event()
        self.asked: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.asked.append(seconds)
        self.waiting.set()
        await self.ticks.acquire()

    async def next_wait(self) -> None:
        await asyncio.wait_for(self.waiting.wait(), _WAIT_SECONDS)
        self.waiting.clear()


_WAIT_SECONDS = 10.0
_T0 = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)


def _clock(monkeypatch: pytest.MonkeyPatch, moment: datetime) -> list[datetime]:
    """The registration's clock: what it reads is ``clock[0]``, which the test moves."""

    from finishup.client import helper_registrations

    current = [moment]
    monkeypatch.setattr(helper_registrations, "_now", lambda: current[0])
    return current


def _renewals(monkeypatch: pytest.MonkeyPatch) -> threading.Event:
    from finishup.client import helper_registrations

    done = threading.Event()
    real = helper_registrations.renew

    def renew(*args: Any, **kwargs: Any) -> object:
        try:
            return real(*args, **kwargs)
        finally:
            done.set()

    monkeypatch.setattr(helper_registrations, "renew", renew)
    return done


async def test_an_idle_bridge_renews_its_registration_at_half_its_lease(
    home: Path,
    workspace: str,
    daemon: ScriptedDaemon,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No other request reuses the connection: its own task renews the registration, so the
    helper keeps serving the workspace of a bridge that stays connected (C3)."""

    del home, daemon
    record = _remote(monkeypatch)
    clock = _LeaseClock()
    monkeypatch.setattr(bridge, "_lease_wait", clock, raising=False)
    moment = _clock(monkeypatch, _T0)
    renewed = _renewals(monkeypatch)
    runtime = bridge.build_bridge_runtime(
        host_profile="claude", workspace_locator=WorkspaceLocator(workspace)
    )
    try:
        await bridge.dispatch_status(_status(), runtime)
        (first,) = _registrations(record)
        assert first["expires_at"] == "2026-11-09T12:15:00.000Z"

        await clock.next_wait()
        moment[0] = _T0 + timedelta(minutes=8)
        clock.ticks.release()
        assert await asyncio.to_thread(renewed.wait, _WAIT_SECONDS)
        await clock.next_wait()

        (second,) = _registrations(record)
        assert second["expires_at"] == "2026-11-09T12:23:00.000Z"
        assert second["registrant"] == first["registrant"]
    finally:
        await bridge.close_bridge_runtime(runtime)
    assert _registrations(record) == []


@pytest.mark.parametrize("ending", ["close", "cursor_roots_changed"])
async def test_closing_or_cursors_retirement_ends_the_renewal_and_no_renewal_writes_it_back(
    home: Path,
    workspace: str,
    daemon: ScriptedDaemon,
    monkeypatch: pytest.MonkeyPatch,
    ending: str,
) -> None:
    """The renewal task belongs to the connection: closing it, or Cursor's roots changing,
    cancels the task and releases the registration; a renewal already under way when that
    happens writes nothing back (C3)."""

    from finishup.client import helper_registrations

    del home, daemon
    record = _remote(monkeypatch)
    clock = _LeaseClock()
    monkeypatch.setattr(bridge, "_lease_wait", clock, raising=False)
    # Registered long ago: the renewal is due at the first tick (a tick before it is due only
    # looks at the consent again).
    _clock(monkeypatch, _T0)
    host = "cursor" if ending == "cursor_roots_changed" else "claude"
    runtime = bridge.build_bridge_runtime(
        host_profile=cast(bridge.McpHostProfile, host),
        workspace_locator=WorkspaceLocator(workspace),
    )
    await bridge.dispatch_status(_status(), runtime)
    (lease,) = bridge._HELPER_REGISTRATIONS.values()  # pyright: ignore[reportPrivateUsage]
    task = lease.task
    assert task is not None
    await clock.next_wait()
    loop = asyncio.get_running_loop()
    ended = threading.Event()
    real_register = helper_registrations.register

    async def end() -> None:
        if ending == "close":
            await bridge.close_bridge_runtime(runtime)
        else:
            await bridge._invalidate_cursor_workspace_binding(runtime)  # pyright: ignore[reportPrivateUsage]
        ended.set()

    def register_after_the_end(*args: Any, **kwargs: Any) -> object:
        # The renewal is under way in its worker when the connection ends on the loop.
        asyncio.run_coroutine_threadsafe(end(), loop)
        assert ended.wait(_WAIT_SECONDS)
        return real_register(*args, **kwargs)

    monkeypatch.setattr(helper_registrations, "register", register_after_the_end)
    clock.ticks.release()

    await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), _WAIT_SECONDS)
    assert task.done()
    assert _registrations(record) == []
    assert bridge._HELPER_REGISTRATIONS == {}  # pyright: ignore[reportPrivateUsage]
    await bridge.close_bridge_runtime(runtime)


async def test_one_connections_release_never_removes_another_connections_registration(
    home: Path,
    workspace: str,
    daemon: ScriptedDaemon,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two connections of one bridge serving the same workspace (a replacement published before
    the stale one closes) each own their registration: closing the stale one leaves the new
    one's lease in place (C3)."""

    from finishup.ports.control import ControlClientKind

    del home, daemon
    record = _remote(monkeypatch)
    clock = _LeaseClock()
    monkeypatch.setattr(bridge, "_lease_wait", clock, raising=False)
    runtime = bridge.build_bridge_runtime(
        host_profile="claude", workspace_locator=WorkspaceLocator(workspace)
    )
    stale, fresh = [
        await service_client.connect_service(
            ControlClientKind.MCP_BRIDGE,
            workspace_locator=WorkspaceLocator(workspace),
            serve_workspace=True,
        )
        for _ in range(2)
    ]
    try:
        await bridge._register_for_helper(runtime, stale)  # pyright: ignore[reportPrivateUsage]
        await bridge._register_for_helper(runtime, fresh)  # pyright: ignore[reportPrivateUsage]
        assert len(_registrations(record)) == 2

        await bridge._close_client(stale)  # pyright: ignore[reportPrivateUsage]

        (kept,) = _registrations(record)
        lease = bridge._HELPER_REGISTRATIONS[id(fresh)]  # pyright: ignore[reportPrivateUsage]
        assert lease.registration is not None
        assert kept["registrant"] == lease.registration.registrant
    finally:
        await bridge._close_client(stale)  # pyright: ignore[reportPrivateUsage]
        await bridge._close_client(fresh)  # pyright: ignore[reportPrivateUsage]
    assert _registrations(record) == []


async def test_a_consent_changed_under_a_connected_bridge_renews_its_registration_at_once(
    home: Path,
    workspace: str,
    daemon: ScriptedDaemon,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defect A, review: the owner agreeing again under the same profile revision (``server use
    NAME --level L2``, say) leaves the bridge's connection admitted, but the helper no longer
    serves a registration made under the earlier consent, and the bridge renewed only at half
    its lease (7.5 minutes): an agent session's tasks meanwhile had no background agent to sync.
    The bridge looks at the consent every few seconds and renews at once when it moved; a tick
    before the lease is due with the consent unchanged renews nothing."""

    from dataclasses import replace

    from finishup.client.authorization import consent_digest

    del home, daemon
    record = _remote(monkeypatch)
    clock = _LeaseClock()
    monkeypatch.setattr(bridge, "_lease_wait", clock, raising=False)
    _clock(monkeypatch, datetime.now(UTC))  # registered now: the lease is not due for 7.5 min
    renewed = _renewals(monkeypatch)
    runtime = bridge.build_bridge_runtime(
        host_profile="claude", workspace_locator=WorkspaceLocator(workspace)
    )
    try:
        await bridge.dispatch_status(_status(), runtime)
        (first,) = _registrations(record)
        await clock.next_wait()
        assert clock.asked[-1] <= 2.0  # it looks again within seconds, not at half the lease
        clock.ticks.release()  # nothing changed, not due: no renewal
        await clock.next_wait()
        assert not renewed.is_set()
        assert _registrations(record) == [first]
        root = targets.target_root(record.target_id)
        current = targets.read_target(root)
        assert current is not None
        with targets.registry_lock():
            targets.write_target(root, replace(current, authorized_at="2026-11-11T09:00:00.000Z"))
        moved = targets.read_target(root)
        grant = cast(dict[str, object], first["grant"])
        assert moved is not None and consent_digest(moved) != grant["consent_digest"]
        clock.ticks.release()
        assert await asyncio.to_thread(renewed.wait, _WAIT_SECONDS)
        await clock.next_wait()
        (second,) = _registrations(record)
        assert cast(dict[str, object], second["grant"])["consent_digest"] == consent_digest(moved)
        assert second["registrant"] == first["registrant"]
    finally:
        await bridge.close_bridge_runtime(runtime)
    assert _registrations(record) == []
