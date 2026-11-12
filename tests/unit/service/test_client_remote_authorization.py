"""Every connection from a remote root passes one gate before anything is dialled (ADR-052).

Both connect paths of ``service.client`` (``connect_service`` and ``connect_service_on_demand``)
run the shared authorization gate for a remote root before any claim, dial, spawn or supersede.
In this release no remote kind is open, so every remote root stops at the gate exactly as layer 1
named it (``target_root_is_remote``). Opening a kind in process (``open_remote_kinds``) shows what
the gate does once a later layer opens one: zero-network and the repository hold refuse before a
dial, an admitted connection claims its workspace (never a path) and keeps the authorization it
was admitted under, and a change to it ends the connection with the phase. A local root is
connected exactly as before (O2).

Rewritten from round 5's ``tests/unit/service/test_client_remote_repository_hold.py``
(``30a0a02c0``, ``b192ecd15``) against the layer-2 seam instead of approach A's connector.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from builders.control_relay import as_json, scripted_service
from builders.server_targets import ambient_home, open_remote_kinds
from finishup.adapters.workspace_root import canonical_workspace_root
from finishup.client import targets
from finishup.client.authorization import bump_credential_generation
from finishup.client.everyday_policy import record_reported_policy, record_repository_report
from finishup.client.repository_hold import add_kept, add_override, repository_key
from finishup.config.paths import reset_selection_memo
from finishup.ports.control import ControlClientKind, ControlError, WorkspaceLocator
from finishup.service import client as service_client
from finishup.service.client import ServiceClient, connect_service, connect_service_on_demand

_AT = datetime(2026, 11, 7, 9, 30, tzinfo=UTC)
_STAMP = "2026-11-07T09:30:00.000Z"
_GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": os.defpath,
}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


@pytest.fixture
def nothing_started(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("a remote root never starts or supersedes a service here")

    monkeypatch.setattr(service_client, "_spawn_service_process", refuse)
    monkeypatch.setattr(service_client, "supersede_incompatible_service", refuse)


@pytest.fixture(params=["ssh", "https", "local_port"])
def remote(home: Path, request: pytest.FixtureRequest) -> targets.ServerTarget:
    kind = request.param
    with targets.registry_lock():
        if kind == "ssh":
            record, _root = targets.new_remote_target("lab", "ssh", host="lab.example", port=22)
        elif kind == "https":
            record, _root = targets.new_remote_target(
                "web", "https", base_url="https://finishup.example"
            )
        else:
            record, _root = targets.new_remote_target(
                "port", "local_port", base_url="https://127.0.0.1:8443"
            )
        targets.write_selection(record)
    reset_selection_memo()
    return record


@pytest.fixture
def workspace(tmp_path: Path) -> WorkspaceLocator:
    folder = tmp_path / "private-project"
    folder.mkdir(mode=0o700)
    subprocess.run(
        ("git", "init", "--quiet"),
        cwd=folder,
        check=True,
        capture_output=True,
        env={**_GIT_ENV, "HOME": os.fspath(folder)},
    )
    return WorkspaceLocator(os.fspath(folder.resolve()))


def _report_no_network(workspace: WorkspaceLocator) -> str:
    key = repository_key(asyncio.run(canonical_workspace_root(workspace)))
    assert record_repository_report(key, workspace.path, no_network=True, now=_AT)
    return key


async def _connect(path: str, workspace: WorkspaceLocator) -> ServiceClient:
    if path == "connect":
        return await connect_service(
            ControlClientKind.CLI, workspace_locator=workspace, serve_workspace=True
        )
    return await connect_service_on_demand(
        ControlClientKind.CLI, workspace_locator=workspace, serve_workspace=True
    )


def _refused(path: str, workspace: WorkspaceLocator) -> tuple[str, bool, str | None]:
    async def attempt() -> tuple[str, bool, str | None]:
        with pytest.raises(ControlError) as raised:
            await _connect(path, workspace)
        return raised.value.reason, raised.value.retryable, raised.value.phase

    return asyncio.run(attempt())


_PATHS = ("connect", "on_demand")


# --- this release: no remote kind is open ----------------------------------------------------


@pytest.mark.parametrize("path", _PATHS)
def test_every_remote_root_is_refused_before_anything_is_dialled(
    remote: targets.ServerTarget,
    workspace: WorkspaceLocator,
    nothing_started: None,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
) -> None:
    async def dial() -> object:
        raise AssertionError("nothing is dialled for a remote root in this release")

    monkeypatch.setattr(service_client, "connect_control", dial)
    claimed: list[object] = []

    def claim(*args: object) -> None:
        claimed.append(args)

    monkeypatch.setattr("finishup.client.remote_binding.workspace_claim_for_root", claim)
    from finishup.client.authorization import OPEN_REMOTE_KINDS

    # SSH is open in this release (layer 4): a target the owner never consented to a server
    # profile for is refused at the consent step, before anything is dialled, like a closed kind.
    phase = (
        "server_profile_changed" if remote.kind in OPEN_REMOTE_KINDS else "target_root_is_remote"
    )
    assert _refused(path, workspace) == ("service_unavailable", True, phase)
    assert claimed == []


# --- once a later layer opens a kind (in process here) -----------------------------------------


@pytest.mark.parametrize("path", _PATHS)
def test_zero_network_and_a_held_or_kept_repository_refuse_before_a_dial(
    remote: targets.ServerTarget,
    workspace: WorkspaceLocator,
    nothing_started: None,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
) -> None:
    open_remote_kinds(monkeypatch, remote.kind)
    dialled: list[int] = []

    async def dial() -> object:
        dialled.append(1)
        raise AssertionError("refused before any dial")

    monkeypatch.setattr(service_client, "connect_control", dial)
    key = _report_no_network(workspace)
    assert _refused(path, workspace) == ("service_unavailable", True, "repository_egress_held")
    root = targets.target_root(remote.target_id)
    with targets.registry_lock():
        add_kept(root, remote.target_id, key, workspace.path, _STAMP)
    assert _refused(path, workspace) == ("service_unavailable", True, "repository_egress_kept")
    record_reported_policy(zero_network=True)
    # Zero-network comes first in the gate's order.
    assert _refused(path, workspace) == (
        "service_unavailable",
        True,
        "zero_network_remote_selected",
    )
    assert dialled == []


@pytest.mark.anyio
async def test_an_admitted_connection_claims_its_workspace_and_keeps_its_authorization(
    remote: targets.ServerTarget,
    workspace: WorkspaceLocator,
    nothing_started: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    open_remote_kinds(monkeypatch, remote.kind)
    daemon = scripted_service(monkeypatch)
    key = repository_key(await canonical_workspace_root(workspace))
    record_repository_report(key, workspace.path, no_network=True, now=_AT)
    with targets.registry_lock():
        add_override(
            targets.target_root(remote.target_id), remote.target_id, key, workspace.path, _STAMP
        )

    # From a subfolder: the claim is the worktree's own, and no path is ever sent.
    sub = Path(workspace.path) / "src"
    sub.mkdir()
    client = await connect_service(
        ControlClientKind.CLI,
        workspace_locator=WorkspaceLocator(os.fspath(sub)),
        serve_workspace=True,
    )
    try:
        await client.service_status()
        assert client._watch is not None  # pyright: ignore[reportPrivateUsage]
    finally:
        await client.close()
        await asyncio.gather(*daemon.serving, return_exceptions=True)
    hello = as_json(daemon.received(0)[0])
    assert "workspace_locator" not in hello
    assert hello["workspace_claim"] is not None and hello["workspace_agent"] is not None
    everything = b"".join(daemon.received(0))
    assert os.fsencode(workspace.path) not in everything
    assert b"private-project" not in everything


@pytest.mark.anyio
@pytest.mark.parametrize("change", ["selection", "credential", "hold"])
async def test_a_change_to_what_a_connection_was_admitted_under_ends_it(
    remote: targets.ServerTarget,
    workspace: WorkspaceLocator,
    nothing_started: None,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    open_remote_kinds(monkeypatch, remote.kind)
    daemon = scripted_service(monkeypatch)
    client = await connect_service(
        ControlClientKind.CLI, workspace_locator=workspace, serve_workspace=False
    )
    try:
        await client.service_status()
        if change == "selection":
            targets.clear_selection()
            expected = "server_authorization_changed"
        elif change == "credential":
            assert bump_credential_generation(targets.target_root(remote.target_id))
            expected = "server_authorization_changed"
        else:
            record_repository_report(
                repository_key(await canonical_workspace_root(workspace)),
                workspace.path,
                no_network=True,
            )
            # An open connection ends as a changed authorization whatever changed (it already
            # sent something); the next connection names the hold before anything is sent.
            expected = "server_authorization_changed"
        with pytest.raises(ControlError) as raised:
            await client.service_status()
        assert (raised.value.reason, raised.value.phase) == ("service_unavailable", expected)
    finally:
        await client.close()
        await asyncio.gather(*daemon.serving, return_exceptions=True)
    # The hello and the one call before the change, nothing after it.
    assert len(daemon.received(0)) == 2
    if change == "hold":
        with pytest.raises(ControlError) as refused:
            await connect_service(
                ControlClientKind.CLI, workspace_locator=workspace, serve_workspace=False
            )
        assert refused.value.phase == "repository_egress_held"
        assert daemon.connections == 1


@pytest.mark.anyio
@pytest.mark.parametrize("change", ["selection", "hold"])
async def test_a_change_while_the_dial_is_under_way_refuses_the_hello(
    remote: targets.ServerTarget,
    workspace: WorkspaceLocator,
    nothing_started: None,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    """The hello carries the claim and the agent declaration: it is checked like every frame, so
    a change made after the pre-dial check and before the hello sends nothing at all."""

    open_remote_kinds(monkeypatch, remote.kind)
    daemon = scripted_service(monkeypatch)
    key = repository_key(await canonical_workspace_root(workspace))
    serve = service_client.connect_control

    async def dial_while_the_owner_changes_it() -> object:
        stream = await serve()
        if change == "selection":
            targets.clear_selection()
        else:
            record_repository_report(key, workspace.path, no_network=True)
        return stream

    monkeypatch.setattr(service_client, "connect_control", dial_while_the_owner_changes_it)
    with pytest.raises(ControlError) as refused:
        await connect_service(
            ControlClientKind.CLI, workspace_locator=workspace, serve_workspace=True
        )
    await asyncio.gather(*daemon.serving, return_exceptions=True)
    expected = "server_authorization_changed" if change == "selection" else "repository_egress_held"
    assert (refused.value.reason, refused.value.retryable, refused.value.phase) == (
        "service_unavailable",
        True,
        expected,
    )
    # Dialled, and nothing written: not the hello, not the claim.
    assert daemon.connections == 1
    assert daemon.received(0) == []


@pytest.mark.anyio
async def test_a_prebuilt_binding_keeps_its_repository_check(
    remote: targets.ServerTarget,
    workspace: WorkspaceLocator,
    nothing_started: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A binding made earlier carries its repository's hold: a hold that came after it was made
    refuses the connection before anything is dialled, and ends one made before it."""

    from finishup.client.remote_binding import binding_for_active_root

    open_remote_kinds(monkeypatch, remote.kind)
    daemon = scripted_service(monkeypatch)
    key = repository_key(await canonical_workspace_root(workspace))
    binding = await binding_for_active_root(workspace, serve_workspace=False)
    assert binding is not None and binding.authorization is not None
    client = await connect_service(ControlClientKind.CLI, workspace_binding=binding)
    try:
        await client.service_status()
        record_repository_report(key, workspace.path, no_network=True)
        with pytest.raises(ControlError) as ended:
            await client.service_status()
        assert (ended.value.reason, ended.value.phase) == (
            "service_unavailable",
            "server_authorization_changed",
        )
    finally:
        await client.close()
    # The hello and the one call before the hold, nothing after it.
    assert len(daemon.received(0)) == 2
    with pytest.raises(ControlError) as refused:
        await connect_service(ControlClientKind.CLI, workspace_binding=binding)
    assert (refused.value.reason, refused.value.phase) == (
        "service_unavailable",
        "repository_egress_held",
    )
    await asyncio.gather(*daemon.serving, return_exceptions=True)
    assert daemon.connections == 1


@pytest.mark.anyio
async def test_a_binding_made_for_another_server_is_refused_before_a_dial(
    remote: targets.ServerTarget,
    workspace: WorkspaceLocator,
    nothing_started: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.client.remote_binding import binding_for_active_root

    open_remote_kinds(monkeypatch, remote.kind)
    daemon = scripted_service(monkeypatch)
    binding = await binding_for_active_root(workspace, serve_workspace=False)
    assert binding is not None
    with targets.registry_lock():
        if remote.kind == "ssh":
            other, _root = targets.new_remote_target("other", "ssh", host="other.example", port=22)
        else:
            other, _root = targets.new_remote_target(
                "other", remote.kind, base_url="https://127.0.0.1:9443"
            )
        targets.write_selection(other)
    with pytest.raises(ControlError) as refused:
        await connect_service(ControlClientKind.CLI, workspace_binding=binding)
    assert (refused.value.reason, refused.value.phase) == (
        "service_unavailable",
        "server_authorization_changed",
    )
    assert daemon.connections == 0


@pytest.mark.anyio
async def test_a_local_root_connects_exactly_as_before(
    home: Path, monkeypatch: pytest.MonkeyPatch, workspace: WorkspaceLocator
) -> None:
    """O2: no gate, no claim, no authorization and no watch for a server on this computer."""

    daemon = scripted_service(monkeypatch)
    calls: list[str] = []

    def gate(*_args: object, **_kwargs: object) -> object:
        calls.append("gate")
        raise AssertionError("a local root is never gated")

    monkeypatch.setattr("finishup.client.authorization.authorize_active_root", gate)
    client = await connect_service(ControlClientKind.CLI, serve_workspace=True)
    try:
        await client.service_status()
        assert client._authorization is None  # pyright: ignore[reportPrivateUsage]
        assert client._watch is None  # pyright: ignore[reportPrivateUsage]
    finally:
        await client.close()
        await asyncio.gather(*daemon.serving, return_exceptions=True)
    assert calls == []
    assert "workspace_claim" not in as_json(daemon.received(0)[0])
