"""A remote connection names the profile revision its consent admits, and is refused under any
other before anything else is sent (ADR-052, design v2 section 8.2).

The connect seam (``service.client``) runs the gate, whose consent step admits a connection under
the revision of the server's current profile; the hello names it, and the service admits the hello
only under the revision it issues. A profile the owner did not agree to is refused before any dial,
and an open connection whose consent moved to another revision ends.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from builders.control_relay import as_json, scripted_service
from builders.server_profiles import TEST_REVISION, profile_document, refreshed
from builders.server_targets import ambient_home, open_remote_kinds
from finishup.client import targets
from finishup.config.paths import reset_selection_memo
from finishup.ports.control import ControlClientKind, ControlError, WorkspaceLocator
from finishup.protocol.consent_envelope import ReviewEgress
from finishup.protocol.server_profile import ProfileLevels, ServerProfileRevision, revision_to_json
from finishup.service import client as service_client
from finishup.service.client import connect_service

_GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": os.defpath,
}

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(params=["ssh", "https"])
def remote(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> Iterator[targets.ServerTarget]:
    with ambient_home(monkeypatch):
        open_remote_kinds(monkeypatch, request.param)
        fields: dict[str, object] = (
            {"host": "lab.example", "port": 22}
            if request.param == "ssh"
            else {"base_url": "https://finishup.example"}
        )
        with targets.registry_lock():
            record, _root = targets.new_remote_target("lab", request.param, **fields)  # pyright: ignore[reportArgumentType]
            targets.write_selection(record)
        reset_selection_memo()
        yield record


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


def _stored(record: targets.ServerTarget) -> targets.ServerTarget:
    stored = targets.read_target(targets.target_root(record.target_id))
    assert stored is not None
    return stored


async def test_an_admitted_connection_names_its_consented_revision_in_the_hello(
    remote: targets.ServerTarget, workspace: WorkspaceLocator, monkeypatch: pytest.MonkeyPatch
) -> None:
    daemon = scripted_service(monkeypatch)
    client = await connect_service(
        ControlClientKind.CLI, workspace_locator=workspace, serve_workspace=False
    )
    try:
        await client.service_status()
    finally:
        await client.close()
        await asyncio.gather(*daemon.serving, return_exceptions=True)
    hello = as_json(daemon.received(0)[0])
    assert hello["server_profile"] == revision_to_json(TEST_REVISION)
    assert hello["workspace_claim"] is not None


async def test_a_service_issuing_another_revision_admits_nothing_but_the_hello(
    remote: targets.ServerTarget, workspace: WorkspaceLocator, monkeypatch: pytest.MonkeyPatch
) -> None:
    daemon = scripted_service(monkeypatch)
    daemon.profile_revision = ServerProfileRevision(
        TEST_REVISION.issuer, 2, TEST_REVISION.profile_digest
    )
    with pytest.raises(ControlError) as refused:
        await connect_service(
            ControlClientKind.CLI, workspace_locator=workspace, serve_workspace=True
        )
    await asyncio.gather(*daemon.serving, return_exceptions=True)
    assert (refused.value.reason, refused.value.retryable, refused.value.phase) == (
        "service_unavailable",
        True,
        "server_profile_changed",
    )
    assert len(daemon.received(0)) == 1  # the hello, nothing after it


@pytest.mark.parametrize(
    ("document", "phase"),
    [
        (
            profile_document(review=ReviewEgress("server_policy", "openai"), revision=2),
            "server_profile_changed",
        ),
        (
            profile_document(levels=ProfileLevels(("L1", "L2"), "L2"), revision=2),
            "server_level_unavailable",
        ),
    ],
    ids=["widened", "level"],
)
async def test_a_profile_the_owner_did_not_agree_to_is_refused_before_any_dial(
    remote: targets.ServerTarget,
    workspace: WorkspaceLocator,
    monkeypatch: pytest.MonkeyPatch,
    document: dict[str, object],
    phase: str,
) -> None:
    refreshed(_stored(remote), document)
    dialled: list[int] = []

    async def dial() -> object:
        dialled.append(1)
        raise AssertionError("refused before any dial")

    monkeypatch.setattr(service_client, "connect_control", dial)
    with pytest.raises(ControlError) as refused:
        await connect_service(
            ControlClientKind.CLI, workspace_locator=workspace, serve_workspace=True
        )
    assert refused.value.phase == phase
    assert dialled == []


async def test_an_open_connection_ends_when_its_consent_moves_to_another_revision(
    remote: targets.ServerTarget, workspace: WorkspaceLocator, monkeypatch: pytest.MonkeyPatch
) -> None:
    daemon = scripted_service(monkeypatch)
    client = await connect_service(
        ControlClientKind.CLI, workspace_locator=workspace, serve_workspace=False
    )
    try:
        await client.service_status()
        # The same offer under a new revision: recorded quietly, but this connection named the
        # old one in its hello, so it ends (the server would refuse it too).
        assert refreshed(_stored(remote), profile_document(revision=2)).phase is None
        with pytest.raises(ControlError) as ended:
            await client.service_status()
        assert ended.value.phase == "server_authorization_changed"
    finally:
        await client.close()
        await asyncio.gather(*daemon.serving, return_exceptions=True)
    assert len(daemon.received(0)) == 2
