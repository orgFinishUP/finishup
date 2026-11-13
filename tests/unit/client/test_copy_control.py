"""Copy control: the connection ``server code list``/``forget`` reach a server's copy over (#1357).

A repository held from a server elsewhere, kept on this computer, lowered to level L1 or gone from
disk may still have a copy there (ADR-054): forget is the only way to delete it. The connection
that names it carries the copy's claim (its keyed digest and its worktree's, under the target's
salt: the copy's id there) and nothing else: no path, no workspace agent, so the server can read
or sync nothing over it, no registration with the target's helper, and it sends no request but
``code_copy``. It is admitted by the shared gate alone (the target record, this computer's
zero-network policy, the reauthorization and the consent), never by the repository's hold, and
it is made directly, never relayed by the helper (whose relay binds a claim to that hold).
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Buffer, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from tests.builders.server_copy import git
from tests.builders.server_targets import ambient_home, open_remote_kinds, record_remote_target

from finishup.adapters.control.unix_socket import AuthenticatedUnixStream
from finishup.client.remote_binding import copy_claim, copy_control_binding
from finishup.client.targets import ServerTarget, TargetError
from finishup.ports.control import (
    ControlClientKind,
    ControlError,
    ControlMethod,
    WorkspaceClaim,
    WorkspaceLocator,
)
from finishup.service import client as client_module
from finishup.service.client import ClientWorkspaceBinding
from finishup.service.control_protocol import ControlSession

_CLAIM = WorkspaceClaim("git_common_root", "sha256:" + "a" * 64, "sha256:" + "b" * 64)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def remote(monkeypatch: pytest.MonkeyPatch) -> Iterator[ServerTarget]:
    with ambient_home(monkeypatch):
        open_remote_kinds(monkeypatch, "https", consent=False)
        yield record_remote_target()


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    (root / "a.py").write_bytes(b"a\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "m")
    return Path(os.path.realpath(root))


# --- the binding ------------------------------------------------------------------------------


def test_a_copy_control_binding_names_the_copy_and_nothing_else() -> None:
    binding = copy_control_binding(_CLAIM)
    assert binding.copy_control is True and binding.claim == _CLAIM
    assert binding.agent is None and binding.authorization is None
    assert binding.worktree is None and binding.repository_key is None
    assert "copy_control" not in repr(binding)
    with pytest.raises(ValueError, match="workspace_binding_invalid"):
        ClientWorkspaceBinding(_CLAIM, authorization=SimpleNamespace(), copy_control=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="workspace_binding_invalid"):
        ClientWorkspaceBinding(_CLAIM, worktree="/srv/app", copy_control=True)
    with pytest.raises(TypeError, match="workspace_binding_invalid"):
        ClientWorkspaceBinding(_CLAIM, copy_control=1)  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_the_copy_claim_is_the_claim_every_connection_of_this_computer_names(
    remote: ServerTarget, repository: Path
) -> None:
    """The same keyed digest and worktree digest a task's connection sends: the copy's id there."""

    from finishup.client.remote_binding import remote_workspace_binding

    salt = __import__("base64").b64decode(cast(str, remote.claim_salt))
    sent = await remote_workspace_binding(
        WorkspaceLocator(str(repository)), salt, serve_workspace=False
    )
    assert await copy_claim(remote, str(repository)) == sent.claim
    with pytest.raises(TargetError, match="target_record_invalid"):
        await copy_claim(
            cast(ServerTarget, SimpleNamespace(claim_salt="not base64!")), str(repository)
        )


# --- the admission: the shared gate, never the repository's hold -------------------------------


def _record(kind: str = "https") -> SimpleNamespace:
    return SimpleNamespace(
        is_remote=True, target_id="tgt_lab", kind=kind, consent=SimpleNamespace(level="L2")
    )


@pytest.mark.anyio
async def test_copy_control_is_admitted_by_the_gate_and_never_by_the_hold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.client import authorization as authorization_module
    from finishup.client import targets as targets_module

    monkeypatch.setattr(targets_module, "active_target_record", _record)
    admitted = SimpleNamespace(grant=SimpleNamespace(target_id="tgt_lab"))
    monkeypatch.setattr(authorization_module, "authorize_active_root", lambda: admitted)

    def no_hold(*_arguments: object, **_options: object) -> object:
        raise AssertionError("copy control never decides or binds the repository's hold")

    monkeypatch.setattr("finishup.client.repository_hold.require_sendable", no_hold)
    admission = await client_module._admit_remote(  # pyright: ignore[reportPrivateUsage]
        None, copy_control_binding(_CLAIM), serve_workspace=False
    )
    assert admission is not None
    assert admission.authorization is admitted
    assert admission.workspace_binding is not None
    assert admission.workspace_binding.copy_control is True


@pytest.mark.anyio
@pytest.mark.parametrize(
    "phase", ["zero_network_remote_selected", "target_reauthorization_required"]
)
async def test_the_gate_still_refuses_copy_control_before_anything_is_dialled(
    monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    """This computer's zero-network policy is not weakened: no server is reached."""

    from finishup.client import authorization as authorization_module
    from finishup.client import targets as targets_module

    monkeypatch.setattr(targets_module, "active_target_record", _record)

    def refuse() -> object:
        raise TargetError(phase)

    monkeypatch.setattr(authorization_module, "authorize_active_root", refuse)
    with pytest.raises(ControlError) as raised:
        await client_module._admit_remote(  # pyright: ignore[reportPrivateUsage]
            None, copy_control_binding(_CLAIM), serve_workspace=False
        )
    assert (raised.value.reason, raised.value.phase) == ("service_unavailable", phase)


# --- the transport: direct, never the helper's relay -------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize(("kind", "expected"), [("ssh", "ssh"), ("https", "rest")])
@pytest.mark.parametrize("style", ["relay", "direct"])
async def test_copy_control_is_made_directly_whatever_the_connection_style(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, kind: str, expected: str, style: str
) -> None:
    from finishup.client import helper_status
    from finishup.client import targets as targets_module

    def root_of(_target_id: str) -> Path:
        return tmp_path

    def style_of(_root: Path) -> str:
        return style

    def epoch_of(_root: Path) -> int:
        return 0

    monkeypatch.setattr(targets_module, "target_root", root_of)
    monkeypatch.setattr(helper_status, "read_connection_style", style_of)
    monkeypatch.setattr(helper_status, "read_helper_epoch", epoch_of)
    reached: list[str] = []

    def route(name: str) -> Any:
        async def reach(*_arguments: object, **_options: object) -> object:
            reached.append(name)
            return SimpleNamespace()

        return reach

    monkeypatch.setattr(client_module, "_connect_direct", route("ssh"))
    monkeypatch.setattr(client_module, "_connect_direct_rest", route("rest"))
    monkeypatch.setattr(client_module, "_connect_through_helper", route("helper"))
    admission = client_module._RemoteAdmission(  # pyright: ignore[reportPrivateUsage]
        cast(Any, SimpleNamespace(refusal=lambda: None)),
        copy_control_binding(_CLAIM),
        "tgt_lab",
        kind,
        "L2",
    )
    await client_module._reach_remote(  # pyright: ignore[reportPrivateUsage]
        admission,
        ControlClientKind.CLI,
        projection_render_mode=cast(Any, None),
        output_is_controlling_tty=False,
        deadline=0.0,
    )
    assert reached == [expected]


# --- the connection sends nothing but code_copy -------------------------------------------------


class _Stream:
    def __init__(self) -> None:
        self.peer_identity = object()
        self.sent: list[bytes] = []
        self._closed = asyncio.Event()

    async def receive(self, max_bytes: int) -> bytes:
        del max_bytes
        await self._closed.wait()
        return b""

    async def send_all(self, data: Buffer) -> None:
        self.sent.append(bytes(memoryview(data)))

    async def aclose(self) -> None:
        self._closed.set()


@pytest.mark.anyio
async def test_a_copy_control_connection_refuses_every_method_but_code_copy() -> None:
    stream = _Stream()
    session = ControlSession(
        protocol_version="1.0",
        client_kind=ControlClientKind.CLI,
        service_instance_id="svc_00000000-0000-4000-8000-000000000085",
        service_generation="1",
        allowed_methods=tuple(sorted(ControlMethod, key=lambda method: method.value.encode())),
        peer_identity=stream.peer_identity,
        connection_nonce="0" * 64,
        workspace_binding="client_claim",
        workspace_handle="client:0123456789abcdef",
    )
    client = client_module._connected_client(  # pyright: ignore[reportPrivateUsage]
        cast(AuthenticatedUnixStream, stream),
        session,
        ControlClientKind.CLI,
        transport="https",
        copy_only=True,
    )
    try:
        assert client.copy_only is True
        for call in (client.service_status, client.server_profile, client.lock):
            with pytest.raises(ControlError, match="method_forbidden"):
                await call()
        assert stream.sent == []
    finally:
        await client.close()


# --- the sync records the claim it sent the copy under ------------------------------------------


def test_the_export_record_keeps_the_claim_and_a_record_without_one_still_reads(
    tmp_path: Path,
) -> None:
    from finishup.client.code_export import ExportDatabase, export_records

    folder = tmp_path / "exports" / ("0" * 32)
    database = ExportDatabase(folder)
    database.remember_root(Path("/srv/app"))
    (record,) = export_records(folder.parent)
    assert record.readable and record.claim is None
    database.remember_claim(_CLAIM)
    (record,) = export_records(folder.parent)
    assert record.readable and record.claim == _CLAIM and record.root == "/srv/app"
    # Read back by a new database, and kept through its other writes.
    again = ExportDatabase(folder)
    again.remember_sent("c" * 40, 1)
    (record,) = export_records(folder.parent)
    assert record.claim == _CLAIM
    assert (folder / "export.json").read_bytes().count(b'"claim"') == 1
    # The claim is never shown: its digests stay out of every representation.
    assert "a" * 64 not in repr(record)


def test_a_claim_out_of_shape_makes_the_record_unreadable(tmp_path: Path) -> None:
    import json

    from finishup.client.code_export import ExportDatabase, export_records

    folder = tmp_path / "exports" / ("1" * 32)
    ExportDatabase(folder).remember_claim(_CLAIM)
    path = folder / "export.json"
    document = json.loads(path.read_bytes())
    document["claim"]["digest"] = "md5:00"
    path.write_text(json.dumps(document))
    (record,) = export_records(folder.parent)
    assert not record.readable and record.claim is None
