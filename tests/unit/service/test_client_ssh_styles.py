"""A client reaches an SSH server through its helper or directly (ADR-052; design v2 §1.2, §3, §8.9).

The relay style (the default) dials the target root's ``run/control.sock``, which the target's
helper serves; when nothing answers the client starts the helper (never a service) and waits
within its one deadline, naming the phase the helper recorded. The direct style dials its own
``ssh -W`` stream. Both keep the authorization they were admitted under. A scripted service
stands in for the server, and stand-ins for the helper and OpenSSH: no process, no network.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Buffer, Iterator
from pathlib import Path

import pytest

from builders.control_relay import ScriptedDaemon, memory_pair, scripted_service
from builders.server_profiles import profile_document
from builders.server_targets import ambient_home, open_remote_kinds
from finishup.adapters.control.unix_socket import LocalControlTransportError
from finishup.client import helper_status, ssh_transport, targets
from finishup.client.authorization import bump_credential_generation
from finishup.client.helper_status import (
    HelperLock,
    new_status,
    now_stamp,
    write_connection_style,
    write_helper_status,
)
from finishup.config.paths import reset_selection_memo
from finishup.ports.control import ControlClientKind, ControlError
from finishup.service import client as service_client
from finishup.service.client import connect_service, connect_service_on_demand
from finishup.service.control_protocol import ControlStream


@pytest.fixture
def ssh_selected(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[targets.ServerTarget, Path]]:
    with ambient_home(monkeypatch):
        open_remote_kinds(monkeypatch, "ssh")
        with targets.registry_lock():
            _record, root = targets.new_remote_target(
                "lab",
                "ssh",
                user="owner",
                host="lab.example",
                port=22,
                remote_root="/srv/fu",
                remote_launcher="/srv/bin/finishup",
            )
            record = targets.read_target(root)
            assert record is not None
            targets.write_selection(record)
        reset_selection_memo()

        def refuse(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("a remote root never starts or supersedes a service here")

        monkeypatch.setattr(service_client, "_spawn_service_process", refuse)
        monkeypatch.setattr(service_client, "supersede_incompatible_service", refuse)
        yield record, root


def test_the_relay_style_reaches_the_helpers_endpoint(
    ssh_selected: tuple[targets.ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def run() -> tuple[str, int]:
        daemon = scripted_service(monkeypatch)
        client = await connect_service(ControlClientKind.CLI)
        try:
            await client.service_status()
            return client._transport, daemon.connections  # pyright: ignore[reportPrivateUsage]
        finally:
            await client.close()

    assert asyncio.run(run()) == ("connector", 1)


class _HelperStandIn:
    """Answers ``spawn_helper``: the next dials reach the scripted service (the helper is up)."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, *, starts: bool = True) -> None:
        self.spawns: list[str] = []
        self.started = False
        self.daemon = ScriptedDaemon()
        self.starts = starts
        self.dials = 0
        self.on_dial: list[object] = []
        monkeypatch.setattr(helper_status, "spawn_helper", self.spawn)
        monkeypatch.setattr(service_client, "connect_control", self.dial)

    def spawn(self, _root: Path, target_id: str) -> object:
        self.spawns.append(target_id)
        self.started = self.starts
        return object()

    async def dial(self):  # noqa: ANN201
        self.dials += 1
        if self.on_dial:
            action = self.on_dial.pop(0)
            if callable(action):
                action()
        if not self.started:
            raise LocalControlTransportError("endpoint_missing")
        client_end, server_end = memory_pair()
        self.daemon.serving.append(asyncio.create_task(self.daemon.serve(server_end)))
        return client_end


def test_a_cold_helper_is_started_and_waited_for_within_the_one_deadline(
    ssh_selected: tuple[targets.ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    record, _root = ssh_selected
    helper = _HelperStandIn(monkeypatch)

    async def run() -> None:
        client = await connect_service_on_demand(ControlClientKind.CLI, timeout_seconds=5.0)
        await client.close()

    asyncio.run(run())
    assert helper.spawns == [record.target_id]


def test_a_helper_that_never_answers_fails_on_the_deadline_naming_a_remote_phase(
    ssh_selected: tuple[targets.ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Design v2 §8.9: a hook's deadline bounds the helper's start; it fails open with a phase."""

    _HelperStandIn(monkeypatch, starts=False)

    async def run() -> ControlError:
        started = asyncio.get_running_loop().time()
        with pytest.raises(ControlError) as raised:
            await connect_service_on_demand(ControlClientKind.CLI, timeout_seconds=0.5)
        assert asyncio.get_running_loop().time() - started < 3.0
        return raised.value

    error = asyncio.run(run())
    assert (error.reason, error.phase) == ("service_unavailable", "remote_unreachable")


def test_the_phase_the_helper_recorded_ends_the_wait_and_is_named(
    ssh_selected: tuple[targets.ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    _record, root = ssh_selected
    helper = _HelperStandIn(monkeypatch, starts=False)

    def outage() -> None:
        write_helper_status(
            root, new_status(None, "unavailable", "remote_auth_failed", started_at=now_stamp())
        )

    # The helper records the outage while the client waits for it.
    helper.on_dial = [None, outage]

    async def run() -> ControlError:
        with pytest.raises(ControlError) as raised:
            await connect_service_on_demand(ControlClientKind.CLI, timeout_seconds=20.0)
        return raised.value

    error = asyncio.run(run())
    assert error.phase == "remote_auth_failed"
    assert helper.dials <= 3


@pytest.mark.parametrize(
    ("ended", "successor"), [("idle_timeout", True), ("stop_requested", False)]
)
def test_only_a_helpers_idle_exit_has_a_successor_in_a_clients_wait(
    ssh_selected: tuple[targets.ServerTarget, Path],
    monkeypatch: pytest.MonkeyPatch,
    ended: str,
    successor: bool,
) -> None:
    """A-HANDOFF: a client dialling while the helper ends its idle exit starts the next one; a
    deliberate stop (``server use``, ``disconnect``, ``remove``) stays a stop."""

    from finishup import __version__
    from finishup.protocol.schemas import schema_manifest_digest

    record, root = ssh_selected
    helper = _HelperStandIn(monkeypatch, starts=False)
    lock = HelperLock(root)
    lock.acquire(version=__version__, schema_manifest_digest=schema_manifest_digest())

    def end() -> None:
        write_helper_status(root, new_status(None, "stopped", ended, started_at=now_stamp()))
        lock.release()

    helper.on_dial = [None, end]
    helper.started = False

    async def run() -> ControlError | None:
        try:
            client = await connect_service_on_demand(ControlClientKind.CLI, timeout_seconds=1.5)
        except ControlError as error:
            return error
        await client.close()
        return None

    error = asyncio.run(run())
    lock.release()
    assert helper.spawns == ([record.target_id] if successor else [])
    if not successor:
        assert error is not None and error.phase == "remote_unreachable"


def test_the_direct_style_dials_its_own_stream_and_checks_every_frame(
    ssh_selected: tuple[targets.ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    _record, root = ssh_selected
    write_connection_style(root, "direct")
    daemon = ScriptedDaemon()
    opened: list[tuple[str, str | None, bool]] = []

    async def open_stream(  # noqa: ANN202
        ssh: str,
        _root: Path,
        record: targets.ServerTarget,
        *,
        expected: str | None,
        deadline: float | None,
    ):
        # The verified direct transport (``ssh_transport.open_direct_stream``), stood in: it is
        # asked for the key the owner's consent names, within the connection's deadline.
        opened.append((ssh, expected, deadline is not None))
        client_end, server_end = memory_pair()
        daemon.serving.append(asyncio.create_task(daemon.serve(server_end)))
        return client_end

    monkeypatch.setattr(ssh_transport, "resolve_ssh", lambda: "/usr/bin/ssh")
    monkeypatch.setattr(ssh_transport, "open_direct_stream", open_stream)

    def no_helper(*_args: object) -> object:
        raise AssertionError("the direct style never dials the helper's endpoint")

    monkeypatch.setattr(service_client, "connect_control", no_helper)

    async def run() -> tuple[str, ControlError]:
        client = await connect_service(ControlClientKind.CLI)
        try:
            await client.service_status()
            transport = client._transport  # pyright: ignore[reportPrivateUsage]
            bump_credential_generation(root)
            with pytest.raises(ControlError) as raised:
                await client.service_status()
            return transport, raised.value
        finally:
            await client.close()

    transport, refused = asyncio.run(run())
    assert transport == "ssh"
    assert refused.phase == "server_authorization_changed"
    from builders.server_profiles import HOST_KEY

    assert opened == [("/usr/bin/ssh", HOST_KEY, True)]
    # One status call reached the server; the one after the owner's change never left.
    assert len(daemon.received(0)) == 2


def test_a_server_that_refuses_the_consented_revision_asks_the_helper_to_refresh(
    ssh_selected: tuple[targets.ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    from builders.server_profiles import _revision_of  # pyright: ignore[reportPrivateUsage]

    _record, root = ssh_selected

    async def run() -> ControlError:
        daemon = scripted_service(monkeypatch)
        daemon.profile_revision = _revision_of(profile_document(revision=2))
        with pytest.raises(ControlError) as raised:
            await connect_service(ControlClientKind.CLI)
        return raised.value

    error = asyncio.run(run())
    assert error.phase == "server_profile_changed"
    # The marker names the revision the refused hello named (the cached one), so the helper
    # fetches at its next tick rather than after the 30-second floor (CHECKPOINT-u5 F2).
    from builders.server_profiles import TEST_REVISION
    from finishup.client.helper_status import (
        ProfileRefreshRequest,
        take_named_profile_refresh_request,
    )

    assert take_named_profile_refresh_request(root) == ProfileRefreshRequest(TEST_REVISION)


def test_the_holder_of_a_remote_root_is_its_helper_and_moves_with_its_status(
    ssh_selected: tuple[targets.ServerTarget, Path],
) -> None:
    from finishup import __version__
    from finishup.protocol.schemas import schema_manifest_digest

    _record, root = ssh_selected
    assert service_client.service_holder_identity() is None
    lock = HelperLock(root)
    lock.acquire(version=__version__, schema_manifest_digest=schema_manifest_digest())
    try:
        first = new_status(None, "ready", None, started_at=now_stamp())
        write_helper_status(root, first)
        holder = service_client.service_holder_identity()
        assert holder is not None and holder.pid == os.getpid()
        write_helper_status(
            root, new_status(first, "unavailable", "remote_unreachable", started_at=now_stamp())
        )
        moved = service_client.service_holder_identity()
        assert moved is not None and moved.instance_id != holder.instance_id
    finally:
        lock.release()


def test_a_hello_the_helper_closes_unanswered_is_named_by_what_it_recorded(
    ssh_selected: tuple[targets.ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The helper reads a hello and closes it when its own admission or the server refuses (its
    status names why): the client names that phase, never a failed local handshake."""

    _record, root = ssh_selected

    async def closes() -> object:
        client_end, server_end = memory_pair()
        write_helper_status(
            root,
            new_status(None, "unavailable", "remote_service_not_running", started_at=now_stamp()),
        )
        await server_end.aclose()
        return client_end

    monkeypatch.setattr(service_client, "connect_control", closes)

    async def run() -> ControlError:
        with pytest.raises(ControlError) as raised:
            await connect_service(ControlClientKind.CLI)
        return raised.value

    error = asyncio.run(run())
    assert (error.reason, error.phase) == ("service_unavailable", "remote_service_not_running")


class _WedgedDirectStream:
    """A direct stream whose server end answers the hello with bytes that are no frame, and whose
    ``ssh`` never says why it ended (it keeps running, its diagnostics open)."""

    def __init__(self, *, broken: bool) -> None:
        self.asked_why = 0
        self.closed = False
        self.broken = broken

    @property
    def peer_identity(self) -> object:
        return self

    async def send_all(self, data: Buffer) -> None:
        del data

    async def receive(self, max_bytes: int) -> bytes:
        del max_bytes
        if self.broken:
            raise LocalControlTransportError("connection_failed")
        return b"\x00\x00\x00\x02{]"

    async def failure_phase(self) -> str | None:
        self.asked_why += 1
        await asyncio.Event().wait()
        return None

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.parametrize("failure", ["protocol", "transport"])
def test_why_a_direct_stream_ended_is_asked_only_within_the_connections_deadline(
    failure: str,
) -> None:
    """B5: classifying a failed handshake never outlives the connection's own deadline."""

    import time

    from finishup.service.client import connect_service_via

    stream = _WedgedDirectStream(broken=failure == "transport")

    async def dial() -> ControlStream:
        return stream

    async def run() -> tuple[ControlError, float]:
        started = time.monotonic()
        with pytest.raises(ControlError) as raised:
            # Bounded from outside: a classification that ignored the deadline would hang.
            async with asyncio.timeout(10):
                await connect_service_via(
                    dial,
                    ControlClientKind.CLI,
                    workspace_binding=None,
                    authorization=None,
                    transport="ssh",
                    timeout_seconds=0.3,
                )
        return raised.value, time.monotonic() - started

    error, took = asyncio.run(run())
    # The protocol's own reason, or the transport's; never a phase it could not name in time.
    assert (error.reason, error.phase) == (
        ("frame_invalid", None) if failure == "protocol" else ("service_unavailable", None)
    )
    assert stream.asked_why == 1 and stream.closed
    assert took < 5.0


def _claim_binding(repository_key: str | None) -> service_client.ClientWorkspaceBinding:
    from builders.control_relay import CLAIM_DIGEST, WORKTREE_DIGEST
    from finishup.ports.control import WorkspaceClaim

    claim = WorkspaceClaim(
        identity_kind="git_common_root", digest=CLAIM_DIGEST, worktree=WORKTREE_DIGEST
    )
    return service_client.ClientWorkspaceBinding(claim, repository_key=repository_key)


def test_a_relayed_claim_names_its_repository_to_the_helper_and_to_nothing_else() -> None:
    """B3: through the target's helper (``connector``), a connection that claims a workspace
    writes the repository key its admission is bound to before its hello; over any other
    transport, or without a key, nothing but the hello is written."""

    from builders.control_relay import RELAY_KEY

    async def connect(transport: str, key: str | None, *, relay: bool) -> ScriptedDaemon:
        daemon = ScriptedDaemon()
        daemon.profile_revision = None  # no consent here: a claim is admitted as in layer 1

        async def dial() -> ControlStream:
            client_end, server_end = memory_pair()
            daemon.serving.append(asyncio.create_task(daemon.serve(server_end, relay=relay)))
            return client_end

        client = await service_client.connect_service_via(
            dial,
            ControlClientKind.CLI,
            workspace_binding=_claim_binding(key),
            authorization=None,
            transport=transport,  # type: ignore[arg-type]
        )
        await client.close()
        await asyncio.gather(*daemon.serving)
        return daemon

    async def run() -> None:
        relayed = await connect("connector", RELAY_KEY, relay=True)
        assert relayed.relay_keys == [RELAY_KEY]
        assert b'"workspace_claim"' in relayed.received(0)[0]  # the hello, after the binding
        for transport in ("ssh", "https", "unix"):
            direct = await connect(transport, RELAY_KEY, relay=False)
            # The service read the claim's hello first: nothing else was written before it.
            assert b'"workspace_claim"' in direct.received(0)[0]
            assert RELAY_KEY.encode() not in bytes(direct.inbound[0])
        unnamed = await connect("connector", None, relay=True)
        assert unnamed.relay_keys == []

    asyncio.run(run())


def test_a_stream_that_sends_on_its_own_is_bound_to_its_connections_authorization() -> None:
    """B3: a REST stream (here a stand-in with ``bind``) asks the connection's own authorization,
    its repository's hold included, before each request it makes on its own; a refusal names
    ``server_authorization_changed``."""

    class _Bindable:
        def __init__(self, inner: ControlStream) -> None:
            self.inner = inner
            self.checks: list[object] = []

        @property
        def peer_identity(self) -> object:
            return self.inner.peer_identity

        def bind(self, refusal: object) -> None:
            self.checks.append(refusal)

        async def receive(self, max_bytes: int) -> bytes:
            return await self.inner.receive(max_bytes)

        async def send_all(self, data: Buffer) -> None:
            await self.inner.send_all(data)

        async def aclose(self) -> None:
            await self.inner.aclose()

    class _Check:
        phase: str | None = None

        def refusal(self) -> str | None:
            return self.phase

    async def run() -> None:
        daemon = ScriptedDaemon()
        streams: list[_Bindable] = []

        async def dial() -> ControlStream:
            client_end, server_end = memory_pair()
            daemon.serving.append(asyncio.create_task(daemon.serve(server_end)))
            streams.append(_Bindable(client_end))
            return streams[-1]

        check = _Check()
        client = await service_client.connect_service_via(
            dial,
            ControlClientKind.CLI,
            workspace_binding=None,
            authorization=check,
            transport="ssh",
        )
        try:
            (bound,) = streams[0].checks
            assert callable(bound) and bound() is None
            check.phase = "repository_egress_held"
            assert bound() == "server_authorization_changed"
        finally:
            await client.close()

    asyncio.run(run())
