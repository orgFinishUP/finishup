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
from collections.abc import Buffer, Callable, Iterator
from pathlib import Path

import pytest

from builders.control_relay import ScriptedDaemon, memory_pair, scripted_service
from builders.control_relay import service_status as service_client_status
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
        self.epochs: list[str | None] = []
        self.started = False
        self.daemon = ScriptedDaemon()
        self.starts = starts
        self.dials = 0
        self.on_dial: list[object] = []
        monkeypatch.setattr(helper_status, "spawn_helper", self.spawn)
        monkeypatch.setattr(service_client, "connect_control", self.dial)

    def spawn(self, _root: Path, target_id: str, *, epoch: str | None = None) -> object:
        self.spawns.append(target_id)
        self.epochs.append(epoch)
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
    assert (root / "state" / "profile-refresh-requested").exists()


@pytest.mark.parametrize("running", [False, True])
def test_a_direct_style_refusal_of_the_consented_revision_starts_the_helper_to_refresh(
    ssh_selected: tuple[targets.ServerTarget, Path], monkeypatch: pytest.MonkeyPatch, running: bool
) -> None:
    """No helper is on the direct style's path: the refusal starts one (unless one runs), which
    fetches the profile, so ``server status`` names the change and a narrowing is adjusted."""

    from builders.server_profiles import _revision_of  # pyright: ignore[reportPrivateUsage]

    record, root = ssh_selected
    write_connection_style(root, "direct")
    daemon = ScriptedDaemon()
    daemon.profile_revision = _revision_of(profile_document(revision=2))

    async def open_stream(  # noqa: ANN202
        _ssh: str,
        _root: Path,
        _record: targets.ServerTarget,
        *,
        expected: str | None,
        deadline: float | None,
    ):
        del expected, deadline
        client_end, server_end = memory_pair()
        daemon.serving.append(asyncio.create_task(daemon.serve(server_end)))
        return client_end

    monkeypatch.setattr(ssh_transport, "resolve_ssh", lambda: "/usr/bin/ssh")
    monkeypatch.setattr(ssh_transport, "open_direct_stream", open_stream)
    spawns: list[str] = []

    def spawn(_root: Path, target_id: str, *, epoch: str | None = None) -> object:
        del epoch
        spawns.append(target_id)
        return object()

    monkeypatch.setattr(helper_status, "spawn_helper", spawn)

    def holder(_root: Path) -> object | None:
        return object() if running else None

    monkeypatch.setattr(helper_status, "helper_holder", holder)

    async def run() -> ControlError:
        with pytest.raises(ControlError) as raised:
            await connect_service(ControlClientKind.CLI)
        return raised.value

    error = asyncio.run(run())
    assert error.phase == "server_profile_changed"
    assert (root / "state" / "profile-refresh-requested").exists()
    assert spawns == ([] if running else [record.target_id])


class _MultiplexedDirectStream:
    """A direct ``ssh -W`` stand-in whose close cancels its own stderr reader (an OpenSSH master
    holds a multiplexed client's stderr past its exit), and which, asked afterwards why it
    ended, raises that reader's cancellation: the shape the real stream had. ``on_close`` runs
    as it closes (what another process did meanwhile)."""

    def __init__(self, inner: ControlStream, on_close: Callable[[], None] | None = None) -> None:
        self._inner = inner
        self._on_close = on_close
        self._reader = asyncio.get_running_loop().create_task(asyncio.Event().wait())

    @property
    def peer_identity(self) -> object:
        return self._inner.peer_identity

    async def receive(self, max_bytes: int) -> bytes:
        return await self._inner.receive(max_bytes)

    async def send_all(self, data: Buffer) -> None:
        await self._inner.send_all(data)

    async def aclose(self) -> None:
        if self._on_close is not None:
            on_close, self._on_close = self._on_close, None
            on_close()
        self._reader.cancel()
        await asyncio.gather(self._reader, return_exceptions=True)
        await self._inner.aclose()

    async def failure_phase(self) -> str | None:
        await asyncio.shield(self._reader)
        return None


def _refusing_direct_server(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    on_close: Callable[[], None] | None = None,
    epochs: list[str | None] | None = None,
) -> tuple[list[str], list[str]]:
    """The direct style against a server that issues another profile revision now, over the
    multiplexed stand-in; returns the helper spawns and the profile refreshes run here (and
    records each spawn's stop epoch in ``epochs``)."""

    from builders.server_profiles import _revision_of  # pyright: ignore[reportPrivateUsage]
    from finishup.client import server_profile

    write_connection_style(root, "direct")
    daemon = ScriptedDaemon()
    daemon.profile_revision = _revision_of(profile_document(revision=2))

    async def open_stream(  # noqa: ANN202
        _ssh: str,
        _root: Path,
        _record: targets.ServerTarget,
        *,
        expected: str | None,
        deadline: float | None,
    ):
        del expected, deadline
        client_end, server_end = memory_pair()
        daemon.serving.append(asyncio.create_task(daemon.serve(server_end)))
        return _MultiplexedDirectStream(client_end, on_close)

    monkeypatch.setattr(ssh_transport, "resolve_ssh", lambda: "/usr/bin/ssh")
    monkeypatch.setattr(ssh_transport, "open_direct_stream", open_stream)
    spawns: list[str] = []
    refreshes: list[str] = []

    def spawn(_root: Path, target_id: str, *, epoch: str | None = None) -> object:
        spawns.append(target_id)
        if epochs is not None:
            epochs.append(epoch)
        return object()

    def refresh(*_args: object, **_kwargs: object) -> object:
        refreshes.append("refresh")
        raise AssertionError("a refused request never refreshes the profile on its own path")

    def no_holder(_root: Path) -> None:
        return None

    monkeypatch.setattr(helper_status, "spawn_helper", spawn)
    monkeypatch.setattr(helper_status, "helper_holder", no_holder)
    monkeypatch.setattr(server_profile, "refresh_profile", refresh)
    return spawns, refreshes


@pytest.mark.parametrize("surface", ["cli", "mcp_bridge", "hook"])
def test_a_multiplexed_direct_streams_refusal_is_typed_and_starts_the_helper_on_every_surface(
    ssh_selected: tuple[targets.ServerTarget, Path], monkeypatch: pytest.MonkeyPatch, surface: str
) -> None:
    """The ssh-direct-L1 matrix cell: the hello's ``server_profile_changed`` reaches every
    surface as the typed refusal (never the stream's own cancellation, which left as a
    traceback), and leaves the marker and starts the helper, which refreshes the profile, so
    ``server status`` names the change. Nothing refreshes it on the refused request's path (a
    hook's included: design v2 section 8.9)."""

    record, root = ssh_selected
    spawns, refreshes = _refusing_direct_server(root, monkeypatch)

    async def run() -> ControlError:
        with pytest.raises(ControlError) as raised:
            if surface == "hook":
                # The hooks' attach path (``observe_hooks._connect_attachment_service``).
                await connect_service_on_demand(
                    ControlClientKind.CLI, timeout_seconds=5.0, supersede_incompatible=False
                )
            else:
                await connect_service(ControlClientKind(surface))
        return raised.value

    error = asyncio.run(run())
    assert (error.reason, error.phase) == ("service_unavailable", "server_profile_changed")
    assert (root / "state" / "profile-refresh-requested").exists()
    assert spawns == [record.target_id]
    assert refreshes == []


@pytest.mark.parametrize("meanwhile", ["server_use_local", "stopped_only"])
def test_a_direct_refusals_refresh_helper_keeps_the_admission_and_the_pre_dial_stop_epoch(
    ssh_selected: tuple[targets.ServerTarget, Path], monkeypatch: pytest.MonkeyPatch, meanwhile: str
) -> None:
    """The hello was refused ``server_profile_changed``; while its stream closed, another process
    ran ``server use local`` (the selection moves and the target's helper is stopped: its epoch
    moves). The refresh helper is never started then: the admission the request was made under
    no longer holds, and a helper's own admission is not bound to the selection, so it would
    reach a server the owner deselected. A stop alone (the selection kept) still starts it, with
    the epoch read before the dial, so that stop fences it before it serves anything."""

    from finishup.client.helper_status import read_helper_epoch, stop_helper

    record, root = ssh_selected
    before = read_helper_epoch(root)

    def elsewhere() -> None:
        if meanwhile == "server_use_local":
            targets.clear_selection()
        assert stop_helper(root, timeout_seconds=0.2) is True

    epochs: list[str | None] = []
    spawns, refreshes = _refusing_direct_server(
        root, monkeypatch, on_close=elsewhere, epochs=epochs
    )

    async def run() -> ControlError:
        with pytest.raises(ControlError) as raised:
            await connect_service(ControlClientKind.MCP_BRIDGE)
        return raised.value

    error = asyncio.run(run())
    assert (error.reason, error.phase) == ("service_unavailable", "server_profile_changed")
    assert read_helper_epoch(root) != before
    assert refreshes == []
    if meanwhile == "server_use_local":
        assert spawns == [] and epochs == []
    else:
        assert spawns == [record.target_id] and epochs == [before]


@pytest.mark.parametrize("meanwhile", ["server_use_local", "stopped_only"])
def test_a_relay_helper_start_keeps_the_admission_and_the_pre_dial_stop_epoch(
    ssh_selected: tuple[targets.ServerTarget, Path], monkeypatch: pytest.MonkeyPatch, meanwhile: str
) -> None:
    """The relay style's first dial found no helper; before it starts one, another process ran
    ``server use local`` (or only stopped the target). Nothing is started under an admission
    that no longer holds; a helper started after a stop alone carries the epoch read before the
    first dial, so that stop fences it (it never serves the target the owner stopped)."""

    from finishup.client.helper_status import read_helper_epoch, stop_helper

    record, root = ssh_selected
    before = read_helper_epoch(root)
    helper = _HelperStandIn(monkeypatch)

    def elsewhere() -> None:
        if meanwhile == "server_use_local":
            targets.clear_selection()
        assert stop_helper(root, timeout_seconds=0.2) is True

    helper.on_dial.append(elsewhere)

    async def run() -> ControlError | None:
        try:
            client = await connect_service_on_demand(ControlClientKind.CLI, timeout_seconds=2.0)
        except ControlError as error:
            return error
        await client.close()
        return None

    error = asyncio.run(run())
    assert read_helper_epoch(root) != before
    if meanwhile == "server_use_local":
        assert error is not None
        assert (error.reason, error.phase) == (
            "service_unavailable",
            "server_authorization_changed",
        )
        assert helper.spawns == []
    else:
        assert error is None
        assert helper.spawns == [record.target_id] and helper.epochs == [before]


def test_service_status_names_a_multiplexed_direct_streams_refusal_with_its_continuation(
    ssh_selected: tuple[targets.ServerTarget, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """``finishup service status --json`` (its fast path) names the refusal and the owner's way
    back (``remote_reconsent``), exit 20; never a traceback, never exit 1."""

    import json

    from finishup.cli import entry

    _record, root = ssh_selected
    _refusing_direct_server(root, monkeypatch)
    monkeypatch.chdir(tmp_path)

    code = entry._service_status_fast_path(["--json"])  # pyright: ignore[reportPrivateUsage]

    captured = capsys.readouterr()
    assert code == 20
    assert "Traceback" not in captured.err
    document = json.loads(captured.out)
    assert document["phase"] == "server_profile_changed"
    assert document["recovery"]["continuation"] == "remote_reconsent"
    assert "server_profile_changed" in captured.err


def test_a_direct_stream_that_does_not_answer_within_the_deadline_names_remote_unreachable(
    ssh_selected: tuple[targets.ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hook's bounded connect in the direct style fails open naming the remote phase (as the
    relay style does), never a phaseless outage that reads as this computer's service."""

    _record, root = ssh_selected
    write_connection_style(root, "direct")
    kept: list[object] = []

    async def open_stream(  # noqa: ANN202
        _ssh: str,
        _root: Path,
        _record: targets.ServerTarget,
        *,
        expected: str | None,
        deadline: float | None,
    ):
        del expected, deadline
        client_end, server_end = memory_pair()
        # The stream opens and the hello leaves, but nothing ever answers.
        kept.append(server_end)
        return client_end

    monkeypatch.setattr(ssh_transport, "resolve_ssh", lambda: "/usr/bin/ssh")
    monkeypatch.setattr(ssh_transport, "open_direct_stream", open_stream)

    async def run() -> ControlError:
        with pytest.raises(ControlError) as raised:
            await connect_service_on_demand(ControlClientKind.CLI, timeout_seconds=0.3)
        return raised.value

    error = asyncio.run(run())
    assert error.reason == "service_unavailable"
    assert error.phase == "remote_unreachable"


class _OtherBuildHelper:
    """A live helper of this release but another build holds the target (its lock stamp), and
    does not answer this client's hello; ``supersede_helper`` and ``stop_helper`` are recorded."""

    OTHER = "sha256:" + "e" * 64

    def __init__(self, root: Path, monkeypatch: pytest.MonkeyPatch, *, started_at: str) -> None:
        from finishup import __version__

        self.helper = _HelperStandIn(monkeypatch)
        self.helper.started = False
        write_helper_status(root, new_status(None, "ready", None, started_at=started_at))
        self.stamp = helper_status.HelperStamp(os.getpid(), __version__, self.OTHER)
        self.holders: list[helper_status.HelperStamp] = [self.stamp]
        self.lock_held: list[bool] = []
        self.supersedes: list[helper_status.HelperStamp] = []
        self.stops: list[Path] = []
        self.on_supersede: Callable[[], None] | None = None
        monkeypatch.setattr(helper_status, "helper_holder", self.holder)
        monkeypatch.setattr(helper_status, "helper_lock_held", self.held)
        monkeypatch.setattr(helper_status, "supersede_helper", self.supersede)
        monkeypatch.setattr(helper_status, "stop_helper", self.stop)

    def holder(self, _root: Path) -> helper_status.HelperStamp | None:
        return self.holders[0] if self.holders else None

    def held(self, _root: Path) -> bool:
        return self.lock_held.pop(0) if self.lock_held else bool(self.holders)

    def supersede(
        self, _root: Path, holder: helper_status.HelperStamp, *, timeout_seconds: float
    ) -> str:
        del timeout_seconds
        self.supersedes.append(holder)
        if self.on_supersede is not None:
            self.on_supersede()
        self.holders.clear()
        return "f" * 32

    def stop(self, path: Path, *, timeout_seconds: float = 5.0) -> bool:
        del timeout_seconds
        self.stops.append(path)
        self.holders.clear()
        return True


async def _connect_or_error(timeout_seconds: float = 2.0) -> ControlError | None:
    try:
        client = await connect_service_on_demand(
            ControlClientKind.CLI, timeout_seconds=timeout_seconds
        )
    except ControlError as error:
        return error
    await client.close()
    return None


@pytest.mark.parametrize(
    ("installed", "started"),
    [
        ("this", "before"),
        ("this", "after"),
        ("helper", "before"),
        ("helper", "after"),
        ("unreadable", "before"),
    ],
)
def test_a_helper_of_another_build_of_this_release_is_replaced_only_by_the_build_installed_now(
    ssh_selected: tuple[targets.ServerTarget, Path],
    monkeypatch: pytest.MonkeyPatch,
    installed: str,
    started: str,
) -> None:
    """Two builds of one version (a test instance, a dogfood build) cannot be ordered by version,
    nor by when their processes started: a bridge kept from before an in-place upgrade (on its
    retained runtime) may start its older helper after a newer process started, at a helper's
    idle exit. The installation orders them: the build installed now replaces the other build's
    helper whenever it started (exactly that helper, then its own carries the epoch that stop
    wrote), and a process that is not the build installed now (or cannot tell) never replaces
    it, so the two never flap; it is told ``service_incompatible`` (the bridge asks to reopen)."""

    from datetime import UTC, datetime, timedelta

    from finishup.config.installation import format_rfc3339_ms
    from finishup.protocol.schemas import schema_manifest_digest

    record, root = ssh_selected
    moment = (
        datetime(2020, 1, 1, tzinfo=UTC)
        if started == "before"
        else datetime.now(UTC) + timedelta(minutes=10)
    )
    other = _OtherBuildHelper(root, monkeypatch, started_at=format_rfc3339_ms(moment))
    digest = {
        "this": schema_manifest_digest(),
        "helper": _OtherBuildHelper.OTHER,
        "unreadable": None,
    }[installed]
    monkeypatch.setattr(service_client, "_installed_manifest_digest", lambda: digest)

    error = asyncio.run(_connect_or_error())
    assert other.stops == []
    if installed == "this":
        assert error is None
        assert other.supersedes == [other.stamp]
        assert other.helper.spawns == [record.target_id]
        assert other.helper.epochs == ["f" * 32]
    else:
        assert error is not None and (error.reason, error.phase) == ("service_incompatible", None)
        assert other.supersedes == [] and other.helper.spawns == []


def test_a_replacement_decides_again_when_another_helper_took_the_target_meanwhile(
    ssh_selected: tuple[targets.ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The replacement is fenced to the helper it decided about: when a helper of this build took
    the target meanwhile (``supersede_helper`` found another holder and moved nothing), it is
    neither stopped nor doubled; the client connects to it."""

    from finishup import __version__
    from finishup.protocol.schemas import schema_manifest_digest

    _record, root = ssh_selected
    other = _OtherBuildHelper(root, monkeypatch, started_at=now_stamp())
    monkeypatch.setattr(service_client, "_installed_manifest_digest", schema_manifest_digest)
    same = helper_status.HelperStamp(os.getpid() + 1, __version__, schema_manifest_digest())

    def taken(_root: Path, holder: helper_status.HelperStamp, *, timeout_seconds: float) -> str:
        del timeout_seconds
        other.supersedes.append(holder)
        other.holders[:] = [same]
        other.helper.started = True
        raise helper_status.HelperHolderChanged

    monkeypatch.setattr(helper_status, "supersede_helper", taken)

    assert asyncio.run(_connect_or_error()) is None
    assert other.supersedes == [other.stamp]
    assert other.stops == [] and other.helper.spawns == []


def test_a_helper_holding_the_lock_before_its_stamp_is_waited_for_never_stopped_or_doubled(
    ssh_selected: tuple[targets.ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A helper stamps its lock before it binds its endpoint and publishes its status; between
    taking the lock and stamping it, its identity is unknown. A client that finds the lock held
    and no stamp waits for it within its deadline (it neither starts another helper nor stops
    one), and decides once the stamp is there: here a helper of this build, which answers."""

    from finishup import __version__
    from finishup.protocol.schemas import schema_manifest_digest

    _record, root = ssh_selected
    other = _OtherBuildHelper(root, monkeypatch, started_at=now_stamp())
    other.holders.clear()
    same = helper_status.HelperStamp(os.getpid(), __version__, schema_manifest_digest())

    def held(_root: Path) -> bool:
        # The helper stamps its lock, binds and answers right after the first look.
        other.holders[:] = [same]
        other.helper.started = True
        return True

    monkeypatch.setattr(helper_status, "helper_lock_held", held)

    assert asyncio.run(_connect_or_error()) is None
    assert other.helper.spawns == [] and other.stops == [] and other.supersedes == []


def test_the_build_installed_now_is_read_from_the_installation_a_retained_runtime_copies(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``_installed_manifest_digest`` reads the package files of the installation (the origin of a
    retained runtime, which an in-place upgrade replaced), never this process's cached digest."""

    import hashlib
    import sys

    import finishup
    from finishup.adapters import release_runtime
    from finishup.protocol.schemas import schema_manifest_digest

    # This process runs its own package: the build installed now is its own.
    assert service_client._installed_manifest_digest() == schema_manifest_digest()  # pyright: ignore[reportPrivateUsage]

    relative = Path("lib", "python3", "site-packages", "finishup")
    origin = tmp_path / "venv"
    retained = tmp_path / ".venv-releases" / ("0" * 64)
    (retained / relative).mkdir(parents=True)
    upgraded = b'{"upgraded": true}\n'
    (origin / relative / "resources" / "schemas").mkdir(parents=True)
    (origin / relative / "resources" / "schemas" / "manifest.json").write_bytes(upgraded)
    monkeypatch.setattr(sys, "prefix", str(retained))
    monkeypatch.setattr(finishup, "__file__", str(retained / relative / "__init__.py"))
    monkeypatch.setattr(release_runtime, "installation_prefix", lambda: origin)
    expected = "sha256:" + hashlib.sha256(upgraded).hexdigest()
    assert service_client._installed_manifest_digest() == expected  # pyright: ignore[reportPrivateUsage]
    (origin / relative / "resources" / "schemas" / "manifest.json").unlink()
    assert service_client._installed_manifest_digest() is None  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize("stale", [False, True])
def test_a_server_of_another_release_is_remote_incompatible_never_the_local_restart(
    ssh_selected: tuple[targets.ServerTarget, Path], monkeypatch: pytest.MonkeyPatch, stale: bool
) -> None:
    """A server elsewhere answers another schema manifest (it was not upgraded with this client):
    ``remote_incompatible``, its owner upgrades it, never ``finishup service restart`` here.
    When this process is the stale one (a newer build runs the helper), ``service_incompatible``
    (the bridge asks to reopen)."""

    from finishup.service import control_protocol
    from finishup.service.control_protocol import read_control_frame, write_control_frame

    _record, root = ssh_selected
    write_connection_style(root, "direct")

    async def foreign_server(stream: ControlStream) -> None:
        await read_control_frame(stream)
        wire = control_protocol._hello_result_wire(  # pyright: ignore[reportPrivateUsage]
            service_client_status(),
            control_protocol._released_allowed_for(  # pyright: ignore[reportPrivateUsage]
                ControlClientKind.CLI
            ),
        )
        await write_control_frame(stream, {**wire, "schema_manifest_digest": "sha256:" + "e" * 64})

    serving: list[asyncio.Task[None]] = []

    async def open_stream(  # noqa: ANN202
        _ssh: str,
        _root: Path,
        _record: targets.ServerTarget,
        *,
        expected: str | None,
        deadline: float | None,
    ):
        del expected, deadline
        client_end, server_end = memory_pair()
        serving.append(asyncio.create_task(foreign_server(server_end)))
        return client_end

    monkeypatch.setattr(ssh_transport, "resolve_ssh", lambda: "/usr/bin/ssh")
    monkeypatch.setattr(ssh_transport, "open_direct_stream", open_stream)
    monkeypatch.setattr(service_client, "newer_helper_build_holds_selection", lambda: stale)

    async def run() -> ControlError:
        with pytest.raises(ControlError) as raised:
            await connect_service(ControlClientKind.CLI)
        return raised.value

    error = asyncio.run(run())
    if stale:
        assert (error.reason, error.phase) == ("service_incompatible", None)
    else:
        assert (error.reason, error.phase) == ("service_unavailable", "remote_incompatible")


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
