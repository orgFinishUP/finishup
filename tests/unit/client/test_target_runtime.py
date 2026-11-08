"""``TargetRuntime`` dispatch: local and connector runtimes; an unregistered kind fails closed."""

from __future__ import annotations

from pathlib import Path

import pytest

from finishup.client import target_runtime
from finishup.client.target_runtime import (
    LocalTargetRuntime,
    ProbeResult,
    TargetRuntimeError,
    register_target_runtime,
    runtime_for,
)


def test_the_local_kind_has_the_built_in_runtime() -> None:
    assert isinstance(runtime_for("local"), LocalTargetRuntime)


@pytest.mark.parametrize("kind", ["local_port", "ssh", "https"])
def test_remote_kinds_run_through_the_connector(kind: str) -> None:
    """Approach A registers the connector runtime for every remote kind."""

    from finishup.client.connector_runtime import ConnectorTargetRuntime

    assert isinstance(runtime_for(kind), ConnectorTargetRuntime)  # type: ignore[arg-type]


@pytest.mark.parametrize("kind", ["local_port", "ssh", "https"])
def test_an_unregistered_remote_kind_is_a_closed_refusal(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    loaders = dict(target_runtime._RUNTIME_LOADERS)  # pyright: ignore[reportPrivateUsage]
    del loaders[kind]
    monkeypatch.setattr(target_runtime, "_RUNTIME_LOADERS", loaders)
    with pytest.raises(TargetRuntimeError) as raised:
        runtime_for(kind)  # type: ignore[arg-type]
    assert (raised.value.reason, raised.value.phase) == (
        "remote_unreachable",
        "runtime_unavailable",
    )


def test_an_approach_registers_its_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Runtime:
        def ensure_ready(self, root: Path | None) -> None:
            del root

        def stop(self, root: Path | None) -> None:
            del root

        def probe(self, root: Path | None) -> ProbeResult:
            del root
            return ProbeResult("ready", samples=1, round_trip_p95_ms=3)

    monkeypatch.setattr(target_runtime, "_RUNTIME_LOADERS", dict(target_runtime._RUNTIME_LOADERS))  # pyright: ignore[reportPrivateUsage]
    register_target_runtime("ssh", _Runtime)
    assert runtime_for("ssh").probe(Path("/x")).outcome == "ready"


@pytest.mark.parametrize(
    "arguments",
    [
        {"outcome": "maybe"},
        {"outcome": "ready", "reason": "Free text"},
        {"outcome": "ready", "phase": "has space"},
        {"outcome": "ready", "round_trip_p95_ms": -1},
    ],
)
def test_probe_results_carry_only_closed_tokens(arguments: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        ProbeResult(**arguments)  # type: ignore[arg-type]


def test_runtime_errors_carry_only_closed_tokens() -> None:
    with pytest.raises(ValueError):
        TargetRuntimeError("Not a token")
    with pytest.raises(ValueError):
        TargetRuntimeError("remote_unreachable", phase="no spaces allowed")
    error = TargetRuntimeError("remote_unreachable", phase="runtime_unavailable")
    assert str(error) == "remote_unreachable:runtime_unavailable"


@pytest.mark.parametrize(
    ("samples", "expected"),
    [([0.001], 1), ([0.001] * 19 + [0.5], 1), ([0.001] * 18 + [0.4, 0.5], 400)],
)
def test_p95_is_nearest_rank(samples: list[float], expected: int) -> None:
    assert target_runtime._p95(samples) == expected  # pyright: ignore[reportPrivateUsage]


def test_the_connector_probe_times_only_warm_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A just-started connector's first call opens its upstream; the probe does not time it.

    Found in the real-environment run: with ten samples the p95 is the slowest call, so the one
    cold call made ``server test`` warn that agent tools would be denied right after ``server
    connect``, while every later probe read about 30 ms.
    """

    import finishup.client.connector_runtime as connector_runtime
    import finishup.service.client as service_client
    from finishup.client.target_runtime import PROBE_SAMPLES
    from finishup.ports.control import ServiceState, ServiceStatus

    clock = [100.0]
    calls: list[int] = []
    status = ServiceStatus(
        protocol_version="1.0",
        service_version="0.3.0",
        service_instance_id="svc_00000000-0000-4000-8000-000000000081",
        service_generation="1",
        state=ServiceState.READY,
        state_reason="none",
        vault_mode="passphrase",
        capabilities=("workflow",),
        session_monitor="unavailable",
    )

    class _Client:
        async def service_status(self) -> ServiceStatus:
            # The first call is the cold one: 900 ms; every later call takes 20 ms.
            clock[0] += 0.9 if not calls else 0.02
            calls.append(1)
            return status

        async def close(self) -> None:
            return None

    async def on_demand(*_args: object, **_kwargs: object) -> _Client:
        return _Client()

    monkeypatch.setattr(service_client, "connect_service_on_demand", on_demand)
    monkeypatch.setattr(connector_runtime.time, "monotonic", lambda: clock[0])
    result = connector_runtime.ConnectorTargetRuntime().probe(tmp_path)
    assert len(calls) == PROBE_SAMPLES + 1
    assert (result.outcome, result.samples, result.round_trip_p95_ms) == (
        "ready",
        PROBE_SAMPLES,
        20,
    )


def test_disconnecting_a_server_on_this_computer_stops_its_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SRV-9: ``server disconnect`` of the everyday or a named local server stops its FinishUP
    service (``SERVICE_STOP``, as ``finishup service stop`` does); servers.md says so."""

    import finishup.service.client as service_client

    stopped: list[bool] = []

    class _Client:
        async def stop(self) -> None:
            stopped.append(True)

        async def close(self) -> None:
            return None

    async def connect(*_args: object, **_kwargs: object) -> _Client:
        return _Client()

    monkeypatch.setattr(service_client, "connect_service", connect)
    LocalTargetRuntime().stop(None)
    assert stopped == [True]
    usage = Path(__file__).parents[3] / "docs" / "usage"
    servers = " ".join((usage / "servers.md").read_text(encoding="utf-8").split())
    assert "Neither stops the FinishUP service on the server." not in servers
    assert "`disconnect` stops it, as `finishup service stop` does" in servers


def test_the_docs_name_the_api_key_entry_that_outlives_a_deleted_folder() -> None:
    """SRV-10: an API key kept in the platform credential store lives outside the target's
    folder, so deleting the folder (or FinishUP's folders) leaves it; the ADR and the uninstall
    guidance name that entry and the commands that delete it."""

    from finishup.client.credentials import SERVER_CREDENTIAL_SERVICE

    docs = Path(__file__).parents[3] / "docs"
    upgrading = " ".join((docs / "usage" / "upgrading.md").read_text(encoding="utf-8").split())
    assert f"`{SERVER_CREDENTIAL_SERVICE}`" in upgrading
    assert "`finishup server remove` and `finishup server logout` delete it" in upgrading
    adr = " ".join(
        (docs / "adr" / "ADR-051-client-server-cut-and-server-targets.md")
        .read_text(encoding="utf-8")
        .split()
    )
    assert "removes every client-side artifact of that target except an API key" in adr


@pytest.mark.parametrize(
    ("earlier", "now"),
    [
        # An outage recorded during a Wi-Fi drop that has since been repaired.
        ("remote_unreachable", None),
        ("remote_unreachable", "remote_auth_failed"),
        # ``ready`` recorded before the network went down, with no client relayed since.
        (None, None),
        (None, "remote_unreachable"),
    ],
)
def test_connect_checks_again_instead_of_repeating_what_the_connector_last_recorded(
    monkeypatch: pytest.MonkeyPatch, earlier: str | None, now: str | None
) -> None:
    """A running connector records a phase only when it starts or relays a connection, so what
    it last recorded stays in its status until a client happens to be relayed: an outage since
    repaired, or ``ready`` from before the network went down. ``server connect`` checks again
    through it, once, and reports what that connection finds, never the earlier phase."""

    from builders.server_targets import ambient_home
    from finishup import __version__
    from finishup.client import targets
    from finishup.client.connector_runtime import ConnectorTargetRuntime
    from finishup.client.connector_status import (
        ConnectorLock,
        new_status,
        now_stamp,
        write_connector_status,
    )
    from finishup.ports.control import ControlError
    from finishup.protocol.schemas import schema_manifest_digest
    from finishup.service import client as service_client

    connects: list[str] = []

    class _Client:
        async def close(self) -> None:
            return None

    async def on_demand(*_args: object, **_kwargs: object) -> _Client:
        connects.append("connect")
        if now is not None:
            raise ControlError("service_unavailable", retryable=True, phase=now)
        return _Client()

    monkeypatch.setattr(service_client, "connect_service_on_demand", on_demand)
    with ambient_home(monkeypatch):
        with targets.registry_lock():
            _record, root = targets.new_remote_target(
                "lab", "ssh", host="lab.example", port=22, remote_launcher="/opt/fu/bin/finishup"
            )
        lock = ConnectorLock(root)
        lock.acquire(version=__version__, schema_manifest_digest=schema_manifest_digest())
        try:
            write_connector_status(
                root,
                new_status(
                    None,
                    "ready" if earlier is None else "unavailable",
                    earlier,
                    started_at=now_stamp(),
                ),
            )
            if now is None:
                ConnectorTargetRuntime().ensure_ready(root)
            else:
                with pytest.raises(TargetRuntimeError) as raised:
                    ConnectorTargetRuntime().ensure_ready(root)
                assert raised.value.reason == now
        finally:
            lock.release()
    assert connects == ["connect"]
