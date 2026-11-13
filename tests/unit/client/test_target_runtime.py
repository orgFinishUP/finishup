"""``TargetRuntime`` dispatch: the local runtime is built in; remote kinds fail closed by token."""

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


def test_an_ssh_target_has_its_helper_runtime() -> None:
    from finishup.client.helper_runtime import SshTargetRuntime

    assert isinstance(runtime_for("ssh"), SshTargetRuntime)


@pytest.mark.parametrize("kind", ["local_port", "https"])
def test_https_and_port_servers_run_through_the_helper_runtime(kind: str) -> None:
    """Layer 5 (ADR-053): HTTPS and port servers are reached through the same helper."""

    from finishup.client.helper_runtime import SshTargetRuntime

    assert isinstance(runtime_for(kind), SshTargetRuntime)  # type: ignore[arg-type]


@pytest.mark.parametrize("kind", ["local_port", "https"])
def test_an_unregistered_remote_kind_is_a_closed_refusal(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.client import target_runtime

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

        def time_new_connections(self, root: Path | None, count: int) -> tuple[int, ...]:
            del root
            return (3,) * count

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
