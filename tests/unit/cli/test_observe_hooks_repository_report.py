"""A session start asks this computer's FinishUP about its repository (ADR-051 decision 8).

Maintainer decision of 2026-11-07, round 4. The SessionStart hook pass, for every host and in
both consent branches, asks this computer's everyday FinishUP about the session's repository when
its report is missing or stale: on the everyday root (while its service usually runs, so the
report exists before the owner switches to a server elsewhere) and while a server elsewhere is
selected. It does so before any attach, status or drain connection, so a repository just found
to allow no network use is held in the same pass; a later session start finds the report and asks
nothing, and the connection seam holds the repository from the record alone.
"""

from __future__ import annotations

import asyncio
import io
import json
import math
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

import finishup.cli.observe_hooks as observe_hooks
import finishup.client.everyday_repository as everyday_repository
from builders.server_targets import ambient_home, open_remote_kinds, record_remote_target
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.client import targets
from finishup.client.everyday_policy import record_repository_report, repository_report
from finishup.client.everyday_repository import EverydayReads, repository_key_for
from finishup.config.paths import reset_selection_memo
from finishup.domain.observation import ObservationSource
from finishup.ports.control import ControlError, WorkspaceLocator


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


@pytest.fixture
def elsewhere(home: Path) -> None:
    """A server elsewhere is recorded (not selected): the hold's reads are switched on (O3)."""

    record_remote_target()


@pytest.fixture
def workspace(tmp_path: Path) -> str:
    folder = tmp_path / "project"
    folder.mkdir()
    return os.fspath(folder.resolve())


@pytest.fixture
def live(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, float]]:
    """This computer's FinishUP, answering that the repository allows no network use."""

    asked: list[tuple[str, float]] = []

    async def read(
        locator: str, *, budget_seconds: float, lock_wait_seconds: float, key: str | None
    ) -> object:
        # The key the session start already derived is passed on, never derived again.
        assert key is not None and key == await repository_key_for(locator)
        # What is left of the half second (or the hook's budget) once the key was derived.
        asked.append((locator, math.ceil(budget_seconds * 10) / 10))
        record_repository_report(key, locator, no_network=True)
        return EverydayReads("network_permitted", "no_network")

    monkeypatch.setattr(everyday_repository, "_live_read", read)
    return asked


def _key(workspace: str) -> str:
    key = asyncio.run(repository_key_for(workspace))
    assert key is not None
    return key


def _session_start(
    tmp_path: Path,
    workspace: str,
    *,
    source: str = "startup",
    consent: bool = True,
    **kwargs: object,
) -> dict[str, object]:
    store = LocalObservationStore(_state=tmp_path / "state")
    if consent:
        store.grant_consent(store.workspace_commitment(workspace))
    out = io.BytesIO()
    code = observe_hooks.handle_observe(
        event_name="SessionStart",
        stdin_bytes=json.dumps(
            {"session_id": "claude:report-1", "hook_event_name": "SessionStart", "source": source}
        ).encode(),
        stdout=out,
        workspace=workspace,
        _state=tmp_path / "state",
        source=ObservationSource.CLAUDE_HOOK,
        **kwargs,  # type: ignore[arg-type]
    )
    assert code == 0
    raw = out.getvalue()
    return json.loads(raw) if raw else {}


@pytest.fixture
def connections(monkeypatch: pytest.MonkeyPatch, workspace: str) -> list[bool]:
    """Every service connection the pass opens records whether the report already existed."""

    opened: list[bool] = []
    key = _key(workspace)

    async def connect(_kind: object, **_kwargs: object) -> object:
        opened.append(repository_report(key) is not None)
        raise ControlError("service_unavailable", retryable=True)

    monkeypatch.setattr(observe_hooks, "connect_service", connect, raising=False)
    return opened


@pytest.mark.parametrize("consent", [True, False], ids=["consented", "unconsented"])
def test_a_session_start_on_the_everyday_root_records_the_report_before_any_connection(
    home: Path,
    elsewhere: None,
    tmp_path: Path,
    workspace: str,
    live: list[tuple[str, float]],
    connections: list[bool],
    consent: bool,
) -> None:
    _session_start(tmp_path, workspace, consent=consent)

    assert live == [(workspace, 0.5)]
    report = repository_report(_key(workspace))
    assert report is not None and report.no_network and report.worktrees == (workspace,)
    # Nothing connected before the report was there; the consented pass did try to attach.
    assert all(connections)
    assert bool(connections) is consent


def test_a_later_session_start_asks_nothing_and_a_server_elsewhere_is_held_from_the_record(
    home: Path,
    elsewhere: None,
    tmp_path: Path,
    workspace: str,
    live: list[tuple[str, float]],
    connections: list[bool],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.client.remote_binding import binding_for_active_root
    from finishup.client.targets import TargetError

    _session_start(tmp_path, workspace)
    assert len(live) == 1
    with targets.registry_lock():
        record, _root = targets.new_remote_target(
            "lab", "ssh", user="owner", host="lab.example", port=22
        )
    targets.write_selection(record)
    reset_selection_memo()

    _session_start(tmp_path, workspace, source="resume")

    assert len(live) == 1
    # The hold is the gate's last step; the kind is opened in process to reach it (ADR-052).
    open_remote_kinds(monkeypatch, "ssh")
    with pytest.raises(TargetError) as held:
        asyncio.run(binding_for_active_root(WorkspaceLocator(workspace), serve_workspace=False))
    assert held.value.reason == "repository_egress_held"


def test_with_a_server_elsewhere_a_missing_report_is_asked_for_before_any_connection(
    home: Path,
    tmp_path: Path,
    workspace: str,
    live: list[tuple[str, float]],
    connections: list[bool],
) -> None:
    with targets.registry_lock():
        record, _root = targets.new_remote_target(
            "web", "https", base_url="https://finishup.example"
        )
    targets.write_selection(record)
    reset_selection_memo()

    _session_start(tmp_path, workspace)

    assert live == [(workspace, 0.5)]
    assert connections and all(connections)


@pytest.mark.parametrize(
    ("source", "skip_service"),
    [("clear", False), ("startup", True)],
    ids=["clear", "skip_service"],
)
def test_a_clear_or_local_only_session_start_asks_nothing(
    home: Path,
    elsewhere: None,
    tmp_path: Path,
    workspace: str,
    live: list[tuple[str, float]],
    connections: list[bool],
    source: str,
    skip_service: bool,
) -> None:
    _session_start(tmp_path, workspace, source=source, skip_service=skip_service)
    assert live == []
    assert repository_report(_key(workspace)) is None
    # The same session start, of the asking kind, asks.
    _session_start(tmp_path, workspace)
    assert live == [(workspace, 0.5)]


def test_a_named_local_server_asks_nothing(
    home: Path,
    tmp_path: Path,
    workspace: str,
    live: list[tuple[str, float]],
    connections: list[bool],
) -> None:
    with targets.registry_lock():
        record, _root = targets.new_local_target("work")
    targets.write_selection(record)
    reset_selection_memo()
    _session_start(tmp_path, workspace)
    assert live == []
    # A server on this computer asks nothing; one elsewhere does.
    with targets.registry_lock():
        remote, _remote_root = targets.new_remote_target(
            "lab", "ssh", user="owner", host="lab.example", port=22
        )
    targets.write_selection(remote)
    reset_selection_memo()
    _session_start(tmp_path, workspace)
    assert live == [(workspace, 0.5)]


# --- dormant until a server elsewhere is recorded (ADR-052, the owner's answer O3) -------------


def _files(root: Path) -> list[str]:
    return sorted(os.fspath(path.relative_to(root)) for path in root.rglob("*"))


@pytest.mark.parametrize("consent", [True, False], ids=["consented", "unconsented"])
@pytest.mark.parametrize(
    "source",
    [ObservationSource.CLAUDE_HOOK, ObservationSource.CODEX_HOOK, ObservationSource.CURSOR_HOOK],
)
def test_with_no_server_elsewhere_a_session_start_is_as_before_the_hold(
    home: Path,
    tmp_path: Path,
    workspace: str,
    live: list[tuple[str, float]],
    monkeypatch: pytest.MonkeyPatch,
    consent: bool,
    source: ObservationSource,
) -> None:
    """With no remote target, a session start asks nothing, records nothing, and its output,
    its connections and the files it leaves are those of a pass without the hold's read."""

    def run(state: Path) -> tuple[bytes, list[str], list[str]]:
        opened: list[str] = []

        async def connect(_kind: object, **kwargs: object) -> object:
            opened.append(",".join(sorted(kwargs)))
            raise ControlError("service_unavailable", retryable=True)

        monkeypatch.setattr(observe_hooks, "connect_service", connect, raising=False)
        store = LocalObservationStore(_state=state)
        if consent:
            store.grant_consent(store.workspace_commitment(workspace))
        out = io.BytesIO()
        code = observe_hooks.handle_observe(
            event_name="SessionStart",
            stdin_bytes=json.dumps(
                {"session_id": "s-1", "hook_event_name": "SessionStart", "source": "startup"}
            ).encode(),
            stdout=out,
            workspace=workspace,
            _state=state,
            source=source,
        )
        assert code == 0
        return out.getvalue(), opened, _files(home)

    with_hold = run(tmp_path / "with")

    def no_read(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(observe_hooks, "_refresh_repository_report", no_read)
    without = run(tmp_path / "without")

    assert live == []
    assert with_hold == without
    assert not any("everyday-repositories" in name for name in with_hold[2])
