"""Setup finishes as local only only once that choice is recorded (review of #1067/#1068)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from finishup.tui.app import FinishUpTui
from finishup.tui.models import (
    Detection,
    HarnessOption,
    LayerState,
    PrivacyPosture,
    ReadinessLayer,
    StatusSnapshot,
    VaultPosture,
)


@pytest.mark.anyio
@pytest.mark.parametrize(("outcome", "finished"), [("configured", True), ("failed", False)])
async def test_local_only_finishes_setup_only_when_recorded(
    monkeypatch: pytest.MonkeyPatch, outcome: str, finished: bool
) -> None:
    app = FinishUpTui()
    finishes: list[bool] = []

    async def privacy(*_args: object, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(outcome=outcome)

    async def hand_over(operation: Callable[[], Awaitable[Any]]) -> Any:
        return await operation()

    async def finish(*, connected: bool) -> None:
        finishes.append(connected)

    def say(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(app.runtime, "run_privacy_setup", privacy)
    monkeypatch.setattr(app, "hand_over_terminal", hand_over)
    monkeypatch.setattr(app, "_finish_setup", finish)
    monkeypatch.setattr(app, "say", say)

    await app._run_initial_review("local_only", connected=True)  # pyright: ignore[reportPrivateUsage]

    assert finishes == ([True] if finished else [])


def _foreign_entry_app(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    first_run: bool,
    review: str,
    privacy_outcome: str,
    events: list[str],
) -> FinishUpTui:
    """A Codex setup whose home already holds a ``finishup`` MCP entry FinishUP does not own."""

    from finishup.cli import setup as cli_setup

    home = tmp_path / "codexhome"
    home.mkdir()
    codex = HarnessOption("/usr/bin/codex", "0.1", "Codex CLI 0.1", "Command-line installation")
    detection = Detection(
        project_root=str(tmp_path),
        project_name="p",
        is_git_repository=True,
        launched_from_subdirectory=False,
        harnesses=(codex,),
        cwd=str(tmp_path),
    )
    app = FinishUpTui(first_run=first_run, cwd=tmp_path)

    async def ask(view: Any) -> Any:
        name = view.view_name
        events.append(f"ask:{name}")
        if name == "codex-home-path":
            view.value = str(home)
            return str(home)
        return {
            "welcome": "connect",
            "connect": "repair",
            "trust": "approve",
            "review-mode": review,
            "foreign": "local",
        }.get(name)

    async def detect() -> Detection:
        return detection

    async def plan(*_args: object, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(foreign_entry=True)

    async def foreign_detail(_option: object) -> tuple[str, ...]:
        return ("finishup: another tool's entry",)

    async def privacy(*_args: object, **kwargs: object) -> SimpleNamespace:
        events.append(f"privacy:{kwargs.get('conversation_review')}")
        return SimpleNamespace(outcome=privacy_outcome)

    async def vault() -> VaultPosture:
        events.append("storage")
        return VaultPosture(reachable=True, state="ready", vault_mode="os_keyring")

    async def snapshot() -> StatusSnapshot:
        return StatusSnapshot(
            project_root=str(tmp_path),
            layers=(ReadinessLayer("service_reachable", "Local service", LayerState.BLOCKED),),
            privacy=PrivacyPosture(profile=None, llm_inference_enabled=None, readable=False),
            open_work=0,
            open_findings=0,
            work_readable=False,
        )

    async def nothing(*_args: object, **_kwargs: object) -> bool:
        return False

    async def hand_over(operation: Callable[[], Awaitable[Any]]) -> Any:
        return await operation()

    def say(*_args: object, **_kwargs: object) -> None:
        return None

    def write_marker(outcome: str) -> None:
        events.append(f"marker:{outcome}")

    monkeypatch.setattr(cli_setup, "write_setup_marker", write_marker)
    monkeypatch.setattr(app.runtime, "detect", detect)
    monkeypatch.setattr(app.runtime, "discover_harnesses", lambda: (codex,))
    monkeypatch.setattr(app.runtime, "integration_plan", plan)
    monkeypatch.setattr(app.runtime, "foreign_entry_detail", foreign_detail)
    monkeypatch.setattr(app.runtime, "run_privacy_setup", privacy)
    monkeypatch.setattr(app.runtime, "vault_posture", vault)
    monkeypatch.setattr(app.runtime, "status_snapshot", snapshot)
    monkeypatch.setattr(app.runtime, "suggested_codex_home", lambda: home)
    monkeypatch.setattr(app, "ask", ask)
    monkeypatch.setattr(app, "hand_over_terminal", hand_over)
    monkeypatch.setattr(app, "_refresh_header", nothing)
    monkeypatch.setattr(app, "_maybe_say_package_update_tip", nothing)
    monkeypatch.setattr(app, "_offer_package_upgrade_if_newer", lambda: _true())
    monkeypatch.setattr(app, "say", say)
    return app


async def _true() -> bool:
    return True


@pytest.mark.anyio
@pytest.mark.parametrize("review", ["local_only", "agent_opt_in"])
async def test_first_run_foreign_entry_finishes_local_only_over_recorded_answer_and_storage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, review: str
) -> None:
    events: list[str] = []
    app = _foreign_entry_app(
        monkeypatch,
        tmp_path,
        first_run=True,
        review=review,
        privacy_outcome="configured",
        events=events,
    )

    await app._first_run_flow()  # pyright: ignore[reportPrivateUsage]

    assert "ask:foreign" in events, events
    after = events[events.index("ask:foreign") + 1 :]
    # Continuing locally ends first run as every local-only finish does: storage, then the
    # recorded "local checks only" answer, and only then the setup marker.
    assert after == ["storage", "privacy:local_only", "marker:local_only"], events


@pytest.mark.anyio
async def test_first_run_foreign_entry_leaves_no_marker_when_local_only_is_not_recorded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    events: list[str] = []
    app = _foreign_entry_app(
        monkeypatch,
        tmp_path,
        first_run=True,
        review="agent_opt_in",
        privacy_outcome="failed",
        events=events,
    )

    await app._first_run_flow()  # pyright: ignore[reportPrivateUsage]

    assert "privacy:local_only" in events, events
    assert not [event for event in events if event.startswith("marker:")], events


@pytest.mark.anyio
async def test_connect_after_setup_with_foreign_entry_keeps_the_setup_marker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    events: list[str] = []
    app = _foreign_entry_app(
        monkeypatch,
        tmp_path,
        first_run=False,
        review="agent_opt_in",
        privacy_outcome="configured",
        events=events,
    )

    await app.command_connect()

    assert "ask:foreign" in events, events
    # An installation that is already set up keeps its marker and its recorded policy.
    assert not [event for event in events if event.startswith(("marker:", "privacy:"))], events
