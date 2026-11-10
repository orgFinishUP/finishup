"""Layer 1's three known edges, fixed where remote kinds open (ADR-051, ADR-052).

1. A server-host refusal (``requires_server_host``, which ``service run`` and ``service start``
   get too) names the way back that works: 'finishup server use local' when the selection named
   the root, clearing the override when an isolation variable or a pinned launcher did.
2. The terminal interface never calls a server elsewhere "the local FinishUP service".
3. The menu's "Stop the service" asks nothing while the gate refuses the server in use, and names
   a server elsewhere it would stop.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from builders.server_targets import ambient_home, open_remote_kinds
from finishup.cli import menu
from finishup.cli.command_scope import ServerHostRequired, server_host_refusal_line
from finishup.client import targets
from finishup.client.authorization import refusal_summary
from finishup.client.targets import ServerTarget
from finishup.config.paths import reset_selection_memo
from finishup.ports.control import ControlError


@pytest.fixture
def lab(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[ServerTarget, Path]]:
    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, root = targets.new_remote_target(
                "lab",
                "ssh",
                user="owner",
                host="lab.example",
                port=22,
                remote_root="/srv/fu",
                remote_launcher="/srv/bin/finishup",
            )
        yield record, root


def test_a_server_host_refusal_names_the_way_back_that_works(
    lab: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    record, root = lab
    with targets.registry_lock():
        targets.write_selection(record)
    reset_selection_memo()
    selected = server_host_refusal_line(ServerHostRequired(record.target_id, "ssh"))
    assert "'finishup server use local'" in selected
    assert "selected server target" in selected and "FINISHUP_ISOLATED_ROOT" not in selected

    monkeypatch.setenv("FINISHUP_ISOLATED_ROOT", str(root))
    reset_selection_memo()
    named = server_host_refusal_line(ServerHostRequired(record.target_id, "ssh"))
    assert "server use local" not in named
    assert "unset FINISHUP_ISOLATED_ROOT" in named and "named server target" in named


def test_the_terminal_interface_never_calls_a_server_elsewhere_the_local_service(
    lab: tuple[ServerTarget, Path],
) -> None:
    from finishup.tui.runtime import _connect_failure  # pyright: ignore[reportPrivateUsage]

    record, _root = lab
    local = _connect_failure(ControlError("service_unavailable", retryable=True))
    assert local.message == "the local FinishUP service is not reachable"
    with targets.registry_lock():
        targets.write_selection(record)
    reset_selection_memo()
    unreachable = _connect_failure(
        ControlError("service_unavailable", retryable=True, phase="remote_auth_failed")
    )
    assert unreachable.reason == "remote_auth_failed"
    assert unreachable.message == refusal_summary("remote_auth_failed")
    assert unreachable.details and "SSH key" in unreachable.details[0]
    unnamed = _connect_failure(ControlError("service_unavailable", retryable=True))
    assert unnamed.message == "the selected FinishUP server elsewhere could not be reached"


def test_stop_the_service_asks_nothing_while_the_server_in_use_is_refused(
    lab: tuple[ServerTarget, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    record, _root = lab
    assert menu._stop_question() == "Stop the local service now?"  # pyright: ignore[reportPrivateUsage]
    with targets.registry_lock():
        targets.write_selection(record)
    reset_selection_memo()
    # Closed (or refused): no question, the phase and its way back instead.
    assert menu._stop_question() is None  # pyright: ignore[reportPrivateUsage]
    assert capsys.readouterr().err.startswith("service_unavailable: ")
    open_remote_kinds(monkeypatch, "ssh")
    question = menu._stop_question()  # pyright: ignore[reportPrivateUsage]
    assert question is not None and record.target_id in question and "local" not in question


@pytest.mark.parametrize("kept", [False, True])
def test_stop_the_service_asks_nothing_while_the_current_repository_is_held(
    lab: tuple[ServerTarget, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    kept: bool,
) -> None:
    """C3: the stop's own connection claims the current repository; held or kept from the
    selected server, it is refused, so the menu names that before it asks."""

    import asyncio
    import subprocess
    from datetime import UTC, datetime

    from finishup.adapters.workspace_root import canonical_workspace_root
    from finishup.client.everyday_policy import record_repository_report
    from finishup.client.repository_hold import add_kept, repository_key
    from finishup.ports.control import WorkspaceLocator

    record, root = lab
    open_remote_kinds(monkeypatch, "ssh")
    with targets.registry_lock():
        targets.write_selection(record)
    reset_selection_memo()
    worktree = tmp_path / "repo"
    worktree.mkdir()
    subprocess.run(("git", "init", "-q", str(worktree)), check=True)  # noqa: S607
    monkeypatch.chdir(worktree)
    # Not held yet: the question names the server elsewhere.
    question = menu._stop_question()  # pyright: ignore[reportPrivateUsage]
    assert question is not None and record.target_id in question
    key = repository_key(asyncio.run(canonical_workspace_root(WorkspaceLocator(str(worktree)))))
    since = datetime(2026, 11, 9, 9, 30, tzinfo=UTC)
    record_repository_report(key, str(worktree), no_network=True, now=since)
    if kept:
        with targets.registry_lock():
            assert add_kept(root, record.target_id, key, str(worktree), "2026-11-09T09:30:00.000Z")
    capsys.readouterr()
    assert menu._stop_question() is None  # pyright: ignore[reportPrivateUsage]
    phase = "repository_egress_kept" if kept else "repository_egress_held"
    assert capsys.readouterr().err.startswith(f"service_unavailable: {phase}: ")
