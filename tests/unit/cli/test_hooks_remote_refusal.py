"""Every host's SessionStart hook names a selected server this computer refuses before any dial.

ADR-051 decision 8 (maintainer decision of 2026-11-07): while this computer last reported a
zero-network privacy policy, every connection to a remote target is refused before anything is
sent, as ``zero_network_remote_selected``, until the owner runs ``finishup server use local``.
The CLI and MCP ``start`` say so; the SessionStart hook of Codex, Claude Code and Cursor must say
the same, from a file read only: no dial, no service connection, no hook-budget outage text. A
mapped session's status read names it the same way. (This release adds and selects no remote
server; the record here is one another build left selected.)

A remote target authorized under the current disclosure, with no zero-network policy, is refused
the same way as ``target_root_is_remote``: this release reaches no server elsewhere. Its context
names that phase, its registry directive and ``finishup server use local``, never a service still
to start or ``finishup service run``. The terminal menu's home line and its service actions name
both refusals the same way.
"""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

import finishup.client.everyday_policy as everyday_policy
from builders.server_targets import ambient_home
from finishup.adapters.integrations.codex_lifecycle import LifecycleMapping, store_mapping
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.cli import observe_hooks as observe_hooks_module
from finishup.client import targets
from finishup.config.paths import active_root, reset_selection_memo
from finishup.domain.observation import ObservationSource
from finishup.protocol.ids import IdKind, new_id
from finishup.service import client as service_client

_AT = datetime(2026, 11, 7, 9, 30, tzinfo=UTC)
_SOURCES = (
    ObservationSource.CODEX_HOOK,
    ObservationSource.CLAUDE_HOOK,
    ObservationSource.CURSOR_HOOK,
)


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        monkeypatch.setattr(
            everyday_policy,
            "_location",
            everyday_policy._ambient_marker_path,  # pyright: ignore[reportPrivateUsage]
        )
        yield root


@dataclass(frozen=True, slots=True)
class _Refused:
    root: Path
    phase: str
    continuation: str


@pytest.fixture(params=["zero_network", "remote_root"])
def refused(home: Path, request: pytest.FixtureRequest) -> _Refused:
    """A remote target is selected: with this computer's last report of zero-network, or
    authorized under the current disclosure with no such report (a remote root this release
    does not reach)."""

    with targets.registry_lock():
        record, root = targets.new_remote_target(
            "lab", "ssh", host="lab.example", port=22, remote_launcher="/opt/fu/bin/finishup"
        )
        targets.write_selection(record)
    reset_selection_memo()
    assert active_root() == root
    assert not record.needs_reauthorization
    if request.param == "zero_network":
        everyday_policy.record_reported_policy(zero_network=True, now=_AT)
        return _Refused(root, "zero_network_remote_selected", "zero_network_local_server_required")
    return _Refused(root, "target_root_is_remote", "remote_target_no_local_service")


@pytest.fixture
def nothing_dialled(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    async def dial() -> object:
        calls.append("dial")
        raise OSError("never dialled")

    async def attach(*_args: object, **_kwargs: object) -> object:
        calls.append("attach_connect")
        raise OSError("never connected")

    monkeypatch.setattr(service_client, "connect_control", dial)
    monkeypatch.setattr(
        service_client, "_spawn_service_process", lambda: calls.append("service_spawn")
    )
    monkeypatch.setattr(observe_hooks_module, "_connect_attachment_service", attach)
    return calls


def _consented(state: Path) -> tuple[LocalObservationStore, str]:
    store = LocalObservationStore(_state=state)
    locator = str(state.resolve())
    store.grant_consent(store.workspace_commitment(locator))
    return store, locator


def _session_start(
    source: ObservationSource, session: str, locator: str, state: Path, *, start: str
) -> str:
    out = io.BytesIO()
    stdin = json.dumps({"session_id": session, "source": start}).encode()
    if source is ObservationSource.CODEX_HOOK:
        # Codex's SessionStart hook enters through the re-ground handler, which routes a startup
        # to the shared observation pass and reads a mapped session's status itself.
        from finishup.cli.hooks import handle_session_start

        code = handle_session_start(stdin_bytes=stdin, stdout=out, workspace=locator, _state=state)
    else:
        code = observe_hooks_module.handle_observe(
            event_name="SessionStart",
            stdin_bytes=stdin,
            stdout=out,
            workspace=locator,
            _state=state,
            source=source,
            _output_event_name="sessionStart" if source is ObservationSource.CURSOR_HOOK else None,
        )
    assert code == 0
    rendered = json.loads(out.getvalue())
    if source is ObservationSource.CURSOR_HOOK:
        return str(rendered["additional_context"])
    return str(rendered["hookSpecificOutput"]["additionalContext"])


def _names_the_refusal(context: str, refused: _Refused) -> None:
    assert f"({refused.phase})" in context
    assert "'finishup server use local'" in context
    assert "nothing was sent" in context
    assert f"Continuation: {refused.continuation}." in context
    assert "could not be reached" not in context
    assert "hook budget" not in context
    # Nothing tells the agent a service still has to start, or to start one.
    assert "service startup" not in context
    assert "service run" not in context
    assert "service is unavailable" not in context
    assert "lab.example" not in context and " lab " not in context


@pytest.mark.parametrize("source", _SOURCES)
def test_an_unmapped_session_start_names_the_refusal_without_dialling(
    refused: _Refused,
    nothing_dialled: list[str],
    tmp_path: Path,
    source: ObservationSource,
    capsys: pytest.CaptureFixture[str],
) -> None:
    store, locator = _consented(tmp_path)

    context = _session_start(source, "zn-start", locator, tmp_path, start="startup")

    _names_the_refusal(context, refused)
    assert nothing_dialled == []
    assert observe_hooks_module.load_mapping("zn-start", _state=tmp_path) is None
    # The captured rows stay pending for a later delivery; nothing was sent.
    assert store.list_pending_outbox_rows(store.workspace_commitment(locator))
    assert f"hook_auto_attach_failed: {refused.phase}" in capsys.readouterr().err
    # The diagnostic keeps the closed reason, never the unknown-reason fallback.
    rows = (tmp_path / "observation" / "hook-diagnostics.jsonl").read_text().splitlines()
    reasons = [json.loads(row).get("reason") for row in rows]
    assert refused.phase in reasons
    assert "unknown_reason" not in reasons
    assert not (refused.root / "state" / "claimed-workspaces").exists()


@pytest.mark.parametrize("source", _SOURCES)
def test_a_mapped_session_start_names_the_refusal_without_dialling(
    refused: _Refused,
    nothing_dialled: list[str],
    tmp_path: Path,
    source: ObservationSource,
) -> None:
    _consented(tmp_path)
    locator = str(tmp_path.resolve())
    store_mapping(
        LifecycleMapping(
            mapping_version=1,
            codex_session_id="zn-resume",
            finishup_task_id=new_id(IdKind.TASK),
            finishup_session_id=new_id(IdKind.SESSION),
            finishup_writer_id=new_id(IdKind.WRITER),
            last_frontier=None,
        ),
        _state=tmp_path,
    )

    context = _session_start(source, "zn-resume", locator, tmp_path, start="resume")

    _names_the_refusal(context, refused)
    assert nothing_dialled == []


# --- the terminal menu --------------------------------------------------------------------------


def _quiet_menu_home(monkeypatch: pytest.MonkeyPatch) -> None:
    """The menu home without agent discovery or the everyday service's policy read."""

    from finishup.cli import menu, zero_network_selection

    async def harness() -> tuple[str, ...]:
        return ()

    monkeypatch.setattr(menu, "_harness_summary", harness)
    monkeypatch.setattr("finishup.cli.setup.setup_marker_present", lambda: True)
    monkeypatch.setattr(zero_network_selection, "find_zero_network_selection", lambda: None)


def test_the_menu_names_the_refusal_and_never_a_service_to_start(
    refused: _Refused,
    nothing_dialled: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The menu's home line and an action that needs the service (Service -> Unlock vault) name
    the phase and its registry directive, whose way back is 'finishup server use local', and
    never tell the owner to start a service the connection refused before anything was sent."""

    from finishup.cli import menu
    from finishup.protocol.recovery import directive_for

    _quiet_menu_home(monkeypatch)

    menu._print_home(menu._gather_overview())  # pyright: ignore[reportPrivateUsage]
    menu._service_unlock()  # pyright: ignore[reportPrivateUsage]

    captured = capsys.readouterr()
    directive = directive_for(refused.continuation)
    assert directive is not None
    service = [line for line in captured.out.splitlines() if line.startswith("  Service ")]
    assert service == [
        f"  Service    refused before anything was sent ({refused.phase}) — {directive.directive}"
    ]
    assert captured.err.startswith(
        f"service_unavailable: {refused.phase}: this computer refused the selected FinishUP "
        "server before anything was sent\n"
        f"Continuation: {refused.continuation}\n"
        f"Next: {directive.directive}\n"
    )
    assert "'finishup server use local'" in captured.err
    assert "service run" not in captured.out + captured.err
    assert "start it" not in captured.out
    assert "lab.example" not in captured.out + captured.err
    assert nothing_dialled == []


def test_the_menu_keeps_its_service_hint_without_a_remote_root() -> None:
    """Every other unavailable service keeps the menu's released hint."""

    from finishup.cli import menu
    from finishup.ports.control import ControlError

    guidance = menu._control_guidance(  # pyright: ignore[reportPrivateUsage]
        ControlError("service_unavailable", retryable=True)
    )
    assert guidance == (
        "service_unavailable: run 'finishup service run' under your selected user supervisor"
    )
