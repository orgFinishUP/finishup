"""Every host's SessionStart hook names a selected server this computer refuses before any dial.

ADR-051 decision 8 (maintainer decision of 2026-11-07): while this computer last reported a
zero-network privacy policy, every connection to a remote target is refused before anything is
sent, as ``zero_network_remote_selected``, until the owner runs ``finishup server use local``.
The CLI and MCP ``start`` say so; the SessionStart hook of Codex, Claude Code and Cursor must say
the same, from a file read only: no dial, no connector, no service connection, no hook-budget
outage text. A mapped session's status read names it the same way.
"""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

import finishup.client.everyday_policy as everyday_policy
from builders.server_targets import ambient_home
from finishup.adapters.integrations.codex_lifecycle import LifecycleMapping, store_mapping
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.cli import observe_hooks as observe_hooks_module
from finishup.client import targets, transports
from finishup.config.paths import active_root, reset_selection_memo
from finishup.domain.observation import ObservationSource
from finishup.protocol.ids import IdKind, new_id
from finishup.service import client as service_client

_AT = datetime(2026, 11, 7, 9, 30, tzinfo=UTC)
_PHASE = "zero_network_remote_selected"
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


@pytest.fixture
def refused(home: Path) -> Path:
    """A remote target is selected and this computer last reported zero-network."""

    with targets.registry_lock():
        record, root = targets.new_remote_target(
            "lab", "ssh", host="lab.example", port=22, remote_launcher="/opt/fu/bin/finishup"
        )
        targets.write_selection(record)
    reset_selection_memo()
    assert active_root() == root
    everyday_policy.record_reported_policy(zero_network=True, now=_AT)
    return root


@pytest.fixture
def nothing_dialled(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    async def dial() -> object:
        calls.append("dial")
        raise OSError("never dialled")

    async def attach(*_args: object, **_kwargs: object) -> object:
        calls.append("attach_connect")
        raise OSError("never connected")

    async def remote_dial(*_args: object, **_kwargs: object) -> object:
        calls.append("remote_dial")
        raise OSError("never dialled")

    monkeypatch.setattr(service_client, "connect_control", dial)
    # Approach B dials the server directly: neither an SSH nor an HTTPS stream is opened.
    monkeypatch.setattr(transports.SshTransport, "connect", remote_dial)
    monkeypatch.setattr(transports.HttpsTransport, "connect", remote_dial)
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


def _names_the_refusal(context: str) -> None:
    assert f"({_PHASE})" in context
    assert "'finishup server use local'" in context
    assert "nothing was sent" in context
    assert "Continuation: zero_network_local_server_required." in context
    assert "could not be reached" not in context
    assert "hook budget" not in context
    assert "lab.example" not in context and " lab " not in context


@pytest.mark.parametrize("source", _SOURCES)
def test_an_unmapped_session_start_names_the_zero_network_refusal_without_dialling(
    refused: Path,
    nothing_dialled: list[str],
    tmp_path: Path,
    source: ObservationSource,
    capsys: pytest.CaptureFixture[str],
) -> None:
    store, locator = _consented(tmp_path)

    context = _session_start(source, "zn-start", locator, tmp_path, start="startup")

    _names_the_refusal(context)
    assert nothing_dialled == []
    assert observe_hooks_module.load_mapping("zn-start", _state=tmp_path) is None
    # The captured rows stay pending for a later delivery; nothing was sent.
    assert store.list_pending_outbox_rows(store.workspace_commitment(locator))
    assert f"hook_auto_attach_failed: {_PHASE}" in capsys.readouterr().err
    assert not (refused / "state" / "claimed-workspaces").exists()


@pytest.mark.parametrize("source", _SOURCES)
def test_a_mapped_session_start_names_the_zero_network_refusal_without_dialling(
    refused: Path,
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

    _names_the_refusal(context)
    assert nothing_dialled == []
