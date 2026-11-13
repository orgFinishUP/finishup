"""Every host names a held or kept repository at session start alike (ADR-051 decision 8).

Maintainer decision of 2026-11-07, round 4: while a FinishUP server on another machine, a port or
the web is selected, a repository whose privacy policy on this computer allows no network use is
held from it until the owner decides, or kept on this computer as they chose. "Server should feel
the same on all hooks": Codex, Claude Code and Cursor receive one byte-identical text for each
state (``repository_hold.hook_context``), for every remote kind, in the same shape as every other
remote phase. The connection seam refuses before anything is claimed or dialled, so no connector
starts and no hello is sent; the refused attach, the mapped status read and both drain sites
name the phase in the hook diagnostics, and the rows wait in this computer's outbox.

The hold is the gate's last step (ADR-052); in this release no remote kind is open, so every
remote root is refused earlier, as layer 1 named it. These tests open the kinds in process
(``opened``), and one shows the earlier refusal while they are closed.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import cast

import pytest

import finishup.client.everyday_repository as everyday_repository
from builders.server_targets import ambient_home, open_remote_kinds
from finishup.adapters.integrations.codex_lifecycle import mapping_from_start_ids, store_mapping
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.cli import hooks, observe_hooks
from finishup.client import targets
from finishup.client.everyday_policy import record_repository_report, repository_report
from finishup.client.everyday_repository import EverydayReads, repository_key_for
from finishup.client.repository_hold import HELD, KEPT, add_kept, hook_context
from finishup.config.paths import reset_selection_memo
from finishup.protocol.ids import IdKind, new_id

_HOSTS = ("codex", "claude", "cursor")
_KINDS: dict[str, dict[str, object]] = {
    "ssh": {"user": "owner", "host": "lab.example", "port": 22},
    "https": {"base_url": "https://finishup.example"},
    "local_port": {"base_url": "https://127.0.0.1:9443"},
}
_SESSIONS = {"codex": "codex-held", "claude": "claude:held-1", "cursor": "cursor:held-1"}


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


@pytest.fixture
def workspace(tmp_path: Path) -> str:
    folder = tmp_path / "project"
    folder.mkdir()
    return os.fspath(folder.resolve())


@pytest.fixture(autouse=True)
def opened(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every remote kind open, in process, so the gate reaches the hold."""

    open_remote_kinds(monkeypatch, *_KINDS)


@pytest.fixture
def dialled(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Anything that would start a service or open the control endpoint is recorded."""

    import finishup.service.client as service_client

    seen: list[str] = []

    def spawn(*_args: object, **_kwargs: object) -> object:
        seen.append("spawn_service")
        raise OSError("not in this test")

    async def connect_control(*_args: object, **_kwargs: object) -> object:
        seen.append("connect_control")
        raise OSError("not in this test")

    monkeypatch.setattr(service_client, "_spawn_service_process", spawn)
    monkeypatch.setattr(service_client, "connect_control", connect_control)
    return seen


def _select(kind: str) -> targets.ServerTarget:
    with targets.registry_lock():
        record, _root = targets.new_remote_target("privbox", kind, **_KINDS[kind])  # type: ignore[arg-type]
    targets.write_selection(record)
    reset_selection_memo()
    return record


def _key(workspace: str) -> str:
    key = asyncio.run(repository_key_for(workspace))
    assert key is not None
    return key


def _report_no_network(workspace: str) -> str:
    key = _key(workspace)
    assert record_repository_report(key, workspace, no_network=True)
    return key


def _keep(record: targets.ServerTarget, workspace: str) -> None:
    key = _key(workspace)
    report = repository_report(key)
    assert report is not None and report.no_network_since is not None
    with targets.registry_lock():
        add_kept(
            targets.target_root(record.target_id),
            record.target_id,
            key,
            workspace,
            report.no_network_since,
        )


def _consent(state: Path, workspace: str) -> None:
    store = LocalObservationStore(_state=state)
    store.grant_consent(store.workspace_commitment(workspace))


def _map(state: Path, host: str) -> None:
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=_SESSIONS[host],
            finishup_task_id=new_id(IdKind.TASK),
            finishup_session_id=new_id(IdKind.SESSION),
            finishup_writer_id=new_id(IdKind.WRITER),
            last_frontier=None,
        ),
        _state=state,
    )


def _emitted(host: str, state: Path, workspace: str, *, source: str) -> dict[str, object]:
    """Run one host's real SessionStart entry and return what it wrote to the host."""

    out = io.BytesIO()
    if host == "codex":
        body = {"session_id": _SESSIONS[host], "source": source, "hook_event_name": "SessionStart"}
        code = hooks.handle_session_start(
            stdin_bytes=json.dumps(body).encode(), stdout=out, workspace=workspace, _state=state
        )
    elif host == "claude":
        body = {"session_id": "held-1", "source": source, "hook_event_name": "SessionStart"}
        code = observe_hooks.handle_claude_observe(
            event_name="SessionStart",
            stdin_bytes=json.dumps(body).encode(),
            stdout=out,
            workspace=workspace,
            _state=state,
        )
    else:
        body = {"conversation_id": "held-1", "source": source, "hook_event_name": "sessionStart"}
        code = observe_hooks.handle_cursor_observe(
            event_name="sessionStart",
            stdin_bytes=json.dumps(body).encode(),
            stdout=out,
            workspace=workspace,
            _state=state,
        )
    assert code == 0
    return json.loads(out.getvalue())


def _session_start(host: str, state: Path, workspace: str, *, source: str = "startup") -> str:
    """Run one host's real SessionStart entry and return the context it gave the agent."""

    emitted = _emitted(host, state, workspace, source=source)
    context: object
    if host == "cursor":
        assert set(emitted) == {"additional_context"}
        context = emitted["additional_context"]
    else:
        output = cast(dict[str, object], emitted["hookSpecificOutput"])
        assert output["hookEventName"] == "SessionStart"
        context = output["additionalContext"]
    assert isinstance(context, str)
    return context


def _reasons(state: Path) -> list[str]:
    path = state / "observation/hook-diagnostics.jsonl"
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text().splitlines() if line]
    return [row["reason"] for row in rows if "reason" in row]


def _private(context: str, workspace: str, record: targets.ServerTarget) -> None:
    # Fixed text: no path, no target name or id, no host.
    for value in (workspace, record.name, record.target_id, "lab.example", "finishup.example"):
        assert value not in context


@pytest.mark.parametrize("kind", sorted(_KINDS))
def test_every_host_gives_one_held_text_in_place_of_the_attach_advice(
    home: Path, tmp_path: Path, workspace: str, dialled: list[str], kind: str
) -> None:
    record = _select(kind)
    _report_no_network(workspace)
    contexts: dict[str, str] = {}
    for host in _HOSTS:
        state = tmp_path / f"state-{host}"
        _consent(state, workspace)
        contexts[host] = _session_start(host, state, workspace)
        # The refused attach and the refused drain both name the phase.
        assert _reasons(state).count(HELD) == 2
        assert "drain_connect_failed" not in _reasons(state)

    expected = hook_context(HELD, "attach")
    # Substituted, never prepended to the static "call start" advice: exactly the one text.
    assert contexts == dict.fromkeys(_HOSTS, expected)
    assert "could not be reached within the hook budget" not in expected
    assert "no ledger task is mapped yet" not in expected
    _private(expected, workspace, record)
    assert dialled == []


@pytest.mark.parametrize("kind", sorted(_KINDS))
def test_every_host_says_a_kept_repository_stays_here_without_asking(
    home: Path, tmp_path: Path, workspace: str, dialled: list[str], kind: str
) -> None:
    record = _select(kind)
    _report_no_network(workspace)
    _keep(record, workspace)
    contexts: dict[str, str] = {}
    for host in _HOSTS:
        state = tmp_path / f"state-{host}"
        _consent(state, workspace)
        contexts[host] = _session_start(host, state, workspace)
        assert KEPT in _reasons(state)

    expected = hook_context(KEPT, "attach")
    assert contexts == dict.fromkeys(_HOSTS, expected)
    assert "do not ask the user about sending it again" in expected
    assert "Ask the user" not in expected
    _private(expected, workspace, record)
    assert dialled == []


@pytest.mark.parametrize("phase", [HELD, KEPT])
def test_a_session_without_consent_is_told_too_without_the_observation_clause(
    home: Path, tmp_path: Path, workspace: str, dialled: list[str], phase: str
) -> None:
    record = _select("https")
    _report_no_network(workspace)
    if phase == KEPT:
        _keep(record, workspace)
    contexts = {
        host: _session_start(host, tmp_path / f"state-{host}", workspace) for host in _HOSTS
    }
    expected = hook_context(phase, "unconsented")
    assert contexts == dict.fromkeys(_HOSTS, expected)
    # Nothing is captured without consent, so nothing is said to wait on this computer.
    assert "hook observations wait" not in expected
    for host in _HOSTS:
        assert phase in _reasons(tmp_path / f"state-{host}")
    assert dialled == []


def test_without_consent_only_the_held_repository_is_named(
    home: Path, tmp_path: Path, workspace: str, dialled: list[str]
) -> None:
    _select("ssh")
    other = tmp_path / "other"
    other.mkdir()
    held = os.fspath(other.resolve())
    _report_no_network(held)
    # This workspace was reported to allow network use; the other one is held.
    assert record_repository_report(_key(workspace), workspace, no_network=False)
    for host in _HOSTS:
        state = tmp_path / f"state-{host}"
        assert _emitted(host, state, workspace, source="startup") == {}
        assert _reasons(state) == ["workspace_unconsented"]
        assert _session_start(host, state, held) == hook_context(HELD, "unconsented")


@pytest.mark.parametrize("phase", [HELD, KEPT])
@pytest.mark.parametrize("source", ["resume", "compact"])
def test_every_host_names_a_mapped_session_held_on_resume_and_compact(
    home: Path, tmp_path: Path, workspace: str, dialled: list[str], phase: str, source: str
) -> None:
    record = _select("local_port")
    _report_no_network(workspace)
    if phase == KEPT:
        _keep(record, workspace)
    contexts: dict[str, str] = {}
    for host in _HOSTS:
        state = tmp_path / f"state-{host}"
        _consent(state, workspace)
        _map(state, host)
        contexts[host] = _session_start(host, state, workspace, source=source)
        assert phase in _reasons(state)

    expected = hook_context(phase, "mapped")
    assert contexts == dict.fromkeys(_HOSTS, expected)
    assert expected == hooks.unavailable_context(phase)
    assert "no live receipt can be promised" in expected
    _private(expected, workspace, record)
    assert dialled == []


def test_a_held_session_start_reads_no_admission_notice(
    home: Path,
    tmp_path: Path,
    workspace: str,
    dialled: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.host_startup_advisory as advisory

    asked: list[str] = []

    def notice(additional: str, *_args: object, **_kwargs: object) -> str:
        asked.append(additional)
        return additional

    monkeypatch.setattr(advisory, "append_admission_notice", notice)
    _select("ssh")
    _report_no_network(workspace)
    for host in ("claude", "cursor"):
        state = tmp_path / f"state-{host}"
        _consent(state, workspace)
        assert _session_start(host, state, workspace) == hook_context(HELD, "attach")
    # Its read would only meet the same refusal at the connection seam.
    assert asked == []


def test_a_report_made_at_this_session_start_holds_it_before_any_connection(
    home: Path,
    tmp_path: Path,
    workspace: str,
    dialled: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Critic gap 6: the refresh and the decision run before any attach, status or drain."""

    asked: list[str] = []

    async def read(
        locator: str, *, budget_seconds: float, lock_wait_seconds: float, key: str | None
    ) -> object:
        assert key is not None
        asked.append(locator)
        record_repository_report(key, locator, no_network=True)
        return EverydayReads("network_permitted", "no_network")

    monkeypatch.setattr(everyday_repository, "_live_read", read)
    _select("https")
    assert repository_report(_key(workspace)) is None
    contexts: dict[str, str] = {}
    for host in _HOSTS:
        state = tmp_path / f"state-{host}"
        _consent(state, workspace)
        contexts[host] = _session_start(host, state, workspace)
    # Asked once, by the first session start; every one is held in its own pass.
    assert asked == [workspace]
    assert contexts == dict.fromkeys(_HOSTS, hook_context(HELD, "attach"))
    assert dialled == []


def test_a_codex_resume_reads_the_report_before_its_status_read(
    home: Path,
    tmp_path: Path,
    workspace: str,
    dialled: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order: list[str] = []

    async def read(
        locator: str, *, budget_seconds: float, lock_wait_seconds: float, key: str | None
    ) -> object:
        assert key is not None
        order.append("report")
        record_repository_report(key, locator, no_network=True)
        return EverydayReads("network_permitted", "no_network")

    real_read_status: Callable[..., object] = hooks._read_status  # pyright: ignore[reportPrivateUsage]

    async def read_status(*args: object, **kwargs: object) -> object:
        order.append("status")
        return await real_read_status(*args, **kwargs)  # type: ignore[misc]

    monkeypatch.setattr(everyday_repository, "_live_read", read)
    monkeypatch.setattr(hooks, "_read_status", read_status)
    _select("ssh")
    state = tmp_path / "state"
    _consent(state, workspace)
    _map(state, "codex")

    context = _session_start("codex", state, workspace, source="resume")

    assert order[:2] == ["report", "status"]
    assert context == hook_context(HELD, "mapped")
    assert dialled == []


@pytest.mark.parametrize("json_output", [False, True])
def test_observe_drain_names_a_held_repository_as_every_command_does(
    home: Path,
    tmp_path: Path,
    workspace: str,
    dialled: list[str],
    capsys: pytest.CaptureFixture[str],
    json_output: bool,
) -> None:
    from finishup.cli import observe
    from finishup.cli.observe_hooks import map_hook_payload_to_envelope
    from finishup.cli.render import render_authorization_refusal
    from finishup.ports.control import ControlError

    _select("ssh")
    _report_no_network(workspace)
    state = tmp_path / "state"
    store = LocalObservationStore(_state=state)
    commitment = store.workspace_commitment(workspace)
    store.grant_consent(commitment)
    store.bind_codex_session(commitment, "sess")
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {
            "session_id": "sess",
            "hook_event_name": "PostToolUse",
            "tool_name": "shell",
            "correlation_id": "corr-1",
            "exit_status": 0,
        },
        session_commitment=store.session_commitment("sess"),
        event_ordinal=1,
        key_material=store.key_material(),
    )
    store.enqueue_outbox(commitment, "sess", envelope)

    code = observe.drain_observation(workspace=workspace, json_output=json_output, _state=state)

    assert code == 20
    captured = capsys.readouterr()
    rendered = render_authorization_refusal(
        ControlError("service_unavailable", retryable=True, phase=HELD)
    )
    assert rendered is not None
    expected = rendered.splitlines()
    assert expected[0].startswith(f"{HELD}: this repository's privacy policy on this computer")
    assert captured.err.splitlines()[: len(expected)] == expected
    if json_output:
        # The machine-readable summary is unchanged: the phase is told on stderr only.
        summary = json.loads(captured.out)
        assert summary["terminal"] == "service_unavailable"
        assert "phase" not in summary
    assert workspace not in captured.err and "privbox" not in captured.err
    # The row waits in this computer's outbox.
    assert store.pending_outbox_count(commitment) == 1
    assert dialled == []


def test_while_no_kind_is_open_the_session_start_names_the_earlier_refusal(
    home: Path,
    tmp_path: Path,
    workspace: str,
    dialled: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """This release: the gate's kind step refuses before the hold, as layer 1 named it."""

    open_remote_kinds(monkeypatch)
    _select("https")
    _report_no_network(workspace)
    state = tmp_path / "state"
    _consent(state, workspace)
    texts = {host: _session_start(host, state, workspace, source="startup") for host in _HOSTS}
    for text in texts.values():
        assert "target_root_is_remote" in text
        assert "repository_egress_held" not in text
    assert len(set(texts.values())) == 1
    assert dialled == []


def test_the_codex_re_ground_refreshes_outside_any_running_event_loop(
    home: Path,
    tmp_path: Path,
    workspace: str,
    dialled: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Critic gap 10: the refresh runs its own event loop (``asyncio.run`` in a fresh context), so
    Codex's own session-start re-ground must call it with no loop running; inside one, it would
    fail inside its own ``except`` and the report would silently never be made."""

    running: list[bool] = []
    real = everyday_repository.refresh_at_session_start

    def observed(worktree: str | None, **kwargs: object) -> bool:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            running.append(False)
        else:
            running.append(True)
        return real(worktree, **kwargs)  # type: ignore[arg-type]

    async def read(
        locator: str, *, budget_seconds: float, lock_wait_seconds: float, key: str | None
    ) -> object:
        assert key is not None
        record_repository_report(key, locator, no_network=True)
        return EverydayReads("network_permitted", "no_network")

    monkeypatch.setattr(everyday_repository, "refresh_at_session_start", observed)
    monkeypatch.setattr(everyday_repository, "_live_read", read)
    _select("ssh")
    state = tmp_path / "state"
    _consent(state, workspace)
    _map(state, "codex")

    _session_start("codex", state, workspace, source="resume")

    assert running and not any(running)
    report = repository_report(_key(workspace))
    assert report is not None and report.no_network
    assert dialled == []


def test_while_no_kind_is_open_a_session_without_consent_is_told_nothing_of_the_hold(
    home: Path,
    tmp_path: Path,
    workspace: str,
    dialled: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The hold is named only where it is what stops a connection: with every kind closed, an
    earlier step of the gate does, so a session without consent starts as in layer 1."""

    _select("https")
    _report_no_network(workspace)
    opened = {host: _session_start(host, tmp_path / f"open-{host}", workspace) for host in _HOSTS}
    assert set(opened.values()) == {hook_context(HELD, "unconsented")}
    open_remote_kinds(monkeypatch)
    for host in _HOSTS:
        emitted = _emitted(host, tmp_path / f"closed-{host}", workspace, source="startup")
        assert "repository_egress_held" not in json.dumps(emitted)
    assert dialled == []
