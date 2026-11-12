"""Every host's SessionStart hook names a selected server this computer refuses before any dial.

ADR-051 decision 8 (maintainer decision of 2026-11-07): while this computer last reported a
zero-network privacy policy, every connection to a remote target is refused before anything is
sent, as ``zero_network_remote_selected``, until the owner runs ``finishup server use local``.
The CLI and MCP ``start`` say so; the SessionStart hook of Codex, Claude Code and Cursor must say
the same, from a file read only: no dial, no service connection, no hook-budget outage text. A
mapped session's status read names it the same way. (This release adds and selects no remote
server; the record here is one another build left selected.)

A remote target authorized under the current disclosure, with no zero-network policy, is refused
the same way as ``target_root_is_remote`` when its kind is closed (an HTTPS server here: this
release reaches SSH servers only). Its context
names that phase, its registry directive and ``finishup server use local``, never a service still
to start or ``finishup service run``. A target authorized under an older disclosure
(``target_reauthorization_required``) points to this computer's server as well, or, for an SSH
server, to the owner's own 'finishup server use NAME'. When an isolation variable names the root instead, ``finishup server use
local`` cannot change it (``selection_overridden``), so the directive says to unset it or use an
unpinned launcher (``remote_root_override_clear``). The terminal menu's home line and its service
actions name every refusal the same way.
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
from finishup.config.paths import ISOLATED_ROOT_ENV_NAMES, active_root, reset_selection_memo
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
        # Every remote kind is open from layer 5: HTTPS stays closed in this process as the
        # example of a remote root this client does not reach (the gate's kind step).
        monkeypatch.setattr("finishup.client.authorization.OPEN_REMOTE_KINDS", frozenset({"ssh"}))
        yield root


@dataclass(frozen=True, slots=True)
class _Refused:
    root: Path
    phase: str
    continuation: str
    # The owner's way back: 'finishup server use local' when the selection names the root, and
    # clearing the override when an isolation variable names it, which outranks the selection
    # ('finishup server use local' answers selection_overridden there).
    way_back: str = "'finishup server use local'"


@pytest.fixture(params=["zero_network", "remote_root", "stale_disclosure", "isolation"])
def refused(
    home: Path, request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> _Refused:
    """A remote root: a selected target with this computer's last report of zero-network,
    authorized under the current disclosure with no such report (a remote root this release
    does not reach), or under an older disclosure; or an isolation variable naming its root."""

    with targets.registry_lock():
        # An HTTPS server: a kind this release does not reach (SSH opens in layer 4, where a
        # target the owner never consented to a profile for is refused at the consent step).
        record, root = targets.new_remote_target("lab", "https", base_url="https://lab.example")
        if request.param != "isolation":
            targets.write_selection(record)
    if request.param == "isolation":
        monkeypatch.setenv(ISOLATED_ROOT_ENV_NAMES[0], str(root))
    reset_selection_memo()
    assert active_root() == root
    assert not record.needs_reauthorization
    if request.param == "zero_network":
        everyday_policy.record_reported_policy(zero_network=True, now=_AT)
        return _Refused(root, "zero_network_remote_selected", "zero_network_local_server_required")
    if request.param == "stale_disclosure":
        # A later release shows a newer disclosure than the one the owner confirmed.
        monkeypatch.setattr(targets, "DISCLOSURE_VERSION", targets.DISCLOSURE_VERSION + 1)
        return _Refused(root, "target_reauthorization_required", "server_reauthorization_required")
    if request.param == "isolation":
        return _Refused(
            root,
            "target_root_is_remote",
            "remote_root_override_clear",
            "unset it or use an unpinned launcher",
        )
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
    from finishup.protocol.recovery import directive_for

    assert f"({refused.phase})" in context
    directive = directive_for(refused.continuation)
    assert directive is not None
    assert directive.directive in context
    assert refused.way_back in context
    if refused.phase != "target_reauthorization_required":
        # An older disclosure of an SSH server is confirmed again by the owner, by its name, on
        # their own terminal (layer 4); every other refusal points elsewhere.
        assert "server use NAME" not in context and "with its name" not in context
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
        f"  Service    FinishUP refused the selected server's connection before anything was "
        f"sent ({refused.phase}) — {directive.directive}"
    ]
    assert captured.err.startswith(
        f"service_unavailable: {refused.phase}: FinishUP refused the selected server's "
        "connection before anything was sent\n"
        f"Continuation: {refused.continuation}\n"
        f"Next: {directive.directive}\n"
    )
    assert refused.way_back in captured.err
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


@pytest.mark.parametrize(
    ("phase", "said"),
    [
        ("server_authorization_changed", "stopped sending over it"),
        ("server_profile_changed", "refused before that server did any work for it"),
    ],
)
def test_a_refusal_after_sending_never_says_nothing_was_sent(phase: str, said: str) -> None:
    """C2: a connection whose selection changed may already have sent a request (its outcome is
    unknown); a profile change may be the server's own answer to one. The menu and the hooks say
    what the shared summary says, never 'before anything was sent'."""

    from finishup.cli import menu
    from finishup.cli.hooks import remote_refusal_context
    from finishup.ports.control import ControlError

    guidance = menu._control_guidance(  # pyright: ignore[reportPrivateUsage]
        ControlError("service_unavailable", retryable=True, phase=phase)
    )
    assert guidance.startswith(f"service_unavailable: {phase}: ")
    assert said in guidance and "before anything was sent" not in guidance
    context = remote_refusal_context(phase)
    assert "before anything was sent" not in context
    if phase == "server_profile_changed":
        assert context.startswith("What the selected FinishUP server offers or needs changed")
        assert said in context
    else:
        assert context.startswith("FinishUP ended the selected server's connection")
