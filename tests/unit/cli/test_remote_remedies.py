"""Every surface names the remote phase on a server on another machine (ADR-051, approach C).

On a remote target root no local service exists, so the CLI, the menu, setup, the MCP bridge,
the hook contexts and the terminal interface name the failure's remote phase with its ADR-030
directive (from ``protocol.recovery``, never restated), and a locked server vault as its owner's
to unlock on the server host. None tells the user to run a local ``service run`` or ``service
unlock``, and none prints a host, user or target name. A local root's output is unchanged.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest

from builders.server_targets import ambient_home
from finishup.cli import hooks as hooks_module
from finishup.cli import menu as menu_module
from finishup.cli import setup as cli_setup
from finishup.cli.bootstrap import control_failure
from finishup.client import targets
from finishup.client.remote_remedy import (
    REMOTE_LOCKED_SUMMARY,
    remote_connection_phase,
    remote_remedy,
)
from finishup.config.paths import reset_selection_memo
from finishup.mcp import server as mcp_server
from finishup.ports.control import ControlError
from finishup.protocol.canonical import JsonValue
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.recovery import directive_for
from finishup.tui import runtime as tui_runtime

_NAME = "qzxnamed"
_HOST = "qzxhost.example"
_PHASES = (
    ("remote_unreachable", "remote_server_test"),
    ("remote_auth_failed", "remote_credential_repair"),
    ("remote_identity_changed", "remote_identity_verify"),
    ("remote_service_not_running", "remote_service_start_required"),
    ("remote_incompatible", "remote_release_mismatch"),
)
_LOCAL_REMEDIES = ("service run", "service unlock", "service restart", "auto-unlock")


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


@pytest.fixture
def remote_root(home: Path) -> None:
    del home
    with targets.registry_lock():
        record, _root = targets.new_remote_target(_NAME, "https", base_url=f"https://{_HOST}")
        targets.write_selection(record)
    reset_selection_memo()


def _phase_error(phase: str) -> ControlError:
    return ControlError("service_unavailable", retryable=True, phase=phase)


def _assert_remote_words(text: str) -> None:
    for local in _LOCAL_REMEDIES:
        assert local not in text, text
    assert _HOST not in text and _NAME not in text, text


def _cli(error: ControlError, *, json_output: bool = False) -> tuple[str, list[JsonValue]]:
    lines: list[str] = []
    payloads: list[JsonValue] = []
    control_failure(
        error,
        json_output=json_output,
        stderr_writer=lines.append,
        stdout_writer=payloads.append,
    )
    return "\n".join(lines), payloads


# --- the shared remedy --------------------------------------------------------------------------


@pytest.mark.parametrize(("phase", "token"), _PHASES)
def test_a_remote_phase_names_its_own_directive(home: Path, phase: str, token: str) -> None:
    del home
    error = _phase_error(phase)
    assert remote_connection_phase(error) == phase
    remedy = remote_remedy(error)
    assert remedy is not None and remedy.reason == phase
    assert remedy.directive is directive_for(token)


def test_a_local_root_has_no_remote_remedy(home: Path) -> None:
    del home
    assert remote_remedy(ControlError("service_unavailable", retryable=True)) is None
    assert remote_remedy(ControlError("vault_locked", retryable=False)) is None
    assert remote_remedy(ControlError("frame_invalid")) is None


@pytest.mark.usefixtures("remote_root")
def test_on_a_remote_root_a_closed_connection_and_a_locked_vault_are_remote() -> None:
    closed = remote_remedy(ControlError("service_unavailable", retryable=True))
    assert closed is not None and closed.reason == "remote_unreachable"
    locked = remote_remedy(ControlError("vault_locked", retryable=False))
    assert locked is not None and locked.directive is None
    assert locked.summary == REMOTE_LOCKED_SUMMARY


# --- the CLI ------------------------------------------------------------------------------------


@pytest.mark.parametrize(("phase", "token"), _PHASES)
def test_the_cli_names_the_phase_and_its_directive(home: Path, phase: str, token: str) -> None:
    del home
    text, payloads = _cli(_phase_error(phase), json_output=True)
    assert text.startswith(f"service_unavailable: {phase}: ")
    directive = directive_for(token)
    assert directive is not None and directive.directive in text
    _assert_remote_words(text)
    payload = cast(dict[str, Any], payloads[0])
    assert payload["phase"] == phase and payload["reason"] == "service_unavailable"
    assert payload["recovery"]["continuation"] == token


def test_the_cli_keeps_its_local_text_on_a_local_root(home: Path) -> None:
    del home
    text, _ = _cli(ControlError("service_unavailable", retryable=True))
    assert text == (
        "service_unavailable: run 'finishup service run' under your selected user supervisor"
    )


@pytest.mark.usefixtures("remote_root")
def test_the_cli_sends_a_locked_server_vault_to_its_owner() -> None:
    text, _ = _cli(ControlError("vault_locked", retryable=False))
    assert text == f"vault_locked: vault_locked: {REMOTE_LOCKED_SUMMARY}"
    _assert_remote_words(text)


@pytest.mark.usefixtures("remote_root")
def test_the_menu_and_setup_name_the_remote_remedy() -> None:
    guidance = menu_module._control_guidance(_phase_error("remote_auth_failed"))  # pyright: ignore[reportPrivateUsage]
    assert guidance.startswith("remote_auth_failed: ")
    _assert_remote_words(guidance)
    steps = cli_setup._service_next_steps({"reachable": False, "state": None})  # pyright: ignore[reportPrivateUsage]
    directive = directive_for("remote_server_test")
    assert directive is not None and steps == (directive.directive,)
    assert cli_setup._service_next_steps({"reachable": True, "state": "locked"}) == (  # pyright: ignore[reportPrivateUsage]
        REMOTE_LOCKED_SUMMARY,
    )
    for step in steps:
        _assert_remote_words(step)


def test_the_menu_and_setup_keep_their_local_text(home: Path) -> None:
    del home
    guidance = menu_module._control_guidance(ControlError("service_unavailable", retryable=True))  # pyright: ignore[reportPrivateUsage]
    assert "finishup service run" in guidance
    steps = cli_setup._service_next_steps({"reachable": False, "state": None})  # pyright: ignore[reportPrivateUsage]
    assert steps == (cli_setup._NEXT_SERVICE, cli_setup._NEXT_UNLOCK)  # pyright: ignore[reportPrivateUsage]


# --- the MCP bridge -----------------------------------------------------------------------------


@pytest.mark.parametrize(("phase", "token"), _PHASES)
def test_the_bridge_reports_the_phase_with_its_continuation(
    home: Path, phase: str, token: str
) -> None:
    del home
    result = mcp_server._control_error_result(_phase_error(phase), new_id(IdKind.REQUEST), "start")  # pyright: ignore[reportPrivateUsage]
    error = cast(dict[str, Any], result.structuredContent)["error"]
    assert error["code"] == "SERVICE_UNAVAILABLE"
    assert error["safe_details"]["reason_code"] == phase
    assert error["safe_details"]["continuation"] == token
    _assert_remote_words(error["message"])


@pytest.mark.usefixtures("remote_root")
def test_the_bridge_sends_a_locked_server_vault_to_its_owner() -> None:
    result = mcp_server._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError("vault_locked", retryable=False), new_id(IdKind.REQUEST), "start"
    )
    error = cast(dict[str, Any], result.structuredContent)["error"]
    assert error["code"] == "VAULT_LOCKED"
    assert "server host" in error["message"]
    _assert_remote_words(error["message"])


def test_the_bridge_keeps_its_local_text_on_a_local_root(home: Path) -> None:
    del home
    result = mcp_server._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError("service_unavailable", retryable=True), new_id(IdKind.REQUEST), "start"
    )
    error = cast(dict[str, Any], result.structuredContent)["error"]
    assert "'finishup service run'" in error["message"]


# --- the hooks ----------------------------------------------------------------------------------


@pytest.mark.parametrize(("phase", "token"), _PHASES)
def test_the_hook_context_names_the_phase_continuation(home: Path, phase: str, token: str) -> None:
    del home
    outcome = hooks_module.StatusOutcome(
        "unavailable",
        remote_reason=hooks_module._remote_reason(_phase_error(phase)),  # pyright: ignore[reportPrivateUsage]
    )
    context = hooks_module.unavailable_context(outcome)
    assert context.endswith(f" Continuation: {token}.")
    assert len(context.encode()) <= 512
    _assert_remote_words(context)


@pytest.mark.usefixtures("remote_root")
def test_the_hook_context_sends_a_locked_server_vault_to_its_owner() -> None:
    reason = hooks_module._remote_reason(ControlError("vault_locked", retryable=False))  # pyright: ignore[reportPrivateUsage]
    context = hooks_module.locked_context(
        hooks_module.StatusOutcome("locked", remote_reason=reason)
    )
    assert "server host" in context
    _assert_remote_words(context)


def test_the_hook_contexts_are_unchanged_on_a_local_root(home: Path) -> None:
    del home
    error = ControlError("service_unavailable", retryable=True)
    assert hooks_module._remote_reason(error) is None  # pyright: ignore[reportPrivateUsage]
    outcome = hooks_module.StatusOutcome("unavailable")
    assert hooks_module.unavailable_context(outcome) == hooks_module._UNAVAILABLE_CONTEXT  # pyright: ignore[reportPrivateUsage]
    assert hooks_module.locked_context(outcome) == hooks_module._LOCKED_CONTEXT  # pyright: ignore[reportPrivateUsage]


def _auto_attach(error: ControlError) -> Any:  # noqa: ANN401
    import asyncio

    from finishup.cli import observe_hooks

    async def connect(_kind: object) -> object:
        raise error

    return asyncio.run(
        observe_hooks._try_auto_start(  # pyright: ignore[reportPrivateUsage]
            "claude:qzx-session",
            _state=None,
            harness_id="claude",
            workspace_locator="/qzx/workspace",
            connect=connect,  # type: ignore[arg-type]
        )
    )


@pytest.mark.parametrize(("phase", "token"), _PHASES)
def test_a_failed_auto_attach_names_the_remote_phase(home: Path, phase: str, token: str) -> None:
    # Found in the real-environment run: SessionStart told the agent to "finish service startup"
    # while an HTTPS server was down, a remedy no command on this machine can apply.
    from finishup.cli import observe_hooks

    del home
    outcome = _auto_attach(_phase_error(phase))
    assert (outcome.mapping, outcome.reason, outcome.remote_phase) == (
        None,
        "service_unavailable",
        phase,
    )
    context = observe_hooks._attachment_recovery_context(  # pyright: ignore[reportPrivateUsage]
        outcome.reason, remote_phase=outcome.remote_phase
    )
    assert context.startswith(f"FinishUP attachment pending: {phase}.")
    assert context.endswith(f" Continuation: {token}. ")
    assert "service startup" not in context
    _assert_remote_words(context)


@pytest.mark.usefixtures("remote_root")
def test_a_closed_auto_attach_connection_on_a_remote_root_is_unreachable() -> None:
    outcome = _auto_attach(ControlError("service_unavailable", retryable=True))
    assert outcome.remote_phase == "remote_unreachable"


def test_a_failed_auto_attach_keeps_its_local_context_on_a_local_root(home: Path) -> None:
    from finishup.cli import observe_hooks

    del home
    outcome = _auto_attach(ControlError("service_unavailable", retryable=True))
    assert (outcome.reason, outcome.remote_phase) == ("service_unavailable", None)
    context = observe_hooks._attachment_recovery_context(outcome.reason)  # pyright: ignore[reportPrivateUsage]
    assert context.startswith("FinishUP attachment pending: service_unavailable.")
    with pytest.raises(ValueError, match="auto_attach_outcome_invalid"):
        observe_hooks.AutoAttachOutcome(None, "service_unavailable", remote_phase="vault_locked")


# --- the terminal interface ---------------------------------------------------------------------


@pytest.mark.parametrize(("phase", "token"), _PHASES)
def test_the_terminal_interface_names_the_phase(home: Path, phase: str, token: str) -> None:
    del home
    failure = tui_runtime._connect_failure(_phase_error(phase))  # pyright: ignore[reportPrivateUsage]
    directive = directive_for(token)
    assert failure.reason == phase
    assert directive is not None and failure.details == (directive.directive,)
    _assert_remote_words(failure.message)


def test_the_terminal_interface_keeps_its_local_text(home: Path) -> None:
    del home
    failure = tui_runtime._connect_failure(ControlError("service_unavailable", retryable=True))  # pyright: ignore[reportPrivateUsage]
    assert (failure.reason, failure.message) == (
        "service_unavailable",
        "the local FinishUP service is not reachable",
    )


# --- a target record that cannot be read --------------------------------------------------------


def _selected(home: Path, kind: str) -> Path:
    del home
    with targets.registry_lock():
        if kind == "local":
            record, root = targets.new_local_target(_NAME)
        else:
            record, root = targets.new_remote_target(_NAME, "https", base_url=f"https://{_HOST}")
        targets.write_selection(record)
    reset_selection_memo()
    return root


def test_an_unreadable_target_record_fails_closed_on_every_check(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio

    from finishup.cli.command_scope import (
        ServerHostRequired,
        require_server_host,
        server_host_refusal_line,
    )
    from finishup.client.remote_remedy import remote_root_selected
    from finishup.ports.control import ControlClientKind
    from finishup.service import client as client_module

    root = _selected(home, "https")
    # Restored from a backup, say: the record is group-readable, so it is refused as unsafe.
    (root / "target.json").chmod(0o640)
    spawned: list[str] = []

    def no_spawn() -> object:
        spawned.append("spawn")
        raise AssertionError("a local service was spawned in a remote target's root")

    monkeypatch.setattr(client_module, "_spawn_service_process", no_spawn)
    with pytest.raises(ControlError) as raised:
        asyncio.run(
            client_module.connect_service_on_demand(
                ControlClientKind.CLI, workspace_locator=None, timeout_seconds=1.0
            )
        )
    assert (raised.value.reason, raised.value.phase) == (
        "service_unavailable",
        "remote_unreachable",
    )
    assert raised.value.retryable is False
    with pytest.raises(ControlError):
        asyncio.run(client_module.connect_service(ControlClientKind.CLI))
    assert spawned == []
    assert not (root / "run" / "control.sock").exists()
    # Every surface names the remote remedy, never a local one.
    assert remote_root_selected() is True
    remedy = remote_remedy(ControlError("service_unavailable", retryable=True))
    assert remedy is not None and remedy.reason == "remote_unreachable"
    text, _ = _cli(raised.value)
    _assert_remote_words(text)
    # A server-host command (a vault, a local service) is refused there too.
    with pytest.raises(ServerHostRequired) as refused:
        require_server_host("setup vault")
    # The foundation's ``ServerTargetUnreadable`` line (its own tests pin the wording).
    line = server_host_refusal_line(refused.value)
    assert "cannot be read" in line
    _assert_remote_words(line)


def test_a_readable_named_local_record_keeps_the_local_path(home: Path) -> None:
    from finishup.cli.command_scope import require_server_host
    from finishup.client.remote_remedy import remote_root_selected
    from finishup.service import client as client_module

    _selected(home, "local")
    assert client_module._remote_target() is None  # pyright: ignore[reportPrivateUsage]
    assert remote_root_selected() is False
    require_server_host("setup vault")


# --- this computer's zero-network record (ADR-051 decision 8) -----------------------------------
#
# This computer refused to connect, so no surface may say the server failed to serve: the CLI,
# the menu and setup (the shared summary), the terminal interface's connect failure and the hook
# contexts say that this computer makes no network connections and nothing was sent, with the
# directive that names 'finishup server use local' (the same words as approach A's surfaces).

_ZERO = "zero_network_remote_selected"
_ZERO_WORDS = (
    "this computer's FinishUP is set to make no network connections, so nothing was sent to the "
    "selected FinishUP server"
)


def test_the_zero_network_phase_has_its_own_summary(home: Path) -> None:
    from finishup.client.remote_remedy import ZERO_NETWORK_SUMMARY, remote_summary

    del home
    assert ZERO_NETWORK_SUMMARY == _ZERO_WORDS
    assert remote_summary(_ZERO) == _ZERO_WORDS
    assert remote_summary("remote_unreachable") != _ZERO_WORDS
    remedy = remote_remedy(_phase_error(_ZERO))
    assert remedy is not None and remedy.summary == _ZERO_WORDS
    assert remedy.directive is directive_for("zero_network_local_server_required")


def test_the_cli_says_this_computer_refused_and_names_the_fix(home: Path) -> None:
    del home
    text, _ = _cli(_phase_error(_ZERO))
    assert text.startswith(f"service_unavailable: {_ZERO}: {_ZERO_WORDS}")
    assert "could not serve" not in text
    assert "'finishup server use local'" in text
    _assert_remote_words(text)


def test_the_terminal_interface_says_this_computer_refused(home: Path) -> None:
    del home
    failure = tui_runtime._connect_failure(_phase_error(_ZERO))  # pyright: ignore[reportPrivateUsage]
    assert (failure.reason, failure.message) == (_ZERO, _ZERO_WORDS)
    assert any("'finishup server use local'" in detail for detail in failure.details)


def test_the_hook_contexts_say_this_computer_refused(home: Path) -> None:
    from finishup.cli import observe_hooks

    del home
    outcome = hooks_module.StatusOutcome(
        "unavailable",
        remote_reason=hooks_module._remote_reason(_phase_error(_ZERO)),  # pyright: ignore[reportPrivateUsage]
    )
    context = hooks_module.unavailable_context(outcome)
    # RE-1: the same words as the auto-attach, MCP ``start`` and the CLI: the closed reason, the
    # registry directive with the owner's fix, and the continuation.
    assert context.startswith(
        f"FinishUP refused the selected server's connection before anything was sent ({_ZERO})."
    )
    assert "set to make no network connections" in context
    assert "'finishup server use local'" in context
    assert "nothing was sent" in context and "could not serve" not in context
    assert context.endswith(" Continuation: zero_network_local_server_required.")
    assert len(context.encode()) <= 512
    attached = _auto_attach(_phase_error(_ZERO))
    # The diagnostic names the refusal itself, not an unavailable service.
    assert (attached.reason, attached.remote_phase) == (_ZERO, None)
    attach = observe_hooks._attachment_recovery_context(  # pyright: ignore[reportPrivateUsage]
        attached.reason, remote_phase=attached.remote_phase
    )
    assert attach == context + " "
    _assert_remote_words(context + attach)


@pytest.mark.usefixtures("remote_root")
def test_a_remote_roots_own_remedies_name_the_zero_network_fix() -> None:
    """The remote-root path (``remote_root_selected``) under round 3's record.

    A connection that closed without a phase, setup's next step for an unreachable service and
    the terminal interface's doctor remediation would send the owner to test the server; while
    this computer last reported zero-network, nothing reaches the server, so each names
    'finishup server use local' instead. Without the record they keep the server test.
    """

    from finishup.client.everyday_policy import record_reported_policy, remove_marker

    tested = directive_for("remote_server_test")
    local = directive_for("zero_network_local_server_required")
    assert tested is not None and local is not None
    closed = ControlError("service_unavailable", retryable=True)

    remedy = remote_remedy(closed)
    assert remedy is not None and remedy.reason == "remote_unreachable"
    assert cli_setup._service_next_steps({"reachable": False, "state": None}) == (  # pyright: ignore[reportPrivateUsage]
        tested.directive,
    )
    assert tui_runtime._remote_doctor_remediation()["service_reachable"] == tested.directive  # pyright: ignore[reportPrivateUsage]

    assert record_reported_policy(zero_network=True)
    remedy = remote_remedy(closed)
    assert remedy is not None and remedy.reason == _ZERO
    assert remedy.summary == _ZERO_WORDS and remedy.directive is local
    assert cli_setup._service_next_steps({"reachable": False, "state": None}) == (  # pyright: ignore[reportPrivateUsage]
        local.directive,
    )
    assert tui_runtime._remote_doctor_remediation()["service_reachable"] == local.directive  # pyright: ignore[reportPrivateUsage]
    text, _ = _cli(closed)
    assert text.startswith(f"service_unavailable: {_ZERO}: {_ZERO_WORDS}")

    assert remove_marker()
    remedy = remote_remedy(closed)
    assert remedy is not None and remedy.reason == "remote_unreachable"


@pytest.mark.usefixtures("remote_root")
def test_a_refused_key_reads_as_an_answer_on_every_surface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RE-6: a server that answered and refused the key is never "could not be reached".

    The CLI headline and its directive, the menu, MCP, the SessionStart hook (attach and mapped
    status) and the terminal interface each say it answered and refused this client's key.
    """

    import asyncio

    from finishup.cli import observe_hooks

    phase = "remote_auth_failed"
    token = "remote_credential_repair"
    directive = directive_for(token)
    assert directive is not None
    error = _phase_error(phase)
    answered = "the selected FinishUP server answered and refused this client's key"

    cli_text, _ = _cli(error)
    assert cli_text.splitlines()[0] == f"service_unavailable: {phase}: {answered}"
    assert directive.directive in cli_text

    async def refuse(*_args: object, **_kwargs: object) -> object:
        raise error

    monkeypatch.setattr("finishup.cli.app.build_service_client", refuse)
    summary = asyncio.run(menu_module._service_summary())  # pyright: ignore[reportPrivateUsage]
    assert summary == f"answered, key refused — {phase}: {answered}"

    result = mcp_server._control_error_result(error, new_id(IdKind.REQUEST), "start")  # pyright: ignore[reportPrivateUsage]
    mcp_text = cast(dict[str, Any], result.structuredContent)["error"]["message"]
    assert mcp_text.startswith(
        "The selected FinishUP server answered and refused this client's key. "
    )

    attached = _auto_attach(error)
    attach = observe_hooks._attachment_recovery_context(  # pyright: ignore[reportPrivateUsage]
        attached.reason, remote_phase=attached.remote_phase
    )
    assert attach.startswith(f"FinishUP attachment pending: {phase}. ")
    assert "answered and refused this client's key" in attach
    assert attach.endswith(f" Continuation: {token}. ")
    mapped = hooks_module.unavailable_context(
        hooks_module.StatusOutcome(
            "unavailable",
            remote_reason=hooks_module._remote_reason(error),  # pyright: ignore[reportPrivateUsage]
        )
    )
    assert "answered and refused this client's key" in mapped
    assert mapped.endswith(f" Continuation: {token}.")

    failure = tui_runtime._connect_failure(error)  # pyright: ignore[reportPrivateUsage]
    assert (failure.reason, failure.message) == (phase, answered)

    for text in (cli_text, summary, mcp_text, attach, mapped, failure.message):
        lowered = text.lower()
        assert "could not be reached" not in lowered, text
        assert "not reachable" not in lowered, text
        assert "did not answer" not in lowered, text
        assert "could not serve" not in lowered, text
        _assert_remote_words(text)
