"""Every surface names a remote target's failure with its phase, never a local remedy (ADR-051).

On a remote root the CLI, the menu, setup, the MCP bridge, the hooks and the terminal interface
name the closed remote phase with its ADR-030 directive (``protocol.recovery``), a claim this
computer could not make as this folder's, and a locked server vault as the server owner's. None
of them tells the user to run a local ``service run`` or ``service unlock``, and none prints the
target's host or name. On a local root every one of them is unchanged.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

import pytest

from builders.server_targets import ambient_home
from finishup.cli import bootstrap, hooks, menu, setup
from finishup.client import targets
from finishup.client.remote_remedy import (
    REMOTE_DRAINING_SUMMARY,
    REMOTE_LOCKED_SUMMARY,
    REMOTE_NOT_SENT_SUMMARIES,
    REMOTE_UNAVAILABLE_SUMMARY,
    REMOTE_UNCLAIMABLE_SUMMARY,
    remote_remedy,
)
from finishup.config.paths import reset_selection_memo
from finishup.mcp import server as bridge
from finishup.ports.control import ControlError, ControlMethod, ControlResult
from finishup.protocol.recovery import directive_for
from finishup.tui import runtime as tui_runtime

_LOCAL_REMEDIES = ("service run", "service unlock", "service restart", "local terminal")
_HOST_AND_NAME = ("lab.example", "owner@", "'lab'", " lab ")


@pytest.fixture
def remote(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, _root = targets.new_remote_target(
                "lab", "ssh", user="owner", host="lab.example", port=22
            )
            targets.write_selection(record)
        reset_selection_memo()
        yield


@pytest.fixture
def local(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    with ambient_home(monkeypatch):
        reset_selection_memo()
        yield


def _clean(text: str) -> None:
    lowered = text.lower()
    for phrase in _LOCAL_REMEDIES:
        assert phrase not in lowered, (phrase, text)
    for leak in _HOST_AND_NAME:
        assert leak not in text, (leak, text)


_PHASED = ControlError("service_unavailable", retryable=True, phase="remote_auth_failed")
_BARE = ControlError("service_unavailable", retryable=True)
_LOCKED = ControlError("vault_locked", retryable=False)
_UNCLAIMABLE = ControlError("service_unavailable", retryable=False, phase="handshake")
_OLD_GIT = ControlError("service_unavailable", retryable=False, phase="handshake_git_version")
# The server answered that it is shutting down or restarting.
_DRAINING = ControlError("service_draining", retryable=True)


def test_the_remedy_names_the_phase_its_directive_and_the_owner(remote: None) -> None:
    del remote
    phased = remote_remedy(_PHASED)
    assert phased is not None and phased.reason == "remote_auth_failed"
    assert phased.directive == directive_for("remote_credential_repair")
    bare = remote_remedy(_BARE)
    assert bare is not None and bare.reason == "remote_unreachable"
    assert bare.summary == REMOTE_UNAVAILABLE_SUMMARY
    assert bare.directive == directive_for("remote_server_test")
    locked = remote_remedy(_LOCKED)
    assert locked is not None and (locked.reason, locked.summary) == (
        "vault_locked",
        REMOTE_LOCKED_SUMMARY,
    )
    unclaimable = remote_remedy(_UNCLAIMABLE)
    assert unclaimable is not None and unclaimable.summary == REMOTE_UNCLAIMABLE_SUMMARY
    old_git = remote_remedy(_OLD_GIT)
    assert old_git is not None and old_git.directive == directive_for("system_git_upgrade_required")
    draining = remote_remedy(_DRAINING)
    assert draining is not None
    assert (draining.reason, draining.summary, draining.directive) == (
        "service_draining",
        REMOTE_DRAINING_SUMMARY,
        None,
    )
    assert remote_remedy(ControlError("frame_invalid")) is None


def test_a_local_root_has_no_remote_remedy(local: None) -> None:
    del local
    assert remote_remedy(_BARE) is None
    assert remote_remedy(_LOCKED) is None
    assert remote_remedy(_UNCLAIMABLE) is None
    assert remote_remedy(_DRAINING) is None
    # A phase that only a remote connection carries is remote by construction.
    assert remote_remedy(_PHASED) is not None


@pytest.mark.parametrize("error", [_PHASED, _BARE, _LOCKED, _UNCLAIMABLE, _DRAINING])
def test_the_cli_names_the_remote_remedy(remote: None, error: ControlError) -> None:
    del remote
    lines: list[str] = []
    documents: list[object] = []
    code = bootstrap.control_failure(
        error, json_output=True, stderr_writer=lines.append, stdout_writer=documents.append
    )
    assert code != 0
    text = "\n".join(lines)
    _clean(text)
    (document,) = documents
    assert type(document) is dict
    assert document["reason"] == error.reason
    _clean(json.dumps(document))


def test_the_cli_keeps_its_local_remedy_on_a_local_root(local: None) -> None:
    del local
    lines: list[str] = []
    bootstrap.control_failure(_LOCKED, stderr_writer=lines.append)
    assert lines[0].startswith("vault_locked: run `finishup service unlock` on a local terminal")


@pytest.mark.parametrize("error", [_PHASED, _BARE, _LOCKED, _DRAINING])
def test_the_menu_and_setup_name_the_remote_remedy(remote: None, error: ControlError) -> None:
    del remote
    _clean(menu._control_guidance(error))  # pyright: ignore[reportPrivateUsage]
    for service in (
        {"reachable": False, "state": None},
        {"reachable": True, "state": "locked"},
    ):
        steps = setup._service_next_steps(service)  # pyright: ignore[reportPrivateUsage]
        assert steps
        for step in steps:
            _clean(step)


def test_setup_keeps_its_local_next_steps_on_a_local_root(local: None) -> None:
    del local
    steps = setup._service_next_steps({"reachable": False, "state": None})  # pyright: ignore[reportPrivateUsage]
    assert steps == (
        "run 'finishup service run' under your selected user supervisor",
        "run 'finishup service unlock' from a local terminal if the vault is locked",
    )


@pytest.mark.parametrize("error", [_PHASED, _BARE, _LOCKED, _UNCLAIMABLE, _DRAINING])
def test_the_bridge_names_the_remote_remedy(remote: None, error: ControlError) -> None:
    del remote
    result = bridge._control_error_result(error, None, "start")  # pyright: ignore[reportPrivateUsage]
    assert result.isError
    text = "".join(getattr(item, "text", "") for item in result.content)
    _clean(text)
    structured = json.dumps(result.structuredContent)
    _clean(structured)
    if error.phase == "remote_auth_failed":
        assert "remote_auth_failed" in structured
        assert "remote_credential_repair" in structured


@pytest.mark.parametrize(
    "phase", ["remote_unreachable", "remote_auth_failed", "remote_service_not_running"]
)
def test_a_lost_connection_never_claims_that_nothing_was_recorded(remote: None, phase: str) -> None:
    # A remote connection can end after a call was sent (a dropped network, a revoked key), so
    # its remedy keeps the same-request replay open instead of saying nothing was recorded.
    del remote
    lost = ControlError("service_unavailable", retryable=True, phase=phase)
    remedy = remote_remedy(lost)
    assert remedy is not None and remedy.directive is not None
    for text in (remedy.summary, remedy.directive.directive):
        assert "nothing was recorded" not in text, text
    assert "same request id" in remedy.summary
    result = bridge._control_error_result(lost, None, "publish_work")  # pyright: ignore[reportPrivateUsage]
    text = "".join(getattr(item, "text", "") for item in result.content)
    assert "nothing was recorded" not in text
    structured = json.dumps(result.structuredContent)
    assert "nothing was recorded" not in structured
    assert "same request_id" in structured


@pytest.mark.parametrize(
    ("phase", "continuation"),
    [
        ("target_reauthorization_required", "server_reauthorization_required"),
        ("target_root_is_remote", "remote_target_no_local_service"),
        # ADR-051 decision 8: this computer refused to connect while it is zero-network.
        ("zero_network_remote_selected", "zero_network_local_server_required"),
    ],
)
def test_a_connection_never_opened_says_nothing_was_sent(
    remote: None, phase: str, continuation: str
) -> None:
    # Raised before any dial: the server was never reached, so no surface may call it
    # unreachable or speak of a request it may have recorded.
    del remote
    refused = ControlError("service_unavailable", retryable=True, phase=phase)
    remedy = remote_remedy(refused)
    assert remedy is not None
    assert (remedy.reason, remedy.summary) == (phase, REMOTE_NOT_SENT_SUMMARIES[phase])
    assert remedy.directive == directive_for(continuation)
    lines: list[str] = []
    bootstrap.control_failure(refused, stderr_writer=lines.append)
    result = bridge._control_error_result(refused, None, "start")  # pyright: ignore[reportPrivateUsage]
    text = "".join(getattr(item, "text", "") for item in result.content)
    structured = json.dumps(result.structuredContent)
    for rendered in ("\n".join(lines), text, structured):
        # (The foundation's directive says "no local service runs for it": a fact, not a command.)
        for command in ("finishup service run", "finishup service unlock", "service restart"):
            assert command not in rendered, rendered
        for leak in _HOST_AND_NAME:
            assert leak not in rendered, rendered
        assert "could not be reached" not in rendered, rendered
        assert "may be recorded" not in rendered, rendered
    assert lines[0].startswith(f"service_unavailable: {phase}: ")
    assert "nothing was" in text and phase in structured and continuation in structured


def test_a_draining_server_is_waited_for_never_restarted_or_called_unreachable(
    remote: None,
) -> None:
    del remote
    lines: list[str] = []
    bootstrap.control_failure(_DRAINING, stderr_writer=lines.append)
    result = bridge._control_error_result(_DRAINING, None, "check")  # pyright: ignore[reportPrivateUsage]
    structured = json.dumps(result.structuredContent)
    for text in ("\n".join(lines), structured):
        # Never the local wording ("the local service is draining ... start it again").
        assert "the local service is" not in text.lower(), text
        assert "remote_unreachable" not in text and "start it again" not in text, text
    assert "same request_id" in structured and "service_draining" in structured


@pytest.mark.parametrize("method", list(ControlMethod))
def test_no_service_can_answer_service_unavailable(method: ControlMethod) -> None:
    # Every ``service_unavailable`` a remote client sees is its own connection's: a service
    # cannot answer one (the control-result error codes exclude it), which is why a remote root
    # reads a phase-less one as ``remote_unreachable`` and never as the server's own answer.
    from finishup.protocol.ids import IdKind, new_id
    from finishup.service.control_protocol import ControlProtocolError, validate_result

    answer = ControlResult(
        protocol_version="1.0",
        rpc_id=new_id(IdKind.CONTROL_RPC),
        service_instance_id=new_id(IdKind.SERVICE_INSTANCE),
        service_generation="1",
        method=method,
        outcome="error",
        body=ControlError("service_unavailable", retryable=True),
    )
    with pytest.raises(ControlProtocolError):
        validate_result(answer)


def test_the_hooks_name_the_remote_remedy(remote: None) -> None:
    del remote
    unavailable = hooks.unavailable_context(
        hooks.StatusOutcome("unavailable", remote_reason="remote_service_not_running")
    )
    assert unavailable.endswith("Continuation: remote_service_start_required.")
    locked = hooks.locked_context(hooks.StatusOutcome("locked", remote_reason="vault_locked"))
    for context in (unavailable, locked):
        _clean(context)
    # A local root's contexts are byte-identical to before.
    assert hooks.unavailable_context(hooks.StatusOutcome("unavailable")) == (
        hooks._UNAVAILABLE_CONTEXT  # pyright: ignore[reportPrivateUsage]
    )
    assert hooks.locked_context(hooks.StatusOutcome("locked")) == (
        hooks._LOCKED_CONTEXT  # pyright: ignore[reportPrivateUsage]
    )


@pytest.mark.parametrize("error", [_PHASED, _BARE, _LOCKED, _DRAINING])
def test_the_terminal_interface_names_the_remote_remedy(remote: None, error: ControlError) -> None:
    del remote
    failure = tui_runtime._connect_failure(error)  # pyright: ignore[reportPrivateUsage]
    _clean(str(failure))
    for detail in getattr(failure, "details", ()):
        _clean(detail)


# --- a target record that cannot be read ----------------------------------------------------------


def test_an_unreadable_target_record_fails_closed_and_names_no_local_remedy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A selected root whose ``target.json`` cannot be read may be a server elsewhere: every
    surface treats it as remote, so none names a local remedy, and the connect seam refuses it
    before any dial without starting a local service in it (``isolation_root_invalid``)."""

    import asyncio

    from finishup.client.remote_remedy import remote_root_selected
    from finishup.ports.control import ControlClientKind
    from finishup.service import client as client_module

    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, root = targets.new_remote_target("lab", "https", base_url="https://lab.example")
            targets.write_selection(record)
        reset_selection_memo()
        # Restored from a backup, say: the record is group-readable, so it is refused as unsafe.
        (root / "target.json").chmod(0o640)
        spawned: list[str] = []

        def no_spawn(*_args: object, **_kwargs: object) -> object:
            spawned.append("spawn")
            raise AssertionError("a local service was spawned in a remote target's root")

        monkeypatch.setattr(client_module, "_spawn_service_process", no_spawn)
        for connect in (client_module.connect_service, client_module.connect_service_on_demand):
            with pytest.raises(ControlError) as refused:
                asyncio.run(connect(ControlClientKind.CLI, workspace_locator=None))
            assert client_module.path_refusal_reason(refused.value) == "isolation_root_invalid"
        assert spawned == []
        assert not (root / "run" / "control.sock").exists()

        # Every surface names the remote remedy, never a local one.
        assert remote_root_selected() is True
        remedy = remote_remedy(_BARE)
        assert remedy is not None and remedy.reason == "remote_unreachable"
        lines: list[str] = []
        bootstrap.control_failure(_BARE, stderr_writer=lines.append)
        _clean("\n".join(lines))
        assert lines[0].startswith("service_unavailable: remote_unreachable: ")
        locked = remote_remedy(_LOCKED)
        assert locked is not None and locked.summary == REMOTE_LOCKED_SUMMARY
        failure = tui_runtime._connect_failure(_BARE)  # pyright: ignore[reportPrivateUsage]
        assert failure.reason == "remote_unreachable"
        _clean(str(failure))


def test_a_readable_named_local_record_keeps_the_local_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.client.remote_remedy import remote_root_selected

    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, _root = targets.new_local_target("work")
            targets.write_selection(record)
        reset_selection_memo()
        assert remote_root_selected() is False
        assert remote_remedy(_BARE) is None


_REFUSED_KEY = ControlError("service_unavailable", retryable=True, phase="remote_auth_failed")


def _never_unreachable(text: str) -> None:
    lowered = text.lower()
    for phrase in ("could not be reached", "not reachable", "did not answer", "could not serve"):
        assert phrase not in lowered, (phrase, text)


def test_a_refused_key_reads_as_an_answer_on_every_surface(
    remote: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RE-6 (B-1): a server that answered and refused the key is never "could not be reached".

    The CLI headline and its Next line, the menu, MCP, the SessionStart hook (attach and mapped
    status) and the terminal interface each say it answered and refused this client's key, and
    keep the same-request replay open for a request it received before that.
    """

    import asyncio

    from finishup.cli.observe_hooks import (
        _attachment_recovery_context,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.client.remote_remedy import REMOTE_KEY_REFUSED_SUMMARY

    del remote
    phase = "remote_auth_failed"
    directive = directive_for("remote_credential_repair")
    assert directive is not None
    lines: list[str] = []
    bootstrap.control_failure(_REFUSED_KEY, json_output=False, stderr_writer=lines.append)
    cli_text = "\n".join(lines)
    assert cli_text.splitlines()[0] == f"service_unavailable: {phase}: {REMOTE_KEY_REFUSED_SUMMARY}"
    assert "answered and refused this client's key" in cli_text
    assert directive.directive in cli_text

    async def refuse(*_args: object, **_kwargs: object) -> object:
        raise _REFUSED_KEY

    monkeypatch.setattr("finishup.cli.app.build_service_client", refuse)
    summary = asyncio.run(menu._service_summary())  # pyright: ignore[reportPrivateUsage]
    assert summary.startswith(f"answered, key refused — {phase}: ")

    result = bridge._control_error_result(_REFUSED_KEY, None, "start")  # pyright: ignore[reportPrivateUsage]
    structured = json.dumps(result.structuredContent)
    assert "answered and refused this client's key" in structured
    assert "same request_id" in structured and "remote_credential_repair" in structured

    attach = _attachment_recovery_context("service_unavailable", phase)
    assert f"service_unavailable ({phase})" in attach
    assert "answered and refused this client's key" in attach
    assert "Continuation: remote_credential_repair." in attach
    mapped = hooks.unavailable_context(hooks.StatusOutcome("unavailable", remote_reason=phase))
    assert "answered and refused this client's key" in mapped
    assert f"({phase})" in mapped and mapped.endswith("Continuation: remote_credential_repair.")

    failure = tui_runtime._connect_failure(_REFUSED_KEY)  # pyright: ignore[reportPrivateUsage]
    assert str(getattr(failure, "message", "")) == REMOTE_KEY_REFUSED_SUMMARY

    for text in (cli_text, summary, structured, attach, mapped, str(failure)):
        _never_unreachable(text)
        _clean(text)


def test_a_web_server_with_no_stored_key_was_sent_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RE-6 on approach B: the key is read before the connection opens, so a web server this
    computer holds no API key for was never asked: no surface says it answered."""

    from finishup.client.remote_remedy import REMOTE_NO_KEY_SUMMARY

    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, _root = targets.new_remote_target(
                "lab", "https", base_url="https://lab.example:8443", tls_pin="sha256:" + "a" * 64
            )
            targets.write_selection(record)
        reset_selection_memo()
        remedy = remote_remedy(_REFUSED_KEY)
        assert remedy is not None and remedy.summary == REMOTE_NO_KEY_SUMMARY
        assert remedy.availability() == "no API key stored"
        result = bridge._control_error_result(_REFUSED_KEY, None, "start")  # pyright: ignore[reportPrivateUsage]
        structured = json.dumps(result.structuredContent)
        assert "holds no API key" in structured and "nothing was sent" in structured
        mapped = hooks.unavailable_context(
            hooks.StatusOutcome("unavailable", remote_reason="remote_auth_failed")
        )
        assert mapped.startswith("This computer holds no API key for the selected FinishUP server")
        for text in (remedy.summary, structured, mapped):
            assert "answered" not in text, text
            _never_unreachable(text)


def test_a_session_start_on_a_remote_server_never_names_a_local_service_startup(
    remote: None,
) -> None:
    """B-2: an unmapped SessionStart on a server elsewhere names its phase, never local startup."""

    from finishup.cli.observe_hooks import (
        _attachment_recovery_context,  # pyright: ignore[reportPrivateUsage]
    )

    del remote
    for phase in ("remote_unreachable", "remote_service_not_running", "remote_incompatible"):
        context = _attachment_recovery_context("service_unavailable", phase)
        assert f"service_unavailable ({phase})" in context
        assert "finish service startup" not in context
        _clean(context)
    for reason in ("service_unavailable", "timeout"):
        context = _attachment_recovery_context(reason)
        assert "on another machine" in context
        assert "finish service startup" not in context
        _clean(context)
