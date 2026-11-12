"""Every surface renders every authorization refusal and remote outage the same way (ADR-052).

One matrix over the shared gate's eight phases (``client.authorization.AUTHORIZATION_REFUSALS``):
the zero-network refusal, a stale disclosure, a remote root this release does not connect to, a
held or kept repository, a changed authorization, and the consent step's two profile refusals
(a changed profile, a level not agreed to; ADR-052). For each, every surface names the closed
phase, its fixed summary or text, and the continuation of its way back, as a retryable
``service_unavailable``; none tells the owner to start a local service, and none carries a path,
a server name or a host (the public-boundary canary). Since SSH servers open (layer 4), the same
holds for the five phases of a server elsewhere that could not be reached through its transport
(``remote_unreachable``, ``remote_auth_failed``, ``remote_identity_changed``,
``remote_service_not_running``, ``remote_incompatible``): each names its own repair.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest

import finishup.mcp.server as bridge
from builders.server_targets import ambient_home
from finishup.cli import bootstrap, hooks, menu, observe_hooks
from finishup.client import targets
from finishup.client.authorization import AUTHORIZATION_REFUSALS, refusal_summary
from finishup.config.paths import reset_selection_memo
from finishup.ports.control import ControlError
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import REMOTE_CONNECTION_PHASES
from finishup.protocol.recovery import directive_for
from finishup.tui.runtime import _connect_failure  # pyright: ignore[reportPrivateUsage]

_PHASES = sorted(AUTHORIZATION_REFUSALS)
# Every phase a connection to a server elsewhere names: the refusals, and the transport outages.
_ALL_PHASES = sorted(REMOTE_CONNECTION_PHASES)
_REQUEST = "req_00000000-0000-4000-8000-000000000001"


@pytest.fixture
def selected(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Path, targets.ServerTarget]]:
    """A server elsewhere, selected, with a name and a host no surface may print."""

    with ambient_home(monkeypatch) as home:
        with targets.registry_lock():
            record, _root = targets.new_remote_target(
                "privbox", "ssh", user="owner", host="secret-host.example", port=22
            )
        targets.write_selection(record)
        reset_selection_memo()
        yield home, record


def _continuation(phase: str) -> str:
    token = targets.remote_root_continuation(phase)
    assert token is not None
    return token


def _clean(text: str, home: Path, record: targets.ServerTarget) -> None:
    for forbidden in (str(home), record.name, cast(str, record.host), "owner@", "service run"):
        assert forbidden not in text


def _error(phase: str) -> ControlError:
    return ControlError("service_unavailable", retryable=True, phase=phase)


def test_the_matrix_covers_every_phase_and_each_has_a_summary_and_a_directive() -> None:
    assert set(_PHASES) == {
        "repository_egress_held",
        "repository_egress_kept",
        "server_authorization_changed",
        "server_level_unavailable",
        "server_profile_changed",
        "target_reauthorization_required",
        "target_root_is_remote",
        "zero_network_remote_selected",
    }
    for phase in _ALL_PHASES:
        assert refusal_summary(phase)
    assert set(_ALL_PHASES) - set(_PHASES) == {
        "remote_auth_failed",
        "remote_identity_changed",
        "remote_incompatible",
        "remote_service_not_running",
        "remote_unreachable",
    }
    assert refusal_summary("service_unavailable") is None


def test_the_words_say_refused_before_sending_or_stopped_sending_never_both() -> None:
    """Design v2 section 8.10: a refusal before anything was sent says so; a connection that
    ended after it was open says FinishUP stopped sending and what the server received stays
    there, and never implies that a hold reaches back over what was already sent."""

    for phase in _PHASES:
        summary = cast(str, refusal_summary(phase))
        directive = directive_for(_continuation_token(phase))
        assert directive is not None
        if phase == "server_authorization_changed":
            assert "stopped sending over it" in summary
            assert "already received stays there" in summary
            assert "stopped sending over it" in directive.directive
            for text in (summary, directive.directive):
                assert "nothing" not in text and "before anything" not in text
        elif phase == "server_profile_changed":
            # Also the server's own refusal of a hello or request it was sent: it says only what
            # the server guarantees, that it did no work for it (review of layer 3: B2).
            for text in (summary, directive.directive):
                assert "before that server did any work for it" in text
                assert "nothing" not in text and "before anything" not in text
                assert "stopped sending" not in text and "stays there" not in text
        else:
            assert "before anything" in summary
            assert "stopped sending" not in summary and "stays there" not in summary
            if phase.startswith("repository_egress_"):
                assert "before anything from it was sent" in summary
                assert "before anything from it was sent" in directive.directive


def _continuation_token(phase: str) -> str:
    from finishup.protocol.recovery import continuation_for_reason

    token = continuation_for_reason(phase)
    assert token is not None
    return token


@pytest.mark.parametrize("phase", _ALL_PHASES)
def test_the_cli_names_the_phase_its_summary_and_directive_in_text_and_json(
    selected: tuple[Path, targets.ServerTarget], phase: str
) -> None:
    home, record = selected
    continuation = _continuation(phase)
    directive = directive_for(continuation)
    assert directive is not None
    for json_output in (False, True):
        err: list[str] = []
        out: list[JsonValue] = []
        code = bootstrap.control_failure(
            _error(phase),
            json_output=json_output,
            stderr_writer=err.append,
            stdout_writer=out.append,
        )
        assert code == 20
        text = "\n".join(err)
        assert text.splitlines()[0] == f"{phase}: {refusal_summary(phase)}"
        assert directive.directive in text
        _clean(text, home, record)
        if json_output:
            (payload,) = out
            body = cast(dict[str, JsonValue], payload)
            assert (body["ok"], body["reason"], body["phase"], body["retryable"]) == (
                False,
                "service_unavailable",
                phase,
                True,
            )
            assert cast(dict[str, JsonValue], body["recovery"])["continuation"] == continuation
            _clean(json.dumps(body), home, record)
        else:
            assert out == []


@pytest.mark.parametrize("phase", _ALL_PHASES)
def test_mcp_names_the_phase_and_its_continuation(
    selected: tuple[Path, targets.ServerTarget], phase: str
) -> None:
    home, record = selected
    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        _error(phase), _REQUEST, "start"
    )
    structured = cast(dict[str, object], result.structuredContent)
    error = cast(dict[str, object], structured["error"])
    assert (error["code"], error["retryable"]) == ("SERVICE_UNAVAILABLE", True)
    assert error["safe_details"] == {
        "continuation": _continuation(phase),
        "phase": phase,
        "reason_code": "service_unavailable",
    }
    text = cast(str, getattr(result.content[0], "text"))
    assert f"(phase: {phase})" in text
    _clean(json.dumps(structured) + text, home, record)


@pytest.mark.parametrize("phase", _ALL_PHASES)
def test_hooks_name_the_phase_and_continuation_in_attach_and_mapped_texts(
    selected: tuple[Path, targets.ServerTarget], phase: str
) -> None:
    home, record = selected
    continuation = _continuation(phase)
    attach = observe_hooks._attachment_recovery_context(phase)  # pyright: ignore[reportPrivateUsage]
    mapped = hooks.unavailable_context(phase)
    for text in (attach, mapped):
        assert f"({phase})" in text
        assert f"Continuation: {continuation}." in text
        assert "call start again" not in text.lower() or phase.startswith("repository_")
        _clean(text, home, record)
    if phase == "server_authorization_changed":
        # It had sent things before it ended: never "before anything was sent".
        assert "before anything was sent" not in attach + mapped


@pytest.mark.parametrize("phase", _ALL_PHASES)
def test_the_terminal_interface_and_the_menu_name_the_phase_never_a_local_service(
    selected: tuple[Path, targets.ServerTarget], phase: str
) -> None:
    home, record = selected
    directive = directive_for(_continuation(phase))
    assert directive is not None
    failure = _connect_failure(_error(phase))
    assert (failure.reason, failure.message) == (phase, refusal_summary(phase))
    assert failure.details == (directive.directive,)
    assert "not reachable" not in failure.message
    guidance = menu._control_guidance(_error(phase))  # pyright: ignore[reportPrivateUsage]
    assert phase in guidance and directive.directive in guidance
    assert "finishup service run" not in guidance
    _clean(" ".join((failure.message, *failure.details, guidance)), home, record)


def test_a_changed_identity_names_an_https_servers_trust_as_well_as_an_ssh_host_key() -> None:
    """Layer-5 review (B1): an HTTPS target refused because its certificate or the CA file chosen
    for it changed is told so, not only about an SSH host key."""

    summary = cast(str, refusal_summary("remote_identity_changed"))
    assert "SSH server's host key" in summary
    assert "HTTPS server's certificate or the CA file" in summary


# The owner's WAN-gate decision (2026-11-11): a server elsewhere reached in the direct style that
# did not answer in time tells the user the direct style is slow on this network and that
# 'finishup server set NAME --style relay' is the remedy, on every surface that names the outage.
_RELAY_REMEDY = "'finishup server set NAME --style relay'"


@pytest.fixture
def selected_direct(
    selected: tuple[Path, targets.ServerTarget],
) -> Iterator[tuple[Path, targets.ServerTarget]]:
    from finishup.client.helper_status import write_connection_style

    home, record = selected
    write_connection_style(targets.target_root(record.target_id), "direct")
    yield home, record


@pytest.mark.parametrize("style", ["direct", "relay"])
def test_a_direct_style_outage_names_the_relay_style_on_every_surface(
    selected: tuple[Path, targets.ServerTarget], style: str
) -> None:
    from finishup.client.helper_status import write_connection_style

    home, record = selected
    write_connection_style(targets.target_root(record.target_id), style)  # type: ignore[arg-type]
    expected = "remote_direct_slow" if style == "direct" else "remote_server_test"
    phase = "remote_unreachable"
    assert targets.remote_root_continuation(phase) == expected
    directive = directive_for(expected)
    assert directive is not None
    assert (_RELAY_REMEDY in directive.directive) is (style == "direct")
    # The CLI, text and --json.
    err: list[str] = []
    out: list[JsonValue] = []
    assert (
        bootstrap.control_failure(
            _error(phase), json_output=True, stderr_writer=err.append, stdout_writer=out.append
        )
        == 20
    )
    assert directive.directive in "\n".join(err)
    body = cast(dict[str, JsonValue], out[0])
    assert cast(dict[str, JsonValue], body["recovery"])["continuation"] == expected
    # MCP.
    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        _error(phase), _REQUEST, "start"
    )
    structured = cast(dict[str, object], result.structuredContent)
    details = cast(dict[str, object], cast(dict[str, object], structured["error"])["safe_details"])
    assert details["continuation"] == expected
    # Hooks: the attach context and the mapped outage.
    for text in (
        observe_hooks._attachment_recovery_context(phase),  # pyright: ignore[reportPrivateUsage]
        hooks.unavailable_context(phase),
    ):
        assert f"Continuation: {expected}." in text
        assert (_RELAY_REMEDY in text) is (style == "direct")
    # The terminal interface and the menu.
    failure = _connect_failure(_error(phase))
    assert failure.details == (directive.directive,)
    guidance = menu._control_guidance(_error(phase))  # pyright: ignore[reportPrivateUsage]
    assert directive.directive in guidance
    _clean(" ".join([*err, json.dumps(body), json.dumps(structured), guidance]), home, record)


def test_only_an_outage_names_the_relay_style_never_a_refusal(
    selected_direct: tuple[Path, targets.ServerTarget],
) -> None:
    """A refusal, a refused key or a changed identity is no slow network: each keeps its own
    way back in the direct style."""

    for phase in _ALL_PHASES:
        token = targets.remote_root_continuation(phase)
        if phase == "remote_unreachable":
            assert token == "remote_direct_slow"
        else:
            assert token != "remote_direct_slow"
