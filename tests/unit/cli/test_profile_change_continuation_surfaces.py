"""A changed server profile asks the owner only when that is known (ADR-052 decision 10).

A server elsewhere refuses (``server_profile_changed``) a hello or request naming a profile revision
it no longer issues. When this computer's copy of that server's profile still agrees with the
owner's consent, the refusal is the first news of the change: what changed is not known yet, and
the refresh it asks for may show only a narrowing this computer adjusts to by itself. Such a refusal
continues as ``remote_profile_checking`` (repeat the same request shortly) on every surface: the
CLI in text and JSON, MCP, hooks, the terminal interface and the menu. ``remote_reconsent`` (only
the owner agrees again) stays for a consent the consent step already refuses on what this computer
holds: a changed or wider profile, another issuer, a level above the consent, or no consent.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import cast

import pytest

import finishup.mcp.server as bridge
from builders.server_profiles import consent_to, profile_document, refreshed
from builders.server_targets import ambient_home
from finishup.cli import bootstrap, hooks, menu, observe_hooks
from finishup.client import targets
from finishup.client.authorization import refusal_summary
from finishup.config.paths import reset_selection_memo
from finishup.ports.control import ControlError
from finishup.protocol.canonical import JsonValue
from finishup.protocol.consent_envelope import ReviewEgress
from finishup.protocol.errors import REASON_CODE_CONTINUATIONS
from finishup.protocol.recovery import CONTINUATION_TOKENS, directive_for
from finishup.protocol.server_profile import ProfileLevels
from finishup.tui.runtime import _connect_failure  # pyright: ignore[reportPrivateUsage]

_PHASE = "server_profile_changed"
_CHECKING = "remote_profile_checking"
_RECONSENT = "remote_reconsent"
_REQUEST = "req_00000000-0000-4000-8000-000000000001"


@pytest.fixture
def selected(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Path, targets.ServerTarget]]:
    """A server elsewhere, selected, with a name and a host no surface may print; no consent."""

    with ambient_home(monkeypatch) as home:
        with targets.registry_lock():
            record, _root = targets.new_remote_target(
                "privbox", "ssh", user="owner", host="secret-host.example", port=22
            )
        targets.write_selection(record)
        reset_selection_memo()
        yield home, record


def _consented(record: targets.ServerTarget) -> targets.ServerTarget:
    """The owner's consent to the profile this computer holds: the consent step admits it."""

    return consent_to(record)


def _widened(record: targets.ServerTarget) -> targets.ServerTarget:
    """Consented, then a fetched profile that reviews with a provider: the owner is asked."""

    consented = consent_to(record)
    refreshed(
        consented, profile_document(review=ReviewEgress("server_policy", "openai"), revision=2)
    )
    return consented


def _other_issuer(record: targets.ServerTarget) -> targets.ServerTarget:
    """Consented, then the same offer from another server installation's revisions."""

    consented = consent_to(record)
    refreshed(consented, profile_document(issuer="8" * 32))
    return consented


def _level_above(record: targets.ServerTarget) -> targets.ServerTarget:
    """Consented at L1, then a server that requires L2."""

    consented = consent_to(record)
    refreshed(consented, profile_document(levels=ProfileLevels(("L2",), "L2"), revision=2))
    return consented


def _no_consent(record: targets.ServerTarget) -> targets.ServerTarget:
    """Selected, never consented to (or a consent this computer cannot read)."""

    return record


_KNOWN: dict[str, Callable[[targets.ServerTarget], targets.ServerTarget]] = {
    "no_consent": _no_consent,
    "widened": _widened,
    "other_issuer": _other_issuer,
    "level_above": _level_above,
}


def _clean(text: str, home: Path, record: targets.ServerTarget) -> None:
    for forbidden in (str(home), record.name, cast(str, record.host), "owner@", "service run"):
        assert forbidden not in text


def _error() -> ControlError:
    return ControlError("service_unavailable", retryable=True, phase=_PHASE)


def _surfaces(home: Path, record: targets.ServerTarget, token: str) -> None:
    """Every surface names ``server_profile_changed`` with ``token`` and its directive."""

    directive = directive_for(token)
    assert directive is not None
    # The CLI, in text and in JSON.
    for json_output in (False, True):
        err: list[str] = []
        out: list[JsonValue] = []
        code = bootstrap.control_failure(
            _error(), json_output=json_output, stderr_writer=err.append, stdout_writer=out.append
        )
        assert code == 20
        text = "\n".join(err)
        assert text.splitlines()[0] == f"{_PHASE}: {refusal_summary(_PHASE)}"
        assert directive.directive in text
        _clean(text, home, record)
        if json_output:
            (payload,) = out
            body = cast(dict[str, JsonValue], payload)
            assert (body["reason"], body["phase"], body["retryable"]) == (
                "service_unavailable",
                _PHASE,
                True,
            )
            assert cast(dict[str, JsonValue], body["recovery"])["continuation"] == token
            _clean(json.dumps(body), home, record)
    # MCP.
    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        _error(), _REQUEST, "start"
    )
    structured = cast(dict[str, object], result.structuredContent)
    error = cast(dict[str, object], structured["error"])
    assert error["safe_details"] == {
        "continuation": token,
        "phase": _PHASE,
        "reason_code": "service_unavailable",
    }
    _clean(json.dumps(structured), home, record)
    # Hooks: the attach text and the mapped text.
    attach = observe_hooks._attachment_recovery_context(_PHASE)  # pyright: ignore[reportPrivateUsage]
    mapped = hooks.unavailable_context(_PHASE)
    for text in (attach, mapped):
        assert f"({_PHASE})" in text
        assert f"Continuation: {token}." in text
        # From layer 4 the server itself refuses a hello naming a revision it no longer issues:
        # the hello was sent, so no surface says nothing was (Codex review).
        assert "before anything was sent" not in text
        assert "before that server did any work for it" in text
        _clean(text, home, record)
    # The terminal interface and the menu.
    failure = _connect_failure(_error())
    assert (failure.reason, failure.details) == (_PHASE, (directive.directive,))
    guidance = menu._control_guidance(_error())  # pyright: ignore[reportPrivateUsage]
    assert _PHASE in guidance and directive.directive in guidance
    assert "before anything was sent" not in guidance
    _clean(" ".join((failure.message, *failure.details, guidance)), home, record)
    summary = asyncio.run(_menu_summary_refused())
    assert f"({_PHASE})" in summary and directive.directive in summary
    assert "before anything was sent" not in summary
    _clean(summary, home, record)


async def _menu_summary_refused() -> str:
    """The menu's service line when the selected server refuses with ``_PHASE``."""

    import finishup.cli.app as app

    async def refused() -> object:
        raise _error()

    original = app.build_service_client
    app.build_service_client = refused  # type: ignore[assignment]
    try:
        return await menu._service_summary()  # pyright: ignore[reportPrivateUsage]
    finally:
        app.build_service_client = original


def test_a_refusal_while_the_consent_still_admits_the_profile_continues_as_checking(
    selected: tuple[Path, targets.ServerTarget],
) -> None:
    home, record = selected
    _consented(record)
    assert targets.remote_root_continuation(_PHASE) == _CHECKING
    _surfaces(home, record, _CHECKING)


@pytest.mark.parametrize("state", sorted(_KNOWN))
def test_a_consent_known_to_need_the_owner_keeps_remote_reconsent(
    selected: tuple[Path, targets.ServerTarget], state: str
) -> None:
    home, record = selected
    _KNOWN[state](record)
    assert targets.remote_root_continuation(_PHASE) == _RECONSENT
    _surfaces(home, record, _RECONSENT)


def test_a_narrowing_this_computer_adjusted_to_still_continues_as_checking(
    selected: tuple[Path, targets.ServerTarget],
) -> None:
    # After a refresh recorded a narrower profile and adjusted the consent down to it, a later
    # refusal again names a revision this computer has not fetched: the owner is not asked.
    _home, record = selected
    consented = consent_to(record, profile_document(review=ReviewEgress("server_policy", "openai")))
    refreshed(consented, profile_document(revision=2))
    adjusted = targets.read_target(targets.target_root(record.target_id))
    assert adjusted is not None and adjusted.consent is not None
    assert adjusted.consent.adjusted_at is not None
    assert targets.remote_root_continuation(_PHASE) == _CHECKING


def test_a_named_target_resolves_by_its_own_consent(
    selected: tuple[Path, targets.ServerTarget],
) -> None:
    # A command naming a target (server connect NAME, server status NAME) resolves by that record,
    # not by the selection.
    _home, record = selected
    resolve = targets.profile_change_continuation
    assert resolve(None) == _RECONSENT
    assert resolve(record) == _RECONSENT
    consented = _consented(record)
    assert resolve(consented) == _CHECKING
    targets.clear_selection()
    reset_selection_memo()
    assert resolve(consented) == _CHECKING


def test_the_unselected_or_unreadable_root_keeps_remote_reconsent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with ambient_home(monkeypatch):
        reset_selection_memo()
        assert targets.remote_root_continuation(_PHASE) == _RECONSENT

        def unreadable() -> None:
            raise targets.TargetRecordUnreadable("target_record_invalid", None)

        monkeypatch.setattr(targets, "active_target_record", unreadable)
        assert targets.remote_root_continuation(_PHASE) == _RECONSENT


def test_the_token_is_registered_attached_by_the_client_and_never_asks_the_owner() -> None:
    assert _CHECKING in CONTINUATION_TOKENS
    assert targets.PROFILE_CHECKING_CONTINUATION == _CHECKING
    # Attached by the client that knows the target's state, never through a reason code.
    assert _CHECKING not in set(REASON_CODE_CONTINUATIONS.values())
    assert REASON_CODE_CONTINUATIONS[_PHASE] == _RECONSENT
    entry = directive_for(_CHECKING)
    assert entry is not None and entry.nudge is not None
    assert "before that server did any work for it" in entry.directive
    assert "repeat the same request" in entry.directive
    assert "Only the owner" not in entry.directive and "nothing" not in entry.directive
    assert "remote_reconsent" in entry.nudge and "Never agree for them" in entry.nudge
    assert len(entry.directive.encode()) <= 232 and len(entry.nudge.encode()) <= 128
