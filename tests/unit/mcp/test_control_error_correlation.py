"""Agent-facing correlation ids on ControlError must resolve to the service diagnostic sink.

Plan 05 (run-4 residual): the id written to the durable diagnostic ring and the id handed to the
caller must be the same string for any single failure. The bridge reuses a service-supplied id;
only bridge-local faults mint a fresh one.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

import finishup.mcp.server as bridge
from finishup.config.models import LoggingConfig
from finishup.observability.diagnostics import append_diagnostic_record, lookup_diagnostic_records
from finishup.observability.logging import LogMode, configure_logging
from finishup.ports.control import ControlError
from finishup.protocol.errors import PublicErrorCode
from finishup.service.client import (
    _AcceptedServiceUnresponsive,  # pyright: ignore[reportPrivateUsage]
)

_CORRELATION = "err_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
_REQUEST = "req_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
_ABSENT_SERVICE_MESSAGE = (
    "The local FinishUP service is not running. On a local terminal run "
    "'finishup service run' under your selected user supervisor, then retry this "
    "operation with the same request_id."
)
_LEAK_TOKENS = (
    "Traceback",
    "/tmp/",
    ".sock",
    "Application Support",
    "must-not-reach-public-output",
    "YZH1-",
    "Bearer ",
)


@pytest.fixture
def diagnostic_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    return tmp_path


def _error_of(result: object) -> dict[str, object]:
    structured = cast(dict[str, object], getattr(result, "structuredContent"))
    assert structured["request_id"] == _REQUEST
    return cast(dict[str, object], structured["error"])


def _assert_no_leakage(*blobs: object) -> None:
    rendered = json.dumps(blobs, default=str)
    for token in _LEAK_TOKENS:
        assert token not in rendered


def test_bridge_reuses_service_correlation_for_response_projection_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A check-shaped write failure must surface the daemon's id, not a second mint."""

    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    append_diagnostic_record(
        correlation_id=_CORRELATION,
        component="service.daemon",
        operation="check_response_projection_failed",
        reason="exception_validation_error",
        request_id=_REQUEST,
        root=tmp_path,
    )

    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError(
            "response_projection_failed",
            retryable=True,
            correlation_id=_CORRELATION,
        ),
        request_id=_REQUEST,
        operation="check",
    )

    assert result.isError is True
    structured = cast(dict[str, object], result.structuredContent)
    error = cast(dict[str, object], structured["error"])
    assert error["code"] == PublicErrorCode.INTERNAL_ERROR.value
    assert error["retryable"] is True
    assert error["correlation_id"] == _CORRELATION
    found = lookup_diagnostic_records(_CORRELATION, root=tmp_path)
    assert len(found) == 1
    assert found[0]["operation"] == "check_response_projection_failed"
    # Sink stays structural — no exception text / payload / path.
    for record in found:
        for forbidden in ("traceback", "exception", "payload", "path", "message"):
            assert forbidden not in record


def test_bridge_reuses_service_correlation_for_read_projection_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A status read failure must surface the daemon's id so diagnostics resolve."""

    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    append_diagnostic_record(
        correlation_id=_CORRELATION,
        component="service.daemon",
        operation="status_read_projection_failed",
        reason="exception_runtime_error",
        request_id=_REQUEST,
        root=tmp_path,
    )

    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError("read_projection_failed", retryable=True, correlation_id=_CORRELATION),
        request_id=_REQUEST,
        operation="status",
    )

    assert result.isError is True
    structured = cast(dict[str, object], result.structuredContent)
    error = cast(dict[str, object], structured["error"])
    assert error["correlation_id"] == _CORRELATION
    found = lookup_diagnostic_records(cast(str, error["correlation_id"]), root=tmp_path)
    assert len(found) == 1
    assert found[0]["operation"] == "status_read_projection_failed"


def test_bridge_level_failure_without_service_id_still_resolves(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Bridge-originated ControlError without a service id mints and records under its own id."""

    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    configure_logging(LoggingConfig(level="error"), LogMode.MCP_STDIO)  # type: ignore[arg-type]

    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError("internal_error"),
        request_id=_REQUEST,
        operation="check",
    )

    assert result.isError is True
    structured = cast(dict[str, object], result.structuredContent)
    error = cast(dict[str, object], structured["error"])
    correlation_id = cast(str, error["correlation_id"])
    assert correlation_id.startswith("err_")
    found = lookup_diagnostic_records(correlation_id, root=tmp_path)
    assert len(found) == 1
    assert found[0]["component"] == "mcp.bridge"
    assert found[0]["operation"] == "check_public_error"
    assert found[0]["reason"] == "internal_error"
    # Typed ControlError now records as a public error, which is a warning. Error-level
    # MCP_STDIO logging therefore has no stderr line; the durable ring is the join key.
    err = capsys.readouterr().err
    assert "traceback" not in err.lower()


def test_bridge_does_not_re_record_when_service_id_is_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reusing a service id must not mint a second diagnostic record under a different id."""

    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    append_diagnostic_record(
        correlation_id=_CORRELATION,
        component="service.daemon",
        operation="check_internal_error",
        reason="exception_runtime_error",
        request_id=_REQUEST,
        root=tmp_path,
    )
    recorded: list[str] = []

    def track(
        exc: BaseException,
        *,
        component: str = "process_boundary",
        operation: str = "unexpected_exception",
        request_id: str | None = None,
    ) -> str:
        del exc, component, operation, request_id
        recorded.append("minted")
        return "err_cccccccc-cccc-4ccc-8ccc-cccccccccccc"

    monkeypatch.setattr(bridge, "record_unexpected_exception_without_raising", track)

    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError("internal_error", correlation_id=_CORRELATION),
        request_id=_REQUEST,
        operation="check",
    )

    structured = cast(dict[str, object], result.structuredContent)
    error = cast(dict[str, object], structured["error"])
    assert error["correlation_id"] == _CORRELATION
    assert recorded == []
    assert len(lookup_diagnostic_records(_CORRELATION, root=tmp_path)) == 1
    assert (
        lookup_diagnostic_records("err_cccccccc-cccc-4ccc-8ccc-cccccccccccc", root=tmp_path) == ()
    )


def test_vault_locked_message_and_retryable_follow_the_daemon_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A retryable soft/transient lock must not be described as a terminal hard lock (#276).

    The daemon distinguishes a soft lock (heals on the next attempt) from a hard lock or
    missing setup (needs a ceremony) via ``retryable``. Discarding that flag once told an
    agent to abandon evidence and receipts a single retry would have recorded.
    """

    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)

    transient = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError("vault_locked", retryable=True),
        request_id=_REQUEST,
        operation="publish_work",
    )
    structured = cast(dict[str, object], transient.structuredContent)
    error = cast(dict[str, object], structured["error"])
    assert error["code"] == PublicErrorCode.VAULT_LOCKED.value
    assert error["retryable"] is True
    message = cast(str, error["message"])
    assert "Retry this operation" in message
    assert "hard lock or missing setup" not in message

    terminal = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError("vault_locked", retryable=False),
        request_id=_REQUEST,
        operation="publish_work",
    )
    structured = cast(dict[str, object], terminal.structuredContent)
    error = cast(dict[str, object], structured["error"])
    assert error["code"] == PublicErrorCode.VAULT_LOCKED.value
    assert error["retryable"] is False
    message = cast(str, error["message"])
    assert "hard lock or missing setup" in message
    assert "Retry this operation" not in message


def test_incompatible_service_is_a_bounded_service_unavailable_with_the_repair_command() -> None:
    """The 2026-08-27 dogfood saw an opaque INTERNAL_ERROR here; agents need the repair."""

    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError("service_incompatible", retryable=True, correlation_id=_CORRELATION),
        request_id=_REQUEST,
        operation="start",
    )
    assert result.isError is True
    structured = cast(dict[str, object], result.structuredContent)
    error = cast(dict[str, object], structured["error"])
    assert error["code"] == PublicErrorCode.SERVICE_UNAVAILABLE.value
    assert error["retryable"] is True
    assert error["correlation_id"] == _CORRELATION
    assert cast(dict[str, object], error["safe_details"])["reason_code"] == "service_incompatible"
    assert "finishup service restart" in str(error["message"])


def test_bridge_from_before_an_update_asks_to_reopen_instead_of_restarting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A newer service already serves new sessions; this older bridge must not replace it (#820)."""

    from finishup.service.lifecycle import SingletonHolder

    monkeypatch.setattr(
        bridge,
        "service_holder_identity",
        lambda: SingletonHolder(
            pid=4242,
            instance_id="svc_test",
            schema_manifest_digest="sha256:" + "b" * 64,
            service_version="99.0.0",
        ),
    )
    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError("service_incompatible", retryable=True, correlation_id=_CORRELATION),
        request_id=_REQUEST,
        operation="start",
    )
    error = _error_of(result)
    assert error["code"] == PublicErrorCode.SERVICE_UNAVAILABLE.value
    assert error["retryable"] is True
    message = cast(str, error["message"])
    assert "reopen this session" in message
    assert "finishup service restart" not in message
    assert cast(dict[str, object], error["safe_details"])["reason_code"] == "service_incompatible"


def test_bridge_from_before_an_update_of_a_remote_helper_asks_to_reopen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A server elsewhere: a newer build of this release now runs its helper (same version, so
    the version cannot tell): this older bridge asks to reopen, never ``service restart``."""

    monkeypatch.setattr(bridge, "service_holder_identity", lambda: None)
    monkeypatch.setattr(bridge, "newer_helper_build_holds_selection", lambda: True)
    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError("service_incompatible", retryable=True, correlation_id=_CORRELATION),
        request_id=_REQUEST,
        operation="status",
    )
    message = cast(str, _error_of(result)["message"])
    assert "reopen this session" in message
    assert "finishup service restart" not in message


def test_absent_service_maps_to_supervisor_copy_and_control_class_reason(
    diagnostic_root: Path,
) -> None:
    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError("service_unavailable", retryable=True),
        request_id=_REQUEST,
        operation="start",
    )
    error = _error_of(result)
    assert error["code"] == PublicErrorCode.SERVICE_UNAVAILABLE.value
    assert error["retryable"] is True
    assert error["message"] == _ABSENT_SERVICE_MESSAGE
    assert cast(dict[str, object], error["safe_details"])["reason_code"] == "service_unavailable"
    correlation_id = cast(str, error["correlation_id"])
    found = lookup_diagnostic_records(correlation_id, root=diagnostic_root)
    assert len(found) == 1
    assert found[0]["reason"] == "service_unavailable"
    assert found[0]["reason"] != "exception_control_error"
    assert found[0]["operation"] == "start_public_error"
    _assert_no_leakage(error, found)


def test_accepted_but_unresponsive_is_distinct_from_absent_service(
    diagnostic_root: Path,
) -> None:
    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        _AcceptedServiceUnresponsive(),  # pyright: ignore[reportPrivateUsage]
        request_id=_REQUEST,
        operation="start",
    )
    error = _error_of(result)
    assert error["code"] == PublicErrorCode.SERVICE_UNAVAILABLE.value
    assert error["retryable"] is True
    message = cast(str, error["message"])
    assert message != _ABSENT_SERVICE_MESSAGE
    assert "under your selected user supervisor" not in message
    assert "Do not run `finishup service run`" in message
    assert (
        cast(dict[str, object], error["safe_details"])["reason_code"] == "accepted_but_unresponsive"
    )
    found = lookup_diagnostic_records(cast(str, error["correlation_id"]), root=diagnostic_root)
    assert len(found) == 1
    assert found[0]["reason"] == "accepted_but_unresponsive"
    _assert_no_leakage(error, found)


def test_protocol_mismatch_uses_restart_copy_and_ships_non_retryable(
    diagnostic_root: Path,
) -> None:
    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError("protocol_mismatch", correlation_id=_CORRELATION),
        request_id=_REQUEST,
        operation="start",
    )
    error = _error_of(result)
    assert error["code"] == PublicErrorCode.SERVICE_UNAVAILABLE.value
    assert error["retryable"] is False
    assert error["correlation_id"] == _CORRELATION
    assert cast(dict[str, object], error["safe_details"])["reason_code"] == "protocol_mismatch"
    assert "finishup service restart" in str(error["message"])
    assert lookup_diagnostic_records(_CORRELATION, root=diagnostic_root) == ()
    _assert_no_leakage(error)


def test_endpoint_unsafe_is_non_retryable_service_unavailable_without_a_socket_path(
    diagnostic_root: Path,
) -> None:
    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError("endpoint_unsafe"),
        request_id=_REQUEST,
        operation="start",
    )
    error = _error_of(result)
    assert error["code"] == PublicErrorCode.SERVICE_UNAVAILABLE.value
    assert error["retryable"] is False
    assert "unsafe to use" in str(error["message"])
    assert "same request_id" in str(error["message"])
    assert cast(dict[str, object], error["safe_details"])["reason_code"] == "endpoint_unsafe"
    found = lookup_diagnostic_records(cast(str, error["correlation_id"]), root=diagnostic_root)
    assert len(found) == 1
    assert found[0]["reason"] == "endpoint_unsafe"
    _assert_no_leakage(error, found)


def test_control_public_error_result_reuses_service_correlation_id(
    diagnostic_root: Path,
) -> None:
    append_diagnostic_record(
        correlation_id=_CORRELATION,
        component="service.daemon",
        operation="start_peer_untrusted",
        reason="peer_untrusted",
        request_id=_REQUEST,
        root=diagnostic_root,
    )
    result = bridge._control_public_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError("peer_untrusted", correlation_id=_CORRELATION),
        _REQUEST,
        "start",
        code=PublicErrorCode.SERVICE_UNAVAILABLE,
        message="The local control endpoint identity could not be trusted.",
        retryable=False,
        host_profile="generic",
        safe_details={"reason_code": "peer_untrusted"},
    )
    error = _error_of(result)
    assert error["correlation_id"] == _CORRELATION
    found = lookup_diagnostic_records(_CORRELATION, root=diagnostic_root)
    assert len(found) == 1
    assert found[0]["reason"] == "peer_untrusted"
    _assert_no_leakage(error, found)


def test_peer_untrusted_requires_local_repair_then_same_request_replay(
    diagnostic_root: Path,
) -> None:
    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError("peer_untrusted"),
        request_id=_REQUEST,
        operation="start",
    )

    error = _error_of(result)
    assert error["code"] == PublicErrorCode.SERVICE_UNAVAILABLE.value
    assert error["retryable"] is False
    assert "could not be trusted" in str(error["message"])
    assert "same request_id" in str(error["message"])
    assert cast(dict[str, object], error["safe_details"])["reason_code"] == "peer_untrusted"
    found = lookup_diagnostic_records(cast(str, error["correlation_id"]), root=diagnostic_root)
    assert len(found) == 1
    assert found[0]["reason"] == "peer_untrusted"
    _assert_no_leakage(error, found)


@pytest.mark.parametrize(
    ("reason", "retryable"),
    (
        ("vault_locked", True),
        ("vault_locked", False),
        ("request_cancelled", False),
        ("privacy_projection_blocked", False),
        ("response_projection_failed", True),
        ("read_projection_failed", True),
        ("privacy_projection_unavailable", True),
        ("request_timeout", True),
        ("service_incompatible", True),
        ("protocol_mismatch", False),
        ("service_draining", False),
        ("service_unavailable", True),
        ("service_generation_changed", True),
        ("peer_untrusted", False),
        ("endpoint_unsafe", False),
        ("frame_invalid", False),
        ("invalid_request", False),
        ("frame_too_large", False),
        ("method_forbidden", False),
        ("internal_error", False),
    ),
)
def test_every_mapped_control_reason_reuses_a_service_correlation_id(
    reason: str, retryable: bool, diagnostic_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    minted: list[str] = []

    def forbid_public_mint(**kwargs: object) -> str:
        del kwargs
        minted.append("public")
        return "err_ffffffff-ffff-4fff-8fff-ffffffffffff"

    def forbid_unexpected_mint(*args: object, **kwargs: object) -> str:
        del args, kwargs
        minted.append("unexpected")
        return "err_ffffffff-ffff-4fff-8fff-ffffffffffff"

    monkeypatch.setattr(bridge, "record_public_error_without_raising", forbid_public_mint)
    monkeypatch.setattr(
        bridge, "record_unexpected_exception_without_raising", forbid_unexpected_mint
    )
    append_diagnostic_record(
        correlation_id=_CORRELATION,
        component="service.daemon",
        operation=f"start_{reason}",
        reason=reason,
        request_id=_REQUEST,
        root=diagnostic_root,
    )

    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError(reason, retryable=retryable, correlation_id=_CORRELATION),
        request_id=_REQUEST,
        operation="start",
    )
    error = _error_of(result)
    assert error["correlation_id"] == _CORRELATION
    assert minted == []
    found = lookup_diagnostic_records(_CORRELATION, root=diagnostic_root)
    assert len(found) == 1
    _assert_no_leakage(error, found)


def test_start_timeout_names_a_slow_start_not_a_supervisor_or_lifecycle_command(
    diagnostic_root: Path,
) -> None:
    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError("service_unavailable", retryable=True, phase="handshake_timeout"),
        request_id=_REQUEST,
        operation="start",
    )
    error = _error_of(result)
    assert error["code"] == PublicErrorCode.SERVICE_UNAVAILABLE.value
    assert error["retryable"] is True
    message = cast(str, error["message"])
    assert "service_handshake_timeout" in message
    assert "under your selected user supervisor" not in message
    assert "same request_id" in message
    assert "no reusable hash-verified bytecode" in message
    details = cast(dict[str, object], error["safe_details"])
    assert details == {"reason_code": "service_unavailable", "phase": "handshake_timeout"}
    found = lookup_diagnostic_records(cast(str, error["correlation_id"]), root=diagnostic_root)
    assert len(found) == 1
    _assert_no_leakage(error, found)


@pytest.mark.parametrize(
    "phase",
    ["target_root_is_remote", "zero_network_remote_selected", "target_reauthorization_required"],
)
def test_a_refused_remote_root_names_its_continuation_never_a_local_service(phase: str) -> None:
    """MCP names a remote root's refusal and its continuation, never 'finishup service run'.

    The phase is kept where an agent reads it: in the final structured details (the normalizer
    admits exactly the three remote-root phases) and in the native text, which never carries the
    free-form message.
    """

    from finishup.protocol.recovery import continuation_for_reason, directive_for

    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError("service_unavailable", retryable=True, phase=phase),
        request_id=_REQUEST,
        operation="start",
    )
    continuation = continuation_for_reason(phase)
    assert continuation is not None
    error = _error_of(result)
    assert error["code"] == "SERVICE_UNAVAILABLE"
    assert error["retryable"] is True
    assert error["safe_details"] == {
        "continuation": continuation,
        "phase": phase,
        "reason_code": "service_unavailable",
    }
    text = cast(str, getattr(result.content[0], "text"))
    assert f" Reason: service_unavailable (phase: {phase})." in text
    directive = directive_for(continuation)
    assert directive is not None
    assert f"Continuation: {continuation}. {directive.directive}" in text
    assert "service run" not in json.dumps(result.structuredContent) + text


@pytest.mark.parametrize("phase", ["target_root_is_remote", "target_reauthorization_required"])
def test_a_bridge_whose_root_an_isolation_variable_names_points_to_that_override(
    phase: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """'finishup server use local' cannot change a root an isolation variable names (it answers
    selection_overridden), so the bridge names the override's way back instead."""

    from finishup.config.paths import ISOLATED_ROOT_ENV_NAMES
    from finishup.protocol.recovery import directive_for

    monkeypatch.setenv(ISOLATED_ROOT_ENV_NAMES[0], str(tmp_path))
    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError("service_unavailable", retryable=True, phase=phase),
        request_id=_REQUEST,
        operation="start",
    )
    error = _error_of(result)
    assert error["safe_details"] == {
        "continuation": "remote_root_override_clear",
        "phase": phase,
        "reason_code": "service_unavailable",
    }
    directive = directive_for("remote_root_override_clear")
    assert directive is not None
    text = cast(str, getattr(result.content[0], "text"))
    assert f" Reason: service_unavailable (phase: {phase})." in text
    assert f"Continuation: remote_root_override_clear. {directive.directive}" in text
    assert "Ask the owner to run 'finishup server use local'" not in text


def test_every_remote_connection_phase_is_admitted_and_nothing_else() -> None:
    """Every remote connection phase is admitted as a detail (ADR-052): the gate's refusals (the
    three remote-root refusals, the repository hold and the owner's kept choice, a changed
    authorization, a changed profile or level) and, since SSH servers open (layer 4), the five
    transport outages, each with its own repair. Any other remote-looking token stays out."""

    from finishup.protocol.errors import (
        AUTHORIZATION_REFUSAL_PHASES,
        REMOTE_CONNECTION_PHASES,
        REMOTE_ROOT_REFUSAL_PHASES,
        normalize_safe_details,
    )

    assert REMOTE_ROOT_REFUSAL_PHASES == frozenset(
        {"target_reauthorization_required", "target_root_is_remote", "zero_network_remote_selected"}
    )
    assert AUTHORIZATION_REFUSAL_PHASES == REMOTE_ROOT_REFUSAL_PHASES | {
        "repository_egress_held",
        "repository_egress_kept",
        "server_authorization_changed",
        "server_profile_changed",
        "server_level_unavailable",
    }
    assert REMOTE_CONNECTION_PHASES - AUTHORIZATION_REFUSAL_PHASES == {
        "remote_auth_failed",
        "remote_identity_changed",
        "remote_incompatible",
        "remote_service_not_running",
        "remote_unreachable",
    }
    for phase in REMOTE_CONNECTION_PHASES:
        assert normalize_safe_details({"phase": phase}).get("phase") == phase
    for other in ("remote_host_key_unconfirmed", "remote_kind_unavailable", "lab.example"):
        assert normalize_safe_details({"phase": other}).get("phase") is None
