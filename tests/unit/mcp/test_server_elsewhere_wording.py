"""What the bridge says about a failure a server elsewhere can return never calls it local (ADR-051).

Since layer 4 the bridge's root may be a FinishUP server on another machine, reached over SSH.
Every failure that server's service reports (a projection, a drained or restarted service, a
locked vault), and every outcome the bridge itself reports for a call to it (a timeout, a failed
call, an unreachable recovery lookup), reaches the agent through the texts below, so they name the
FinishUP service, which is true wherever it runs. The texts only this computer's own service can
cause (its on-demand start, its singleton) are out of scope here and keep their wording.
"""

from __future__ import annotations

import re
from typing import Any, cast

import pytest

import finishup.mcp.server as bridge
from finishup.ports.control import ControlError

_REQUEST = "req_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
_LOCAL = re.compile(r"\blocal (?:FinishUP )?service\b|\bThe local (?:start|operation|read)\b")


def _message(result: object) -> str:
    structured = cast(dict[str, Any], getattr(result, "structuredContent"))
    return cast(str, structured["error"]["message"])


@pytest.mark.parametrize(
    ("reason", "retryable", "operation", "expected"),
    [
        ("response_projection_failed", True, "publish_work", "completed on the FinishUP service"),
        ("read_projection_failed", True, "status", "The read completed on the FinishUP service"),
        ("privacy_projection_unavailable", True, "receipt", "after the FinishUP service is ready"),
        ("service_draining", True, "status", "The FinishUP service is draining"),
        ("service_generation_changed", True, "status", "The FinishUP service instance changed"),
        ("vault_locked", True, "start", "The FinishUP service vault is soft-locked"),
        ("vault_locked", False, "start", "The FinishUP service vault is locked or uninitialized"),
        ("request_timeout", True, "start", "The start timed out and may still have committed"),
        ("request_timeout", True, "publish_work", "The operation timed out and may still have"),
        ("request_timeout", True, "status", "The read timed out and requested no write"),
    ],
)
def test_a_failure_a_server_elsewhere_can_return_names_the_finishup_service(
    reason: str, retryable: bool, operation: str, expected: str
) -> None:
    message = _message(
        bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
            ControlError(reason, retryable=retryable), _REQUEST, operation
        )
    )
    assert expected in message
    assert _LOCAL.search(message) is None, message


@pytest.mark.parametrize("include_authorize", [True, False])
def test_an_uninitialized_vault_names_the_finishup_service(include_authorize: bool) -> None:
    message = bridge._vault_initialization_required_message(  # pyright: ignore[reportPrivateUsage]
        include_authorize
    )
    assert message.startswith("The FinishUP service vault is uninitialized:")
    assert _LOCAL.search(message) is None, message


def test_a_failed_call_to_the_service_names_the_finishup_service() -> None:
    message = _message(
        bridge._internal_stage_error(  # pyright: ignore[reportPrivateUsage]
            "bridge_invoke_failed",
            request_id=_REQUEST,
            correlation_id=None,
            host_profile="generic",
            operation="publish_work",
        )
    )
    assert "The bridge failed while calling the FinishUP service." in message
    assert _LOCAL.search(message) is None, message


def test_an_unreachable_recovery_lookup_names_the_finishup_service() -> None:
    message = _message(
        bridge._publish_validation_recovery_unavailable_result(  # pyright: ignore[reportPrivateUsage]
            _REQUEST
        )
    )
    assert "could not be checked; the FinishUP service was unreachable." in message
    assert _LOCAL.search(message) is None, message
