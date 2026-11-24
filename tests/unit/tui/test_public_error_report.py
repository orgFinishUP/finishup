"""A public service error reaches the terminal interface's blocked report whole (ADR-030).

The command line renders the same failure through ``render_human_error``: the wire code, the
retryable marker, and the registry directive its safe details name. The terminal interface must
show that identity and that directive too, not the code's Python spelling and nothing to do next.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from finishup.cli.render import render_human_error
from finishup.mcp.errors import build_public_error_result
from finishup.protocol.errors import PublicErrorCode
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import OperationFailureModel, ReceiptResultModel
from finishup.protocol.recovery import directive_for
from finishup.tui.app import FinishUpTui
from finishup.tui.runtime import FinishUpRuntime, RuntimeError_, _WorkSession
from finishup.tui.symbols import Level

pytestmark = pytest.mark.anyio

_CORRELATION = new_id(IdKind.CORRELATION)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _refused_receipt() -> ReceiptResultModel:
    return ReceiptResultModel.model_validate(
        build_public_error_result(
            PublicErrorCode.FRONTIER_CONFLICT,
            "The receipt frontier is not current.",
            True,
            _CORRELATION,
            safe_details={
                "reason_code": "frontier_changed",
                "continuation": "frontier_refresh_required",
            },
        )
    )


async def _receipt_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> RuntimeError_:
    class _Client:
        async def receipt(self, request: Any) -> ReceiptResultModel:
            del request
            return _refused_receipt()

    @asynccontextmanager
    async def connect(_runtime: Any) -> AsyncGenerator[_Client]:
        yield _Client()

    monkeypatch.setattr(FinishUpRuntime, "_client", connect)
    runtime = FinishUpRuntime(cwd=tmp_path)
    runtime._sessions["t"] = _WorkSession(
        "tsk_00000000-0000-4000-8000-0000000000e1",
        "ses_00000000-0000-4000-8000-0000000000e2",
        "wri_00000000-0000-4000-8000-0000000000e4",
        SimpleNamespace(sequence="3", head_digest="sha256:" + "1" * 64),
    )
    with pytest.raises(RuntimeError_) as raised:
        await runtime.build_receipt("t", "markdown")
    return raised.value


def _report(
    error: RuntimeError_, monkeypatch: pytest.MonkeyPatch
) -> tuple[object, str, tuple[str, ...], tuple[str, ...]]:
    app = FinishUpTui(SimpleNamespace())  # pyright: ignore[reportArgumentType]
    said: list[tuple[object, str, tuple[str, ...], tuple[str, ...]]] = []

    def say(level: object, title: str, body: Any = (), *, details: Any = ()) -> None:
        said.append((level, title, tuple(body), tuple(details)))

    monkeypatch.setattr(app, "say", say)
    app._report(error)
    (event,) = said
    return event


async def test_a_refused_receipt_keeps_the_wire_code_and_the_cli_directive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    error = await _receipt_failure(tmp_path, monkeypatch)
    assert error.reason == "FRONTIER_CONFLICT"

    level, title, body, details = _report(error, monkeypatch)
    assert level is Level.BLOCKED
    assert title == "The receipt frontier is not current."
    shown = "\n".join((title, *body, *details))
    assert "PublicErrorCode" not in shown
    assert body[0] == "Reason: FRONTIER_CONFLICT (retryable)"

    directive = directive_for("frontier_refresh_required")
    assert directive is not None
    failure = _refused_receipt().root
    assert isinstance(failure, OperationFailureModel)
    cli = render_human_error(failure.error)
    # The same directive lines the command line prints, from the same resolver.
    assert list(body[1:]) == cli.splitlines()[1:]
    assert f"Next: {directive.directive}" in body
    assert details == (
        "reason=FRONTIER_CONFLICT",
        "retryable=yes",
        f"correlation_id={_CORRELATION}",
    )


async def test_a_local_reason_still_resolves_its_own_directive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _level, _title, body, details = _report(
        RuntimeError_("task_not_open", "open the task first"), monkeypatch
    )
    assert body[0] == "Reason: task_not_open"
    assert details == ("reason=task_not_open",)
