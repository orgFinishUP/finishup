"""Secure entry hands the terminal back to the interface however the ceremony ends (#1326).

``hand_over_terminal`` runs a ceremony inside Textual's ``App.suspend``, which resumes the
interface only when its block exits normally. A ceremony cancelled by Ctrl-C at its prompt, or
refused, used to leave the terminal suspended: nothing redrawn, keys echoed and ignored, and the
cancellation never reported. These tests use the real ``App.suspend`` on a headless driver that
records the mode changes instead of touching a terminal.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

import pytest
from textual.drivers.headless_driver import HeadlessDriver

from builders.tui_runtime import FakeRuntime
from finishup.tui.app import FinishUpTui
from finishup.tui.runtime import RuntimeError_

pytestmark = pytest.mark.anyio

WIDE = (100, 34)
MakeApp = Callable[..., FinishUpTui]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _record_terminal_modes(app: FinishUpTui, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Let the headless driver suspend, and record each mode change in order."""

    driver = app._driver  # pyright: ignore[reportPrivateUsage]
    assert isinstance(driver, HeadlessDriver)
    modes: list[str] = []
    monkeypatch.setattr(HeadlessDriver, "can_suspend", property(lambda _driver: True))
    monkeypatch.setattr(driver, "suspend_application_mode", lambda: modes.append("suspended"))
    monkeypatch.setattr(driver, "resume_application_mode", lambda: modes.append("resumed"))
    return modes


async def test_a_ceremony_cancelled_at_its_prompt_resumes_the_interface_before_reporting(
    make_app: MakeApp, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = FakeRuntime()

    async def cancelled_at_the_prompt() -> None:
        raise RuntimeError_("cancelled", "the vault could not be unlocked")

    async def approve(_view: object) -> str:
        return "approve"

    app = make_app(runtime=runtime, suspendable=False)
    monkeypatch.setattr(app, "ask", approve)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        modes = _record_terminal_modes(app, monkeypatch)
        reported: list[tuple[str, tuple[str, ...]]] = []

        def say(_level: object, title: str, body: tuple[str, ...] = (), **_kwargs: object) -> None:
            modes.append("reported")
            reported.append((title, tuple(body)))

        monkeypatch.setattr(app, "say", say)
        result = await app._run_confidential(  # pyright: ignore[reportPrivateUsage]
            "Unlock FinishUP", cancelled_at_the_prompt
        )

    assert result is None
    assert modes == ["suspended", "resumed", "reported"]
    assert reported == [("the vault could not be unlocked", ("Reason: cancelled",))]


async def test_a_completed_ceremony_resumes_the_interface_and_returns_its_result(
    make_app: MakeApp, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def completed() -> str:
        return "stored"

    app = make_app(suspendable=False)
    async with app.run_test(size=WIDE):
        modes = _record_terminal_modes(app, monkeypatch)
        result = await app.hand_over_terminal(completed)

    assert result == "stored"
    assert modes == ["suspended", "resumed"]


async def test_an_unexpected_ceremony_failure_still_resumes_the_interface(
    make_app: MakeApp, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def failed() -> None:
        raise OSError("console unavailable")

    app = make_app(suspendable=False)
    async with app.run_test(size=WIDE):
        modes = _record_terminal_modes(app, monkeypatch)
        with pytest.raises(OSError, match="console unavailable"):
            await app.hand_over_terminal(failed)

    assert modes == ["suspended", "resumed"]


async def test_a_ceremony_whose_task_is_cancelled_resumes_the_interface_then_stays_cancelled(
    make_app: MakeApp, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A worker cancelled during the hand-over (a dismissed screen, a newer exclusive worker)
    must not leave the interface suspended; the cancellation still reaches the caller."""

    async def cancelled() -> None:
        raise asyncio.CancelledError

    app = make_app(suspendable=False)
    async with app.run_test(size=WIDE):
        modes = _record_terminal_modes(app, monkeypatch)
        with pytest.raises(asyncio.CancelledError):
            await app.hand_over_terminal(cancelled)

    assert modes == ["suspended", "resumed"]
