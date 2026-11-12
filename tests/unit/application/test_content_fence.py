"""The fence between a task's content publishers and the forget of its copy content (ADR-054)."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from types import SimpleNamespace
from typing import Any, cast

import pytest

from finishup.application import content_fence
from finishup.application.content_fence import content_forgotten_after, content_publication_fence


def test_publishers_and_the_forget_of_one_task_exclude_each_other_and_leave_nothing() -> None:
    async def scenario() -> list[str]:
        order: list[str] = []
        inside = asyncio.Event()
        release = asyncio.Event()

        async def forget() -> None:
            async with content_publication_fence("tsk_a"):
                order.append("forget in")
                inside.set()
                await release.wait()
                order.append("forget out")

        async def publish(task: str, name: str) -> None:
            async with content_publication_fence(task):
                order.append(name)

        held = asyncio.create_task(forget())
        await inside.wait()
        same = asyncio.create_task(publish("tsk_a", "same task"))
        other = asyncio.create_task(publish("tsk_b", "other task"))
        await other  # another task's publisher is never held up
        assert not same.done()
        release.set()
        await asyncio.gather(held, same)
        assert content_fence._FENCES.get(asyncio.get_running_loop(), {}) == {}
        return order

    assert asyncio.run(scenario()) == [
        "forget in",
        "other task",
        "forget out",
        "same task",
    ]


def test_a_fence_left_by_an_error_is_released_and_dropped() -> None:
    async def scenario() -> None:
        with pytest.raises(RuntimeError):
            async with content_publication_fence("tsk_a"):
                raise RuntimeError("publisher failed")
        assert content_fence._FENCES.get(asyncio.get_running_loop(), {}) == {}
        async with content_publication_fence("tsk_a"):
            pass

    asyncio.run(scenario())


class _Ledger:
    def __init__(self, records: list[tuple[int, bool]]) -> None:
        self.records = records
        self.asked: list[tuple[str, int]] = []

    def load_events(self, session_id: str, *, after: int = 0) -> AsyncIterator[object]:
        self.asked.append((session_id, after))

        async def rows() -> AsyncIterator[object]:
            for sequence, forgotten in self.records:
                if sequence > after:
                    yield SimpleNamespace(sequence=sequence, forgotten=forgotten)

        return rows()


@pytest.mark.parametrize(
    ("records", "subject", "expected"),
    [
        ([(3, False), (5, True)], 4, True),  # forgotten after the frontier the work tested
        ([(3, True), (5, False)], 4, False),  # forgotten before it: later work, never masked
        ([(3, True)], 3, False),  # the event is the frontier itself: the work saw it
        ([], 0, False),
    ],
)
def test_content_forgotten_after_names_a_forget_after_the_work_s_frontier_only(
    monkeypatch: pytest.MonkeyPatch, records: list[tuple[int, bool]], subject: int, expected: bool
) -> None:
    def forgotten(record: object) -> bool:
        return cast(Any, record).forgotten

    monkeypatch.setattr(content_fence, "is_content_forgotten_record", forgotten)
    ledger = _Ledger(records)
    runtime = SimpleNamespace(ledger=ledger, session_id="ses_1")
    assert asyncio.run(content_forgotten_after(cast(Any, runtime), subject)) is expected
    assert ledger.asked == [("ses_1", subject)]


@pytest.mark.parametrize("subject", [-1, True, "3", None])
def test_content_forgotten_after_refuses_a_frontier_that_is_not_one(subject: object) -> None:
    runtime = SimpleNamespace(ledger=_Ledger([]), session_id="ses_1")
    with pytest.raises(ValueError, match="subject_sequence_invalid"):
        asyncio.run(content_forgotten_after(cast(Any, runtime), cast(Any, subject)))
