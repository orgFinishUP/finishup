"""``task_close`` retention reads a task's work state from the lineage catalog (ADR-054)."""

from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass

from finishup.domain.coordination import WorkState
from finishup.service.daemon import _lineage_task_closed  # pyright: ignore[reportPrivateUsage]


@dataclass(frozen=True)
class _Snapshot:
    work_state: WorkState


class _Store:
    def __init__(self) -> None:
        self.tasks = {
            "open_task": _Snapshot(WorkState.OPEN),
            "closed_task": _Snapshot(WorkState.CLOSED),
            "abandoned_task": _Snapshot(WorkState.ABANDONED),
        }

    async def get_task(self, task_id: str) -> _Snapshot | None:
        if task_id == "broken":
            raise RuntimeError("catalog unavailable")
        return self.tasks.get(task_id)


def test_only_a_task_whose_work_is_no_longer_open_is_closed() -> None:
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    try:
        closed = _lineage_task_closed(_Store(), loop)
        assert closed("closed_task") is True
        assert closed("abandoned_task") is True
        # Open, unknown or unreadable: the copy stays.
        assert closed("open_task") is False
        assert closed("missing") is False
        assert closed("broken") is False
        # Asked from the loop itself it cannot wait for the loop: open.
        on_loop = asyncio.run_coroutine_threadsafe(_call(closed, "closed_task"), loop)
        assert on_loop.result(timeout=5) is False
        assert _lineage_task_closed(object(), loop)("closed_task") is False
    finally:
        loop.call_soon_threadsafe(loop.stop)
        thread.join(5)
        loop.close()
    assert closed("closed_task") is False  # a closed loop answers open


async def _call(closed: object, task_id: str) -> bool:
    return closed(task_id)  # type: ignore[operator,no-any-return]  # pyright: ignore[reportCallIssue,reportUnknownVariableType]
