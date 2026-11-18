"""The fence between a task's content publishers and the forget of its server-copy content.

ADR-054 (owner ruling U20). ``application.content_forgetting`` erases a task's check-time change
objects and reviewer ``SEMANTIC_RESPONSE`` objects once a server copy they were derived from is
forgotten. Two things must never outlive a completed forget:

* a content object published while the forget lists what to erase, records its
  ``content_forgotten`` event and erases it: so the forget holds ``content_publication_fence``
  for the task from its inventory through its erasure, and every publisher of such an object
  holds the same fence around its check and its publication;
* a content object of work that tested a frontier before the event (a check or review in flight
  when the copy was forgotten), published after it: every view masks that work's excerpts
  (``kernel.forgotten_content``), so its publisher asks ``content_forgotten_after`` inside the
  fence and publishes nothing when it answers True.

Every content publisher and the forget run on the service's one event loop, so the fence is an
``asyncio`` lock per loop and task, dropped once nobody holds or waits for it.
"""

from __future__ import annotations

import asyncio
import weakref
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Final

from finishup.domain.events import is_content_forgotten_record

if TYPE_CHECKING:
    from finishup.ports.runtime import TaskRuntime

__all__ = ["ContentForgottenError", "content_forgotten_after", "content_publication_fence"]


class ContentForgottenError(Exception):
    """A content object of work whose content was forgotten meanwhile: nothing was published."""

    def __init__(self) -> None:
        super().__init__("content_forgotten")


class _Fence:
    __slots__ = ("lock", "users")

    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.users = 0


_FENCES: Final[weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, dict[str, _Fence]]] = (
    weakref.WeakKeyDictionary()
)


@asynccontextmanager
async def content_publication_fence(task_id: str) -> AsyncGenerator[None]:
    """Hold the task's content fence for the block (see the module text)."""

    fences = _FENCES.setdefault(asyncio.get_running_loop(), {})
    fence = fences.get(task_id)
    if fence is None:
        fence = fences[task_id] = _Fence()
    fence.users += 1
    try:
        async with fence.lock:
            yield
    finally:
        fence.users -= 1
        if fence.users == 0 and fences.get(task_id) is fence:
            del fences[task_id]


async def content_forgotten_after(runtime: TaskRuntime, subject_sequence: int) -> bool:
    """Whether the task's ledger records a ``content_forgotten`` event after ``subject_sequence``.

    True when work that tested the frontier at ``subject_sequence`` was in flight when a server
    copy's content was forgotten: every view masks its excerpts, so nothing of it may be
    published as a content object. The ledger reads the whole task chain from any of its sessions.
    """

    if type(subject_sequence) is not int or subject_sequence < 0:
        raise ValueError("subject_sequence_invalid")
    async for record in runtime.ledger.load_events(runtime.session_id, after=subject_sequence):
        if is_content_forgotten_record(record):
            return True
    return False
