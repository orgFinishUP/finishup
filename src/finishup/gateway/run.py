"""Run the REST gateway in the foreground (``finishup service rest run``, ADR-053).

The listener is bound before this runs (``rest.listener.RestListener.bind``), so a refused or
unbindable address fails before anything is served. The gateway then serves the REST v1 routes over
the control-socket backend until ``SIGTERM`` or ``SIGINT``, and stops by closing the listener: it
stops accepting, answers every long-poll, ends every agent's control connection and drops what is
left. Nothing here starts the service by itself; a client's request does, on demand.
"""

from __future__ import annotations

import asyncio
import contextlib
import signal
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, cast

from finishup.gateway.backend import ControlSocketBackend
from finishup.rest.app import RestApp

if TYPE_CHECKING:
    from finishup.rest.api_keys import ApiKeyStore
    from finishup.rest.audit import AuditSink
    from finishup.rest.listener import RestListener

__all__ = ["serve_gateway"]


async def serve_gateway(
    listener: RestListener,
    keys: ApiKeyStore,
    *,
    audit: AuditSink | None,
    ready: Callable[[int], None] | None = None,
    stopped: Awaitable[object] | None = None,
) -> None:
    """Serve until a stop signal (or ``stopped`` completes, for tests); always close."""

    app = RestApp(ControlSocketBackend(), keys, audit=audit)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    installed: list[int] = []
    for signum in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
            loop.add_signal_handler(signum, stop.set)
            installed.append(signum)
    try:
        await listener.start(app.asgi(), app)
        if ready is not None:
            ready(listener.port)
        waiters: list[asyncio.Future[object]] = [
            cast("asyncio.Future[object]", asyncio.ensure_future(stop.wait()))
        ]
        if stopped is not None:
            waiters.append(asyncio.ensure_future(stopped))
        try:
            await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for waiter in waiters:
                waiter.cancel()
    finally:
        await listener.close()
        for signum in installed:
            with contextlib.suppress(Exception):
                loop.remove_signal_handler(signum)
