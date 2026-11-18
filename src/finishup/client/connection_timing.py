"""``server test``'s new-process timing: one connection and one status, as the startup gate times them.

``python -m finishup.client.connection_timing TARGET`` (``TARGET``: a target id, ``local`` for the
everyday server, or ``own`` for the selection this process inherits) resolves that target as its
selection (``config.paths.selection_override``, exactly as the in-process probe does), then
times, after its imports, a new connection (``service.client.connect_service``: the shared gate,
the transport and the handshake) and one ``service_status`` call within one bound. The required
startup gate (``cli.startup_gate_probe``) times its connection and a task's status the same way, in a
process of its own, after its imports; a process that already made a connection would time
neither its schema parsing nor (relayed) its first channel (design v2 section 8.9).

It prints one JSON object, ``{"ms": <int>}`` or ``{"error": <closed token>, "phase": <closed token
or null>}``; nothing else leaves it (no path, host or name). It names no workspace, as
``server test`` never involves the folder it runs in.
"""

from __future__ import annotations

import json
import re
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from finishup.protocol.canonical import JsonValue

__all__ = ["BOUND_SECONDS", "main", "measure"]

# The in-process probe's own connect bound (``client.target_runtime``).
BOUND_SECONDS: Final = 5.0
_TARGET_ID: Final = re.compile(r"^t_[0-9a-f]{8}$", re.ASCII)
_TOKEN: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$", re.ASCII)


class _Unresolved(Exception):
    pass


def _root_of(target: str) -> tuple[bool, Path | None]:
    """``(override, root)``: whether to resolve the selection as ``root``, and that root."""

    if target == "own":
        return False, None
    if target == "local":
        return True, None
    if not _TARGET_ID.match(target):
        raise _Unresolved
    from finishup.client.targets import TargetError, read_target, target_root

    try:
        root = target_root(target)
        record = read_target(root)
    except (TargetError, OSError, ValueError):
        raise _Unresolved from None
    if record is None or record.target_id != target:
        raise _Unresolved
    return True, root


def _token(value: object) -> str | None:
    return value if isinstance(value, str) and _TOKEN.match(value) else None


def measure(target: str) -> dict[str, JsonValue]:
    """One new connection and one status for ``target``, timed; or the closed reason it failed."""

    import anyio

    from finishup.config.paths import selection_override
    from finishup.ports.control import ControlClientKind, ControlError
    from finishup.service.client import connect_service

    try:
        override, root = _root_of(target)
    except _Unresolved:
        return {"error": "target_unknown", "phase": None}

    async def timed() -> int:
        client = None
        try:
            with anyio.fail_after(BOUND_SECONDS):
                started = time.monotonic()
                client = await connect_service(ControlClientKind.CLI, workspace_locator=None)
                await client.service_status()
                return round((time.monotonic() - started) * 1000)
        finally:
            if client is not None:
                with anyio.move_on_after(0.05, shield=True):
                    await client.close()

    def run() -> int:
        if not override:
            return anyio.run(timed)
        with selection_override(root):
            return anyio.run(timed)

    try:
        return {"ms": run()}
    except ControlError as error:
        return {
            "error": _token(error.reason) or "service_unavailable",
            "phase": _token(error.phase),
        }
    except TimeoutError:
        return {"error": "service_unavailable", "phase": "timeout"}
    except Exception:  # noqa: BLE001 - nothing but a closed token leaves this process
        return {"error": "service_unavailable", "phase": None}


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    target = arguments[0] if len(arguments) == 1 else ""
    print(json.dumps(measure(target)), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
