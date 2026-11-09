"""The REST edge's bounded audit (ADR-053; approach A's gateway audit, re-hosted).

Every request an edge answers is one canonical JSON line in an owner-only file beneath the server
root's log folder (``rest-audit.jsonl``): the time, the edge, the route, the HTTP status or closed
refusal reason, the key id when a key authenticated, and for a call its control method, outcome and
duration. Never a body, a header value, a label, a path, a host or an address.

The audit is bounded: the file is renamed to ``<name>.1`` (replacing the previous one) once it
reaches ``AUDIT_ROTATE_BYTES``, so it holds about twice that at most; and a refusal of a request no
key authenticated is written at most once per reason per ``UNAUTHENTICATED_AUDIT_SECONDS``, the
ones not written counted in the next line for that reason (``suppressed``), so a client without a
key cannot grow the server's disk.
"""

from __future__ import annotations

import contextlib
import os
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Protocol

from finishup.protocol.canonical import JsonValue, canonical_encode

__all__ = [
    "AUDIT_FILE_NAME",
    "AUDIT_ROTATE_BYTES",
    "UNAUTHENTICATED_AUDIT_SECONDS",
    "AuditSink",
    "FileAuditSink",
    "RestAudit",
]

AUDIT_FILE_NAME: Final = "rest-audit.jsonl"
AUDIT_ROTATE_BYTES: Final = 8 * 1_048_576
UNAUTHENTICATED_AUDIT_SECONDS: Final = 60.0


class AuditSink(Protocol):
    def write(self, record: dict[str, JsonValue]) -> None: ...


class FileAuditSink:
    """Append canonical audit lines to an owner-only file, rotating once at ``rotate_bytes``."""

    def __init__(self, path: Path, *, rotate_bytes: int = AUDIT_ROTATE_BYTES) -> None:
        self._path = path
        self._rotate_bytes = rotate_bytes

    def write(self, record: dict[str, JsonValue]) -> None:
        with contextlib.suppress(OSError):
            self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW
            descriptor = os.open(self._path, flags, 0o600)
            try:
                if os.fstat(descriptor).st_size >= self._rotate_bytes:
                    os.close(descriptor)
                    descriptor = -1
                    os.replace(self._path, self._path.with_name(f"{self._path.name}.1"))
                    descriptor = os.open(self._path, flags, 0o600)
                os.write(descriptor, canonical_encode(record) + b"\n")
            finally:
                if descriptor >= 0:
                    os.close(descriptor)


def _stamp() -> str:
    from finishup.config.installation import format_rfc3339_ms

    return format_rfc3339_ms(datetime.now(UTC))


class RestAudit:
    """What one edge writes to its sink; never raises."""

    __slots__ = ("_clock", "_edge", "_last", "_sink", "_suppressed")

    def __init__(
        self,
        sink: AuditSink | None,
        *,
        edge: str,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._sink = sink
        self._edge = edge
        self._clock = clock
        self._last: dict[str, float] = {}
        self._suppressed: dict[str, int] = {}

    def _write(self, record: dict[str, JsonValue]) -> None:
        if self._sink is None:
            return
        with contextlib.suppress(Exception):
            self._sink.write({"at": _stamp(), "edge": self._edge, **record})

    def request(self, route: str, status: int, key_id: str | None) -> None:
        self._write({"event": "rest_request", "route": route, "status": status, "key_id": key_id})

    def call(self, method: str, outcome: str, duration_ms: int) -> None:
        self._write(
            {
                "event": "rest_call",
                "control_method": method,
                "outcome": outcome,
                "duration_ms": duration_ms,
            }
        )

    def refusal(
        self, route: str, reason: str, *, authenticated: bool, key_id: str | None = None
    ) -> None:
        if not authenticated:
            now = self._clock()
            last = self._last.get(reason)
            if last is not None and now - last < UNAUTHENTICATED_AUDIT_SECONDS:
                self._suppressed[reason] = self._suppressed.get(reason, 0) + 1
                return
            self._last[reason] = now
            suppressed = self._suppressed.pop(reason, 0)
            self._write(
                {
                    "event": "rest_refusal",
                    "route": route,
                    "reason": reason,
                    "suppressed": suppressed,
                }
            )
            return
        self._write({"event": "rest_refusal", "route": route, "reason": reason, "key_id": key_id})
