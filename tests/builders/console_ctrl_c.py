"""Press Ctrl-C at a prompt on a pty from a helper thread, for console-read tests (#1326).

The code under test runs on the main thread and reads from the pty slave. ``CtrlCAtPrompt``
watches the master side for the prompt, then raises one SIGINT on the main thread, as the
terminal does for Ctrl-C.

It sends SIGINT only while the read is waiting at its prompt. If the code under test ends first
(``ended``), or the prompt never appears, it sends nothing. An early failure then fails its own
test and does not raise ``KeyboardInterrupt`` in pytest. If the read keeps waiting after Ctrl-C,
the helper types one line so the test cannot hang, and ``late_line_typed`` records that.
Leaving the block stops the helper and joins it before the caller closes the pty.

Both helpers keep reading the master side until the code under test ends, as a terminal does. On
macOS a ``tcsetattr(..., TCSADRAIN)`` on the slave waits until the master has read all pending
output (the prompt, echoed input), so a test that never read the master would hang there.
``AnswerAtPrompt`` types a line once the prompt appears, for reads that should complete.
"""

from __future__ import annotations

import os
import select
import signal
import threading
import time
from types import TracebackType
from typing import Final, Self

_POLL_SECONDS: Final = 0.05


class CtrlCAtPrompt:
    """Context manager: one Ctrl-C at ``prompt``; construct and enter it on the main thread."""

    def __init__(
        self,
        master: int,
        prompt: bytes,
        *,
        late_line: bytes = b"approve\n",
        deadline_seconds: float = 10.0,
    ) -> None:
        self.ended = threading.Event()
        self.ctrl_c_sent = threading.Event()
        self.late_line_typed = threading.Event()
        self._master = master
        self._prompt = prompt
        self._late_line = late_line
        self._deadline_seconds = deadline_seconds
        self._main_thread = threading.get_ident()
        self._thread = threading.Thread(target=self._press_ctrl_c_at_the_prompt, daemon=True)

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.ended.set()
        self._thread.join(self._deadline_seconds)

    def _press_ctrl_c_at_the_prompt(self) -> None:
        if not self._prompt_is_up() or self.ended.is_set():
            return
        signal.pthread_kill(self._main_thread, signal.SIGINT)
        self.ctrl_c_sent.set()
        # A swallowed Ctrl-C leaves the read waiting; type a line so the test cannot hang.
        if not _drain_until(self._master, self.ended, self._deadline_seconds):
            self.late_line_typed.set()
            os.write(self._master, self._late_line)
            _drain_until(self._master, self.ended, self._deadline_seconds)

    def _prompt_is_up(self) -> bool:
        return _prompt_is_up(self._master, self._prompt, self.ended, self._deadline_seconds)


class AnswerAtPrompt:
    """Context manager: type ``line`` once ``prompt`` appears, and keep draining the master."""

    def __init__(
        self, master: int, prompt: bytes, line: bytes, *, deadline_seconds: float = 10.0
    ) -> None:
        self.ended = threading.Event()
        self.answered = threading.Event()
        self._master = master
        self._prompt = prompt
        self._line = line
        self._deadline_seconds = deadline_seconds
        self._thread = threading.Thread(target=self._answer, daemon=True)

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.ended.set()
        self._thread.join(self._deadline_seconds)

    def _answer(self) -> None:
        if not _prompt_is_up(self._master, self._prompt, self.ended, self._deadline_seconds):
            return
        os.write(self._master, self._line)
        self.answered.set()
        _drain_until(self._master, self.ended, self._deadline_seconds)


def _prompt_is_up(master: int, prompt: bytes, ended: threading.Event, seconds: float) -> bool:
    """Wait for the prompt; ``False`` once the code under test ends or the deadline passes."""

    seen = b""
    deadline = time.monotonic() + seconds
    while prompt not in seen:
        remaining = deadline - time.monotonic()
        if ended.is_set() or remaining <= 0:
            return False
        ready, _, _ = select.select([master], [], [], min(remaining, _POLL_SECONDS))
        if ready:
            seen += os.read(master, 1024)
    return True


def _drain_until(master: int, ended: threading.Event, seconds: float) -> bool:
    """Read the master until ``ended``; ``False`` if the deadline passes first."""

    deadline = time.monotonic() + seconds
    while not ended.is_set():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        try:
            ready, _, _ = select.select([master], [], [], min(remaining, _POLL_SECONDS))
            if ready:
                os.read(master, 1024)
        except OSError:
            return True
    return True
