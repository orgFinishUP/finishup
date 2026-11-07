"""Press Ctrl-C at a prompt on a pty from a helper thread, for console-read tests (#1326).

The code under test runs on the main thread and reads from the pty slave. ``CtrlCAtPrompt``
watches the master side for the prompt, then raises one SIGINT on the main thread, as the
terminal does for Ctrl-C.

It sends SIGINT only while the read is waiting at its prompt. If the code under test ends first
(``ended``), or the prompt never appears, it sends nothing. An early failure then fails its own
test and does not raise ``KeyboardInterrupt`` in pytest. If the read keeps waiting after Ctrl-C,
the helper types one line so the test cannot hang, and ``late_line_typed`` records that.
Leaving the block stops the helper and joins it before the caller closes the pty.
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
        if not self.ended.wait(self._deadline_seconds):
            self.late_line_typed.set()
            os.write(self._master, self._late_line)

    def _prompt_is_up(self) -> bool:
        """Wait for the prompt; ``False`` once the code under test ends or the deadline passes."""

        seen = b""
        deadline = time.monotonic() + self._deadline_seconds
        while self._prompt not in seen:
            remaining = deadline - time.monotonic()
            if self.ended.is_set() or remaining <= 0:
                return False
            ready, _, _ = select.select([self._master], [], [], min(remaining, _POLL_SECONDS))
            if ready:
                seen += os.read(self._master, 1024)
        return True
