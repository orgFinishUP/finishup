"""Shared POSIX process-group helpers for the cleanups that tear down a child's group.

A group whose members have all exited can still answer ``killpg(group, 0)``: an exited member
stays a zombie until its parent reaps it. That parent is this process when it is a child
subreaper (approved checks turn that on, on Linux) and a member outlived its leader, or a
container PID 1 that never reaps. Each cleanup that decides "is the group gone?" therefore reaps
what it can and treats a group of only exited members as gone. These helpers keep the approved
check runner and both Codex cleanups on the same rule.
"""

from __future__ import annotations

import os
from pathlib import Path


def reap_group_members(group_id: int) -> tuple[int, bool]:
    """Reap every waitable member of ``group_id``; return (reaped_count, waitable_remaining).

    ``waitpid(-group_id, WNOHANG)`` is scoped to that one process group, so it can never steal
    an unrelated child of this process. It may reap the group leader, so a caller whose leader is
    still tracked by a process object calls this only after that object observed the exit.
    """

    if os.name == "nt" or not hasattr(os, "waitpid"):
        return 0, False
    reaped = 0
    while True:
        try:
            pid, _status = os.waitpid(-group_id, os.WNOHANG)
        except ChildProcessError:
            # No member of the group is a child of ours: nothing here is waitable.
            return reaped, False
        except OSError:
            return reaped, reaped > 0
        if pid == 0:
            # Live children remain but none has exited yet.
            return reaped, True
        reaped += 1


def group_has_only_exited_members(group_id: int) -> bool:
    """On Linux, whether every remaining member of ``group_id`` has already exited (zombie).

    Elsewhere, or when the process table cannot be read, this reports ``False`` and the caller's
    bounded wait decides.
    """

    proc = Path("/proc")
    if not proc.is_dir():
        return False
    members = 0
    try:
        entries = tuple(proc.iterdir())
    except OSError:
        return False
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rpartition(")")[2].split()
        except OSError:
            continue
        if len(fields) < 3 or fields[2] != str(group_id):
            continue
        if fields[0] not in {"Z", "X"}:
            return False
        members += 1
    return members > 0
