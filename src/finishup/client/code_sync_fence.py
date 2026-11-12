"""The fence that stops level-L2 sync to one target while ``server remove`` forgets its copies.

``finishup server remove NAME --forget-copies`` (or yes on the trusted console) forgets every
repository this computer sent a copy from, one at a time, then removes the target, which deletes
its claim salt: afterwards this computer can no longer ask that server to forget anything. A
check still running could otherwise make the target's helper sync a repository already
forgotten, under the new epoch the forget began, while the next one is being forgotten; that new
copy would then stay behind. So before it lists the repositories, ``server remove`` raises this
fence, renews it before each repository and before the removal, and lowers it only when the
removal does not happen (the target stays, and so does its way back to level L2). Removing the
target deletes the fence with its folder.

The fence is an owner-only empty file, ``<target root>/state/code-sync-fence``, in force while
its modification time is within ``FENCE_SECONDS`` of now: a remove that was interrupted (a crash,
a closed terminal) never keeps a target from syncing for longer than that. While it is in force
the helper's ``code_sync_prepare`` and ``code_sync_read`` refuse (``client.code_sync``) before
anything is read or sent. A fence whose state cannot be read is in force (fail closed).

Standard library and ``config.paths`` only.
"""

from __future__ import annotations

import errno
import os
import secrets
import time
from pathlib import Path
from typing import Final

from finishup.config.paths import PathSafetyError, ensure_owner_only_dir

__all__ = [
    "FENCE_NAME",
    "FENCE_SECONDS",
    "CodeSyncFenceError",
    "fence_path",
    "fenced",
    "lower_fence",
    "raise_fence",
]

FENCE_NAME: Final = "code-sync-fence"
# How long one raise holds without a renewal: longer than one repository's forget can take.
FENCE_SECONDS: Final = 600.0


class CodeSyncFenceError(Exception):
    """The fence could not be raised: nothing may be forgotten or removed under it."""


def fence_path(root: Path) -> Path:
    """``<target root>/state/code-sync-fence``."""

    return root / "state" / FENCE_NAME


def raise_fence(root: Path) -> None:
    """Raise (or renew) the fence for the target at ``root``; ``CodeSyncFenceError`` if it
    cannot be written durably (owner-only file, fsync, rename, directory fsync)."""

    path = fence_path(root)
    try:
        ensure_owner_only_dir(path.parent)
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
        )
        try:
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, path)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except (OSError, PathSafetyError):
        raise CodeSyncFenceError from None


def lower_fence(root: Path) -> None:
    """Lower the fence (the removal did not happen); a fence already gone is fine."""

    try:
        fence_path(root).unlink(missing_ok=True)
    except OSError:
        return  # it expires on its own within FENCE_SECONDS


def fenced(root: Path, *, now: float | None = None) -> bool:
    """Whether the fence for the target at ``root`` is in force now (see the module text)."""

    try:
        facts = fence_path(root).lstat()
    except OSError as error:
        return error.errno not in {errno.ENOENT, errno.ENOTDIR}
    moment = time.time() if now is None else now
    return abs(moment - facts.st_mtime) < FENCE_SECONDS
