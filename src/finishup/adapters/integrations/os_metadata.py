"""Files an operating system writes into a folder on its own, which no owner put there.

macOS Finder writes ``.DS_Store`` into any folder it shows. On a volume that cannot store
extended attributes natively (exFAT, FAT, SMB and NFS shares), macOS keeps a file's or folder's
attributes in an AppleDouble sibling named ``._<name>``. Neither is content anyone chose to keep
in a FinishUP-managed tree, and neither is visible in Finder, so a refusal that asks the owner to
move them out cannot be followed.

The managed-tree readers of every host (the Codex plugin source, the Codex project skill and the
Yoetz-era skill tree it migrates, the portable plugin tree, and the Claude Code and Cursor plugin
trees) skip such a file: it never counts as a file FinishUP did not write, never enters an
inspection or preview digest, and never blocks an install, refresh or removal. It goes with the
tree when FinishUP replaces or removes that tree as a whole (ADR-023 §9). Only a regular file is
judged by name; a link or any other non-regular member under such a name stays unsafe, and a file
inside a folder named ``._x`` is still owner content.
"""

from __future__ import annotations

from typing import Final

__all__ = ["is_os_metadata_file"]

_FINDER_METADATA: Final = ".DS_Store"
_APPLEDOUBLE_PREFIX: Final = "._"


def is_os_metadata_file(relative_path: str) -> bool:
    """True when a regular file's name marks it as OS-written metadata rather than owner content.

    ``relative_path`` is a slash-separated path inside a managed tree, or a bare file name; only
    its last component is judged. The caller has already established that it names a regular
    file. No name FinishUP renders into a managed tree matches.
    """

    name = relative_path.rsplit("/", 1)[-1]
    return name == _FINDER_METADATA or (
        name.startswith(_APPLEDOUBLE_PREFIX) and len(name) > len(_APPLEDOUBLE_PREFIX)
    )
