"""Builders for the server copy (level L2): git helpers and synthetic snapshots.

``git`` runs the real Git with no system or global configuration, in a fixed locale.
``snapshot_objects`` builds a base commit and a snapshot commit (the two synthetic shapes of
``protocol.server_copy``) from plain ``{path: content}`` maps, the way the exporter does, so a
test can write, tamper with and verify bundles without a repository.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable, Generator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from finishup.protocol.server_copy import (
    MODE_EXECUTABLE,
    MODE_GITLINK,
    MODE_LINK,
    MODE_REGULAR,
    MODE_TREE,
    GitObject,
    Held,
    SnapshotManifest,
    TreeEntry,
    encode_commit,
    encode_tree,
    write_bundle,
    write_pack,
)

__all__ = [
    "Snapshot",
    "git",
    "git_bytes",
    "held_lookup",
    "manifest_for",
    "release_l2",
    "snapshot_objects",
]


def git_bytes(repository: Path, *arguments: str, stdin: bytes | None = None) -> bytes:
    """Run ``git`` in ``repository`` with no ambient configuration; its standard output."""

    completed = subprocess.run(  # noqa: S603 - fixed argv in tests
        ("git", *arguments),
        cwd=repository,
        input=stdin,
        capture_output=True,
        check=True,
        env={
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": os.fspath(repository),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", os.defpath),
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.invalid",
        },
    )
    return completed.stdout


def git(repository: Path, *arguments: str) -> str:
    """``git_bytes`` decoded as UTF-8 and stripped."""

    return git_bytes(repository, *arguments).decode("utf-8").strip()


# A file's value: bytes (a regular file), ("x", bytes) executable, ("link", target), ("gitlink", id).
type FileValue = bytes | tuple[str, bytes | str]


def _tree(files: Mapping[str, FileValue], objects: dict[str, GitObject]) -> str:
    children: dict[str, dict[str, FileValue]] = {}
    entries: list[TreeEntry] = []
    for path, value in files.items():
        head, _, rest = path.partition("/")
        if rest:
            children.setdefault(head, {})[rest] = value
            continue
        if isinstance(value, bytes):
            blob = GitObject("blob", value)
            objects[blob.oid] = blob
            entries.append(TreeEntry(MODE_REGULAR, head.encode(), blob.oid))
            continue
        kind, payload = value
        if kind == "gitlink":
            entries.append(TreeEntry(MODE_GITLINK, head.encode(), str(payload)))
            continue
        data = payload if isinstance(payload, bytes) else payload.encode()
        blob = GitObject("blob", data)
        objects[blob.oid] = blob
        mode = MODE_EXECUTABLE if kind == "x" else MODE_LINK
        entries.append(TreeEntry(mode, head.encode(), blob.oid))
    for name, below in children.items():
        entries.append(TreeEntry(MODE_TREE, name.encode(), _tree(below, objects)))
    tree = GitObject("tree", encode_tree(entries))
    objects[tree.oid] = tree
    return tree.oid


@dataclass(frozen=True, slots=True)
class Snapshot:
    """A base and a snapshot commit with every object they reach."""

    base: str
    snapshot: str
    base_tree: str
    tree: str
    objects: dict[str, GitObject]

    def bundle(
        self,
        *,
        omit: frozenset[str] = frozenset(),
        extra: tuple[GitObject, ...] = (),
        prerequisites: tuple[str, ...] = (),
        ref_number: int = 1,
    ) -> bytes:
        """The snapshot as a ``git-bundle-1`` bundle (``omit`` left out, ``extra`` added)."""

        sent = [item for oid, item in self.objects.items() if oid not in omit]
        return write_bundle(prerequisites, self.snapshot, ref_number, write_pack((*sent, *extra)))


def snapshot_objects(base: Mapping[str, FileValue], current: Mapping[str, FileValue]) -> Snapshot:
    """The synthetic base and snapshot commits of ``base`` and ``current`` file maps."""

    objects: dict[str, GitObject] = {}
    base_tree = _tree(base, objects)
    tree = _tree(current, objects)
    base_commit = GitObject("commit", encode_commit(base_tree, None))
    objects[base_commit.oid] = base_commit
    snapshot = GitObject("commit", encode_commit(tree, base_commit.oid))
    objects[snapshot.oid] = snapshot
    return Snapshot(base_commit.oid, snapshot.oid, base_tree, tree, objects)


def held_lookup(
    objects: Mapping[str, GitObject], trees: Mapping[str, tuple[int, int]]
) -> Callable[[str], Held | None]:
    """A ``have`` callback over ``objects`` already admitted (with tree ``aggregates``), each
    held as a receiver keeps it (``Held``: a tree's expansion bounds computed here)."""

    from finishup.protocol.server_copy import decode_commit, decode_tree

    shapes: dict[str, tuple[int, int]] = {}

    def shape(oid: str) -> tuple[int, int]:
        known = shapes.get(oid)
        if known is not None:
            return known
        entries = 0
        names = 0
        for entry in decode_tree(objects[oid].data):
            step = 1 + len(entry.name)
            entries += 1
            names += step
            if entry.mode == MODE_TREE:
                below_entries, below_names = shape(entry.oid)
                entries += below_entries
                names += below_names + below_entries * step
        shapes[oid] = (entries, names)
        return entries, names

    def have(oid: str) -> Held | None:
        item = objects.get(oid)
        if item is None:
            return None
        if item.kind == "blob":
            return Held("blob", len(item.data))
        if item.kind == "tree":
            size, files = trees[oid]
            entries, names = shape(oid)
            return Held("tree", size, files, entries=entries, names=names)
        tree, _parent = decode_commit(item.data)
        return Held("commit", tree=tree)

    return have


@contextmanager
def release_l2() -> Generator[None]:
    """Marks a test's level-L2 part. Level L2 is released (``L2_RELEASED``), so it changes
    nothing; it fails the test if the release is ever withdrawn without its tests."""

    from finishup.protocol.server_copy import l2_released

    assert l2_released(), "level L2 is not released: these tests need it"
    yield


def manifest_for(
    snapshot: Snapshot,
    *,
    revision: tuple[str, int, str],
    worktree: str,
    purpose: str = "check",
) -> SnapshotManifest:
    """The manifest a client would send with ``snapshot`` (sizes from the verifier)."""

    from finishup.protocol.server_copy import (
        COMPLETENESS_COUNTS,
        COMPLETENESS_LISTS,
        BundleLimits,
        verify_snapshot_bundle,
    )

    verified = verify_snapshot_bundle(
        snapshot.bundle(), have=lambda _oid: None, limits=BundleLimits(max_file_bytes=1 << 24)
    )
    return SnapshotManifest(
        snapshot=snapshot.snapshot,
        base=snapshot.base,
        tree=snapshot.tree,
        base_tree=snapshot.base_tree,
        original_base_format="sha1",
        original_base="d" * 40,
        export_id="e" * 32,
        worktree=worktree,
        policy="sha256:" + "f" * 64,
        lists={name: () for name in COMPLETENESS_LISTS},
        more=dict.fromkeys(COMPLETENESS_LISTS, 0),
        counts=dict.fromkeys(COMPLETENESS_COUNTS, 0),
        subject_state=None,
        issuer=revision[0],
        revision=revision[1],
        profile_digest=revision[2],
        purpose=purpose,  # type: ignore[arg-type]
        synced_at="2026-11-10T08:00:00.000Z",
        files=verified.tree_files,
        bytes=verified.tree_bytes,
    )
