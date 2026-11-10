"""The working checkout the server reads a copy's snapshot from (level L2; design v2 §4.1; ADR-054).

At level L2 the server reads evidence of a claim-bound task from its own copy of the repository
instead of asking the client's workspace agent. The reads reuse the service's local adapters
(``adapters.git_change_capture``, ``adapters.task_input_read``) unchanged, so they need a real
working directory: this module materializes one snapshot of one copy into it.

* **One checkout per copy**, ``<state>/code-copies/checkouts/<copy key>/``: owner-only (``0700``
  directories, ``0600``/``0700`` files), never reached through a link, written only here and only
  from objects the copy store verified and decrypted. Its ``.git`` is made by hand: the loose
  objects the snapshot reaches, ``HEAD`` detached at the snapshot's synthetic base, an index Git
  builds from that base (``git read-tree``, no system or global configuration, no hooks), no
  remote, no config beyond the format. The working tree is the snapshot's tree: files with their
  modes, links as links (their target text; never followed here), gitlinks as empty directories.
* **Updated in place.** Moving to another snapshot rewrites only the paths whose mode or object
  changed and removes the paths that went, so an unchanged file keeps its ``stat`` identity and
  the untracked files a task's base recorded (by ``stat`` digest) stay baseline across checks.
* **One reader at a time per copy**: ``checkout`` holds the copy's lock while the caller reads.
* **Plaintext while in use.** The copy store keeps every object encrypted; the checkout is the
  plaintext a read needs. It is removed when the service starts (``sweep``), when its copy is
  forgotten or expires (``discard`` / ``discard_orphans``), and never survives the copy. A rebuilt
  checkout has new ``stat`` identities, so after a service restart untracked files that predate a
  task read as additions (an honest limit: more change is shown, never less).
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import threading
from collections.abc import Callable, Generator, Iterable
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from finishup.protocol.server_copy import (
    MODE_EXECUTABLE,
    MODE_GITLINK,
    MODE_LINK,
    MODE_TREE,
    GitObject,
    SnapshotManifest,
    decode_commit,
    decode_tree,
    loose_encode,
)
from finishup.service.code_store import CodeStore

__all__ = ["CheckoutError", "CopyCheckouts"]

_GIT_SECONDS: Final = 60.0
_MAX_DEPTH: Final = 128
_DIRECTORY: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_CONFIG: Final = (
    b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
    b"\tlogallrefupdates = false\n"
)


class CheckoutError(Exception):
    """A checkout that could not be made; ``reason`` is a closed token."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


type _Entries = dict[bytes, tuple[bytes, str]]
type _Reader = Callable[[str], GitObject]


@dataclass(slots=True)
class _State:
    folder: Path
    snapshot: str | None = None
    base: str | None = None
    entries: _Entries = field(default_factory=lambda: {})
    objects: set[str] = field(default_factory=lambda: set())


def _environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "HOME": os.devnull,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "XDG_CONFIG_HOME": os.devnull,
    }


def _private_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, exist_ok=True)
        facts = os.lstat(path)
    except OSError:
        raise CheckoutError("code_checkout_unsafe") from None
    if not stat.S_ISDIR(facts.st_mode) or facts.st_uid != os.geteuid():
        raise CheckoutError("code_checkout_unsafe")
    if stat.S_IMODE(facts.st_mode) != 0o700:
        os.chmod(path, 0o700)


def _remove(path: Path) -> None:
    try:
        if path.is_symlink() or not path.is_dir():
            path.unlink(missing_ok=True)
        else:
            shutil.rmtree(path)
    except OSError:
        pass


class CopyCheckouts:
    """The checkouts of every copy a service keeps (see the module text). Thread-safe."""

    __slots__ = ("_lock", "_locks", "_root", "_states", "_store")

    def __init__(self, root: Path, store: CodeStore) -> None:
        self._root = root
        self._store = store
        self._lock = threading.Lock()
        self._locks: dict[str, threading.Lock] = {}
        self._states: dict[str, _State] = {}

    @property
    def root(self) -> Path:
        return self._root

    def sweep(self) -> None:
        """Remove every checkout (service start: nothing of a previous run is trusted)."""

        with self._lock:
            self._states.clear()
            if self._root.is_symlink():
                self._root.unlink()
            if self._root.is_dir():
                shutil.rmtree(self._root, ignore_errors=True)
            _private_directory(self._root)

    def discard(self, copy_key: str) -> None:
        """Remove one copy's checkout (its copy was forgotten or expired)."""

        lock = self._copy_lock(copy_key)
        with lock:
            with self._lock:
                self._states.pop(copy_key, None)
            _remove(self._root / copy_key[:32])

    def discard_orphans(self) -> None:
        """Remove the checkout of every copy that is gone (after a forget or an expiry)."""

        with self._lock:
            keys = tuple(self._states)
        for copy_key in keys:
            if not self._store.holds(copy_key):
                self.discard(copy_key)

    def _copy_lock(self, copy_key: str) -> threading.Lock:
        with self._lock:
            return self._locks.setdefault(copy_key, threading.Lock())

    @contextmanager
    def checkout(
        self,
        principal: str,
        repository: str,
        manifest: SnapshotManifest,
        *,
        commits: Iterable[str] = (),
    ) -> Generator[Path]:
        """The copy's checkout at ``manifest``'s snapshot, held for the caller's reads.

        ``commits`` are further synthetic base commits of this copy whose objects the checkout's
        Git must hold too (the task base a capture diffs against). Raises ``CheckoutError`` or
        the store's ``CodeStoreError`` (a locked vault, a copy that is gone); nothing is left
        half-made: a
        failed update removes the checkout, and the next read makes it again.
        """

        copy_key = self._store.copy_key(principal, repository)
        with self._copy_lock(copy_key):
            try:
                folder = self._update(copy_key, principal, repository, manifest, tuple(commits))
            except BaseException:
                with self._lock:
                    self._states.pop(copy_key, None)
                _remove(self._root / copy_key[:32])
                raise
            yield folder

    # --- making and updating ---------------------------------------------------------------

    def _update(
        self,
        copy_key: str,
        principal: str,
        repository: str,
        manifest: SnapshotManifest,
        commits: tuple[str, ...],
    ) -> Path:
        _private_directory(self._root)
        with self._lock:
            state = self._states.get(copy_key)
        if state is None:
            state = self._fresh(copy_key)
            with self._lock:
                self._states[copy_key] = state

        def read(oid: str) -> GitObject:
            return self._store.read_object(principal, repository, oid)

        for commit in (manifest.snapshot, manifest.base, *commits):
            self._admit_commit(state, read, commit)
        if state.snapshot != manifest.snapshot:
            target = self._entries(read, manifest.tree)
            self._apply(state, target)
            if state.base != manifest.base:
                _write_file(state.folder / ".git" / "HEAD", (manifest.base + "\n").encode(), 0o600)
                self._git(state.folder, "read-tree", manifest.base)
                state.base = manifest.base
            # Fills the index's stat data, so a later read compares by stat, not by content.
            self._git(state.folder, "update-index", "-q", "--refresh", check=False)
            state.snapshot = manifest.snapshot
        return state.folder

    def _fresh(self, copy_key: str) -> _State:
        folder = self._root / copy_key[:32]
        _remove(folder)
        _private_directory(folder)
        git = folder / ".git"
        _private_directory(git)
        for below in ("objects", "refs", "refs/heads", "refs/tags", "info"):
            _private_directory(git / below)
        _write_file(git / "config", _CONFIG, 0o600)
        _write_file(git / "description", b"FinishUP copy checkout\n", 0o600)
        return _State(folder)

    def _admit_object(self, state: _State, item: GitObject) -> None:
        if item.oid in state.objects:
            return
        directory = state.folder / ".git" / "objects" / item.oid[:2]
        _private_directory(directory)
        path = directory / item.oid[2:]
        if not path.exists():
            _write_file(path, loose_encode(item), 0o400)
        state.objects.add(item.oid)

    def _admit_tree(self, state: _State, read: _Reader, oid: str, depth: int = 0) -> None:
        if oid in state.objects:
            return
        if depth > _MAX_DEPTH:
            raise CheckoutError("code_checkout_too_deep")
        item = read(oid)
        if item.kind != "tree":
            raise CheckoutError("code_checkout_corrupt")
        for entry in decode_tree(item.data):
            if entry.mode == MODE_TREE:
                self._admit_tree(state, read, entry.oid, depth + 1)
            elif entry.mode != MODE_GITLINK and entry.oid not in state.objects:
                self._admit_object(state, read(entry.oid))
        self._admit_object(state, item)

    def _admit_commit(self, state: _State, read: _Reader, oid: str) -> None:
        if oid in state.objects:
            return
        item = read(oid)
        if item.kind != "commit":
            raise CheckoutError("code_checkout_corrupt")
        tree, parent = decode_commit(item.data)
        self._admit_tree(state, read, tree)
        if parent is not None:
            self._admit_commit(state, read, parent)
        self._admit_object(state, item)

    def _entries(self, read: _Reader, tree: str) -> _Entries:
        found: _Entries = {}

        def walk(oid: str, prefix: bytes, depth: int) -> None:
            if depth > _MAX_DEPTH:
                raise CheckoutError("code_checkout_too_deep")
            item = read(oid)
            for entry in decode_tree(item.data):
                path = prefix + entry.name
                if entry.mode == MODE_TREE:
                    walk(entry.oid, path + b"/", depth + 1)
                else:
                    found[path] = (entry.mode, entry.oid)

        walk(tree, b"", 0)
        return found

    def _apply(self, state: _State, target: _Entries) -> None:
        """Move the working tree from ``state.entries`` to ``target`` in place."""

        root = os.open(state.folder, _DIRECTORY)
        try:
            gone = [path for path, value in state.entries.items() if target.get(path) != value]
            for path in sorted(gone, reverse=True):
                _unlink_beneath(root, path)
            for path in sorted(gone, reverse=True):
                _prune_parents(root, path)
            for path, (mode, oid) in sorted(target.items()):
                if state.entries.get(path) == (mode, oid):
                    continue
                data = b"" if mode == MODE_GITLINK else self._blob(state, oid)
                _write_beneath(root, path, mode, data)
            state.entries = dict(target)
        finally:
            os.close(root)

    def _blob(self, state: _State, oid: str) -> bytes:
        path = state.folder / ".git" / "objects" / oid[:2] / oid[2:]
        from finishup.protocol.server_copy import loose_decode

        try:
            item = loose_decode(path.read_bytes(), oid, limit=1 << 31)
        except (OSError, ValueError):
            raise CheckoutError("code_checkout_corrupt") from None
        if item.kind != "blob":
            raise CheckoutError("code_checkout_corrupt")
        return item.data

    @staticmethod
    def _git(folder: Path, *arguments: str, check: bool = True) -> None:
        executable = shutil.which("git", path=os.defpath)
        if executable is None:
            raise CheckoutError("git_unavailable")
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
                (
                    executable,
                    "-c",
                    "core.hooksPath=" + os.devnull,
                    "--git-dir",
                    os.fspath(folder / ".git"),
                    "--work-tree",
                    os.fspath(folder),
                    *arguments,
                ),
                cwd=folder,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=_GIT_SECONDS,
                env=_environment(),
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            raise CheckoutError("git_failed") from None
        if check and completed.returncode != 0:
            raise CheckoutError("git_failed")


# --- writing beneath the checkout, never through a link ---------------------------------------


def _write_file(path: Path, data: bytes, mode: int) -> None:
    try:
        path.unlink(missing_ok=True)
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode
        )
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(descriptor, view) :]
        finally:
            os.close(descriptor)
    except OSError:
        raise CheckoutError("code_checkout_unsafe") from None


def _parent(root: int, path: bytes, *, create: bool) -> tuple[int, bytes] | None:
    """An open descriptor of ``path``'s directory beneath ``root`` and its last component.

    Each component is opened without following a link; with ``create``, a missing one is made
    (``0700``) and one that is not a directory is removed first. None when it is not there."""

    *components, name = path.split(b"/")
    current = os.dup(root)
    try:
        for component in components:
            try:
                following = os.open(component, _DIRECTORY, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    os.close(current)
                    return None
                os.mkdir(component, 0o700, dir_fd=current)
                following = os.open(component, _DIRECTORY, dir_fd=current)
            except (NotADirectoryError, OSError):
                if not create:
                    os.close(current)
                    return None
                # A link or a file where the snapshot has a directory: it goes.
                os.unlink(component, dir_fd=current)
                os.mkdir(component, 0o700, dir_fd=current)
                following = os.open(component, _DIRECTORY, dir_fd=current)
            os.close(current)
            current = following
    except OSError:
        os.close(current)
        raise CheckoutError("code_checkout_unsafe") from None
    return current, name


def _clear(directory: int, name: bytes) -> None:
    try:
        facts = os.lstat(name, dir_fd=directory)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(facts.st_mode):
        shutil.rmtree(name, dir_fd=directory)
    else:
        os.unlink(name, dir_fd=directory)


def _unlink_beneath(root: int, path: bytes) -> None:
    opened = _parent(root, path, create=False)
    if opened is None:
        return
    directory, name = opened
    try:
        _clear(directory, name)
    except OSError:
        raise CheckoutError("code_checkout_unsafe") from None
    finally:
        os.close(directory)


def _prune_parents(root: int, path: bytes) -> None:
    """Remove the directories ``path`` leaves empty (Git shows no empty directory)."""

    parts = path.split(b"/")[:-1]
    while parts:
        opened = _parent(root, b"/".join(parts), create=False)
        if opened is None:
            return
        directory, name = opened
        try:
            os.rmdir(name, dir_fd=directory)
        except OSError:
            return
        finally:
            os.close(directory)
        parts.pop()


def _write_beneath(root: int, path: bytes, mode: bytes, data: bytes) -> None:
    opened = _parent(root, path, create=True)
    assert opened is not None  # noqa: S101 - ``create`` makes every parent
    directory, name = opened
    try:
        _clear(directory, name)
        if mode == MODE_LINK:
            os.symlink(data, name, dir_fd=directory)
        elif mode == MODE_GITLINK:
            os.mkdir(name, 0o700, dir_fd=directory)
        else:
            permissions = 0o700 if mode == MODE_EXECUTABLE else 0o600
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                permissions,
                dir_fd=directory,
            )
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(descriptor, view) :]
                os.fchmod(descriptor, permissions)
            finally:
                os.close(descriptor)
    except OSError:
        raise CheckoutError("code_checkout_unsafe") from None
    finally:
        os.close(directory)
