"""The sanitized exporter of a repository's server copy (level L2; design v2 §4.2, §8.1, U6, U10, U19).

The helper runs this, and nothing else does: never a hook, an MCP bridge or a CLI command. Given a
repository's worktree, the export policy and what the server already holds, ``export_snapshot``
produces one ``git-bundle-1`` bundle (``protocol.server_copy``) and its snapshot manifest:

1. ``gate()`` first (FR-7): the caller's checks of the authorization, the round-5 hold, the
   zero-network marker, the consent at L2 and the repository's own level. A refusal raises
   before any file is read and before any object is written.
2. The **base** (the original commit the task started from, ``HEAD`` by default) is listed with
   ``git ls-tree`` and its blobs read with ``git cat-file``; the **current tree** is every
   git-visible file: tracked (``git ls-files --stage``) and untracked-not-ignored
   (``--exclude-standard`` plus the owner's own global ignore file), read from the worktree
   without following any link (each directory opened with ``O_NOFOLLOW``, the file's type
   checked on its open descriptor). Deleted files are absent.
3. Each path is admitted or held out, and held-out paths leave **both** trees (so nothing held
   out reads as deleted): always-excluded, server and owner patterns (``excluded``); not
   representable as a safe tree entry; over ``max_file_bytes`` (``too_large``); a known secret
   format in its bytes unless the owner allowed that exact content (``held_for_content``); a
   Git LFS file whose bytes are not its pointer (``lfs_content``); case-fold collisions
   (``case_collision``); nested repositories that are not submodules; special files, links to
   directories through a path and multiply-linked files (``special``). Symlinks are sent as
   their target text, submodules as gitlinks (commit id only), LFS files as their pointers.
4. Every admitted object is re-created from the bytes read, by this module, into the target's
   **export object database** (``ExportDatabase``: git loose objects owned by FinishUP, never
   the repository's own ``.git``), and wrapped in the two synthetic commits. A sanitized tree
   over ``max_repo_bytes`` refuses the export: no partial copy is sent.
5. The bundle carries only what the server's have-set does not reach (incremental), and the
   **object-closure audit** parses it back with the server's own verifier: every object in it
   was admitted in this run, everything the snapshot reaches is in it or held by the server,
   and its trees and size are exactly the ones built. Any difference refuses the export.

Paths held out are named in the manifest (path only, never content), bounded at 256 per list.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import shutil
import stat
import subprocess
import zlib
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, cast

from finishup.client.code_copy_settings import RepositoryCodeSettings
from finishup.client.code_secrets import ALWAYS_EXCLUDED, excluded_by, holds_known_secret
from finishup.config.installation import format_rfc3339_ms
from finishup.config.paths import PathSafetyError, ensure_owner_only_dir
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.server_copy import (
    COMPLETENESS_COUNTS,
    COMPLETENESS_LISTS,
    MODE_EXECUTABLE,
    MODE_GITLINK,
    MODE_LINK,
    MODE_REGULAR,
    MODE_TREE,
    BundleLimits,
    CopyError,
    GitObject,
    Held,
    SnapshotManifest,
    TreeEntry,
    component_refusal,
    decode_commit,
    decode_tree,
    encode_commit,
    encode_tree,
    folded_name,
    loose_decode,
    loose_encode,
    policy_digest,
    verify_snapshot_bundle,
    write_bundle,
    write_pack,
)

__all__ = [
    "EXPORT_SCHEMA",
    "ExportDatabase",
    "ExportPolicy",
    "ExportRecord",
    "ExportRefused",
    "ExportRequest",
    "PreparedExport",
    "export_records",
    "export_snapshot",
]

EXPORT_SCHEMA: Final = "yoetz.code-export/1"
_EXPORT_NAME: Final = "export.json"
_MAX_SENT: Final = 64
_MAX_LISTED: Final = 256
_MAX_LINK_BYTES: Final = 4_096
_MAX_LFS_POINTER_BYTES: Final = 1_024
_MAX_LFS_HASH_BYTES: Final = 1 << 30
_MAX_GIT_OUTPUT: Final = 512 * 1024 * 1024
_GIT_SECONDS: Final = 120.0
_HEX: Final = re.compile(rb"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_EXPORT_ID: Final = re.compile(r"^[0-9a-f]{32}$")
# An export folder's name: the first 32 hex digits of the repository key's digest (``code_sync``).
_FOLDER_NAME: Final = re.compile(r"^[0-9a-f]{32}$")
_MAX_ROOT_BYTES: Final = 4_096
_MAX_RECORD_BYTES: Final = 65_536
_LFS_POINTER: Final = re.compile(
    rb"^version https://git-lfs\.github\.com/spec/v1\n(?:[a-z0-9.-]+ [^\n]*\n)*$"
)
_LFS_OID: Final = re.compile(rb"^oid sha256:([0-9a-f]{64})$", re.MULTILINE)
_OPEN_FILE: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0)
_OPEN_DIRECTORY: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_DIRECTORY
# The repository's own configuration is still read (its ignore rules, its object store); these
# keep it from running anything: no fsmonitor hook (empty disables it on every Git), no hooks,
# no credential helper, no transport (a partial clone fails, never fetches), no replace refs.
_GIT_PREFIX: Final = (
    "--no-replace-objects",
    "-c",
    "core.fsmonitor=",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "credential.helper=",
    "-c",
    "protocol.allow=never",
    "-c",
    "core.quotePath=false",
)


class ExportRefused(Exception):
    """Nothing was exported; ``reason`` is a closed token."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


# --- the export object database --------------------------------------------------------------------


def _recordable_root(value: object) -> bool:
    """Whether ``value`` can be kept as the repository's folder: absolute, normal, printable."""

    if type(value) is not str or not value.startswith("/") or os.path.normpath(value) != value:
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return len(encoded) <= _MAX_ROOT_BYTES and value.isprintable()


type _Record = tuple[str, int, tuple[str, ...], str | None]


def _read_export_record(path: Path) -> _Record | None:
    """``(export id, next ref, sent, root)`` from ``export.json``; None when there is none.

    Raises ``ExportRefused("code_export_unsafe")`` for a record that is not an owner-only regular
    file; a record that cannot be parsed or names a value out of shape is None too: nothing it
    named is trusted (fail closed).
    """

    try:
        descriptor = os.open(path, _OPEN_FILE)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError:
        raise ExportRefused("code_export_unsafe") from None
    try:
        facts = os.fstat(descriptor)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != os.geteuid()
            or stat.S_IMODE(facts.st_mode) & 0o077
        ):
            raise ExportRefused("code_export_unsafe")
        encoded = os.read(descriptor, _MAX_RECORD_BYTES + 1)
    except OSError:
        raise ExportRefused("code_export_unsafe") from None
    finally:
        os.close(descriptor)
    if len(encoded) > _MAX_RECORD_BYTES:
        return None
    try:
        value = strict_json_parse(encoded.rstrip(b"\n"))
        source = cast(dict[str, JsonValue], value)
        if set(source) != {"schema", "export_id", "next_ref", "sent", "root"}:
            raise ValueError("members")
        if source["schema"] != EXPORT_SCHEMA:
            raise ValueError("schema")
        export_id = cast(str, source["export_id"])
        next_ref = cast(int, source["next_ref"])
        sent = tuple(cast(list[str], source["sent"]))
        root = source["root"]
        if not _EXPORT_ID.match(export_id) or type(next_ref) is not int or next_ref < 1:
            raise ValueError("values")
        if any(not _HEX.match(item.encode()) for item in sent):
            raise ValueError("sent")
        if root is not None and not _recordable_root(root):
            raise ValueError("root")
    except (ValueError, TypeError, AttributeError):
        return None
    return export_id, next_ref, sent, cast(str | None, root)


class ExportDatabase:
    """A FinishUP-owned store of git loose objects for one repository's copy on one target.

    ``<target root>/state/code-export/<repository key digest>/``: ``objects/xx/…`` (git's loose
    format, so ``git cat-file`` reads it in tests), and ``export.json`` with a random export id,
    the next ref number, the snapshot commits sent (the local mirror of the server's have-set,
    newest last) and ``root``: the repository's folder the latest sync read (its worktree's top,
    an absolute path; ``null`` before a sync read one, or for a path that cannot be shown), which
    ``server code forget --all`` claims to forget that repository's copy. Everything owner-only;
    never the repository's own object store, and this computer's own record: never sent.
    """

    __slots__ = ("_export_id", "_folder", "_next_ref", "_root", "_scanned", "_sent")

    def __init__(self, folder: Path) -> None:
        self._folder = folder
        try:
            ensure_owner_only_dir(folder)
            ensure_owner_only_dir(folder / "objects")
        except PathSafetyError:
            raise ExportRefused("code_export_unsafe") from None
        self._scanned: dict[str, bool] = {}
        record = _read_export_record(self._record_path())
        if record is None:
            # A record that cannot be read starts a new export: nothing it named is trusted.
            self._export_id = secrets.token_hex(16)
            self._next_ref = 1
            self._sent: tuple[str, ...] = ()
            self._root: str | None = None
            self._write_record()
        else:
            self._export_id, self._next_ref, self._sent, self._root = record

    @property
    def export_id(self) -> str:
        return self._export_id

    @property
    def present(self) -> bool:
        """Whether its folder still exists (``server code forget`` removes it from elsewhere)."""

        return (self._folder / _EXPORT_NAME).is_file()

    @property
    def sent(self) -> tuple[str, ...]:
        return self._sent

    @property
    def root(self) -> str | None:
        """The repository's folder the latest sync read, or None (see the class text)."""

        return self._root

    def _record_path(self) -> Path:
        return self._folder / _EXPORT_NAME

    def _write_record(self) -> None:
        document: dict[str, JsonValue] = {
            "schema": EXPORT_SCHEMA,
            "export_id": self._export_id,
            "next_ref": self._next_ref,
            "sent": list(self._sent),
            "root": self._root,
        }
        self._write_file(self._record_path(), canonical_encode(document) + b"\n")

    def remember_root(self, root: Path) -> None:
        """Record the repository's folder a sync read (written only when it changes).

        A path that cannot be kept as shown (not absolute and normal, not printable, too long)
        is recorded as ``null``: ``forget --all`` then says it cannot name that folder.
        """

        value = os.fspath(root)
        kept = value if _recordable_root(value) else None
        if kept != self._root:
            self._root = kept
            self._write_record()

    @staticmethod
    def _write_file(path: Path, data: bytes) -> None:
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(descriptor, view) :]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, path)
        except OSError:
            temporary.unlink(missing_ok=True)
            raise ExportRefused("code_export_unsafe") from None

    def _object_path(self, oid: str) -> Path:
        return self._folder / "objects" / oid[:2] / oid[2:]

    def has(self, oid: str) -> bool:
        return self._object_path(oid).is_file()

    def write(self, item: GitObject) -> None:
        path = self._object_path(item.oid)
        if path.is_file():
            return
        try:
            ensure_owner_only_dir(path.parent)
        except PathSafetyError:
            raise ExportRefused("code_export_unsafe") from None
        self._write_file(path, loose_encode(item))

    def read(self, oid: str, *, limit: int) -> GitObject:
        try:
            descriptor = os.open(self._object_path(oid), _OPEN_FILE)
        except OSError:
            raise ExportRefused("code_export_object_missing") from None
        try:
            raw = b""
            while chunk := os.read(descriptor, 1 << 20):
                raw += chunk
                if len(raw) > limit + 4_096:
                    raise ExportRefused("code_export_object_missing")
        finally:
            os.close(descriptor)
        try:
            return loose_decode(raw, oid, limit=limit)
        except CopyError:
            raise ExportRefused("code_export_object_missing") from None

    def blob_size(self, oid: str) -> int:
        """The size of a stored blob, from its loose header only."""

        try:
            with open(self._object_path(oid), "rb") as handle:  # noqa: PTH123
                head = zlib.decompressobj().decompress(handle.read(256), 64)
        except (OSError, zlib.error):
            raise ExportRefused("code_export_object_missing") from None
        header = head.partition(b"\x00")[0]
        kind, _space, size = header.partition(b" ")
        if kind != b"blob" or not size.isdigit():
            raise ExportRefused("code_export_object_missing")
        return int(size)

    def scanned(self, oid: str) -> bool | None:
        return self._scanned.get(oid)

    def remember_scan(self, oid: str, holds_secret: bool) -> None:
        self._scanned[oid] = holds_secret

    def next_ref(self) -> int:
        return self._next_ref

    def remember_sent(self, snapshot: str, ref_number: int) -> None:
        """Record a snapshot the server admitted (newest last, bounded)."""

        sent = tuple(item for item in self._sent if item != snapshot) + (snapshot,)
        self._sent = sent[-_MAX_SENT:]
        self._next_ref = max(self._next_ref, ref_number + 1)
        self._write_record()

    def forget_sent(self) -> None:
        """Forget what the server held (after a forget there, or a refused have-set)."""

        self._sent = ()
        self._write_record()

    def remove(self) -> None:
        """Delete this export database (``server code forget``, L2 → L1, ``server remove``)."""

        shutil.rmtree(self._folder, ignore_errors=True)


@dataclass(frozen=True, slots=True)
class ExportRecord:
    """One export folder of a target, as ``server code forget --all`` reads it.

    ``short_id`` names it on owner displays: the folder name's first 8 hex digits, or for an
    entry FinishUP did not name, the first 8 of its name's digest (the name itself is never
    shown). ``root`` is the repository's folder its record names, or None. ``readable`` is False
    for an entry whose record is missing, unsafe or malformed, or that is not a folder.
    """

    folder: Path
    short_id: str
    root: str | None
    readable: bool


def export_records(directory: Path) -> tuple[ExportRecord, ...]:
    """Every entry of a target's ``state/code-export`` folder, in name order; none when absent.

    Nothing is created, changed or followed. Raises ``ExportRefused("code_export_unsafe")`` when
    the folder itself is a link, not a folder, or cannot be listed: then which repositories
    copies were sent from is not known.
    """

    try:
        facts = os.lstat(directory)
    except (FileNotFoundError, NotADirectoryError):
        return ()
    except OSError:
        raise ExportRefused("code_export_unsafe") from None
    if not stat.S_ISDIR(facts.st_mode):
        raise ExportRefused("code_export_unsafe")
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        raise ExportRefused("code_export_unsafe") from None
    records: list[ExportRecord] = []
    for name in names:
        folder = directory / name
        if not _FOLDER_NAME.match(name):
            digest = hashlib.sha256(os.fsencode(name)).hexdigest()
            records.append(ExportRecord(folder, digest[:8], None, False))
            continue
        record: _Record | None = None
        try:
            if stat.S_ISDIR(os.lstat(folder).st_mode):
                record = _read_export_record(folder / _EXPORT_NAME)
        except (OSError, ExportRefused):
            record = None
        if record is None:
            records.append(ExportRecord(folder, name[:8], None, False))
        else:
            records.append(ExportRecord(folder, name[:8], record[3], True))
    return tuple(records)


# --- policy and request ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExportPolicy:
    """What leaves a repository's copy: the always-excluded list, the server's exclusions, the
    owner's per-repository choices, and the caps from the consented profile."""

    server: tuple[str, ...]
    owner: RepositoryCodeSettings
    max_file_bytes: int
    max_repo_bytes: int
    always: tuple[str, ...] = ALWAYS_EXCLUDED

    @property
    def patterns(self) -> tuple[str, ...]:
        return tuple(sorted({*self.always, *self.server, *self.owner.exclude}))

    def digest(self) -> str:
        return policy_digest(
            always=self.always,
            server=self.server,
            owner=self.owner.exclude,
            allowed=self.owner.allow,
            max_file_bytes=self.max_file_bytes,
            max_repo_bytes=self.max_repo_bytes,
        )


@dataclass(frozen=True, slots=True)
class ExportRequest:
    """One sync: the worktree, why it is synced, what the server holds, and the provenance the
    manifest carries (the consented revision, the claim's worktree digest, the subject state)."""

    root: Path
    purpose: Literal["base", "check"]
    have: tuple[str, ...]
    issuer: str
    revision: int
    profile_digest: str
    worktree: str
    subject_state: str | None = None
    base_commit: str | None = None


@dataclass(frozen=True, slots=True)
class PreparedExport:
    """A bundle ready to upload (empty when the server already holds this snapshot)."""

    manifest: SnapshotManifest
    bundle: bytes = field(repr=False)
    unchanged: bool
    ref_number: int

    @property
    def sha256(self) -> str:
        return "sha256:" + hashlib.sha256(self.bundle).hexdigest()


# --- reading the repository -------------------------------------------------------------------------


def _environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "HOME": os.devnull,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "XDG_CONFIG_HOME": os.devnull,
    }


def _git(root: Path, *arguments: str, stdin: bytes | None = None, check: bool = True) -> bytes:
    executable = shutil.which("git", path=os.defpath)
    if executable is None:
        raise ExportRefused("code_export_git_unavailable")
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            (executable, *_GIT_PREFIX, *arguments),
            cwd=root,
            input=stdin,
            stdin=None if stdin is not None else subprocess.DEVNULL,
            capture_output=True,
            timeout=_GIT_SECONDS,
            env=_environment(),
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise ExportRefused("code_export_git_failed") from None
    if (check and completed.returncode != 0) or len(completed.stdout) > _MAX_GIT_OUTPUT:
        raise ExportRefused("code_export_git_failed")
    return completed.stdout if completed.returncode == 0 else b""


def _global_excludes() -> str | None:
    """The owner's own global Git ignore file, so a file ignored everywhere stays out."""

    home = os.environ.get("HOME") or os.path.expanduser("~")
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
    candidate: str | None = None
    executable = shutil.which("git", path=os.defpath)
    if executable is not None:
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
                (executable, "config", "--global", "--path", "--get", "core.excludesFile"),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=10,
                env={
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "HOME": home,
                    "XDG_CONFIG_HOME": xdg,
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PATH": os.defpath,
                },
                cwd=home if os.path.isdir(home) else "/",
                check=False,
            )
            if completed.returncode == 0 and len(completed.stdout) <= 4_096:
                candidate = os.fsdecode(completed.stdout.rstrip(b"\n")) or None
        except (OSError, subprocess.SubprocessError):
            candidate = None
    if candidate is None:
        candidate = os.path.join(xdg, "git", "ignore")
    if not os.path.isabs(candidate) or any(mark in candidate for mark in "\0\n\r"):
        return None
    try:
        return candidate if stat.S_ISREG(os.stat(candidate).st_mode) else None
    except OSError:
        return None


def _nul_split(data: bytes) -> list[bytes]:
    return [item for item in data.split(b"\x00") if item]


@dataclass(frozen=True, slots=True)
class _Read:
    """One path as read: ``kind`` is ``file``, ``link``, ``gitlink``, ``absent``, ``directory`` or
    ``special``; ``data`` the bytes (file), target (link) or commit id (gitlink)."""

    kind: str
    data: bytes = field(default=b"", repr=False)
    executable: bool = False
    over: bool = False


def _read_beneath(root_fd: int, relative: bytes, limit: int) -> _Read:
    """Read ``relative`` beneath the root without following any link (see the module text)."""

    parts = relative.split(b"/")
    directory = root_fd
    opened: list[int] = []
    try:
        for part in parts[:-1]:
            try:
                directory = os.open(part, _OPEN_DIRECTORY, dir_fd=directory)
            except FileNotFoundError:
                return _Read("absent")
            except OSError:
                return _Read("special")
            opened.append(directory)
        name = parts[-1]
        try:
            facts = os.lstat(name, dir_fd=directory)
        except FileNotFoundError:
            return _Read("absent")
        except OSError:
            return _Read("special")
        if stat.S_ISLNK(facts.st_mode):
            try:
                target = os.readlink(name, dir_fd=directory)
            except OSError:
                return _Read("special")
            return _Read(
                "link", os.fsencode(target), over=len(os.fsencode(target)) > _MAX_LINK_BYTES
            )
        if stat.S_ISDIR(facts.st_mode):
            return _Read("directory")
        if not stat.S_ISREG(facts.st_mode):
            return _Read("special")
        try:
            descriptor = os.open(name, _OPEN_FILE, dir_fd=directory)
        except OSError:
            return _Read("special")
        try:
            opened_facts = os.fstat(descriptor)
            if not stat.S_ISREG(opened_facts.st_mode) or opened_facts.st_nlink != 1:
                return _Read("special")
            executable = bool(opened_facts.st_mode & stat.S_IXUSR)
            if opened_facts.st_size > limit:
                return _Read("file", executable=executable, over=True)
            chunks: list[bytes] = []
            remaining = limit + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(remaining, 1 << 20))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            return _Read("file", data, executable, over=len(data) > limit)
        except OSError:
            return _Read("special")
        finally:
            os.close(descriptor)
    finally:
        for descriptor in opened:
            os.close(descriptor)


def _hash_file_beneath(root_fd: int, relative: bytes) -> str | None:
    """The sha256 of a regular file's bytes (an LFS file's smudged content), streamed."""

    parts = relative.split(b"/")
    directory = root_fd
    opened: list[int] = []
    try:
        for part in parts[:-1]:
            directory = os.open(part, _OPEN_DIRECTORY, dir_fd=directory)
            opened.append(directory)
        descriptor = os.open(parts[-1], _OPEN_FILE, dir_fd=directory)
        try:
            facts = os.fstat(descriptor)
            if not stat.S_ISREG(facts.st_mode) or facts.st_size > _MAX_LFS_HASH_BYTES:
                return None
            digest = hashlib.sha256()
            while chunk := os.read(descriptor, 1 << 20):
                digest.update(chunk)
            return digest.hexdigest()
        finally:
            os.close(descriptor)
    except OSError:
        return None
    finally:
        for descriptor in opened:
            os.close(descriptor)


def _lfs_pointer(data: bytes) -> bytes | None:
    """The sha256 an LFS pointer names, when ``data`` is one."""

    if len(data) > _MAX_LFS_POINTER_BYTES or not _LFS_POINTER.match(data):
        return None
    found = _LFS_OID.search(data)
    return None if found is None else found.group(1)


# --- admission --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Entry:
    mode: bytes
    oid: str
    size: int


class _Admission:
    """The admitted entries and the held-out paths of one tree."""

    __slots__ = ("entries", "held", "objects")

    def __init__(self) -> None:
        self.entries: dict[bytes, _Entry] = {}
        self.held: dict[bytes, str] = {}
        self.objects: dict[str, GitObject] = {}


class _Exporter:
    __slots__ = ("counts", "database", "lfs", "policy", "root", "root_fd")

    def __init__(
        self, root: Path, root_fd: int, policy: ExportPolicy, database: ExportDatabase
    ) -> None:
        self.root = root
        self.root_fd = root_fd
        self.policy = policy
        self.database = database
        self.lfs: frozenset[bytes] = frozenset()
        self.counts: dict[str, int] = dict.fromkeys(COMPLETENESS_COUNTS, 0)

    # Each path goes through the same checks, in the same order, on both sides.
    def _name_refusal(self, path: bytes, mode: bytes) -> str | None:
        components = path.split(b"/")
        if len(path) > 4_096:
            return "unrepresentable"
        for index, component in enumerate(components):
            last = index == len(components) - 1
            if component_refusal(component, mode if last else MODE_TREE) is not None:
                return "unrepresentable"
        if excluded_by(path.decode("utf-8"), self.policy.patterns) is not None:
            return "excluded"
        return None

    def _secret(self, item: GitObject, path: str) -> bool:
        if self.policy.owner.allows(path, "sha256:" + hashlib.sha256(item.data).hexdigest()):
            return False
        known = self.database.scanned(item.oid)
        if known is None:
            known = holds_known_secret(item.data)
            self.database.remember_scan(item.oid, known)
        return known

    def admit(self, admission: _Admission, path: bytes, mode: bytes, data: bytes) -> None:
        """Admit one regular file or link of ``data``, or record why it is held out."""

        refusal = self._name_refusal(path, mode)
        if refusal is not None:
            admission.held[path] = refusal
            return
        if len(data) > self.policy.max_file_bytes:
            admission.held[path] = "too_large"
            return
        item = GitObject("blob", data)
        if self._secret(item, path.decode("utf-8")):
            admission.held[path] = "held_for_content"
            return
        admission.entries[path] = _Entry(mode, item.oid, len(data))
        admission.objects[item.oid] = item

    def admit_gitlink(self, admission: _Admission, path: bytes, commit: str) -> None:
        refusal = self._name_refusal(path, MODE_GITLINK)
        if refusal is not None:
            admission.held[path] = refusal
            return
        if not _HEX.match(commit.encode()) or len(commit) != 40:
            admission.held[path] = "unrepresentable"
            return
        admission.entries[path] = _Entry(MODE_GITLINK, commit, 0)

    # --- the base -------------------------------------------------------------------------------

    def base_listing(self, commit: str | None) -> list[bytes]:
        if commit is None:
            return []
        return _nul_split(_git(self.root, "ls-tree", "-r", "-z", "--full-tree", "--long", commit))

    def base(self, listing: list[bytes]) -> _Admission:
        admission = _Admission()
        blobs: list[tuple[bytes, bytes, str, int]] = []
        for line in listing:
            meta, _tab, path = line.partition(b"\t")
            fields = meta.split()
            if len(fields) != 4:
                raise ExportRefused("code_export_git_failed")
            mode, kind, oid = fields[0], fields[1], fields[2].decode("ascii")
            if kind == b"commit":
                self.admit_gitlink(admission, path, oid)
                continue
            if kind != b"blob" or mode not in {MODE_REGULAR, MODE_EXECUTABLE, MODE_LINK}:
                admission.held[path] = "unrepresentable"
                continue
            size = int(fields[3]) if fields[3].isdigit() else -1
            blobs.append((path, mode, oid, size))
        readable: list[tuple[bytes, bytes, str]] = []
        for path, mode, oid, size in blobs:
            if size < 0 or size > self.policy.max_file_bytes:
                refusal = self._name_refusal(path, mode)
                admission.held[path] = refusal or "too_large"
            else:
                readable.append((path, mode, oid))
        contents = self._cat_blobs([oid for _path, _mode, oid in readable])
        for path, mode, oid in readable:
            data = contents[oid]
            if path in self.lfs and _lfs_pointer(data) is None:
                admission.held[path] = "lfs_content"
                continue
            if path in self.lfs:
                self.counts["lfs_pointers"] += 1
            if mode == MODE_LINK and (len(data) > _MAX_LINK_BYTES or b"\x00" in data):
                admission.held[path] = "special"
                continue
            self.admit(admission, path, mode, data)
        return admission

    def _cat_blobs(self, oids: list[str]) -> dict[str, bytes]:
        if not oids:
            return {}
        unique = sorted(set(oids))
        output = _git(
            self.root, "cat-file", "--batch", stdin=b"".join(o.encode() + b"\n" for o in unique)
        )
        contents: dict[str, bytes] = {}
        position = 0
        for oid in unique:
            end = output.find(b"\n", position)
            header = output[position:end].split()
            if len(header) != 3 or header[0].decode() != oid or header[1] != b"blob":
                raise ExportRefused("code_export_git_failed")
            size = int(header[2])
            contents[oid] = output[end + 1 : end + 1 + size]
            position = end + 2 + size
        return contents

    # --- the current tree -----------------------------------------------------------------------

    def current_listing(self) -> tuple[dict[bytes, tuple[bytes, str]], list[bytes]]:
        """The index (path → mode, object id) and the untracked-not-ignored paths."""

        staged = _git(self.root, "ls-files", "-z", "--stage")
        index: dict[bytes, tuple[bytes, str]] = {}
        for line in _nul_split(staged):
            meta, _tab, path = line.partition(b"\t")
            fields = meta.split()
            if len(fields) != 3:
                raise ExportRefused("code_export_git_failed")
            index.setdefault(path, (fields[0], fields[1].decode("ascii")))
        arguments = ["ls-files", "-z", "--others", "--exclude-standard"]
        excludes = _global_excludes()
        if excludes is not None:
            arguments.append(f"--exclude-from={excludes}")
        untracked = [path for path in _nul_split(_git(self.root, *arguments)) if path not in index]
        return index, untracked

    def current(
        self, index: Mapping[bytes, tuple[bytes, str]], untracked: Iterable[bytes]
    ) -> _Admission:
        admission = _Admission()
        for path, (mode, oid) in sorted(index.items()):
            if mode == MODE_GITLINK:
                self.admit_gitlink(admission, path, oid)
                continue
            self._admit_worktree(admission, path, index_mode=mode, index_oid=oid)
        for path in sorted(untracked):
            if path.endswith(b"/"):
                admission.held[path.rstrip(b"/")] = "nested_repository"
                continue
            self._admit_worktree(admission, path, index_mode=None, index_oid=None)
        return admission

    def _admit_worktree(
        self,
        admission: _Admission,
        path: bytes,
        *,
        index_mode: bytes | None,
        index_oid: str | None,
    ) -> None:
        read = _read_beneath(self.root_fd, path, self.policy.max_file_bytes)
        if read.kind == "absent":
            return  # deleted: absent from the tree
        if read.kind == "directory":
            admission.held[path] = "nested_repository"
            return
        if read.kind == "special" or (read.kind == "link" and (read.over or b"\x00" in read.data)):
            refusal = self._name_refusal(path, MODE_REGULAR)
            if refusal == "excluded":
                admission.held[path] = refusal
                return
            admission.held[path] = "special"
            return
        if read.kind == "link":
            self.admit(admission, path, MODE_LINK, read.data)
            return
        if index_mode == MODE_LINK:
            # A link stored as a file (core.symlinks=false): its bytes are the target.
            if read.over or len(read.data) > _MAX_LINK_BYTES or b"\x00" in read.data:
                admission.held[path] = "special"
                return
            self.admit(admission, path, MODE_LINK, read.data)
            return
        mode = MODE_EXECUTABLE if read.executable else MODE_REGULAR
        if path in self.lfs:
            self._admit_lfs(admission, path, mode, read, index_oid)
            return
        if read.over:
            refusal = self._name_refusal(path, mode)
            admission.held[path] = refusal or "too_large"
            return
        self.admit(admission, path, mode, read.data)

    def _admit_lfs(
        self, admission: _Admission, path: bytes, mode: bytes, read: _Read, index_oid: str | None
    ) -> None:
        """An LFS file is sent as its pointer only: the worktree bytes when they are a pointer,
        else the index's pointer when it names exactly these bytes; never the content."""

        if not read.over and _lfs_pointer(read.data) is not None:
            self.counts["lfs_pointers"] += 1
            self.admit(admission, path, mode, read.data)
            return
        if index_oid is not None:
            pointer = self._cat_blobs([index_oid]).get(index_oid, b"")
            named = _lfs_pointer(pointer)
            if named is not None and _hash_file_beneath(self.root_fd, path) == named.decode():
                self.counts["lfs_pointers"] += 1
                self.admit(admission, path, mode, pointer)
                return
        refusal = self._name_refusal(path, mode)
        admission.held[path] = refusal or "lfs_content"

    def lfs_paths(self, paths: Iterable[bytes]) -> None:
        listed = sorted(set(paths))
        if not listed:
            return
        output = _git(
            self.root, "check-attr", "-z", "--stdin", "filter", stdin=b"\x00".join(listed) + b"\x00"
        )
        fields = output.split(b"\x00")
        found: set[bytes] = set()
        for index in range(0, len(fields) - 2, 3):
            if fields[index + 2] == b"lfs":
                found.add(fields[index])
        self.lfs = frozenset(found)


def _case_collisions(entries: Mapping[bytes, _Entry]) -> set[bytes]:
    """Paths whose name collides by case fold with an earlier name in the same directory."""

    seen: dict[tuple[bytes, str], bytes] = {}
    colliding: set[bytes] = set()
    names: set[tuple[bytes, bytes]] = set()
    for path in sorted(entries):
        parts = path.split(b"/")
        for depth in range(len(parts)):
            names.add((b"/".join(parts[:depth]), b"/".join(parts[: depth + 1])))
    for parent, path in sorted(names):
        name = path.rsplit(b"/", 1)[-1]
        key = (parent, folded_name(name))
        first = seen.setdefault(key, path)
        if first != path:
            colliding.add(path)
    return colliding


def _under(path: bytes, held: Iterable[bytes]) -> bool:
    return any(path == item or path.startswith(item + b"/") for item in held)


def _build_tree(
    entries: Mapping[bytes, _Entry], objects: dict[str, GitObject]
) -> tuple[str, int, int]:
    """The tree of ``entries`` (written into ``objects``); its id, size and file count."""

    children: dict[bytes, dict[bytes, _Entry]] = {}
    listed: list[TreeEntry] = []
    size = 0
    files = 0
    for path, entry in entries.items():
        head, _slash, rest = path.partition(b"/")
        if rest:
            children.setdefault(head, {})[rest] = entry
            continue
        listed.append(TreeEntry(entry.mode, head, entry.oid))
        size += entry.size
        files += 1
    for name, below in children.items():
        oid, below_size, below_files = _build_tree(below, objects)
        listed.append(TreeEntry(MODE_TREE, name, oid))
        size += below_size
        files += below_files
    tree = GitObject("tree", encode_tree(listed))
    objects[tree.oid] = tree
    return tree.oid, size, files


# --- the export ---------------------------------------------------------------------------------------


def _resolve_base(
    root: Path, requested: str | None
) -> tuple[str | None, Literal["sha1", "sha256"]]:
    try:
        named = _git(root, "rev-parse", "--show-object-format", check=False).strip()
    except ExportRefused:
        named = b""
    object_format: Literal["sha1", "sha256"] = "sha256" if named == b"sha256" else "sha1"
    if requested is not None:
        if not _HEX.match(requested.encode()):
            raise ExportRefused("code_export_base_unknown")
        found = _git(root, "rev-parse", "--verify", "-q", requested + "^{commit}", check=False)
        if found.strip().decode() != requested:
            raise ExportRefused("code_export_base_unknown")
        return requested, object_format
    head = _git(root, "rev-parse", "--verify", "-q", "HEAD^{commit}", check=False).strip()
    if not head:
        return None, object_format
    if not _HEX.match(head):
        raise ExportRefused("code_export_git_failed")
    return head.decode("ascii"), object_format


def _listed(paths: Iterable[bytes]) -> tuple[tuple[str, ...], int]:
    names = sorted({path.decode("utf-8", "replace") for path in paths})
    return tuple(names[:_MAX_LISTED]), max(0, len(names) - _MAX_LISTED)


def _closure(database: ExportDatabase, commits: Iterable[str], limit: int) -> dict[str, Held]:
    """Every object the given snapshot commits reach in the export database, as ``Held``."""

    held: dict[str, Held] = {}

    def tree(oid: str) -> tuple[int, int]:
        known = held.get(oid)
        if known is not None:
            return known.bytes, known.files
        item = database.read(oid, limit=1 << 20)
        size = 0
        files = 0
        for entry in decode_tree(item.data):
            if entry.mode == MODE_TREE:
                below, count = tree(entry.oid)
                size += below
                files += count
            elif entry.mode == MODE_GITLINK:
                files += 1
            else:
                blob = held.get(entry.oid)
                blob_size = blob.bytes if blob is not None else database.blob_size(entry.oid)
                held[entry.oid] = Held("blob", blob_size)
                size += blob_size
                files += 1
        held[oid] = Held("tree", size, files)
        return size, files

    for commit in commits:
        snapshot_tree, parent = decode_commit(database.read(commit, limit=limit).data)
        tree(snapshot_tree)
        held[commit] = Held("commit", tree=snapshot_tree)
        if parent is not None:
            base_tree, _none = decode_commit(database.read(parent, limit=limit).data)
            tree(base_tree)
            held[parent] = Held("commit", tree=base_tree)
    return held


def export_snapshot(
    request: ExportRequest,
    policy: ExportPolicy,
    database: ExportDatabase,
    *,
    gate: Callable[[], None],
    now: datetime | None = None,
) -> PreparedExport:
    """Build one sanitized snapshot of ``request.root`` (see the module text).

    ``gate`` runs first and raises (``ExportRefused`` or the caller's own refusal) when nothing may
    be exported; nothing is read or written before it returns.
    """

    gate()
    # Every listing is made from the worktree's top level (the locator may name a folder in it).
    top = _git(request.root, "rev-parse", "--show-toplevel").rstrip(b"\n")
    if not top.startswith(b"/"):
        raise ExportRefused("code_export_root_unavailable")
    root = Path(os.fsdecode(top))
    # The folder ``server code forget --all`` claims to forget this repository's copy.
    database.remember_root(root)
    base_commit, object_format = _resolve_base(root, request.base_commit)
    try:
        root_fd = os.open(root, _OPEN_DIRECTORY)
    except OSError:
        raise ExportRefused("code_export_root_unavailable") from None
    try:
        exporter = _Exporter(root, root_fd, policy, database)
        index, untracked = exporter.current_listing()
        listing = exporter.base_listing(base_commit)
        base_paths = [line.partition(b"\t")[2] for line in listing]
        exporter.lfs_paths([*index, *untracked, *base_paths])
        base = exporter.base(listing)
        current = exporter.current(index, untracked)
    finally:
        os.close(root_fd)
    for admission in (base, current):
        for path in _case_collisions(admission.entries):
            admission.held[path] = "case_collision"
    held_paths = {*base.held, *current.held}
    base_entries = {p: e for p, e in base.entries.items() if not _under(p, held_paths)}
    current_entries = {p: e for p, e in current.entries.items() if not _under(p, held_paths)}
    objects: dict[str, GitObject] = {}
    base_tree, _base_size, _base_files = _build_tree(base_entries, objects)
    tree, tree_bytes, tree_files = _build_tree(current_entries, objects)
    if tree_bytes > policy.max_repo_bytes:
        raise ExportRefused("code_copy_too_large")
    for admission in (base, current):
        for path, entry in admission.entries.items():
            if path in base_entries or path in current_entries:
                item = admission.objects.get(entry.oid)
                if item is not None:
                    objects[item.oid] = item
    base_object = GitObject("commit", encode_commit(base_tree, None))
    snapshot_object = GitObject("commit", encode_commit(tree, base_object.oid))
    objects[base_object.oid] = base_object
    objects[snapshot_object.oid] = snapshot_object
    for item in objects.values():
        database.write(item)
    # What the server holds: only snapshots this export database sent and still has.
    have = tuple(oid for oid in request.have if oid in database.sent and database.has(oid))
    held = _closure(database, have, 1 << 20)
    ref_number = database.next_ref()
    reasons: dict[str, set[bytes]] = {name: set() for name in COMPLETENESS_LISTS}
    counts = dict(exporter.counts)
    for path, reason in {**base.held, **current.held}.items():
        if reason in reasons:
            reasons[reason].add(path)
        elif reason == "special":
            counts["special"] += 1
        else:
            counts["unrepresentable"] += 1
    counts["links"] = sum(1 for e in current_entries.values() if e.mode == MODE_LINK)
    counts["gitlinks"] = sum(1 for e in current_entries.values() if e.mode == MODE_GITLINK)
    lists: dict[str, tuple[str, ...]] = {}
    more: dict[str, int] = {}
    for name in COMPLETENESS_LISTS:
        lists[name], more[name] = _listed(reasons[name])
    if base_commit is None:
        original = "0" * (64 if object_format == "sha256" else 40)
    else:
        original = base_commit
    manifest = SnapshotManifest(
        snapshot=snapshot_object.oid,
        base=base_object.oid,
        tree=tree,
        base_tree=base_tree,
        original_base_format=object_format,
        original_base=original,
        export_id=database.export_id,
        worktree=request.worktree,
        policy=policy.digest(),
        lists=lists,
        more=more,
        counts=counts,
        subject_state=request.subject_state,
        issuer=request.issuer,
        revision=request.revision,
        profile_digest=request.profile_digest,
        purpose=request.purpose,
        synced_at=format_rfc3339_ms(now or datetime.now(UTC)),
        files=tree_files,
        bytes=tree_bytes,
    )
    if snapshot_object.oid in held:
        return PreparedExport(manifest, b"", True, ref_number)
    send = [item for oid, item in objects.items() if oid not in held]
    bundle = write_bundle(have, snapshot_object.oid, ref_number, write_pack(send))
    _audit(bundle, held, objects, manifest, policy)
    return PreparedExport(manifest, bundle, False, ref_number)


def _audit(
    bundle: bytes,
    held: Mapping[str, Held],
    admitted: Mapping[str, GitObject],
    manifest: SnapshotManifest,
    policy: ExportPolicy,
) -> None:
    """The object-closure audit: the server's own verifier, plus "only what was admitted"."""

    try:
        verified = verify_snapshot_bundle(
            bundle,
            have=held.get,
            limits=BundleLimits(max_file_bytes=max(policy.max_file_bytes, _MAX_LINK_BYTES)),
        )
    except CopyError:
        raise ExportRefused("code_export_audit_failed") from None
    if (
        not set(verified.objects) <= set(admitted)
        or verified.snapshot != manifest.snapshot
        or verified.base != manifest.base
        or verified.tree != manifest.tree
        or verified.base_tree != manifest.base_tree
        or verified.tree_bytes != manifest.bytes
        or verified.tree_files != manifest.files
    ):
        raise ExportRefused("code_export_audit_failed")
