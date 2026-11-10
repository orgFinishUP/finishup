"""The server copy's wire format and its hostile-input verifier (level L2, design v2 §4, §8.1, §8.6).

At level L2 a FinishUP server keeps a copy of a repository's git-visible files, sent by the client
as git data (U6). What is sent is never the repository's own history: the client's exporter
(``client.code_export``) re-creates every object from the bytes it admitted, into a separate
export object database, and wraps the sanitized trees in **synthetic commits** of exactly two
shapes (``encode_commit``): a *base commit* (the sanitized task base, no parent) and a *snapshot
commit* (the sanitized working tree, whose one parent is that base commit). No original commit,
author, message or ancestry is ever an object; the original base commit id travels only as
provenance in the snapshot manifest.

The method ``git-bundle-1`` is a git bundle v2 (``# v2 git bundle``) with exactly one ref,
``refs/finishup/snap/<n>``, whose pack (v2) holds only whole blob, tree and commit objects, every
one hashed with SHA-1 by the client itself (the source repository's object format never
matters). ``verify_snapshot_bundle`` is the one verifier both sides run: the client's
object-closure audit before every upload and the server's admission. It refuses (``CopyError``
with a closed reason, never input text) delta and tag objects, a second ref, an object whose id
does not verify, a pack trailer that does not verify, unreachable objects, objects missing from
both the pack and what the receiver already holds, commits of any other shape, trees with an
invalid, unsorted, duplicate or case-colliding entry, a ``.git`` alias, unknown modes, links that
are too long or hold a NUL, and every size beyond the caps it is given: the inflated bytes of the
whole pack (before each object is inflated) and what a checkout of either tree expands to (its
paths, a subtree counted at every place it is referenced). What it verified is what a receiver
keeps of each object (``Held``), so the next, incremental bundle is held to the same bounds.

``SnapshotManifest`` (``yoetz.code-snapshot/1``) is the immutable record of one snapshot: the two
synthetic commits and trees, the original base commit as provenance, the export and worktree
identities, the digest of the exclusion policy that produced it, its completeness (what was left
out, and why), the client's subject-state commitment, the consented profile revision and when it
was synced (design v2 §8.6).

``L2_RELEASED`` is the release's switch for level L2. It is true: every protection design v2
§8.3 requires before a copy of code may leave a client exists (sync consent, the hold checked
before a bundle is built, encrypted storage, forget with the erasure of derived excerpts,
per-evidence provenance and the receipts that state it), and
``tests/unit/architecture/test_level_l2_released.py`` names each one and the tests that hold it.
A server still offers L2 only when its owner's ``[server.code_copy]`` table enables an offer, and
a client sends a copy only after its owner consented at L2 on the trusted console.

The module is pure: the standard library and ``protocol.canonical`` only.
"""

from __future__ import annotations

import hashlib
import re
import struct
import unicodedata
import zlib
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final, Literal, cast

from finishup.protocol.canonical import (
    JsonValue,
    ProtocolValueError,
    canonical_encode,
    strict_json_parse,
)

__all__ = [
    "BUNDLE_HEADER",
    "CODE_SYNC_METHOD",
    "COMPLETENESS_LISTS",
    "COMPLETENESS_COUNTS",
    "EVIDENCE_PROVENANCE",
    "L2_RELEASED",
    "MANIFEST_SCHEMA",
    "MAX_SNAPSHOT_ENTRIES",
    "MAX_SNAPSHOT_PATH_BYTES",
    "MODE_EXECUTABLE",
    "MODE_GITLINK",
    "MODE_LINK",
    "MODE_REGULAR",
    "MODE_TREE",
    "SNAPSHOT_REF_PREFIX",
    "SYNTHETIC_IDENTITY",
    "SYNTHETIC_MESSAGE",
    "BundleLimits",
    "CopyError",
    "GitObject",
    "Held",
    "SnapshotManifest",
    "TreeEntry",
    "VerifiedSnapshot",
    "component_refusal",
    "decode_commit",
    "decode_tree",
    "encode_commit",
    "encode_tree",
    "folded_name",
    "held_from_json",
    "held_to_json",
    "l2_released",
    "loose_decode",
    "loose_encode",
    "manifest_digest",
    "manifest_from_json",
    "manifest_to_json",
    "object_id",
    "policy_digest",
    "read_bundle",
    "read_pack",
    "verify_snapshot_bundle",
    "write_bundle",
    "write_pack",
]

# Level L2 is released (see the module text); ``tests/unit/architecture`` pins the value and the
# protections it rests on. Nothing a user can set changes it.
L2_RELEASED: Final = True


def l2_released() -> bool:
    """Whether level L2 is available in this release (``L2_RELEASED``)."""

    return L2_RELEASED


CODE_SYNC_METHOD: Final = "git-bundle-1"
BUNDLE_HEADER: Final = b"# v2 git bundle\n"
SNAPSHOT_REF_PREFIX: Final = b"refs/finishup/snap/"
SYNTHETIC_IDENTITY: Final = b"FinishUP export <export@finishup.invalid> 0 +0000"
SYNTHETIC_MESSAGE: Final = b"finishup snapshot\n"
MANIFEST_SCHEMA: Final = "yoetz.code-snapshot/1"
# Per-evidence provenance tokens (design v2 §8.6, ``yoetz.evidence-provenance/1``).
EVIDENCE_PROVENANCE: Final = (
    "server_copy_read",
    "client_attested_read",
    "client_check",
    "client_observation",
    "outside_read",
    "stale_copy_read",
)

MODE_REGULAR: Final = b"100644"
MODE_EXECUTABLE: Final = b"100755"
MODE_LINK: Final = b"120000"
MODE_GITLINK: Final = b"160000"
MODE_TREE: Final = b"40000"
_BLOB_MODES: Final = frozenset({MODE_REGULAR, MODE_EXECUTABLE, MODE_LINK})
_MODES: Final = frozenset({*_BLOB_MODES, MODE_GITLINK, MODE_TREE})

type ObjectKind = Literal["blob", "tree", "commit"]
_KINDS: Final[frozenset[str]] = frozenset({"blob", "tree", "commit"})
# Pack object type numbers (git's ``object_type``): 1 commit, 2 tree, 3 blob, 4 tag, 6/7 deltas.
_PACK_TYPES: Final[dict[int, ObjectKind]] = {1: "commit", 2: "tree", 3: "blob"}
_PACK_NUMBERS: Final[dict[str, int]] = {"commit": 1, "tree": 2, "blob": 3}
_HEX40: Final = re.compile(rb"^[0-9a-f]{40}$")
_HEX40_TEXT: Final = re.compile(r"^[0-9a-f]{40}$")
_HEX64_TEXT: Final = re.compile(r"^[0-9a-f]{64}$")
_DIGEST: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_EXPORT_ID: Final = re.compile(r"^[0-9a-f]{32}$")
_ISSUER: Final = re.compile(r"^[0-9a-f]{32}$")
_STAMP: Final = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$")
_REF_NUMBER: Final = re.compile(rb"^[1-9][0-9]{0,9}$")
_MAX_LINK_BYTES: Final = 4_096
_MAX_PATH_BYTES: Final = 4_096
_MAX_COMPONENT_BYTES: Final = 255
_MAX_TREE_DEPTH: Final = 128
# What one checkout of a tree may expand to: its paths (files, links, gitlinks and directories,
# a subtree counted again at every place it is referenced) and the bytes of those paths.
MAX_SNAPSHOT_ENTRIES: Final = 1_048_576
MAX_SNAPSHOT_PATH_BYTES: Final = 134_217_728
_MAX_META_OBJECT_BYTES: Final = 1_048_576
_MAX_PREREQUISITES: Final = 16
_CHUNK: Final = 65_536
# Code points HFS+ ignores in a name (git's ``is_hfs_dotgit``), so ``.g‌it`` is ``.git`` there.
_IGNORABLE: Final = re.compile("[‌‍‎‏‪‫‬‭‮⁪⁫⁬⁭⁮⁯﻿]")
# Files git itself reads from a tree: never a link (git fsck's ``.gitmodules`` rule, extended).
_GIT_META_NAMES: Final = frozenset({".gitmodules", ".gitattributes", ".gitignore", ".mailmap"})


class CopyError(ValueError):
    """A refused server-copy document; ``reason`` is a closed token, never input text."""

    reason: str

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


# --- objects --------------------------------------------------------------------------------------


def object_id(kind: str, data: bytes) -> str:
    """The SHA-1 git object id of ``data`` as an object of ``kind``."""

    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(f"{kind} {len(data)}\x00".encode("ascii"))
    digest.update(data)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class GitObject:
    """One whole git object: its kind and its content (no header)."""

    kind: ObjectKind
    data: bytes = field(repr=False)
    oid: str = field(default="", compare=False)

    def __post_init__(self) -> None:
        if self.kind not in _KINDS or type(self.data) is not bytes:
            raise CopyError("object_invalid")
        if not self.oid:
            object.__setattr__(self, "oid", object_id(self.kind, self.data))


def loose_encode(item: GitObject) -> bytes:
    """``item`` in git's loose-object form (zlib of ``<kind> <size>\\0<data>``)."""

    return zlib.compress(f"{item.kind} {len(item.data)}\x00".encode("ascii") + item.data, 6)


def loose_decode(raw: bytes, expected: str, *, limit: int) -> GitObject:
    """A loose object read back; refuses anything whose header, size or id does not verify."""

    inflater = zlib.decompressobj()
    try:
        plain = inflater.decompress(raw, limit + 64)
    except zlib.error:
        raise CopyError("object_unreadable") from None
    if not inflater.eof or inflater.unconsumed_tail or inflater.unused_data:
        raise CopyError("object_unreadable")
    header, separator, data = plain.partition(b"\x00")
    kind, space, size = header.partition(b" ")
    if not separator or not space or kind.decode("ascii", "replace") not in _KINDS:
        raise CopyError("object_unreadable")
    if not size.isdigit() or int(size) != len(data) or len(data) > limit:
        raise CopyError("object_unreadable")
    item = GitObject(cast(ObjectKind, kind.decode("ascii")), data)
    if item.oid != expected:
        raise CopyError("object_id_mismatch")
    return item


# --- paths and trees ------------------------------------------------------------------------------


def folded_name(name: bytes) -> str:
    """``name`` as a case-insensitive, normalizing filesystem compares it (raises for non-UTF-8):
    two names with the same fold are one file on such a filesystem."""

    text = name.decode("utf-8")
    return unicodedata.normalize("NFC", _IGNORABLE.sub("", text)).casefold()


def component_refusal(name: bytes, mode: bytes) -> str | None:
    """Why one tree entry name (``mode``) is never admitted, or ``None``.

    Names are UTF-8, one component (no ``/``, no NUL, not ``.`` or ``..``), at most 255 bytes, and
    never ``.git`` as any filesystem may read it (case, trailing dots or spaces, HFS+ ignorable
    code points, the NTFS short name ``git~1``, an NTFS stream). A file git reads from a tree
    (``.gitmodules``, ``.gitattributes``, ``.gitignore``, ``.mailmap``) is never a link.
    """

    if not name or name in {b".", b".."} or b"/" in name or b"\x00" in name:
        return "path_invalid"
    if len(name) > _MAX_COMPONENT_BYTES:
        return "path_invalid"
    try:
        folded = folded_name(name)
    except UnicodeDecodeError:
        return "path_not_utf8"
    trimmed = folded.rstrip(". ")
    if trimmed in {".git", "git~1"} or trimmed.startswith(".git:") or folded.startswith(".git:"):
        return "path_git_alias"
    if mode == MODE_LINK and trimmed in _GIT_META_NAMES:
        return "path_git_alias"
    return None


@dataclass(frozen=True, slots=True)
class TreeEntry:
    """One tree entry: ``mode`` as git writes it, the name (one component) and the object id."""

    mode: bytes
    name: bytes
    oid: str

    def sort_key(self) -> bytes:
        return self.name + b"/" if self.mode == MODE_TREE else self.name


def encode_tree(entries: Iterable[TreeEntry]) -> bytes:
    """The tree object of ``entries`` in git's order; refuses an entry ``decode_tree`` would."""

    ordered = sorted(entries, key=TreeEntry.sort_key)
    parts: list[bytes] = []
    for entry in ordered:
        if entry.mode not in _MODES or not _HEX40_TEXT.match(entry.oid):
            raise CopyError("tree_entry_invalid")
        parts.append(entry.mode + b" " + entry.name + b"\x00" + bytes.fromhex(entry.oid))
    data = b"".join(parts)
    decode_tree(data)
    return data


def decode_tree(data: bytes) -> tuple[TreeEntry, ...]:
    """A tree's entries; refuses unknown modes, invalid or unsorted names, duplicates and
    case-fold collisions (two names one filesystem would make the same file)."""

    entries: list[TreeEntry] = []
    position = 0
    folded: set[str] = set()
    previous: bytes | None = None
    while position < len(data):
        space = data.find(b" ", position, position + 8)
        if space < 0:
            raise CopyError("tree_invalid")
        mode = data[position:space]
        end = data.find(b"\x00", space + 1, space + 2 + _MAX_COMPONENT_BYTES)
        if mode not in _MODES or end < 0 or end + 21 > len(data):
            raise CopyError("tree_invalid")
        name = data[space + 1 : end]
        refusal = component_refusal(name, mode)
        if refusal is not None:
            raise CopyError(refusal)
        entry = TreeEntry(mode, name, data[end + 1 : end + 21].hex())
        key = entry.sort_key()
        if previous is not None and key <= previous:
            raise CopyError("tree_unsorted")
        previous = key
        fold = folded_name(name)
        if fold in folded:
            raise CopyError("tree_case_collision")
        folded.add(fold)
        entries.append(entry)
        position = end + 21
    return tuple(entries)


# --- synthetic commits ----------------------------------------------------------------------------


def encode_commit(tree: str, parent: str | None) -> bytes:
    """The one synthetic commit shape: ``tree``, at most one ``parent``, fixed identities and
    message. The base commit has no parent; a snapshot commit's parent is its base commit."""

    if not _HEX40_TEXT.match(tree) or (parent is not None and not _HEX40_TEXT.match(parent)):
        raise CopyError("commit_invalid")
    lines = [b"tree " + tree.encode("ascii")]
    if parent is not None:
        lines.append(b"parent " + parent.encode("ascii"))
    lines.append(b"author " + SYNTHETIC_IDENTITY)
    lines.append(b"committer " + SYNTHETIC_IDENTITY)
    return b"\n".join(lines) + b"\n\n" + SYNTHETIC_MESSAGE


def decode_commit(data: bytes) -> tuple[str, str | None]:
    """``(tree, parent)`` of a synthetic commit; refuses every other commit byte for byte."""

    if len(data) > 512 or not data.startswith(b"tree "):
        raise CopyError("commit_not_synthetic")
    tree = data[5:45]
    parent: bytes | None = None
    if data[45:53] == b"\nparent ":
        parent = data[53:93]
    if not _HEX40.match(tree) or (parent is not None and not _HEX40.match(parent)):
        raise CopyError("commit_not_synthetic")
    decoded = (tree.decode("ascii"), None if parent is None else parent.decode("ascii"))
    if encode_commit(*decoded) != data:
        raise CopyError("commit_not_synthetic")
    return decoded


# --- packs and bundles ----------------------------------------------------------------------------


def _pack_header(kind: ObjectKind, size: int) -> bytes:
    byte = (_PACK_NUMBERS[kind] << 4) | (size & 0x0F)
    size >>= 4
    out = bytearray()
    while size:
        out.append(byte | 0x80)
        byte = size & 0x7F
        size >>= 7
    out.append(byte)
    return bytes(out)


def write_pack(objects: Sequence[GitObject]) -> bytes:
    """A pack v2 of whole objects only (never a delta), with its SHA-1 trailer."""

    body = bytearray(b"PACK" + struct.pack(">II", 2, len(objects)))
    for item in objects:
        body += _pack_header(item.kind, len(item.data))
        body += zlib.compress(item.data, 6)
    body += hashlib.sha1(body, usedforsecurity=False).digest()
    return bytes(body)


@dataclass(frozen=True, slots=True)
class BundleLimits:
    """Caps a bundle is verified under (from the server profile's ``code_sync``).

    ``max_inflated_bytes`` bounds the inflated bytes of all the pack's objects together. Each
    object's declared size is added before that object is inflated, and the pack is refused
    (``pack_over_budget``) as soon as the sum passes the budget. Without it, a pack under
    ``max_bundle_bytes`` holding many distinct, highly compressible objects could allocate
    gigabytes. A receiver of a bundle it did not build passes a budget (the store passes what the
    copy's and the principal's quotas still allow); ``None`` keeps only the per-object caps (a
    sender auditing the bundle it just built from its own bytes).

    ``max_entries`` and ``max_path_bytes`` bound what a checkout of the base tree or of the
    snapshot tree expands to (``tree_too_many_entries``): its paths, every file, link, gitlink
    and directory, a subtree counted again at every place it is referenced, and the bytes of
    those paths. A few dozen small trees that reference each other twice describe a billion
    empty files; they are refused before the snapshot is admitted.
    """

    max_file_bytes: int
    max_bundle_bytes: int = 67_108_864
    max_objects: int = 200_000
    max_inflated_bytes: int | None = None
    max_entries: int = MAX_SNAPSHOT_ENTRIES
    max_path_bytes: int = MAX_SNAPSHOT_PATH_BYTES

    def __post_init__(self) -> None:
        for value in (
            self.max_file_bytes,
            self.max_bundle_bytes,
            self.max_objects,
            self.max_entries,
            self.max_path_bytes,
        ):
            if type(value) is not int or value < 1:
                raise CopyError("limits_invalid")
        budget = self.max_inflated_bytes
        if budget is not None and (type(budget) is not int or budget < 0):
            raise CopyError("limits_invalid")


def _inflate(view: memoryview, position: int, size: int) -> tuple[bytes, int]:
    """Inflate one zlib stream at ``position`` holding exactly ``size`` bytes; return the data and
    the position after the stream. Feeds bounded chunks, so nothing is copied twice."""

    inflater = zlib.decompressobj()
    out = bytearray()
    cursor = position
    end = len(view) - 20
    while not inflater.eof:
        if cursor >= end:
            raise CopyError("pack_truncated")
        chunk = view[cursor : min(cursor + _CHUNK, end)]
        try:
            out += inflater.decompress(chunk, size + 1 - len(out))
        except zlib.error:
            raise CopyError("pack_object_unreadable") from None
        if len(out) > size or inflater.unconsumed_tail:
            raise CopyError("pack_object_size_mismatch")
        cursor += len(chunk) - len(inflater.unused_data)
    if len(out) != size:
        raise CopyError("pack_object_size_mismatch")
    return bytes(out), cursor


def read_pack(data: bytes, limits: BundleLimits) -> dict[str, GitObject]:
    """Every object of a pack v2 of whole objects, by id; refuses deltas, tags, duplicates,
    oversized objects, a pack whose objects together inflate past the budget (checked before
    each object is inflated) and a trailer or count that does not verify."""

    if len(data) < 32 or data[:4] != b"PACK":
        raise CopyError("pack_invalid")
    version, count = struct.unpack(">II", data[4:12])
    if version != 2 or count > limits.max_objects:
        raise CopyError("pack_invalid")
    if hashlib.sha1(data[:-20], usedforsecurity=False).digest() != data[-20:]:
        raise CopyError("pack_checksum_mismatch")
    view = memoryview(data)
    position = 12
    objects: dict[str, GitObject] = {}
    budget = limits.max_inflated_bytes
    inflated = 0
    for _ in range(count):
        if position >= len(data) - 20:
            raise CopyError("pack_truncated")
        byte = data[position]
        number = (byte >> 4) & 0x07
        size = byte & 0x0F
        shift = 4
        position += 1
        while byte & 0x80:
            if position >= len(data) - 20 or shift > 35:
                raise CopyError("pack_invalid")
            byte = data[position]
            size |= (byte & 0x7F) << shift
            shift += 7
            position += 1
        if number in {6, 7}:
            raise CopyError("pack_delta_refused")
        kind = _PACK_TYPES.get(number)
        if kind is None:
            raise CopyError("pack_object_type_refused")
        cap = limits.max_file_bytes if kind == "blob" else _MAX_META_OBJECT_BYTES
        if size > cap:
            raise CopyError("pack_object_too_large")
        # The declared size bounds what ``_inflate`` may allocate (it refuses any other size).
        inflated += size
        if budget is not None and inflated > budget:
            raise CopyError("pack_over_budget")
        content, position = _inflate(view, position, size)
        item = GitObject(kind, content)
        if item.oid in objects:
            raise CopyError("pack_duplicate_object")
        objects[item.oid] = item
    if position != len(data) - 20:
        raise CopyError("pack_trailing_bytes")
    return objects


def write_bundle(prerequisites: Sequence[str], tip: str, ref_number: int, pack: bytes) -> bytes:
    """A git bundle v2 with ``prerequisites`` and the one ref ``refs/finishup/snap/<n>``."""

    if len(prerequisites) > _MAX_PREREQUISITES or not 1 <= ref_number <= 9_999_999_999:
        raise CopyError("bundle_invalid")
    lines = [BUNDLE_HEADER]
    for prerequisite in sorted(set(prerequisites)):
        if not _HEX40_TEXT.match(prerequisite):
            raise CopyError("bundle_invalid")
        lines.append(b"-" + prerequisite.encode("ascii") + b"\n")
    if not _HEX40_TEXT.match(tip):
        raise CopyError("bundle_invalid")
    lines.append(
        tip.encode("ascii") + b" " + SNAPSHOT_REF_PREFIX + str(ref_number).encode() + b"\n"
    )
    lines.append(b"\n")
    return b"".join(lines) + pack


@dataclass(frozen=True, slots=True)
class _Bundle:
    prerequisites: tuple[str, ...]
    tip: str
    ref_number: int
    pack: bytes = field(repr=False)


def read_bundle(data: bytes, limits: BundleLimits) -> _Bundle:
    """The header of a ``git-bundle-1`` bundle and its pack bytes (not yet parsed)."""

    if type(data) is not bytes or len(data) > limits.max_bundle_bytes:
        raise CopyError("bundle_too_large")
    if not data.startswith(BUNDLE_HEADER):
        raise CopyError("bundle_invalid")
    position = len(BUNDLE_HEADER)
    prerequisites: list[str] = []
    tip: str | None = None
    ref_number = 0
    while True:
        end = data.find(b"\n", position, position + 128)
        if end < 0:
            raise CopyError("bundle_invalid")
        line = data[position:end]
        position = end + 1
        if not line:
            break
        if line.startswith(b"-"):
            if tip is not None or not _HEX40.match(line[1:]):
                raise CopyError("bundle_invalid")
            prerequisites.append(line[1:].decode("ascii"))
            if len(prerequisites) > _MAX_PREREQUISITES:
                raise CopyError("bundle_invalid")
            continue
        oid, space, ref = line.partition(b" ")
        if tip is not None or not space or not _HEX40.match(oid):
            raise CopyError("bundle_ref_refused")
        number = ref.removeprefix(SNAPSHOT_REF_PREFIX)
        if number == ref or not _REF_NUMBER.match(number):
            raise CopyError("bundle_ref_refused")
        tip = oid.decode("ascii")
        ref_number = int(number)
    if tip is None or len(set(prerequisites)) != len(prerequisites):
        raise CopyError("bundle_invalid")
    return _Bundle(tuple(prerequisites), tip, ref_number, data[position:])


# --- the shared verifier --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Held:
    """What the receiver already holds of an object: its kind and, for a tree, the size and the
    number of files beneath it (for a blob, its size); for a commit, its tree.

    For a tree also what a checkout of it expands to, relative to the tree, so the tree can be
    checked where it is referenced again: ``entries`` (every path beneath it, directories
    included, a subtree counted at every place it is referenced) and ``names`` (the bytes of
    those paths, each component with its separator). For a blob whether it may be a link's
    target (``link_safe``: at most 4 KiB, no NUL), so a blob held as a file is never reused as a
    link it could not be. ``None``: not known (kept before these were recorded); the verifier
    refuses a reuse it cannot check.
    """

    kind: str
    bytes: int = 0
    files: int = 0
    tree: str | None = None
    entries: int | None = None
    names: int | None = None
    link_safe: bool | None = None


# The members after the first four were added later: an older entry reads them as unknown.
_HELD_MEMBERS: Final = 7


def held_to_json(held: Held) -> list[JsonValue]:
    """``held`` as the receiver keeps it in its index (a fixed-position list)."""

    return [
        held.kind,
        held.bytes,
        held.files,
        held.tree,
        held.entries,
        held.names,
        held.link_safe,
    ]


def _held_count(value: JsonValue) -> int | None:
    if type(value) is int and value >= 0:
        return value
    if value is None:
        return None
    raise CopyError("held_invalid")


def _held_flag(value: JsonValue) -> bool | None:
    if value is None or type(value) is bool:
        return value
    raise CopyError("held_invalid")


def held_from_json(value: JsonValue) -> Held:
    """An index entry ``held_to_json`` wrote (or a shorter one written before the later members
    were kept: those read as ``None``, unknown)."""

    if type(value) is not list or not 4 <= len(value) <= _HELD_MEMBERS:
        raise CopyError("held_invalid")
    members: list[JsonValue] = [*value, *([None] * (_HELD_MEMBERS - len(value)))]
    kind, size, files, tree, entries, names, link_safe = members
    if kind not in _KINDS or type(size) is not int or type(files) is not int:
        raise CopyError("held_invalid")
    if size < 0 or files < 0 or (tree is not None and type(tree) is not str):
        raise CopyError("held_invalid")
    return Held(
        kind,
        size,
        files,
        tree,
        _held_count(entries),
        _held_count(names),
        _held_flag(link_safe),
    )


def _link_safe(data: bytes) -> bool:
    return len(data) <= _MAX_LINK_BYTES and b"\x00" not in data


@dataclass(frozen=True, slots=True)
class VerifiedSnapshot:
    """What a verified bundle adds: its synthetic commits and trees, the objects it carries, and
    the sizes the receiver counts against its quotas.

    ``tree_bytes``/``tree_files`` are the snapshot tree's size and file count as a checkout would
    hold them (every path counted, gitlinks as empty files); ``new_bytes`` is what the pack adds;
    ``aggregates`` gives the same size and count for every tree the pack carries; ``held`` is
    what a receiver keeps of every object the pack carries (``Held``), for the next bundle.
    """

    snapshot: str
    base: str
    tree: str
    base_tree: str
    ref_number: int
    prerequisites: tuple[str, ...]
    objects: Mapping[str, GitObject] = field(repr=False)
    aggregates: Mapping[str, tuple[int, int]] = field(repr=False)
    new_bytes: int
    tree_bytes: int
    tree_files: int
    held: Mapping[str, Held] = field(default_factory=dict[str, Held], repr=False)


@dataclass(frozen=True, slots=True)
class _Shape:
    """A tree as a checkout expands it: size, files, and its paths and their bytes (``Held``)."""

    bytes: int
    files: int
    entries: int
    names: int


class _Walk:
    __slots__ = ("have", "limits", "objects", "reached", "shapes")

    def __init__(
        self,
        objects: Mapping[str, GitObject],
        have: Callable[[str], Held | None],
        limits: BundleLimits,
    ) -> None:
        self.objects = objects
        self.have = have
        self.limits = limits
        self.reached: set[str] = set()
        self.shapes: dict[str, _Shape] = {}

    def _bound(self, entries: int, names: int) -> None:
        # Checked as each tree is summed, so a hostile tree's counts never grow past the cap.
        if entries > self.limits.max_entries or names > self.limits.max_path_bytes:
            raise CopyError("tree_too_many_entries")

    def _held(self, oid: str) -> Held:
        held = self.have(oid)
        if held is None:
            raise CopyError("bundle_incomplete")
        return held

    def blob(self, oid: str, mode: bytes) -> int:
        """A blob entry in its mode here, whether in the pack or held: a held blob is checked
        against this placement as a blob in the pack is (a link's target, the file cap)."""

        item = self.objects.get(oid)
        if item is None:
            held = self._held(oid)
            if held.kind != "blob":
                raise CopyError("tree_entry_type_mismatch")
            if held.bytes > self.limits.max_file_bytes:
                raise CopyError("pack_object_too_large")
            if mode == MODE_LINK and held.link_safe is not True:
                raise CopyError("link_invalid")
            return held.bytes
        if item.kind != "blob":
            raise CopyError("tree_entry_type_mismatch")
        self.reached.add(oid)
        if mode == MODE_LINK and not _link_safe(item.data):
            raise CopyError("link_invalid")
        return len(item.data)

    def tree(self, oid: str, depth: int, path_bytes: int) -> _Shape:
        """Walk tree ``oid`` (each entry in the pack or held, typed as named); its shape."""

        if depth > _MAX_TREE_DEPTH:
            raise CopyError("tree_too_deep")
        item = self.objects.get(oid)
        if item is None:
            held = self._held(oid)
            if held.kind != "tree":
                raise CopyError("tree_entry_type_mismatch")
            if held.entries is None or held.names is None:
                raise CopyError("held_tree_unbounded")
            # Held by the receiver: its closure was verified when it was admitted.
            shape = _Shape(held.bytes, held.files, held.entries, held.names)
            self._bound(shape.entries, shape.names)
            return shape
        if item.kind != "tree":
            raise CopyError("tree_entry_type_mismatch")
        self.reached.add(oid)
        known = self.shapes.get(oid)
        if known is not None:
            return known
        size = 0
        files = 0
        entries = 0
        names = 0
        for entry in decode_tree(item.data):
            length = path_bytes + 1 + len(entry.name)
            if length > _MAX_PATH_BYTES:
                raise CopyError("path_invalid")
            step = 1 + len(entry.name)
            entries += 1
            names += step
            if entry.mode == MODE_TREE:
                below = self.tree(entry.oid, depth + 1, length)
                size += below.bytes
                files += below.files
                entries += below.entries
                # Every path beneath the subtree is prefixed by this entry's name here.
                names += below.names + below.entries * step
            elif entry.mode == MODE_GITLINK:
                if entry.oid in self.objects:
                    raise CopyError("gitlink_content_refused")
                files += 1
            else:
                size += self.blob(entry.oid, entry.mode)
                files += 1
            self._bound(entries, names)
        shape = _Shape(size, files, entries, names)
        self.shapes[oid] = shape
        return shape


def verify_snapshot_bundle(
    data: bytes,
    *,
    have: Callable[[str], Held | None],
    limits: BundleLimits,
) -> VerifiedSnapshot:
    """Verify a ``git-bundle-1`` snapshot bundle (see the module text) against what the receiver
    already holds (``have``). Every prerequisite must be a commit it holds; every object
    reachable from the ref must be in the pack or held; every object in the pack must be
    reachable; nothing may exceed ``limits``."""

    bundle = read_bundle(data, limits)
    for prerequisite in bundle.prerequisites:
        held = have(prerequisite)
        if held is None or held.kind != "commit":
            raise CopyError("bundle_prerequisite_unknown")
    objects = read_pack(bundle.pack, limits)
    walk = _Walk(objects, have, limits)
    tip = objects.get(bundle.tip)
    if tip is None or tip.kind != "commit":
        raise CopyError("bundle_tip_invalid")
    walk.reached.add(bundle.tip)
    tree, base = decode_commit(tip.data)
    if base is None:
        raise CopyError("commit_not_synthetic")
    base_object = objects.get(base)
    if base_object is not None:
        if base_object.kind != "commit":
            raise CopyError("commit_not_synthetic")
        walk.reached.add(base)
        base_tree, grandparent = decode_commit(base_object.data)
        if grandparent is not None:
            raise CopyError("commit_not_synthetic")
    else:
        held = have(base)
        if held is None or held.kind != "commit" or held.tree is None:
            raise CopyError("bundle_incomplete")
        base_tree = held.tree
    walk.tree(base_tree, 0, 0)
    shape = walk.tree(tree, 0, 0)
    if walk.reached != set(objects):
        raise CopyError("bundle_unreachable_object")
    kept: dict[str, Held] = {}
    for oid, item in objects.items():
        if item.kind == "blob":
            kept[oid] = Held("blob", len(item.data), link_safe=_link_safe(item.data))
        elif item.kind == "tree":
            below = walk.shapes[oid]
            kept[oid] = Held(
                "tree", below.bytes, below.files, entries=below.entries, names=below.names
            )
        else:
            kept[oid] = Held("commit", tree=tree if oid == bundle.tip else base_tree)
    return VerifiedSnapshot(
        snapshot=bundle.tip,
        base=base,
        tree=tree,
        base_tree=base_tree,
        ref_number=bundle.ref_number,
        prerequisites=bundle.prerequisites,
        objects=objects,
        aggregates={oid: (item.bytes, item.files) for oid, item in walk.shapes.items()},
        new_bytes=sum(len(item.data) for item in objects.values()),
        tree_bytes=shape.bytes,
        tree_files=shape.files,
        held=kept,
    )


# --- policy digest and the snapshot manifest ------------------------------------------------------

_POLICY_DOMAIN: Final = b"yoetz/code-exclusion-policy/v1\x00"
_MANIFEST_DOMAIN: Final = b"yoetz/code-snapshot/v1\x00"
_MAX_LISTED: Final = 256
_MAX_PATTERNS: Final = 512


def _patterns(values: Iterable[str]) -> list[JsonValue]:
    ordered = sorted(set(values))
    if len(ordered) > _MAX_PATTERNS or any(type(v) is not str or not v for v in ordered):
        raise CopyError("policy_invalid")
    return list(ordered)


def policy_digest(
    *,
    always: Iterable[str],
    server: Iterable[str],
    owner: Iterable[str],
    allowed: Iterable[tuple[str, str]],
    max_file_bytes: int,
    max_repo_bytes: int,
) -> str:
    """The digest of the exclusion policy a snapshot was made under (design v2 §8.6)."""

    allows = sorted(set(allowed))
    if any(not _DIGEST.match(content) for _path, content in allows):
        raise CopyError("policy_invalid")
    document: dict[str, JsonValue] = {
        "always": _patterns(always),
        "server": _patterns(server),
        "owner": _patterns(owner),
        "allowed": [[path, content] for path, content in allows],
        "max_file_bytes": max_file_bytes,
        "max_repo_bytes": max_repo_bytes,
    }
    return "sha256:" + hashlib.sha256(_POLICY_DOMAIN + canonical_encode(document)).hexdigest()


# Completeness: what a snapshot left out. Lists name paths (path only, never content); counts
# cover what is never named. ``*_more`` counts the names past the list bound.
COMPLETENESS_LISTS: Final = (
    "excluded",
    "held_for_content",
    "too_large",
    "lfs_content",
    "case_collision",
    "nested_repository",
)
COMPLETENESS_COUNTS: Final = ("links", "gitlinks", "lfs_pointers", "special", "unrepresentable")


@dataclass(frozen=True, slots=True)
class SnapshotManifest:
    """``yoetz.code-snapshot/1``: one immutable snapshot of a repository's server copy."""

    snapshot: str
    base: str
    tree: str
    base_tree: str
    original_base_format: Literal["sha1", "sha256"]
    original_base: str
    export_id: str
    worktree: str
    policy: str
    lists: Mapping[str, tuple[str, ...]]
    more: Mapping[str, int]
    counts: Mapping[str, int]
    subject_state: str | None
    issuer: str
    revision: int
    profile_digest: str
    purpose: Literal["base", "check"]
    synced_at: str
    files: int
    bytes: int

    def __post_init__(self) -> None:
        for oid in (self.snapshot, self.base, self.tree, self.base_tree):
            if not _HEX40_TEXT.match(oid):
                raise CopyError("manifest_invalid")
        pattern = _HEX40_TEXT if self.original_base_format == "sha1" else _HEX64_TEXT
        if self.original_base_format not in {"sha1", "sha256"} or not pattern.match(
            self.original_base
        ):
            raise CopyError("manifest_invalid")
        if not _EXPORT_ID.match(self.export_id) or not _ISSUER.match(self.issuer):
            raise CopyError("manifest_invalid")
        for digest in (self.worktree, self.policy, self.profile_digest):
            if not _DIGEST.match(digest):
                raise CopyError("manifest_invalid")
        if self.subject_state is not None and not _DIGEST.match(self.subject_state):
            raise CopyError("manifest_invalid")
        if set(self.lists) != set(COMPLETENESS_LISTS) or set(self.more) != set(COMPLETENESS_LISTS):
            raise CopyError("manifest_invalid")
        if set(self.counts) != set(COMPLETENESS_COUNTS):
            raise CopyError("manifest_invalid")
        for name, paths in self.lists.items():
            if (
                type(paths) is not tuple
                or len(paths) > _MAX_LISTED
                or list(paths) != sorted(set(paths))
                or any(type(p) is not str or not p or len(p) > _MAX_PATH_BYTES for p in paths)
            ):
                raise CopyError("manifest_invalid")
            _ = name
        for value in (*self.more.values(), *self.counts.values(), self.files, self.bytes):
            if type(value) is not int or value < 0:
                raise CopyError("manifest_invalid")
        if type(self.revision) is not int or self.revision < 1:
            raise CopyError("manifest_invalid")
        if self.purpose not in {"base", "check"} or not _STAMP.match(self.synced_at):
            raise CopyError("manifest_invalid")

    @property
    def held_out(self) -> int:
        """How many paths the snapshot left out, named or not."""

        return sum(len(paths) for paths in self.lists.values()) + sum(self.more.values())


_MANIFEST_KEYS: Final = frozenset(
    {
        "schema",
        "snapshot",
        "base",
        "tree",
        "base_tree",
        "original_base",
        "export_id",
        "worktree",
        "policy",
        "completeness",
        "subject_state",
        "revision",
        "purpose",
        "synced_at",
        "files",
        "bytes",
    }
)


def manifest_to_json(manifest: SnapshotManifest) -> dict[str, JsonValue]:
    """``manifest`` as its canonical JSON object."""

    completeness: dict[str, JsonValue] = {}
    for name in COMPLETENESS_LISTS:
        completeness[name] = {
            "paths": list(manifest.lists[name]),
            "more": manifest.more[name],
        }
    for name in COMPLETENESS_COUNTS:
        completeness[name] = manifest.counts[name]
    return {
        "schema": MANIFEST_SCHEMA,
        "snapshot": manifest.snapshot,
        "base": manifest.base,
        "tree": manifest.tree,
        "base_tree": manifest.base_tree,
        "original_base": {
            "object_format": manifest.original_base_format,
            "commit": manifest.original_base,
        },
        "export_id": manifest.export_id,
        "worktree": manifest.worktree,
        "policy": manifest.policy,
        "completeness": completeness,
        "subject_state": manifest.subject_state,
        "revision": {
            "issuer": manifest.issuer,
            "revision": manifest.revision,
            "profile_digest": manifest.profile_digest,
        },
        "purpose": manifest.purpose,
        "synced_at": manifest.synced_at,
        "files": manifest.files,
        "bytes": manifest.bytes,
    }


def _object_member(value: JsonValue, keys: frozenset[str]) -> Mapping[str, JsonValue]:
    if type(value) is not dict:
        raise CopyError("manifest_invalid")
    source = cast(dict[str, JsonValue], value)
    if frozenset(source) != keys:
        raise CopyError("manifest_invalid")
    return source


def manifest_from_json(value: JsonValue | bytes) -> SnapshotManifest:
    """A manifest from its JSON (strict: exact members, canonical bytes when given bytes)."""

    raw: bytes | None = None
    if isinstance(value, bytes):
        raw = value
        if len(raw) > 262_144:
            raise CopyError("manifest_invalid")
        try:
            value = strict_json_parse(raw)
        except (ProtocolValueError, ValueError):
            raise CopyError("manifest_invalid") from None
    source = _object_member(value, _MANIFEST_KEYS)
    if source["schema"] != MANIFEST_SCHEMA:
        raise CopyError("manifest_schema_unknown")
    original = _object_member(source["original_base"], frozenset({"object_format", "commit"}))
    revision = _object_member(
        source["revision"], frozenset({"issuer", "revision", "profile_digest"})
    )
    completeness = _object_member(
        source["completeness"], frozenset({*COMPLETENESS_LISTS, *COMPLETENESS_COUNTS})
    )
    lists: dict[str, tuple[str, ...]] = {}
    more: dict[str, int] = {}
    for name in COMPLETENESS_LISTS:
        entry = _object_member(completeness[name], frozenset({"paths", "more"}))
        paths = entry["paths"]
        if type(paths) is not list:
            raise CopyError("manifest_invalid")
        lists[name] = tuple(cast(list[str], paths))
        more[name] = cast(int, entry["more"])
    try:
        manifest = SnapshotManifest(
            snapshot=cast(str, source["snapshot"]),
            base=cast(str, source["base"]),
            tree=cast(str, source["tree"]),
            base_tree=cast(str, source["base_tree"]),
            original_base_format=cast(Literal["sha1", "sha256"], original["object_format"]),
            original_base=cast(str, original["commit"]),
            export_id=cast(str, source["export_id"]),
            worktree=cast(str, source["worktree"]),
            policy=cast(str, source["policy"]),
            lists=lists,
            more=more,
            counts={name: cast(int, completeness[name]) for name in COMPLETENESS_COUNTS},
            subject_state=cast(str | None, source["subject_state"]),
            issuer=cast(str, revision["issuer"]),
            revision=cast(int, revision["revision"]),
            profile_digest=cast(str, revision["profile_digest"]),
            purpose=cast(Literal["base", "check"], source["purpose"]),
            synced_at=cast(str, source["synced_at"]),
            files=cast(int, source["files"]),
            bytes=cast(int, source["bytes"]),
        )
    except (TypeError, AttributeError):
        raise CopyError("manifest_invalid") from None
    if raw is not None and canonical_encode(manifest_to_json(manifest)) != raw:
        raise CopyError("manifest_not_canonical")
    return manifest


def manifest_digest(manifest: SnapshotManifest) -> str:
    """The digest a pin, a receipt and the server's record name a snapshot by."""

    encoded = canonical_encode(manifest_to_json(manifest))
    return "sha256:" + hashlib.sha256(_MANIFEST_DOMAIN + encoded).hexdigest()
