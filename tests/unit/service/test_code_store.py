"""The server's store of repository copies, encrypted at rest (design v2 §4.3, §8.7, Q4, Q7)."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import keywrap
from tests.builders.server_copy import Snapshot, held_lookup, snapshot_objects

from finishup.protocol import server_copy
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.server_copy import (
    COMPLETENESS_COUNTS,
    COMPLETENESS_LISTS,
    MODE_LINK,
    MODE_REGULAR,
    MODE_TREE,
    BundleLimits,
    GitObject,
    SnapshotManifest,
    TreeEntry,
    encode_commit,
    encode_tree,
    manifest_from_json,
    manifest_to_json,
    verify_snapshot_bundle,
    write_bundle,
    write_pack,
)
from finishup.service import code_store
from finishup.service.code_store import CodeStore, CodeStoreError, StoreLimits, WrappedKey

MARKER = b"PLAINTEXT-MARKER-7f3a"
BASE = {"README.md": b"readme\n", "src/app.py": b"app " + MARKER + b"\n"}
CURRENT = {**BASE, "src/app.py": b"app v2 " + MARKER + b"\n", "src/new.py": b"new\n"}
REVISION = ("a" * 32, 2, "sha256:" + "b" * 64)
WORKTREE = "sha256:" + "c" * 64
LIMITS = StoreLimits(max_file_bytes=65_536, max_repo_bytes=1_048_576)


@dataclass
class MemoryKeyring:
    """The vault's per-copy keys, in memory: AES key wrap, discard deletes the key."""

    keys: dict[str, bytes] = field(default_factory=dict[str, bytes])
    locked: bool = False
    discarded: list[str] = field(default_factory=list[str])

    def wrap(self, copy_id: str, data_key: bytes) -> WrappedKey:
        if self.locked:
            raise CodeStoreError("vault_locked")
        key = self.keys.setdefault(copy_id, os.urandom(32))
        return WrappedKey(
            "aes-256-kw-rfc3394", f"code-copy:{copy_id}", keywrap.aes_key_wrap(key, data_key)
        )

    def unwrap(self, copy_id: str, wrapped: WrappedKey) -> bytes:
        if self.locked or copy_id not in self.keys:
            raise CodeStoreError("vault_locked")
        return keywrap.aes_key_unwrap(self.keys[copy_id], wrapped.wrapped)

    def discard(self, copy_id: str) -> None:
        self.discarded.append(copy_id)
        self.keys.pop(copy_id, None)


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 11, 10, 8, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


def _manifest(snap: Snapshot, bundle: bytes, **changes: object) -> bytes:
    verified = verify_snapshot_bundle(
        snap.bundle(), have=lambda _o: None, limits=BundleLimits(max_file_bytes=65_536)
    )
    manifest = SnapshotManifest(
        snapshot=snap.snapshot,
        base=snap.base,
        tree=snap.tree,
        base_tree=snap.base_tree,
        original_base_format="sha1",
        original_base="d" * 40,
        export_id="e" * 32,
        worktree=WORKTREE,
        policy="sha256:" + "f" * 64,
        lists={name: () for name in COMPLETENESS_LISTS},
        more=dict.fromkeys(COMPLETENESS_LISTS, 0),
        counts=dict.fromkeys(COMPLETENESS_COUNTS, 0),
        subject_state=None,
        issuer=REVISION[0],
        revision=REVISION[1],
        profile_digest=REVISION[2],
        purpose="check",
        synced_at="2026-11-10T08:00:00.000Z",
        files=verified.tree_files,
        bytes=verified.tree_bytes,
    )
    _ = bundle
    return canonical_encode(manifest_to_json(replace(manifest, **changes)))  # type: ignore[arg-type]


def _store(tmp_path: Path, keyring: MemoryKeyring | None = None, **options: object) -> CodeStore:
    tmp_path.mkdir(parents=True, exist_ok=True)
    store = CodeStore(
        tmp_path / "code-copies",
        keyring or MemoryKeyring(),
        options.pop("limits", LIMITS),  # type: ignore[arg-type]
        clock=options.pop("clock", Clock()),  # type: ignore[arg-type]
    )
    store.open()
    return store


def _upload(
    store: CodeStore,
    bundle: bytes,
    manifest: bytes,
    *,
    principal: str = "alice",
    repository: str = "repo-1",
    retention: tuple[str, int | None] = ("until_forgotten", None),
    chunk: int = 97,
    commit: bool = True,
    revision: tuple[str, int, str] = REVISION,
) -> object:
    upload = store.begin_upload(
        principal,
        repository,
        manifest=manifest,
        size=len(bundle),
        sha256="sha256:" + hashlib.sha256(bundle).hexdigest(),
        retention=retention,  # type: ignore[arg-type]
    )
    for offset in range(0, len(bundle), chunk):
        store.append(upload, principal, repository, offset, bundle[offset : offset + chunk])
    if not commit:
        return upload
    return store.commit(upload, principal, repository, revision=revision, worktree=WORKTREE)


def _all_bytes(folder: Path) -> list[tuple[Path, bytes]]:
    return [(path, path.read_bytes()) for path in folder.rglob("*") if path.is_file()]


def test_a_snapshot_is_admitted_read_back_and_kept_encrypted(tmp_path: Path) -> None:
    store = _store(tmp_path)
    snap = snapshot_objects(BASE, CURRENT)
    bundle = snap.bundle()
    receipt = _upload(store, bundle, _manifest(snap, bundle))
    assert receipt.snapshot == snap.snapshot  # type: ignore[attr-defined]
    assert store.have("alice", "repo-1") == (snap.snapshot,)
    manifest = store.snapshot("alice", "repo-1", snap.snapshot)
    assert manifest.tree == snap.tree and manifest.worktree == WORKTREE
    blob = next(oid for oid, item in snap.objects.items() if item.data == CURRENT["src/app.py"])
    assert store.read_object("alice", "repo-1", blob).data == CURRENT["src/app.py"]
    # Nothing on disk holds the code, a path or a principal in plaintext.
    for path, data in _all_bytes(tmp_path / "code-copies"):
        assert MARKER not in data, path
        assert b"src/app.py" not in data and b"alice" not in data and b"repo-1" not in data, path
        assert path.stat().st_mode & 0o077 == 0, path
    (summary,) = store.copies("alice")
    assert summary.snapshots == 1 and summary.retention_kind == "until_forgotten"
    assert store.copies("bob") == ()


def test_a_second_snapshot_needs_only_what_the_copy_lacks(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first = snapshot_objects(BASE, CURRENT)
    _upload(store, first.bundle(), _manifest(first, first.bundle()))
    second = snapshot_objects(BASE, {**CURRENT, "src/new.py": b"newer\n"})
    verified = verify_snapshot_bundle(
        first.bundle(), have=lambda _o: None, limits=BundleLimits(max_file_bytes=65_536)
    )
    held = held_lookup(first.objects, verified.aggregates)
    bundle = second.bundle(
        omit=frozenset(oid for oid in second.objects if held(oid) is not None),
        prerequisites=(first.snapshot,),
        ref_number=2,
    )
    receipt = _upload(store, bundle, _manifest(second, bundle))
    assert receipt.new_bytes < verified.new_bytes  # type: ignore[attr-defined]
    assert store.have("alice", "repo-1") == (first.snapshot, second.snapshot)


def test_a_locked_vault_admits_and_reads_nothing(tmp_path: Path) -> None:
    keyring = MemoryKeyring()
    store = _store(tmp_path, keyring)
    snap = snapshot_objects(BASE, CURRENT)
    _upload(store, snap.bundle(), _manifest(snap, snap.bundle()))
    keyring.locked = True
    with pytest.raises(CodeStoreError, match="vault_locked"):
        store.snapshot("alice", "repo-1", snap.snapshot)
    with pytest.raises(CodeStoreError, match="vault_locked"):
        _upload(store, snap.bundle(), _manifest(snap, snap.bundle()))


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"tree": "1" * 40}, "code_manifest_mismatch"),
        ({"bytes": 1}, "code_manifest_mismatch"),
        ({"worktree": "sha256:" + "9" * 64}, "code_manifest_mismatch"),
        ({"revision": 1}, "server_profile_changed"),
    ],
)
def test_a_manifest_that_does_not_match_what_was_verified_is_refused(
    tmp_path: Path, change: dict[str, object], reason: str
) -> None:
    store = _store(tmp_path)
    snap = snapshot_objects(BASE, CURRENT)
    with pytest.raises(CodeStoreError, match=reason):
        _upload(store, snap.bundle(), _manifest(snap, snap.bundle(), **change))
    assert store.copies("alice") == ()
    assert list((tmp_path / "code-copies" / "copies").iterdir()) == []


def test_hostile_or_broken_uploads_are_refused(tmp_path: Path) -> None:
    keyring = MemoryKeyring()
    store = _store(tmp_path, keyring)
    snap = snapshot_objects(BASE, CURRENT)
    bundle = snap.bundle()
    manifest = _manifest(snap, bundle)
    hostile = bundle.replace(b"refs/finishup/snap/1", b"refs/heads/snap/main")
    with pytest.raises(CodeStoreError, match="code_bundle_invalid"):
        _upload(store, hostile, manifest)
    # The never-admitted copy left nothing, not even its vault key.
    assert keyring.keys == {} and len(keyring.discarded) == 1
    upload = store.begin_upload(
        "alice",
        "repo-1",
        manifest=manifest,
        size=len(bundle),
        sha256="sha256:" + "0" * 64,
        retention=("until_forgotten", None),
    )
    store.append(upload, "alice", "repo-1", 0, bundle)
    with pytest.raises(CodeStoreError, match="code_upload_digest_mismatch"):
        store.commit(upload, "alice", "repo-1", revision=REVISION, worktree=WORKTREE)
    upload = _upload(store, bundle, manifest, commit=False, chunk=len(bundle))
    with pytest.raises(CodeStoreError, match="code_upload_unknown"):
        store.commit(str(upload), "mallory", "repo-1", revision=REVISION, worktree=WORKTREE)
    second = store.begin_upload(
        "alice",
        "repo-1",
        manifest=manifest,
        size=len(bundle),
        sha256="sha256:" + "0" * 64,
        retention=("until_forgotten", None),
    )
    with pytest.raises(CodeStoreError, match="code_upload_out_of_order"):
        store.append(second, "alice", "repo-1", 5, bundle[5:10])
    third = store.begin_upload(
        "alice",
        "repo-1",
        manifest=manifest,
        size=len(bundle),
        sha256="sha256:" + "0" * 64,
        retention=("until_forgotten", None),
    )
    store.append(third, "alice", "repo-1", 0, bundle[:10])
    with pytest.raises(CodeStoreError, match="code_upload_incomplete"):
        store.commit(third, "alice", "repo-1", revision=REVISION, worktree=WORKTREE)
    with pytest.raises(CodeStoreError, match="code_copy_too_large"):
        store.begin_upload(
            "alice",
            "repo-1",
            manifest=manifest,
            size=LIMITS.max_bundle_bytes + 1,
            sha256="sha256:" + "0" * 64,
            retention=("until_forgotten", None),
        )


def test_quotas_bound_a_copy_and_a_principal(tmp_path: Path) -> None:
    snap = snapshot_objects(BASE, CURRENT)
    # A checkout over the cap whose pack the copy's quota still holds: too large, not over quota.
    large = snapshot_objects(BASE, {**CURRENT, "big.bin": os.urandom(8_192)})
    large_verified = verify_snapshot_bundle(
        large.bundle(), have=lambda _o: None, limits=BundleLimits(max_file_bytes=65_536)
    )
    cap = large_verified.tree_bytes - 1
    assert 4 * cap >= large_verified.new_bytes
    tight = StoreLimits(max_file_bytes=65_536, max_repo_bytes=cap)
    with pytest.raises(CodeStoreError, match="code_copy_too_large"):
        _upload(
            _store(tmp_path / "a", limits=tight), large.bundle(), _manifest(large, large.bundle())
        )
    verified = verify_snapshot_bundle(
        snap.bundle(), have=lambda _o: None, limits=BundleLimits(max_file_bytes=65_536)
    )
    # Each copy fits, but the principal's four copies do not.
    limits = StoreLimits(
        max_file_bytes=65_536, max_repo_bytes=max(verified.tree_bytes, verified.new_bytes // 4 + 1)
    )
    store = _store(tmp_path / "b", limits=limits)
    admitted = 0
    with pytest.raises(CodeStoreError, match="code_copy_over_quota"):
        for number in range(40):
            _upload(
                store, snap.bundle(), _manifest(snap, snap.bundle()), repository=f"repo-{number}"
            )
            admitted += 1
    assert 0 < admitted < 40
    # Another principal has its own quota.
    _upload(store, snap.bundle(), _manifest(snap, snap.bundle()), principal="bob")


def test_a_pack_inflating_past_the_quota_left_is_refused_before_it_is_inflated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A4/B4: many distinct, highly compressible blobs in a tiny bundle.
    hostile = snapshot_objects(
        BASE, {f"f{number}.txt": bytes([65 + number]) * 60_000 for number in range(26)}
    )
    bundle = hostile.bundle()
    assert len(bundle) < 16_384
    manifest = _manifest(hostile, bundle)
    snap = snapshot_objects(BASE, CURRENT)
    snap_manifest = _manifest(snap, snap.bundle())
    inflated: list[int] = []
    real = server_copy._inflate  # pyright: ignore[reportPrivateUsage]

    def counting(view: memoryview, position: int, size: int) -> tuple[bytes, int]:
        inflated.append(size)
        return real(view, position, size)

    monkeypatch.setattr(server_copy, "_inflate", counting)
    limits = StoreLimits(max_file_bytes=65_536, max_repo_bytes=65_536)  # copy quota 256 KiB
    store = _store(tmp_path, limits=limits)
    with pytest.raises(CodeStoreError, match="code_copy_over_quota"):
        _upload(store, bundle, manifest)
    assert sum(inflated) <= limits.copy_quota
    assert len(inflated) < len(hostile.objects)
    assert store.have("alice", "repo-1") == ()
    # The principal's quota left bounds it too: alice's other copies used most of it.
    fit = sum(len(item.data) for item in snap.objects.values())
    principal = StoreLimits(max_file_bytes=65_536, max_repo_bytes=fit // 4 + 1)
    assert principal.copy_quota >= fit and principal.principal_quota < 5 * fit
    shared = _store(tmp_path / "principal", limits=principal)
    for number in range(4):
        _upload(shared, snap.bundle(), snap_manifest, repository=f"r{number}")
    inflated.clear()
    with pytest.raises(CodeStoreError, match="code_copy_over_quota"):
        _upload(shared, snap.bundle(), snap_manifest, repository="r4")
    assert len(inflated) < len(snap.objects)
    # Bob's budget is his own.
    _upload(shared, snap.bundle(), snap_manifest, principal="bob")


def _doubled(levels: int, leaf: str, *extra: GitObject) -> tuple[Snapshot, int]:
    """A snapshot whose tree doubles ``levels`` times over ``leaf`` (a tree id); its file count."""

    objects = {item.oid: item for item in extra}
    inner = leaf
    for _ in range(levels):
        tree = GitObject(
            "tree",
            encode_tree([TreeEntry(MODE_TREE, b"a", inner), TreeEntry(MODE_TREE, b"b", inner)]),
        )
        objects[tree.oid] = tree
        inner = tree.oid
    empty = GitObject("tree", b"")
    base = GitObject("commit", encode_commit(empty.oid, None))
    tip = GitObject("commit", encode_commit(inner, base.oid))
    for item in (empty, base, tip):
        objects[item.oid] = item
    return Snapshot(base.oid, tip.oid, empty.oid, inner, objects), 2**levels


def _unverified_manifest(snap: Snapshot, files: int) -> bytes:
    manifest = manifest_from_json(_manifest(snapshot_objects(BASE, CURRENT), b""))
    return canonical_encode(
        manifest_to_json(
            replace(
                manifest,
                snapshot=snap.snapshot,
                base=snap.base,
                tree=snap.tree,
                base_tree=snap.base_tree,
                files=files,
                bytes=0,
            )
        )
    )


def test_a_snapshot_expanding_to_a_billion_files_is_never_admitted(tmp_path: Path) -> None:
    # A5/B5: dozens of objects, zero content bytes, 2**30 empty files in a checkout.
    blob = GitObject("blob", b"")
    leaf = GitObject("tree", encode_tree([TreeEntry(MODE_REGULAR, b"f", blob.oid)]))
    hostile, files = _doubled(30, leaf.oid, blob, leaf)
    store = _store(tmp_path)
    with pytest.raises(CodeStoreError, match="code_bundle_invalid"):
        _upload(store, hostile.bundle(), _unverified_manifest(hostile, files))
    assert store.have("alice", "repo-1") == ()
    # The bound holds across uploads: a held subtree placed again is counted from the index.
    small, small_files = _doubled(6, leaf.oid, blob, leaf)
    _upload(store, small.bundle(), _unverified_manifest(small, small_files))
    grown, grown_files = _doubled(16, small.tree)
    grown_objects = {oid: item for oid, item in grown.objects.items() if oid not in small.objects}
    incremental = write_bundle(
        (small.snapshot,), grown.snapshot, 2, write_pack(list(grown_objects.values()))
    )
    with pytest.raises(CodeStoreError, match="code_bundle_invalid"):
        _upload(store, incremental, _unverified_manifest(grown, grown_files * small_files))
    assert store.have("alice", "repo-1") == (small.snapshot,)


def test_a_held_file_is_never_admitted_again_as_a_link_it_could_not_be(tmp_path: Path) -> None:
    # B7: a regular file holding NUL, then an incremental snapshot naming it as a link.
    store = _store(tmp_path)
    first = snapshot_objects(BASE, {**CURRENT, "data.bin": b"a\x00b", "note": b"../README.md"})
    _upload(store, first.bundle(), _manifest(first, first.bundle()))
    held = held_lookup(first.objects, {})
    for target, admitted in ((b"a\x00b", False), (b"../README.md", True)):
        blob = GitObject("blob", target).oid
        tree = GitObject("tree", encode_tree([TreeEntry(MODE_LINK, b"l", blob)]))
        base = GitObject("commit", encode_commit(first.base_tree, None))
        tip = GitObject("commit", encode_commit(tree.oid, base.oid))
        assert held(blob) is not None and base.oid == first.base
        objects = {tree.oid: tree, tip.oid: tip}
        snap = Snapshot(first.base, tip.oid, first.base_tree, tree.oid, objects)
        bundle = write_bundle((first.snapshot,), tip.oid, 2, write_pack(list(objects.values())))
        manifest = _unverified_manifest(snap, 1)
        manifest = canonical_encode(
            manifest_to_json(replace(manifest_from_json(manifest), bytes=len(target)))
        )
        if admitted:
            _upload(store, bundle, manifest)
            continue
        with pytest.raises(CodeStoreError, match="code_bundle_invalid"):
            _upload(store, bundle, manifest)
        assert store.have("alice", "repo-1") == (first.snapshot,)


def test_a_held_subtree_grafted_deeper_is_refused_by_the_index_bounds(tmp_path: Path) -> None:
    # B8: the copy's index keeps each tree's height, so placing it deeper is checked.
    blob = GitObject("blob", b"leaf")
    inner = GitObject("tree", encode_tree([TreeEntry(MODE_REGULAR, b"f", blob.oid)]))
    objects = {blob.oid: blob, inner.oid: inner}
    for _ in range(100):
        inner = GitObject("tree", encode_tree([TreeEntry(MODE_TREE, b"d", inner.oid)]))
        objects[inner.oid] = inner
    empty = GitObject("tree", b"")
    base = GitObject("commit", encode_commit(empty.oid, None))
    tip = GitObject("commit", encode_commit(inner.oid, base.oid))
    for item in (empty, base, tip):
        objects[item.oid] = item
    first = Snapshot(base.oid, tip.oid, empty.oid, inner.oid, objects)
    store = _store(tmp_path)
    _upload(store, first.bundle(), _manifest(first, b""))
    for levels, admitted in ((28, True), (29, False)):
        top = inner.oid
        added: dict[str, GitObject] = {}
        for _ in range(levels):
            tree = GitObject("tree", encode_tree([TreeEntry(MODE_TREE, b"g", top)]))
            added[tree.oid] = tree
            top = tree.oid
        graft_tip = GitObject("commit", encode_commit(top, base.oid))
        added[graft_tip.oid] = graft_tip
        snap = Snapshot(base.oid, graft_tip.oid, empty.oid, top, added)
        manifest = canonical_encode(
            manifest_to_json(
                replace(manifest_from_json(_unverified_manifest(snap, 1)), bytes=len(b"leaf"))
            )
        )
        bundle = write_bundle((first.snapshot,), graft_tip.oid, 2, write_pack(list(added.values())))
        if admitted:
            _upload(store, bundle, manifest)
            continue
        with pytest.raises(CodeStoreError, match="code_bundle_invalid"):
            _upload(store, bundle, manifest)


def test_a_snapshot_on_a_held_snapshot_commit_is_refused(tmp_path: Path) -> None:
    # B10: the copy keeps which held commits are bases; a held snapshot commit is not one.
    store = _store(tmp_path)
    first = snapshot_objects(BASE, CURRENT)
    _upload(store, first.bundle(), _manifest(first, first.bundle()))
    blob = GitObject("blob", b"new\n")
    tree = GitObject("tree", encode_tree([TreeEntry(MODE_REGULAR, b"n", blob.oid)]))
    for parent, admitted in ((first.snapshot, False), (first.base, True)):
        tip = GitObject("commit", encode_commit(tree.oid, parent))
        objects = {tip.oid: tip, tree.oid: tree, blob.oid: blob}
        snap = Snapshot(parent, tip.oid, first.base_tree, tree.oid, objects)
        manifest = canonical_encode(
            manifest_to_json(
                replace(manifest_from_json(_unverified_manifest(snap, 1)), bytes=len(blob.data))
            )
        )
        if parent == first.snapshot:
            manifest = canonical_encode(
                manifest_to_json(replace(manifest_from_json(manifest), base_tree=first.tree))
            )
        bundle = write_bundle((first.snapshot,), tip.oid, 2, write_pack(list(objects.values())))
        if admitted:
            _upload(store, bundle, manifest)
            continue
        with pytest.raises(CodeStoreError, match="code_bundle_invalid"):
            _upload(store, bundle, manifest)
        assert store.have("alice", "repo-1") == (first.snapshot,)


def test_one_principal_never_reaches_another_s_copy(tmp_path: Path) -> None:
    store = _store(tmp_path)
    snap = snapshot_objects(BASE, CURRENT)
    _upload(store, snap.bundle(), _manifest(snap, snap.bundle()))
    assert store.have("bob", "repo-1") == ()
    with pytest.raises(CodeStoreError, match="code_snapshot_unknown"):
        store.snapshot("bob", "repo-1", snap.snapshot)
    with pytest.raises(CodeStoreError, match="code_copy_unknown"):
        store.read_object("bob", "repo-1", snap.tree)
    assert store.forget("bob").copies == 0
    assert store.have("alice", "repo-1") == (snap.snapshot,)


def test_forget_deletes_the_copy_and_its_key_exactly_once(tmp_path: Path) -> None:
    keyring = MemoryKeyring()
    store = _store(tmp_path, keyring)
    snap = snapshot_objects(BASE, CURRENT)
    _upload(store, snap.bundle(), _manifest(snap, snap.bundle()))
    _upload(store, snap.bundle(), _manifest(snap, snap.bundle()), repository="repo-2")
    store.pin("alice", "repo-1", "task_1", snap.snapshot)
    report = store.forget("alice", "repo-1")
    assert (report.copies, report.snapshots) == (1, 1)
    assert report.objects == len(snap.objects) and report.bytes > 0
    assert report.to_json()["backups"] == "not_managed"
    assert store.have("alice", "repo-1") == () and store.pinned("alice", "repo-1", "task_1") is None
    assert len(keyring.keys) == 1
    again = store.forget("alice", "repo-1")
    assert (again.copies, again.objects, again.bytes) == (0, 0, 0)
    everything = store.forget("alice")
    assert everything.copies == 1 and store.copies("alice") == ()
    assert keyring.keys == {}


def test_forget_fences_an_upload_already_in_flight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    snap = snapshot_objects(BASE, CURRENT)
    bundle = snap.bundle()
    upload = _upload(store, bundle, _manifest(snap, bundle), commit=False)
    store.forget("alice")
    with pytest.raises(CodeStoreError, match="code_upload_unknown"):
        store.commit(str(upload), "alice", "repo-1", revision=REVISION, worktree=WORKTREE)
    # Even if the upload survived the forget, its epoch fences it (the tombstone came first).
    upload = _upload(store, bundle, _manifest(snap, bundle), commit=False)

    def keep_upload(_self: CodeStore, _upload_id: str) -> None:
        return None

    monkeypatch.setattr(CodeStore, "_drop_upload", keep_upload)
    store.forget("alice", "repo-1")
    monkeypatch.undo()
    with pytest.raises(CodeStoreError, match="code_copy_forgotten"):
        store.commit(str(upload), "alice", "repo-1", revision=REVISION, worktree=WORKTREE)
    assert store.copies("alice") == ()


def test_expiry_follows_the_retention_chosen(tmp_path: Path) -> None:
    clock = Clock()
    store = _store(tmp_path, clock=clock)
    snap = snapshot_objects(BASE, CURRENT)
    _upload(
        store,
        snap.bundle(),
        _manifest(snap, snap.bundle()),
        repository="days",
        retention=("days", 7),
    )
    _upload(
        store,
        snap.bundle(),
        _manifest(snap, snap.bundle()),
        repository="close",
        retention=("task_close", None),
    )
    _upload(
        store,
        snap.bundle(),
        _manifest(snap, snap.bundle()),
        repository="kept",
        retention=("until_forgotten", None),
    )
    store.pin("alice", "close", "task_1", snap.snapshot)
    store.pin("alice", "close", "task_2", snap.snapshot)
    closed = {"task_1"}
    clock.now += timedelta(days=6)
    assert store.expire(task_closed=closed.__contains__).copies == 0
    clock.now += timedelta(days=1)
    report = store.expire(task_closed=closed.__contains__)
    assert report.copies == 1 and report.reason == "expired"
    assert store.have("alice", "days") == ()
    closed.add("task_2")
    assert store.expire(task_closed=closed.__contains__).copies == 1
    clock.now += timedelta(days=3650)
    assert store.expire(task_closed=closed.__contains__).copies == 0
    assert [summary.retention_kind for summary in store.copies("alice")] == ["until_forgotten"]


def test_an_unchanged_sync_refreshes_retention_metadata_and_sync_time(tmp_path: Path) -> None:
    """C2: nothing is uploaded, but the consent as it is now and the sync time hold."""

    clock = Clock()
    store = _store(tmp_path, clock=clock)
    snap = snapshot_objects(BASE, CURRENT)
    _upload(store, snap.bundle(), _manifest(snap, snap.bundle()))
    epoch = store.epoch("alice", "repo-1")
    clock.now += timedelta(days=3)
    fresh = _manifest(
        snap,
        snap.bundle(),
        subject_state="sha256:" + "5" * 64,
        synced_at="2026-11-13T08:00:00.000Z",
    )
    refreshed = store.refresh(
        "alice",
        "repo-1",
        manifest=fresh,
        retention=("days", 1),
        epoch=epoch,
        revision=REVISION,
        worktree=WORKTREE,
    )
    assert refreshed.subject_state == "sha256:" + "5" * 64
    stored = store.snapshot("alice", "repo-1", snap.snapshot)
    assert stored.subject_state == refreshed.subject_state
    assert stored.synced_at == "2026-11-13T08:00:00.000Z"
    (summary,) = store.copies("alice")
    assert (summary.retention_kind, summary.retention_days) == ("days", 1)
    assert summary.last_sync_at == "2026-11-13T08:00:00.000Z"
    # In use: kept a day after the last sync, not three days after the upload ...
    clock.now += timedelta(hours=23)
    assert store.expire(task_closed=lambda _task: False).copies == 0
    # ... and the shorter retention chosen since holds.
    clock.now += timedelta(hours=2)
    assert store.expire(task_closed=lambda _task: False).copies == 1
    assert store.copies("alice") == ()


def test_an_unchanged_sync_is_validated_and_fenced_by_a_forget(tmp_path: Path) -> None:
    store = _store(tmp_path)
    snap = snapshot_objects(BASE, CURRENT)
    _upload(store, snap.bundle(), _manifest(snap, snap.bundle()))
    epoch = store.epoch("alice", "repo-1")
    other = snapshot_objects(BASE, {**CURRENT, "src/other.py": b"other\n"})

    def refresh(manifest: bytes, **changes: object) -> CodeStoreError:
        values: dict[str, object] = {
            "manifest": manifest,
            "retention": ("days", 1),
            "epoch": epoch,
            "revision": REVISION,
            "worktree": WORKTREE,
        }
        values.update(changes)
        with pytest.raises(CodeStoreError) as raised:
            store.refresh("alice", "repo-1", **values)  # type: ignore[arg-type]
        return raised.value

    same = _manifest(snap, snap.bundle())
    assert refresh(_manifest(other, other.bundle())).reason == "code_snapshot_unknown"
    assert refresh(_manifest(snap, snap.bundle(), tree=other.tree)).reason == (
        "code_manifest_mismatch"
    )
    assert refresh(_manifest(snap, snap.bundle(), files=99)).reason == "code_manifest_mismatch"
    assert refresh(same, worktree="sha256:" + "9" * 64).reason == "code_manifest_mismatch"
    assert refresh(same, revision=("a" * 32, 3, REVISION[2])).reason == "server_profile_changed"
    assert refresh(same, retention=("days", None)).reason == "code_upload_invalid"
    assert refresh(b"{}").reason == "code_manifest_invalid"
    (summary,) = store.copies("alice")
    assert summary.retention_kind == "until_forgotten"
    # A forget since the sync began fences it: nothing is refreshed or made again.
    assert store.forget("alice", "repo-1").copies == 1
    assert refresh(same).reason == "code_copy_forgotten"
    assert store.copies("alice") == ()


def test_the_closed_task_question_is_asked_with_the_store_free(tmp_path: Path) -> None:
    """The question may wait for the service loop, which may be waiting for this store: it is
    asked with the lock released, and a copy a task pinned meanwhile is not forgotten."""

    import threading

    store = _store(tmp_path)
    snap = snapshot_objects(BASE, CURRENT)
    _upload(
        store,
        snap.bundle(),
        _manifest(snap, snap.bundle()),
        repository="close",
        retention=("task_close", None),
    )
    store.pin("alice", "close", "task_1", snap.snapshot)

    def from_the_loop(task: str) -> bool:
        answered = threading.Event()
        threading.Thread(
            target=lambda: (store.pending_erasures(), answered.set()), daemon=True
        ).start()
        return answered.wait(5.0) and task == "task_1"

    report = store.expire(task_closed=from_the_loop)
    assert report.copies == 1
    assert store.copies("alice") == ()

    _upload(
        store,
        snap.bundle(),
        _manifest(snap, snap.bundle()),
        repository="close",
        retention=("task_close", None),
    )
    store.pin("alice", "close", "task_1", snap.snapshot)

    def while_another_task_reads_it(task: str) -> bool:
        store.pin("alice", "close", "task_2", snap.snapshot)
        return task == "task_1"

    assert store.expire(task_closed=while_another_task_reads_it).copies == 0
    assert [summary.retention_kind for summary in store.copies("alice")] == ["task_close"]


def test_a_crash_leaves_the_previous_snapshot_in_force_and_start_removes_the_rest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    first = snapshot_objects(BASE, CURRENT)
    _upload(store, first.bundle(), _manifest(first, first.bundle()))
    second = snapshot_objects(BASE, {**CURRENT, "x.py": b"x\n"})
    real = code_store._write_private  # pyright: ignore[reportPrivateUsage]

    def crash(path: Path, data: bytes) -> None:
        if path.name == "copy.json":
            raise CodeStoreError("code_store_unsafe")
        real(path, data)

    monkeypatch.setattr(code_store, "_write_private", crash)
    with pytest.raises(CodeStoreError):
        _upload(store, second.bundle(), _manifest(second, second.bundle()))
    monkeypatch.undo()
    assert store.have("alice", "repo-1") == (first.snapshot,)
    # A process that stopped part way: a staged upload and a first copy without its record.
    _upload(
        store, first.bundle(), _manifest(first, first.bundle()), repository="other", commit=False
    )
    orphan = tmp_path / "code-copies" / "copies" / ("0" * 32)
    (orphan / "objects").mkdir(parents=True)
    (orphan / "objects" / "x").write_bytes(b"ciphertext")
    restarted = _store(tmp_path)
    assert list((tmp_path / "code-copies" / "uploads").iterdir()) == []
    assert not orphan.exists()
    assert restarted.have("alice", "repo-1") == (first.snapshot,)


def test_a_forget_never_drops_an_erasure_it_cannot_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Past the pending-erasure bound (e.g. a locked vault keeps erasures from completing), a
    forget keeps the copy, fenced, and says it is not complete; it never deletes a copy whose
    tasks' excerpts it could not record for erasure (U20)."""

    monkeypatch.setattr(code_store, "_MAX_PENDING_ERASURES", 3)
    clock = Clock()
    store = _store(tmp_path, clock=clock)
    snap = snapshot_objects(BASE, CURRENT)
    for repository in ("repo-1", "repo-2"):
        _upload(store, snap.bundle(), _manifest(snap, snap.bundle()), repository=repository)
    store.pin("alice", "repo-1", "task_1", snap.snapshot)
    store.pin("alice", "repo-1", "task_2", snap.snapshot)
    store.pin("alice", "repo-2", "task_3", snap.snapshot)
    store.pin("alice", "repo-2", "task_4", snap.snapshot)
    first = store.forget("alice", "repo-1")
    assert first.complete and first.to_json()["complete"] is True and first.copies == 1
    second = store.forget("alice", "repo-2")
    assert (second.copies, second.left, second.complete) == (0, 1, False)
    assert second.to_json()["complete"] is False and second.tasks == ()
    from finishup.protocol.schemas import validate_schema_instance

    forgot = {key: value for key, value in second.to_json().items() if key != "reason"}
    validate_schema_instance(
        "control-result",
        "2.10.0",
        {  # pyright: ignore[reportArgumentType]
            "protocol_version": "1.0",
            "rpc_id": "rpc_12345678-1234-4123-8123-123456789abc",
            "service_instance_id": "svc_12345678-1234-4123-8123-123456789abc",
            "service_generation": "1",
            "method": "code_copy",
            "outcome": "ok",
            "body": {"action": "forget", "copy": None, "forgot": forgot},
        },
    )
    # Nothing of the copy went and nothing was half-recorded; fenced, it serves nothing more.
    assert [item.snapshots for item in store.copies("alice")] == [1]
    assert {item.task_id for item in store.pending_erasures()} == {"task_1", "task_2"}
    assert store.have("alice", "repo-2") == () and store.pinned("alice", "repo-2", "task_3") is None
    # No new copy is made over it, and an expiry run that finds the same backlog keeps it too.
    with pytest.raises(CodeStoreError, match="code_copy_erasure_backlog"):
        _upload(store, snap.bundle(), _manifest(snap, snap.bundle()), repository="repo-2")
    clock.now += timedelta(days=2)
    expired = store.expire(task_closed=lambda _task: True)
    assert (expired.copies, expired.complete) == (0, False)
    assert [item.snapshots for item in store.copies("alice")] == [1]
    # Once the backlog drains, the next expiry run finishes it: every task recorded, then gone.
    for pending in store.pending_erasures():
        store.complete_erasure(pending.forget_id, pending.task_id)
    finished = store.expire(task_closed=lambda _task: True)
    assert finished.complete and finished.copies == 1
    assert {item.task_id for item in store.pending_erasures()} == {"task_3", "task_4"}
    assert store.copies("alice") == () and store.forget("alice", "repo-2").complete


def _copy_folder(tmp_path: Path) -> Path:
    (folder,) = list((tmp_path / "code-copies" / "copies").iterdir())
    return folder


def test_a_forgotten_copy_that_reappears_is_never_read_and_goes_at_start(
    tmp_path: Path,
) -> None:
    """A power loss can bring back directory entries a forget removed: a copy whose record is
    older than its tombstone's epoch is rejected by every read and removed at start, and its
    tasks' erasures are recorded once, under the same forget (§8.7)."""

    import shutil

    keyring = MemoryKeyring()
    store = _store(tmp_path, keyring)
    snap = snapshot_objects(BASE, CURRENT)
    _upload(store, snap.bundle(), _manifest(snap, snap.bundle()))
    store.pin("alice", "repo-1", "task_1", snap.snapshot)
    original = _copy_folder(tmp_path)
    saved = tmp_path / "saved"
    shutil.copytree(original, saved)
    key_id = next(iter(keyring.keys))
    key = keyring.keys[key_id]
    assert store.forget("alice", "repo-1").complete
    (pending,) = store.pending_erasures()
    # The deletion did not reach the disk: the folder (and the wrapped key) are back.
    shutil.copytree(saved, original)
    keyring.keys[key_id] = key
    assert store.have("alice", "repo-1") == ()
    assert store.latest("alice", "repo-1") is None and store.copies("alice") != ()
    with pytest.raises(CodeStoreError, match="code_snapshot_unknown"):
        store.snapshot("alice", "repo-1", snap.snapshot)
    with pytest.raises(CodeStoreError, match="code_copy_unknown"):
        store.read_object("alice", "repo-1", snap.tree)
    assert store.task_entry("alice", "task_1") is None
    with pytest.raises(CodeStoreError, match="code_snapshot_unknown"):
        store.pin("alice", "repo-1", "task_2", snap.snapshot)
    restarted = _store(tmp_path, keyring)
    assert list((tmp_path / "code-copies" / "copies").iterdir()) == []
    assert restarted.copies("alice") == ()
    assert restarted.pending_erasures() == (pending,)
    # A new copy after that is a copy again (its record carries the new epoch).
    _upload(restarted, snap.bundle(), _manifest(snap, snap.bundle()))
    assert restarted.have("alice", "repo-1") == (snap.snapshot,)
    assert _store(tmp_path, keyring).have("alice", "repo-1") == (snap.snapshot,)


def test_a_forget_is_durable_before_it_is_acknowledged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The record (with the wrapped key) goes first and that is fsynced, then the rest, then the
    ``copies`` folder is fsynced; the tombstone was written (fsynced) before any of it."""

    store = _store(tmp_path)
    snap = snapshot_objects(BASE, CURRENT)
    _upload(store, snap.bundle(), _manifest(snap, snap.bundle()))
    folder = _copy_folder(tmp_path)
    events: list[str] = []
    real_fsync = code_store._fsync_directory  # pyright: ignore[reportPrivateUsage]
    real_unlink = os.unlink

    def fsync(path: Path) -> None:
        events.append("fsync " + ("copy" if path == folder else path.name))
        real_fsync(path)

    def unlink(path: object, *args: object, **kwargs: object) -> None:
        if os.fspath(path) == os.fspath(folder / "copy.json"):  # type: ignore[arg-type]
            events.append("unlink record")
        real_unlink(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(code_store, "_fsync_directory", fsync)
    monkeypatch.setattr(code_store.os, "unlink", unlink)
    assert store.forget("alice", "repo-1").complete
    assert events == ["unlink record", "fsync copy", "fsync copies"]
    assert not folder.exists()


def test_a_deletion_that_fails_is_fenced_not_complete_and_finished_later(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    snap = snapshot_objects(BASE, CURRENT)
    _upload(store, snap.bundle(), _manifest(snap, snap.bundle()))
    store.pin("alice", "repo-1", "task_1", snap.snapshot)
    folder = _copy_folder(tmp_path)
    real_rmtree = code_store.shutil.rmtree

    def rmtree(path: object, *args: object, **kwargs: object) -> None:
        del path, args, kwargs  # nothing is removed

    monkeypatch.setattr(code_store.shutil, "rmtree", rmtree)
    report = store.forget("alice", "repo-1")
    assert (report.copies, report.complete) == (0, False)
    assert [task.task_id for task in report.tasks] == ["task_1"]
    # The record and its wrapped key went first; the ciphertext left is read by nothing.
    assert folder.exists() and not (folder / "copy.json").exists()
    assert store.have("alice", "repo-1") == () and store.copies("alice") == ()
    again = store.forget("alice", "repo-1")
    assert not again.complete
    monkeypatch.setattr(code_store.shutil, "rmtree", real_rmtree)
    assert store.forget("alice", "repo-1").complete and not folder.exists()
    assert [item.task_id for item in store.pending_erasures()] == ["task_1"]


def test_a_record_written_before_epochs_is_forgotten_by_a_newer_tombstone(
    tmp_path: Path,
) -> None:
    import json

    clock = Clock()
    store = _store(tmp_path, clock=clock)
    snap = snapshot_objects(BASE, CURRENT)
    _upload(store, snap.bundle(), _manifest(snap, snap.bundle()))
    record_path = _copy_folder(tmp_path) / "copy.json"
    record = json.loads(record_path.read_bytes())
    assert record["epoch"] == 0
    del record["epoch"]
    record_path.write_bytes(canonical_encode(record))
    assert _store(tmp_path, clock=clock).have("alice", "repo-1") == (snap.snapshot,)
    tombstones = tmp_path / "code-copies" / "tombstones.json"
    later = (clock.now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    document = {
        "schema": "yoetz.code-copy-tombstones/1",
        "epochs": {record["copy_key"]: {"epoch": 1, "forgotten_at": later, "reason": "owner"}},
    }
    tombstones.write_bytes(canonical_encode(document))
    os.chmod(tombstones, 0o600)
    assert _store(tmp_path, clock=clock).copies("alice") == ()


def _second(first: Snapshot) -> tuple[Snapshot, bytes]:
    second = snapshot_objects(BASE, {**CURRENT, "src/more.py": b"more " + MARKER + b"\n"})
    verified = verify_snapshot_bundle(
        first.bundle(), have=lambda _o: None, limits=BundleLimits(max_file_bytes=65_536)
    )
    held = held_lookup(first.objects, verified.aggregates)
    bundle = second.bundle(
        omit=frozenset(oid for oid in second.objects if held(oid) is not None),
        prerequisites=(first.snapshot,),
        ref_number=2,
    )
    return second, bundle


@pytest.mark.parametrize("stopped", ["failed", "crashed"])
def test_an_admission_that_stops_before_its_record_leaves_nothing_outside_the_quota(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stopped: str
) -> None:
    """Objects and the next index are written before the record: until the record names the
    new generation, the previous one is in force, and what was added goes (at once after a
    failure, at the next start after a crash), so no later upload can lean on uncharged bytes."""

    keyring = MemoryKeyring()
    store = _store(tmp_path, keyring)
    first = snapshot_objects(BASE, CURRENT)
    _upload(store, first.bundle(), _manifest(first, first.bundle()))
    folder = _copy_folder(tmp_path)
    before = sorted(path.name for path in (folder / "objects").iterdir())
    stored = store.copies("alice")[0].stored_bytes
    second, bundle = _second(first)
    real = code_store._write_private  # pyright: ignore[reportPrivateUsage]

    def stop(path: Path, data: bytes) -> None:
        if path.name == "copy.json":
            raise CodeStoreError("code_store_unsafe")
        real(path, data)

    monkeypatch.setattr(code_store, "_write_private", stop)
    if stopped == "crashed":
        # The process dies: nothing runs after the failed write.
        def dies(_self: CodeStore, _key: str) -> bool:
            return True

        monkeypatch.setattr(CodeStore, "_recover", dies)
    with pytest.raises(CodeStoreError):
        _upload(store, bundle, _manifest(second, bundle))
    monkeypatch.undo()
    if stopped == "crashed":
        assert sorted(path.name for path in (folder / "objects").iterdir()) != before
        store = _store(tmp_path, keyring)  # the next start
    assert sorted(path.name for path in (folder / "objects").iterdir()) == before
    assert sorted(path.name for path in folder.iterdir()) == [
        "copy.json",
        "index.1.enc",
        "objects",
        "snapshots",
    ]
    assert sorted(path.name for path in (folder / "snapshots").iterdir()) == [
        f"{first.snapshot}.enc"
    ]
    assert store.copies("alice")[0].stored_bytes == stored
    # A later upload that leans on the uncommitted snapshot as held is refused, and the same
    # snapshot sent again is charged in full.
    third = snapshot_objects(
        BASE, {**CURRENT, "src/more.py": b"more " + MARKER + b"\n", "z": b"z\n"}
    )
    lean = third.bundle(
        omit=frozenset(oid for oid in third.objects if oid in second.objects),
        prerequisites=(second.snapshot,),
        ref_number=3,
    )
    with pytest.raises(CodeStoreError, match="code_bundle_invalid"):
        _upload(store, lean, _manifest(third, lean))
    receipt = _upload(store, bundle, _manifest(second, bundle))
    assert receipt.stored_bytes == stored + receipt.new_bytes > stored  # type: ignore[attr-defined]
    assert sorted(path.name for path in folder.iterdir()) == [
        "copy.json",
        "index.2.enc",
        "objects",
        "snapshots",
    ]
    assert store.have("alice", "repo-1") == (first.snapshot, second.snapshot)
    assert _store(tmp_path, keyring).have("alice", "repo-1") == (first.snapshot, second.snapshot)


def test_a_pinned_snapshot_outlives_the_recent_window_until_no_pin_names_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A task's reviewer and offline reads read its pinned snapshot: newer syncs past the recent
    window never take it away; it leaves once no pin names it (design v2 §8.6)."""

    monkeypatch.setattr(code_store, "_MAX_SNAPSHOTS", 2)
    store = _store(tmp_path)
    snaps = [snapshot_objects(BASE, {**CURRENT, "n.py": f"{n}\n".encode()}) for n in range(5)]
    _upload(store, snaps[0].bundle(), _manifest(snaps[0], snaps[0].bundle()))
    store.pin("alice", "repo-1", "task_1", snaps[0].snapshot, served=True)
    for snap in snaps[1:]:
        _upload(store, snap.bundle(), _manifest(snap, snap.bundle()))
    folder = _copy_folder(tmp_path)
    first, gone = snaps[0].snapshot, snaps[1].snapshot
    assert store.have("alice", "repo-1") == (first, snaps[3].snapshot, snaps[4].snapshot)
    assert store.snapshot("alice", "repo-1", first).snapshot == first
    assert store.pin_entry("alice", "repo-1", "task_1") is not None
    assert store.manifest_with_base("alice", "repo-1", snaps[0].base) is not None
    store.pin("alice", "repo-1", "task_1", first, stale=True)  # still pinnable
    with pytest.raises(CodeStoreError, match="code_snapshot_unknown"):
        store.snapshot("alice", "repo-1", gone)
    assert not (folder / "snapshots" / f"{gone}.enc").exists()
    # The pin moves to a newer snapshot: the old one is past the window and leaves.
    store.pin("alice", "repo-1", "task_1", snaps[4].snapshot)
    assert store.have("alice", "repo-1") == (snaps[3].snapshot, snaps[4].snapshot)
    with pytest.raises(CodeStoreError, match="code_snapshot_unknown"):
        store.snapshot("alice", "repo-1", first)
    assert not (folder / "snapshots" / f"{first}.enc").exists()


def test_uploads_are_charged_to_their_authenticated_account_not_the_copy_namespace(
    tmp_path: Path,
) -> None:
    """Copies of every claim share one owning namespace (``COPY_PRINCIPAL``); the principal
    quota is charged per authenticated account, so one account filling its quota never blocks
    another's uploads (and without an account, the namespace is charged as before)."""

    snap = snapshot_objects(BASE, CURRENT)
    verified = verify_snapshot_bundle(
        snap.bundle(), have=lambda _o: None, limits=BundleLimits(max_file_bytes=65_536)
    )
    limits = StoreLimits(
        max_file_bytes=65_536, max_repo_bytes=max(verified.tree_bytes, verified.new_bytes // 4 + 1)
    )
    store = _store(tmp_path, limits=limits)

    def upload(repository: str, account: str | None) -> object:
        bundle = snap.bundle()
        upload_id = store.begin_upload(
            "claim",
            repository,
            manifest=_manifest(snap, bundle),
            size=len(bundle),
            sha256="sha256:" + hashlib.sha256(bundle).hexdigest(),
            retention=("until_forgotten", None),
            account=account,
        )
        store.append(upload_id, "claim", repository, 0, bundle)
        return store.commit(upload_id, "claim", repository, revision=REVISION, worktree=WORKTREE)

    admitted = 0
    with pytest.raises(CodeStoreError, match="code_copy_over_quota"):
        for number in range(40):
            upload(f"mallory-{number}", "key:mallory")
            admitted += 1
    assert 0 < admitted < 40
    upload("alice-1", "key:alice")  # another account still has its own quota
    with pytest.raises(CodeStoreError, match="code_copy_owner_invalid"):
        upload("x", "")
    # Without an account, the owning namespace is what is charged.
    shared = _store(tmp_path / "shared", limits=limits)
    store = shared
    with pytest.raises(CodeStoreError, match="code_copy_over_quota"):
        for number in range(40):
            upload(f"anyone-{number}", None)
