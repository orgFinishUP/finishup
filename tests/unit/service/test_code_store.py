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

from finishup.protocol.canonical import canonical_encode
from finishup.protocol.server_copy import (
    COMPLETENESS_COUNTS,
    COMPLETENESS_LISTS,
    BundleLimits,
    SnapshotManifest,
    manifest_to_json,
    verify_snapshot_bundle,
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
    tight = StoreLimits(max_file_bytes=65_536, max_repo_bytes=10)
    with pytest.raises(CodeStoreError, match="code_copy_too_large"):
        _upload(_store(tmp_path / "a", limits=tight), snap.bundle(), _manifest(snap, snap.bundle()))
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
