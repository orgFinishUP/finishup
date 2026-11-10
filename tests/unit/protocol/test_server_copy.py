"""The server copy's wire format and its hostile-input verifier (design v2 §8.1, §8.6)."""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import replace
from pathlib import Path

import pytest
from tests.builders.server_copy import git, git_bytes, held_lookup, snapshot_objects

from finishup.protocol import server_copy
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.server_copy import (
    COMPLETENESS_COUNTS,
    COMPLETENESS_LISTS,
    SYNTHETIC_IDENTITY,
    BundleLimits,
    CopyError,
    GitObject,
    SnapshotManifest,
    TreeEntry,
    component_refusal,
    decode_commit,
    decode_tree,
    encode_commit,
    loose_decode,
    loose_encode,
    manifest_digest,
    manifest_from_json,
    manifest_to_json,
    object_id,
    policy_digest,
    read_pack,
    verify_snapshot_bundle,
    write_bundle,
    write_pack,
)

LIMITS = BundleLimits(max_file_bytes=1_048_576)
BASE = {"README.md": b"hello\n", "src/app.py": b"print(1)\n"}
CURRENT = {
    "README.md": b"hello again\n",
    "src/app.py": b"print(2)\n",
    "src/new.py": b"x = 1\n",
    "bin/run": ("x", b"#!/bin/sh\necho run\n"),
    "docs/latest": ("link", "../README.md"),
    "vendor/lib": ("gitlink", "1" * 40),
}


def _nothing(_oid: str) -> None:
    return None


def _raw_tree(*entries: tuple[bytes, bytes, str]) -> bytes:
    return b"".join(
        mode + b" " + name + b"\x00" + bytes.fromhex(oid) for mode, name, oid in entries
    )


def _bundle_of(objects: list[GitObject], tip: str, *, ref: int = 1) -> bytes:
    return write_bundle((), tip, ref, write_pack(objects))


def _snapshot_with_tree(tree_data: bytes, *extra: GitObject) -> bytes:
    """A bundle whose snapshot tree is ``tree_data`` exactly (written raw, not via encode_tree)."""

    empty = GitObject("tree", b"")
    tree = GitObject("tree", tree_data)
    base = GitObject("commit", encode_commit(empty.oid, None))
    tip = GitObject("commit", encode_commit(tree.oid, base.oid))
    return _bundle_of([tip, base, empty, tree, *extra], tip.oid)


# --- objects, trees and commits ------------------------------------------------------------------


def test_object_ids_and_loose_objects_are_git_s_own(tmp_path: Path) -> None:
    git(tmp_path, "init", "-q")
    data = b"some content\n"
    assert (
        object_id("blob", data)
        == git_bytes(tmp_path, "hash-object", "--stdin", stdin=data).decode().strip()
    )
    item = GitObject("blob", data)
    assert loose_decode(loose_encode(item), item.oid, limit=1024) == item
    with pytest.raises(CopyError, match="object_id_mismatch"):
        loose_decode(loose_encode(item), "0" * 40, limit=1024)
    with pytest.raises(CopyError, match="object_unreadable"):
        loose_decode(loose_encode(item), item.oid, limit=4)
    with pytest.raises(CopyError, match="object_unreadable"):
        loose_decode(b"not zlib", item.oid, limit=1024)


def test_a_synthetic_commit_has_exactly_one_shape() -> None:
    tree = "a" * 40
    base = encode_commit(tree, None)
    snapshot = encode_commit(tree, "b" * 40)
    assert decode_commit(base) == (tree, None)
    assert decode_commit(snapshot) == (tree, "b" * 40)
    assert SYNTHETIC_IDENTITY in base
    refused = [
        base.replace(b"finishup snapshot", b"my real message"),
        base.replace(b"FinishUP export", b"Real Author"),
        snapshot.replace(b"\nauthor", b"\nparent " + b"c" * 40 + b"\nauthor"),
        base.replace(b"\n\n", b"\ngpgsig -----\n\n"),
        base.replace(b"\n\n", b"\nencoding latin-1\n\n"),
        base + b"trailing",
    ]
    for data in refused:
        with pytest.raises(CopyError, match="commit_not_synthetic"):
            decode_commit(data)


@pytest.mark.parametrize(
    ("name", "mode", "reason"),
    [
        (b"", b"100644", "path_invalid"),
        (b".", b"100644", "path_invalid"),
        (b"..", b"40000", "path_invalid"),
        (b"a/b", b"100644", "path_invalid"),
        (b"a\x00b", b"100644", "path_invalid"),
        (b"x" * 256, b"100644", "path_invalid"),
        (b"\xff\xfe", b"100644", "path_not_utf8"),
        (b".git", b"40000", "path_git_alias"),
        (b".GIT", b"40000", "path_git_alias"),
        (b".git. . ", b"40000", "path_git_alias"),
        (b"GIT~1", b"40000", "path_git_alias"),
        (".g‌it".encode(), b"40000", "path_git_alias"),
        (b".git::$INDEX_ALLOCATION", b"40000", "path_git_alias"),
        (b".gitmodules", b"120000", "path_git_alias"),
        (b".GitAttributes", b"120000", "path_git_alias"),
    ],
)
def test_a_name_no_filesystem_may_read_safely_is_refused(
    name: bytes, mode: bytes, reason: str
) -> None:
    assert component_refusal(name, mode) == reason


def test_ordinary_names_are_admitted() -> None:
    for name in (b"a.py", b".gitmodules", b".github", b"gitx", "café".encode(), b"-dash"):
        assert component_refusal(name, b"100644") is None


def test_a_tree_must_be_sorted_unique_and_free_of_case_collisions() -> None:
    oid = "e" * 40
    with pytest.raises(CopyError, match="tree_unsorted"):
        decode_tree(_raw_tree((b"100644", b"b", oid), (b"100644", b"a", oid)))
    with pytest.raises(CopyError, match="tree_unsorted"):
        decode_tree(_raw_tree((b"100644", b"a", oid), (b"100644", b"a", oid)))
    with pytest.raises(CopyError, match="tree_case_collision"):
        decode_tree(_raw_tree((b"100644", b"README", oid), (b"100644", b"readme", oid)))
    with pytest.raises(CopyError, match="tree_case_collision"):
        decode_tree(_raw_tree((b"100644", "é".encode(), oid), (b"100644", "é".encode(), oid)))
    with pytest.raises(CopyError, match="tree_invalid"):
        decode_tree(_raw_tree((b"100664", b"a", oid)))
    with pytest.raises(CopyError, match="tree_invalid"):
        decode_tree(b"100644 a\x00" + b"\x01" * 5)
    # A directory sorts as its name followed by "/" (git's order).
    entries = decode_tree(_raw_tree((b"100644", b"a.txt", oid), (b"40000", b"a", oid)))
    assert [entry.name for entry in entries] == [b"a.txt", b"a"]


# --- bundles: git's own tools read them, and the verifier admits them ------------------------------


def test_a_bundle_round_trips_through_git_itself(tmp_path: Path) -> None:
    snap = snapshot_objects(BASE, CURRENT)
    bundle_path = tmp_path / "snap.bundle"
    bundle_path.write_bytes(snap.bundle())
    repository = tmp_path / "receiver"
    repository.mkdir()
    git(repository, "init", "-q", "--bare")
    git(repository, "bundle", "verify", str(bundle_path))
    git(repository, "fetch", "-q", str(bundle_path), "refs/finishup/snap/1:refs/heads/snap")
    assert git(repository, "rev-parse", "refs/heads/snap") == snap.snapshot
    assert git(repository, "rev-list", "--count", "refs/heads/snap") == "2"
    git(repository, "fsck", "--strict", "--no-dangling")
    listing = git(repository, "ls-tree", "-r", "refs/heads/snap")
    assert "120000 blob" in listing and "160000 commit" in listing and "100755 blob" in listing
    assert git(repository, "show", "refs/heads/snap:src/new.py") == "x = 1"


def test_the_verifier_admits_a_full_bundle_and_counts_what_a_checkout_holds() -> None:
    snap = snapshot_objects(BASE, CURRENT)
    verified = verify_snapshot_bundle(snap.bundle(), have=_nothing, limits=LIMITS)
    assert (verified.snapshot, verified.base) == (snap.snapshot, snap.base)
    assert (verified.tree, verified.base_tree) == (snap.tree, snap.base_tree)
    assert set(verified.objects) == set(snap.objects)
    assert verified.tree_files == 6
    expected = 0
    for value in CURRENT.values():
        if isinstance(value, bytes):
            expected += len(value)
        elif value[0] != "gitlink":
            payload = value[1]
            expected += len(payload if isinstance(payload, bytes) else payload.encode())
    assert verified.tree_bytes == expected
    assert verified.aggregates[snap.tree] == (expected, 6)


def test_an_incremental_bundle_needs_only_what_the_receiver_lacks() -> None:
    first = snapshot_objects(BASE, CURRENT)
    verified = verify_snapshot_bundle(first.bundle(), have=_nothing, limits=LIMITS)
    second = snapshot_objects(BASE, {**CURRENT, "src/new.py": b"x = 2\n"})
    held = held_lookup(first.objects, verified.aggregates)
    missing = frozenset(oid for oid in second.objects if held(oid) is not None)
    assert first.base in missing  # the same sanitized base: already held
    bundle = second.bundle(omit=missing, prerequisites=(first.snapshot,), ref_number=2)
    again = verify_snapshot_bundle(bundle, have=held, limits=LIMITS)
    assert again.snapshot == second.snapshot and again.base_tree == first.base_tree
    assert again.tree_files == 6 and again.ref_number == 2
    assert again.new_bytes < verified.new_bytes
    with pytest.raises(CopyError, match="bundle_prerequisite_unknown"):
        verify_snapshot_bundle(bundle, have=_nothing, limits=LIMITS)
    with pytest.raises(CopyError, match="bundle_incomplete"):
        verify_snapshot_bundle(second.bundle(omit=missing), have=_nothing, limits=LIMITS)


# --- hostile bundles --------------------------------------------------------------------------------


def _pack_with(raw_objects: list[tuple[int, bytes]]) -> bytes:
    body = bytearray(b"PACK" + struct.pack(">II", 2, len(raw_objects)))
    for number, data in raw_objects:
        size = len(data)
        byte = (number << 4) | (size & 0x0F)
        size >>= 4
        while size:
            body.append(byte | 0x80)
            byte = size & 0x7F
            size >>= 7
        body.append(byte)
        body += zlib.compress(data)
    body += hashlib.sha1(body, usedforsecurity=False).digest()
    return bytes(body)


def test_delta_tag_and_unknown_objects_are_refused() -> None:
    for number, reason in (
        (6, "pack_delta_refused"),
        (7, "pack_delta_refused"),
        (4, "pack_object_type_refused"),
        (5, "pack_object_type_refused"),
    ):
        with pytest.raises(CopyError, match=reason):
            read_pack(_pack_with([(number, b"x")]), LIMITS)


def test_a_pack_that_does_not_verify_is_refused() -> None:
    snap = snapshot_objects(BASE, CURRENT)
    pack = write_pack(list(snap.objects.values()))
    with pytest.raises(CopyError, match="pack_checksum_mismatch"):
        read_pack(pack[:-1] + bytes([pack[-1] ^ 1]), LIMITS)
    with pytest.raises(CopyError, match="pack_invalid"):
        read_pack(b"KCAP" + pack[4:], LIMITS)
    duplicate = write_pack([GitObject("blob", b"a"), GitObject("blob", b"a")])
    with pytest.raises(CopyError, match="pack_duplicate_object"):
        read_pack(duplicate, LIMITS)
    with pytest.raises(CopyError, match="pack_object_too_large"):
        read_pack(write_pack([GitObject("blob", b"a" * 11)]), BundleLimits(max_file_bytes=10))
    with pytest.raises(CopyError, match="pack_invalid"):
        read_pack(pack, BundleLimits(max_file_bytes=1024, max_objects=2))
    # A header that understates the inflated size.
    lying = bytearray(_pack_with([(3, b"abcdef")]))
    lying[12] = (3 << 4) | 2
    lying[-20:] = hashlib.sha1(bytes(lying[:-20]), usedforsecurity=False).digest()
    with pytest.raises(CopyError, match="pack_object_size_mismatch"):
        read_pack(bytes(lying), LIMITS)


def test_a_pack_past_its_inflated_budget_is_refused_before_inflating_more(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Each object is under the per-object cap; together they pass the budget (A4/B4).
    blobs = [GitObject("blob", bytes([65 + number]) * 1_000) for number in range(4)]
    pack = write_pack(blobs)
    assert len(pack) < 200  # compressed: tiny on the wire
    inflated: list[int] = []
    real = server_copy._inflate  # pyright: ignore[reportPrivateUsage]

    def counting(view: memoryview, position: int, size: int) -> tuple[bytes, int]:
        inflated.append(size)
        return real(view, position, size)

    monkeypatch.setattr(server_copy, "_inflate", counting)
    with pytest.raises(CopyError, match="pack_over_budget"):
        read_pack(pack, BundleLimits(max_file_bytes=1_000, max_inflated_bytes=2_999))
    # The third object would pass the budget: it is never inflated.
    assert inflated == [1_000, 1_000]
    inflated.clear()
    assert len(read_pack(pack, BundleLimits(max_file_bytes=1_000, max_inflated_bytes=4_000))) == 4
    assert sum(inflated) == 4_000
    # Trees and commits count too, and the whole bundle is verified under the same budget.
    snap = snapshot_objects(BASE, CURRENT)
    total = sum(len(item.data) for item in snap.objects.values())
    verified = verify_snapshot_bundle(
        snap.bundle(), have=_nothing, limits=replace(LIMITS, max_inflated_bytes=total)
    )
    assert verified.new_bytes == total
    with pytest.raises(CopyError, match="pack_over_budget"):
        verify_snapshot_bundle(
            snap.bundle(), have=_nothing, limits=replace(LIMITS, max_inflated_bytes=total - 1)
        )
    for invalid in (-1, True, 1.5):
        with pytest.raises(CopyError, match="limits_invalid"):
            BundleLimits(max_file_bytes=1, max_inflated_bytes=invalid)  # type: ignore[arg-type]


def test_every_truncation_of_a_valid_bundle_is_a_closed_refusal() -> None:
    bundle = snapshot_objects(BASE, CURRENT).bundle()
    for cut in range(0, len(bundle) - 1, 7):
        with pytest.raises(CopyError):
            verify_snapshot_bundle(bundle[:cut], have=_nothing, limits=LIMITS)


def test_bundle_headers_admit_one_snapshot_ref_only() -> None:
    snap = snapshot_objects(BASE, CURRENT)
    pack = write_pack(list(snap.objects.values()))
    head = b"# v2 git bundle\n"
    cases = {
        head + snap.snapshot.encode() + b" refs/heads/main\n\n": "bundle_ref_refused",
        head + snap.snapshot.encode() + b" refs/finishup/snap/01\n\n": "bundle_ref_refused",
        head
        + snap.snapshot.encode()
        + b" refs/finishup/snap/1\n"
        + snap.base.encode()
        + b" refs/finishup/snap/2\n\n": "bundle_ref_refused",
        b"# v3 git bundle\n"
        + snap.snapshot.encode()
        + b" refs/finishup/snap/1\n\n": "bundle_invalid",
        head + b"\n": "bundle_invalid",
    }
    for header, reason in cases.items():
        with pytest.raises(CopyError, match=reason):
            verify_snapshot_bundle(header + pack, have=_nothing, limits=LIMITS)
    with pytest.raises(CopyError, match="bundle_too_large"):
        verify_snapshot_bundle(
            snap.bundle(), have=_nothing, limits=replace(LIMITS, max_bundle_bytes=64)
        )
    with pytest.raises(CopyError, match="bundle_prerequisite_unknown"):
        verify_snapshot_bundle(snap.bundle(prerequisites=("f" * 40,)), have=_nothing, limits=LIMITS)


def test_objects_outside_the_snapshot_or_missing_from_it_are_refused() -> None:
    snap = snapshot_objects(BASE, CURRENT)
    stray = GitObject("blob", b"an old secret from history\n")
    with pytest.raises(CopyError, match="bundle_unreachable_object"):
        verify_snapshot_bundle(snap.bundle(extra=(stray,)), have=_nothing, limits=LIMITS)
    blob = GitObject("blob", b"x = 1\n").oid
    with pytest.raises(CopyError, match="bundle_incomplete"):
        verify_snapshot_bundle(snap.bundle(omit=frozenset({blob})), have=_nothing, limits=LIMITS)
    with pytest.raises(CopyError, match="bundle_incomplete"):
        verify_snapshot_bundle(
            snap.bundle(omit=frozenset({snap.base})), have=_nothing, limits=LIMITS
        )


def test_commits_of_any_other_shape_are_refused() -> None:
    real = GitObject(
        "commit",
        b"tree "
        + b"a" * 40
        + b"\nauthor Someone <s@x> 1 +0000\ncommitter Someone <s@x> 1 +0000\n\nfix secret\n",
    )
    with pytest.raises(CopyError, match="commit_not_synthetic"):
        verify_snapshot_bundle(_bundle_of([real], real.oid), have=_nothing, limits=LIMITS)
    empty = GitObject("tree", b"")
    orphan = GitObject("commit", encode_commit(empty.oid, None))
    with pytest.raises(CopyError, match="commit_not_synthetic"):
        verify_snapshot_bundle(
            _bundle_of([orphan, empty], orphan.oid), have=_nothing, limits=LIMITS
        )
    grand = GitObject("commit", encode_commit(empty.oid, orphan.oid))
    tip = GitObject("commit", encode_commit(empty.oid, grand.oid))
    with pytest.raises(CopyError, match="commit_not_synthetic"):
        verify_snapshot_bundle(
            _bundle_of([tip, grand, orphan, empty], tip.oid), have=_nothing, limits=LIMITS
        )
    with pytest.raises(CopyError, match="bundle_tip_invalid"):
        verify_snapshot_bundle(_bundle_of([empty], empty.oid), have=_nothing, limits=LIMITS)


def test_hostile_trees_are_refused() -> None:
    blob = GitObject("blob", b"data")
    sub = GitObject("tree", _raw_tree((b"100644", b"f", blob.oid)))
    cases: list[tuple[bytes, tuple[GitObject, ...], str]] = [
        (_raw_tree((b"40000", b".git", sub.oid)), (sub, blob), "path_git_alias"),
        (_raw_tree((b"40000", b"Git~1", sub.oid)), (sub, blob), "path_git_alias"),
        (
            _raw_tree((b"100644", b"A", blob.oid), (b"100644", b"a", blob.oid)),
            (blob,),
            "tree_case_collision",
        ),
        (_raw_tree((b"100644", b"f", sub.oid)), (sub, blob), "tree_entry_type_mismatch"),
        (_raw_tree((b"40000", b"d", blob.oid)), (blob,), "tree_entry_type_mismatch"),
        (_raw_tree((b"160000", b"m", blob.oid)), (blob,), "gitlink_content_refused"),
    ]
    for tree_data, extra, reason in cases:
        with pytest.raises(CopyError, match=reason):
            verify_snapshot_bundle(
                _snapshot_with_tree(tree_data, *extra), have=_nothing, limits=LIMITS
            )
    long_link = GitObject("blob", b"x" * 4097)
    nul_link = GitObject("blob", b"a\x00b")
    for link in (long_link, nul_link):
        with pytest.raises(CopyError, match="link_invalid"):
            verify_snapshot_bundle(
                _snapshot_with_tree(_raw_tree((b"120000", b"l", link.oid)), link),
                have=_nothing,
                limits=LIMITS,
            )


def test_a_tree_nested_beyond_the_bound_is_refused() -> None:
    blob = GitObject("blob", b"deep")
    inner = GitObject("tree", _raw_tree((b"100644", b"f", blob.oid)))
    chain = [blob, inner]
    for _ in range(130):
        inner = GitObject("tree", _raw_tree((b"40000", b"d", inner.oid)))
        chain.append(inner)
    with pytest.raises(CopyError, match="tree_too_deep"):
        verify_snapshot_bundle(
            _snapshot_with_tree(inner.data, *chain[:-1]), have=_nothing, limits=LIMITS
        )


# --- the policy digest and the manifest ------------------------------------------------------------


def _policy(**changes: object) -> str:
    values: dict[str, object] = {
        "always": [".env", "*.pem"],
        "server": ["*.sqlite"],
        "owner": ["private/"],
        "allowed": [("config/test.pem", "sha256:" + "a" * 64)],
        "max_file_bytes": 1024,
        "max_repo_bytes": 4096,
    }
    values.update(changes)
    return policy_digest(**values)  # type: ignore[arg-type]


def test_the_policy_digest_is_order_free_and_moves_with_every_member() -> None:
    assert _policy() == _policy(always=["*.pem", ".env", ".env"])
    seen = {
        _policy(),
        _policy(always=[".env"]),
        _policy(server=[]),
        _policy(owner=["private/", "x"]),
        _policy(allowed=[]),
        _policy(max_file_bytes=1025),
        _policy(max_repo_bytes=4097),
    }
    assert len(seen) == 7
    with pytest.raises(CopyError, match="policy_invalid"):
        _policy(allowed=[("p", "not-a-digest")])


def _manifest() -> SnapshotManifest:
    snap = snapshot_objects(BASE, CURRENT)
    lists: dict[str, tuple[str, ...]] = {name: () for name in COMPLETENESS_LISTS}
    lists["held_for_content"] = ("config/prod.yaml",)
    lists["excluded"] = (".env", "keys/server.pem")
    return SnapshotManifest(
        snapshot=snap.snapshot,
        base=snap.base,
        tree=snap.tree,
        base_tree=snap.base_tree,
        original_base_format="sha1",
        original_base="c" * 40,
        export_id="d" * 32,
        worktree="sha256:" + "1" * 64,
        policy=_policy(),
        lists=lists,
        more={name: 0 for name in COMPLETENESS_LISTS},
        counts={name: 0 for name in COMPLETENESS_COUNTS},
        subject_state="sha256:" + "2" * 64,
        issuer="e" * 32,
        revision=3,
        profile_digest="sha256:" + "3" * 64,
        purpose="check",
        synced_at="2026-11-10T08:00:00.000Z",
        files=6,
        bytes=100,
    )


def test_a_manifest_round_trips_canonically_and_its_digest_is_stable() -> None:
    manifest = _manifest()
    encoded = canonical_encode(manifest_to_json(manifest))
    assert manifest_from_json(encoded) == manifest
    assert manifest_digest(manifest) == manifest_digest(manifest_from_json(encoded))
    assert manifest.held_out == 3
    assert manifest_digest(
        replace(manifest, synced_at="2026-11-10T08:00:00.001Z")
    ) != manifest_digest(manifest)


def test_a_manifest_with_anything_unknown_or_malformed_is_refused() -> None:
    document = manifest_to_json(_manifest())
    with pytest.raises(CopyError, match="manifest_invalid"):
        manifest_from_json({**document, "extra": 1})
    with pytest.raises(CopyError, match="manifest_schema_unknown"):
        manifest_from_json({**document, "schema": "yoetz.code-snapshot/2"})
    with pytest.raises(CopyError, match="manifest_not_canonical"):
        manifest_from_json(canonical_encode(document) + b" ")
    with pytest.raises(CopyError):
        manifest_from_json(b"{not json")
    for change in (
        {"snapshot": "X" * 40},
        {"policy": "md5:abc"},
        {"subject_state": "sha256:short"},
        {"purpose": "sometime"},
        {"synced_at": "yesterday"},
        {"files": -1},
        {"lists": {**_manifest().lists, "excluded": ("b", "a")}},
        {"original_base_format": "sha256"},
    ):
        with pytest.raises(CopyError, match="manifest_invalid"):
            replace(_manifest(), **change)  # type: ignore[arg-type]


def test_tree_entries_from_the_builder_encode_exactly_as_git_writes_them(tmp_path: Path) -> None:
    git(tmp_path, "init", "-q")
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "f").write_bytes(b"1\n")
    (tmp_path / "a.txt").write_bytes(b"2\n")
    git(tmp_path, "add", "-A")
    tree = git(tmp_path, "write-tree")
    snap = snapshot_objects({}, {"a/f": b"1\n", "a.txt": b"2\n"})
    assert snap.tree == tree
    entries = decode_tree(snap.objects[tree].data)
    assert [entry.name for entry in entries] == [b"a.txt", b"a"]
    assert isinstance(entries[0], TreeEntry)
