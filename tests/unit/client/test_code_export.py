"""The sanitized exporter of a server copy, on real repositories (design v2 §4.2, §8.1, U10, U19)."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Sequence
from pathlib import Path

import pytest
from tests.builders.server_copy import git, git_bytes

from finishup.client import code_export
from finishup.client.code_copy_settings import RepositoryCodeSettings
from finishup.client.code_export import (
    ExportDatabase,
    ExportPolicy,
    ExportRefused,
    ExportRequest,
    PreparedExport,
    export_snapshot,
)
from finishup.client.code_secrets import ALWAYS_EXCLUDED, excluded_by, holds_known_secret
from finishup.protocol.server_copy import BundleLimits, GitObject, verify_snapshot_bundle

AWS_KEY = b"aws_access_key_id = AKIA" + b"ABCDEFGHIJKLMNOP" + b"\n"
POLICY = ExportPolicy(
    server=(), owner=RepositoryCodeSettings(), max_file_bytes=65_536, max_repo_bytes=1_048_576
)


def _request(root: Path, **changes: object) -> ExportRequest:
    values: dict[str, object] = {
        "root": root,
        "purpose": "check",
        "have": (),
        "issuer": "a" * 32,
        "revision": 1,
        "profile_digest": "sha256:" + "b" * 64,
        "worktree": "sha256:" + "c" * 64,
    }
    values.update(changes)
    return ExportRequest(**values)  # type: ignore[arg-type]


def _open() -> None:
    return None


def _repository(tmp_path: Path, files: dict[str, bytes], *, commit: bool = True) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    if commit and files:
        git(root, "add", "-A")
        git(root, "commit", "-q", "-m", "real message with a name in it")
    return root


def _export(
    root: Path, tmp_path: Path, policy: ExportPolicy = POLICY, **changes: object
) -> PreparedExport:
    database = ExportDatabase(tmp_path / "export")
    return export_snapshot(_request(root, **changes), policy, database, gate=_open)


def _tree_of(prepared: PreparedExport, tmp_path: Path) -> dict[str, str]:
    """``{path: mode}`` of the snapshot as git reads the bundle."""

    receiver = tmp_path / "receiver"
    receiver.mkdir(exist_ok=True)
    git(receiver, "init", "-q", "--bare")
    bundle = tmp_path / "snapshot.bundle"
    bundle.write_bytes(prepared.bundle)
    git(
        receiver,
        "fetch",
        "-q",
        str(bundle),
        f"refs/finishup/snap/{prepared.ref_number}:refs/heads/s",
    )
    listing = git(receiver, "ls-tree", "-r", "-z", "refs/heads/s")
    result: dict[str, str] = {}
    for line in listing.split("\x00"):
        if line:
            meta, _tab, path = line.partition("\t")
            result[path] = meta.split()[0]
    return result


def _content(tmp_path: Path, name: str) -> bytes:
    return git_bytes(tmp_path / "receiver", "show", f"refs/heads/s:{name}")


# --- names and content ------------------------------------------------------------------------------


def test_the_always_excluded_list_covers_the_reviewed_names() -> None:
    for path in (
        ".env",
        ".env.local",
        "deploy/server.pem",
        "id_rsa",
        "id_ed25519.pub",
        ".npmrc",
        ".pypirc",
        "x/credentials.json",
        "a/b/.aws/credentials",
        "ci/app.p12",
    ):
        assert excluded_by(path, ALWAYS_EXCLUDED) is not None, path
    for path in ("src/env.py", "README.md", "docs/keys.md", "environment.yml"):
        assert excluded_by(path, ALWAYS_EXCLUDED) is None, path
    assert excluded_by("vendor/x/y.py", ("vendor/",)) == "vendor/"
    assert excluded_by("a/vendor/y.py", ("vendor/",)) == "vendor/"
    assert excluded_by("src/data/big.sqlite", ("src/data/*",)) == "src/data/*"
    assert excluded_by("other/data/big.sqlite", ("src/data/*",)) is None


def test_the_content_scan_finds_known_formats_only() -> None:
    assert holds_known_secret(AWS_KEY)
    assert holds_known_secret(
        b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH " + b"PRIVATE KEY-----\n"
    )
    assert holds_known_secret(b"stripe = 'sk_live_" + b"a" * 24 + b"'")
    assert holds_known_secret(b"KEY=AIza" + b"B" * 35)
    assert not holds_known_secret(b"password = os.environ['PASSWORD']\n")
    assert not holds_known_secret(b"def secret(): return compute()\n")


# --- the export -------------------------------------------------------------------------------------


def test_git_visible_files_are_exported_and_nothing_of_the_history(tmp_path: Path) -> None:
    root = _repository(tmp_path, {"a.py": b"1\n", "gone.py": b"bye\n", ".gitignore": b"*.log\n"})
    (root / "a.py").write_bytes(b"2\n")
    (root / "gone.py").unlink()
    (root / "new.py").write_bytes(b"new\n")
    (root / "debug.log").write_bytes(b"ignored\n")
    os.chmod(root / "new.py", 0o755)
    prepared = _export(root, tmp_path)
    tree = _tree_of(prepared, tmp_path)
    assert tree == {".gitignore": "100644", "a.py": "100644", "new.py": "100755"}
    assert _content(tmp_path, "a.py") == b"2\n"
    receiver = tmp_path / "receiver"
    log = git(receiver, "log", "--format=%an %ae %s", "refs/heads/s")
    assert "real message" not in log and "Test" not in log
    assert git(receiver, "rev-list", "--count", "refs/heads/s") == "2"
    # The base is the original HEAD, re-created: its id is never the original commit's.
    head = git(root, "rev-parse", "HEAD")
    assert prepared.manifest.original_base == head
    assert head not in {prepared.manifest.base, prepared.manifest.snapshot}
    assert git(receiver, "show", "refs/heads/s~1:gone.py") == "bye"
    assert prepared.manifest.files == 3 and prepared.manifest.purpose == "check"


def test_the_gate_runs_before_anything_is_read_or_written(tmp_path: Path) -> None:
    root = _repository(tmp_path, {"a.py": b"1\n"})
    database = ExportDatabase(tmp_path / "export")

    def held() -> None:
        raise ExportRefused("repository_egress_held")

    calls: list[tuple[str, ...]] = []
    original = code_export._git  # pyright: ignore[reportPrivateUsage]

    def spy(*arguments: object, **options: object) -> bytes:
        calls.append(tuple(str(a) for a in arguments))
        return original(*arguments, **options)  # type: ignore[arg-type]

    code_export._git = spy  # type: ignore[assignment]  # pyright: ignore[reportPrivateUsage]
    try:
        with pytest.raises(ExportRefused, match="repository_egress_held"):
            export_snapshot(_request(root), POLICY, database, gate=held)
    finally:
        code_export._git = original  # pyright: ignore[reportPrivateUsage]
    assert calls == []
    assert list((tmp_path / "export" / "objects").iterdir()) == []


def test_secret_names_and_patterns_leave_both_trees_and_are_named(tmp_path: Path) -> None:
    root = _repository(
        tmp_path,
        {
            "app.py": b"ok\n",
            ".env": b"TOKEN=1\n",
            "deploy/server.pem": b"pem\n",
            "data/big.sqlite": b"db\n",
            "private/notes.txt": b"mine\n",
        },
    )
    policy = ExportPolicy(
        server=("*.sqlite",),
        owner=RepositoryCodeSettings(exclude=("private/",)),
        max_file_bytes=65_536,
        max_repo_bytes=1_048_576,
    )
    prepared = _export(root, tmp_path, policy)
    assert _tree_of(prepared, tmp_path) == {"app.py": "100644"}
    assert git(tmp_path / "receiver", "ls-tree", "-r", "--name-only", "refs/heads/s~1") == "app.py"
    assert prepared.manifest.lists["excluded"] == (
        ".env",
        "data/big.sqlite",
        "deploy/server.pem",
        "private/notes.txt",
    )
    assert prepared.manifest.policy == policy.digest() != POLICY.digest()


def test_a_known_secret_is_held_out_until_the_owner_allows_that_exact_content(
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path, {"app.py": b"ok\n", "config/aws.ini": b"[default]\n"})
    (root / "config" / "aws.ini").write_bytes(AWS_KEY)
    prepared = _export(root, tmp_path)
    assert prepared.manifest.lists["held_for_content"] == ("config/aws.ini",)
    # Held out of the base as well, so the copy never reads it as deleted.
    assert _tree_of(prepared, tmp_path) == {"app.py": "100644"}
    assert git(tmp_path / "receiver", "ls-tree", "-r", "--name-only", "refs/heads/s~1") == "app.py"
    digest = "sha256:" + hashlib.sha256(AWS_KEY).hexdigest()
    allowed = ExportPolicy(
        server=(),
        owner=RepositoryCodeSettings(allow=(("config/aws.ini", digest),)),
        max_file_bytes=65_536,
        max_repo_bytes=1_048_576,
    )
    again = export_snapshot(
        _request(root), allowed, ExportDatabase(tmp_path / "export2"), gate=_open
    )
    assert again.manifest.lists["held_for_content"] == ()
    (root / "config" / "aws.ini").write_bytes(AWS_KEY + b"# changed\n")
    changed = export_snapshot(
        _request(root), allowed, ExportDatabase(tmp_path / "export3"), gate=_open
    )
    assert changed.manifest.lists["held_for_content"] == ("config/aws.ini",)


def test_caps_hold_a_large_file_and_refuse_an_oversized_copy(tmp_path: Path) -> None:
    root = _repository(tmp_path, {"small.txt": b"s\n", "big.bin": b"x" * 2_000})
    policy = ExportPolicy(
        server=(), owner=RepositoryCodeSettings(), max_file_bytes=1_000, max_repo_bytes=10_000
    )
    prepared = _export(root, tmp_path, policy)
    assert prepared.manifest.lists["too_large"] == ("big.bin",)
    assert _tree_of(prepared, tmp_path) == {"small.txt": "100644"}
    tight = ExportPolicy(
        server=(), owner=RepositoryCodeSettings(), max_file_bytes=1_000, max_repo_bytes=1
    )
    with pytest.raises(ExportRefused, match="code_copy_too_large"):
        export_snapshot(_request(root), tight, ExportDatabase(tmp_path / "e2"), gate=_open)


def test_links_are_sent_as_their_target_and_never_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_bytes(b"outside the repository\n")
    root = _repository(tmp_path, {"a.txt": b"a\n", "d/f.txt": b"inside\n"})
    (root / "to-outside").symlink_to(outside / "secret.txt")
    # A tracked directory replaced by a link: the file beneath it is never read through it.
    (root / "d" / "f.txt").unlink()
    (root / "d").rmdir()
    (root / "d").symlink_to(outside)
    prepared = _export(root, tmp_path)
    tree = _tree_of(prepared, tmp_path)
    assert tree["to-outside"] == "120000"
    assert _content(tmp_path, "to-outside") == os.fsencode(outside / "secret.txt")
    assert "d/f.txt" not in tree
    assert prepared.manifest.counts["special"] >= 1
    assert prepared.manifest.counts["links"] >= 1


def test_submodules_are_gitlinks_and_nested_repositories_are_held(tmp_path: Path) -> None:
    root = _repository(tmp_path, {"a.txt": b"a\n"})
    git(root, "update-index", "--add", "--cacheinfo", f"160000,{'1' * 40},vendor/lib")
    nested = root / "nested"
    nested.mkdir()
    git(nested, "init", "-q")
    (nested / "inner.txt").write_bytes(b"inner\n")
    prepared = _export(root, tmp_path)
    tree = _tree_of(prepared, tmp_path)
    assert tree["vendor/lib"] == "160000"
    assert "nested/inner.txt" not in tree
    assert prepared.manifest.lists["nested_repository"] == ("nested",)
    assert prepared.manifest.counts["gitlinks"] == 1


def test_special_and_multiply_linked_files_are_never_read(tmp_path: Path) -> None:
    root = _repository(tmp_path, {"a.txt": b"a\n", "linked.txt": b"shared\n"})
    os.link(root / "linked.txt", tmp_path / "second-name")
    os.mkfifo(root / "pipe")
    prepared = _export(root, tmp_path)
    tree = _tree_of(prepared, tmp_path)
    assert set(tree) == {"a.txt"}
    # The tracked, multiply linked file is counted; Git never lists a FIFO at all.
    assert prepared.manifest.counts["special"] == 1


def test_case_collisions_keep_the_first_name_only(tmp_path: Path) -> None:
    root = _repository(tmp_path, {"README": b"upper\n", "readme": b"lower\n", "z.txt": b"z\n"})
    prepared = _export(root, tmp_path)
    tree = _tree_of(prepared, tmp_path)
    assert set(tree) == {"README", "z.txt"}
    assert prepared.manifest.lists["case_collision"] == ("readme",)


def test_lfs_files_are_sent_as_their_pointers_only(tmp_path: Path) -> None:
    content = b"large binary content\n" * 10
    pointer = (
        b"version https://git-lfs.github.com/spec/v1\noid sha256:"
        + hashlib.sha256(content).hexdigest().encode()
        + b"\nsize "
        + str(len(content)).encode()
        + b"\n"
    )
    root = _repository(tmp_path, {".gitattributes": b"*.bin filter=lfs diff=lfs merge=lfs -text\n"})
    blob = git_bytes(root, "hash-object", "-w", "--stdin", stdin=pointer).decode().strip()
    git(root, "update-index", "--add", "--cacheinfo", f"100644,{blob},asset.bin")
    git(root, "commit", "-q", "-m", "lfs")
    (root / "asset.bin").write_bytes(content)  # the smudged file, as git-lfs leaves it
    (root / "other.bin").write_bytes(b"not a pointer and not tracked\n")
    prepared = _export(root, tmp_path)
    tree = _tree_of(prepared, tmp_path)
    assert _content(tmp_path, "asset.bin") == pointer
    assert "other.bin" not in tree
    assert prepared.manifest.lists["lfs_content"] == ("other.bin",)
    (root / "asset.bin").write_bytes(b"edited, so no pointer names it\n")
    edited = export_snapshot(_request(root), POLICY, ExportDatabase(tmp_path / "e2"), gate=_open)
    assert "asset.bin" in edited.manifest.lists["lfs_content"]


def test_names_that_are_not_safe_tree_entries_are_counted_not_sent(tmp_path: Path) -> None:
    root = _repository(tmp_path, {"a.txt": b"a\n"})
    (root / os.fsdecode(b"\xff-latin.txt")).write_bytes(b"x\n")
    prepared = _export(root, tmp_path)
    assert set(_tree_of(prepared, tmp_path)) == {"a.txt"}
    assert prepared.manifest.counts["unrepresentable"] == 1


def test_an_unborn_and_a_sha256_repository_export_alike(tmp_path: Path) -> None:
    root = _repository(tmp_path, {}, commit=False)
    (root / "first.txt").write_bytes(b"first\n")
    unborn = _export(root, tmp_path)
    assert unborn.manifest.original_base == "0" * 40
    assert set(_tree_of(unborn, tmp_path)) == {"first.txt"}
    other = tmp_path / "sha256"
    other.mkdir()
    git(other, "init", "-q", "--object-format=sha256")
    (other / "f.txt").write_bytes(b"f\n")
    git(other, "add", "-A")
    git(other, "commit", "-q", "-m", "m")
    prepared = export_snapshot(
        _request(other), POLICY, ExportDatabase(tmp_path / "e256"), gate=_open
    )
    assert prepared.manifest.original_base_format == "sha256"
    assert len(prepared.manifest.original_base) == 64
    assert len(prepared.manifest.snapshot) == 40


def test_an_incremental_export_sends_only_what_the_server_lacks(tmp_path: Path) -> None:
    root = _repository(tmp_path, {"a.txt": b"a\n" * 100, "b.txt": b"b\n" * 100})
    database = ExportDatabase(tmp_path / "export")
    first = export_snapshot(_request(root), POLICY, database, gate=_open)
    database.remember_sent(first.manifest.snapshot, first.ref_number)
    (root / "b.txt").write_bytes(b"changed\n")
    second = export_snapshot(
        _request(root, have=(first.manifest.snapshot,)), POLICY, database, gate=_open
    )
    assert second.ref_number == first.ref_number + 1
    assert len(second.bundle) < len(first.bundle)
    first_objects = verify_snapshot_bundle(
        first.bundle, have=lambda _o: None, limits=BundleLimits(max_file_bytes=65_536)
    )
    have = code_export._closure(database, (first.manifest.snapshot,), 1 << 20)  # pyright: ignore[reportPrivateUsage]
    verified = verify_snapshot_bundle(
        second.bundle, have=have.get, limits=BundleLimits(max_file_bytes=65_536)
    )
    assert set(verified.objects).isdisjoint(first_objects.objects)
    database.remember_sent(second.manifest.snapshot, second.ref_number)
    unchanged = export_snapshot(
        _request(root, have=(second.manifest.snapshot,)), POLICY, database, gate=_open
    )
    assert unchanged.unchanged and unchanged.bundle == b""
    # A have-set naming what this export never sent is not trusted: everything is sent again.
    stranger = export_snapshot(_request(root, have=("f" * 40,)), POLICY, database, gate=_open)
    assert not stranger.unchanged and len(stranger.bundle) >= len(second.bundle)


def test_the_audit_refuses_a_bundle_with_anything_not_admitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repository(tmp_path, {"a.txt": b"a\n"})
    real = code_export.write_pack
    stray = GitObject("blob", b"history the exporter never admitted\n")

    def with_stray(objects: Sequence[GitObject]) -> bytes:
        return real([*objects, stray])

    monkeypatch.setattr(code_export, "write_pack", with_stray)
    with pytest.raises(ExportRefused, match="code_export_audit_failed"):
        _export(root, tmp_path)
    monkeypatch.setattr(code_export, "write_pack", real)
    original = code_export.verify_snapshot_bundle

    def wrong_tree(bundle: bytes, **options: object):  # noqa: ANN202
        verified = original(bundle, **options)  # type: ignore[arg-type]
        from dataclasses import replace

        return replace(verified, tree_bytes=verified.tree_bytes + 1)

    monkeypatch.setattr(code_export, "verify_snapshot_bundle", wrong_tree)
    with pytest.raises(ExportRefused, match="code_export_audit_failed"):
        export_snapshot(_request(root), POLICY, ExportDatabase(tmp_path / "e2"), gate=_open)


def test_the_export_database_is_owner_only_and_never_the_repository_s_own(tmp_path: Path) -> None:
    root = _repository(tmp_path, {"a.txt": b"a\n"})
    objects_before = sorted(p.name for p in (root / ".git" / "objects").rglob("*") if p.is_file())
    database = ExportDatabase(tmp_path / "export")
    export_snapshot(_request(root), POLICY, database, gate=_open)
    objects_after = sorted(p.name for p in (root / ".git" / "objects").rglob("*") if p.is_file())
    assert objects_before == objects_after
    for path in (tmp_path / "export").rglob("*"):
        assert path.stat().st_mode & 0o077 == 0, path
    database.remove()
    assert not (tmp_path / "export").exists()
