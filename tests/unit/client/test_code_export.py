"""The sanitized exporter of a server copy, on real repositories (design v2 §4.2, §8.1, U10, U19)."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
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
    export_records,
    export_snapshot,
)
from finishup.client.code_secrets import ALWAYS_EXCLUDED, excluded_by, holds_known_secret
from finishup.protocol.server_copy import BundleLimits, GitObject, verify_snapshot_bundle

AWS_KEY = b"aws_access_key_id = AKIA" + b"ABCDEFGHIJKLMNOP" + b"\n"
POLICY = ExportPolicy(
    server=(), owner=RepositoryCodeSettings(), max_file_bytes=65_536, max_repo_bytes=1_048_576
)


@pytest.fixture(autouse=True)
def isolated_home(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """Each export reads the owner's own Git configuration from a fresh HOME, never the real one."""

    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", os.fspath(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)
    return home


def _owner_git(home: Path, root: Path, *arguments: str) -> str:
    """``git`` as the owner runs it: their own global configuration in ``home``."""

    completed = subprocess.run(  # noqa: S603 - fixed argv in tests
        ("git", *arguments),
        cwd=root,
        capture_output=True,
        check=False,
        env={"HOME": os.fspath(home), "PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C"},
    )
    return completed.stdout.decode()


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


def test_an_excluded_or_unsafe_base_file_is_never_read_from_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    unsafe = os.fsdecode(b"\xff-latin.txt")
    root = _repository(
        tmp_path,
        {"a.txt": b"a\n", "certs/big.pem": b"p" * 20_000, "dump/data.sql": b"d" * 20_000},
    )
    (root / unsafe).write_bytes(b"u" * 20_000)
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "unsafe")
    excluded = {
        git(root, "rev-parse", f"HEAD:{name}") for name in ("certs/big.pem", "dump/data.sql")
    }
    excluded.add(git(root, "hash-object", unsafe))
    requested: list[str] = []
    original = code_export._Exporter._cat_blobs  # pyright: ignore[reportPrivateUsage]

    def spy(self: object, oids: list[str]) -> dict[str, bytes]:
        requested.extend(oids)
        return original(self, oids)  # type: ignore[arg-type]

    monkeypatch.setattr(code_export._Exporter, "_cat_blobs", spy)  # pyright: ignore[reportPrivateUsage]
    # Git's own output bound: the three held-out files alone would exceed it if they were read.
    monkeypatch.setattr(code_export, "_MAX_GIT_OUTPUT", 16_384)
    policy = ExportPolicy(
        server=(),
        owner=RepositoryCodeSettings(exclude=("dump/",)),
        max_file_bytes=65_536,
        max_repo_bytes=1_048_576,
    )
    prepared = _export(root, tmp_path, policy)
    assert set(_tree_of(prepared, tmp_path)) == {"a.txt"}
    assert not excluded & set(requested)
    assert prepared.manifest.lists["excluded"] == ("certs/big.pem", "dump/data.sql")
    assert prepared.manifest.counts["unrepresentable"] == 1


def test_an_excluded_worktree_file_is_never_opened_hashed_or_looked_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"private payload\n" * 4
    pointer = (
        b"version https://git-lfs.github.com/spec/v1\noid sha256:"
        + hashlib.sha256(content).hexdigest().encode()
        + b"\nsize "
        + str(len(content)).encode()
        + b"\n"
    )
    root = _repository(tmp_path, {".gitattributes": b"*.bin filter=lfs -text\n", "a.txt": b"a\n"})
    blob = git_bytes(root, "hash-object", "-w", "--stdin", stdin=pointer).decode().strip()
    git(root, "update-index", "--add", "--cacheinfo", f"100644,{blob},private/asset.bin")
    git(root, "commit", "-q", "-m", "lfs")
    (root / "private").mkdir()
    (root / "private" / "asset.bin").write_bytes(content)
    (root / "local.pem").write_bytes(b"untracked key\n")
    (root / os.fsdecode(b"\xfe-untracked.txt")).write_bytes(b"u\n")
    opened: list[bytes] = []
    hashed: list[bytes] = []
    looked_up: list[str] = []
    read, digest = code_export._read_beneath, code_export._hash_file_beneath  # pyright: ignore[reportPrivateUsage]
    cat = code_export._Exporter._cat_blobs  # pyright: ignore[reportPrivateUsage]

    def spy_read(root_fd: int, relative: bytes, limit: int) -> object:
        opened.append(relative)
        return read(root_fd, relative, limit)

    def spy_hash(root_fd: int, relative: bytes) -> str | None:
        hashed.append(relative)
        return digest(root_fd, relative)

    def spy_cat(self: object, oids: list[str]) -> dict[str, bytes]:
        looked_up.extend(oids)
        return cat(self, oids)  # type: ignore[arg-type]

    monkeypatch.setattr(code_export, "_read_beneath", spy_read)
    monkeypatch.setattr(code_export, "_hash_file_beneath", spy_hash)
    monkeypatch.setattr(code_export._Exporter, "_cat_blobs", spy_cat)  # pyright: ignore[reportPrivateUsage]
    policy = ExportPolicy(
        server=("private/",),
        owner=RepositoryCodeSettings(),
        max_file_bytes=65_536,
        max_repo_bytes=1_048_576,
    )
    prepared = _export(root, tmp_path, policy)
    assert set(_tree_of(prepared, tmp_path)) == {".gitattributes", "a.txt"}
    assert set(opened) == {b".gitattributes", b"a.txt"}
    assert hashed == [] and blob not in looked_up
    assert prepared.manifest.lists["excluded"] == ("local.pem", "private/asset.bin")
    assert prepared.manifest.counts["unrepresentable"] == 1


def test_an_ignore_file_named_through_a_global_include_keeps_its_files_out(
    tmp_path: Path, isolated_home: Path
) -> None:
    (isolated_home / ".gitconfig").write_text("[include]\n\tpath = ~/.gitconfig-extra\n")
    (isolated_home / ".gitconfig-extra").write_text("[core]\n\texcludesFile = ~/ignored-here\n")
    (isolated_home / "ignored-here").write_text("private.dump\n")
    root = _repository(tmp_path, {"a.txt": b"a\n"})
    (root / "private.dump").write_bytes(b"owner-only data\n")
    assert _owner_git(isolated_home, root, "check-ignore", "private.dump").strip() == "private.dump"
    assert set(_tree_of(_export(root, tmp_path), tmp_path)) == {"a.txt"}


def test_the_owner_s_ignore_file_keeps_git_s_precedence(
    tmp_path: Path, isolated_home: Path
) -> None:
    # A global "!name" never re-includes a file the repository's own .gitignore ignores.
    (isolated_home / ".config" / "git").mkdir(parents=True)
    (isolated_home / ".config" / "git" / "ignore").write_text("*.cache\n!private.dump\n")
    root = _repository(tmp_path, {".gitignore": b"*.dump\n", "a.txt": b"a\n"})
    (root / "private.dump").write_bytes(b"owner-only data\n")
    (root / "build.cache").write_bytes(b"ignored everywhere\n")
    (root / "kept.txt").write_bytes(b"kept\n")
    ignored = _owner_git(isolated_home, root, "status", "--porcelain", "--ignored")
    assert "!! private.dump" in ignored and "!! build.cache" in ignored
    tree = _tree_of(_export(root, tmp_path), tmp_path)
    assert set(tree) == {".gitignore", "a.txt", "kept.txt"}


def test_a_repository_s_own_ignore_file_wins_over_the_global_one(
    tmp_path: Path, isolated_home: Path
) -> None:
    (isolated_home / ".gitconfig").write_text("[core]\n\texcludesFile = ~/global-ignore\n")
    (isolated_home / "global-ignore").write_text("global.tmp\n")
    root = _repository(tmp_path, {"a.txt": b"a\n"})
    (root / ".git" / "local-ignore").write_text("local.tmp\n")
    git(root, "config", "core.excludesFile", ".git/local-ignore")
    (root / "local.tmp").write_bytes(b"l\n")
    (root / "global.tmp").write_bytes(b"g\n")
    tree = _tree_of(_export(root, tmp_path), tmp_path)
    assert set(tree) == {"a.txt", "global.tmp"}


def test_a_git_configuration_that_cannot_be_read_refuses_the_export(
    tmp_path: Path, isolated_home: Path
) -> None:
    root = _repository(tmp_path, {"a.txt": b"a\n"})
    (isolated_home / ".gitconfig").write_text("[core\nbroken")
    database = ExportDatabase(tmp_path / "export")
    with pytest.raises(ExportRefused, match="code_export_git_failed"):
        export_snapshot(_request(root), POLICY, database, gate=_open)
    assert [p for p in (tmp_path / "export" / "objects").rglob("*") if p.is_file()] == []


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


def test_the_repository_cap_holds_for_the_base_too(tmp_path: Path) -> None:
    # Each file fits, the worktree fits, but the base whose files were deleted since does not.
    root = _repository(
        tmp_path, {"keep.txt": b"k\n", "old/a.bin": b"a" * 900, "old/b.bin": b"b" * 900}
    )
    for name in ("old/a.bin", "old/b.bin"):
        (root / name).unlink()
    policy = ExportPolicy(
        server=(), owner=RepositoryCodeSettings(), max_file_bytes=1_000, max_repo_bytes=1_500
    )
    database = ExportDatabase(tmp_path / "export")
    with pytest.raises(ExportRefused, match="code_copy_too_large"):
        export_snapshot(_request(root), policy, database, gate=_open)
    # Refused before anything was written into the export database.
    assert [p for p in (tmp_path / "export" / "objects").rglob("*") if p.is_file()] == []
    # The same worktree from a base that fits is exported.
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "drop the old files")
    prepared = export_snapshot(_request(root), policy, database, gate=_open)
    assert set(_tree_of(prepared, tmp_path)) == {"keep.txt"}


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


def _pointer(content: bytes) -> bytes:
    return (
        b"version https://git-lfs.github.com/spec/v1\noid sha256:"
        + hashlib.sha256(content).hexdigest().encode()
        + b"\nsize "
        + str(len(content)).encode()
        + b"\n"
    )


@pytest.mark.parametrize("source", ["included", "xdg", "info"])
def test_lfs_attributes_from_every_source_git_reads_hold_the_content(
    tmp_path: Path, isolated_home: Path, source: str
) -> None:
    root = _repository(tmp_path, {"a.txt": b"a\n"})
    rule = "*.bin filter=lfs diff=lfs merge=lfs -text\n"
    if source == "included":
        (isolated_home / ".gitconfig").write_text("[include]\n\tpath = ~/.gitconfig-extra\n")
        (isolated_home / ".gitconfig-extra").write_text("[core]\n\tattributesFile = ~/attrs\n")
        (isolated_home / "attrs").write_text(rule)
    elif source == "xdg":
        (isolated_home / ".config" / "git").mkdir(parents=True)
        (isolated_home / ".config" / "git" / "attributes").write_text(rule)
    else:
        (root / ".git" / "info").mkdir(exist_ok=True)
        (root / ".git" / "info" / "attributes").write_text(rule)
    (root / "model.bin").write_bytes(b"smudged large file content\n")
    assert "filter: lfs" in _owner_git(isolated_home, root, "check-attr", "filter", "model.bin")
    prepared = _export(root, tmp_path)
    assert set(_tree_of(prepared, tmp_path)) == {"a.txt"}
    assert prepared.manifest.lists["lfs_content"] == ("model.bin",)


def test_lfs_pointers_are_recognized_without_any_attribute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No .gitattributes anywhere: the pointers in the base and the index alone mark the files.
    committed, staged, edited = b"committed payload\n" * 8, b"staged payload\n" * 8, b"e\n" * 8
    root = _repository(tmp_path, {"a.txt": b"a\n"})
    for name, content in (("asset.dat", committed), ("old.dat", committed), ("edit.dat", edited)):
        blob = git_bytes(root, "hash-object", "-w", "--stdin", stdin=_pointer(content))
        git(root, "update-index", "--add", "--cacheinfo", f"100644,{blob.decode().strip()},{name}")
    git(root, "commit", "-q", "-m", "pointers")
    blob = git_bytes(root, "hash-object", "-w", "--stdin", stdin=_pointer(staged)).decode().strip()
    git(root, "update-index", "--add", "--cacheinfo", f"100644,{blob},staged.dat")
    git(root, "rm", "-q", "--cached", "old.dat")  # untracked now; only the base has its pointer
    (root / "asset.dat").write_bytes(committed)  # smudged, as git-lfs leaves them
    (root / "staged.dat").write_bytes(staged)
    (root / "old.dat").write_bytes(committed)
    (root / "edit.dat").write_bytes(b"edited, so no pointer names it\n")
    # A staged blob larger than any pointer is never read to look for one.
    (root / "large.txt").write_bytes(b"l" * 4_096)
    git(root, "add", "large.txt")
    large = git(root, "rev-parse", ":large.txt")
    requested: list[str] = []
    cat = code_export._Exporter._cat_blobs  # pyright: ignore[reportPrivateUsage]

    def spy(self: object, oids: list[str]) -> dict[str, bytes]:
        requested.extend(oids)
        return cat(self, oids)  # type: ignore[arg-type]

    monkeypatch.setattr(code_export._Exporter, "_cat_blobs", spy)  # pyright: ignore[reportPrivateUsage]
    prepared = _export(root, tmp_path)
    assert large not in requested and blob in requested
    tree = _tree_of(prepared, tmp_path)
    assert set(tree) == {"a.txt", "asset.dat", "large.txt", "staged.dat"}
    assert _content(tmp_path, "asset.dat") == _pointer(committed)
    assert _content(tmp_path, "staged.dat") == _pointer(staged)
    assert prepared.manifest.lists["lfs_content"] == ("edit.dat", "old.dat")
    assert prepared.manifest.counts["lfs_pointers"] >= 2


def test_names_that_are_not_safe_tree_entries_are_counted_not_sent(tmp_path: Path) -> None:
    root = _repository(tmp_path, {"a.txt": b"a\n"})
    (root / os.fsdecode(b"\xff-latin.txt")).write_bytes(b"x\n")
    prepared = _export(root, tmp_path)
    assert set(_tree_of(prepared, tmp_path)) == {"a.txt"}
    assert prepared.manifest.counts["unrepresentable"] == 1


def _objects(folder: Path) -> list[Path]:
    return sorted(path for path in (folder / "objects").rglob("*") if path.is_file())


def test_a_base_the_server_names_is_one_this_export_chose_itself_or_head_now(
    tmp_path: Path,
) -> None:
    """B1: a server that knows an older commit's id never gets that commit's tree."""

    root = _repository(tmp_path, {"app.py": b"1\n", "old_notes.txt": b"deleted before the task\n"})
    old = git(root, "rev-parse", "HEAD").strip()
    (root / "old_notes.txt").unlink()
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "drop the notes")
    task_base = git(root, "rev-parse", "HEAD").strip()
    folder = tmp_path / "export"
    database = ExportDatabase(folder)
    # A commit this export never chose: refused before anything of it is listed, read or written.
    with pytest.raises(ExportRefused, match="code_export_base_unknown"):
        export_snapshot(_request(root, base_commit=old), POLICY, database, gate=_open)
    assert _objects(folder) == [] and database.bases == ()
    # The task's base: this export chooses HEAD itself and records it.
    first = export_snapshot(_request(root, purpose="base"), POLICY, database, gate=_open)
    assert first.manifest.original_base == task_base and database.bases == (task_base,)
    assert ExportDatabase(folder).bases == (task_base,)
    # HEAD moves on; a later check may name the base this export chose, never the older commit.
    (root / "app.py").write_bytes(b"2\n")
    git(root, "commit", "-q", "-am", "work")
    head = git(root, "rev-parse", "HEAD").strip()
    check = export_snapshot(_request(root, base_commit=task_base), POLICY, database, gate=_open)
    assert check.manifest.original_base == task_base
    assert _tree_of(check, tmp_path) == {"app.py": "100644"}
    with pytest.raises(ExportRefused, match="code_export_base_unknown"):
        export_snapshot(_request(root, base_commit=old), POLICY, database, gate=_open)
    # HEAD now is always a base this computer would choose itself.
    fresh = ExportDatabase(tmp_path / "other")
    named = export_snapshot(_request(root, base_commit=head), POLICY, fresh, gate=_open)
    assert named.manifest.original_base == head and fresh.bases == (head,)
    # A base that is not a commit here, or not an object id, is refused too.
    for value in ("0" * 40, "HEAD~1", git(root, "rev-parse", "HEAD^{tree}").strip()):
        with pytest.raises(ExportRefused, match="code_export_base_unknown"):
            export_snapshot(_request(root, base_commit=value), POLICY, fresh, gate=_open)


def test_the_chosen_bases_are_bounded_and_a_record_out_of_shape_is_not_trusted(
    tmp_path: Path,
) -> None:
    folder = tmp_path / "code-export" / ("b" * 32)
    database = ExportDatabase(folder)
    commits = [f"{index:040x}" for index in range(70)]
    for commit in commits:
        database.remember_base(commit)
    assert database.bases == tuple(commits[-64:])
    database.remember_base(commits[10 + 6])  # one chosen again is kept as the newest
    assert database.bases[-1] == commits[16] and len(database.bases) == 64
    assert _record(folder)["bases"] == list(database.bases)
    first = database.export_id
    # A record written before bases were kept reads as having chosen none.
    document = _record(folder)
    del document["bases"]
    (folder / "export.json").write_bytes(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )
    older = ExportDatabase(folder)
    assert older.export_id == first and older.bases == ()
    for bad in (["HEAD"], "0" * 40, [7], ["0" * 40] * 65):
        document["bases"] = bad
        (folder / "export.json").write_bytes(
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )
        fresh = ExportDatabase(folder)
        assert fresh.export_id != first and fresh.bases == (), bad
        first = fresh.export_id
        document = _record(folder)


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


# --- the export record names the repository's folder (server code forget --all) -----------------


def _record(folder: Path) -> dict[str, object]:
    return json.loads((folder / "export.json").read_bytes())


def test_a_sync_records_the_repository_folder_it_read_and_a_refused_one_records_none(
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path, {"a.py": b"1\n"})
    (root / "sub").mkdir()
    folder = tmp_path / "export"
    database = ExportDatabase(folder)
    assert database.root is None and _record(folder)["root"] is None

    def held() -> None:
        raise ExportRefused("repository_egress_held")

    with pytest.raises(ExportRefused):
        export_snapshot(_request(root), POLICY, database, gate=held)
    assert _record(folder)["root"] is None
    # A sync from a folder inside the worktree records the worktree's top.
    export_snapshot(_request(root / "sub"), POLICY, database, gate=_open)
    top = os.path.realpath(root)
    assert database.root == top and _record(folder)["root"] == top
    again = ExportDatabase(folder)
    assert again.root == top and again.export_id == database.export_id


def test_a_folder_that_cannot_be_shown_is_recorded_as_none(tmp_path: Path) -> None:
    database = ExportDatabase(tmp_path / "export")
    database.remember_root(Path("/srv/app"))
    assert database.root == "/srv/app"
    for unshowable in ("/srv/new\nline", "/srv/\x1b[2Japp", "/" + "a" * 4_100):
        database.remember_root(Path(unshowable))
        assert database.root is None, unshowable
        assert _record(tmp_path / "export")["root"] is None


@pytest.mark.parametrize("root", ["relative/app", "/srv/../app", "/srv/new\nline", 7, ["/srv/app"]])
def test_a_record_naming_a_folder_out_of_shape_is_not_trusted(tmp_path: Path, root: object) -> None:
    folder = tmp_path / "code-export" / ("a" * 32)
    database = ExportDatabase(folder)
    database.remember_root(Path("/srv/app"))
    first = database.export_id
    document = _record(folder)
    document["root"] = root
    (folder / "export.json").write_bytes(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )
    (listed,) = export_records(tmp_path / "code-export")
    assert listed.readable is False and listed.root is None and listed.short_id == "a" * 8
    # The exporter starts a new export from it: nothing the record named is trusted.
    fresh = ExportDatabase(folder)
    assert fresh.export_id != first and fresh.root is None and fresh.sent == ()


def test_export_records_lists_every_entry_in_order_and_never_creates_or_follows(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "code-export"
    assert export_records(directory) == ()
    assert not directory.exists()
    good = ExportDatabase(directory / ("b" * 32))
    good.remember_root(Path("/srv/app"))
    ExportDatabase(directory / ("a" * 32))
    damaged = directory / ("c" * 32)
    damaged.mkdir(mode=0o700)
    (damaged / "export.json").write_bytes(b"{not json\n")
    (damaged / "export.json").chmod(0o600)
    loose = directory / ("d" * 32)
    loose.mkdir(mode=0o700)
    (loose / "export.json").write_bytes((directory / ("b" * 32) / "export.json").read_bytes())
    (loose / "export.json").chmod(0o644)
    (directory / "stray name").write_bytes(b"")
    listed = export_records(directory)
    assert [(r.short_id, r.root, r.readable) for r in listed[:4]] == [
        ("a" * 8, None, True),
        ("b" * 8, "/srv/app", True),
        ("c" * 8, None, False),
        ("d" * 8, None, False),
    ]
    stray = listed[4]
    assert stray.readable is False and stray.root is None and "stray" not in stray.short_id
    assert len(stray.short_id) == 8 and len(listed) == 5
    linked = tmp_path / "linked"
    linked.symlink_to(directory)
    with pytest.raises(ExportRefused, match="code_export_unsafe"):
        export_records(linked)
    (tmp_path / "file").write_bytes(b"")
    with pytest.raises(ExportRefused, match="code_export_unsafe"):
        export_records(tmp_path / "file")


def test_an_incremental_export_reuses_a_held_link_target_the_server_accepts(
    tmp_path: Path,
) -> None:
    # B7: the closure tells the verifier which held blobs may be link targets.
    root = _repository(tmp_path, {"README.md": b"readme\n", "note": b"README.md", "bin": b"a\x00b"})
    (root / "link").symlink_to("README.md")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "m")
    database = ExportDatabase(tmp_path / "export")
    first = export_snapshot(_request(root), POLICY, database, gate=_open)
    database.remember_sent(first.manifest.snapshot, first.ref_number)
    (root / "README.md").write_bytes(b"changed\n")
    (root / "other").symlink_to("README.md")
    second = export_snapshot(
        _request(root, have=(first.manifest.snapshot,)), POLICY, database, gate=_open
    )
    assert not second.unchanged
    have = code_export._closure(database, (first.manifest.snapshot,), 1 << 20)  # pyright: ignore[reportPrivateUsage]
    target = have[GitObject("blob", b"README.md").oid]
    assert target.link_safe is True
    assert have[GitObject("blob", b"a\x00b").oid].link_safe is False
    verified = verify_snapshot_bundle(
        second.bundle, have=have.get, limits=BundleLimits(max_file_bytes=65_536)
    )
    assert GitObject("blob", b"README.md").oid not in verified.objects
