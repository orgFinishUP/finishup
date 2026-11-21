"""The object-store fence lists the loose-object fan-out directories once (ADR-031).

``_refuse_unsafe_object_store`` takes the identity of every ``.git/objects/00``..``ff`` from one
listing of ``.git/objects`` instead of 256 walks from the root. That is a speed-up only: every
test here compares the fence's snapshot or refusal with the retained one-walk-per-name path and
counts the walks the listing saves.
"""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest

import finishup.adapters.git_change_capture as capture_module
from finishup.adapters.git_change_capture import ChangeCaptureUnavailable, GitChangeCaptureAdapter


def _git(repository: Path, *arguments: str) -> None:
    subprocess.run(
        ("git", *arguments),
        cwd=repository,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        env={
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": os.fspath(repository),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.defpath,
        },
    )


@pytest.fixture(autouse=True)
def isolated_global_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", os.fspath(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)


def _repository(tmp_path: Path, *, packed: bool = True) -> Path:
    repository = tmp_path / "repo"
    repository.mkdir(mode=0o700)
    _git(repository, "init", "--quiet")
    for index in range(12):
        (repository / f"file_{index}.txt").write_text(f"content {index}\n", encoding="utf-8")
    _git(repository, "add", "-A")
    _git(
        repository,
        "-c",
        "user.name=FinishUP Test",
        "-c",
        "user.email=finishup@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "baseline",
    )
    if not packed:
        # Without a pack directory the fence returns its snapshot unsorted, in listing order.
        pack = repository / ".git" / "objects" / "pack"
        for entry in pack.iterdir():
            entry.unlink()
        pack.rmdir()
    return repository


def _fence(repository: Path) -> tuple[object, ...]:
    adapter: Any = GitChangeCaptureAdapter()
    pinned = adapter._open(os.fspath(repository), time.monotonic() + 30.0)
    try:
        return ("ok", adapter._refuse_unsafe_object_store(pinned))
    except ChangeCaptureUnavailable as exc:
        return ("refused", exc.reason)
    finally:
        os.close(pinned.descriptor)


def _no_listing(_root_descriptor: int) -> None:
    return None


def _both(
    repository: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[tuple[object, ...], tuple[object, ...]]:
    listed = _fence(repository)
    with monkeypatch.context() as patched:
        patched.setattr(capture_module, "_listed_fan_out_identities", _no_listing)
        walked = _fence(repository)
    return listed, walked


def _counted_walks(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    real: Callable[[int, bytes], object] = getattr(capture_module, "_path_identity")
    walks: list[bytes] = []

    def counted(root_descriptor: int, path: bytes) -> object:
        walks.append(path)
        return real(root_descriptor, path)

    monkeypatch.setattr(capture_module, "_path_identity", counted)
    return walks


@pytest.mark.parametrize("packed", [True, False])
def test_listed_fan_outs_equal_one_walk_per_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, packed: bool
) -> None:
    repository = _repository(tmp_path, packed=packed)
    objects = repository / ".git" / "objects"
    # Names that are not two hex digits are not fan-out directories.
    for ignored in ("zz", "abc", "a", "A", "ABC"):
        (objects / ignored).mkdir()
    (objects / "ef0").write_text("not a fan-out\n", encoding="utf-8")

    listed, walked = _both(repository, monkeypatch)

    assert listed == walked
    assert listed[0] == "ok"
    snapshot = cast(tuple[tuple[bytes, object], ...], listed[1])
    names = [name for name, _ in snapshot]
    assert b".git/objects/ABC" not in names and b".git/objects/zz" not in names
    walks = _counted_walks(monkeypatch)
    assert _fence(repository) == listed
    # Only ``info`` and ``pack`` are still walked from the root; the 256 fan-outs are listed.
    assert walks == [b".git/objects/info", b".git/objects/pack"]


@pytest.mark.parametrize("name", ["AB", "Cd", "eF", "\ufb00"])
@pytest.mark.parametrize("kind", ["directory", "file", "symlink"])
def test_a_name_another_file_system_could_fold_onto_a_fan_out_is_walked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, kind: str
) -> None:
    """On a case-insensitive file system the walk of ``ab`` finds ``AB``; only the walk decides.

    This file system is case-sensitive, so the listing cannot be shown to differ here: it must
    give up whenever such a name is present, and the walk then answers exactly as before.
    """

    repository = _repository(tmp_path)
    target = repository / ".git" / "objects" / name
    if kind == "directory":
        target.mkdir()
    elif kind == "file":
        target.write_text("not a fan-out\n", encoding="utf-8")
    else:
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        target.symlink_to(elsewhere)
    adapter: Any = GitChangeCaptureAdapter()
    pinned = adapter._open(os.fspath(repository), time.monotonic() + 30.0)
    try:
        assert getattr(capture_module, "_listed_fan_out_identities")(pinned.descriptor) is None
    finally:
        os.close(pinned.descriptor)

    walks = _counted_walks(monkeypatch)
    listed, walked = _both(repository, monkeypatch)

    assert listed == walked
    assert listed[0] == "ok"
    # Every fan-out name was walked from the root, as before the listing existed.
    assert len(walks) == 2 * 258


@pytest.mark.parametrize("kind", ["file", "symlink"])
def test_a_fan_out_that_is_not_a_directory_is_refused_the_same_way(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    repository = _repository(tmp_path)
    objects = repository / ".git" / "objects"
    target = objects / "fe"
    if target.exists():
        for entry in target.iterdir():
            entry.unlink()
        target.rmdir()
    if kind == "file":
        target.write_text("not a directory\n", encoding="utf-8")
    else:
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        target.symlink_to(elsewhere)

    listed, walked = _both(repository, monkeypatch)

    assert listed == walked == ("refused", "unsafe_root")


def test_an_unreadable_object_directory_is_decided_by_one_walk_per_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.geteuid() == 0:
        pytest.skip("root reads any directory")
    repository = _repository(tmp_path)
    objects = repository / ".git" / "objects"
    adapter: Any = GitChangeCaptureAdapter()
    pinned = adapter._open(os.fspath(repository), time.monotonic() + 30.0)

    def outcome() -> tuple[object, ...]:
        try:
            return ("ok", adapter._refuse_unsafe_object_store(pinned))
        except ChangeCaptureUnavailable as exc:
            return ("refused", exc.reason)

    # Searchable but not readable: no listing, so each name is walked as before.
    objects.chmod(0o300)
    try:
        assert getattr(capture_module, "_listed_fan_out_identities")(pinned.descriptor) is None
        walks = _counted_walks(monkeypatch)
        fallback = outcome()
        fallback_walks = list(walks)
        monkeypatch.setattr(capture_module, "_listed_fan_out_identities", _no_listing)
        walked = outcome()
    finally:
        objects.chmod(0o700)
        os.close(pinned.descriptor)

    assert fallback == walked == ("refused", "unsafe_root")
    # Refused at the first name, exactly where the walk alone stops.
    assert fallback_walks == [b".git/objects/00"]
