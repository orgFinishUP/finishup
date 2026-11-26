"""The object-store fence lists the loose-object fan-out directories once (ADR-031).

``_refuse_unsafe_object_store`` takes the identity of every ``.git/objects/00``..``ff`` from one
listing of ``.git/objects`` instead of 256 walks from the root. That is a speed-up only: every
test here compares the fence's snapshot or refusal with the retained one-walk-per-name path and
counts the walks the listing saves. They hold on file systems that fold case or U+FB00 (default
APFS, ext4 casefold) as well as on ones that fold neither.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest

import finishup.adapters.git_change_capture as capture_module
import finishup.adapters.git_subject_state as subject_state_module
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
            # A fixed date fixes the baseline commit's name, and so the fan-out directory it is
            # stored in: no planted name can meet it there by the clock's chance.
            "GIT_AUTHOR_DATE": "2001-02-03T04:05:06Z",
            "GIT_COMMITTER_DATE": "2001-02-03T04:05:06Z",
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


def _release(pinned: Any) -> None:
    """Close the pinned root through the handle that owns it, so it is closed exactly once.

    Closing ``pinned.descriptor`` directly leaves the owner to close the same number again when
    it is collected, which shuts whatever file has reused that number by then: on macOS, where
    the refusal cases keep the handle alive until a later garbage collection, that was the
    observation store's lock in the next test module.
    """

    payload = getattr(subject_state_module, "_workspace_payload")(pinned.handle)
    payload.close()
    assert payload.descriptor == -1


def _fence(repository: Path) -> tuple[object, ...]:
    adapter: Any = GitChangeCaptureAdapter()
    pinned = adapter._open(os.fspath(repository), time.monotonic() + 30.0)
    try:
        return ("ok", adapter._refuse_unsafe_object_store(pinned))
    except ChangeCaptureUnavailable as exc:
        return ("refused", exc.reason)
    finally:
        _release(pinned)


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


def _folds_onto(probe: Path, name: str, fan_out: str) -> bool:
    """Whether a lookup of ``fan_out`` finds an entry stored as ``name`` on this file system.

    A case-insensitive file system (default APFS, HFS+, ext4 casefold, WSL's drvfs) folds ``AB``
    onto ``ab``; default APFS and ext4 casefold fold U+FB00 onto ``ff`` as well. ``probe`` is a
    fresh directory beside the repository, so it answers for the file system the repository is on.
    """

    probe.mkdir()
    (probe / name).touch()
    return os.path.lexists(probe / fan_out)


def _model_folding_lookups(monkeypatch: pytest.MonkeyPatch, repository: Path) -> None:
    """Make the walk find an entry stored under any spelling that folds to the name it looks up.

    This models a folding file system on one that is not: only a lookup by name folds, so the
    listing, which reports each name as it is stored, is left as it is.
    """

    real: Callable[[int, bytes], object] = getattr(capture_module, "_path_identity")

    def folding(root_descriptor: int, path: bytes) -> object:
        identity = real(root_descriptor, path)
        if identity is not None:
            return identity
        parent, _, leaf = path.rpartition(b"/")
        wanted = os.fsdecode(leaf).casefold()
        for stored in os.listdir(repository / os.fsdecode(parent)):
            if stored.casefold() == wanted:
                return real(root_descriptor, parent + b"/" + os.fsencode(stored))
        return None

    monkeypatch.setattr(capture_module, "_path_identity", folding)


@pytest.mark.parametrize("packed", [True, False])
def test_listed_fan_outs_equal_one_walk_per_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, packed: bool
) -> None:
    repository = _repository(tmp_path, packed=packed)
    objects = repository / ".git" / "objects"
    # Names that are not two hex digits are not fan-out directories. No two of them fold to the
    # same name, so they stay distinct on a file system that folds case.
    for ignored in ("zz", "abc", "a", "B", "DEF"):
        (objects / ignored).mkdir()
    (objects / "ef0").write_text("not a fan-out\n", encoding="utf-8")

    listed, walked = _both(repository, monkeypatch)

    assert listed == walked
    assert listed[0] == "ok"
    snapshot = cast(tuple[tuple[bytes, object], ...], listed[1])
    names = [name for name, _ in snapshot]
    assert b".git/objects/DEF" not in names and b".git/objects/zz" not in names
    walks = _counted_walks(monkeypatch)
    assert _fence(repository) == listed
    # Only ``info`` and ``pack`` are still walked from the root; the 256 fan-outs are listed.
    assert walks == [b".git/objects/info", b".git/objects/pack"]


@pytest.mark.parametrize("name", ["AB", "Cd", "eF", "\ufb00"])
@pytest.mark.parametrize("kind", ["directory", "file", "symlink"])
@pytest.mark.parametrize("file_system", ["here", "folding"])
def test_a_name_another_file_system_could_fold_onto_a_fan_out_is_walked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, kind: str, file_system: str
) -> None:
    """On a case-insensitive file system the walk of ``ab`` finds ``AB``; only the walk decides.

    The listing must give up whenever such a name is present, and the walk then answers exactly
    as before. What the walk finds depends on the file system: ``here`` asks the one the test runs
    on; ``folding`` models a folding one on any file system, so both answers are checked
    everywhere.
    """

    fan_out = name.casefold()
    path = b".git/objects/" + fan_out.encode("ascii")
    repository = _repository(tmp_path)
    objects = repository / ".git" / "objects"
    # The fixture's objects leave this fan-out free, so the planted entry is the only thing a
    # lookup of it can find (and creating it cannot collide on a folding file system).
    assert not os.path.lexists(objects / fan_out)
    target = objects / name
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
        _release(pinned)

    if file_system == "folding":
        folds = True
        _model_folding_lookups(monkeypatch, repository)
    else:
        folds = _folds_onto(tmp_path / "fold-probe", name, fan_out)
    walks = _counted_walks(monkeypatch)
    listed, walked = _both(repository, monkeypatch)

    assert listed == walked
    fan_outs = [b".git/objects/%02x" % index for index in range(256)]
    if folds and kind != "directory":
        # The walk of the fan-out found a file or a link and refused there, as it always has.
        assert listed == ("refused", "unsafe_root")
        assert walks == 2 * fan_outs[: fan_outs.index(path) + 1]
        return
    assert listed[0] == "ok"
    snapshot = dict(cast(tuple[tuple[bytes, object], ...], listed[1]))
    # Where the walk finds the planted directory, it is fenced as the fan-out it answers for.
    if folds:
        assert snapshot[path] == getattr(capture_module, "_identity")(os.lstat(target))
    else:
        assert path not in snapshot
    # Every fan-out name was walked from the root, as before the listing existed.
    assert walks == 2 * [*fan_outs, b".git/objects/info", b".git/objects/pack"]


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
        _release(pinned)

    assert fallback == walked == ("refused", "unsafe_root")
    # Refused at the first name, exactly where the walk alone stops.
    assert fallback_walks == [b".git/objects/00"]


@pytest.mark.skipif(
    sys.platform != "darwin", reason="asks the volume through a macOS pathconf name"
)
def test_the_fold_probe_answers_as_the_macos_volume_says(tmp_path: Path) -> None:
    """The probe that picks the expectations above agrees with the volume's own answer.

    A default APFS volume is case-insensitive and folds U+FB00 onto ``ff`` too, so there the
    tests above take their folding expectations from the real lookup; a case-sensitive volume
    folds neither.
    """

    # ``_PC_CASE_SENSITIVE`` is 11 in macOS's <sys/unistd.h>, whether or not this Python names it.
    case_sensitive = os.pathconf(tmp_path, os.pathconf_names.get("PC_CASE_SENSITIVE", 11))
    assert case_sensitive in (0, 1)
    folds = case_sensitive == 0
    assert _folds_onto(tmp_path / "case", "AB", "ab") is folds
    assert _folds_onto(tmp_path / "ligature", "\ufb00", "ff") is folds


def test_releasing_a_pinned_root_never_closes_a_reused_descriptor(tmp_path: Path) -> None:
    """The helpers' release closes the root once; collecting the handle later closes nothing."""

    import gc

    repository = _repository(tmp_path)
    adapter: Any = GitChangeCaptureAdapter()
    pinned = adapter._open(os.fspath(repository), time.monotonic() + 30.0)
    number = pinned.descriptor
    _release(pinned)
    reused = os.open(tmp_path, os.O_RDONLY)
    try:
        del pinned
        gc.collect()
        assert os.fstat(reused) is not None
    finally:
        os.close(reused)
    assert number >= 0
