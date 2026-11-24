"""`finishup privacy export-desired --output` names an unwritable path instead of failing inside.

It also leaves what a plain write leaves: a symlink is followed and kept, an existing file keeps
its permissions, group, access-control list, extended attributes and other hard links, and a
device or pipe is written directly.
"""

from __future__ import annotations

import errno
import json
import os
import stat
import struct
import sys
from pathlib import Path

import pytest
from tests.unit.config.test_privacy_desired import (
    _policy,  # pyright: ignore[reportPrivateUsage]
)

import finishup.cli.app as app
import finishup.config.paths as paths
from finishup.config.privacy_desired import (
    _to_json,  # pyright: ignore[reportPrivateUsage]
    load_privacy_desired_canonical,
    render_privacy_desired_toml,
)

_REMEDY = (
    "privacy_desired_output_unwritable: Nothing was saved. Choose a writable file path in an "
    "existing directory and export again."
)
_INCOMPLETE = (
    "privacy_desired_output_incomplete: The write stopped part-way, so the file may be "
    "incomplete. Export again, or choose another writable file path."
)


class _Client:
    def __init__(self, policy: object) -> None:
        self._policy = policy

    async def privacy_get_effective(self, _request: object) -> object:
        return {"policy": self._policy}

    async def close(self) -> None:
        return None


def _run_export(
    target: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *extra: str,
) -> int | str | None:
    def state_dir(**_kwargs: object) -> Path:
        return tmp_path / "state"

    monkeypatch.setattr(paths, "state_dir", state_dir)
    policy = _to_json(_policy(network=False, telemetry=False))

    async def connect(*_args: object, **_kwargs: object) -> _Client:
        return _Client(policy)

    monkeypatch.setattr(app, "build_service_client", connect)
    monkeypatch.setattr(app, "_machine_scope_request_or_none", lambda: {"scope": "machine"})
    monkeypatch.setattr(
        sys, "argv", ["finishup", "privacy", "export-desired", "--output", str(target), *extra]
    )
    with pytest.raises(SystemExit) as raised:
        app.main()
    return raised.value.code


def _unwritable_target(kind: str, tmp_path: Path) -> Path:
    if kind == "directory":
        target = tmp_path / "existing-directory"
        target.mkdir()
        return target
    if kind == "parent_is_file":
        parent = tmp_path / "plain-file"
        parent.write_text("x", encoding="utf-8")
        return parent / "policy.toml"
    parent = tmp_path / "read-only"
    parent.mkdir()
    parent.chmod(0o500)
    return parent / "policy.toml"


@pytest.mark.parametrize("json_flag", [(), ("--json",)])
@pytest.mark.parametrize("kind", ["directory", "parent_is_file", "read_only_parent"])
def test_unwritable_output_is_a_named_refusal_and_saves_nothing(
    kind: str,
    json_flag: tuple[str, ...],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    if kind == "read_only_parent" and os.geteuid() == 0:
        pytest.skip("a superuser can write beneath a read-only directory")
    target = _unwritable_target(kind, tmp_path)
    try:
        code = _run_export(target, tmp_path, monkeypatch, *json_flag)
    finally:
        if kind == "read_only_parent":
            target.parent.chmod(0o700)
    captured = capsys.readouterr()
    assert code == 2, captured.err
    assert captured.err.strip() == _REMEDY
    assert "internal_error" not in captured.err
    assert str(target) not in captured.err
    assert captured.out == ""
    if kind == "read_only_parent":
        assert list(target.parent.iterdir()) == []
    if kind == "directory":
        assert list(target.iterdir()) == []


def test_export_writes_the_whole_file_and_leaves_no_temporary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "out"
    destination.mkdir()
    target = destination / "policy.toml"
    target.write_text("stale", encoding="utf-8")

    code = _run_export(target, tmp_path, monkeypatch, "--json")

    assert code == 0, capsys.readouterr().err
    assert [entry.name for entry in destination.iterdir()] == ["policy.toml"]
    load_privacy_desired_canonical(target)


def _entries(directory: Path) -> list[str]:
    return sorted(entry.name for entry in directory.iterdir())


def _permissions(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _stale_file(tmp_path: Path, mode: int = 0o644) -> Path:
    destination = tmp_path / "out"
    destination.mkdir()
    target = destination / "policy.toml"
    target.write_text("stale", encoding="utf-8")
    target.chmod(mode)
    return target


def _group_a_new_file_would_not_get(directory: Path) -> int | None:
    probe = directory / "probe"
    probe.touch()
    default = probe.stat().st_gid
    probe.unlink()
    return next((group for group in os.getgroups() if group != default), None)


def _errno_name(code: int) -> str:
    return errno.errorcode[code]


def _octal(bits: int) -> str:
    return f"{bits:04o}"


# Linux keeps a file's access-control list, and the list a folder gives each new file, in these
# extended attributes.
_ACCESS_LIST = "system.posix_acl_access"
_FOLDER_DEFAULT_LIST = "system.posix_acl_default"


def _access_list_with_a_named_user() -> bytes:
    """An access-control list in the kernel's layout: the owning group reads, a named user writes.

    The mask lets a named user write, and a file's permission bits show the mask where its group
    bits are, so the file reads as 0660 while its group may only read. The named user is this
    one, the only number every container is sure to accept.
    """

    unnamed = 0xFFFFFFFF
    entries = (
        (0x01, 0o6, unnamed),  # the owner
        (0x02, 0o6, os.getuid()),  # a user named by number
        (0x04, 0o4, unnamed),  # the owning group
        (0x10, 0o6, unnamed),  # the mask: the most a named user or the group gets
        (0x20, 0o0, unnamed),  # everyone else
    )
    return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in entries)


def _attributes(path: Path) -> dict[str, bytes]:
    if sys.platform != "linux":
        return {}
    return {name: os.getxattr(path, name) for name in os.listxattr(path)}


def _set_attribute(path: Path, name: str, value: bytes) -> None:
    if sys.platform != "linux":
        pytest.skip("Python reads and writes extended attributes only on Linux")
    try:
        os.setxattr(path, name, value)
    except OSError as error:
        if error.errno != errno.ENOTSUP:
            raise
        pytest.skip("this file system does not keep the attribute")


@pytest.mark.parametrize("spelling", ["absolute", "relative"])
def test_export_through_a_symlink_replaces_the_file_it_names_and_keeps_the_link(
    spelling: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    tracked = tmp_path / "tracked"
    tracked.mkdir()
    real = tracked / "policy.toml"
    real.write_text("stale", encoding="utf-8")
    real.chmod(0o640)
    linked = tmp_path / "linked"
    linked.mkdir()
    link = linked / "policy.toml"
    link.symlink_to(real if spelling == "absolute" else Path("..", "tracked", "policy.toml"))
    pointer = os.readlink(link)

    code = _run_export(link, tmp_path, monkeypatch, "--json")

    captured = capsys.readouterr()
    assert code == 0, captured.err
    assert json.loads(captured.out)["path"] == str(link)
    assert link.is_symlink()
    assert os.readlink(link) == pointer
    load_privacy_desired_canonical(real)
    assert _permissions(real) == 0o640
    assert _entries(tracked) == ["policy.toml"]
    assert _entries(linked) == ["policy.toml"]


def test_export_through_a_symlink_to_no_file_yet_creates_that_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    tracked = tmp_path / "tracked"
    tracked.mkdir()
    real = tracked / "policy.toml"
    linked = tmp_path / "linked"
    linked.mkdir()
    link = linked / "policy.toml"
    link.symlink_to(real)

    code = _run_export(link, tmp_path, monkeypatch)

    assert code == 0, capsys.readouterr().err
    assert link.is_symlink()
    load_privacy_desired_canonical(real)
    assert _entries(tracked) == ["policy.toml"]
    assert _entries(linked) == ["policy.toml"]


@pytest.mark.parametrize("mode", [0o600, 0o640, 0o644, 0o664], ids=_octal)
def test_export_replaces_an_existing_file_whole_and_keeps_its_permissions(
    mode: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = _stale_file(tmp_path, mode)
    before = target.stat()

    code = _run_export(target, tmp_path, monkeypatch)

    assert code == 0, capsys.readouterr().err
    load_privacy_desired_canonical(target)
    assert _permissions(target) == mode
    # A new file took the old one's place: the old one was never open for writing.
    assert target.stat().st_ino != before.st_ino
    assert _entries(target.parent) == ["policy.toml"]


@pytest.mark.parametrize("mask", [0o022, 0o027, 0o077], ids=_octal)
def test_a_new_export_file_gets_the_permissions_any_new_file_would(
    mask: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "out"
    destination.mkdir()
    target = destination / "policy.toml"
    previous = os.umask(mask)
    try:
        code = _run_export(target, tmp_path, monkeypatch)
    finally:
        os.umask(previous)

    assert code == 0, capsys.readouterr().err
    load_privacy_desired_canonical(target)
    assert _permissions(target) == 0o666 & ~mask
    assert _entries(destination) == ["policy.toml"]


def test_export_to_a_pipe_writes_into_it_and_leaves_the_pipe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "out"
    destination.mkdir()
    pipe = destination / "policy.pipe"
    os.mkfifo(pipe)
    # A reader that is already open lets the writer's open return at once.
    reader = os.open(pipe, os.O_RDONLY | os.O_NONBLOCK)
    try:
        code = _run_export(pipe, tmp_path, monkeypatch)
        try:
            received = os.read(reader, 1 << 20)
        except BlockingIOError:
            received = b""
    finally:
        os.close(reader)

    assert code == 0, capsys.readouterr().err
    assert stat.S_ISFIFO(pipe.lstat().st_mode)
    expected = render_privacy_desired_toml(_policy(network=False, telemetry=False))
    assert received == expected.encode("utf-8")
    assert _entries(destination) == ["policy.pipe"]


def test_export_to_a_device_writes_it_directly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    if os.geteuid() == 0:
        pytest.skip("a superuser could replace the device node if this ever regressed")
    device = Path(os.devnull)

    code = _run_export(device, tmp_path, monkeypatch, "--json")

    captured = capsys.readouterr()
    assert code == 0, captured.err
    assert json.loads(captured.out)["path"] == str(device)
    assert stat.S_ISCHR(device.stat().st_mode)


def test_export_rewrites_a_writable_file_in_a_folder_that_takes_no_new_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    if os.geteuid() == 0:
        pytest.skip("a superuser can create files in a read-only directory")
    target = _stale_file(tmp_path, 0o640)
    before = target.stat()
    target.parent.chmod(0o500)
    try:
        code = _run_export(target, tmp_path, monkeypatch)
    finally:
        target.parent.chmod(0o700)

    assert code == 0, capsys.readouterr().err
    load_privacy_desired_canonical(target)
    assert (target.stat().st_ino, _permissions(target)) == (before.st_ino, 0o640)
    assert _entries(target.parent) == ["policy.toml"]


def test_export_refuses_a_file_that_may_not_be_written_and_leaves_it_as_it_was(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    if os.geteuid() == 0:
        pytest.skip("a superuser can write a read-only file")
    target = _stale_file(tmp_path, 0o444)
    before = target.stat()

    code = _run_export(target, tmp_path, monkeypatch)

    captured = capsys.readouterr()
    assert code == 2, captured.err
    assert captured.err.strip() == _REMEDY
    assert captured.out == ""
    assert target.read_text(encoding="utf-8") == "stale"
    assert (target.stat().st_ino, _permissions(target)) == (before.st_ino, 0o444)
    assert _entries(target.parent) == ["policy.toml"]


def test_export_writes_a_file_whose_name_leaves_no_room_for_a_temporary_beside_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "out"
    destination.mkdir()
    longest = os.pathconf(destination, "PC_NAME_MAX")
    target = destination / ("p" * (longest - len(".toml")) + ".toml")

    code = _run_export(target, tmp_path, monkeypatch)

    assert code == 0, capsys.readouterr().err
    load_privacy_desired_canonical(target)
    assert _entries(destination) == [target.name]


def test_export_reaches_every_hard_link_to_the_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = _stale_file(tmp_path)
    other = target.with_name("tracked.toml")
    os.link(target, other)

    code = _run_export(target, tmp_path, monkeypatch)

    assert code == 0, capsys.readouterr().err
    load_privacy_desired_canonical(target)
    load_privacy_desired_canonical(other)
    assert os.path.samefile(target, other)
    assert _entries(target.parent) == ["policy.toml", "tracked.toml"]


def test_export_keeps_an_existing_files_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = _stale_file(tmp_path, 0o660)
    group = _group_a_new_file_would_not_get(target.parent)
    if group is None:
        pytest.skip("needs a second group to give the existing file")
    os.chown(target, -1, group)
    before = target.stat()

    code = _run_export(target, tmp_path, monkeypatch)

    assert code == 0, capsys.readouterr().err
    load_privacy_desired_canonical(target)
    after = target.stat()
    assert (after.st_uid, after.st_gid, _permissions(target)) == (before.st_uid, group, 0o660)
    assert after.st_ino != before.st_ino


def test_export_rewrites_in_place_a_file_whose_owner_it_may_not_give_a_new_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = _stale_file(tmp_path, 0o660)
    group = _group_a_new_file_would_not_get(target.parent)
    if group is None:
        pytest.skip("needs a second group to give the existing file")
    os.chown(target, -1, group)
    before = target.stat()

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))

    monkeypatch.setattr(os, "fchown", refuse)

    code = _run_export(target, tmp_path, monkeypatch)

    assert code == 0, capsys.readouterr().err
    load_privacy_desired_canonical(target)
    after = target.stat()
    assert (after.st_ino, after.st_gid, _permissions(target)) == (before.st_ino, group, 0o660)
    assert _entries(target.parent) == ["policy.toml"]


def test_export_writes_in_place_a_file_that_has_an_access_control_list(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = _stale_file(tmp_path, 0o640)
    _set_attribute(target, _ACCESS_LIST, _access_list_with_a_named_user())
    before = target.stat()
    listed = _attributes(target)
    assert _permissions(target) == 0o660

    code = _run_export(target, tmp_path, monkeypatch)

    assert code == 0, capsys.readouterr().err
    load_privacy_desired_canonical(target)
    # A new file given mode 0660 would let the owning group write and would name no user.
    assert _attributes(target) == listed
    assert (target.stat().st_ino, _permissions(target)) == (before.st_ino, 0o660)
    assert _entries(target.parent) == ["policy.toml"]


def test_export_writes_in_place_a_file_without_the_access_list_its_folder_gives_new_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = _stale_file(tmp_path, 0o640)
    _set_attribute(target.parent, _FOLDER_DEFAULT_LIST, _access_list_with_a_named_user())
    before = target.stat()
    listed = _attributes(target)
    assert _ACCESS_LIST not in listed

    code = _run_export(target, tmp_path, monkeypatch)

    assert code == 0, capsys.readouterr().err
    load_privacy_desired_canonical(target)
    # A new file here would name a user the old file gave nothing to.
    assert _attributes(target) == listed
    assert (target.stat().st_ino, _permissions(target)) == (before.st_ino, 0o640)
    assert _entries(target.parent) == ["policy.toml"]


def test_export_replaces_a_file_whose_access_list_is_the_one_its_folder_gives_new_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "out"
    destination.mkdir()
    _set_attribute(destination, _FOLDER_DEFAULT_LIST, _access_list_with_a_named_user())
    target = destination / "policy.toml"
    target.write_text("stale", encoding="utf-8")
    before = target.stat()
    listed = _attributes(target)
    assert _ACCESS_LIST in listed

    code = _run_export(target, tmp_path, monkeypatch)

    assert code == 0, capsys.readouterr().err
    load_privacy_desired_canonical(target)
    assert _attributes(target) == listed
    assert _permissions(target) == stat.S_IMODE(before.st_mode)
    assert target.stat().st_ino != before.st_ino
    assert _entries(destination) == ["policy.toml"]


def test_export_writes_in_place_a_file_with_an_attribute_a_new_file_would_not_have(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = _stale_file(tmp_path, 0o640)
    _set_attribute(target, "user.note", b"kept")
    before = target.stat()
    listed = _attributes(target)
    assert listed["user.note"] == b"kept"

    code = _run_export(target, tmp_path, monkeypatch)

    assert code == 0, capsys.readouterr().err
    load_privacy_desired_canonical(target)
    assert _attributes(target) == listed
    assert (target.stat().st_ino, _permissions(target)) == (before.st_ino, 0o640)
    assert _entries(target.parent) == ["policy.toml"]


def test_export_writes_in_place_a_file_whose_attributes_cannot_be_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    if sys.platform != "linux":
        pytest.skip("Python reads and writes extended attributes only on Linux")
    target = _stale_file(tmp_path, 0o640)
    before = target.stat()

    def refuse(*_args: object, **_kwargs: object) -> list[str]:
        raise OSError(errno.EIO, os.strerror(errno.EIO))

    monkeypatch.setattr(os, "listxattr", refuse)

    code = _run_export(target, tmp_path, monkeypatch)

    assert code == 0, capsys.readouterr().err
    load_privacy_desired_canonical(target)
    assert (target.stat().st_ino, _permissions(target)) == (before.st_ino, 0o640)
    assert _entries(target.parent) == ["policy.toml"]


def test_export_replaces_a_file_on_a_file_system_that_has_no_attributes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    if sys.platform != "linux":
        pytest.skip("Python reads and writes extended attributes only on Linux")
    target = _stale_file(tmp_path, 0o640)
    before = target.stat()

    def unsupported(*_args: object, **_kwargs: object) -> list[str]:
        raise OSError(errno.ENOTSUP, os.strerror(errno.ENOTSUP))

    monkeypatch.setattr(os, "listxattr", unsupported)

    code = _run_export(target, tmp_path, monkeypatch)

    assert code == 0, capsys.readouterr().err
    load_privacy_desired_canonical(target)
    assert target.stat().st_ino != before.st_ino
    assert _permissions(target) == 0o640
    assert _entries(target.parent) == ["policy.toml"]


def _fail_the_rename_onto(target: Path, code: int, monkeypatch: pytest.MonkeyPatch) -> None:
    rename = os.replace

    def replace(source: str | Path, destination: str | Path) -> None:
        if os.path.realpath(destination) == os.path.realpath(target):
            raise OSError(code, os.strerror(code))
        rename(source, destination)

    monkeypatch.setattr(os, "replace", replace)


@pytest.mark.parametrize(
    "refusal", [errno.EBUSY, errno.EXDEV, errno.EPERM, errno.EACCES], ids=_errno_name
)
def test_export_rewrites_in_place_a_file_the_folder_will_not_let_it_replace(
    refusal: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = _stale_file(tmp_path, 0o640)
    before = target.stat()
    _fail_the_rename_onto(target, refusal, monkeypatch)

    code = _run_export(target, tmp_path, monkeypatch)

    assert code == 0, capsys.readouterr().err
    load_privacy_desired_canonical(target)
    assert (target.stat().st_ino, _permissions(target)) == (before.st_ino, 0o640)
    assert _entries(target.parent) == ["policy.toml"]


@pytest.mark.parametrize("failure", [errno.ENOSPC, errno.EDQUOT, errno.EIO], ids=_errno_name)
def test_failing_storage_leaves_the_existing_file_as_it_was(
    failure: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = _stale_file(tmp_path)
    _fail_the_rename_onto(target, failure, monkeypatch)

    code = _run_export(target, tmp_path, monkeypatch)

    captured = capsys.readouterr()
    assert code == 2, captured.err
    assert captured.err.strip() == _REMEDY
    assert captured.out == ""
    assert target.read_text(encoding="utf-8") == "stale"
    assert _entries(target.parent) == ["policy.toml"]


def _fail_every_flush(code: int, monkeypatch: pytest.MonkeyPatch) -> None:
    def fsync(_descriptor: int) -> None:
        raise OSError(code, os.strerror(code))

    monkeypatch.setattr(os, "fsync", fsync)


@pytest.mark.parametrize("refusal", [errno.EINVAL, errno.ENOSYS, errno.ENOTSUP], ids=_errno_name)
def test_export_replaces_a_file_on_storage_that_cannot_be_told_to_flush(
    refusal: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = _stale_file(tmp_path, 0o640)
    before = target.stat()
    _fail_every_flush(refusal, monkeypatch)

    code = _run_export(target, tmp_path, monkeypatch)

    assert code == 0, capsys.readouterr().err
    load_privacy_desired_canonical(target)
    assert target.stat().st_ino != before.st_ino
    assert _permissions(target) == 0o640
    assert _entries(target.parent) == ["policy.toml"]


@pytest.mark.parametrize("failure", [errno.ENOSPC, errno.EDQUOT, errno.EIO], ids=_errno_name)
def test_a_flush_that_fails_leaves_the_existing_file_as_it_was(
    failure: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = _stale_file(tmp_path)
    before = target.stat()
    _fail_every_flush(failure, monkeypatch)

    code = _run_export(target, tmp_path, monkeypatch)

    captured = capsys.readouterr()
    assert code == 2, captured.err
    assert captured.err.strip() == _REMEDY
    assert captured.out == ""
    assert target.read_text(encoding="utf-8") == "stale"
    assert target.stat().st_ino == before.st_ino
    assert _entries(target.parent) == ["policy.toml"]


@pytest.mark.parametrize("json_flag", [(), ("--json",)], ids=["text", "json"])
def test_a_direct_write_that_stops_part_way_says_the_file_may_be_incomplete(
    json_flag: tuple[str, ...],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # `/dev/full` opens for writing and then refuses every byte, as a full disk would.
    device = Path("/dev/full")
    if not device.is_char_device():
        pytest.skip("needs a device that opens for writing and refuses the bytes")
    if os.geteuid() == 0:
        pytest.skip("a superuser could replace the device node if this ever regressed")

    code = _run_export(device, tmp_path, monkeypatch, *json_flag)

    captured = capsys.readouterr()
    assert code == 2, captured.err
    assert captured.err.strip() == _INCOMPLETE
    assert "internal_error" not in captured.err
    assert str(device) not in captured.err
    assert captured.out == ""
