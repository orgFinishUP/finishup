"""Exact-byte approved-check policy parsing and local trust gates."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from finishup.application.observation_check_policy import (
    CHECK_POLICY_PATH,
    LEGACY_CHECK_POLICY_PATH,
    ObservationCheckPolicyAbsent,
    ObservationCheckPolicyAmbiguous,
    load_observation_check_policy,
    parse_observation_check_policy,
)
from finishup.protocol.errors import ProtocolValueError


def _policy(*, argv: str = '["/usr/bin/true"]') -> bytes:
    return (
        'format = "yoetz.approved-check-policy/1"\n'
        "\n"
        "[[checks]]\n"
        'id = "smoke"\n'
        f"argv = {argv}\n"
        "timeout_seconds = 10\n"
        "network = false\n"
    ).encode()


def test_policy_trust_identity_is_exact_raw_bytes() -> None:
    original = parse_observation_check_policy(_policy())
    whitespace_changed = parse_observation_check_policy(_policy() + b"\n")
    assert original.raw_digest != whitespace_changed.raw_digest
    assert original.checks[0].argv == ("/usr/bin/true",)
    assert original.checks[0].allow_network is False


def test_policy_rejects_unknown_fields_and_freeform_command() -> None:
    with pytest.raises(ProtocolValueError):
        parse_observation_check_policy(
            _policy().replace(b"network = false", b'network = false\ncommand = "true"')
        )
    with pytest.raises(ProtocolValueError):
        parse_observation_check_policy(_policy(argv='["/bin/sh", "-c", "echo unsafe"]'))


def test_policy_reader_rejects_symlinked_policy_directory(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "checks.toml").write_bytes(_policy())
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".finishup").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ProtocolValueError):
        load_observation_check_policy(workspace)


def test_policy_reader_accepts_fixed_in_workspace_file(tmp_path: Path) -> None:
    policy_dir = tmp_path / ".finishup"
    policy_dir.mkdir()
    (policy_dir / "checks.toml").write_bytes(_policy())
    policy, raw = load_observation_check_policy(tmp_path)
    assert raw == _policy()
    assert tuple(item.approval_id for item in policy.checks) == ("smoke",)


@pytest.mark.parametrize("make_dir", [False, True])
def test_policy_reader_reports_missing_policy_as_absent_not_invalid(
    tmp_path: Path, make_dir: bool
) -> None:
    if make_dir:
        (tmp_path / ".finishup").mkdir()
    with pytest.raises(ObservationCheckPolicyAbsent) as caught:
        load_observation_check_policy(tmp_path)
    # Still the invalid-policy failure for callers that only need "no usable policy".
    assert isinstance(caught.value, ProtocolValueError)
    assert caught.value.reason_code == "invalid_approved_check_policy"


def test_policy_reader_keeps_present_but_broken_policy_invalid(tmp_path: Path) -> None:
    policy_dir = tmp_path / ".finishup"
    policy_dir.mkdir()
    (policy_dir / "checks.toml").write_bytes(b"not = [valid")
    with pytest.raises(ProtocolValueError) as caught:
        load_observation_check_policy(tmp_path)
    assert not isinstance(caught.value, ObservationCheckPolicyAbsent)
    assert caught.value.reason_code == "invalid_approved_check_policy"


@pytest.mark.parametrize(
    "timeout",
    ["9" * 400, "1000", "-5", "0", "300.5", "1e400", "nan", "inf"],
    ids=["too_large_for_a_float", "1000", "-5", "0", "300.5", "1e400", "nan", "inf"],
)
def test_policy_with_an_unusable_timeout_is_an_invalid_policy(timeout: str) -> None:
    raw = _policy().replace(b"timeout_seconds = 10", f"timeout_seconds = {timeout}".encode())
    with pytest.raises(ProtocolValueError) as caught:
        parse_observation_check_policy(raw)
    assert caught.value.reason_code == "invalid_approved_check_policy"


def test_policy_with_an_unapprovable_argv_is_an_invalid_policy() -> None:
    with pytest.raises(ProtocolValueError) as caught:
        parse_observation_check_policy(_policy(argv='["/bin/sh", "-c", "echo unsafe"]'))
    assert caught.value.reason_code == "invalid_approved_check_policy"


@pytest.mark.parametrize("timeout", ["0.1", "300", "300.0"])
def test_policy_accepts_timeouts_at_the_approved_bounds(timeout: str) -> None:
    raw = _policy().replace(b"timeout_seconds = 10", f"timeout_seconds = {timeout}".encode())
    assert parse_observation_check_policy(raw).checks[0].timeout_seconds == float(timeout)


def test_policy_reader_reports_a_huge_timeout_as_invalid_not_a_crash(tmp_path: Path) -> None:
    policy_dir = tmp_path / ".finishup"
    policy_dir.mkdir()
    raw = _policy().replace(b"timeout_seconds = 10", b"timeout_seconds = " + b"9" * 400)
    (policy_dir / "checks.toml").write_bytes(raw)
    with pytest.raises(ProtocolValueError) as caught:
        load_observation_check_policy(tmp_path)
    assert caught.value.reason_code == "invalid_approved_check_policy"


@pytest.mark.parametrize("kind", ["file", "symlink"])
def test_policy_reader_treats_non_directory_policy_dir_as_invalid(
    tmp_path: Path, kind: str
) -> None:
    if kind == "file":
        (tmp_path / ".finishup").write_bytes(b"")
    else:
        (tmp_path / ".finishup").symlink_to(tmp_path / "missing-dir")
    with pytest.raises(ProtocolValueError) as caught:
        load_observation_check_policy(tmp_path)
    assert not isinstance(caught.value, ObservationCheckPolicyAbsent)


def test_policy_reader_treats_dangling_policy_symlink_as_invalid(tmp_path: Path) -> None:
    policy_dir = tmp_path / ".finishup"
    policy_dir.mkdir()
    (policy_dir / "checks.toml").symlink_to(tmp_path / "missing.toml")
    with pytest.raises(ProtocolValueError) as caught:
        load_observation_check_policy(tmp_path)
    assert not isinstance(caught.value, ObservationCheckPolicyAbsent)


def _write(workspace: Path, location: Path, raw: bytes) -> None:
    (workspace / location.parent).mkdir(exist_ok=True)
    (workspace / location).write_bytes(raw)


def test_policy_reader_reads_the_legacy_location_when_it_is_the_only_one(tmp_path: Path) -> None:
    _write(tmp_path, LEGACY_CHECK_POLICY_PATH, _policy())
    policy, raw = load_observation_check_policy(tmp_path)
    assert raw == _policy()
    assert policy.source_path == Path(".yoetz/checks.toml")


def test_policy_reader_names_the_finishup_location_when_it_is_the_only_one(
    tmp_path: Path,
) -> None:
    _write(tmp_path, CHECK_POLICY_PATH, _policy())
    policy, _raw = load_observation_check_policy(tmp_path)
    assert policy.source_path == Path(".finishup/checks.toml")


def test_a_moved_policy_keeps_its_byte_bound_trust_identity(tmp_path: Path) -> None:
    legacy = tmp_path / "legacy"
    moved = tmp_path / "moved"
    legacy.mkdir()
    moved.mkdir()
    _write(legacy, LEGACY_CHECK_POLICY_PATH, _policy())
    _write(moved, CHECK_POLICY_PATH, _policy())
    before, _ = load_observation_check_policy(legacy)
    after, _ = load_observation_check_policy(moved)
    assert before.raw_digest == after.raw_digest
    assert before == after


def test_policy_reader_refuses_to_choose_between_both_locations(tmp_path: Path) -> None:
    _write(tmp_path, CHECK_POLICY_PATH, _policy())
    _write(tmp_path, LEGACY_CHECK_POLICY_PATH, _policy())
    with pytest.raises(ObservationCheckPolicyAmbiguous) as caught:
        load_observation_check_policy(tmp_path)
    # Every caller that only needs "no usable policy" keeps failing closed.
    assert caught.value.reason_code == "invalid_approved_check_policy"
    assert not isinstance(caught.value, ObservationCheckPolicyAbsent)


def test_an_empty_legacy_directory_does_not_make_the_policy_ambiguous(tmp_path: Path) -> None:
    _write(tmp_path, CHECK_POLICY_PATH, _policy())
    (tmp_path / ".yoetz").mkdir()
    policy, _raw = load_observation_check_policy(tmp_path)
    assert policy.source_path == CHECK_POLICY_PATH


def test_a_symlinked_legacy_policy_directory_is_invalid(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "checks.toml").write_bytes(_policy())
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".yoetz").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ProtocolValueError) as caught:
        load_observation_check_policy(workspace)
    assert not isinstance(caught.value, ObservationCheckPolicyAbsent)


@pytest.mark.parametrize("location", [CHECK_POLICY_PATH, LEGACY_CHECK_POLICY_PATH])
@pytest.mark.parametrize("other_present", [False, True])
def test_a_policy_fifo_never_blocks_the_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, location: Path, other_present: bool
) -> None:
    (tmp_path / location.parent).mkdir()
    os.mkfifo(tmp_path / location)
    if other_present:
        other = LEGACY_CHECK_POLICY_PATH if location == CHECK_POLICY_PATH else CHECK_POLICY_PATH
        _write(tmp_path, other, _policy())
    real_open = os.open

    def bounded_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if dir_fd is not None:
            facts = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
            if stat.S_ISFIFO(facts.st_mode) and not flags & os.O_NONBLOCK:
                # Fail before the unsafe open rather than leave a hung test process.
                raise AssertionError("policy open would block on a named pipe")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", bounded_open)
    expected = ObservationCheckPolicyAmbiguous if other_present else ProtocolValueError
    with pytest.raises(expected):
        load_observation_check_policy(tmp_path)


@pytest.mark.parametrize(
    "body",
    [b"x = " + b"1" * 4301 + b"\n", b"x = " + b"[" * 5000 + b"]" * 5000 + b"\n"],
    ids=["huge_int", "deep"],
)
def test_policy_tomllib_cannot_load_is_invalid(body: bytes) -> None:
    """``tomllib`` raises ``ValueError``/``RecursionError`` here, not a decode error (#1484)."""

    with pytest.raises(ProtocolValueError) as caught:
        parse_observation_check_policy(body)
    assert caught.value.reason_code == "invalid_approved_check_policy"
