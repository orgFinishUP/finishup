"""Batched blob verification in the check-time change capture (ADR-031).

``_verify_section_objects`` reads the blobs it re-hashes with one ``cat-file --batch-check`` and
one ``cat-file --batch`` instead of one ``cat-file blob`` each. That is a speed-up only: every test
here takes the same capture with the batch disabled (the retained one-read-per-object path) and
requires the identical result, and counts the Git calls the batched path makes.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

import finishup.adapters.git_change_capture as capture_module
from finishup.adapters.git_change_capture import GitChangeCaptureAdapter
from finishup.ports.change_capture import (
    ChangeCaptureUnavailable,
    CheckChangeCapture,
    TaskChangeBase,
)


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
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
    return completed.stdout.decode("utf-8")


def _commit_all(repository: Path, message: str) -> None:
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
        message,
    )


@pytest.fixture(autouse=True)
def isolated_global_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", os.fspath(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)


def _repository(tmp_path: Path) -> Path:
    """Many changed files of different sizes and kinds, one commit after the task base."""

    repository = tmp_path / "repo"
    repository.mkdir(mode=0o700)
    _git(repository, "init", "--quiet")
    for index in range(8):
        (repository / f"module_{index}.py").write_text(
            f"VALUE_{index} = {index}\n" + "# pad\n" * (index * 900), encoding="utf-8"
        )
    (repository / "script.sh").write_text("echo base\n", encoding="utf-8")
    (repository / "doomed.txt").write_text("to be deleted\n", encoding="utf-8")
    (repository / "same one.txt").write_text("shared bytes\n", encoding="utf-8")
    (repository / "same two.txt").write_text("shared bytes\n", encoding="utf-8")
    _commit_all(repository, "baseline")
    return repository


def _change(repository: Path) -> None:
    for index in range(8):
        (repository / f"module_{index}.py").write_text(
            f"VALUE_{index} = {index + 100}\n" + "# pad\n" * (index * 900), encoding="utf-8"
        )
    (repository / "script.sh").chmod(0o755)
    (repository / "script.sh").write_text("echo changed\n", encoding="utf-8")
    (repository / "doomed.txt").unlink()
    (repository / "same one.txt").write_text("shared bytes, changed\n", encoding="utf-8")
    (repository / "same two.txt").write_text("shared bytes, changed\n", encoding="utf-8")
    (repository / "staged new.txt").write_text("new and staged\n", encoding="utf-8")
    _git(repository, "add", "--", "staged new.txt")


def _cat_file_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, ...]]:
    calls: list[tuple[str, ...]] = []
    real = capture_module.run_read_only_git

    def run(handle: Any, arguments: tuple[str, ...], **kwargs: Any) -> tuple[int, bytes]:
        if "cat-file" in arguments:
            calls.append(arguments[arguments.index("cat-file") :])
        return real(handle, arguments, **kwargs)

    monkeypatch.setattr(capture_module, "run_read_only_git", run)
    return calls


def _both(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    base: TaskChangeBase | None,
    **options: Any,
) -> tuple[CheckChangeCapture, CheckChangeCapture]:
    """The capture batched, then the same capture read one object at a time."""

    batched = GitChangeCaptureAdapter().capture(os.fspath(repository), base, **options)
    with monkeypatch.context() as legacy:
        legacy.setattr(capture_module, "_PREFETCH_MIN_OBJECTS", 1_000_000)
        single = GitChangeCaptureAdapter().capture(os.fspath(repository), base, **options)
    return batched, single


def test_batched_verification_equals_one_read_per_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    base = GitChangeCaptureAdapter().read_task_base(os.fspath(repository))
    (repository / "module_0.py").write_text("VALUE_0 = 'committed'\n", encoding="utf-8")
    _commit_all(repository, "agent commit")
    _change(repository)
    calls = _cat_file_calls(monkeypatch)

    for task_base in (base, None):
        calls.clear()
        batched, single = _both(repository, monkeypatch, task_base)

        assert batched == single
        assert "+VALUE_7 = 107" in batched.text.decode("utf-8")
        assert not batched.truncated
        # The batched capture makes two cat-file calls in all; the legacy one makes one per blob.
        batched_calls = [call for call in calls if call[:2] != ("cat-file", "blob")]
        assert [call[1] for call in batched_calls] == ["--batch-check", "--batch"]
        single_reads = [call for call in calls if call[:2] == ("cat-file", "blob")]
        assert len(single_reads) >= 10


def test_batched_verification_keeps_the_budget_outcomes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Too-large objects and a spent total budget withhold the same files either way."""

    repository = _repository(tmp_path)
    _change(repository)
    monkeypatch.setattr(capture_module, "_MAX_VERIFIED_OBJECT_BYTES", 4_000)
    monkeypatch.setattr(capture_module, "_MAX_TOTAL_VERIFIED_OBJECT_BYTES", 12_000)

    for options in ({}, {"priority_paths": ("module_7.py", "module_1.py")}):
        batched, single = _both(repository, monkeypatch, None, **options)

        assert batched == single
        text = batched.text.decode("utf-8")
        assert "not shown" in text


def test_batched_verification_keeps_a_withheld_object_withheld(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A loose object that does not hash to its name is withheld, batched or not."""

    repository = _repository(tmp_path)
    _change(repository)
    oid = _git(repository, "rev-parse", "HEAD:module_3.py").strip()
    other = _git(repository, "rev-parse", "HEAD:module_2.py").strip()
    target = repository / ".git" / "objects" / oid[:2] / oid[2:]
    source = repository / ".git" / "objects" / other[:2] / other[2:]
    target.chmod(0o600)
    target.write_bytes(source.read_bytes())
    target.chmod(0o444)

    batched, single = _both(repository, monkeypatch, None)

    assert batched == single
    assert "VALUE_3" not in batched.text.decode("utf-8")
    assert "+VALUE_4 = 104" in batched.text.decode("utf-8")


@pytest.mark.parametrize("answer", [b"", b"garbage\n", b"0" * 40 + b" missing\n"])
def test_an_unexpected_batch_answer_falls_back_to_one_read_per_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: bytes
) -> None:
    repository = _repository(tmp_path)
    _change(repository)
    _, single = _both(repository, monkeypatch, None)
    reads: list[tuple[str, ...]] = []
    real = capture_module.run_read_only_git

    def run(handle: Any, arguments: tuple[str, ...], **kwargs: Any) -> tuple[int, bytes]:
        if "--batch" in arguments:
            return 0, answer
        if "blob" in arguments:
            reads.append(arguments)
        return real(handle, arguments, **kwargs)

    monkeypatch.setattr(capture_module, "run_read_only_git", run)
    batched = GitChangeCaptureAdapter().capture(os.fspath(repository), None)

    assert batched == single
    assert len(reads) >= 10


def test_a_failed_batch_call_falls_back_to_one_read_per_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    _change(repository)
    _, single = _both(repository, monkeypatch, None)
    real = capture_module.run_read_only_git

    def run(handle: Any, arguments: tuple[str, ...], **kwargs: Any) -> tuple[int, bytes]:
        if "--batch-check" in arguments:
            raise ValueError("git_failed")
        return real(handle, arguments, **kwargs)

    monkeypatch.setattr(capture_module, "run_read_only_git", run)

    assert GitChangeCaptureAdapter().capture(os.fspath(repository), None) == single


def test_one_or_two_blobs_are_still_read_one_at_a_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Below three objects the two batched calls would save nothing, so none is made."""

    repository = _repository(tmp_path)
    (repository / "module_5.py").write_text("VALUE_5 = 'only'\n", encoding="utf-8")
    calls = _cat_file_calls(monkeypatch)

    GitChangeCaptureAdapter().capture(os.fspath(repository), None)

    assert calls and all(call[:2] == ("cat-file", "blob") for call in calls)


def test_a_root_replaced_during_the_batch_is_refused_as_the_single_read_refuses_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The root fence after the first cat-file call fails: both paths end the capture alike."""

    repository = _repository(tmp_path)
    _change(repository)
    real_run = capture_module.run_read_only_git
    real_fence: Any = getattr(capture_module, "_verify_same_root")
    swapped = [False]
    seen: list[str] = []

    def run(handle: Any, arguments: tuple[str, ...], **kwargs: Any) -> tuple[int, bytes]:
        if "cat-file" in arguments:
            seen.append(arguments[arguments.index("cat-file") + 1])
            swapped[0] = True
        return real_run(handle, arguments, **kwargs)

    def fence(pinned: Any) -> None:
        if swapped[0]:
            raise ChangeCaptureUnavailable("unsafe_root")
        real_fence(pinned)

    monkeypatch.setattr(capture_module, "run_read_only_git", run)
    monkeypatch.setattr(capture_module, "_verify_same_root", fence)
    reasons: list[str] = []
    for minimum in (getattr(capture_module, "_PREFETCH_MIN_OBJECTS"), 1_000_000):
        swapped[0] = False
        with monkeypatch.context() as patched:
            patched.setattr(capture_module, "_PREFETCH_MIN_OBJECTS", minimum)
            with pytest.raises(ChangeCaptureUnavailable) as caught:
                GitChangeCaptureAdapter().capture(os.fspath(repository), None)
        reasons.append(caught.value.reason)

    assert reasons == ["unsafe_root", "unsafe_root"]
    # The batched capture is refused at its first batch call, the legacy one at its first read.
    assert seen == ["--batch-check", "blob"]


def test_a_capture_short_of_time_skips_the_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    _change(repository)
    _, single = _both(repository, monkeypatch, None)
    calls = _cat_file_calls(monkeypatch)
    monkeypatch.setattr(capture_module, "_PREFETCH_MIN_SECONDS_LEFT", 1_000_000.0)

    assert GitChangeCaptureAdapter().capture(os.fspath(repository), None) == single
    assert calls and all(call[:2] == ("cat-file", "blob") for call in calls)


def test_the_batch_never_takes_more_than_half_of_the_time_left(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The one-at-a-time loop always keeps time to verify the deliverables first."""

    repository = _repository(tmp_path)
    _change(repository)
    monkeypatch.setattr(capture_module, "_GIT_CALL_SECONDS", 1_000.0)
    timeouts: dict[str, list[float]] = {"batch": [], "single": []}
    real = capture_module.run_read_only_git

    def run(handle: Any, arguments: tuple[str, ...], **kwargs: Any) -> tuple[int, bytes]:
        if "cat-file" in arguments:
            kind = "single" if arguments[-2:-1] == ("blob",) else "batch"
            timeouts[kind].append(kwargs["timeout_seconds"])
        return real(handle, arguments, **kwargs)

    monkeypatch.setattr(capture_module, "run_read_only_git", run)
    GitChangeCaptureAdapter(_deadline_seconds=100.0).capture(os.fspath(repository), None)

    assert len(timeouts["batch"]) == 2
    assert all(0.0 < timeout <= 50.0 for timeout in timeouts["batch"])
