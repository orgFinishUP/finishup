"""Metadata-only reads of requested output paths at check time (issue #977, ADR-033)."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from finishup.adapters import git_change_capture as capture_module
from finishup.adapters.git_change_capture import GitChangeCaptureAdapter
from finishup.application.check_change import requested_output_states
from finishup.domain.events import (
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
)
from finishup.domain.values import obligation_id
from finishup.kernel.projections import ProjectionState
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import (
    REQUESTED_OUTPUT_GIT_IGNORED_GAP,
    REQUESTED_OUTPUT_IGNORED_BY_REPOSITORY_GAP,
    REQUESTED_OUTPUT_OUTSIDE_WORKSPACE_GAP,
    REQUESTED_OUTPUT_UNCHANGED_GAP,
    requested_output_facts,
)
from finishup.ports.change_capture import CheckWorkspaceSource, TaskChangeBase

_OBLIGATION = obligation_id("obl_00000000-0000-4000-8000-000000000001")


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


@pytest.fixture(autouse=True)
def isolated_global_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", os.fspath(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repo"
    repository.mkdir(mode=0o700)
    _git(repository, "init", "--quiet")
    (repository / ".gitignore").write_text("checkpoints/\n", encoding="utf-8")
    (repository / "kept.txt").write_text("kept\n", encoding="utf-8")
    (repository / "gone.txt").write_text("gone\n", encoding="utf-8")
    _git(repository, "add", "--", ".gitignore", "kept.txt", "gone.txt")
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
    return repository


def test_probe_reports_existence_and_ignore_source(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    (repository / "checkpoints").mkdir()
    (repository / "checkpoints" / "model.pt").write_bytes(b"\0")
    (repository / "output").mkdir()
    (repository / "output" / "flag.txt").write_text("flag\n", encoding="utf-8")
    exclude = repository / ".git" / "info" / "exclude"
    exclude.write_text(exclude.read_text(encoding="utf-8") + "/output/\n", encoding="utf-8")
    adapter = GitChangeCaptureAdapter()

    probes = adapter.probe_requested_paths(
        os.fspath(repository),
        (
            "kept.txt",
            os.fspath(repository / "checkpoints" / "model.pt"),
            "output/flag.txt",
            "missing/report.json",
            "/etc/hosts",
            "../escape.txt",
        ),
    )

    kept, checkpoint, flag, missing, outside, escape = probes
    assert (kept.location, kept.exists, kept.ignored) == ("inside", True, False)
    assert checkpoint.relative == "checkpoints/model.pt"
    assert (checkpoint.ignored, checkpoint.ignore_source, checkpoint.ignore_file) == (
        True,
        "repository_file",
        ".gitignore",
    )
    assert (flag.ignored, flag.ignore_source) == (True, "info_exclude")
    assert (missing.exists, missing.ignored) == (False, False)
    assert outside.location == "outside" and outside.relative is None
    assert escape.location == "outside"


def test_probe_never_follows_a_link(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "report.json").write_text("{}", encoding="utf-8")
    (repository / "linked").symlink_to(elsewhere, target_is_directory=True)

    (probe,) = GitChangeCaptureAdapter().probe_requested_paths(
        os.fspath(repository), ("linked/report.json",)
    )
    assert probe.exists is None


def _projection(*values: str, edited: tuple[str, ...] = ()) -> ProjectionState:
    from builders.observed_runs import ObservedLedger
    from finishup.domain.events import ActionKind, ActionRecordedPayload, EventSchema
    from finishup.domain.values import action_id

    ledger = ObservedLedger()
    ledger.append(
        EventSchema("obligation_published", "1.0.0"),
        ObligationPublishedPayload(
            obligation_id=_OBLIGATION,
            description="Deliver the outputs",
            evidence_expectation="The files",
            status=ObligationStatus.OPEN,
            requested_items=tuple(RequestedItem(RequestedItemKind.FILE, value) for value in values),
        ),
        observed=False,
    )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_OBLIGATION,)),
        observed=False,
    )
    if edited:
        ledger.append(
            EventSchema("action_recorded", "1.0.0"),
            ActionRecordedPayload(
                action_id("act_00000000-0000-4000-8000-000000000901"),
                ActionKind.EDIT,
                "Wrote the requested outputs.",
                attempted_items=tuple(sorted(edited)),
            ),
            observed=False,
        )
    return replay(ledger.prefix)


def test_check_time_states_feed_the_requested_output_facts(tmp_path: Path) -> None:
    """shadow-relay: the agent excluded /output/ from Git; atrx: the report was never written."""

    repository = _repository(tmp_path)
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    (repository / "output").mkdir()
    (repository / "output" / "flag.txt").write_text("flag\n", encoding="utf-8")
    exclude = repository / ".git" / "info" / "exclude"
    exclude.write_text(exclude.read_text(encoding="utf-8") + "/output/\n", encoding="utf-8")
    (repository / "checkpoints").mkdir()
    (repository / "checkpoints" / "model.pt").write_bytes(b"\0")
    (repository / "gone.txt").unlink()
    capture = adapter.capture_metadata(os.fspath(repository), base)
    projection = _projection(
        "output/flag.txt",
        "mutation.report.json",
        "checkpoints/model.pt",
        "kept.txt",
        "gone.txt",
        "/elsewhere/out.json",
        edited=("/elsewhere/out.json", "kept.txt"),
    )
    source = CheckWorkspaceSource(os.fspath(repository), "hmac-sha256:" + "0" * 64)

    states = asyncio.run(
        requested_output_states(
            projection=projection,
            capture=capture,
            source=source,
            port=adapter,
            request_id="req_00000000-0000-4000-8000-000000000001",
        )
    )
    absent, markers = requested_output_facts(projection, states, blocked=())

    assert absent == ((_OBLIGATION, 1),)  # mutation.report.json; gone.txt is a tracked deletion
    assert {code for code, _ in markers} == {
        REQUESTED_OUTPUT_GIT_IGNORED_GAP,  # output/ excluded through .git/info/exclude
        REQUESTED_OUTPUT_IGNORED_BY_REPOSITORY_GAP,  # checkpoints/ ignored by the base .gitignore
        REQUESTED_OUTPUT_UNCHANGED_GAP,  # kept.txt, recorded as edited
        REQUESTED_OUTPUT_OUTSIDE_WORKSPACE_GAP,  # /elsewhere/out.json, recorded as edited
    }

    # tb4v1: the same unchanged tracked file and outside path, only read as inputs, are no
    # requested-output facts; the new untracked report is counted as changed.
    (repository / "mutation.report.json").write_text("{}\n", encoding="utf-8")
    capture = adapter.capture_metadata(os.fspath(repository), base)
    inputs = _projection("kept.txt", "/elsewhere/out.json", "mutation.report.json")
    states = asyncio.run(
        requested_output_states(
            projection=inputs,
            capture=capture,
            source=source,
            port=adapter,
            request_id="req_00000000-0000-4000-8000-000000000002",
        )
    )
    assert states[(_OBLIGATION, 2)].changed is True
    assert requested_output_facts(inputs, states, blocked=()) == ((), ())


def test_without_a_capture_every_requested_file_is_unverified() -> None:
    projection = _projection("out.json")
    states = asyncio.run(
        requested_output_states(
            projection=projection,
            capture=None,
            source=None,
            port=None,
            request_id="req_00000000-0000-4000-8000-000000000001",
        )
    )
    assert {state.location for state in states.values()} == {"unverified"}


def test_a_requested_directory_is_changed_by_new_files_under_it(tmp_path: Path) -> None:
    """tb4n1 E1/E7: retro-console-soc (/app/src), risk-scorer (/app/parityctl), nextjs (/app).

    The agents named their output directory, and the workspace root itself, in edit actions and
    wrote new files under it. The capture lists files only, so an exact path match reported each
    directory unchanged and the root outside the workspace.
    """

    repository = _repository(tmp_path)
    for relative in ("parityctl/cli.py", "untouched/a.txt", "sr/keep.txt"):
        (repository / relative).parent.mkdir(exist_ok=True)
        (repository / relative).write_text("old\n", encoding="utf-8")
    _git(repository, "add", "--", "parityctl/cli.py", "untouched/a.txt", "sr/keep.txt")
    _git(
        repository,
        "-c",
        "user.name=FinishUP Test",
        "-c",
        "user.email=finishup@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "inputs",
    )
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    root = os.fspath(repository)
    values = (
        root + "/src",  # new untracked files only
        root + "/parityctl/",  # a tracked file modified; trailing slash
        root,  # the workspace root
        root + "/untouched",  # nothing under it changed
        root + "/sr",  # a sibling prefix of src/ is not src/
    )
    projection = _projection(*values, edited=values)
    source = CheckWorkspaceSource(root, "hmac-sha256:" + "0" * 64)

    before = asyncio.run(
        requested_output_states(
            projection=projection,
            capture=adapter.capture_metadata(root, base),
            source=source,
            port=adapter,
            request_id="req_00000000-0000-4000-8000-000000000003",
        )
    )
    assert before[(_OBLIGATION, 2)].location == "inside"
    assert before[(_OBLIGATION, 2)].changed is False

    (repository / "src").mkdir()
    for name in ("apu2a03.sv", "console_system.sv", "cpu6502.sv", "ppu2c02.sv"):
        (repository / "src" / name).write_text("module m; endmodule\n", encoding="utf-8")
    (repository / "parityctl" / "cli.py").write_text("new\n", encoding="utf-8")
    capture = adapter.capture_metadata(root, base)
    states = asyncio.run(
        requested_output_states(
            projection=projection,
            capture=capture,
            source=source,
            port=adapter,
            request_id="req_00000000-0000-4000-8000-000000000004",
        )
    )

    assert [states[(_OBLIGATION, index)].changed for index in range(5)] == [
        True,
        True,
        True,
        False,
        False,
    ]
    _, markers = requested_output_facts(projection, states, blocked=())
    # Only the genuinely untouched directories stay unchanged; nothing is "outside".
    assert {code for code, _ in markers} == {REQUESTED_OUTPUT_UNCHANGED_GAP}


def test_the_workspace_root_probe_is_inside_and_existing(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    (probe,) = GitChangeCaptureAdapter().probe_requested_paths(
        os.fspath(repository), (os.fspath(repository),)
    )
    assert (probe.location, probe.relative, probe.exists, probe.ignored) == (
        "inside",
        ".",
        True,
        False,
    )


def test_probe_reports_whether_a_directory_holds_a_file(tmp_path: Path) -> None:
    """#1002: an existing directory with no file beneath it delivers nothing."""

    repository = _repository(tmp_path)
    (repository / "empty").mkdir()
    (repository / "hollow" / "a" / "b").mkdir(parents=True)
    (repository / "deep" / "a" / "b").mkdir(parents=True)
    (repository / "deep" / "a" / "b" / "out.sv").write_text("module m; endmodule\n")
    (repository / "linked_only").mkdir()
    (repository / "linked_only" / "link").symlink_to(tmp_path)

    probes = GitChangeCaptureAdapter().probe_requested_paths(
        os.fspath(repository),
        ("empty", "hollow", "deep", "linked_only", "kept.txt", "missing", "."),
    )

    assert [probe.holds_file for probe in probes] == [False, False, True, True, None, None, True]
    assert all(probe.exists is True for probe in probes[:5])


def _items_projection(*items: RequestedItem, edited: tuple[str, ...] = ()) -> ProjectionState:
    from builders.observed_runs import ObservedLedger
    from finishup.domain.events import ActionKind, ActionRecordedPayload, EventSchema
    from finishup.domain.values import action_id

    ledger = ObservedLedger()
    ledger.append(
        EventSchema("obligation_published", "1.1.0"),
        ObligationPublishedPayload(
            obligation_id=_OBLIGATION,
            description="Deliver the outputs",
            evidence_expectation="The files",
            status=ObligationStatus.OPEN,
            requested_items=items,
        ),
        observed=False,
    )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_OBLIGATION,)),
        observed=False,
    )
    if edited:
        ledger.append(
            EventSchema("action_recorded", "1.0.0"),
            ActionRecordedPayload(
                action_id("act_00000000-0000-4000-8000-000000000902"),
                ActionKind.EDIT,
                "Wrote the requested outputs.",
                attempted_items=tuple(sorted(edited)),
            ),
            observed=False,
        )
    return replay(ledger.prefix)


def test_roles_and_directories_at_check_time(tmp_path: Path) -> None:
    """tb4n1 layout-config and retro-console-soc, with the roles declared (#1002).

    The read-only /app/layout_spec.json input is never a requested-output fact, even when an edit
    action names it; /app/src as an output directory is absent while missing or holding only
    empty directories, and changed once files land under it. A declared output file the change
    leaves untouched is reported without any edit action naming it.
    """

    from finishup.domain.events import RequestedItemRole

    repository = _repository(tmp_path)
    (repository / "layout_spec.json").write_text("{}\n", encoding="utf-8")
    _git(repository, "add", "--", "layout_spec.json")
    _git(
        repository,
        "-c",
        "user.name=FinishUP Test",
        "-c",
        "user.email=finishup@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "spec",
    )
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    root = os.fspath(repository)
    items = (
        RequestedItem(RequestedItemKind.FILE, root + "/layout_spec.json", RequestedItemRole.INPUT),
        RequestedItem(RequestedItemKind.DIRECTORY, root + "/src", RequestedItemRole.OUTPUT),
        RequestedItem(RequestedItemKind.FILE, "kept.txt", RequestedItemRole.OUTPUT),
        RequestedItem(RequestedItemKind.FILE, root + "/missing_input.csv", RequestedItemRole.INPUT),
        # No role: a directory named as a plain file item keeps the 1.0.0 reading.
        RequestedItem(RequestedItemKind.FILE, root + "/hollow"),
    )
    projection = _items_projection(*items, edited=(items[0].value,))
    source = CheckWorkspaceSource(root, "hmac-sha256:" + "0" * 64)

    def facts() -> tuple[object, ...]:
        states = asyncio.run(
            requested_output_states(
                projection=projection,
                capture=adapter.capture_metadata(root, base),
                source=source,
                port=adapter,
                request_id="req_00000000-0000-4000-8000-000000000005",
            )
        )
        # Inputs are not read at all.
        assert (_OBLIGATION, 0) not in states and (_OBLIGATION, 3) not in states
        return requested_output_facts(projection, states, blocked=())

    (repository / "hollow" / "sub").mkdir(parents=True)
    unchanged = ((REQUESTED_OUTPUT_UNCHANGED_GAP, _OBLIGATION),)
    assert facts() == (((_OBLIGATION, 1),), unchanged)  # src missing; kept.txt untouched

    (repository / "src" / "rtl").mkdir(parents=True)
    assert facts() == (((_OBLIGATION, 1),), unchanged)  # only empty directories

    for name in ("apu2a03.sv", "cpu6502.sv"):
        (repository / "src" / "rtl" / name).write_text("module m; endmodule\n", encoding="utf-8")
    (repository / "kept.txt").write_text("rewritten\n", encoding="utf-8")
    assert facts() == ((), ())


def test_a_line_break_file_name_keeps_requested_output_facts_live(tmp_path: Path) -> None:
    """#1019 (tb4n2 rs-archive D): one probe file named ``a\\nq`` no longer darkens the facts.

    Before the fix the whole metadata read failed, so every requested output was unverified for
    the rest of the task. Now the odd name is skipped and counted, and the outputs stay live.
    """

    repository = _repository(tmp_path)
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    probes = repository / "probes"
    probes.mkdir()
    (probes / "a\nq").write_bytes(b"probe\n")
    (repository / "report.json").write_text("{}\n", encoding="utf-8")
    capture = adapter.capture_metadata(os.fspath(repository), base)
    assert capture.unrepresentable_files == 1
    assert capture.truncated is True
    projection = _projection("report.json", "missing.json", edited=("report.json",))
    states = asyncio.run(
        requested_output_states(
            projection=projection,
            capture=capture,
            source=CheckWorkspaceSource(os.fspath(repository), "hmac-sha256:" + "0" * 64),
            port=adapter,
            request_id="req_00000000-0000-4000-8000-000000001019",
        )
    )
    assert states[(_OBLIGATION, 0)].changed is True
    assert states[(_OBLIGATION, 1)].exists is False
    absent, _markers = requested_output_facts(projection, states, blocked=())
    assert absent == ((_OBLIGATION, 1),)


def _created(adapter: GitChangeCaptureAdapter, repository: Path, base: TaskChangeBase) -> set[str]:
    capture = adapter.capture_metadata(os.fspath(repository), base)
    return {
        entry.path for entry in capture.entries if entry.untracked or entry.status.startswith("A")
    }


@pytest.mark.parametrize("directory", ["plain", "résultats", "run:1", 'say "hi"'])
def test_ignore_file_names_the_rule_file_as_the_capture_does(
    tmp_path: Path, directory: str
) -> None:
    repository = _repository(tmp_path)
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    folder = repository / directory
    folder.mkdir()
    (folder / ".gitignore").write_text("out.csv\n", encoding="utf-8")
    (folder / "out.csv").write_text("a,b\n", encoding="utf-8")

    (probe,) = adapter.probe_requested_paths(os.fspath(repository), (f"{directory}/out.csv",))

    assert (probe.ignored, probe.ignore_source, probe.ignore_file) == (
        True,
        "repository_file",
        f"{directory}/.gitignore",
    )
    assert probe.ignore_file in _created(adapter, repository, base)


@pytest.mark.parametrize("directory", ["résultats", "run:1"])
def test_a_task_created_rule_file_in_any_directory_is_the_tasks_ignore(
    tmp_path: Path, directory: str
) -> None:
    repository = _repository(tmp_path)
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    folder = repository / directory
    folder.mkdir()
    (folder / ".gitignore").write_text("out.csv\n", encoding="utf-8")
    (folder / "out.csv").write_text("a,b\n", encoding="utf-8")
    capture = adapter.capture_metadata(os.fspath(repository), base)
    projection = _projection(f"{directory}/out.csv")

    states = asyncio.run(
        requested_output_states(
            projection=projection,
            capture=capture,
            source=CheckWorkspaceSource(os.fspath(repository), "hmac-sha256:" + "0" * 64),
            port=adapter,
            request_id="req_00000000-0000-4000-8000-000000000003",
        )
    )
    _, markers = requested_output_facts(projection, states, blocked=())

    assert {code for code, _ in markers} == {REQUESTED_OUTPUT_GIT_IGNORED_GAP}


@pytest.mark.parametrize("name", ["re:po", "dépôt"])
def test_info_exclude_is_recognized_under_any_root_name(tmp_path: Path, name: str) -> None:
    repository = _repository(tmp_path).rename(tmp_path / name)
    (repository / "output").mkdir()
    (repository / "output" / "flag.txt").write_text("flag\n", encoding="utf-8")
    exclude = repository / ".git" / "info" / "exclude"
    exclude.write_text(exclude.read_text(encoding="utf-8") + "/output/\n", encoding="utf-8")

    (probe,) = GitChangeCaptureAdapter().probe_requested_paths(
        os.fspath(repository), ("output/flag.txt",)
    )

    assert (probe.ignored, probe.ignore_source, probe.ignore_file) == (True, "info_exclude", None)


# The same folder name spelled two ways: decomposed (``e`` + U+0301, as a macOS file system or
# input method may hand it over) and composed (U+00E9, as a ``.gitignore`` usually holds it).
_DECOMPOSED = "cafe\u0301"
_COMPOSED = "caf\u00e9"


def _set_precompose_unicode(repository: Path, setting: str | None) -> None:
    # ``git init`` writes ``true`` on macOS and nothing elsewhere; set it the same way everywhere.
    _git(repository, "config", "core.precomposeUnicode", setting or "true")
    if setting is None:
        _git(repository, "config", "--unset", "core.precomposeUnicode")


@pytest.mark.parametrize(
    ("macos", "setting", "sent"),
    [
        (True, "true", _COMPOSED),
        (True, "false", _DECOMPOSED),
        (True, None, _DECOMPOSED),
        (False, "true", _DECOMPOSED),
    ],
)
def test_the_rule_source_query_sends_the_path_git_composes_from_its_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, macos: bool, setting: str | None, sent: str
) -> None:
    """macOS regression: Git there composes an argument path but reads ``--stdin`` as sent.

    With ``core.precomposeUnicode`` (which ``git init`` sets on macOS) the quiet query is answered
    for the composed spelling of a decomposed path, so the ``-v -z --stdin`` query that names the
    rule must be sent that spelling too, or it matches nothing and the rule reads as outside the
    repository. Git elsewhere never composes, so there the path is sent unchanged and the setting
    is not even read.
    """

    repository = _repository(tmp_path)
    _set_precompose_unicode(repository, setting)
    (repository / ".gitignore").write_text("checkpoints/\ncaf*/\n", encoding="utf-8")
    folder = repository / _DECOMPOSED
    folder.mkdir()
    (folder / "x").write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(capture_module, "_git_precomposes_arguments", lambda: macos)
    calls: list[tuple[tuple[str, ...], bytes | None]] = []
    real = capture_module.run_read_only_git

    def run(*args: Any, **kwargs: Any) -> tuple[int, bytes]:
        calls.append((tuple(args[1]), kwargs.get("stdin_bytes")))
        return real(*args, **kwargs)

    monkeypatch.setattr(capture_module, "run_read_only_git", run)

    (probe,) = GitChangeCaptureAdapter().probe_requested_paths(
        os.fspath(repository), (f"{_DECOMPOSED}/x",)
    )

    assert (probe.ignored, probe.ignore_source, probe.ignore_file) == (
        True,
        "repository_file",
        ".gitignore",
    )
    assert [stdin for arguments, stdin in calls if "--stdin" in arguments] == [
        f"{sent}/x".encode() + b"\0"
    ]
    assert any("core.precomposeUnicode" in arguments for arguments, _ in calls) is macos


# The spelling the rule query is sent on macOS when Git composes argument paths there.
_precomposed: Callable[[bytes], bytes] = getattr(capture_module, "_precomposed")

# Git for macOS composes an argument path with iconv's ``UTF-8-MAC`` decoder, which joins only a
# canonical pair (Unicode 3.2, Basic Multilingual Plane) and the Hangul syllables. NFC does more:
# it maps singletons and decomposes composition exclusions. Git keeps each of these as written.
_KEPT_AS_WRITTEN = {
    "kelvin sign, NFC K": "\u212a",
    "greek question mark, NFC semicolon": "\u037e",
    "ohm sign, NFC omega": "\u2126",
    "angstrom sign, NFC A with ring": "\u212b",
    "CJK compatibility ideograph, NFC U+8C48": "\uf900",
    "composition exclusion, NFC decomposes it": "\u0958",
    "Hebrew presentation form, NFC decomposes it": "\ufb1d",
    "singleton combining mark, NFC U+0300": "\u0340",
    "non-starter decomposition, NFC U+0308 U+0301": "\u0344",
    "singleton mark after a base, NFC U+00E0": "a\u0340",
    "excluded pair stays decomposed": "\u0915\u093c",
    "singleton before a mark, NFC U+01FA": "\u212b\u0301",
    "pair added after Unicode 3.2, NFC U+1B06": "\u1b05\u1b35",
}

# Decomposed spellings Git for macOS composes, left to right, each character joined to the one
# before it only: marks out of canonical order, or blocked, stay as they are.
_COMPOSED_BY_GIT = {
    "latin e and acute": ("cafe\u0301", "caf\u00e9"),
    "two marks in canonical order": ("a\u0323\u0302", "\u1ead"),
    "two marks in the other order, NFC U+1EAD": ("a\u0302\u0323", "\u00e2\u0323"),
    "a second acute is blocked": ("e\u0301\u0301", "\u00e9\u0301"),
    "hangul syllables with and without a final": (
        "\u1112\u1161\u11ab\u1100\u1173\u11af\u1100\u1161",
        "\ud55c\uae00\uac00",
    ),
    "kana and voiced sound mark": ("\u304b\u3099", "\u304c"),
    "devanagari pair outside the exclusions": ("\u0928\u093c", "\u0929"),
    "a kept character beside a composed one": ("\u212acafe\u0301", "\u212acaf\u00e9"),
}


@pytest.mark.parametrize("written", _KEPT_AS_WRITTEN.values(), ids=_KEPT_AS_WRITTEN)
def test_precomposition_keeps_what_git_for_macos_keeps(written: str) -> None:
    assert _precomposed(f"{written}/x".encode()) == f"{written}/x".encode()


@pytest.mark.parametrize(("written", "composed"), _COMPOSED_BY_GIT.values(), ids=_COMPOSED_BY_GIT)
def test_precomposition_composes_what_git_for_macos_composes(written: str, composed: str) -> None:
    assert _precomposed(f"{written}/x".encode()) == f"{composed}/x".encode()


@pytest.mark.parametrize(
    "raw",
    [
        b"plain/ascii.txt",
        "cafe\u0301/\U0001f600".encode(),
        "cafe\u0301/\uffff".encode(),
        "cafe\u0301/\ufffe".encode(),
        "cafe\u0301/".encode() + b"\xff",
    ],
    ids=["ascii", "beyond the basic plane", "U+FFFF", "U+FFFE", "not UTF-8"],
)
def test_a_path_git_for_macos_cannot_convert_is_sent_as_written(raw: bytes) -> None:
    """Apple's ``UTF-8-MAC`` decoder refuses these, and Git then keeps the whole path as is."""

    assert _precomposed(raw) == raw


def _canonical_pairs(database: Any) -> dict[str, str]:
    """Every Basic Multilingual Plane primary composite of ``database`` but the Hangul syllables
    (composed by arithmetic, not a table), keyed by its canonical pair."""

    pairs: dict[str, str] = {}
    for code in range(0x10000):
        if 0xD800 <= code < 0xE000 or 0xAC00 <= code <= 0xD7A3:
            continue
        fields = database.decomposition(chr(code)).split()
        if len(fields) != 2 or fields[0].startswith("<"):
            continue
        pair = "".join(chr(int(field, 16)) for field in fields)
        if database.normalize("NFC", pair) == chr(code):
            pairs[pair] = chr(code)
    return pairs


def test_precomposition_joins_exactly_the_pairs_of_apples_table() -> None:
    """Apple's ``UTF-8-MAC`` composition table holds 917 pairs: Unicode 3.2's, in the BMP.

    A pair Unicode defined later in the plane (Balinese, 5.0) is missing from that table, so Git
    for macOS leaves it decomposed though NFC composes it.
    """

    unicode_3_2 = _canonical_pairs(unicodedata.ucd_3_2_0)
    later = {
        pair: composite
        for pair, composite in _canonical_pairs(unicodedata).items()
        if pair not in unicode_3_2
    }

    assert len(unicode_3_2) == 917
    assert "\u1b05\u1b35" in later
    assert all(
        _precomposed(pair.encode()) == composite.encode() for pair, composite in unicode_3_2.items()
    )
    assert all(_precomposed(pair.encode()) == pair.encode() for pair in later)


def test_precomposition_joins_every_hangul_syllable_as_unicode_defines_it() -> None:
    leading = [chr(code) for code in range(0x1100, 0x1113)]
    vowels = [chr(code) for code in range(0x1161, 0x1176)]
    trailing = [chr(code) for code in range(0x11A8, 0x11C3)]
    sequences = [first + vowel for first in leading for vowel in vowels]
    sequences += [
        unicodedata.normalize("NFC", pair) + last for pair in sequences for last in trailing
    ]

    assert all(
        _precomposed(sequence.encode()) == unicodedata.normalize("NFC", sequence).encode()
        for sequence in sequences
    )
    assert len({unicodedata.normalize("NFC", sequence) for sequence in sequences}) == 11_172


def _record_git_calls(
    monkeypatch: pytest.MonkeyPatch, *, failing: str | None = None
) -> list[tuple[tuple[str, ...], bytes | None]]:
    calls: list[tuple[tuple[str, ...], bytes | None]] = []
    real = capture_module.run_read_only_git

    def run(*args: Any, **kwargs: Any) -> tuple[int, bytes]:
        arguments = tuple(args[1])
        calls.append((arguments, kwargs.get("stdin_bytes")))
        if failing is not None and failing in arguments:
            raise ValueError("git_failed")
        return real(*args, **kwargs)

    monkeypatch.setattr(capture_module, "run_read_only_git", run)
    return calls


def test_the_rule_source_query_keeps_a_character_nfc_would_rewrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reviewer regression: NFC sends U+212A KELVIN SIGN as ``K`` and misses its rule.

    Git for macOS composes only the decomposed ``e`` + U+0301 of this path, so the rule query is
    sent exactly that spelling (the sign as written) and names the ``.gitignore`` rule spelled
    with the sign, as the argument query that proved the path ignored matched it.
    """

    repository = _repository(tmp_path)
    _set_precompose_unicode(repository, "true")
    (repository / ".gitignore").write_text("checkpoints/\n\u212a*/\n", encoding="utf-8")
    folder = repository / f"\u212a{_DECOMPOSED}"
    folder.mkdir()
    (folder / "x").write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(capture_module, "_git_precomposes_arguments", lambda: True)
    calls = _record_git_calls(monkeypatch)

    (probe,) = GitChangeCaptureAdapter().probe_requested_paths(
        os.fspath(repository), (f"\u212a{_DECOMPOSED}/x",)
    )

    assert (probe.ignored, probe.ignore_source, probe.ignore_file) == (
        True,
        "repository_file",
        ".gitignore",
    )
    assert [stdin for arguments, stdin in calls if "--stdin" in arguments] == [
        f"\u212a{_COMPOSED}/x".encode() + b"\0"
    ]


@pytest.mark.parametrize("written", _KEPT_AS_WRITTEN.values(), ids=_KEPT_AS_WRITTEN)
def test_a_path_git_composes_no_further_is_sent_as_written_without_a_config_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, written: str
) -> None:
    """Nothing in these paths composes, so the setting is not read and the rule still matches."""

    repository = _repository(tmp_path)
    _set_precompose_unicode(repository, "true")
    (repository / ".gitignore").write_text(f"checkpoints/\n{written}/\n", encoding="utf-8")
    folder = repository / written
    folder.mkdir()
    (folder / "x").write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(capture_module, "_git_precomposes_arguments", lambda: True)
    calls = _record_git_calls(monkeypatch)

    (probe,) = GitChangeCaptureAdapter().probe_requested_paths(
        os.fspath(repository), (f"{written}/x",)
    )

    assert (probe.ignored, probe.ignore_source, probe.ignore_file) == (
        True,
        "repository_file",
        ".gitignore",
    )
    assert [stdin for arguments, stdin in calls if "--stdin" in arguments] == [
        f"{written}/x".encode() + b"\0"
    ]
    assert not any("core.precomposeUnicode" in arguments for arguments, _ in calls)


def test_a_failed_precompose_setting_read_is_made_once_and_counts_as_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A setting that cannot be read is not retried per path; each path then goes as written."""

    repository = _repository(tmp_path)
    _set_precompose_unicode(repository, "true")
    (repository / ".gitignore").write_text("checkpoints/\ncaf*/\n", encoding="utf-8")
    written = (_DECOMPOSED, "cafe\u0300")
    for name in written:
        folder = repository / name
        folder.mkdir()
        (folder / "x").write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(capture_module, "_git_precomposes_arguments", lambda: True)
    calls = _record_git_calls(monkeypatch, failing="core.precomposeUnicode")

    probes = GitChangeCaptureAdapter().probe_requested_paths(
        os.fspath(repository), tuple(f"{name}/x" for name in written)
    )

    assert [(probe.ignored, probe.ignore_source, probe.ignore_file) for probe in probes] == [
        (True, "repository_file", ".gitignore"),
        (True, "repository_file", ".gitignore"),
    ]
    assert sum("core.precomposeUnicode" in arguments for arguments, _ in calls) == 1
    assert sorted(stdin or b"" for arguments, stdin in calls if "--stdin" in arguments) == sorted(
        f"{name}/x".encode() + b"\0" for name in written
    )


@pytest.mark.skipif(sys.platform != "darwin", reason="only Git for macOS composes argument paths")
@pytest.mark.parametrize("kept", ["\uf900", "\u212b"], ids=["U+F900", "U+212B"])
def test_macos_names_the_rule_file_for_a_character_nfc_would_rewrite(
    tmp_path: Path, kept: str
) -> None:
    """Real macOS Git: a character its precomposition keeps is sent as written, beside a composed
    ``e`` + U+0301, so the ``.gitignore`` rule spelled the same way is named.

    NFC would have sent U+F900 as U+8C48 (U+212B as U+00C5), a spelling no rule matches, and the
    path would have read as ignored by a rule outside the repository.
    """

    repository = _repository(tmp_path)
    _set_precompose_unicode(repository, "true")
    (repository / ".gitignore").write_text(
        f"checkpoints/\n{kept}{_COMPOSED}/\n{kept}/\n", encoding="utf-8"
    )
    for name in (f"{kept}{_DECOMPOSED}", kept):
        folder = repository / name
        folder.mkdir()
        (folder / "x").write_text("x\n", encoding="utf-8")

    probes = GitChangeCaptureAdapter().probe_requested_paths(
        os.fspath(repository), (f"{kept}{_DECOMPOSED}/x", f"{kept}{_COMPOSED}/x", f"{kept}/x")
    )

    assert [(probe.ignored, probe.ignore_source, probe.ignore_file) for probe in probes] == [
        (True, "repository_file", ".gitignore"),
        (True, "repository_file", ".gitignore"),
        (True, "repository_file", ".gitignore"),
    ]


@pytest.mark.skipif(sys.platform != "darwin", reason="only Git for macOS composes argument paths")
def test_macos_names_the_rule_file_for_a_decomposed_path(tmp_path: Path) -> None:
    """Real macOS Git: a decomposed spelling of a folder a composed rule ignores names that rule.

    Before the fix the decomposed spelling was reported ignored by a rule outside the repository
    (``outside_repository``), while the composed one named ``.gitignore``.
    """

    repository = _repository(tmp_path)
    _set_precompose_unicode(repository, "true")
    (repository / ".gitignore").write_text(f"checkpoints/\n{_COMPOSED}/\n", encoding="utf-8")
    folder = repository / _DECOMPOSED
    folder.mkdir()
    (folder / "x").write_text("x\n", encoding="utf-8")

    probes = GitChangeCaptureAdapter().probe_requested_paths(
        os.fspath(repository), (f"{_DECOMPOSED}/x", f"{_COMPOSED}/x")
    )

    assert [(probe.ignored, probe.ignore_source, probe.ignore_file) for probe in probes] == [
        (True, "repository_file", ".gitignore"),
        (True, "repository_file", ".gitignore"),
    ]


@pytest.mark.skipif(
    sys.platform == "darwin",
    reason="Git for macOS composes the argument query, so a decomposed rule never matches it",
)
def test_a_composed_spelling_that_names_no_rule_is_asked_once_more_as_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Git whose composition differs from the modelled decoder still gets its rule named.

    Here the rule is spelled decomposed, so only the path as written matches it. On Linux the
    quiet argument query (never composed) proves the path ignored; with composition modelled on,
    the composed rule query names nothing, and the path is asked once more as written instead of
    reading as outside the repository. Composition that matches costs no second query.
    """

    repository = _repository(tmp_path)
    _set_precompose_unicode(repository, "true")
    (repository / ".gitignore").write_text(f"checkpoints/\n{_DECOMPOSED}/\n", encoding="utf-8")
    folder = repository / _DECOMPOSED
    folder.mkdir()
    (folder / "x").write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(capture_module, "_git_precomposes_arguments", lambda: True)
    calls = _record_git_calls(monkeypatch)

    (probe,) = GitChangeCaptureAdapter().probe_requested_paths(
        os.fspath(repository), (f"{_DECOMPOSED}/x",)
    )

    assert (probe.ignored, probe.ignore_source, probe.ignore_file) == (
        True,
        "repository_file",
        ".gitignore",
    )
    assert [stdin for arguments, stdin in calls if "--stdin" in arguments] == [
        f"{_COMPOSED}/x".encode() + b"\0",
        f"{_DECOMPOSED}/x".encode() + b"\0",
    ]
