"""Consent at level L2 and ``finishup server code`` (ADR-054; design v2 §2.3, §4.3, §4.4, U11)."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Iterator
from pathlib import Path
from types import TracebackType
from typing import Self

import pytest
from tests.builders.server_copy import git, release_l2
from tests.builders.server_profiles import fetched, profile_document
from tests.builders.server_targets import ambient_home
from typer.testing import CliRunner

from finishup.cli import server as server_cli
from finishup.cli import server_code, trusted_console
from finishup.cli import zero_network_selection as zero_network
from finishup.cli.app import app
from finishup.cli.server import LevelChoice, ServerCommandRefused
from finishup.client import targets
from finishup.client.code_copy_settings import read_settings
from finishup.protocol.consent_envelope import Retention
from finishup.protocol.server_profile import ProfileLevels

_RUNNER = CliRunner()
_L2_DOCUMENT = profile_document(levels=ProfileLevels(("L1", "L2"), "L1"))


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        monkeypatch.setattr(zero_network, "_selection_on_disk", zero_network.read_selection_on_disk)
        yield root


@pytest.fixture
def remote(home: Path) -> targets.ServerTarget:
    del home
    with targets.registry_lock():
        record, _root = targets.new_remote_target("lab", "https", base_url="https://lab.example")
        targets.write_selection(record)
    return record


@pytest.fixture
def repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    (root / "a.py").write_bytes(b"a\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "m")
    monkeypatch.chdir(root)
    return root


class _Console:
    """A trusted console that answers from a script and records what it showed."""

    def __init__(self, *answers: bytes) -> None:
        self.answers = list(answers)
        self.shown: list[str] = []
        self.opened = 0

    def __call__(self) -> Self:
        self.opened += 1
        return self

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        _kind: type[BaseException] | None,
        _value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        return None

    def write(self, text: str) -> None:
        self.shown.append(text)

    def read_choice(self, _prompt: str, allowed: tuple[bytes, ...]) -> bytes:
        if not self.answers:
            raise trusted_console.TrustedConsoleError("eof")
        answer = self.answers.pop(0)
        if answer in allowed:
            return answer
        raise trusted_console.TrustedConsoleError("input_invalid")

    @property
    def text(self) -> str:
        return "".join(self.shown)


class _NoConsole:
    """No trusted console here (a pipe, a script); counts every attempt to open one."""

    def __init__(self) -> None:
        self.opened = 0

    def __call__(self) -> Self:
        self.opened += 1
        raise trusted_console.TrustedConsoleError("trusted_console_required")


def _console(monkeypatch: pytest.MonkeyPatch, console: _Console | _NoConsole) -> None:
    monkeypatch.setattr(trusted_console, "TrustedForegroundConsole", console)


def _offer(record: targets.ServerTarget, choice: LevelChoice, document: object = _L2_DOCUMENT):
    return server_cli._consent_offer(record, fetched(record, document), choice)  # type: ignore[arg-type]  # pyright: ignore[reportPrivateUsage]


# --- consent at L2 --------------------------------------------------------------------------------


def test_l1_stays_the_default_and_its_disclosure_is_unchanged(remote: targets.ServerTarget) -> None:
    envelope, lines = _offer(remote, LevelChoice())
    assert envelope.level == "L1" and envelope.retention is None
    assert lines[0].startswith(
        "Level of use: that server keeps your tasks, its ledger and reviews;"
    )
    assert not any("copy" in line for line in lines)
    with pytest.raises(ServerCommandRefused) as raised:
        _offer(remote, LevelChoice(retention="days:7"))
    assert raised.value.reason == "usage"


def test_l2_is_refused_when_the_server_does_not_offer_it(remote: targets.ServerTarget) -> None:
    with release_l2(), pytest.raises(ServerCommandRefused) as raised:
        _offer(remote, LevelChoice(level="L2"), profile_document())
    assert raised.value.reason == "server_level_unavailable"


def test_l2_consents_to_an_offered_retention_and_discloses_the_copy(
    remote: targets.ServerTarget,
) -> None:
    with release_l2():
        envelope, lines = _offer(remote, LevelChoice(level="L2"))
        assert envelope.level == "L2" and envelope.retention == Retention("days", 7)
        assert envelope.code_sync is not None and envelope.exclusions
        again, _ = _offer(remote, LevelChoice(level="L2", retention="days:7"))
        assert again == envelope
        with pytest.raises(ServerCommandRefused) as raised:
            _offer(remote, LevelChoice(level="L2", retention="until_forgotten"))
        assert raised.value.reason == "usage"
        with pytest.raises(ServerCommandRefused):
            _offer(remote, LevelChoice(level="L2", retention="days:07"))
    text = "\n".join(lines)
    assert "a copy of each" in text and "never its history" in text
    assert "names of the files left" in text and "not a guarantee" in text
    assert "for 7 days after its last sync" in text
    assert "'finishup server code forget' deletes a copy there" in text
    assert "only forget does" in text
    assert "Checks you approved still run on this computer." in text


@pytest.mark.parametrize("written", ["days:0", "days:36501", "days:+7", "weekly"])
def test_a_retention_no_envelope_admits_is_a_usage_error_naming_the_tokens(
    remote: targets.ServerTarget, written: str
) -> None:
    """``--retention`` is read by the one shared parser ``[server.code_copy]`` uses too."""

    with release_l2(), pytest.raises(ServerCommandRefused) as raised:
        _offer(remote, LevelChoice(level="L2", retention=written))
    assert raised.value.reason == "usage"
    assert "--retention is task_close, until_forgotten or days:N" in str(raised.value.message)


def test_server_use_keeps_the_level_and_retention_already_agreed(
    remote: targets.ServerTarget,
) -> None:
    from tests.builders.server_profiles import consent_to

    stored = consent_to(remote, _L2_DOCUMENT, level="L2", retention=Retention("days", 7))
    with release_l2():
        envelope, _lines = server_cli._consent_offer(  # pyright: ignore[reportPrivateUsage]
            stored, fetched(stored, _L2_DOCUMENT), None, stored=stored
        )
    assert (envelope.level, envelope.retention) == ("L2", Retention("days", 7))
    # A server that no longer offers L2: 'use' never narrows on its own; the owner chooses L1.
    with pytest.raises(ServerCommandRefused) as raised:
        server_cli._consent_offer(  # pyright: ignore[reportPrivateUsage]
            stored, fetched(stored, profile_document()), None, stored=stored
        )
    assert raised.value.reason == "server_level_unavailable"
    envelope, _lines = server_cli._consent_offer(  # pyright: ignore[reportPrivateUsage]
        stored, fetched(stored, profile_document()), LevelChoice(level="L1"), stored=stored
    )
    assert envelope.level == "L1"


def _plain(text: str) -> str:
    """Help text without terminal styling: CI forces colour, so options carry escapes."""

    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)


def test_the_level_options_are_shown_and_refused_for_a_server_on_this_computer(home: Path) -> None:
    del home
    shown = _plain(_RUNNER.invoke(app, ["server", "add", "--help"]).output)
    assert "--level" in shown and "--retention" in shown
    assert "code" in _plain(_RUNNER.invoke(app, ["server", "--help"]).output).split("Commands")[-1]
    refused = _RUNNER.invoke(app, ["server", "add", "here", "--local", "--level", "L2"])
    assert refused.exit_code != 0
    assert "--level and --retention apply to a server elsewhere" in refused.output


# --- finishup server code: this computer's own choices ----------------------------------------------


def _settings(record: targets.ServerTarget) -> dict[str, object]:
    found = read_settings(targets.target_root(record.target_id), record.target_id)
    return {key: value for key, value in found.items()}


def test_exclude_and_level_l1_only_ever_send_less_and_need_no_question(
    remote: targets.ServerTarget, repository: Path
) -> None:
    del repository
    added = _RUNNER.invoke(app, ["server", "code", "exclude", "add", "data/"])
    assert added.exit_code == 0, added.output
    listed = _RUNNER.invoke(app, ["server", "code", "exclude", "list"])
    assert "data/" in listed.output
    level = _RUNNER.invoke(app, ["server", "code", "level", "L1"])
    assert level.exit_code == 0 and "kept at level L1" in level.output
    assert "only" not in level.output or "forget" in level.output
    (entry,) = _settings(remote).values()
    assert entry.level == "L1" and entry.exclude == ("data/",)  # type: ignore[attr-defined]
    bad = _RUNNER.invoke(app, ["server", "code", "exclude", "add", "/"])
    assert bad.exit_code != 0


def test_what_sends_more_needs_the_trusted_console(
    remote: targets.ServerTarget, repository: Path
) -> None:
    (repository / "aws.ini").write_bytes(b"key\n")
    _RUNNER.invoke(app, ["server", "code", "exclude", "add", "data/"])
    _RUNNER.invoke(app, ["server", "code", "level", "L1"])
    before = _settings(remote)
    for arguments in (
        ["server", "code", "exclude", "remove", "data/"],
        ["server", "code", "level", "default"],
        ["server", "code", "allow", "add", "aws.ini"],
    ):
        result = _RUNNER.invoke(app, arguments)
        assert result.exit_code != 0, arguments
        assert "trusted_console_required" in result.output or "terminal" in result.output
    assert _settings(remote) == before
    outside = _RUNNER.invoke(app, ["server", "code", "allow", "add", "../elsewhere.txt"])
    assert outside.exit_code != 0


def test_the_choices_are_refused_without_a_server_elsewhere(home: Path, repository: Path) -> None:
    del home, repository
    result = _RUNNER.invoke(app, ["server", "code", "exclude", "add", "data/"])
    assert result.exit_code != 0


_EVERY_CODE_COMMAND: tuple[tuple[str, ...], ...] = (
    ("list",),
    ("list", "--json"),
    ("forget",),
    ("forget", "--all"),
    ("exclude", "add", "logs/"),
    ("exclude", "remove", "data/"),
    ("exclude", "list"),
    ("allow", "add", "aws.ini"),
    ("allow", "list"),
    ("allow", "remove", "aws.ini"),
    ("level", "L1"),
    ("level", "default"),
)


@pytest.mark.parametrize("source", ["variable", "pin"])
@pytest.mark.parametrize("arguments", _EVERY_CODE_COMMAND, ids=" ".join)
def test_an_isolation_root_or_a_runtime_pin_refuses_every_code_command_before_it_acts(
    remote: targets.ServerTarget,
    repository: Path,
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    arguments: tuple[str, ...],
    source: str,
) -> None:
    """E5: a process an isolation variable or a pinned launcher points elsewhere never acts on
    the everyday selection's target: no server asked, no console opened, nothing written."""

    from finishup.config.paths import ISOLATED_ROOT_ENV_NAMES

    (repository / "aws.ini").write_bytes(b"key\n")
    assert _RUNNER.invoke(app, ["server", "code", "exclude", "add", "data/"]).exit_code == 0
    assert _RUNNER.invoke(app, ["server", "code", "level", "L1"]).exit_code == 0
    folder = _sent_from(remote, repository)
    before = _settings(remote)
    server = _server(monkeypatch, _Server())
    console = _Console(b"lab", b"lab")
    _console(monkeypatch, console)
    if source == "variable":
        explicit = home / "explicit"
        explicit.mkdir(mode=0o700)
        monkeypatch.setenv(ISOLATED_ROOT_ENV_NAMES[0], str(explicit))
    else:

        def pinned(**_kwargs: object) -> object:
            return object()

        monkeypatch.setattr("finishup.config.paths.read_runtime_pin", pinned)
    result = _RUNNER.invoke(app, ["server", "code", *arguments])
    assert result.exit_code == 2, result.output
    assert result.stderr.startswith("selection_overridden:")
    assert server.asked == [] and console.opened == 0
    assert _settings(remote) == before and folder.exists()


# --- allow: add, list and remove ----------------------------------------------------------------------


def _allowed(record: targets.ServerTarget) -> tuple[tuple[str, str], ...]:
    found = read_settings(targets.target_root(record.target_id), record.target_id)
    return tuple(item for entry in found.values() for item in entry.allow)


def test_allow_list_shows_paths_and_short_digests_never_contents(
    remote: targets.ServerTarget, repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Built at run time so this file itself holds no credential-shaped literal.
    secret = b"aws_secret = " + b"AKIA" + b"ABCDEFGHIJKLMNOP" + b"\n"
    (repository / "aws.ini").write_bytes(secret)
    empty = _RUNNER.invoke(app, ["server", "code", "allow", "list"])
    assert empty.exit_code == 0, empty.output
    assert "No file of this repository is allowed past the content scan on lab." in empty.output
    assert json.loads(
        _RUNNER.invoke(app, ["server", "code", "allow", "list", "--json"]).output
    ) == {"allow": []}
    console = _Console(b"lab")
    _console(monkeypatch, console)
    added = _RUNNER.invoke(app, ["server", "code", "allow", "add", "aws.ini"])
    assert added.exit_code == 0, added.output
    assert "matched a known secret format" in console.text
    full = "sha256:" + hashlib.sha256(secret).hexdigest()
    assert _allowed(remote) == (("aws.ini", full),)
    listed = _RUNNER.invoke(app, ["server", "code", "allow", "list"])
    assert listed.exit_code == 0, listed.output
    assert f"  aws.ini  {full[:19]}\n" in listed.output
    assert full not in listed.output and "AKIA" not in listed.output
    assert "allow remove PATH" in listed.output
    shown = json.loads(_RUNNER.invoke(app, ["server", "code", "allow", "list", "--json"]).output)
    assert shown == {"allow": [{"digest": full[:19], "path": "aws.ini"}]}
    # A directory is refused as a file, never read.
    (repository / "folder").mkdir()
    refused = _RUNNER.invoke(app, ["server", "code", "allow", "add", "folder"])
    assert refused.exit_code != 0 and "FILE must be a regular file" in refused.output
    # A named pipe is refused at once, never waited on for a writer.
    os.mkfifo(repository / "pipe")
    piped = _RUNNER.invoke(app, ["server", "code", "allow", "add", "pipe"])
    assert piped.exit_code != 0 and "FILE must be a regular file" in piped.output
    assert console.opened == 1


def test_allow_remove_sends_less_with_no_question_and_is_idempotent(
    remote: targets.ServerTarget, repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (repository / "aws.ini").write_bytes(b"one\n")
    _console(monkeypatch, _Console(b"lab", b"lab", b"lab"))
    assert _RUNNER.invoke(app, ["server", "code", "allow", "add", "aws.ini"]).exit_code == 0
    (repository / "aws.ini").write_bytes(b"two\n")
    assert _RUNNER.invoke(app, ["server", "code", "allow", "add", "aws.ini"]).exit_code == 0
    (repository / "other.ini").write_bytes(b"three\n")
    assert _RUNNER.invoke(app, ["server", "code", "allow", "add", "other.ini"]).exit_code == 0
    assert len(_allowed(remote)) == 3
    no_console = _NoConsole()
    _console(monkeypatch, no_console)
    removed = _RUNNER.invoke(app, ["server", "code", "allow", "remove", "aws.ini"])
    assert removed.exit_code == 0, removed.output
    assert "aws.ini is no longer allowed past the content scan on lab" in removed.output
    assert "stays there until you run 'finishup server code forget'" in removed.output
    # Every allowed content of that path goes; the other file's stays; no question was asked.
    assert [path for path, _digest in _allowed(remote)] == ["other.ini"]
    assert no_console.opened == 0
    again = _RUNNER.invoke(app, ["server", "code", "allow", "remove", "aws.ini"])
    assert again.exit_code == 0, again.output
    assert "aws.ini is not allowed past the content scan" in again.output
    assert "nothing was changed" in again.output
    never = _RUNNER.invoke(app, ["server", "code", "allow", "remove", "never.ini"])
    assert never.exit_code == 0 and "never.ini is not allowed" in never.output
    outside = _RUNNER.invoke(app, ["server", "code", "allow", "remove", "../aws.ini"])
    assert outside.exit_code != 0 and "PATH must be inside the repository" in outside.output
    assert [path for path, _digest in _allowed(remote)] == ["other.ini"]


# --- forget --all ---------------------------------------------------------------------------------

_FORGOT = {
    "copies": 1,
    "snapshots": 2,
    "objects": 10,
    "bytes": 732,
    "backups": "not_managed",
    "complete": True,
}


def _sent_from(record: targets.ServerTarget, folder: Path) -> Path:
    """An export folder as a sync from ``folder`` leaves it: its record names that folder."""

    from finishup.cli.server import repository_here
    from finishup.client.code_export import ExportDatabase
    from finishup.client.code_sync import export_folder

    path = export_folder(record.target_id, repository_here(str(folder)).key)
    ExportDatabase(path).remember_root(Path(os.path.realpath(folder)))
    return path


def _second_repository(tmp_path: Path, name: str = "other") -> Path:
    root = tmp_path / name
    root.mkdir()
    git(root, "init", "-q")
    (root / "b.py").write_bytes(b"b\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "m")
    return root


class _Server:
    """Stands in for a target's ``code_copy`` forget; records each claimed folder and the root of
    the target it was asked of."""

    def __init__(
        self, refuse: dict[str, str] | None = None, unfinished: frozenset[str] = frozenset()
    ) -> None:
        self.asked: list[tuple[str, str, Path | None]] = []
        self.refuse = refuse or {}
        self.unfinished = unfinished

    def __call__(
        self, record: targets.ServerTarget, worktree: str, action: str
    ) -> dict[str, object]:
        self.asked.append((worktree, action, targets.target_root(record.target_id)))
        reason = self.refuse.get(worktree)
        if reason is not None:
            raise ServerCommandRefused(reason)
        forgot: dict[str, object] = dict(_FORGOT)
        if worktree in self.unfinished:
            forgot.update(copies=0, snapshots=0, objects=0, bytes=0, complete=False)
        return {"action": action, "copy": None, "forgot": forgot}


def _server(monkeypatch: pytest.MonkeyPatch, server: _Server) -> _Server:
    monkeypatch.setattr(server_code, "_server_answer", server)
    return server


def test_forget_all_with_no_record_asks_nothing_and_says_so(
    remote: targets.ServerTarget, repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del remote, repository
    server = _server(monkeypatch, _Server())
    result = _RUNNER.invoke(app, ["server", "code", "forget", "--all"])
    assert result.exit_code == 0, result.output
    assert "no record of a copy of code it sent to lab; nothing was forgotten" in result.output
    shown = _RUNNER.invoke(app, ["server", "code", "forget", "--all", "--json"])
    assert shown.exit_code == 0, shown.output
    assert json.loads(shown.output) == {
        "action": "forget_all",
        "forgotten": 0,
        "not_forgotten": 0,
        "repositories": [],
    }
    assert server.asked == []


def test_forget_all_and_repository_are_refused_together(
    remote: targets.ServerTarget, repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _sent_from(remote, repository)
    server = _server(monkeypatch, _Server())
    result = _RUNNER.invoke(
        app, ["server", "code", "forget", "--all", "--repository", str(repository)]
    )
    assert result.exit_code == 2
    assert "usage: give --all or --repository FOLDER, not both" in result.output
    assert server.asked == []


def test_forget_all_forgets_each_folder_and_names_the_one_whose_folder_is_gone(
    remote: targets.ServerTarget,
    repository: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gone = _second_repository(tmp_path, "gone")
    kept = _sent_from(remote, repository)
    lost = _sent_from(remote, gone)
    import shutil

    shutil.rmtree(gone)
    server = _server(monkeypatch, _Server())
    result = _RUNNER.invoke(app, ["server", "code", "forget", "--all"])
    assert result.exit_code == 20, result.output
    top = os.path.realpath(repository)
    # Only the folder still there was claimed (its own worktree), and its export folder went.
    assert server.asked == [(top, "forget", targets.target_root(remote.target_id))]
    assert not kept.exists() and lost.exists()
    lines = result.stdout.splitlines()
    assert lines[0] == "Copies of code this computer sent to lab (2 repositories):"
    forgotten = next(line for line in lines if top in line)
    assert forgotten.endswith(
        f"(copy {kept.name[:8]}): forgotten; lab deleted 2 snapshot(s), 10 stored objects, "
        "732 bytes."
    )
    missing = next(line for line in lines if os.path.realpath(gone) in line)
    assert f"(copy {lost.name[:8]}): not forgotten (repository_folder_missing): " in missing
    assert "that folder is no longer there" in missing
    assert "1 of 2 not forgotten: each stays on lab until it expires or is forgotten." in lines
    assert "backups" in result.stdout
    assert result.stderr.startswith("code_copy_forget_incomplete:")
    # Once the folder is back as that repository, the same command forgets it (and only it).
    _second_repository(tmp_path, "gone")
    again = _RUNNER.invoke(app, ["server", "code", "forget", "--all", "--json"])
    assert again.exit_code == 0, again.output
    document = json.loads(again.stdout)
    assert document["forgotten"] == 1 and document["not_forgotten"] == 0
    (entry,) = document["repositories"]
    assert entry["outcome"] == "forgotten" and entry["reason"] is None
    assert entry["folder"] == os.path.realpath(gone) and entry["answer"]["forgot"] == _FORGOT
    assert not lost.exists()


def test_forget_all_names_every_copy_it_could_not_forget_and_keeps_its_record(
    remote: targets.ServerTarget,
    repository: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.client.code_export import ExportDatabase
    from finishup.client.code_sync import exports_folder

    refused = _second_repository(tmp_path, "refused")
    outer = _second_repository(tmp_path, "outer")
    inner = _second_repository(outer, "inner")
    first = _sent_from(remote, refused)
    moved = _sent_from(remote, inner)
    import shutil

    # That folder is no longer a repository of its own but a folder of another one: its key no
    # longer names that export folder.
    shutil.rmtree(inner / ".git")
    unknown = exports_folder(remote.target_id) / ("e" * 32)
    ExportDatabase(unknown)
    damaged = exports_folder(remote.target_id) / ("f" * 32)
    ExportDatabase(damaged)
    (damaged / "export.json").write_bytes(b"{}\n")
    server = _server(monkeypatch, _Server(refuse={os.path.realpath(refused): "remote_unreachable"}))
    result = _RUNNER.invoke(app, ["server", "code", "forget", "--all", "--json"])
    assert result.exit_code == 20, result.output
    document = json.loads(result.stdout)
    reasons = {entry["copy"]: entry["reason"] for entry in document["repositories"]}
    assert reasons == {
        first.name[:8]: "remote_unreachable",
        moved.name[:8]: "repository_changed",
        "e" * 8: "repository_folder_unknown",
        "f" * 8: "export_record_unreadable",
    }
    assert [entry["position"] for entry in document["repositories"]] == [1, 2, 3, 4]
    assert document["forgotten"] == 0 and document["not_forgotten"] == 4
    assert [asked[0] for asked in server.asked] == [os.path.realpath(refused)]
    # Nothing was forgotten, so every export folder stays for the next attempt.
    assert all(path.exists() for path in (first, moved, unknown, damaged))
    text = _RUNNER.invoke(app, ["server", "code", "forget", "--all"])
    assert text.exit_code == 20
    assert "not forgotten (remote_unreachable): the server could not be reached" in text.stdout
    assert "then run this command again" in text.stdout
    assert "that folder now holds another repository" in text.stdout
    assert "a folder this computer cannot name (copy eeeeeeee)" in text.stdout
    assert "4 of 4 not forgotten" in text.stdout and "backups" not in text.stdout
    assert repository.exists()


def test_a_forget_the_server_could_not_finish_is_never_shown_as_done(
    remote: targets.ServerTarget, repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A copy kept (fenced) because its erasures could not be recorded, or a deletion that
    failed: the server says it is not complete, so the command refuses and keeps this computer's
    export record, and ``--all`` names it as not forgotten (ADR-054, never a false success)."""

    exported = _sent_from(remote, repository)
    top = os.path.realpath(repository)
    server = _server(monkeypatch, _Server(unfinished=frozenset({top})))
    one = _RUNNER.invoke(app, ["server", "code", "forget", "--repository", str(repository)])
    assert one.exit_code == 20, one.output
    assert "lab could not finish deleting its copy of this repository" in one.stdout
    assert "Run this command again later." in one.stdout
    assert "deleted its copy" not in one.stdout and "backups" not in one.stdout
    assert one.stderr.startswith("code_copy_deletion_unfinished:")
    assert exported.exists()
    shown = _RUNNER.invoke(app, ["server", "code", "forget", "--all", "--json"])
    assert shown.exit_code == 20, shown.output
    document = json.loads(shown.stdout)
    assert (document["forgotten"], document["not_forgotten"]) == (0, 1)
    (entry,) = document["repositories"]
    assert (entry["outcome"], entry["reason"]) == ("not_forgotten", "code_copy_deletion_unfinished")
    assert exported.exists()
    text = _RUNNER.invoke(app, ["server", "code", "forget", "--all"])
    assert "not forgotten (code_copy_deletion_unfinished): that server could not finish" in (
        text.stdout
    )
    # Once the server finishes, the same command forgets it and the record goes.
    server.unfinished = frozenset()
    done = _RUNNER.invoke(app, ["server", "code", "forget", "--repository", str(repository)])
    assert done.exit_code == 0, done.output
    assert "lab deleted its copy of this repository: 2 snapshot(s)" in done.stdout
    assert not exported.exists()


# --- server remove offers to forget first ------------------------------------------------------------


@pytest.fixture
def far(remote: targets.ServerTarget, monkeypatch: pytest.MonkeyPatch) -> targets.ServerTarget:
    """A second server elsewhere, not selected (``lab`` is), with a stand-in connection."""

    from tests.builders.server_targets import remote_runtime

    del remote
    remote_runtime(monkeypatch)
    monkeypatch.setattr("finishup.client.credentials._platform_backend", lambda: None)
    with targets.registry_lock():
        record, _root = targets.new_remote_target("far", "https", base_url="https://far.example")
    return record


def _names() -> set[str]:
    return {record.name for record in targets.list_targets()}


def test_remove_asks_first_and_yes_forgets_through_that_target_before_removing_it(
    far: targets.ServerTarget, repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = _sent_from(far, repository)
    server = _server(monkeypatch, _Server())
    console = _Console(b"yes")
    _console(monkeypatch, console)
    result = _RUNNER.invoke(app, ["server", "remove", "far"])
    assert result.exit_code == 0, result.output
    assert "Forget deletes those copies and their snapshots on far now." in console.text
    assert "removing far here does not delete them" in console.text
    assert "this computer cannot ask it to forget them" in console.text
    # Asked of that target's own root, though another one is selected; then it was removed.
    root = targets.target_root(far.target_id)
    assert server.asked == [(os.path.realpath(repository), "forget", root)]
    assert "forgotten; far deleted 2 snapshot(s)" in result.stdout
    assert "Removed server target far" in result.stdout
    assert "may still keep copies" not in result.output
    assert "far" not in _names() and not folder.exists() and not root.exists()


def test_remove_no_keeps_the_copies_there_and_says_so(
    far: targets.ServerTarget, repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _sent_from(far, repository)
    server = _server(monkeypatch, _Server())
    _console(monkeypatch, _Console(b"no"))
    result = _RUNNER.invoke(app, ["server", "remove", "far"])
    assert result.exit_code == 0, result.output
    assert server.asked == []
    assert "far may still keep copies of code this computer sent it." in result.stderr
    assert "they stay until they expire or that server's owner deletes them" in result.stderr
    assert "could not ask" not in result.stderr
    assert "far" not in _names()


def test_remove_answered_with_neither_yes_nor_no_removes_nothing(
    far: targets.ServerTarget, repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = _sent_from(far, repository)
    server = _server(monkeypatch, _Server())
    _console(monkeypatch, _Console(b"far"))
    result = _RUNNER.invoke(app, ["server", "remove", "far"])
    assert result.exit_code == 2
    assert result.stderr.startswith(
        "authorization_declined: neither yes nor no was typed, so nothing was removed"
    )
    assert server.asked == [] and "far" in _names() and folder.exists()


def test_remove_forget_copies_stops_before_removing_when_a_forget_fails(
    far: targets.ServerTarget, repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = _sent_from(far, repository)
    top = os.path.realpath(repository)
    server = _server(monkeypatch, _Server(refuse={top: "remote_unreachable"}))
    console = _NoConsole()
    _console(monkeypatch, console)
    result = _RUNNER.invoke(app, ["server", "remove", "far", "--forget-copies"])
    assert result.exit_code == 20, result.output
    assert f"1. {top} (copy {folder.name[:8]}): not forgotten (remote_unreachable)" in result.stdout
    assert result.stderr.startswith("code_copy_forget_incomplete: not every copy")
    assert "so the target was not removed" in result.stderr
    assert "Removed" not in result.output
    # Nothing was removed or asked on a console: the owner can retry.
    assert "far" in _names() and folder.exists() and console.opened == 0
    assert len(server.asked) == 1
    server.refuse.clear()
    again = _RUNNER.invoke(app, ["server", "remove", "far", "--forget-copies"])
    assert again.exit_code == 0, again.output
    assert "far" not in _names() and console.opened == 0


class _Watched:
    """Records whether ``far``'s L2 sync fence is in force at each step of ``server remove``."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
        from finishup.client import code_export
        from finishup.client.code_sync_fence import fenced

        self.steps: list[tuple[str, bool]] = []
        listing = code_export.export_records
        removing = server_cli._remove_remote  # pyright: ignore[reportPrivateUsage]

        def records(directory: Path) -> object:
            self.steps.append(("listed", fenced(root)))
            return listing(directory)

        def remove(record: targets.ServerTarget, at: Path) -> bool:
            self.steps.append(("removed", fenced(root)))
            return removing(record, at)

        monkeypatch.setattr(code_export, "export_records", records)
        monkeypatch.setattr(server_cli, "_remove_remote", remove)
        self.fenced = fenced


class _FencedServer(_Server):
    def __init__(self, watched: _Watched, root: Path, refuse: dict[str, str] | None = None) -> None:
        super().__init__(refuse)
        self.watched = watched
        self.root = root

    def __call__(
        self, record: targets.ServerTarget, worktree: str, action: str
    ) -> dict[str, object]:
        self.watched.steps.append(("forgot", self.watched.fenced(self.root)))
        return super().__call__(record, worktree, action)


def test_remove_forget_copies_fences_l2_sync_from_the_listing_through_the_removal(
    far: targets.ServerTarget, repository: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """E2: no check can make far's helper sync a forgotten repository again meanwhile."""

    _sent_from(far, repository)
    _sent_from(far, _second_repository(tmp_path))
    root = targets.target_root(far.target_id)
    watched = _Watched(monkeypatch, root)
    _server(monkeypatch, _FencedServer(watched, root))
    _console(monkeypatch, _NoConsole())
    result = _RUNNER.invoke(app, ["server", "remove", "far", "--forget-copies"])
    assert result.exit_code == 0, result.output
    assert watched.steps == [
        ("listed", True),
        ("forgot", True),
        ("forgot", True),
        ("removed", True),
    ]
    assert not root.exists() and "far" not in _names()


@pytest.mark.parametrize("failure", ["forget", "removal"])
def test_a_remove_that_does_not_happen_lowers_the_fence_again(
    far: targets.ServerTarget,
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    from finishup.client.code_sync_fence import fenced

    _sent_from(far, repository)
    root = targets.target_root(far.target_id)
    watched = _Watched(monkeypatch, root)
    top = os.path.realpath(repository)
    refuse = {top: "remote_unreachable"} if failure == "forget" else None
    _server(monkeypatch, _FencedServer(watched, root, refuse))
    _console(monkeypatch, _NoConsole())
    if failure == "removal":

        def still_connected(_record: targets.ServerTarget, _root: Path) -> bool:
            raise ServerCommandRefused("target_still_connected")

        monkeypatch.setattr(server_cli, "_remove_remote", still_connected)
    result = _RUNNER.invoke(app, ["server", "remove", "far", "--forget-copies"])
    assert result.exit_code != 0, result.output
    assert ("forgot", True) in watched.steps
    # The target stays, and so does its way back to sending copies at level L2.
    assert "far" in _names() and root.exists() and not fenced(root)


def test_a_fence_that_cannot_be_raised_refuses_the_remove_before_anything_is_forgotten(
    far: targets.ServerTarget, repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.client import code_sync_fence

    folder = _sent_from(far, repository)
    server = _server(monkeypatch, _Server())
    _console(monkeypatch, _NoConsole())

    def unwritable(_root: Path) -> None:
        raise code_sync_fence.CodeSyncFenceError

    monkeypatch.setattr(code_sync_fence, "raise_fence", unwritable)
    result = _RUNNER.invoke(app, ["server", "remove", "far", "--forget-copies"])
    assert result.exit_code != 0, result.output
    assert result.stderr.startswith("code_copy_fence_unavailable:")
    assert "the target was not removed" in result.stderr
    assert server.asked == [] and folder.exists() and "far" in _names()


def test_remove_keep_copies_removes_without_a_question_or_a_forget(
    far: targets.ServerTarget, repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _sent_from(far, repository)
    server = _server(monkeypatch, _Server())
    console = _NoConsole()
    _console(monkeypatch, console)
    result = _RUNNER.invoke(app, ["server", "remove", "far", "--keep-copies"])
    assert result.exit_code == 0, result.output
    assert "far may still keep copies of code this computer sent it." in result.stderr
    assert "could not ask" not in result.stderr
    assert server.asked == [] and console.opened == 0 and "far" not in _names()


def test_remove_with_no_console_and_no_flag_removes_and_warns_as_before(
    far: targets.ServerTarget, repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _sent_from(far, repository)
    server = _server(monkeypatch, _Server())
    console = _NoConsole()
    _console(monkeypatch, console)
    result = _RUNNER.invoke(app, ["server", "remove", "far"])
    assert result.exit_code == 0, result.output
    assert console.opened == 1 and server.asked == []
    assert "far may still keep copies of code this computer sent it." in result.stderr
    assert "'finishup server remove far --forget-copies' forgets them" in result.stderr
    assert "far" not in _names()


def test_remove_flags_are_shown_refused_together_and_need_copies_to_ask(
    far: targets.ServerTarget, repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del repository
    shown = _plain(_RUNNER.invoke(app, ["server", "remove", "--help"]).output)
    assert "--forget-copies" in shown and "--keep-copies" in shown
    both = _RUNNER.invoke(app, ["server", "remove", "far", "--forget-copies", "--keep-copies"])
    assert both.exit_code == 2
    assert "give --forget-copies or --keep-copies, not both" in both.output
    leftover = _RUNNER.invoke(app, ["server", "remove", "t_0badf00d", "--forget-copies"])
    assert leftover.exit_code == 2 and "a leftover folder names no server" in leftover.output
    assert "far" in _names()
    # No copies sent: nothing is asked, and --forget-copies says there was nothing to forget.
    server = _server(monkeypatch, _Server())
    console = _NoConsole()
    _console(monkeypatch, console)
    result = _RUNNER.invoke(app, ["server", "remove", "far", "--forget-copies"])
    assert result.exit_code == 0, result.output
    assert "no record of a copy of code it sent to far; nothing was forgotten" in result.stdout
    assert console.opened == 0 and server.asked == [] and "far" not in _names()


# --- the connection is bound to the target the command read (E4) ------------------------------------


class _Connection:
    """Stands in for ``build_service_client``: admitted for the record at the root this process
    resolves now (as the real admission reads it), recording which root was asked what."""

    asked: list[tuple[Path | None, str]] = []

    def __init__(self) -> None:
        from finishup.client.authorization import Grant, consent_digest, identity_digest
        from finishup.config.paths import active_root

        self.root = active_root()
        record = targets.active_target_record()
        assert record is not None
        self.authorization = type("Admitted", (), {})()
        self.authorization.grant = Grant(  # type: ignore[attr-defined]
            target_id=record.target_id,
            kind=record.kind,
            identity_digest=identity_digest(record),
            consent_digest=consent_digest(record),
            repository_key=None,
            selection_bound=False,
        )

    async def code_copy(self, action: str) -> dict[str, object]:
        _Connection.asked.append((self.root, action))
        return {"action": action, "copy": None, "forgot": dict(_FORGOT)}

    async def close(self) -> None:
        return None


@pytest.fixture
def connection(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Path | None, str]]:
    async def build(*_arguments: object, **_options: object) -> _Connection:
        return _Connection()

    _Connection.asked = []
    monkeypatch.setattr("finishup.cli.app.build_service_client", build)
    return _Connection.asked


def _meanwhile(monkeypatch: pytest.MonkeyPatch, change: Callable[[], None]) -> None:
    """Run ``change`` once, after the command read its target and before it connects."""

    real = server_code.repository_here
    done: list[bool] = []

    def here(folder: str | None = None) -> object:
        if not done:
            done.append(True)
            change()
        return real(folder)

    monkeypatch.setattr(server_code, "repository_here", here)


@pytest.fixture
def other(remote: targets.ServerTarget) -> targets.ServerTarget:
    del remote
    with targets.registry_lock():
        record, _root = targets.new_remote_target(
            "other", "https", base_url="https://other.example"
        )
    return record


@pytest.mark.parametrize("arguments", [("forget",), ("forget", "--all"), ("list",)], ids=" ".join)
def test_a_selection_changed_before_the_connection_still_asks_the_target_read(
    remote: targets.ServerTarget,
    other: targets.ServerTarget,
    repository: Path,
    connection: list[tuple[Path | None, str]],
    monkeypatch: pytest.MonkeyPatch,
    arguments: tuple[str, ...],
) -> None:
    mine = _sent_from(remote, repository)
    theirs = _sent_from(other, repository)

    def select_other() -> None:
        with targets.registry_lock():
            targets.write_selection(other)

    _meanwhile(monkeypatch, select_other)
    result = _RUNNER.invoke(app, ["server", "code", *arguments])
    assert result.exit_code == 0, result.output
    action = "status" if arguments[0] == "list" else "forget"
    # Asked of lab, the target the command read and names, never of the newly selected one.
    assert connection == [(targets.target_root(remote.target_id), action)]
    assert "lab" in result.stdout and "other" not in result.stdout
    assert theirs.exists()
    assert mine.exists() == (action == "status")


@pytest.mark.parametrize("arguments", [("forget",), ("forget", "--all"), ("list",)], ids=" ".join)
def test_a_target_authorized_again_before_the_connection_is_refused_and_nothing_is_forgotten(
    remote: targets.ServerTarget,
    repository: Path,
    connection: list[tuple[Path | None, str]],
    monkeypatch: pytest.MonkeyPatch,
    arguments: tuple[str, ...],
) -> None:
    folder = _sent_from(remote, repository)

    def authorize_again() -> None:
        root = targets.target_root(remote.target_id)
        with targets.registry_lock():
            current = targets.read_target(root)
            assert current is not None
            targets.write_target(
                root, targets.reauthorized(current, now="2031-01-01T00:00:00.000Z")
            )

    _meanwhile(monkeypatch, authorize_again)
    result = _RUNNER.invoke(app, ["server", "code", *arguments])
    assert result.exit_code != 0, result.output
    assert "server_authorization_changed" in result.output
    assert connection == [] and folder.exists()
    assert "deleted" not in result.stdout.replace("not forgotten", "")


@pytest.mark.parametrize(
    ("before", "after", "helper"),
    [
        ("L1", "L2", "follows"),
        ("L2", "L1", "follows"),
        ("L1", "L2", "silent"),
        ("L1", "L2", "none"),
        ("L1", "L1", "silent"),
    ],
)
def test_server_use_that_changes_the_level_ends_once_that_servers_helper_follows_it(
    remote: targets.ServerTarget,
    monkeypatch: pytest.MonkeyPatch,
    before: str,
    after: str,
    helper: str,
) -> None:
    """Defect A, re-review (Codex, R2-1): a helper's background agent declares the code-sync
    operations only when it opens, and the helper follows a changed consent only at its next
    tick, so a task sent right after ``server use NAME --level L2`` could meet the L1 agent and
    be refused the sync at once. A level change now waits until that server's running helper
    says it follows the new consent (every agent that declared less closed); one that does not
    say so in time is stopped instead; with no helper nothing is waited for. Confirming the same
    level waits for nothing."""

    from types import SimpleNamespace

    from tests.builders.server_profiles import consent_to
    from tests.builders.server_targets import remote_runtime

    from finishup.client import helper_status
    from finishup.client.authorization import consent_digest

    def at(level: str) -> targets.ServerTarget:
        with release_l2():
            return consent_to(
                remote,
                _L2_DOCUMENT,
                level=level,
                retention=Retention("days", 7) if level == "L2" else None,
            )

    at(before)
    runtime = remote_runtime(monkeypatch)
    root = targets.target_root(remote.target_id)
    waited: list[float] = []

    def use(_name: str, **_options: object) -> object:
        record = at(after)
        if helper == "follows":
            helper_status.write_followed_consent(root, consent_digest(record))
        return SimpleNamespace(record=record, left_lines=tuple, left_open=False)

    monkeypatch.setattr(server_cli, "use_target", use)
    monkeypatch.setattr(
        helper_status, "helper_holder", lambda _root: None if helper == "none" else object()
    )
    monkeypatch.setattr(server_cli, "_FOLLOW_SECONDS", 0.3)
    monkeypatch.setattr(server_cli.time, "sleep", waited.append)
    result = CliRunner().invoke(server_cli.server_app, ["use", "lab", "--level", after])
    assert result.exit_code == 0, result.output
    stopped = before != after and helper == "silent"
    assert runtime.stops == ([root] if stopped else [])
    assert bool(waited) is stopped
