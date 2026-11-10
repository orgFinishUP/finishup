"""Consent at level L2 and ``finishup server code`` (ADR-054; design v2 §2.3, §4.3, §4.4, U11)."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
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


def test_l2_is_refused_before_any_console_while_it_is_unreleased(
    remote: targets.ServerTarget,
) -> None:
    with pytest.raises(ServerCommandRefused) as raised:
        _offer(remote, LevelChoice(level="L2"))
    assert raised.value.reason == "server_level_unavailable"


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
    # Without L2 released, 'use' falls back to L1 rather than ask for an unavailable level.
    envelope, _lines = server_cli._consent_offer(  # pyright: ignore[reportPrivateUsage]
        stored, fetched(stored, _L2_DOCUMENT), None, stored=stored
    )
    assert envelope.level == "L1"


def test_the_level_options_are_hidden_and_refused_for_a_server_on_this_computer(home: Path) -> None:
    del home
    shown = _RUNNER.invoke(app, ["server", "add", "--help"])
    assert "--level" not in shown.output and "--retention" not in shown.output
    assert "code" not in _RUNNER.invoke(app, ["server", "--help"]).output.split("Commands")[-1]
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


# --- allow: add, list and remove ----------------------------------------------------------------------


def _allowed(record: targets.ServerTarget) -> tuple[tuple[str, str], ...]:
    found = read_settings(targets.target_root(record.target_id), record.target_id)
    return tuple(item for entry in found.values() for item in entry.allow)


def test_allow_list_shows_paths_and_short_digests_never_contents(
    remote: targets.ServerTarget, repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = b"aws_secret = AKIAABCDEFGHIJKLMNOP\n"
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

_FORGOT = {"copies": 1, "snapshots": 2, "objects": 10, "bytes": 732, "backups": "not_managed"}


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
    """Stands in for the selected server's ``code_copy`` forget; records each claimed folder."""

    def __init__(self, refuse: dict[str, str] | None = None) -> None:
        self.asked: list[tuple[str, str, Path | None]] = []
        self.refuse = refuse or {}

    def __call__(self, worktree: str, action: str) -> dict[str, object]:
        from finishup.config.paths import active_root

        self.asked.append((worktree, action, active_root()))
        reason = self.refuse.get(worktree)
        if reason is not None:
            raise ServerCommandRefused(reason)
        return {"action": action, "copy": None, "forgot": dict(_FORGOT)}


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
    assert lines[0] == "Every copy of code this computer sent to lab (2):"
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
