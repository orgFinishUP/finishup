"""Consent at level L2 and ``finishup server code`` (ADR-054; design v2 §2.3, §4.3, §4.4, U11)."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.builders.server_copy import git, release_l2
from tests.builders.server_profiles import fetched, profile_document
from tests.builders.server_targets import ambient_home
from typer.testing import CliRunner

from finishup.cli import server as server_cli
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
        ["server", "code", "allow", "aws.ini"],
    ):
        result = _RUNNER.invoke(app, arguments)
        assert result.exit_code != 0, arguments
        assert "trusted_console_required" in result.output or "terminal" in result.output
    assert _settings(remote) == before
    outside = _RUNNER.invoke(app, ["server", "code", "allow", "../elsewhere.txt"])
    assert outside.exit_code != 0


def test_the_choices_are_refused_without_a_server_elsewhere(home: Path, repository: Path) -> None:
    del home, repository
    result = _RUNNER.invoke(app, ["server", "code", "exclude", "add", "data/"])
    assert result.exit_code != 0
    _ = (json, os)
