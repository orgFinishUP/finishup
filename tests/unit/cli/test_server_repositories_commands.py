"""``finishup server repositories``: a repository whose policy here allows no network use (ADR-051).

Maintainer decision of 2026-11-07, round 4. While a server elsewhere is selected, such a
repository is held from it until the owner decides. ``add`` sends it anyway, after a disclosure on
the trusted console and the typed target name; ``keep`` keeps it on this computer without asking
again, needs neither and may be run by an agent; ``remove`` undoes either, and ``list`` and
``status`` show them. Refusals are a closed reason and fixed text, never a path or a name.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner, Result

import finishup.cli.zero_network_selection as zero_network
from builders.server_targets import ambient_home
from finishup.cli import app as cli
from finishup.cli import server as server_cli
from finishup.cli import trusted_console
from finishup.client import targets
from finishup.client.everyday_policy import (
    forget_repository_reports,
    record_reported_policy,
    record_repository_report,
    repository_report,
)
from finishup.client.everyday_repository import repository_key_for
from finishup.client.repository_hold import (
    add_kept,
    add_override,
    overrides_path,
    read_overrides,
)
from finishup.config.paths import reset_selection_memo
from finishup.protocol.canonical import JsonValue
from finishup.protocol.schemas import validate_schema_instance

_RUNNER = CliRunner()
_AT = datetime(2026, 11, 7, 9, 30, tzinfo=UTC)
_STAMP = "2026-11-07T09:30:00.000Z"


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        monkeypatch.setattr(zero_network, "_selection_on_disk", zero_network.read_selection_on_disk)
        yield root


def _remote(kind: str = "https", *, select: bool = True, name: str = "lab") -> targets.ServerTarget:
    fields: dict[str, object]
    if kind == "ssh":
        fields = {"user": "owner", "host": "lab.example", "port": 22}
    elif kind == "local_port":
        fields = {"base_url": "https://127.0.0.1:8443"}
    else:
        fields = {"base_url": "https://lab.example"}
    with targets.registry_lock():
        record, _root = targets.new_remote_target(name, kind, **fields)  # pyright: ignore[reportArgumentType]
        if select:
            targets.write_selection(record)
    return record


@pytest.fixture
def remote(home: Path) -> targets.ServerTarget:
    del home
    return _remote()


@pytest.fixture
def repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """A Git repository, and the current folder."""

    path = tmp_path / "repository"
    path.mkdir()
    subprocess.run(
        ["git", "-C", os.fspath(path), "init"],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"},
    )
    resolved = os.fspath(path.resolve())
    monkeypatch.chdir(resolved)
    return resolved


def _key(worktree: str) -> str:
    key = asyncio.run(repository_key_for(worktree))
    assert key is not None
    return key


def _held(worktree: str) -> str:
    key = _key(worktree)
    assert record_repository_report(key, worktree, no_network=True, now=_AT)
    return key


@pytest.fixture
def confirmed(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str, str]]:
    """Record the trusted-console confirmations instead of opening /dev/tty."""

    seen: list[tuple[str, str, str]] = []

    def confirm(record: targets.ServerTarget, worktree: str, state: str) -> None:
        seen.append((record.target_id, worktree, state))

    monkeypatch.setattr(server_cli, "_confirm_repository_on_trusted_console", confirm)
    return seen


def _invoke(*arguments: str) -> Result:
    reset_selection_memo()
    return _RUNNER.invoke(cli.app, ["server", "repositories", *arguments])


def _no_trusted_console(monkeypatch: pytest.MonkeyPatch) -> None:
    def refused(_self: object) -> object:
        raise trusted_console.TrustedConsoleError("trusted_console_required")

    monkeypatch.setattr(trusted_console.TrustedForegroundConsole, "__enter__", refused)


def _clean(text: str, *forbidden: str) -> None:
    for value in forbidden:
        assert value not in text


@pytest.mark.parametrize("command", ["", "add", "keep", "list", "remove"])
def test_every_repositories_command_renders_its_help(home: Path, command: str) -> None:
    del home
    result = _RUNNER.invoke(
        cli.app, ["server", "repositories", *([command] if command else []), "--help"]
    )
    assert result.exit_code == 0, result.output
    assert "Usage" in result.output


def test_the_command_runs_only_on_this_client() -> None:
    from finishup.cli.command_scope import command_scope

    assert command_scope("server repositories") == "client_only"


# --- add ------------------------------------------------------------------------------------------


def test_adding_needs_the_trusted_console(
    remote: targets.ServerTarget, repository: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _held(repository)
    _no_trusted_console(monkeypatch)
    result = _invoke("add")
    assert result.exit_code == 2
    assert result.stderr.startswith("trusted_console_required:")
    _clean(result.stderr, repository, "lab")
    assert read_overrides(targets.target_root(remote.target_id), remote.target_id) == ()


def test_a_wrong_name_declines_and_records_nothing(
    remote: targets.ServerTarget, repository: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _held(repository)

    class Console:
        shown: list[str] = []

        def __enter__(self) -> Console:
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def write(self, text: str) -> None:
            Console.shown.append(text)

        def read_choice(self, prompt: str, allowed: tuple[bytes, ...]) -> bytes:
            assert allowed == (b"lab",)
            raise trusted_console.TrustedConsoleError("input_invalid")

    monkeypatch.setattr(trusted_console, "TrustedForegroundConsole", Console)
    result = _invoke("add")
    assert result.exit_code == 2
    assert result.stderr.startswith("authorization_declined:")
    shown = "".join(Console.shown)
    # The notice says what is sent, that the policy here is unchanged, and the honest limit.
    assert f"Send this repository's work to server target lab ({remote.target_id}) anyway:" in shown
    assert f"  {repository}\n" in shown
    assert "(this computer's FinishUP last reported this at 2026-11-07T09:30:00.000Z" in shown
    assert "without the content captured while it was held" in shown
    assert "not what an agent in another folder reads and its hooks capture" in shown
    assert read_overrides(targets.target_root(remote.target_id), remote.target_id) == ()


@pytest.mark.parametrize("kind", ["ssh", "https", "local_port"])
def test_add_records_the_allow_for_the_selected_server_by_default(
    home: Path, repository: str, confirmed: list[tuple[str, str, str]], kind: str
) -> None:
    record = _remote(kind)
    key = _held(repository)
    result = _invoke("add")
    assert result.exit_code == 0, result.output
    assert confirmed == [
        (
            record.target_id,
            repository,
            "Its privacy policy on this computer allows no network use (this computer's FinishUP "
            "last reported this at 2026-11-07T09:30:00.000Z; it cannot be asked now).",
        )
    ]
    (choice,) = read_overrides(targets.target_root(record.target_id), record.target_id)
    # The allow carries the report's own stretch: it lapses if the policy changes.
    assert (choice.key, choice.choice, choice.no_network_since) == (key, "send", _STAMP)
    assert "now receives this repository's work" in result.stdout
    assert "Your agent can repeat its last FinishUP request now" in result.stdout


def test_a_live_answer_and_a_changed_policy_are_said_before_the_name(
    remote: targets.ServerTarget,
    repository: str,
    confirmed: list[tuple[str, str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = _held(repository)
    root = targets.target_root(remote.target_id)
    with targets.registry_lock():
        add_override(root, remote.target_id, key, repository, "2026-11-01T00:00:00.000Z")
    monkeypatch.setattr(zero_network, "_repository_reader", lambda _worktree: "no_network")
    assert _invoke("add").exit_code == 0
    (_id, _worktree, state) = confirmed[0]
    assert state.splitlines() == [
        "Its privacy policy on this computer allows no network use (this computer's FinishUP "
        "said so now).",
        "You chose for it before, but its privacy policy here changed since, so FinishUP asks "
        "again.",
    ]


@pytest.mark.parametrize(
    ("setup", "line"),
    [
        ("never_set_up", "was never set up"),
        ("not_reported", "has not reported this repository's privacy policy"),
        ("permitted", "allows network use, so lab"),
        ("sent", "already receives this repository's work (you allowed it at"),
    ],
)
def test_the_four_informational_outcomes_record_nothing(
    remote: targets.ServerTarget,
    repository: str,
    confirmed: list[tuple[str, str, str]],
    monkeypatch: pytest.MonkeyPatch,
    setup: str,
    line: str,
) -> None:
    root = targets.target_root(remote.target_id)
    if setup == "never_set_up":
        monkeypatch.setattr(zero_network, "_repository_reader", lambda _worktree: "no_policy")
    elif setup == "permitted":
        record_repository_report(_key(repository), repository, no_network=False, now=_AT)
    elif setup == "sent":
        key = _held(repository)
        with targets.registry_lock():
            add_override(root, remote.target_id, key, repository, _STAMP)
    before = read_overrides(root, remote.target_id)
    result = _invoke("add")
    assert result.exit_code == 0, result.output
    assert line in result.stdout
    assert confirmed == []
    assert read_overrides(root, remote.target_id) == before


def test_add_is_for_a_server_elsewhere_inside_a_repository(
    home: Path, repository: str, tmp_path: Path, confirmed: list[tuple[str, str, str]]
) -> None:
    # Nothing selected, or a server on this computer: nothing is held for it.
    nothing = _invoke("add")
    assert nothing.exit_code == 2 and nothing.stderr.startswith("repositories_not_applicable:")
    with targets.registry_lock():
        local, _root = targets.new_local_target("work")
        targets.write_selection(local)
    named_local = _invoke("add", "work")
    assert named_local.exit_code == 2
    assert named_local.stderr.startswith("repositories_not_applicable:")
    _remote(select=True, name="lab")
    root_folder = _invoke("add", "lab", "--repository", "/")
    assert root_folder.exit_code == 2 and root_folder.stderr.startswith("repository_invalid:")
    missing = _invoke("add", "lab", "--repository", os.fspath(tmp_path / "missing"))
    assert missing.exit_code == 2 and missing.stderr.startswith("repository_invalid:")
    _clean(missing.stderr, os.fspath(tmp_path), "lab ")
    assert confirmed == []


def test_zero_network_is_refused_before_the_repository_is_looked_at(
    remote: targets.ServerTarget, repository: str, confirmed: list[tuple[str, str, str]]
) -> None:
    _held(repository)
    record_reported_policy(zero_network=True, now=_AT)
    result = _invoke("add")
    assert result.exit_code == 2
    assert result.stderr.startswith("zero_network_remote_selected:")
    assert confirmed == []


def test_a_full_or_damaged_record_is_refused_before_the_name(
    remote: targets.ServerTarget, repository: str, confirmed: list[tuple[str, str, str]]
) -> None:
    root = targets.target_root(remote.target_id)
    _held(repository)
    with targets.registry_lock():
        for number in range(64):
            add_kept(root, remote.target_id, f"sha256:{number:064x}", f"/srv/r{number}", _STAMP)
    full = _invoke("add")
    assert full.exit_code == 2 and full.stderr.startswith("repository_limit:")
    overrides_path(root).write_bytes(b"{oops\n")
    damaged = _invoke("add")
    assert damaged.exit_code == 20
    assert damaged.stderr.startswith("repositories_record_invalid:")
    assert "'finishup server repositories remove NAME --all'" in damaged.stderr
    _clean(damaged.stderr, repository)
    assert confirmed == []


# --- keep -----------------------------------------------------------------------------------------


def test_keep_needs_no_console_and_records_the_choice_by_id_only(
    remote: targets.ServerTarget, repository: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_trusted_console(monkeypatch)
    key = _held(repository)
    result = _invoke("keep")
    assert result.exit_code == 0, result.output
    (choice,) = read_overrides(targets.target_root(remote.target_id), remote.target_id)
    assert (choice.key, choice.choice, choice.no_network_since) == (key, "keep", _STAMP)
    assert f"kept on this computer for Server {remote.target_id} (https)" in result.stdout
    assert "FinishUP does not ask about it again" in result.stdout
    assert "What an agent in another folder reads and its hooks capture is not covered" in (
        result.stdout
    )
    # An agent may run it: no path and no name it did not type.
    _clean(result.stdout, repository, "lab")
    again = _invoke("keep")
    assert again.exit_code == 0 and "already kept" in again.stdout


def test_keep_replaces_an_allow_and_says_open_connections_close(
    remote: targets.ServerTarget, repository: str
) -> None:
    key = _held(repository)
    root = targets.target_root(remote.target_id)
    with targets.registry_lock():
        add_override(root, remote.target_id, key, repository, _STAMP)
    result = _invoke("keep", "lab")
    assert result.exit_code == 0, result.output
    assert "'finishup server repositories add lab'" in result.stdout
    assert "open ones close within about a second" in result.stdout
    (choice,) = read_overrides(root, remote.target_id)
    assert choice.choice == "keep"


def test_keep_records_nothing_when_nothing_is_held(
    remote: targets.ServerTarget, repository: str
) -> None:
    result = _invoke("keep")
    assert result.exit_code == 0 and "nothing to keep" in result.stdout
    assert read_overrides(targets.target_root(remote.target_id), remote.target_id) == ()


# --- list and remove ------------------------------------------------------------------------------


def test_list_shows_every_group_and_the_reverse_commands(
    remote: targets.ServerTarget, repository: str, tmp_path: Path
) -> None:
    root = targets.target_root(remote.target_id)
    held = _held(repository)
    for name in ("kept", "sent", "open"):
        (tmp_path / name).mkdir()
    kept = "sha256:" + "1" * 64
    sent = "sha256:" + "2" * 64
    opened = "sha256:" + "3" * 64
    record_repository_report(kept, os.fspath(tmp_path / "kept"), no_network=True, now=_AT)
    record_repository_report(sent, os.fspath(tmp_path / "sent"), no_network=True, now=_AT)
    record_repository_report(opened, os.fspath(tmp_path / "open"), no_network=False, now=_AT)
    with targets.registry_lock():
        add_kept(root, remote.target_id, kept, os.fspath(tmp_path / "kept"), _STAMP, now=_AT)
        add_override(root, remote.target_id, sent, os.fspath(tmp_path / "sent"), _STAMP, now=_AT)
        add_override(root, remote.target_id, opened, os.fspath(tmp_path / "open"), _STAMP, now=_AT)
        add_kept(root, remote.target_id, held, "/srv/moved-away", "2026-11-01T00:00:00.000Z")
    result = _invoke("list")
    assert result.exit_code == 0, result.output
    lines = result.stdout.splitlines()
    assert f"lab ({remote.target_id}), a FinishUP server over HTTPS:" in lines
    assert "  Held (privacy policy here allows no network use):" in lines
    assert (
        f"    {repository}  (reported {_STAMP})  — its policy changed after you chose for it"
    ) in lines
    assert "  Kept on this computer, as you chose:" in lines
    assert f"    {tmp_path / 'kept'}  (kept {_STAMP})" in lines
    assert "  Sent anyway, as you allowed:" in lines
    assert f"    {tmp_path / 'sent'}  (allowed {_STAMP})" in lines
    assert "  Chosen earlier, not needed now (its policy here allows network use):" in lines
    assert f"    {tmp_path / 'open'}" in lines
    assert lines[-1].startswith("A repository this computer's FinishUP has not reported")


def test_list_says_folder_not_found_and_forgets_reports_of_gone_repositories(
    remote: targets.ServerTarget, tmp_path: Path
) -> None:
    root = targets.target_root(remote.target_id)
    gone = "sha256:" + "4" * 64
    record_repository_report(gone, os.fspath(tmp_path / "gone"), no_network=True, now=_AT)
    with targets.registry_lock():
        add_kept(root, remote.target_id, gone, os.fspath(tmp_path / "gone"), _STAMP, now=_AT)
    # The report names only a folder that no longer exists: it is forgotten (unknown, not held).
    result = _invoke("list", "lab")
    assert result.exit_code == 0, result.output
    assert repository_report(gone) is None
    assert f"    {tmp_path / 'gone'}  — folder not found" in result.stdout.splitlines()


def test_list_shows_damaged_records_without_refusing(
    remote: targets.ServerTarget, tmp_path: Path
) -> None:
    root = targets.target_root(remote.target_id)
    overrides_path(root).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    overrides_path(root).write_bytes(b"{oops\n")
    overrides_path(root).chmod(0o600)
    from finishup.client.everyday_policy import reports_path

    reports_path().parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    reports_path().write_bytes(b"{oops\n")
    reports_path().chmod(0o600)
    result = _invoke("list")
    assert result.exit_code == 0, result.output
    assert "cannot be read, so FinishUP holds no repository from it now" in result.stdout
    assert "is damaged or not private to you, so it receives none of them" in result.stdout
    assert "'finishup server repositories remove lab --all'" in result.stdout


def test_remove_by_folder_by_stale_path_and_all(
    remote: targets.ServerTarget, repository: str, tmp_path: Path
) -> None:
    root = targets.target_root(remote.target_id)
    key = _held(repository)
    moved = os.fspath(tmp_path / "moved")
    stale = "sha256:" + "5" * 64
    record_repository_report(stale, moved, no_network=True, now=_AT)
    with targets.registry_lock():
        add_override(root, remote.target_id, key, repository, _STAMP)
        add_kept(root, remote.target_id, stale, moved, _STAMP)

    by_folder = _invoke("remove")
    assert by_folder.exit_code == 0, by_folder.output
    assert "no longer receives this repository's work" in by_folder.stdout
    assert zero_network.OPEN_SESSIONS_LINE in by_folder.stdout
    absent = _invoke("remove")
    assert absent.exit_code == 0 and "nothing changed" in absent.stdout

    # A moved repository is removed by the path recorded for it, and its report forgotten.
    by_path = _invoke("remove", "lab", "--repository", moved)
    assert by_path.exit_code == 0, by_path.output
    assert "no longer kept on this computer by your choice" in by_path.stdout
    assert read_overrides(root, remote.target_id) == ()
    assert repository_report(stale) is None

    usage = _invoke("remove", "--all", "--repository", repository)
    assert usage.exit_code == 2 and usage.stderr.startswith("usage:")
    overrides_path(root).write_bytes(b"{oops\n")
    repaired = _invoke("remove", "--all")
    assert repaired.exit_code == 0, repaired.output
    assert "The damaged record was replaced by an empty one" in repaired.stdout
    assert read_overrides(root, remote.target_id) == ()


# --- server status, use and add -------------------------------------------------------------------


def _status_json() -> dict[str, JsonValue]:
    reset_selection_memo()
    result = _RUNNER.invoke(cli.app, ["server", "status", "--json"])
    assert result.exit_code == 0, result.output
    document = cast(dict[str, JsonValue], json.loads(result.stdout))
    validate_schema_instance("server-target-status", "1.0.0", cast(JsonValue, document))
    return document


@pytest.fixture
def quiet_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    from finishup.client.target_runtime import ProbeResult

    def probe(_record: object, _root: object) -> ProbeResult:
        return ProbeResult("not_running", None, None, None, None, None, None, None, 0)

    monkeypatch.setattr(server_cli, "_probe", probe)


def test_status_says_what_is_held_kept_and_sent_and_this_folders_state(
    remote: targets.ServerTarget, repository: str, quiet_probe: None
) -> None:
    root = targets.target_root(remote.target_id)
    key = _held(repository)
    document = _status_json()
    repositories = cast(
        dict[str, JsonValue], cast(dict[str, JsonValue], document["target"])["repositories"]
    )
    assert repositories == {
        "reports": "readable",
        "record": "readable",
        "held": [{"worktree": repository, "reported_at": _STAMP, "cause": "not_allowed"}],
        "kept": [],
        "allowed": [],
        "here": {
            "state": "held",
            "cause": "not_allowed",
            "policy_read": "last_reported",
            "reported_at": _STAMP,
        },
    }
    # Not a terminal here, so 'server status' answered in JSON: its owner lines are these.
    text = "\n".join(server_cli.status_lines(document))
    assert (
        "Repositories: 1 held, 0 kept on this computer, 0 sent anyway as you allowed "
        "('finishup server repositories list lab' shows them)."
    ) in text
    assert "This folder's repository: held — its privacy policy on this computer allows no " in text
    with targets.registry_lock():
        add_kept(root, remote.target_id, key, repository, _STAMP, now=_AT)
    here = cast(
        dict[str, JsonValue],
        cast(
            dict[str, JsonValue],
            cast(dict[str, JsonValue], _status_json()["target"])["repositories"],
        )["here"],
    )
    assert here["state"] == "kept" and here["cause"] is None
    forget_repository_reports([key])
    here = cast(
        dict[str, JsonValue],
        cast(
            dict[str, JsonValue],
            cast(dict[str, JsonValue], _status_json()["target"])["repositories"],
        )["here"],
    )
    assert here == {
        "state": "not_reported",
        "cause": None,
        "policy_read": None,
        "reported_at": None,
    }


def test_status_of_a_server_on_this_computer_has_no_repositories(
    home: Path, repository: str, quiet_probe: None
) -> None:
    target = cast(dict[str, JsonValue], _status_json()["target"])
    assert target["repositories"] is None


def test_server_use_says_this_repository_is_held(
    home: Path,
    repository: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = _remote(select=False)
    _held(repository)
    monkeypatch.setattr(server_cli, "_authorize_remote", lambda *_args, **_kwargs: None)
    reset_selection_memo()
    result = _RUNNER.invoke(cli.app, ["server", "use", "lab"])
    assert result.exit_code == 0, result.output
    assert (
        "This repository's privacy policy on this computer allows no network use, so FinishUP "
        "holds its work for lab: nothing from it is sent."
    ) in result.stdout
    del record


def test_server_use_counts_the_held_repositories_elsewhere(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    _remote(select=False)
    for number in range(2):
        folder = tmp_path / f"r{number}"
        folder.mkdir()
        record_repository_report(f"sha256:{number:064x}", os.fspath(folder), no_network=True)
    monkeypatch.setattr(server_cli, "_authorize_remote", lambda *_args, **_kwargs: None)
    reset_selection_memo()
    result = _RUNNER.invoke(cli.app, ["server", "use", "lab"])
    assert result.exit_code == 0, result.output
    assert (
        "2 repositories whose privacy policy on this computer allows no network use are held "
        "for lab; 'finishup server repositories list lab' shows them."
    ) in result.stdout
