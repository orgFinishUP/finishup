"""``finishup server repositories``: a repository whose policy here allows no network use (ADR-051).

Maintainer decision of 2026-11-07, round 4. While a server elsewhere is selected, such a
repository is held from it until the owner decides. ``add`` sends it anyway, after a disclosure on
the trusted console and the typed target name; ``keep`` keeps it on this computer without asking
again, needs neither and may be run by an agent; ``remove`` undoes either, and ``list`` and
``status`` show them. Refusals are a closed reason and fixed text, never a path or a name.

In this release no server elsewhere can be connected to (ADR-052, the owner's answer O4): the
group is hidden, ``add`` refuses ``remote_kind_unavailable`` before the console, and ``keep``,
``list`` and ``remove`` work. The ``add`` tests open the kinds in process (``opened``) to exercise
what a later release reaches.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner, Result

import finishup.cli.zero_network_selection as zero_network
from builders.server_targets import ambient_home, open_remote_kinds
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
    remove_override,
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
        # Every remote kind is open from layer 5: HTTPS stays closed in this process as the
        # closed kind's example; the 'opened' cases open it again.
        monkeypatch.setattr("finishup.client.authorization.OPEN_REMOTE_KINDS", frozenset({"ssh"}))
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
def opened(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every remote kind open, in process (after ``home`` closed HTTPS as the closed example)."""

    del home
    open_remote_kinds(monkeypatch, "ssh", "https", "local_port")


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


def _answers(state: str) -> Callable[[str], str]:
    """This computer's FinishUP, answering ``state`` for every repository it is asked about."""

    def reader(_worktree: str) -> str:
        return state

    return reader


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
    """Named on its own, as 'server folders' is: this client's record, never sent anywhere."""

    from finishup.cli.command_scope import COMMAND_SCOPES, command_scope

    assert COMMAND_SCOPES["server repositories"] == "client_only"
    assert command_scope("server repositories keep") == "client_only"


# --- add ------------------------------------------------------------------------------------------


def test_adding_needs_the_trusted_console(
    opened: None, remote: targets.ServerTarget, repository: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _held(repository)
    _no_trusted_console(monkeypatch)
    result = _invoke("add")
    assert result.exit_code == 2
    assert result.stderr.startswith("trusted_console_required:")
    _clean(result.stderr, repository, "lab")
    assert read_overrides(targets.target_root(remote.target_id), remote.target_id) == ()


def test_a_wrong_name_declines_and_records_nothing(
    opened: None, remote: targets.ServerTarget, repository: str, monkeypatch: pytest.MonkeyPatch
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
    opened: None, home: Path, repository: str, confirmed: list[tuple[str, str, str]], kind: str
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
    opened: None,
    remote: targets.ServerTarget,
    repository: str,
    confirmed: list[tuple[str, str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = _held(repository)
    root = targets.target_root(remote.target_id)
    with targets.registry_lock():
        add_override(root, remote.target_id, key, repository, "2026-11-01T00:00:00.000Z")
    monkeypatch.setattr(zero_network, "_repository_reader", _answers("no_network"))
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
    opened: None,
    remote: targets.ServerTarget,
    repository: str,
    confirmed: list[tuple[str, str, str]],
    monkeypatch: pytest.MonkeyPatch,
    setup: str,
    line: str,
) -> None:
    root = targets.target_root(remote.target_id)
    if setup == "never_set_up":
        monkeypatch.setattr(zero_network, "_repository_reader", _answers("no_policy"))
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
    opened: None, home: Path, repository: str, tmp_path: Path, confirmed: list[tuple[str, str, str]]
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
    opened: None,
    remote: targets.ServerTarget,
    repository: str,
    confirmed: list[tuple[str, str, str]],
) -> None:
    _held(repository)
    record_reported_policy(zero_network=True, now=_AT)
    result = _invoke("add")
    assert result.exit_code == 2
    assert result.stderr.startswith("zero_network_remote_selected:")
    assert confirmed == []


def test_a_full_or_damaged_record_is_refused_before_the_name(
    opened: None,
    remote: targets.ServerTarget,
    repository: str,
    confirmed: list[tuple[str, str, str]],
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


@pytest.mark.parametrize("kinds", ["closed", "opened"])
def test_keep_replaces_an_allow_and_says_open_connections_close(
    remote: targets.ServerTarget, repository: str, monkeypatch: pytest.MonkeyPatch, kinds: str
) -> None:
    if kinds == "opened":
        open_remote_kinds(monkeypatch, "ssh", "https", "local_port")
    key = _held(repository)
    root = targets.target_root(remote.target_id)
    with targets.registry_lock():
        add_override(root, remote.target_id, key, repository, _STAMP)
    result = _invoke("keep", "lab")
    assert result.exit_code == 0, result.output
    if kinds == "opened":
        assert "'finishup server repositories add lab'" in result.stdout
    else:
        # 'add' cannot act while no remote kind is open: it is never offered as the way on.
        assert "repositories add" not in result.stdout
        assert "Sending it anyway arrives in a later release" in result.stdout
        assert "'finishup server repositories remove lab' asks again" in result.stdout
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


def test_list_never_says_a_choice_without_a_report_allows_network_use(
    remote: targets.ServerTarget, tmp_path: Path
) -> None:
    """A choice whose report was forgotten (or whose record cannot be read) is ``not_reported``:
    its own state in the list, never "its policy here allows network use", which is unknown."""

    root = targets.target_root(remote.target_id)
    for name in ("open", "unknown"):
        (tmp_path / name).mkdir()
    opened = "sha256:" + "3" * 64
    unknown = "sha256:" + "8" * 64
    record_repository_report(opened, os.fspath(tmp_path / "open"), no_network=False, now=_AT)
    record_repository_report(unknown, os.fspath(tmp_path / "unknown"), no_network=True, now=_AT)
    with targets.registry_lock():
        add_override(root, remote.target_id, opened, os.fspath(tmp_path / "open"), _STAMP)
        add_kept(root, remote.target_id, unknown, os.fspath(tmp_path / "unknown"), _STAMP)
    forget_repository_reports([unknown])
    result = _invoke("list", "lab")
    assert result.exit_code == 0, result.output
    lines = result.stdout.splitlines()
    needed = lines.index("  Chosen earlier, not needed now (its policy here allows network use):")
    assert lines[needed + 1] == f"    {tmp_path / 'open'}"
    unreported = lines.index(
        "  Chosen earlier, its policy here not reported now (this computer's FinishUP has no "
        "report of it, so it is not held until one is made):"
    )
    assert lines[unreported + 1] == f"    {tmp_path / 'unknown'}"
    assert f"    {tmp_path / 'unknown'}" not in lines[needed + 1 : unreported]
    # The status document already said it apart; the list now agrees with it.
    status = _RUNNER.invoke(cli.app, ["server", "status", "lab", "--json"])
    kept = cast(
        dict[str, JsonValue],
        cast(dict[str, JsonValue], json.loads(status.stdout)["target"])["repositories"],
    )["kept"]
    assert cast(list[dict[str, JsonValue]], kept)[0]["state"] == "not_reported"
    # Only a choice with no report at all: nothing else is listed as not reported.
    forget_repository_reports([opened])
    again = _invoke("list", "lab").stdout.splitlines()
    assert "  Chosen earlier, not needed now (its policy here allows network use):" not in again
    assert f"    {tmp_path / 'open'}" in again


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


def test_list_says_when_a_report_did_not_fit_and_that_no_hold_was_dropped(
    remote: targets.ServerTarget, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import finishup.client.everyday_policy as everyday_policy

    held = "sha256:" + "6" * 64
    assert record_repository_report(held, os.fspath(tmp_path), no_network=True, now=_AT)
    # Room for the record as it is, not for one more entry.
    bound = len(everyday_policy.reports_path().read_bytes()) + 16
    monkeypatch.setattr(everyday_policy, "_MAX_REPORTS_BYTES", bound)
    late = datetime(2026, 11, 8, 10, 0, tzinfo=UTC)
    newcomer = "sha256:" + "7" * 64
    assert not record_repository_report(newcomer, os.fspath(tmp_path), no_network=True, now=late)
    result = _invoke("list")
    assert result.exit_code == 0, result.output
    assert (
        "This computer's record of what its FinishUP reported about repositories is full: a "
        "report at 2026-11-08T10:00:00.000Z did not fit, so that repository is not held until a "
        "report of it fits. The record was kept as it was, and no repository it holds was dropped."
    ) in result.stdout
    assert repository_report(held) is not None and repository_report(newcomer) is None
    assert "cannot be read" not in result.stdout


def test_list_with_no_server_elsewhere_asks_and_records_nothing(
    home: Path, repository: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """O3: before the first server elsewhere is recorded, no surface asks this computer's
    FinishUP about a repository or keeps what it says, so there is no history from before then.
    The everyday service here is up and would answer."""

    import finishup.client.everyday_repository as everyday_repository
    from finishup.client.everyday_policy import marker_path, reports_path

    asked: list[str] = []

    class _Service:
        async def privacy_get_effective(self, request: object) -> object:
            asked.append("effective")
            return {"policy": {"network_egress_permitted": True}}

        async def privacy_get_setup(self, request: object) -> object:
            asked.append("setup")
            return {
                "schema_version": "2.0.0",
                "grant_state": "granted",
                "composed_policy": {"network_egress_permitted": False},
            }

        async def close(self) -> None:
            return None

    async def connect(*_args: object, **_kwargs: object) -> object:
        asked.append("connect")
        return _Service()

    # The real read (the suite replaces it with one that reaches nothing), against a stand-in
    # for this computer's running service.
    monkeypatch.setattr(zero_network, "_repository_reader", zero_network._read_repository)  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(everyday_repository, "_connect", connect)
    monkeypatch.setattr(zero_network, "_everyday_installation_exists", lambda: True)
    monkeypatch.setattr(
        "finishup.cli.provider_status.machine_scope_request", lambda: {"scope": "machine"}
    )
    result = _invoke("list")
    assert result.exit_code == 0, result.output
    assert "No server on another machine, a port or the web was added." in result.stdout
    assert asked == []
    assert not reports_path().exists() and not marker_path().exists()
    # The shared read itself is dormant too, whichever surface asks.
    assert zero_network.everyday_repository_state(repository) == "unreadable"
    assert asked == [] and not reports_path().exists()
    # Once one is recorded, the same list asks and records.
    _remote(select=False)
    result = _invoke("list")
    assert result.exit_code == 0, result.output
    assert asked == ["connect", "effective", "setup"]
    assert repository_report(_key(repository)) is not None


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


@pytest.mark.parametrize("kinds", ["closed", "opened"])
def test_no_surface_offers_add_while_it_cannot_act(
    remote: targets.ServerTarget,
    repository: str,
    quiet_probe: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kinds: str,
) -> None:
    """While the remote kinds are closed, 'server repositories add' refuses
    ``remote_kind_unavailable`` (O4): status, list and keep show what works (keep, remove) and
    say that sending anyway arrives later. Once a kind opens, they offer it again."""

    if kinds == "opened":
        open_remote_kinds(monkeypatch, "ssh", "https", "local_port")
    root = targets.target_root(remote.target_id)
    key = _held(repository)
    (tmp_path / "kept").mkdir()
    kept = "sha256:" + "1" * 64
    record_repository_report(kept, os.fspath(tmp_path / "kept"), no_network=True, now=_AT)
    with targets.registry_lock():
        add_kept(root, remote.target_id, kept, os.fspath(tmp_path / "kept"), _STAMP, now=_AT)
    texts: list[str] = []
    held_status = "\n".join(server_cli.status_lines(_status_json()))
    texts.append(held_status)
    listed = _invoke("list", "lab")
    assert listed.exit_code == 0, listed.output
    texts.append(listed.stdout)
    with targets.registry_lock():
        add_override(root, remote.target_id, key, repository, "2026-11-01T00:00:00.000Z", now=_AT)
    texts.append("\n".join(server_cli.status_lines(_status_json())))  # held again
    with targets.registry_lock():
        remove_override(root, remote.target_id, key=key, worktree=repository)
        add_kept(root, remote.target_id, key, repository, _STAMP, now=_AT)
    texts.append("\n".join(server_cli.status_lines(_status_json())))  # kept
    everything = "\n".join(texts)
    if kinds == "opened":
        assert "'finishup server repositories add lab'" in held_status
        assert "To send a held repository anyway" in listed.stdout
        return
    assert "repositories add" not in everything
    assert "'finishup server repositories keep lab'" in held_status
    assert "sending it anyway arrives in a later release, with servers elsewhere" in held_status
    assert "Sending a held repository anyway arrives in a later release" in listed.stdout
    assert "'finishup server repositories remove lab --repository FOLDER'" in listed.stdout
    assert "'finishup server repositories remove lab' here undoes that choice." in texts[-1]
    assert "held again" in texts[2] and "'finishup server repositories keep lab'" in texts[2]


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
    home: Path, repository: str, quiet_probe: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A server on this computer gains only ``repositories: null`` and asks nothing more."""

    asked: list[str] = []

    def reader(worktree: str) -> str:
        asked.append(worktree)
        return "no_network"

    monkeypatch.setattr(zero_network, "_repository_reader", reader)
    _held(repository)
    target = cast(dict[str, JsonValue], _status_json()["target"])
    assert target["repositories"] is None
    assert asked == []


def test_server_use_of_a_server_elsewhere_refuses_and_says_nothing_of_the_hold(
    home: Path, repository: str
) -> None:
    """``server use`` refuses a remote kind in this release (layer 1), so the line after a switch
    that names a held repository (round 5) waits for the layer that opens the kinds (FR-5)."""

    _remote(select=False)
    _held(repository)
    reset_selection_memo()
    result = _RUNNER.invoke(cli.app, ["server", "use", "lab"])
    assert result.exit_code != 0
    assert "remote_kind_unavailable" in result.output
    assert "holds its work" not in result.output


def test_the_group_is_shown_and_add_refuses_before_the_console_for_a_closed_kind(
    home: Path,
    remote: targets.ServerTarget,
    repository: str,
    confirmed: list[tuple[str, str, str]],
) -> None:
    """The owner's answer O4, since SSH servers open (layer 4, FR-5): the group is shown; for a
    kind still closed (HTTPS here) 'add' refuses before anything is asked or recorded, and 'keep',
    'list' and 'remove' stay usable as the way back."""

    plain = re.sub(
        r"\x1b\[[0-9;?]*[A-Za-z]", "", _RUNNER.invoke(cli.app, ["server", "--help"]).output
    )
    assert "repositories" in plain
    assert remote.kind == "https"
    key = _held(repository)
    added = _invoke("add")
    assert added.exit_code != 0
    assert "remote_kind_unavailable" in added.output
    assert "nothing was recorded" in added.output
    assert confirmed == []
    assert read_overrides(targets.target_root(remote.target_id), remote.target_id) == ()
    kept = _invoke("keep")
    assert kept.exit_code == 0, kept.output
    (choice,) = read_overrides(targets.target_root(remote.target_id), remote.target_id)
    assert (choice.key, choice.choice) == (key, "keep")
    assert _invoke("list").exit_code == 0
    removed = _invoke("remove")
    assert removed.exit_code == 0, removed.output
    assert read_overrides(targets.target_root(remote.target_id), remote.target_id) == ()
