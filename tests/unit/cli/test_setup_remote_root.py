"""Setup refuses a remote root at its entry, before it looks, asks or writes anything (ADR-051).

This release reaches no server elsewhere: while the root this process uses is a server target on
another machine, the web or a port (a selection another build or a hand edit left, or an
isolation variable naming such a target's root), every connection is refused before anything is
sent with ``target_root_is_remote``, or ``zero_network_remote_selected`` /
``target_reauthorization_required`` (RE-1). Setup used to meet that refusal only when it probed
the service, after its questions and after registering agents. Every way into setup that can ask
or write (``setup run`` in every form, bare ``finishup`` without the terminal interface, the
menu's setup wizard) now names that phase and its directive first, on stderr with exit 20, and
looks for no agent, asks nothing and writes nothing. The terminal interface's first run does the
same (``tests/tui/test_first_run.py``).
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

import finishup.client.everyday_policy as everyday_policy
from builders.server_targets import ambient_home
from finishup.cli import app as cli
from finishup.cli import setup as setup_cli
from finishup.client import targets
from finishup.config.paths import ISOLATED_ROOT_ENV_NAMES, active_root, reset_selection_memo
from finishup.protocol.recovery import directive_for

_RUNNER = CliRunner()
_AT = datetime(2026, 11, 7, 9, 30, tzinfo=UTC)
_HEAD = (
    "the FinishUP server this process uses is refused before anything is sent, so setup stopped "
    "before looking for agents, asking anything, or changing any agent's configuration"
)


@dataclass(frozen=True, slots=True)
class _Refused:
    phase: str
    continuation: str
    # What the owner does about it: 'finishup server use local' when the selection names the
    # root; clearing the override when an isolation variable names it, which outranks the
    # selection ('finishup server use local' answers selection_overridden there).
    way_back: str = "Ask the owner to run 'finishup server use local'"


_OVERRIDE_WAY_BACK = "Ask the owner to unset it or use an unpinned launcher"


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        user_home = root / "home"
        user_home.mkdir(mode=0o700)
        monkeypatch.setenv("HOME", str(user_home))
        yield root


@pytest.fixture(params=["selection", "zero_network", "stale_disclosure", "isolation"])
def refused(
    home: Path, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> _Refused:
    """A remote root this process inherits: a selection another build left (authorized under the
    current disclosure, with this computer's last report of zero-network, or under an older
    disclosure), or an isolation variable naming a remote target's root."""

    with targets.registry_lock():
        record, root = targets.new_remote_target("lab", "https", base_url="https://lab.example")
        if request.param != "isolation":
            targets.write_selection(record)
    if request.param == "isolation":
        monkeypatch.setenv(ISOLATED_ROOT_ENV_NAMES[0], str(root))
    reset_selection_memo()
    assert active_root() == root
    if request.param == "zero_network":
        everyday_policy.record_reported_policy(zero_network=True, now=_AT)
        return _Refused("zero_network_remote_selected", "zero_network_local_server_required")
    if request.param == "stale_disclosure":
        # A later release shows a newer disclosure than the one the owner confirmed.
        monkeypatch.setattr(targets, "DISCLOSURE_VERSION", targets.DISCLOSURE_VERSION + 1)
        return _Refused("target_reauthorization_required", "server_reauthorization_required")
    if request.param == "isolation":
        return _Refused("target_root_is_remote", "remote_root_override_clear", _OVERRIDE_WAY_BACK)
    return _Refused("target_root_is_remote", "remote_target_no_local_service")


@pytest.fixture
def nothing_happens(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every discovery, question, registration and service step setup could take fails the test."""

    import finishup.adapters.integrations.host_discovery as host_discovery
    import finishup.cli.host_batch as host_batch
    import finishup.cli.host_connection as host_connection
    import finishup.service.client as service_client

    def never(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("setup refuses a remote root before this step")

    monkeypatch.setattr("typer.prompt", never)
    monkeypatch.setattr("typer.confirm", never)
    monkeypatch.setattr(host_discovery, "discover_hosts", never)
    monkeypatch.setattr(setup_cli, "discover_codex_binaries", never)
    monkeypatch.setattr(setup_cli, "_resolve_setup_project", never)
    monkeypatch.setattr(setup_cli, "_choose_review_mode", never)
    monkeypatch.setattr(setup_cli, "_register_step", never)
    monkeypatch.setattr(setup_cli, "_service_reachability", never)
    monkeypatch.setattr(setup_cli, "_write_setup_marker", never)
    monkeypatch.setattr(host_connection, "run_host_connection", never)
    monkeypatch.setattr(host_batch, "run_host_batch", never)
    monkeypatch.setattr(host_batch, "select_installations", never)
    monkeypatch.setattr(service_client, "connect_control", never)
    monkeypatch.setattr(service_client, "_spawn_service_process", never)
    # An interactive terminal: the run that would ask the most questions.
    monkeypatch.setattr(setup_cli, "_is_interactive_terminal", lambda: True)


def _tree(root: Path) -> set[tuple[str, int]]:
    """Every path beneath ``root`` with its size, to show that nothing was created or changed."""

    found: set[tuple[str, int]] = set()
    for folder, directories, files in os.walk(root):
        for name in (*directories, *files):
            path = Path(folder) / name
            found.add((str(path.relative_to(root)), path.lstat().st_size))
    return found


def _refusal(refused: _Refused) -> str:
    directive = directive_for(refused.continuation)
    assert directive is not None
    return (
        f"{refused.phase}: {_HEAD}\n"
        f"Continuation: {refused.continuation}\n"
        f"Next: {directive.directive}\n"
    )


@pytest.mark.parametrize(
    "arguments",
    [
        ("setup", "run"),
        ("setup", "run", "--non-interactive", "--json"),
        ("setup", "run", "--non-interactive", "--accept", "--json"),
        ("setup", "run", "--host", "claude"),
        ("setup", "run", "--host", "cursor", "--non-interactive", "--json"),
        ("setup", "run", "--host", "all"),
        ("setup", "run", "--host", "codex", "--host", "claude"),
    ],
    ids=lambda arguments: "-".join(arguments[2:]) or "interactive",
)
def test_setup_run_refuses_a_remote_root_before_it_looks_asks_or_writes(
    home: Path, refused: _Refused, nothing_happens: None, arguments: tuple[str, ...]
) -> None:
    before = _tree(home)

    result = _RUNNER.invoke(cli.app, list(arguments))

    assert result.exit_code == 20, result.output
    assert result.stdout == ""
    assert result.stderr.startswith(_refusal(refused))
    assert refused.way_back in result.stderr
    if "reauthorization" not in refused.phase:
        # An older disclosure of an SSH server is confirmed again by the owner, by its name, on
        # their own terminal (layer 4); every other refusal points to this computer's server.
        assert "server use NAME" not in result.stderr and "with its name" not in result.stderr
    assert "service run" not in result.stderr
    assert "lab.example" not in result.stderr
    assert _tree(home) == before
    assert not any((home / "home").iterdir())


def test_bare_finishup_without_the_terminal_interface_refuses_its_first_run(
    home: Path, refused: _Refused, nothing_happens: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_interface(*, first_run: bool) -> bool:
        assert first_run
        return False

    monkeypatch.setattr(cli, "_open_tui", no_interface)
    monkeypatch.setattr(setup_cli, "should_offer_first_run", lambda: True)
    before = _tree(home)

    result = _RUNNER.invoke(cli.app, [])

    assert result.exit_code == 20, result.output
    assert result.stderr.startswith(_refusal(refused))
    assert _tree(home) == before


def test_the_menu_setup_wizard_refuses_a_remote_root(
    home: Path,
    refused: _Refused,
    nothing_happens: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from finishup.cli import menu

    before = _tree(home)

    menu._run_wizard()  # pyright: ignore[reportPrivateUsage]

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith(_refusal(refused))
    assert _tree(home) == before


def test_the_terminal_interface_reads_the_same_refusal(home: Path, refused: _Refused) -> None:
    from finishup.tui.runtime import FinishUpRuntime

    assert FinishUpRuntime().remote_root_refusal() == refused.phase


@pytest.mark.anyio
@pytest.mark.parametrize("anyio_backend", ["asyncio"])
async def test_the_terminal_interface_first_run_asks_and_writes_nothing_live(
    home: Path, refused: _Refused, monkeypatch: pytest.MonkeyPatch, anyio_backend: str
) -> None:
    """The real interface refuses its first run before this computer's policy is read.

    That read asks the everyday service and records its answer beside the server registry, so a
    refusal after it would say "Nothing was changed" over a write. Here the read answers as a
    reachable service would (and records the answer); the refused first run never makes it.
    """

    from finishup.cli import zero_network_selection
    from finishup.tui.app import FinishUpTui
    from finishup.tui.runtime import FinishUpRuntime

    # The real selection read (the suite answers "no selection" unless a test puts it back).
    monkeypatch.setattr(
        zero_network_selection,
        "_selection_on_disk",
        zero_network_selection.read_selection_on_disk,
    )
    asked: list[str] = []

    def live_policy() -> str:
        asked.append("everyday_network_state")
        everyday_policy.record_reported_policy(zero_network=False, now=_AT)
        return "network_permitted"

    monkeypatch.setattr(zero_network_selection, "everyday_network_state", live_policy)
    project = home / "project"
    project.mkdir(mode=0o700)
    marker = everyday_policy.read_marker()
    before = _tree(home)

    app = FinishUpTui(FinishUpRuntime(cwd=project), first_run=True)
    async with app.run_test(size=(100, 34)) as pilot:
        await pilot.pause()
        shown = "\n".join("\n".join((event.title, *event.body)) for event in app.transcript.events)

    assert "Setup did not start" in shown
    directive = directive_for(refused.continuation)
    assert directive is not None
    assert directive.directive in shown
    assert refused.way_back in shown
    assert "Setup stopped. Nothing was changed." in shown
    assert "Welcome to FinishUP" not in shown
    assert asked == []
    assert everyday_policy.read_marker() == marker
    assert _tree(home) == before


def test_a_server_on_this_computer_is_never_refused(home: Path) -> None:
    """The everyday server and a named local one go on to setup's own steps, byte for byte."""

    assert setup_cli._remote_root_refused() is None  # pyright: ignore[reportPrivateUsage]
    with targets.registry_lock():
        record, _root = targets.new_local_target("work")
        targets.write_selection(record)
    reset_selection_memo()
    assert setup_cli._remote_root_refused() is None  # pyright: ignore[reportPrivateUsage]
