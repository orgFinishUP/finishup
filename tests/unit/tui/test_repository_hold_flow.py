"""``/server`` shows a repository held from, or kept here for, a server elsewhere (ADR-051 d. 8).

Maintainer decision of 2026-11-07, round 4. While a server on another machine, a port or the web
is selected, a repository whose privacy policy on this computer allows no network use is held
from it until the owner decides. ``/server`` says so in the shape it uses for the zero-network
item: a title and the lines, then the way out. "Send this repository's work to this server
anyway" hands the terminal to the very confirmation ``finishup server repositories add`` asks
(the same core, read on the interface's event loop thread). The header adds " · this repository
held" while the records still hold it, and drops it when they do not or the selection changes.

In this release no remote kind is open (ADR-052, the owner's answer O4): the item is never shown,
"repo-send" refuses ``remote_kind_unavailable`` before the confirmation, and ``/server`` offers no
"repositories" option. The real-runtime tests open the kinds in process (``opened``).
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable, Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest

import finishup.cli.zero_network_selection as zero_network
from builders.server_targets import ambient_home, open_remote_kinds, remote_runtime
from builders.tui_runtime import FakeRuntime
from finishup.client import targets
from finishup.client.everyday_policy import record_repository_report, repository_report
from finishup.client.everyday_repository import repository_key_for
from finishup.client.repository_hold import add_kept, read_overrides
from finishup.config.paths import reset_selection_memo
from finishup.tui.app import FinishUpTui
from finishup.tui.models import ServerRow
from finishup.tui.runtime import RuntimeError_
from finishup.tui.symbols import Level
from finishup.tui.widgets.views import ApprovalView, BaseView, SelectionView

pytestmark = pytest.mark.anyio

_ROWS = (
    ServerRow("local", "local", None, None, False),
    ServerRow("lab", "ssh", "t_9f8e7d6c", "ssh://owner@lab.example:22", True),
)
_HELD_LINES = (
    "This repository's privacy policy on this computer allows no network use, so FinishUP "
    "sends nothing from it to ssh t_9f8e7d6c.",
    "Its starts, checks and observations wait here until you decide.",
)
_TITLE = "This repository's work is held from the selected server"
_DECLINED = ("Nothing changed; this repository's work stays on this computer.",)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Harness:
    def __init__(self, runtime: FakeRuntime, answers: Sequence[str | None]) -> None:
        self.runtime = runtime
        self.app = FinishUpTui(runtime)  # pyright: ignore[reportArgumentType]
        self.said: list[tuple[Level, str, tuple[str, ...]]] = []
        self.views: list[BaseView] = []
        self.answers = list(answers)
        self.handed_over = 0

        def say(
            level: Level, title: str, body: Sequence[str] = (), *, details: Sequence[str] = ()
        ) -> None:
            del details
            self.said.append((level, title, tuple(body)))

        async def ask(view: BaseView) -> str | None:
            self.views.append(view)
            return self.answers.pop(0)

        async def hand_over(operation: Callable[[], Awaitable[Any]]) -> Any:
            self.handed_over += 1
            return await operation()

        async def refresh_header() -> None:
            return None

        self.app.say = say  # pyright: ignore[reportAttributeAccessIssue]
        self.app.ask = ask  # pyright: ignore[reportAttributeAccessIssue]
        self.app.hand_over_terminal = hand_over  # pyright: ignore[reportAttributeAccessIssue]
        self.app._refresh_header = refresh_header  # pyright: ignore[reportAttributeAccessIssue,reportPrivateUsage]

    def options(self) -> list[str]:
        selection = self.views[0]
        assert isinstance(selection, SelectionView)
        return [option.key for option in selection.options]


async def test_server_shows_the_held_item_and_offers_to_send_it() -> None:
    runtime = FakeRuntime(
        servers=_ROWS, server_selected="ssh t_9f8e7d6c", repository_hold=_HELD_LINES
    )
    harness = _Harness(runtime, [None])

    await harness.app.command_server()

    assert (Level.UNPROVEN, _TITLE, _HELD_LINES) in harness.said
    options = harness.options()
    assert "repo-send" in options
    # The 'server repositories' group is hidden in this release (O4): no option prints it.
    assert "repositories" not in options
    # Showing the item sends, allows and switches nothing.
    assert runtime.repository_allows == 0 and runtime.server_uses == []
    assert runtime.repository_hold_reads == 1

    # While the zero-network item is shown, that refusal governs: no hold is read or offered.
    runtime.zero_network = ("This computer's privacy policy forbids all network use.",)
    governed = _Harness(runtime, [None])
    await governed.app.command_server()
    assert runtime.repository_hold_reads == 1
    assert "repo-send" not in governed.options()


async def test_without_a_held_repository_server_offers_no_send() -> None:
    runtime = FakeRuntime(servers=_ROWS, server_selected="ssh t_9f8e7d6c")
    harness = _Harness(runtime, [None])

    await harness.app.command_server()

    assert _TITLE not in [title for _level, title, _body in harness.said]
    assert "repo-send" not in harness.options()
    assert runtime.repository_hold_reads == 1


async def test_send_hands_the_terminal_to_the_add_confirmation() -> None:
    runtime = FakeRuntime(
        servers=_ROWS, server_selected="ssh t_9f8e7d6c", repository_hold=_HELD_LINES
    )
    harness = _Harness(runtime, ["repo-send", "approve"])

    await harness.app.command_server()

    assert isinstance(harness.views[1], ApprovalView)
    assert harness.handed_over == 1 and runtime.repository_allows == 1
    assert harness.said[-1] == (
        Level.VERIFIED,
        "Sending this repository's work to t_9f8e7d6c",
        ("Your agent can repeat its last FinishUP request now.",),
    )


@pytest.mark.parametrize("answer", ["decline", None])
async def test_not_now_changes_nothing(answer: str | None) -> None:
    runtime = FakeRuntime(
        servers=_ROWS, server_selected="ssh t_9f8e7d6c", repository_hold=_HELD_LINES
    )
    harness = _Harness(runtime, ["repo-send", answer])

    await harness.app.command_server()

    assert harness.handed_over == 0 and runtime.repository_allows == 0
    assert harness.said[-1] == (Level.OPTIONAL, "Nothing changed", _DECLINED)


async def test_a_wrong_name_typed_at_the_confirmation_changes_nothing() -> None:
    runtime = FakeRuntime(
        servers=_ROWS,
        server_selected="ssh t_9f8e7d6c",
        repository_hold=_HELD_LINES,
        repository_allow_error=RuntimeError_("authorization_declined", "declined"),
    )
    harness = _Harness(runtime, ["repo-send", "approve"])

    await harness.app.command_server()

    assert harness.handed_over == 1
    assert harness.said[-1] == (Level.OPTIONAL, "Nothing changed", _DECLINED)


async def test_a_terminal_that_cannot_hand_over_prints_the_command() -> None:
    from textual.app import SuspendNotSupported

    runtime = FakeRuntime(
        servers=_ROWS, server_selected="ssh t_9f8e7d6c", repository_hold=_HELD_LINES
    )
    harness = _Harness(runtime, ["repo-send", "approve"])

    async def refuse(_operation: Callable[[], Awaitable[Any]]) -> Any:
        raise SuspendNotSupported

    harness.app.hand_over_terminal = refuse  # pyright: ignore[reportAttributeAccessIssue]

    await harness.app.command_server()

    level, title, body = harness.said[-1]
    assert (level, title) == (Level.UNPROVEN, "This terminal cannot hand over for the confirmation")
    assert body == ("Run this from your shell instead:", "", "    finishup server repositories add")
    assert runtime.repository_allows == 0


# --- the real runtime: the item, the header and the shared core ---------------------------------


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        monkeypatch.setattr(zero_network, "_selection_on_disk", zero_network.read_selection_on_disk)
        yield root


@pytest.fixture
def opened(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every remote kind open, in process: what a later release reaches."""

    open_remote_kinds(monkeypatch, "ssh", "https", "local_port")


@pytest.fixture
def project(tmp_path: Path) -> Path:
    folder = (tmp_path / "project").resolve()
    folder.mkdir()
    return folder


def _remote_selected(kind: str = "ssh") -> targets.ServerTarget:
    fields: dict[str, object] = {
        "ssh": {"user": "owner", "host": "lab.example", "port": 22},
        "https": {"base_url": "https://finishup.example"},
        "local_port": {"base_url": "https://127.0.0.1:9443"},
    }[kind]  # type: ignore[assignment]
    with targets.registry_lock():
        record, _root = targets.new_remote_target("privbox", kind, **fields)  # type: ignore[arg-type]
        targets.write_selection(record)
    reset_selection_memo()
    return record


def _answers(state: str) -> Callable[[str], str]:
    """This computer's FinishUP, answering ``state`` for any repository it is asked about."""

    def read(_worktree: str) -> str:
        return state

    return read


async def _held(project: Path) -> str:
    key = await repository_key_for(os.fspath(project))
    assert key is not None
    assert record_repository_report(key, os.fspath(project), no_network=True)
    return key


@pytest.mark.parametrize("kind", ["ssh", "https", "local_port"])
async def test_the_header_names_a_held_repository_until_it_no_longer_holds(
    home: Path, opened: None, project: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    from finishup.tui.runtime import FinishUpRuntime

    record = _remote_selected(kind)
    key = await _held(project)
    asked: list[str] = []

    def live(worktree: str) -> str:
        asked.append(worktree)
        return "no_network"

    monkeypatch.setattr(zero_network, "_repository_reader", live)
    runtime = FinishUpRuntime(cwd=project)
    assert runtime.server_indicator() == f"{kind} {record.target_id}"

    lines = await runtime.refresh_repository_hold_item()

    # The live read asked this computer's FinishUP about this repository first.
    assert asked == [os.fspath(project)]
    assert lines[0] == (
        "This repository's privacy policy on this computer allows no network use, so FinishUP "
        f"sends nothing from it to {kind} {record.target_id}."
    )
    assert runtime.repository_hold_heading() == _TITLE
    assert runtime.server_indicator() == f"{kind} {record.target_id} · this repository held"
    assert "privbox" not in " ".join(lines) and os.fspath(project) not in " ".join(lines)

    # Kept on this computer: the header says so, from the records alone.
    report = repository_report(key)
    assert report is not None and report.no_network_since is not None
    with targets.registry_lock():
        add_kept(
            targets.target_root(record.target_id),
            record.target_id,
            key,
            os.fspath(project),
            report.no_network_since,
        )
    # The cached held item no longer applies as held: the header drops it, from the records
    # alone, until /server reads it again.
    assert runtime.server_indicator() == f"{kind} {record.target_id}"
    await runtime.refresh_repository_hold_item()
    assert runtime.server_indicator() == f"{kind} {record.target_id} · this repository kept here"

    # The selection changes: the header drops it.
    with targets.registry_lock():
        targets.clear_selection()
    assert runtime.server_indicator() is None


async def test_send_runs_the_add_core_with_its_confirmation_on_the_loop_thread(
    home: Path, opened: None, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import threading

    from finishup.cli import server as server_cli
    from finishup.tui.runtime import FinishUpRuntime

    record = _remote_selected("https")
    key = await _held(project)
    monkeypatch.setattr(zero_network, "_repository_reader", _answers("no_network"))
    asked: list[tuple[str, str, bool]] = []
    loop_thread = threading.get_ident()

    def confirm(target: targets.ServerTarget, worktree: str, state: str) -> None:
        del state
        asked.append((target.target_id, worktree, threading.get_ident() == loop_thread))

    monkeypatch.setattr(server_cli, "_confirm_repository_on_trusted_console", confirm)
    runtime = FinishUpRuntime(cwd=project)
    await runtime.refresh_repository_hold_item()

    target_id, allowed = await runtime.allow_repository_here()

    assert (target_id, allowed) == (record.target_id, True)
    # The very disclosure and typed name of 'server repositories add', read on the loop thread.
    assert asked == [(record.target_id, os.fspath(project), True)]
    choices = read_overrides(targets.target_root(record.target_id), record.target_id)
    assert [(item.key, item.choice) for item in choices] == [(key, "send")]
    assert runtime.server_indicator() == f"https {record.target_id}"


async def test_a_declined_confirmation_records_nothing(
    home: Path, opened: None, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.cli import server as server_cli
    from finishup.tui.runtime import FinishUpRuntime

    record = _remote_selected("ssh")
    await _held(project)
    monkeypatch.setattr(zero_network, "_repository_reader", _answers("no_network"))

    def decline(*_args: object) -> None:
        raise server_cli.ServerCommandRefused("authorization_declined")

    monkeypatch.setattr(server_cli, "_confirm_repository_on_trusted_console", decline)
    runtime = FinishUpRuntime(cwd=project)

    with pytest.raises(RuntimeError_) as refused:
        await runtime.allow_repository_here()

    assert refused.value.reason == "authorization_declined"
    assert read_overrides(targets.target_root(record.target_id), record.target_id) == ()


async def test_server_status_reads_this_interfaces_repository(
    home: Path, opened: None, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.client.target_runtime import ProbeResult
    from finishup.tui.runtime import FinishUpRuntime

    remote_runtime(monkeypatch).probe_result = ProbeResult(
        "unavailable", reason="remote_unreachable"
    )
    monkeypatch.setattr(zero_network, "everyday_network_state", lambda: "network_permitted")
    monkeypatch.setattr(zero_network, "_repository_reader", _answers("unreadable"))
    _remote_selected("ssh")
    await _held(project)
    # The interface runs in its project; the process may be anywhere.
    monkeypatch.chdir(project.parent)
    runtime = FinishUpRuntime(cwd=project)

    lines = await runtime.server_status_lines()

    assert any(line.startswith("This folder's repository: held") for line in lines)


async def test_while_no_kind_is_open_nothing_is_shown_and_send_refuses_before_the_confirmation(
    home: Path, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The owner's answer O4: with every remote kind closed the item is never shown, and the
    shared core behind "repo-send" refuses before the confirmation and records nothing. (Every
    kind is open from layer 5: they are closed in this process.)"""

    monkeypatch.setattr("finishup.client.authorization.OPEN_REMOTE_KINDS", frozenset[str]())

    from finishup.cli import server as server_cli
    from finishup.tui.runtime import FinishUpRuntime

    record = _remote_selected("https")
    await _held(project)
    monkeypatch.setattr(zero_network, "_repository_reader", _answers("no_network"))
    asked: list[str] = []

    def confirm(*_args: object) -> None:
        asked.append("confirm")

    monkeypatch.setattr(server_cli, "_confirm_repository_on_trusted_console", confirm)
    runtime = FinishUpRuntime(cwd=project)
    assert await runtime.refresh_repository_hold_item() == ()
    assert runtime.server_indicator() == f"https {record.target_id}"

    with pytest.raises(RuntimeError_) as refused:
        await runtime.allow_repository_here()

    assert refused.value.reason == "remote_kind_unavailable"
    assert asked == []
    assert read_overrides(targets.target_root(record.target_id), record.target_id) == ()
