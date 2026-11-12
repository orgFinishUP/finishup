"""``/server`` lists server targets, shows status, and switches as ``finishup server use`` does.

ADR-051: the header names a selected target by kind and id only; the everyday server leaves the
header exactly as before. The remote kinds are closed in this release: ``/server`` offers to add
only a server on this computer, and a remote record (one another build wrote) is shown as not
available and refused with ``remote_kind_unavailable`` when chosen, the selection unchanged.
``add`` and ``remove`` belong on the command line, so ``/server`` prints those commands.
Server-host commands refuse a remote target.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

from builders.tui_runtime import REMOTE_USE_REFUSED, FakeRuntime
from finishup.cli.command_scope import ServerHostRequired
from finishup.tui.app import FinishUpTui
from finishup.tui.commands import command_named
from finishup.tui.models import ServerRow, ServerSwitch
from finishup.tui.render import render_session_header
from finishup.tui.runtime import RuntimeError_
from finishup.tui.symbols import Level
from finishup.tui.widgets.views import BaseView, SelectionView

pytestmark = pytest.mark.anyio

_ROWS = (
    ServerRow("local", "local", None, None, True),
    ServerRow("work", "local", "t_1a2b3c4d", None, False),
    # An HTTPS server: the closed example (the tests that use it close HTTPS in process).
    ServerRow("lab", "https", "t_9f8e7d6c", "https://lab.example", False),
)


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
        self.header_refreshes = 0

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
            self.header_refreshes += 1

        self.app.say = say  # pyright: ignore[reportAttributeAccessIssue]
        self.app.ask = ask  # pyright: ignore[reportAttributeAccessIssue]
        self.app.hand_over_terminal = hand_over  # pyright: ignore[reportAttributeAccessIssue]
        self.app._refresh_header = refresh_header  # pyright: ignore[reportAttributeAccessIssue,reportPrivateUsage]

    @property
    def titles(self) -> list[str]:
        return [title for _level, title, _body in self.said]


async def test_switching_to_a_named_local_server_needs_no_terminal_handoff() -> None:
    runtime = FakeRuntime(servers=_ROWS)
    harness = _Harness(runtime, ["use:work"])

    await harness.app.command_server()

    assert runtime.server_uses == ["work"]
    assert harness.handed_over == 0
    assert harness.header_refreshes == 1
    assert runtime.server_indicator() == "local t_1a2b3c4d"
    assert "Using the server work" in harness.titles
    selection = harness.views[0]
    assert isinstance(selection, SelectionView)


async def test_a_remote_server_is_shown_as_not_available_and_refused_when_chosen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A closed kind (HTTPS, closed in this process: every kind is open from layer 5): "Use lab"
    asks for no confirmation and hands nothing over; the refusal is reported with its reason and
    the selection is unchanged."""

    monkeypatch.setattr("finishup.client.authorization.OPEN_REMOTE_KINDS", frozenset({"ssh"}))

    runtime = FakeRuntime(servers=_ROWS)
    harness = _Harness(runtime, ["use:lab"])

    await harness.app._dispatch("server")  # pyright: ignore[reportPrivateUsage]

    selection = harness.views[0]
    assert isinstance(selection, SelectionView)
    offered = {
        option.key: option.description
        for option in selection._all_options  # pyright: ignore[reportPrivateUsage]
    }
    assert offered["use:lab"] == "not available in this release"
    assert offered["use:work"] == "local"
    assert len(harness.views) == 1
    assert harness.handed_over == 0
    assert harness.header_refreshes == 0
    assert runtime.server_indicator() is None
    level, title, body = harness.said[-1]
    assert (level, title) == (Level.BLOCKED, REMOTE_USE_REFUSED)
    assert body[0] == "Reason: remote_kind_unavailable"


_LEFT = (
    "Closed this computer's connection to the server t_9f8e7d6c (ssh): it no longer answers "
    "that server's requests for your files.",
)


async def test_switching_away_from_a_remote_server_says_its_connection_closed() -> None:
    """ADR-051 decision 8: ``/server`` "Use local" is the way out, and it stops the traffic."""

    rows = (
        ServerRow("local", "local", None, None, False),
        ServerRow("lab", "ssh", "t_9f8e7d6c", "ssh://owner@lab.example:22", True),
    )
    runtime = FakeRuntime(servers=rows, server_selected="ssh t_9f8e7d6c", server_left_lines=_LEFT)
    harness = _Harness(runtime, ["use:local"])

    await harness.app.command_server()

    assert runtime.server_uses == ["local"]
    level, title, body = harness.said[-1]
    assert (level, title) == (Level.VERIFIED, "Using this computer's everyday server")
    assert body[0] == _LEFT[0]
    assert "Restart open agent sessions: a running" in body[1]


async def test_a_left_connection_that_did_not_close_is_not_shown_as_done() -> None:
    rows = (
        ServerRow("local", "local", None, None, False),
        ServerRow("lab", "ssh", "t_9f8e7d6c", "ssh://owner@lab.example:22", True),
    )
    still = ("The connection to the server t_9f8e7d6c (ssh) did not close in time, ...",)
    runtime = FakeRuntime(
        servers=rows,
        server_selected="ssh t_9f8e7d6c",
        server_left_lines=still,
        server_left_open=True,
    )
    harness = _Harness(runtime, ["use:local"])

    await harness.app.command_server()

    verified = [entry for entry in harness.said if entry[0] is Level.VERIFIED]
    assert len(verified) == 1 and still[0] not in verified[0][2]
    assert harness.said[-1] == (
        Level.UNPROVEN,
        "The connection to the server you left did not close",
        still,
    )


async def test_remove_prints_the_cli_command_and_no_remote_only_change_is_offered() -> None:
    """``login`` and ``folders`` act only on servers elsewhere, closed in this release: ``/server``
    offers neither (the commands are hidden from ``finishup server --help`` too)."""

    runtime = FakeRuntime(servers=_ROWS)
    harness = _Harness(runtime, ["remove"])

    await harness.app.command_server()

    level, title, body = harness.said[-1]
    assert (level, title) == (Level.OPTIONAL, "Run this in your shell")
    assert body == ("    finishup server remove NAME",)
    assert runtime.server_uses == []
    selection = harness.views[0]
    assert isinstance(selection, SelectionView)
    keys = [option.key for option in selection._all_options]  # pyright: ignore[reportPrivateUsage]
    assert keys == ["use:work", "use:lab", "status", "add", "remove"]


@pytest.mark.parametrize("official", [False, True])
async def test_adding_offers_only_a_server_on_this_computer(
    monkeypatch: pytest.MonkeyPatch, official: bool
) -> None:
    """The remote kinds are closed in this release: the add flow offers "On this computer" and
    nothing else, even while a reviewed official endpoint exists, and asks no outside-read
    question; the printed command is the named local one."""

    from finishup.client import server_folders

    if official:
        monkeypatch.setattr(
            server_folders,
            "OFFICIAL_ENDPOINT_ORIGINS",
            (server_folders.OfficialOrigin("fu.example"),),
        )
    runtime = FakeRuntime(servers=_ROWS)
    harness = _Harness(runtime, ["add", "add:local"])

    await harness.app.command_server()

    where = harness.views[1]
    assert isinstance(where, SelectionView)
    keys = [option.key for option in where._all_options]  # pyright: ignore[reportPrivateUsage]
    assert keys == ["add:local"]
    level, title, body = harness.said[-1]
    assert (level, title) == (Level.OPTIONAL, "Run this in your shell")
    assert body[0] == "    finishup server add NAME --local"
    assert not any("ssh://" in line or "https://" in line or "--port" in line for line in body)
    assert not any("--outside-reads" in line for line in body)
    assert len(harness.views) == 2  # no outside-read question
    assert runtime.server_uses == []


async def test_going_back_from_the_add_flow_adds_nothing() -> None:
    runtime = FakeRuntime(servers=_ROWS)
    harness = _Harness(runtime, ["add", None])

    await harness.app.command_server()

    assert harness.said[-1][1] == "No server was added."
    assert not any(title == "Run this in your shell" for title in harness.titles)


async def test_status_shows_the_probe_lines() -> None:
    runtime = FakeRuntime(servers=_ROWS)
    harness = _Harness(runtime, ["status"])

    await harness.app.command_server()

    assert harness.said[-1][1] == "Server status"


async def test_a_refusal_is_reported_with_its_reason() -> None:
    runtime = FakeRuntime(
        servers=_ROWS,
        server_error=RuntimeError_("selection_overridden", "the selection is not used here"),
    )
    harness = _Harness(runtime, [])

    await harness.app._dispatch("server")  # pyright: ignore[reportPrivateUsage]

    assert any("selection is not used here" in title for title in harness.titles)


async def test_server_host_commands_refuse_a_remote_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(command: str) -> None:
        if command in {"/privacy", "/provider", "/service"}:
            raise ServerHostRequired("t_9f8e7d6c", "ssh")

    monkeypatch.setattr("finishup.cli.command_scope.require_server_host", refuse)
    runtime = FakeRuntime(servers=_ROWS)
    harness = _Harness(runtime, [])

    await harness.app._dispatch("service")  # pyright: ignore[reportPrivateUsage]

    level, title, body = harness.said[-1]
    assert level is Level.BLOCKED
    assert title == "/service runs on the FinishUP server host"
    assert "requires_server_host" in body[0]
    assert "t_9f8e7d6c" in body[0]
    assert "lab" not in body[0].replace("t_9f8e7d6c", "")


def test_the_header_is_unchanged_without_a_selected_target() -> None:
    plain = render_session_header(
        version="1.2.3",
        project_root="/srv/p",
        harness_state="connected",
        privacy_summary="local only",
        width=72,
    )
    with_none = render_session_header(
        version="1.2.3",
        project_root="/srv/p",
        harness_state="connected",
        privacy_summary="local only",
        width=72,
        server=None,
    )
    selected = render_session_header(
        version="1.2.3",
        project_root="/srv/p",
        harness_state="connected",
        privacy_summary="local only",
        width=72,
        server="ssh t_9f8e7d6c",
    )
    assert plain == with_none
    assert len(selected) == len(plain) + 1
    assert selected[-1].split() == ["server:", "ssh", "t_9f8e7d6c", "/server", "to", "change"]


def test_server_is_a_slash_command() -> None:
    command = command_named("/server")
    assert command is not None and command.name == "server"


async def test_the_real_runtime_lists_switches_and_names_the_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from builders.server_targets import ambient_home
    from finishup.client import targets
    from finishup.config.paths import reset_selection_memo
    from finishup.tui.runtime import FinishUpRuntime

    with ambient_home(monkeypatch) as home:
        with targets.registry_lock():
            record, _root = targets.new_local_target("work")
        runtime = FinishUpRuntime(cwd=home)
        assert runtime.server_indicator() is None

        rows, lines = await runtime.server_rows()
        assert [(row.name, row.selected) for row in rows] == [("local", True), ("work", False)]
        assert any(record.target_id in line for line in lines)

        assert await runtime.use_server("work") == ServerSwitch(f"local {record.target_id}")
        reset_selection_memo()
        assert runtime.server_indicator() == f"local {record.target_id}"

        assert await runtime.use_server("local") == ServerSwitch("everyday")
        reset_selection_memo()
        assert runtime.server_indicator() is None

        with pytest.raises(RuntimeError_) as raised:
            await runtime.use_server("nowhere")
        assert raised.value.reason == "target_unknown"
        assert "nowhere" not in raised.value.message


async def test_the_real_runtime_refuses_a_remote_record_and_leaves_one_quietly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A remote record another build wrote and selected: ``/server`` "Use lab" runs ``finishup
    server use lab``, refused with ``remote_kind_unavailable`` before anything is asked, the
    selection unchanged; "Use local" is the way back, and with no runtime for that kind this
    client ran nothing for it, so the switch says nothing of a connection it never had."""

    from builders.server_targets import ambient_home
    from finishup.client import targets
    from finishup.config.paths import reset_selection_memo
    from finishup.tui.runtime import FinishUpRuntime

    def no_console(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("a remote record is refused before any prompt")

    monkeypatch.setattr("finishup.cli.trusted_console.TrustedForegroundConsole", no_console)
    with ambient_home(monkeypatch) as home:
        # Every remote kind is open from layer 5: HTTPS is closed in this process as the example,
        # with no runtime for it.
        monkeypatch.setattr("finishup.client.authorization.OPEN_REMOTE_KINDS", frozenset({"ssh"}))
        from finishup.client import target_runtime

        loaders = dict(target_runtime._RUNTIME_LOADERS)  # pyright: ignore[reportPrivateUsage]
        loaders.pop("https", None)
        monkeypatch.setattr(target_runtime, "_RUNTIME_LOADERS", loaders)
        with targets.registry_lock():
            # An HTTPS server: closed in this process.
            record, _root = targets.new_remote_target(
                "lab", "https", base_url="https://lab.example"
            )
            targets.write_selection(record)
        reset_selection_memo()
        runtime = FinishUpRuntime(cwd=home)

        with pytest.raises(RuntimeError_) as raised:
            await runtime.use_server("lab")
        assert raised.value.reason == "remote_kind_unavailable"
        assert raised.value.message == REMOTE_USE_REFUSED
        assert "lab" not in raised.value.message
        assert targets.read_selected_target_id() == record.target_id

        rows, lines = await runtime.server_rows()
        assert [(row.name, row.remote) for row in rows] == [("local", False), ("lab", True)]
        assert any(line.endswith("(not available in this release)") for line in lines)

        switch = await runtime.use_server("local")

        assert switch == ServerSwitch("everyday")
        assert targets.read_selected_target_id() is None


async def test_the_real_runtime_status_shows_what_a_remote_server_may_read_outside(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """ADR-051 decision 5: ``/server`` status shows the outside-read mode, where it came from,
    and the folders listed for that server, as ``finishup server status`` does."""

    from builders.server_targets import ambient_home
    from finishup.cli import server as server_cli
    from finishup.client import targets
    from finishup.client.server_folders import add_folder, set_mode
    from finishup.client.target_runtime import ProbeResult
    from finishup.tui.runtime import FinishUpRuntime

    def unreachable(_record: object, _root: object) -> ProbeResult:
        return ProbeResult("unavailable", reason="remote_unreachable")

    monkeypatch.setattr(server_cli, "_probe", unreachable)
    with ambient_home(monkeypatch) as home:
        with targets.registry_lock():
            record, root = targets.new_remote_target(
                "devbox", "ssh", host="devbox.example", port=22
            )
        shared = (tmp_path / "shared").resolve()
        shared.mkdir()
        with targets.registry_lock():
            add_folder(root, record.target_id, str(shared))
        runtime = FinishUpRuntime(cwd=home)
        lines = await runtime.server_status_lines("devbox")
        # Not selected, so what chose the server in use is not said of it (RE-5).
        assert lines[0] == f"Server: devbox ({record.target_id}, ssh); not the server in use"
        assert (await runtime.server_status_lines("local"))[0].endswith("; chosen by: ambient")
        # No mode chosen: listed, and how to choose, as 'finishup server status' says.
        assert (
            "Outside your projects: reads only folders you list (mode listed, not chosen yet)"
        ) in lines
        assert any("'finishup server folders mode devbox local'" in line for line in lines)
        with targets.registry_lock():
            set_mode(root, record.target_id, "local")
        lines = await runtime.server_status_lines("devbox")
        assert (
            "Outside your projects: reads what FinishUP on this computer would read (mode local, "
            "set by you)"
        ) in lines
        assert f"  {shared}" in lines
        with targets.registry_lock():
            set_mode(root, record.target_id, "listed")
        lines = await runtime.server_status_lines("devbox")
        assert (
            "Outside your projects: reads only folders you list (mode listed, set by you)" in lines
        )
        at = lines.index("Folders it may read outside your projects:")
        assert lines[at + 1] == f"  {shared}"
        # A damaged record: say so, with the one repair, where to run it, and its full name.
        from finishup.client.server_folders import folders_path

        folders_path(root).write_text("{damaged\n")
        lines = await runtime.server_status_lines("devbox")
        assert (
            "Outside your projects: reads only folders you list (mode listed, because its record "
            "cannot be read)"
        ) in lines
        assert any(
            "Repair it on this computer with 'finishup server folders remove devbox --all'" in line
            for line in lines
        )


@pytest.mark.parametrize("answer", ["typed", "interrupted"])
async def test_the_typed_confirmation_of_a_remote_server_is_read_on_the_loop_thread(
    monkeypatch: pytest.MonkeyPatch, answer: str
) -> None:
    """SRV-6, brought back with the consent flow of a kind a later layer opens (ADR-052):
    ``/server`` "Use NAME" runs the switch in a worker thread (the policy read runs its own event
    loop, and the profile is fetched there), but the disclosure and the typed confirmation run on
    the loop thread with Python's default Ctrl-C handler, so an interrupt cancels it as
    ``authorization_declined`` and the interface keeps running."""

    import signal
    import threading

    from builders.server_profiles import fetched
    from builders.server_targets import ambient_home, open_remote_kinds
    from finishup.cli import server as server_cli
    from finishup.client import server_profile, targets
    from finishup.config.paths import reset_selection_memo
    from finishup.tui.runtime import FinishUpRuntime

    seen: dict[str, object] = {}

    def policy_read() -> bool:
        seen["policy_on_main"] = threading.current_thread() is threading.main_thread()
        return False

    class Source:
        def fetch(self, record: Any) -> Any:  # noqa: ANN401
            seen["fetch_on_main"] = threading.current_thread() is threading.main_thread()
            return fetched(record)

    def confirm(_name: str, _kind: str, lines: tuple[str, ...], **_question: object) -> None:
        seen["confirm_on_main"] = threading.current_thread() is threading.main_thread()
        seen["default_handler"] = signal.getsignal(signal.SIGINT) is signal.default_int_handler
        seen["lines"] = lines
        if answer == "interrupted":
            raise KeyboardInterrupt

    def loop_handler(_signum: int, _frame: object) -> None:
        raise AssertionError("the loop's own handler never answers the prompt")

    monkeypatch.setattr(server_cli, "_zero_network_in_force", policy_read)
    monkeypatch.setattr(server_cli, "_confirm_on_trusted_console", confirm)
    previous = signal.signal(signal.SIGINT, loop_handler)  # what an event loop runner installs
    try:
        with ambient_home(monkeypatch) as home:
            open_remote_kinds(monkeypatch, "ssh", consent=False)
            monkeypatch.setitem(server_profile.PROFILE_SOURCES, "ssh", Source)
            with targets.registry_lock():
                record, _root = targets.new_remote_target(
                    "lab", "ssh", user="owner", host="lab.example", port=22
                )
            reset_selection_memo()
            runtime = FinishUpRuntime(cwd=home)
            if answer == "typed":
                switch = await runtime.use_server("lab")
                assert switch.indicator == f"ssh {record.target_id}"
                assert targets.read_selected_target_id() == record.target_id
                stored = targets.read_target(targets.target_root(record.target_id))
                assert stored is not None and stored.consent is not None
            else:
                with pytest.raises(RuntimeError_) as raised:
                    await runtime.use_server("lab")
                assert raised.value.reason == "authorization_declined"
                assert targets.read_selected_target_id() is None
            assert signal.getsignal(signal.SIGINT) is loop_handler
    finally:
        signal.signal(signal.SIGINT, previous)
    assert seen["policy_on_main"] is False and seen["fetch_on_main"] is False
    assert seen["confirm_on_main"] is True and seen["default_handler"] is True
    assert any("Level of use" in line for line in seen["lines"])  # type: ignore[union-attr]
