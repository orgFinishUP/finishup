"""The CLI converts only the invoked command's path to click, and that tree is Typer's own.

``finishup.cli.app.main`` dispatches through ``lazy_command`` instead of
``typer.main.get_command``. These tests hold the lazily built tree to the eagerly converted one
for the whole registry (names, order, options, help, hidden flags, rendered help and usage
errors), and count conversions so one invocation never converts the other commands again.
"""

from __future__ import annotations

import inspect
import sys
from collections.abc import Callable, Iterator
from typing import Any, cast

import pytest
import typer
import typer.main

import finishup.cli.lazy_command as lazy_module
from finishup import __version__
from finishup.cli import app as app_module
from finishup.cli.app import app
from finishup.cli.command_scope import command_scope, iter_command_paths
from finishup.cli.lazy_command import LazyCommands, LazyTyper, lazy_command


def _walk(command: Any, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], Any]]:
    yield path, command
    for name in getattr(command, "commands", {}):
        yield from _walk(command.commands[name], (*path, name))


def _plain(value: object, depth: int = 0) -> object:
    """A comparable rendering of a click parameter: plain values, types, and callables by name."""

    if isinstance(value, (str, int, float, bool, type(None), type)):
        return value
    if isinstance(value, (list, tuple)):
        return tuple(_plain(item, depth + 1) for item in value)  # type: ignore[union-attr]
    if isinstance(value, dict):
        return tuple((key, _plain(item, depth + 1)) for key, item in value.items())  # type: ignore[union-attr]
    if callable(value) and not hasattr(value, "__dict__") or inspect.isroutine(value):
        return (
            "callable",
            getattr(value, "__module__", None),
            getattr(value, "__qualname__", None),
        )
    if depth < 4 and hasattr(value, "__dict__"):
        return (type(value), _plain(vars(value), depth + 1))
    return (type(value), repr(value))


def _node_shape(command: Any) -> tuple[object, ...]:
    context = typer.Context(command)
    params = [_plain(param) for param in command.params]
    shape: list[object] = [
        type(cast(object, command)),
        command.name,
        command.hidden,
        command.help,
        command.short_help,
        command.epilog,
        command.deprecated,
        command.no_args_is_help,
        getattr(command, "invoke_without_command", None),
        getattr(command, "subcommand_metavar", None),
        getattr(command, "rich_help_panel", None),
        getattr(command, "rich_markup_mode", None),
        getattr(command, "suggest_commands", None),
        command.context_settings,
        command.options_metavar,
        command.add_help_option,
        command.get_usage(context),
        list(getattr(command, "commands", {})),
        command.list_commands(context) if hasattr(command, "commands") else None,
        params,
    ]
    return tuple(shape)


def _run(command: Any, args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[object, ...]:
    try:
        command.main(args=args, prog_name="finishup")
        code: object = None
    except SystemExit as exit_:
        code = exit_.code
    captured = capsys.readouterr()
    return code, captured.out, captured.err


@pytest.fixture
def counted(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[Any]]:
    """Record every command and group conversion the lazy tree performs."""

    calls: dict[str, list[Any]] = {"command": [], "group": [], "options": []}

    def wrap(kind: str, real: Callable[..., Any]) -> Callable[..., Any]:
        def counting(info: Any, **kwargs: Any) -> Any:
            calls[kind].append(info)
            calls["options"].append((kind, kwargs))
            return real(info, **kwargs)

        return counting

    monkeypatch.setattr(
        lazy_module, "get_command_from_info", wrap("command", lazy_module.get_command_from_info)
    )
    monkeypatch.setattr(
        lazy_module, "get_group_from_info", wrap("group", lazy_module.get_group_from_info)
    )
    return calls


def test_the_lazy_tree_is_the_eager_tree_for_every_command() -> None:
    eager = list(_walk(typer.main.get_command(app)))
    lazy = list(_walk(lazy_command(app)))

    assert [path for path, _ in lazy] == [path for path, _ in eager]
    assert len(eager) > 250
    hidden = [path for path, command in eager if command.hidden]
    assert hidden, "the registry has hidden commands; they must stay listed and hidden"
    for (path, lazy_node), (_, eager_node) in zip(lazy, eager, strict=True):
        assert _node_shape(lazy_node) == _node_shape(eager_node), path


def test_the_lazy_tree_converts_the_registered_entries(counted: dict[str, list[Any]]) -> None:
    """Each leaf is converted from the registry's own entry, server-host guard included."""

    list(_walk(lazy_command(app)))
    registry = list(iter_command_paths(app))

    assert sorted(map(id, counted["command"])) == sorted(id(info) for _, info in registry)
    # Every conversion gets the app's own settings, as ``typer.main.get_command`` passes them.
    settings = {
        "pretty_exceptions_short": app.pretty_exceptions_short,
        "rich_markup_mode": app.rich_markup_mode,
    }
    group_settings = {**settings, "suggest_commands": app.suggest_commands}
    for kind, options in counted["options"]:
        assert options == (settings if kind == "command" else group_settings), kind
    for path, info in registry:
        if command_scope(path) == "server_host":
            assert getattr(info.callback, "__finishup_server_host_guard__", False), path


def test_help_and_usage_errors_render_byte_for_byte(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("COLUMNS", "100")
    eager_root = typer.main.get_command(app)
    lazy_root = lazy_command(app)
    cases: list[list[str]] = [
        ["--help"],
        ["-h"],
        ["nosuch"],
        ["stauts"],
        ["--nosuch"],
        ["status", "--nosuch"],
        ["service", "statu"],
        ["integrate", "skill", "nosuch"],
        ["recommend", "accept"],
        ["consent", "prepare"],
        ["--version", "status"],
        ["--home-project", "/", "status"],
    ]
    cases.extend([*path, "--help"] for path, _ in _walk(eager_root) if path)
    for args in cases:
        assert _run(lazy_root, args, capsys) == _run(eager_root, args, capsys), args


def test_one_invocation_converts_only_its_own_path(
    counted: dict[str, list[Any]], capsys: pytest.CaptureFixture[str]
) -> None:
    root = lazy_command(app)
    code, out, _ = _run(root, ["service", "restart", "--help"], capsys)

    assert code == 0 and "restart" in str(out)
    assert [info.callback.__name__ for info in counted["command"]] == ["service_restart"]
    # The root and the ``service`` group, each without converting its children.
    assert len(counted["group"]) == 2
    assert isinstance(root.commands, LazyCommands)
    assert root.commands.converted() == {"service"}
    assert root.commands["service"].commands.converted() == {"restart"}


def test_a_full_walk_converts_each_command_once(counted: dict[str, list[Any]]) -> None:
    root = lazy_command(app)
    first = list(_walk(root))
    again = list(_walk(root))

    leaves = [path for path, command in first if not hasattr(command, "commands")]
    assert len(counted["command"]) == len(leaves)
    assert all(a is b for (_, a), (_, b) in zip(first, again, strict=True))


def test_main_dispatches_without_the_eager_conversion(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    counted: dict[str, list[Any]],
) -> None:
    def refuse(_: object) -> None:
        raise AssertionError("main converted the whole command tree")

    monkeypatch.setattr(typer.main, "get_command", refuse)
    monkeypatch.setattr(sys, "argv", ["finishup", "--version"])
    with pytest.raises(SystemExit) as exit_:
        app_module.main()

    assert isinstance(app, LazyTyper)
    assert exit_.value.code == 0
    assert capsys.readouterr().out == f"{__version__}\n"
    assert counted["command"] == []
    assert len(counted["group"]) == 1


def _boom() -> None:
    raise RuntimeError("boom")


def _quiet() -> None:
    """Does nothing."""


def _flagged(flag: bool = False) -> None:
    """Takes a flag."""


def test_an_escaping_error_carries_what_typer_call_gives_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lazy = LazyTyper(pretty_exceptions_enable=False, add_completion=False)
    toy = typer.Typer(pretty_exceptions_enable=False, add_completion=False)
    for registry in (lazy, toy):
        registry.command("boom")(_boom)
        registry.command("other")(_quiet)

    def attributes(run: Callable[[], object]) -> tuple[object, ...]:
        monkeypatch.setattr(sys, "excepthook", sys.__excepthook__)
        with pytest.raises(RuntimeError) as raised:
            run()
        config: object = getattr(raised.value, "__typer_developer_exception__")
        return (sys.excepthook is typer.main.except_hook, type(config), vars(config))

    assert attributes(lambda: lazy(args=["boom"])) == attributes(lambda: toy(args=["boom"]))


def test_registry_shapes_typer_leaves_to_itself_match_too() -> None:
    """Repeated names, a nameless sub-Typer, and a single-command app convert as Typer does."""

    toy = typer.Typer(add_completion=False)
    toy.command("first")(_quiet)
    toy.command("second")(_quiet)
    toy.command("first")(_flagged)  # the last writer keeps the first position
    named = typer.Typer(help="Named.")
    named.command("hidden-leaf", hidden=True)(_quiet)
    toy.add_typer(named, name="named")

    lazy_named = [_node_shape(node) for _, node in _walk(lazy_command(toy))]
    eager_named = [_node_shape(node) for _, node in _walk(typer.main.get_command(toy))]
    assert lazy_named == eager_named
    assert list(lazy_command(toy).commands) == ["first", "second", "named"]

    merged = typer.Typer()
    merged.command("merged-leaf")(_flagged)
    toy.add_typer(merged)
    lazy_merged = [_node_shape(node) for _, node in _walk(lazy_command(toy))]
    eager_merged = [_node_shape(node) for _, node in _walk(typer.main.get_command(toy))]
    assert lazy_merged == eager_merged
    assert "merged-leaf" in lazy_command(toy).commands

    single = typer.Typer(add_completion=False)
    single.command()(_quiet)
    assert _node_shape(lazy_command(single)) == _node_shape(typer.main.get_command(single))
