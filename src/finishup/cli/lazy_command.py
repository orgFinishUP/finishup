"""Convert the Typer command registry to click one invoked subtree at a time.

``typer.main.get_command`` converts every registered command up front: it reads each callback's
signature, resolves its string annotations and builds its click parameters, for every registered
command (about 210 commands in 44 groups), on every full-CLI process, though one invocation
dispatches to one command. ``lazy_command`` builds
the same click tree with the same Typer functions (``get_group_from_info`` for each group's own
options and help, ``get_command_from_info`` for each command), but leaves every child as a pending
entry in an ordered mapping that converts it on first access and keeps the result. Names and their
order come from the registry exactly as the eager conversion inserts them, so listing, lookup,
help, suggestions and usage errors are unchanged, and a walker that reads a group's ``commands``
still sees every command.
"""

from __future__ import annotations

import copy
import sys
from collections.abc import Callable, Iterator, MutableMapping
from typing import Any, Final, cast

import typer
import typer.main
from typer.core import MarkupMode, TyperGroup
from typer.main import get_command_from_info, get_command_name, get_group_from_info
from typer.models import CommandInfo, DeveloperExceptionConfig, TyperInfo

# Typer vendors click privately (``typer._click``) and exports no public command type, so a click
# command is typed by what Typer's own conversion functions return.
type _Command = Any

__all__ = ["LazyCommands", "LazyTyper", "lazy_command"]

# The attribute ``typer.Typer.__call__`` sets on an escaping exception for its excepthook.
_DEVELOPER_EXCEPTION_ATTRIBUTE: Final = cast(
    str, getattr(typer.main, "_typer_developer_exception_attr_name")
)


class _Pending:
    """A child not converted yet: how to build it."""

    __slots__ = ("build",)

    def __init__(self, build: Callable[[], _Command]) -> None:
        self.build = build


class LazyCommands(MutableMapping[str, _Command]):
    """An ordered name -> click command mapping whose entries convert on first read."""

    __slots__ = ("_entries",)

    def __init__(self, entries: dict[str, _Command | _Pending]) -> None:
        self._entries = entries

    def __getitem__(self, name: str) -> _Command:
        entry = self._entries[name]
        if isinstance(entry, _Pending):
            entry = entry.build()
            self._entries[name] = entry
        return entry

    def get(self, name: str, default: Any = None) -> Any:  # noqa: ANN401 - Mapping.get shape
        # Explicit, so a KeyError raised while converting is never read as an absent name.
        if name not in self._entries:
            return default
        return self[name]

    def __contains__(self, name: object) -> bool:
        return name in self._entries

    def __setitem__(self, name: str, command: _Command) -> None:
        self._entries[name] = command

    def __delitem__(self, name: str) -> None:
        del self._entries[name]

    def __iter__(self) -> Iterator[str]:
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def converted(self) -> frozenset[str]:
        """The names converted so far (for tests and diagnostics)."""

        return frozenset(
            name for name, entry in self._entries.items() if not isinstance(entry, _Pending)
        )


def _group_name(group_info: TyperInfo) -> str:
    # The name ``get_group_from_info`` gives the group (``solved_info.name or ""``).
    solved = typer.main.solve_typer_info_defaults(group_info)
    return solved.name or ""


def _lazy_group(
    group_info: TyperInfo,
    *,
    pretty_exceptions_short: bool,
    suggest_commands: bool,
    rich_markup_mode: MarkupMode,
) -> TyperGroup:
    instance = group_info.typer_instance
    assert instance is not None, "A Typer instance is needed to generate a Click Group"
    if any(not _group_name(sub) for sub in instance.registered_groups):
        # A nameless sub-Typer merges its commands into this group; leave it to Typer.
        return get_group_from_info(
            group_info,
            pretty_exceptions_short=pretty_exceptions_short,
            suggest_commands=suggest_commands,
            rich_markup_mode=rich_markup_mode,
        )
    # The group itself (its callback options, help, settings) from Typer, without its children.
    shell = copy.copy(instance)
    shell.registered_commands = []
    shell.registered_groups = []
    shell_info = copy.copy(group_info)
    shell_info.typer_instance = shell
    group = get_group_from_info(
        shell_info,
        pretty_exceptions_short=pretty_exceptions_short,
        suggest_commands=suggest_commands,
        rich_markup_mode=rich_markup_mode,
    )
    # Insertion order and last-writer-wins on a repeated name, as ``get_group_from_info`` fills
    # its ``commands`` dict: commands first, then groups.
    entries: dict[str, _Command | _Pending] = {}
    for command_info in instance.registered_commands:
        if command_info.callback is None:
            # Typer refuses this (``A command must have a callback function``); let it say so.
            command = get_command_from_info(
                command_info,
                pretty_exceptions_short=pretty_exceptions_short,
                rich_markup_mode=rich_markup_mode,
            )
            if command.name:
                entries[command.name] = command
            continue
        name = command_info.name or get_command_name(command_info.callback.__name__)
        if name:
            entries[name] = _Pending(
                _command_builder(command_info, pretty_exceptions_short, rich_markup_mode)
            )
    for sub_group_info in instance.registered_groups:
        entries[_group_name(sub_group_info)] = _Pending(
            _group_builder(
                sub_group_info, pretty_exceptions_short, suggest_commands, rich_markup_mode
            )
        )
    group.commands = LazyCommands(entries)
    return group


def _command_builder(
    command_info: CommandInfo, pretty_exceptions_short: bool, rich_markup_mode: MarkupMode
) -> Callable[[], _Command]:
    def build() -> _Command:
        return get_command_from_info(
            command_info,
            pretty_exceptions_short=pretty_exceptions_short,
            rich_markup_mode=rich_markup_mode,
        )

    return build


def _group_builder(
    group_info: TyperInfo,
    pretty_exceptions_short: bool,
    suggest_commands: bool,
    rich_markup_mode: MarkupMode,
) -> Callable[[], _Command]:
    def build() -> _Command:
        return _lazy_group(
            group_info,
            pretty_exceptions_short=pretty_exceptions_short,
            suggest_commands=suggest_commands,
            rich_markup_mode=rich_markup_mode,
        )

    return build


def lazy_command(app: typer.Typer) -> _Command:
    """The click command ``typer.main.get_command(app)`` returns, converting children on demand.

    Only a group without Typer's completion options is built lazily; any other shape is handed to
    Typer unchanged.
    """

    is_group = bool(
        app.registered_callback
        or app.info.callback
        or app.registered_groups
        or len(app.registered_commands) > 1
    )
    if not is_group or getattr(app, "_add_completion", True):
        return typer.main.get_command(app)
    return _lazy_group(
        TyperInfo(app),
        pretty_exceptions_short=app.pretty_exceptions_short,
        suggest_commands=app.suggest_commands,
        rich_markup_mode=app.rich_markup_mode,
    )


class LazyTyper(typer.Typer):
    """A ``typer.Typer`` whose call converts only the invoked command's path to click.

    ``__call__`` is ``typer.Typer.__call__`` with ``lazy_command`` in place of
    ``typer.main.get_command``; registration, ``typer.main.get_command`` and the test runner see an
    ordinary Typer.
    """

    def __call__(self, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401 - click's result
        if sys.excepthook != typer.main.except_hook:
            sys.excepthook = typer.main.except_hook
        try:
            return lazy_command(self)(*args, **kwargs)
        except Exception as error:
            setattr(
                error,
                _DEVELOPER_EXCEPTION_ATTRIBUTE,
                DeveloperExceptionConfig(
                    pretty_exceptions_enable=self.pretty_exceptions_enable,
                    pretty_exceptions_show_locals=self.pretty_exceptions_show_locals,
                    pretty_exceptions_short=self.pretty_exceptions_short,
                ),
            )
            raise
