"""Every visible command says what it is for in ``--help``.

Filling the descriptions changed help text only: the command tree, the order commands are
registered in, and every option stay as they were. These tests keep blanks from returning and pin
the registration order of the families whose help now comes from a table.
"""

from __future__ import annotations

import re
from typing import Any, cast

import typer
from typer.testing import CliRunner

from finishup.cli.app import app


def _visible_commands() -> list[tuple[str, Any]]:
    found: list[tuple[str, Any]] = []

    def walk(command: Any, path: tuple[str, ...]) -> None:
        if command.hidden:
            return
        if path:
            found.append((" ".join(path), command))
        subcommands = cast(dict[str, Any], getattr(command, "commands", None) or {})
        for name, sub in subcommands.items():
            walk(sub, (*path, name))

    walk(typer.main.get_command(app), ())
    return found


def _subcommand_names(*path: str) -> list[str]:
    command: Any = typer.main.get_command(app)
    for word in path:
        command = command.commands[word]
    return list(command.commands)


def test_every_visible_command_and_group_has_help() -> None:
    commands = _visible_commands()
    assert len(commands) > 200
    blank = [path for path, command in commands if not (command.help or "").strip()]
    assert blank == []


def test_every_deadline_option_explains_itself() -> None:
    seen = 0
    for path, command in _visible_commands():
        for param in command.params:
            if "--deadline-ms" in getattr(param, "opts", ()):
                seen += 1
                assert (getattr(param, "help", None) or "").strip(), path
    assert seen >= 20


def test_six_operations_show_their_description_and_workflow_flags() -> None:
    runner = CliRunner()
    for command in ("start", "publish-work", "check", "respond", "status", "receipt"):
        result = runner.invoke(app, [command, "--help"])
        assert result.exit_code == 0, command
        plain = " ".join(re.sub(r"\x1b\[[0-9;]*m", "", result.stdout).split())
        root: Any = typer.main.get_command(app)
        description = cast(str | None, root.commands[command].help)
        assert description
        assert " ".join(description.split()) in plain, command
        flags = plain.replace(" ", "")
        for flag in ("--json", "--input", "--request", "--deadline-ms"):
            assert flag in flags, (command, flag)


def test_table_driven_families_keep_their_registration_order() -> None:
    assert _subcommand_names("integrate", "skill") == ["preview", "install", "status", "remove"]
    assert _subcommand_names("integrate", "mcp") == [
        "preview",
        "preview-remove",
        "install",
        "status",
        "remove",
    ]
    assert _subcommand_names("integrate", "project-mcp") == [
        "preview",
        "preview-remove",
        "install",
        "status",
        "remove",
    ]
    assert _subcommand_names("integrate", "admission") == ["status", "preview", "grant", "revoke"]
