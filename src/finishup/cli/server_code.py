"""``finishup server code``: what a server keeps of your code, and how to make it keep less (L2).

Level L2 (ADR-054). The group acts on the selected server elsewhere and on the repository of a
folder (the current one by default). It is hidden while level L2 is unreleased
(``protocol.server_copy.L2_RELEASED``); its commands still answer, and those that reach the server
are refused there, since no server keeps copies yet.

* ``list`` asks the server what it keeps of this repository; ``forget`` deletes it there (and this
  computer's export folder for it) and prints exactly what the server deleted. Forget is the only
  way to remove what was already sent: stopping, holding or narrowing to L1 stops future sends.
* ``exclude add|remove|list`` keeps patterns out of this repository's copy. Adding only ever
  sends less, so any process may; removing sends more, so the owner confirms it on the trusted
  console.
* ``allow FILE`` sends one file the content scan held out, exactly as it is now (its bytes'
  digest is recorded; any other content is scanned again); confirmed on the trusted console.
* ``level L1`` keeps this repository at level L1 on that server; ``level default`` undoes it,
  confirmed on the trusted console.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import replace
from typing import TYPE_CHECKING, Annotated, Final

import typer

from finishup.cli.server import (
    _REPOSITORY_OPTION,  # pyright: ignore[reportPrivateUsage]
    ServerCommandRefused,
    _cli,  # pyright: ignore[reportPrivateUsage]
    _repository_target,  # pyright: ignore[reportPrivateUsage]
    repository_here,
    server_app,
)
from finishup.protocol.server_copy import L2_RELEASED

if TYPE_CHECKING:
    from finishup.client.code_copy_settings import RepositoryCodeSettings
    from finishup.client.targets import ServerTarget
    from finishup.protocol.canonical import JsonValue

__all__ = ["code_app"]

code_app = typer.Typer(
    help="What a server elsewhere keeps of your code (level L2), and how to make it keep less.",
    no_args_is_help=True,
)
exclude_app = typer.Typer(help="Keep files out of this repository's copy.", no_args_is_help=True)
code_app.add_typer(exclude_app, name="exclude")
server_app.add_typer(code_app, name="code", hidden=not L2_RELEASED)

_JSON_OPTION = Annotated[bool, typer.Option("--json", help="Print JSON.")]
_MAX_ALLOW_BYTES: Final = 1 << 30


def _selected() -> ServerTarget:
    return _repository_target(None)


async def _ask_server(worktree: str, action: str) -> dict[str, JsonValue]:
    from finishup.cli.app import build_service_client
    from finishup.ports.control import ControlClientKind, WorkspaceLocator

    client = await build_service_client(
        ControlClientKind.CLI, workspace_locator=WorkspaceLocator(worktree)
    )
    try:
        return await client.code_copy("forget" if action == "forget" else "status")
    finally:
        await client.close()


def _server_answer(worktree: str, action: str) -> dict[str, JsonValue]:
    from finishup.cli.app import run_async
    from finishup.ports.control import ControlError

    try:
        return run_async(lambda: _ask_server(worktree, action))
    except ControlError as error:
        if error.reason == "method_forbidden":
            raise ServerCommandRefused(
                "server_level_unavailable",
                message="that server keeps no copy of code (it does not offer level L2)",
            ) from None
        raise ServerCommandRefused(error.phase or error.reason) from None


@code_app.command("list")
@_cli
def server_code_list(
    repository: _REPOSITORY_OPTION = None, json_output: _JSON_OPTION = False
) -> None:
    """Show what the selected server keeps of this repository."""

    record = _selected()
    here = repository_here(repository)
    answer = _server_answer(here.worktree, "status")
    if json_output:
        import json

        typer.echo(json.dumps(answer, sort_keys=True))
        return
    copy = answer.get("copy")
    if not isinstance(copy, dict):
        typer.echo(f"{record.name} keeps no copy of this repository.")
        return
    retention = copy.get("retention")
    kept = "until you forget it"
    if isinstance(retention, dict):
        if retention.get("kind") == "days":
            kept = f"for {retention.get('days')} days after its last sync"
        elif retention.get("kind") == "task_close":
            kept = "until the tasks that read it are closed"
    typer.echo(
        f"{record.name} keeps a copy of this repository: {copy.get('snapshots')} snapshot(s), "
        f"{copy.get('stored_bytes')} bytes, last synced {copy.get('last_sync_at') or 'never'}, "
        f"kept {kept}."
    )


@code_app.command("forget")
@_cli
def server_code_forget(
    repository: _REPOSITORY_OPTION = None, json_output: _JSON_OPTION = False
) -> None:
    """Delete the selected server's copy of this repository, and say exactly what it deleted."""

    from finishup.client.code_sync import export_folder
    from finishup.client.targets import registry_lock

    record = _selected()
    here = repository_here(repository)
    answer = _server_answer(here.worktree, "forget")
    with registry_lock():
        # This computer's export folder for the repository goes too: what it sent is gone there.
        folder = export_folder(record.target_id, here.key)
        if folder.exists():
            import shutil

            shutil.rmtree(folder, ignore_errors=True)
    if json_output:
        import json

        typer.echo(json.dumps(answer, sort_keys=True))
        return
    forgot = answer.get("forgot")
    if not isinstance(forgot, dict) or not forgot.get("copies"):
        typer.echo(f"{record.name} kept no copy of this repository; nothing was deleted.")
    else:
        typer.echo(
            f"{record.name} deleted its copy of this repository: {forgot.get('snapshots')} "
            f"snapshot(s), {forgot.get('objects')} stored objects, {forgot.get('bytes')} bytes."
        )
    typer.echo(
        "Copies of that server's folder in backups its owner made are not managed by FinishUP "
        "and stay until they are removed there. Evidence already recorded in your tasks there "
        "(captured changes, review excerpts) is kept with the task."
    )


# --- the owner's per-repository choices (this computer only) ------------------------------------


def _settings(record: ServerTarget, key: str) -> RepositoryCodeSettings:
    from finishup.client.code_copy_settings import CodeCopySettingsError, settings_for
    from finishup.client.targets import target_root

    try:
        return settings_for(target_root(record.target_id), record.target_id, key)
    except CodeCopySettingsError as error:
        raise ServerCommandRefused(error.reason) from None


def _update(
    record: ServerTarget,
    key: str,
    change: object,
) -> RepositoryCodeSettings:
    from finishup.client.code_copy_settings import CodeCopySettingsError, update_settings
    from finishup.client.targets import registry_lock, target_root

    try:
        with registry_lock():
            return update_settings(target_root(record.target_id), record.target_id, key, change)  # type: ignore[arg-type]
    except CodeCopySettingsError as error:
        raise ServerCommandRefused(error.reason) from None


def _confirm(record: ServerTarget, lines: tuple[str, ...]) -> None:
    from finishup.cli.trusted_console import TrustedConsoleError, TrustedForegroundConsole

    try:
        with TrustedForegroundConsole() as console:
            for line in lines:
                console.write(line + "\n")
            console.read_choice(
                "Type the target name to confirm (anything else cancels): ",
                (record.name.encode("ascii"),),
            )
    except TrustedConsoleError as error:
        if error.reason == "trusted_console_required":
            raise ServerCommandRefused("trusted_console_required") from None
        raise ServerCommandRefused("authorization_declined") from None


@exclude_app.command("add")
@_cli
def server_code_exclude_add(pattern: str, repository: _REPOSITORY_OPTION = None) -> None:
    """Keep files matching PATTERN out of this repository's copy (sends less: no question)."""

    from finishup.domain.code_exclusions import valid_pattern

    if not valid_pattern(pattern):
        raise ServerCommandRefused("usage", message="that pattern cannot be recorded")
    record = _selected()
    here = repository_here(repository)
    _update(
        record,
        here.key,
        lambda s: replace(s, exclude=tuple(sorted({*s.exclude, pattern}))),
    )
    typer.echo(f"Files matching {pattern} are left out of this repository's copy on {record.name}.")


@exclude_app.command("remove")
@_cli
def server_code_exclude_remove(pattern: str, repository: _REPOSITORY_OPTION = None) -> None:
    """Stop leaving PATTERN out (sends more: you confirm it here)."""

    record = _selected()
    here = repository_here(repository)
    if pattern not in _settings(record, here.key).exclude:
        typer.echo(f"{pattern} is not on this repository's list for {record.name}.")
        return
    _confirm(
        record,
        (f"Files matching {pattern} will be sent to {record.name} in this repository's copy.",),
    )
    _update(
        record,
        here.key,
        lambda s: replace(s, exclude=tuple(item for item in s.exclude if item != pattern)),
    )
    typer.echo(f"{pattern} is no longer left out of this repository's copy on {record.name}.")


@exclude_app.command("list")
@_cli
def server_code_exclude_list(repository: _REPOSITORY_OPTION = None) -> None:
    """Show this repository's own list (the always-excluded names apply too)."""

    record = _selected()
    here = repository_here(repository)
    settings = _settings(record, here.key)
    if not settings.exclude:
        typer.echo("No patterns of your own; the always-excluded names still apply.")
    for pattern in settings.exclude:
        typer.echo(pattern)
    if settings.level == "L1":
        typer.echo(f"This repository is kept at level L1 on {record.name}.")


@code_app.command("allow")
@_cli
def server_code_allow(file: str, repository: _REPOSITORY_OPTION = None) -> None:
    """Send FILE, which the content scan held out, exactly as it is now (you confirm it here)."""

    record = _selected()
    here = repository_here(repository)
    path = os.path.normpath(os.path.join(here.worktree, file))
    relative = os.path.relpath(path, here.worktree)
    if relative.startswith("..") or os.path.isabs(relative):
        raise ServerCommandRefused("usage", message="FILE must be inside the repository")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise ServerCommandRefused("usage", message="FILE cannot be read") from None
    try:
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, 1 << 20):
            total += len(chunk)
            if total > _MAX_ALLOW_BYTES:
                raise ServerCommandRefused("usage", message="FILE is too large")
            digest.update(chunk)
    finally:
        os.close(descriptor)
    content = "sha256:" + digest.hexdigest()
    _confirm(
        record,
        (
            f"{relative} was held out of this repository's copy because its content matched a "
            "known secret format.",
            f"Confirm to send it to {record.name} exactly as it is now; any change to it is "
            "scanned again.",
        ),
    )
    _update(
        record,
        here.key,
        lambda s: replace(s, allow=tuple(sorted({*s.allow, (relative, content)}))),
    )
    typer.echo(f"{relative} is sent as it is now at the next sync.")


@code_app.command("level")
@_cli
def server_code_level(value: str, repository: _REPOSITORY_OPTION = None) -> None:
    """L1 keeps this repository at level L1 on the selected server; default undoes it."""

    record = _selected()
    here = repository_here(repository)
    if value == "L1":
        _update(record, here.key, lambda s: replace(s, level="L1"))
        typer.echo(
            f"This repository is kept at level L1 on {record.name}: nothing more of its code is "
            "sent. What was sent before stays there until you run 'finishup server code forget'."
        )
        return
    if value != "default":
        raise ServerCommandRefused("usage", message="the level is L1 or default")
    if _settings(record, here.key).level is None:
        typer.echo(f"This repository already follows the level you agreed to for {record.name}.")
        return
    _confirm(
        record,
        (f"This repository will follow the level you agreed to for {record.name} again.",),
    )
    _update(record, here.key, lambda s: replace(s, level=None))
    typer.echo(f"This repository follows the level you agreed to for {record.name} again.")
