"""``finishup server code``: what a server keeps of your code, and how to make it keep less (L2).

Level L2 (ADR-054). The group acts on the selected server elsewhere and on the repository of a
folder (the current one by default). A server that keeps no copies (its owner's
``[server.code_copy]`` table makes no offer) refuses the commands that reach it. Like every
``finishup server`` command that uses the selection, each one is refused with
``selection_overridden`` while an isolation root or a runtime pin decides this process's root,
before any lookup, prompt or write.

* ``list`` asks the server what it keeps of this repository; ``forget`` deletes it there (and this
  computer's export folder for it) and prints exactly what the server deleted. Forget is the only
  way to remove what was already sent: stopping, holding or narrowing to L1 stops future sends.
  ``forget --all`` forgets every repository this computer sent copies from to that server: the
  server acts on the claimed repository only, so each copy this computer's export records name
  is claimed and forgotten in turn; one that cannot be is named with its reason, never skipped,
  and the exit status says whether every one was forgotten. ``list --all`` lists them the same
  way. ``server remove`` uses the same to offer forgetting before it removes a target.
* Each of them reaches the server over copy control (#1357): a connection that carries the copy's
  claim (its keyed digest and its worktree's, the copy's id there) and nothing else, admitted by
  the shared gate and the check that the target record is still the one read, never by the hold,
  so they work for a repository held from that server or kept on this computer, at level L1, or
  gone from disk. The copy is named by this computer's export record (the claim its sync
  recorded, else the claim on the folder that sync read): the claim that server already saw. A
  held or kept repository with no export record is answered here, and one whose record cannot
  name it is refused: nothing else is ever sent for it. This computer's zero-network policy
  still refuses them before anything is sent.
* ``exclude add|remove|list`` keeps patterns out of this repository's copy. Adding only ever
  sends less, so any process may; removing sends more, so the owner confirms it on the trusted
  console.
* ``allow add FILE`` sends one file the content scan held out, exactly as it is now (its bytes'
  digest is recorded; any other content is scanned again); confirmed on the trusted console.
  ``allow list`` shows what was allowed (paths and short digests, never contents), and
  ``allow remove PATH`` undoes it: sending less, so no question.
* ``level L1`` keeps this repository at level L1 on that server; ``level default`` undoes it,
  confirmed on the trusted console.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Annotated, Final, cast

import typer

from finishup.cli.server import (
    _REPOSITORY_OPTION,  # pyright: ignore[reportPrivateUsage]
    ServerCommandRefused,
    _cli,  # pyright: ignore[reportPrivateUsage]
    _repository_target,  # pyright: ignore[reportPrivateUsage]
    _require_no_explicit_source,  # pyright: ignore[reportPrivateUsage]
    repository_here,
    server_app,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from finishup.cli.server import RepositoryHere
    from finishup.client.code_copy_settings import RepositoryCodeSettings
    from finishup.client.code_export import ExportRecord
    from finishup.client.targets import ServerTarget
    from finishup.ports.control import WorkspaceClaim

__all__ = [
    "FORGET_TRAILER",
    "ZERO_NETWORK_COPY",
    "ForgetOutcome",
    "ListOutcome",
    "code_app",
    "forget_every_copy",
    "forget_lines",
    "list_every_copy",
]

code_app = typer.Typer(
    help="What a server elsewhere keeps of your code (level L2), and how to make it keep less.",
    no_args_is_help=True,
)
exclude_app = typer.Typer(help="Keep files out of this repository's copy.", no_args_is_help=True)
code_app.add_typer(exclude_app, name="exclude")
allow_app = typer.Typer(
    help="Send files the content scan held out, exactly as they are now; list and undo it.",
    no_args_is_help=True,
)
code_app.add_typer(allow_app, name="allow")
server_app.add_typer(code_app, name="code")

_JSON_OPTION = Annotated[bool, typer.Option("--json", help="Print JSON.")]
_MAX_ALLOW_BYTES: Final = 1 << 30
# Hex digits of an allowed content's digest shown by ``allow list``: enough to tell versions apart.
_SHORT_DIGEST: Final = 12


def _field(value: object, key: str) -> object:
    """``value[key]`` when ``value`` is a JSON object, else None."""

    if not isinstance(value, dict):
        return None
    return cast("dict[str, object]", value).get(key)


def _selected() -> ServerTarget:
    """The selected server elsewhere, refused while an isolation root or a runtime pin decides
    this process's root (``selection_overridden``): such a process never reads, changes or acts
    on the everyday selection's target. Every command of the group asks this first, before any
    lookup, prompt or write."""

    _require_no_explicit_source()
    return _repository_target(None)


_AUTHORIZATION_CHANGED: Final = (
    "the server's record changed after this command read it (it was replaced, removed, "
    "authorized again or its consent changed), so nothing was asked of it; run the command again"
)


def _require_captured(record: ServerTarget, authorization: object) -> None:
    """Refuse a connection admitted for anything but ``record`` exactly as this command read it.

    The connection is built for ``record``'s own root (``_server_answer``), and its admission
    reads that root's record again: a target replaced, removed, re-authorized or consented to
    anew in between is ``server_authorization_changed``, before anything is asked of it, so the
    command never reports for one server, or under one consent, what another was asked.
    """

    from finishup.client.authorization import consent_digest, identity_digest

    grant = getattr(authorization, "grant", None)
    if (
        grant is None
        or getattr(grant, "target_id", None) != record.target_id
        or getattr(grant, "identity_digest", None) != identity_digest(record)
        or getattr(grant, "consent_digest", None) != consent_digest(record)
    ):
        raise ServerCommandRefused("server_authorization_changed", message=_AUTHORIZATION_CHANGED)


async def _ask_server(
    record: ServerTarget, worktree: str | None, claim: WorkspaceClaim | None, action: str
) -> dict[str, object]:
    """Ask over copy control (``client.remote_binding.copy_control_binding``): the connection
    carries ``claim`` (or the claim on ``worktree``'s repository) and nothing else."""

    from finishup.adapters.workspace_root import RepositoryIdentityError
    from finishup.client.remote_binding import copy_claim, copy_control_binding
    from finishup.ports.control import ControlClientKind
    from finishup.service.client import connect_service

    if claim is None:
        if worktree is None:
            raise ServerCommandRefused("repository_folder_unknown")
        try:
            claim = await copy_claim(record, worktree)
        except (RepositoryIdentityError, OSError):
            raise ServerCommandRefused("repository_invalid") from None
    from finishup.client.authorization import CapturedTarget

    # The record this command read, asked before the hello: a target replaced, removed,
    # authorized again or consented to anew since is refused before the claim leaves.
    client = await connect_service(
        ControlClientKind.CLI,
        workspace_binding=copy_control_binding(claim, CapturedTarget.of(record)),
    )
    try:
        _require_captured(record, client.authorization)
        return await client.code_copy("forget" if action == "forget" else "status")
    finally:
        await client.close()


# What a copy command says when this computer's zero-network policy refuses it: the rule is not
# weakened, so the owner reads what that means for the copy there and what would let them act.
ZERO_NETWORK_COPY: Final = (
    "this computer's FinishUP is set to make no network connections, so FinishUP cannot reach "
    "that server to list or delete its copy and sent nothing to it; the copy stays there as its "
    "retention says (one kept until forgotten stays until it is forgotten), until this computer "
    "allows network use again ('finishup privacy setup') and you run this command again"
)
_ZERO_NETWORK_PHASES: Final = frozenset({"zero_network_remote_selected"})


def _server_answer(
    record: ServerTarget,
    worktree: str | None,
    action: str,
    *,
    claim: WorkspaceClaim | None = None,
) -> dict[str, object]:
    """Ask ``record``'s server, the target this command read, and no other, about one copy.

    The copy is named by ``claim`` (the claim its sync recorded) or else by the claim on
    ``worktree``'s repository, over copy control. The connection resolves its root as
    ``record``'s own (``selection_override``), whatever the selection names by then, and is
    refused unless its admission is ``record``'s as read (``_require_captured``).
    """

    from finishup.cli.app import run_async
    from finishup.client.targets import TargetError, target_root
    from finishup.config.paths import selection_override
    from finishup.ports.control import ControlError

    try:
        with selection_override(target_root(record.target_id)):
            return run_async(lambda: _ask_server(record, worktree, claim, action))
    except ControlError as error:
        if error.reason == "method_forbidden":
            raise ServerCommandRefused(
                "server_level_unavailable",
                message="that server keeps no copy of code (it does not offer level L2)",
            ) from None
        phase = error.phase or error.reason
        if phase in _ZERO_NETWORK_PHASES:
            raise ServerCommandRefused(phase, message=ZERO_NETWORK_COPY) from None
        raise ServerCommandRefused(phase) from None
    except TargetError as error:
        raise ServerCommandRefused(error.reason) from None


# A held or kept repository whose export record cannot name its copy: nothing is sent, so a
# claim that server never saw (another worktree's) never leaves for it.
_HELD_UNNAMED: Final = (
    "this repository is held from that server, and this computer's record of the copy it sent "
    "names no folder that still holds that repository, so FinishUP sent nothing; run this "
    "command in the folder that copy was sent from, or allow the repository first ('finishup "
    "server repositories add', confirmed in your terminal)"
)


def _copy_here(
    record: ServerTarget, here: RepositoryHere, action: str, *, json_output: bool
) -> _Named | None:
    """How the copy of ``here``'s repository is named there, or None once answered here.

    This computer's export record names it when there is one (``_named``: the claim its sync
    recorded, else the claim on the folder that sync read): exactly the claim that server
    already saw, since an export folder exists only because it asked this computer for a copy
    over a connection carrying that claim. A held or kept repository is never named otherwise:
    with no export record it is answered here (nothing was sent, so nothing is asked), and with
    one that cannot name it, refused. Any other repository with no usable record is named by the
    worktree here, as every connection from it is.
    """

    from finishup.client.code_export import export_record
    from finishup.client.code_sync import export_folder
    from finishup.client.repository_hold import decide
    from finishup.client.targets import target_root

    phase = decide(target_root(record.target_id), record.target_id, here.key).phase
    item = export_record(export_folder(record.target_id, here.key))
    if item is None or (phase is not None and item.readable and not item.sent):
        # No record, or one that names nothing sent there (an export refused or interrupted
        # before anything was offered): a held or kept repository is answered here.
        if phase is not None:
            _answer_never_sent(record, action, phase, json_output=json_output)
            return None
        return _Named(worktree=here.worktree)
    named = _named(record, item)
    if named.reason is None:
        return named
    if phase is None:
        return _Named(worktree=here.worktree)
    raise ServerCommandRefused(named.reason, message=_HELD_UNNAMED)


def _answer_never_sent(record: ServerTarget, action: str, phase: str, *, json_output: bool) -> None:
    if json_output:
        import json

        typer.echo(
            json.dumps(
                {
                    "action": action,
                    "copy": None,
                    "forgot": None,
                    "hold": phase,
                    "server_asked": False,
                },
                sort_keys=True,
            )
        )
        return
    where = (
        "kept on this computer" if phase == "repository_egress_kept" else f"held from {record.name}"
    )
    typer.echo(
        f"This computer has no record of sending {record.name} a copy of this repository, and "
        f"the repository is {where}, so FinishUP asked {record.name} nothing"
        + ("; nothing was deleted." if action == "forget" else ".")
    )


def _copy_line(record: ServerTarget, copy: object, subject: str) -> str:
    """What ``record`` keeps of ``subject`` (``this repository``, ``it``), from its answer."""

    if copy is None:
        return f"{record.name} keeps no copy of {subject}."
    retention = _field(copy, "retention")
    kept = "until you forget it"
    if _field(retention, "kind") == "days":
        kept = f"for {_field(retention, 'days')} days after its last sync"
    elif _field(retention, "kind") == "task_close":
        kept = "until the tasks that read it are closed"
    return (
        f"{record.name} keeps a copy of {subject}: {_field(copy, 'snapshots')} snapshot(s), "
        f"{_field(copy, 'stored_bytes')} bytes, last synced {_field(copy, 'last_sync_at') or 'never'}, "
        f"kept {kept}."
    )


@code_app.command("list")
@_cli
def server_code_list(
    repository: _REPOSITORY_OPTION = None,
    every: Annotated[
        bool,
        typer.Option(
            "--all", help="List every repository this computer sent copies from to that server."
        ),
    ] = False,
    json_output: _JSON_OPTION = False,
) -> None:
    """Show what the selected server keeps of this repository."""

    if every and repository is not None:
        raise ServerCommandRefused("usage", message="give --all or --repository FOLDER, not both")
    record = _selected()
    if every:
        _list_all(record, json_output=json_output)
        return
    here = repository_here(repository)
    named = _copy_here(record, here, "status", json_output=json_output)
    if named is None:
        return
    answer = _server_answer(record, named.worktree, "status", claim=named.claim)
    if json_output:
        import json

        typer.echo(json.dumps(answer, sort_keys=True))
        return
    typer.echo(_copy_line(record, _field(answer, "copy"), "this repository"))


# What forget says after the server answered: what FinishUP does not manage, and what stays.
FORGET_TRAILER: Final = (
    "Copies of that server's folder in backups its owner made are not managed by FinishUP "
    "and stay until they are removed there. The tasks that read the copy lose the captured "
    "changes and review excerpts they kept from it and say that their content was forgotten; "
    "their findings and checks stay."
)
# Why ``forget --all`` could not forget one repository's copy, and what the owner can do.
_NOT_FORGOTTEN: Final[dict[str, str]] = {
    "code_copy_deletion_unfinished": (
        "that server could not finish deleting it yet (what is left stays fenced there and its "
        "deletion is retried); run this command again later"
    ),
    "export_record_unreadable": (
        "this computer's record of it cannot be read, so the repository it came from is not "
        "known; run 'finishup server code forget' in that repository"
    ),
    "repository_folder_unknown": (
        "this computer has no folder of that repository it can name; run 'finishup server code "
        "forget --repository FOLDER' with a folder of it"
    ),
    "repository_folder_missing": (
        "that folder is no longer there, and its record is from before FinishUP kept the copy's "
        "id; run 'finishup server code forget --repository FOLDER' with another worktree of that "
        "repository, or once it is back in that folder"
    ),
    "repository_invalid": (
        "FinishUP cannot name a repository in that folder now; run 'finishup server code forget "
        "--repository FOLDER' with a worktree of the repository it came from"
    ),
    "repository_changed": (
        "that folder now holds another repository; run 'finishup server code forget "
        "--repository FOLDER' with a worktree of the repository it came from"
    ),
    "zero_network_remote_selected": ZERO_NETWORK_COPY,
}


def _forgot_line(record: ServerTarget, answer: object) -> str:
    forgot = _field(answer, "forgot")
    if not _field(forgot, "copies"):
        return f"{record.name} kept no copy of it; nothing was deleted there"
    return (
        f"{record.name} deleted {_field(forgot, 'snapshots')} snapshot(s), "
        f"{_field(forgot, 'objects')} stored objects, {_field(forgot, 'bytes')} bytes"
    )


@code_app.command("forget")
@_cli
def server_code_forget(
    repository: _REPOSITORY_OPTION = None,
    every: Annotated[
        bool,
        typer.Option(
            "--all", help="Forget every repository this computer sent copies from to that server."
        ),
    ] = False,
    json_output: _JSON_OPTION = False,
) -> None:
    """Delete the selected server's copy of this repository, and say exactly what it deleted."""

    from finishup.client.code_sync import export_folder
    from finishup.client.targets import registry_lock

    if every and repository is not None:
        raise ServerCommandRefused("usage", message="give --all or --repository FOLDER, not both")
    record = _selected()
    if every:
        _forget_all(record, json_output=json_output)
        return
    here = repository_here(repository)
    named = _copy_here(record, here, "forget", json_output=json_output)
    if named is None:
        return
    answer = _server_answer(record, named.worktree, "forget", claim=named.claim)
    forgot = _field(answer, "forgot")
    if _field(forgot, "complete") is not True:
        # Never a success while something of the copy is left there: say what was deleted,
        # keep this computer's export record (so the command can be run again), and refuse.
        if json_output:
            import json

            typer.echo(json.dumps(answer, sort_keys=True))
        else:
            typer.echo(
                f"{record.name} could not finish deleting its copy of this repository: "
                f"{_field(forgot, 'snapshots') or 0} snapshot(s), "
                f"{_field(forgot, 'objects') or 0} stored objects, "
                f"{_field(forgot, 'bytes') or 0} bytes deleted so far; the rest stays fenced "
                "there and its deletion is retried. Run this command again later."
            )
        raise ServerCommandRefused("code_copy_deletion_unfinished")
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
    if not _field(forgot, "copies"):
        typer.echo(f"{record.name} kept no copy of this repository; nothing was deleted.")
    else:
        typer.echo(
            f"{record.name} deleted its copy of this repository: {_field(forgot, 'snapshots')} "
            f"snapshot(s), {_field(forgot, 'objects')} stored objects, {_field(forgot, 'bytes')} "
            "bytes."
        )
    typer.echo(FORGET_TRAILER)


# --- forget every repository at once -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ForgetOutcome:
    """What ``forget --all`` did for one repository this computer sent copies from.

    ``position`` (from 1) and ``copy`` (the export folder's short id) name it; ``folder`` is the
    repository's folder this computer recorded, or None; ``reason`` is None once the server
    forgot it, else the closed reason it was not; ``answer`` is the server's answer, if any.
    """

    position: int
    copy: str
    folder: str | None
    reason: str | None
    answer: dict[str, object] | None = None
    # False for a held or kept repository whose record names nothing sent there: nothing was
    # asked of that server (outcome ``never_sent``), and nothing is left to forget (#1357).
    sent: bool = True

    @property
    def forgotten(self) -> bool:
        return self.reason is None

    def to_json(self) -> dict[str, object]:
        outcome = "forgotten" if self.forgotten else "not_forgotten"
        return {
            "position": self.position,
            "copy": self.copy,
            "folder": self.folder,
            "outcome": outcome if self.sent else "never_sent",
            "reason": self.reason,
            "answer": self.answer,
        }


def forget_every_copy(
    record: ServerTarget, *, renew: Callable[[], None] | None = None
) -> tuple[ForgetOutcome, ...]:
    """Forget on ``record``'s server every repository this computer's export records name.

    The server's ``code_copy`` acts on the claimed repository only (ADR-054 decision 5), so each
    record's folder is claimed in turn and forgotten as ``server code forget`` does, its export
    folder here going too. A record that cannot be read, names no folder, or whose folder is gone,
    holds no repository or another one, or that the server did not forget, is returned with its
    closed reason: never skipped. Each is asked of ``record``'s own root (``_server_answer``),
    whether or not it is selected (``server remove`` of a target that is not). ``renew``, when
    given, runs before each repository (``server remove`` renews its sync fence there); it
    refuses by raising, which stops the forget at that repository.
    """

    from finishup.client.code_export import ExportRefused, export_records
    from finishup.client.code_sync import exports_folder

    try:
        records = export_records(exports_folder(record.target_id))
    except ExportRefused as error:
        raise ServerCommandRefused(error.reason) from None
    outcomes: list[ForgetOutcome] = []
    for position, item in enumerate(records, start=1):
        if renew is not None:
            renew()
        outcomes.append(_forget_one(record, position, item))
    return tuple(outcomes)


@dataclass(frozen=True, slots=True)
class _Named:
    """How one export record's copy is named there: the claim its sync recorded, or the
    worktree of the folder it names; or the closed reason it cannot be."""

    worktree: str | None = None
    claim: WorkspaceClaim | None = None
    reason: str | None = None
    # The repository key of the folder that names it (when named by its folder).
    key: str | None = None


def _never_sent(record: ServerTarget, item: ExportRecord, named: _Named) -> bool:
    """Whether ``item`` names nothing sent there for a repository now held from ``record`` or
    kept on this computer (an export refused or interrupted before anything was offered): then
    nothing is asked of that server, as ``_copy_here`` answers for one repository."""

    if item.sent or named.key is None:
        return False
    from finishup.client.repository_hold import decide
    from finishup.client.targets import target_root

    return decide(target_root(record.target_id), record.target_id, named.key).phase is not None


def _named(record: ServerTarget, item: ExportRecord) -> _Named:
    """The claim a sync recorded names the copy exactly, whatever became of its folder (moved,
    deleted, another repository now); a record from before claims were kept names its folder,
    which must still hold that repository."""

    from finishup.client.code_sync import export_folder

    if not item.readable:
        return _Named(reason="export_record_unreadable")
    if item.claim is not None:
        return _Named(claim=item.claim)
    if item.root is None:
        return _Named(reason="repository_folder_unknown")
    if not os.path.isdir(item.root):
        return _Named(reason="repository_folder_missing")
    try:
        here = repository_here(item.root)
    except ServerCommandRefused as error:
        return _Named(reason=error.reason)
    if export_folder(record.target_id, here.key) != item.folder:
        return _Named(reason="repository_changed")
    return _Named(worktree=here.worktree, key=here.key)


def _forget_one(record: ServerTarget, position: int, item: ExportRecord) -> ForgetOutcome:
    from finishup.client.targets import TargetError, registry_lock

    def refused(reason: str) -> ForgetOutcome:
        return ForgetOutcome(position, item.short_id, item.root, reason)

    named = _named(record, item)
    if named.reason is not None:
        return refused(named.reason)
    if _never_sent(record, item, named):
        return ForgetOutcome(position, item.short_id, item.root, None, sent=False)
    try:
        # Through ``record``'s own root, whether or not it is the selected one.
        answer = _server_answer(record, named.worktree, "forget", claim=named.claim)
    except ServerCommandRefused as error:
        return refused(error.reason)
    except TargetError as error:
        return refused(error.reason)
    if _field(_field(answer, "forgot"), "complete") is not True:
        # Not finished there: the export record stays, so this command can name it again.
        return ForgetOutcome(
            position, item.short_id, item.root, "code_copy_deletion_unfinished", answer
        )
    with registry_lock():
        # As ``server code forget``: what it sent is gone there, so its export folder goes here.
        if item.folder.exists():
            import shutil

            shutil.rmtree(item.folder, ignore_errors=True)
    return ForgetOutcome(position, item.short_id, item.root, None, answer)


def forget_lines(record: ServerTarget, outcomes: tuple[ForgetOutcome, ...]) -> tuple[str, ...]:
    """The owner display of ``forget_every_copy``: one line per repository, then what stays."""

    from finishup.cli.server import refusal_message

    if not outcomes:
        return (
            f"This computer has no record of a copy of code it sent to {record.name}; nothing "
            "was forgotten.",
        )
    count = f"{len(outcomes)} {'repository' if len(outcomes) == 1 else 'repositories'}"
    lines = [f"Copies of code this computer sent to {record.name} ({count}):"]
    for outcome in outcomes:
        folder = "a folder this computer cannot name" if outcome.folder is None else outcome.folder
        named = f"  {outcome.position}. {folder} (copy {outcome.copy}): "
        if not outcome.sent:
            lines.append(named + _NEVER_SENT_LINE)
            continue
        if outcome.reason is None:
            lines.append(named + f"forgotten; {_forgot_line(record, outcome.answer)}.")
            continue
        remedy = _NOT_FORGOTTEN.get(outcome.reason)
        if remedy is None:
            remedy = (
                refusal_message(ServerCommandRefused(outcome.reason))
                + "; then run this command again"
            )
        lines.append(named + f"not forgotten ({outcome.reason}): {remedy}.")
    missed = sum(1 for outcome in outcomes if not outcome.forgotten)
    if missed:
        lines.append(
            f"{missed} of {len(outcomes)} not forgotten: each stays on {record.name} until it "
            "expires or is forgotten."
        )
    else:
        lines.append(f"Every copy this computer sent to {record.name} is forgotten there.")
    if missed < len(outcomes):
        lines.append(FORGET_TRAILER)
    return tuple(lines)


def _forget_all(record: ServerTarget, *, json_output: bool) -> None:
    outcomes = forget_every_copy(record)
    missed = sum(1 for outcome in outcomes if not outcome.forgotten)
    if json_output:
        import json

        typer.echo(
            json.dumps(
                {
                    "action": "forget_all",
                    "repositories": [outcome.to_json() for outcome in outcomes],
                    "forgotten": sum(1 for item in outcomes if item.forgotten and item.sent),
                    "not_forgotten": missed,
                },
                sort_keys=True,
            )
        )
    else:
        for line in forget_lines(record, outcomes):
            typer.echo(line)
    if missed:
        raise ServerCommandRefused("code_copy_forget_incomplete")


# --- list every repository at once --------------------------------------------------------------


# A held or kept repository whose record names nothing sent there, in ``--all``'s lines.
_NEVER_SENT_LINE: Final = (
    "never sent; this computer's record of it names nothing sent there, and it is held from that "
    "server or kept here, so FinishUP asked that server nothing."
)


# Why ``list --all`` could not list one repository's copy, and what the owner can do.
_NOT_LISTED: Final[dict[str, str]] = {
    "export_record_unreadable": (
        "this computer's record of it cannot be read, so the repository it came from is not "
        "known; run 'finishup server code list' in that repository"
    ),
    "repository_folder_unknown": (
        "this computer has no folder of that repository it can name; run 'finishup server code "
        "list --repository FOLDER' with a folder of it"
    ),
    "repository_folder_missing": (
        "that folder is no longer there, and its record is from before FinishUP kept the copy's "
        "id; run 'finishup server code list --repository FOLDER' with another worktree of that "
        "repository, or once it is back in that folder"
    ),
    "repository_invalid": (
        "FinishUP cannot name a repository in that folder now; run 'finishup server code list "
        "--repository FOLDER' with a worktree of the repository it came from"
    ),
    "repository_changed": (
        "that folder now holds another repository; run 'finishup server code list "
        "--repository FOLDER' with a worktree of the repository it came from"
    ),
    "zero_network_remote_selected": ZERO_NETWORK_COPY,
}


@dataclass(frozen=True, slots=True)
class ListOutcome:
    """What ``list --all`` found for one repository this computer sent copies from (fields as
    ``ForgetOutcome``): ``reason`` is None once the server answered."""

    position: int
    copy: str
    folder: str | None
    reason: str | None
    answer: dict[str, object] | None = None
    sent: bool = True

    def to_json(self) -> dict[str, object]:
        outcome = "listed" if self.reason is None else "not_listed"
        return {
            "position": self.position,
            "copy": self.copy,
            "folder": self.folder,
            "outcome": outcome if self.sent else "never_sent",
            "reason": self.reason,
            "answer": self.answer,
        }


def list_every_copy(record: ServerTarget) -> tuple[ListOutcome, ...]:
    """Ask ``record``'s server about every copy this computer's export records name, each named
    as ``forget --all`` names it; one that cannot be is returned with its closed reason."""

    from finishup.client.code_export import ExportRefused, export_records
    from finishup.client.code_sync import exports_folder
    from finishup.client.targets import TargetError

    try:
        records = export_records(exports_folder(record.target_id))
    except ExportRefused as error:
        raise ServerCommandRefused(error.reason) from None
    outcomes: list[ListOutcome] = []
    for position, item in enumerate(records, start=1):
        named = _named(record, item)
        reason = named.reason
        answer: dict[str, object] | None = None
        if reason is None and _never_sent(record, item, named):
            outcomes.append(ListOutcome(position, item.short_id, item.root, None, sent=False))
            continue
        if reason is None:
            try:
                answer = _server_answer(record, named.worktree, "status", claim=named.claim)
            except (ServerCommandRefused, TargetError) as error:
                reason = error.reason
        outcomes.append(ListOutcome(position, item.short_id, item.root, reason, answer))
    return tuple(outcomes)


def _list_all(record: ServerTarget, *, json_output: bool) -> None:
    from finishup.cli.server import refusal_message

    outcomes = list_every_copy(record)
    missed = sum(1 for outcome in outcomes if outcome.reason is not None)
    if json_output:
        import json

        typer.echo(
            json.dumps(
                {
                    "action": "status_all",
                    "repositories": [outcome.to_json() for outcome in outcomes],
                    "listed": sum(1 for item in outcomes if item.reason is None and item.sent),
                    "not_listed": missed,
                },
                sort_keys=True,
            )
        )
    elif not outcomes:
        typer.echo(
            f"This computer has no record of a copy of code it sent to {record.name}; nothing "
            "was asked."
        )
    else:
        count = f"{len(outcomes)} {'repository' if len(outcomes) == 1 else 'repositories'}"
        typer.echo(f"Copies of code this computer sent to {record.name} ({count}):")
        for outcome in outcomes:
            folder = (
                "a folder this computer cannot name" if outcome.folder is None else outcome.folder
            )
            named = f"  {outcome.position}. {folder} (copy {outcome.copy}): "
            if not outcome.sent:
                typer.echo(named + _NEVER_SENT_LINE)
                continue
            if outcome.reason is None:
                typer.echo(named + _copy_line(record, _field(outcome.answer, "copy"), "it"))
                continue
            remedy = _NOT_LISTED.get(outcome.reason)
            if remedy is None:
                remedy = (
                    refusal_message(ServerCommandRefused(outcome.reason))
                    + "; then run this command again"
                )
            typer.echo(named + f"not listed ({outcome.reason}): {remedy}.")
    if missed:
        raise ServerCommandRefused("code_copy_list_incomplete")


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
    change: Callable[[RepositoryCodeSettings], RepositoryCodeSettings],
) -> RepositoryCodeSettings:
    from finishup.client.code_copy_settings import CodeCopySettingsError, update_settings
    from finishup.client.targets import registry_lock, target_root

    try:
        with registry_lock():
            return update_settings(target_root(record.target_id), record.target_id, key, change)
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

    def add(settings: RepositoryCodeSettings) -> RepositoryCodeSettings:
        return replace(settings, exclude=tuple(sorted({*settings.exclude, pattern})))

    _update(record, here.key, add)
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

    def remove(settings: RepositoryCodeSettings) -> RepositoryCodeSettings:
        return replace(
            settings, exclude=tuple(item for item in settings.exclude if item != pattern)
        )

    _update(record, here.key, remove)
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


def _shown(path: str) -> str:
    """``path`` for an owner display: a character that is not printable is shown escaped."""

    return "".join(item if item.isprintable() else repr(item)[1:-1] for item in path)


def _inside(here: RepositoryHere, file: str, name: str) -> tuple[str, str]:
    """``(absolute path, path from the worktree's top)`` of ``file``; refused outside it."""

    path = os.path.normpath(os.path.join(here.worktree, file))
    relative = os.path.relpath(path, here.worktree)
    if (
        relative in {os.curdir, os.pardir}
        or relative.startswith(os.pardir + os.sep)
        or os.path.isabs(relative)
    ):
        raise ServerCommandRefused("usage", message=f"{name} must be inside the repository")
    return path, relative


@allow_app.command("add")
@_cli
def server_code_allow_add(file: str, repository: _REPOSITORY_OPTION = None) -> None:
    """Send FILE, which the content scan held out, exactly as it is now (you confirm it here)."""

    record = _selected()
    here = repository_here(repository)
    path, relative = _inside(here, file, "FILE")
    try:
        # Non-blocking, so a named pipe is refused below rather than waited on.
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0)
        )
    except OSError:
        raise ServerCommandRefused("usage", message="FILE cannot be read") from None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ServerCommandRefused("usage", message="FILE must be a regular file")
        digest = hashlib.sha256()
        total = 0
        try:
            while chunk := os.read(descriptor, 1 << 20):
                total += len(chunk)
                if total > _MAX_ALLOW_BYTES:
                    raise ServerCommandRefused("usage", message="FILE is too large")
                digest.update(chunk)
        except OSError:
            raise ServerCommandRefused("usage", message="FILE cannot be read") from None
    finally:
        os.close(descriptor)
    content = "sha256:" + digest.hexdigest()
    _confirm(
        record,
        (
            f"{_shown(relative)} was held out of this repository's copy because its content "
            "matched a known secret format.",
            f"Confirm to send it to {record.name} exactly as it is now; any change to it is "
            "scanned again.",
        ),
    )

    def allow(settings: RepositoryCodeSettings) -> RepositoryCodeSettings:
        return replace(settings, allow=tuple(sorted({*settings.allow, (relative, content)})))

    _update(record, here.key, allow)
    typer.echo(f"{_shown(relative)} is sent as it is now at the next sync.")


@allow_app.command("list")
@_cli
def server_code_allow_list(
    repository: _REPOSITORY_OPTION = None, json_output: _JSON_OPTION = False
) -> None:
    """Show the files allowed past the content scan (paths and short digests, never contents)."""

    record = _selected()
    here = repository_here(repository)
    allowed = [
        (path, digest[: len("sha256:") + _SHORT_DIGEST])
        for path, digest in _settings(record, here.key).allow
    ]
    if json_output:
        import json

        typer.echo(
            json.dumps(
                {"allow": [{"path": path, "digest": digest} for path, digest in allowed]},
                sort_keys=True,
            )
        )
        return
    if not allowed:
        typer.echo(f"No file of this repository is allowed past the content scan on {record.name}.")
        return
    typer.echo(
        f"Allowed past the content scan on {record.name}, each only with the content it had when "
        "you allowed it:"
    )
    for path, digest in allowed:
        typer.echo(f"  {_shown(path)}  {digest}")
    typer.echo("Undo one with 'finishup server code allow remove PATH'.")


@allow_app.command("remove")
@_cli
def server_code_allow_remove(path: str, repository: _REPOSITORY_OPTION = None) -> None:
    """Stop sending PATH past the content scan (sends less: no question)."""

    record = _selected()
    here = repository_here(repository)
    _absolute, relative = _inside(here, path, "PATH")
    if not any(item == relative for item, _digest in _settings(record, here.key).allow):
        typer.echo(
            f"{_shown(relative)} is not allowed past the content scan for this repository on "
            f"{record.name}; nothing was changed."
        )
        return

    def remove(settings: RepositoryCodeSettings) -> RepositoryCodeSettings:
        return replace(
            settings, allow=tuple(item for item in settings.allow if item[0] != relative)
        )

    _update(record, here.key, remove)
    typer.echo(
        f"{_shown(relative)} is no longer allowed past the content scan on {record.name}: from "
        "the next sync it is held out again while its content matches a known secret format. "
        "What was already sent stays there until you run 'finishup server code forget'."
    )


@code_app.command("level")
@_cli
def server_code_level(value: str, repository: _REPOSITORY_OPTION = None) -> None:
    """L1 keeps this repository at level L1 on the selected server; default undoes it."""

    record = _selected()
    here = repository_here(repository)
    if value == "L1":

        def keep(settings: RepositoryCodeSettings) -> RepositoryCodeSettings:
            return replace(settings, level="L1")

        _update(record, here.key, keep)
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

    def follow(settings: RepositoryCodeSettings) -> RepositoryCodeSettings:
        return replace(settings, level=None)

    _update(record, here.key, follow)
    typer.echo(f"This repository follows the level you agreed to for {record.name} again.")
