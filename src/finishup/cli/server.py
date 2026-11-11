"""``finishup server``: choose which FinishUP server this computer's client uses (ADR-051).

Every command here acts on this machine's server targets and selection (scope ``client_only``).
Names and addresses appear only in owner displays (``list``, ``status``, ``test``) and on the
trusted console; refusals name a target by its id or not at all, with a closed reason token.

* ``add NAME --local`` makes a named local server (its own vault, ledger, and on-demand service).
  ``remove`` is the reverse.
* ``use NAME|local`` writes or removes the owner-only selection. ``use local`` is the reverse. A
  switch away from a remote target also stops what this client runs for it, as ``disconnect``
  does (``TargetSwitch``).
* ``connect``/``disconnect`` make the target usable or stop what this client runs for it.
* ``list``, ``status [--json]`` and ``test`` show the deciding source, the target, and a probe.

SSH servers are open (ADR-052, layer 4): ``add NAME ssh://[user@]host[:port]`` runs SSH discovery
(the server's own launcher reports its endpoint and profile; an unknown host key is asked about
only on the trusted console), then the owner's consent; ``set NAME --style relay|direct`` chooses
how this computer reaches it. HTTPS and port servers are open (ADR-053, layer 5): ``add NAME
https://HOST[:PORT][/BASE]`` or ``add NAME --port PORT`` runs HTTPS discovery without a key, reads
the API key (an owner-only file or the trusted console), fetches the profile with it, then asks
the owner's consent; ``add official`` fills the official service's pinned URL (none yet);
``login`` replaces the key after the server checked it, ``logout`` deletes it offline; both bump
the credential generation and stop the target's helper. A kind closed in a build (an address
this release names none of) refuses with ``remote_kind_unavailable`` before any prompt, policy
check, probe or write, and ``list`` and ``status`` show such a record as not available.

An isolation root or a runtime pin outranks the selection; while one is in force every command
that would change or use the selection is refused with ``selection_overridden``.

Every remote kind has an outside-read mode (ADR-051 decision 5), the same two for each: what
the target's server may read outside the claimed workspace on this computer, in ``local`` mode
as a FinishUP service on this computer would, in ``listed`` mode only beneath the folders listed
for it; in both modes a task's files beneath a listed folder are read, whatever the server's own
policy admits (amended 2026-11-07). ``folders mode NAME local|listed`` chooses it: ``local``
needs the owner to type the target name on the trusted console; ``listed`` is the way back.
``folders add NAME FOLDER`` lists one folder, with the same typed confirmation; ``folders
remove`` is the reverse. ``folders list`` and ``status`` show the mode. Once chosen, nothing asks
again: hooks, agent tools, the CLI and the terminal interface read the record. The record is
this client's own (``finishup.client.server_folders``) and never sent to the server.
"""

from __future__ import annotations

import contextlib
import functools
import re
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Final, Literal, NoReturn, cast

import typer

from finishup import __version__
from finishup.cli.startup_gate_probe import STARTUP_GATE_SECONDS
from finishup.client.authorization import bump_credential_generation
from finishup.client.target_runtime import (
    NEW_CONNECTION_SAMPLES,
    ProbeResult,
    TargetRuntime,
    TargetRuntimeError,
    runtime_for,
)
from finishup.client.targets import (
    DISCLOSURE_VERSION,
    ServerTarget,
    TargetError,
    TargetKind,
    active_target_record,
    clear_selection,
    find_target,
    leftover_target_ids,
    list_targets,
    read_selected_target_id,
    read_target,
    registry_lock,
    remote_target_recorded,
    remove_leftover_root,
    require_current_authorization,
    selection_source,
    target_root,
    validate_name,
    write_selection,
    write_target,
)
from finishup.config.installation import format_rfc3339_ms
from finishup.config.paths import PathSafetyError
from finishup.protocol.canonical import JsonValue, canonical_encode

if TYPE_CHECKING:
    from finishup.cli.trusted_console import TrustedForegroundConsole
    from finishup.cli.zero_network_selection import ZeroNetworkSelection
    from finishup.client.repository_hold import HoldDecision, RepositoryChoice
    from finishup.client.server_folders import FolderRecord, OutsideReadMode
    from finishup.client.server_profile import FetchedProfile
    from finishup.client.ssh_discovery import HostKeyQuestion, SshDiscovery
    from finishup.client.targets import ServerConsent
    from finishup.protocol.consent_envelope import ConsentEnvelope, Retention

__all__ = [
    "DISCLOSURE_LINES",
    "REMOTE_KIND_UNAVAILABLE",
    "ROOT_UNUSABLE_MESSAGE",
    "ServerCommandRefused",
    "TargetRow",
    "TargetSwitch",
    "ZeroNetworkRefusal",
    "build_status_document",
    "refusal_message",
    "render_target_rows",
    "server_app",
    "status_lines",
    "target_in_use",
    "target_rows",
    "use_target",
    "zero_network_connection_refusal",
    "zero_network_refusal",
]

server_app = typer.Typer(
    help="Choose which FinishUP server this computer's agents, CLI, and terminal use.",
    no_args_is_help=True,
)

_JSON = Annotated[bool, typer.Option("--json", help="Emit canonical JSON.")]
_EXPLICIT_SOURCES: Final = frozenset({"environment", "runtime_pin", "environment_and_pin"})
_USAGE: Final = 2
_UNSAFE: Final = 20
_UNAVAILABLE: Final = 20

# What every surface says of a server address this release does not connect to. SSH (layer 4),
# HTTPS and port servers (layer 5, ADR-053) are open.
REMOTE_KIND_UNAVAILABLE: Final = (
    "this release connects to FinishUP servers on this computer (the everyday server and named "
    "local servers, 'finishup server add NAME --local'), over SSH ('finishup server add NAME "
    "ssh://[user@]host[:port]') and over HTTPS ('finishup server add NAME https://host[:port]', or "
    "--port PORT on this computer); that address names none of them"
)

# Remedies are fixed text: no name, host, path, or other owner-typed value is ever echoed.
_REMEDIES: Final[dict[str, tuple[str, int]]] = {
    "remote_kind_unavailable": (f"{REMOTE_KIND_UNAVAILABLE}; nothing was added", _USAGE),
    "selection_overridden": (
        "FINISHUP_ISOLATED_ROOT or a runtime pin decides this process's FinishUP root, so the "
        "server selection is not used here; run this from an ordinary shell",
        _USAGE,
    ),
    "target_name_invalid": (
        "a target name is 1 to 16 lowercase letters, digits, or hyphens, starting with a letter "
        "or digit",
        _USAGE,
    ),
    "target_name_reserved": (
        "'local' always means this computer's everyday FinishUP server; choose another name",
        _USAGE,
    ),
    "target_name_taken": (
        "a target already has that name; choose another, or remove that target first",
        _USAGE,
    ),
    "target_unknown": ("no target has that name; 'finishup server list' shows them", _USAGE),
    "target_selected": (
        "that target is selected; pass --select-local to switch to this computer's everyday "
        "server and remove it",
        _USAGE,
    ),
    "target_record_invalid": (
        "a server target record is damaged; 'finishup server list' fails until it is removed "
        "or restored",
        _UNSAFE,
    ),
    "target_url_invalid": (
        "give https://host[:port][/base] (no user, query, or fragment; plain http is refused), "
        "ssh://[user@]host[:port], or --port PORT for this computer's loopback",
        _USAGE,
    ),
    "target_tls_invalid": (
        "give at most one of --ca-file FILE and --tls-pin sha256:<64 lowercase hex>, and only "
        "with an HTTPS target",
        _USAGE,
    ),
    "target_path_invalid": ("give absolute paths for remote and certificate files", _USAGE),
    "target_root_too_long": (
        "the FinishUP state folder is too deep for a local socket path; FinishUP cannot add a "
        "server target under it",
        _UNSAFE,
    ),
    "target_root_unsafe": (
        "a FinishUP server folder is not owner-only or contains a symlink; fix its permissions "
        "and retry",
        _UNSAFE,
    ),
    "selection_invalid": (
        "the server selection is damaged or names a server folder that is missing or unsafe; "
        "'finishup server use local' clears it",
        _UNSAFE,
    ),
    "trusted_console_required": (
        "authorizing a remote server needs your own interactive terminal; run this command there",
        _USAGE,
    ),
    "authorization_declined": ("the target name was not typed; nothing was changed", _USAGE),
    # 'server folders' (ADR-051 decision 5): fixed text, never the folder.
    "folders_not_applicable": (
        "a server on this computer reads your folders under its own privacy policy; folders are "
        "admitted only for a server on another machine, a port or the web",
        _USAGE,
    ),
    # Exactly what ``admitted_root_from_path`` and ``folder_admissible`` refuse, no more.
    "folder_invalid": (
        "give an existing folder by its full path (starting with /), with no link on the way, at "
        "most 190 characters in at most 16 parts, each of letters, digits and . _ + @ - and none "
        "starting with a dot; these cannot be admitted: the filesystem root, /boot, /dev, /etc, "
        "/proc, /run, /sys, /var/run, /private/etc and /private/var/run and every folder inside "
        "them, your home folder, a folder that holds it, and its private folders (Library, "
        "AppData, snap)",
        _USAGE,
    ),
    "folder_limit": (
        "that server may already read the most folders FinishUP allows; remove one first",
        _USAGE,
    ),
    "folders_record_invalid": (
        "the record of what that server may read outside your projects is damaged, so it reads "
        "no folder there (mode listed); repair it on this computer with 'finishup server folders "
        "remove NAME --all', then run this command again",
        _UNSAFE,
    ),
    "folders_record_unsafe": (
        "the record of what that server may read outside your projects is not owner-only or is "
        "a link, so it reads no folder there (mode listed); repair it on this computer with "
        "'finishup server folders remove NAME --all', then run this command again",
        _UNSAFE,
    ),
    "outside_read_mode_invalid": (
        "give 'local' (read outside your projects as FinishUP on this computer would) or "
        "'listed' (only the folders you list)",
        _USAGE,
    ),
    "outside_reads_not_chosen": (
        "no answer chose what that server may read outside your projects, so nothing was added; "
        "run the command again and type local or listed when asked, or give --outside-reads "
        "local or --outside-reads listed",
        _USAGE,
    ),
    "zero_network_in_force": (
        "this computer's FinishUP is set to make no network connections, so it cannot use a "
        "server on another machine; change the privacy policy on this computer first, with "
        "'finishup privacy setup'",
        _USAGE,
    ),
    # ADR-051 decision 8 (2026-11-07): a connection's own refusal, e.g. at 'server connect'.
    "zero_network_remote_selected": (
        "this computer's FinishUP is set to make no network connections (as it last reported), "
        "so nothing was sent to the selected server elsewhere; run 'finishup server use local'",
        _USAGE,
    ),
    "network_policy_unreadable": (
        "this computer's FinishUP has its own privacy policy, which could not be read (its "
        "service is stopped, locked, or did not answer), so a server on another machine is "
        "refused; start it with 'finishup service start', unlock it if it is locked, and retry",
        _UNAVAILABLE,
    ),
    "credential_not_applicable": (
        "only HTTPS targets take an API key; SSH targets use your OpenSSH keys and agent",
        _USAGE,
    ),
    "credential_invalid": (
        "the key must be one line of 16 to 512 printable characters, from your terminal or an "
        "owner-only (0600) key file",
        _USAGE,
    ),
    "credential_unavailable": ("no key could be read; nothing was changed", _USAGE),
    "credential_store_unavailable": (
        "neither the platform credential store nor the owner-only key file could be used",
        _UNAVAILABLE,
    ),
    "runtime_unavailable": (
        "this FinishUP build has no client runtime for that kind of server target",
        _UNAVAILABLE,
    ),
    # A server elsewhere (SSH, HTTPS or a port) is confirmed again with 'finishup server use NAME'
    # on the owner's terminal.
    "target_reauthorization_required": (
        "this server target was authorized under an older disclosure of what leaves this "
        "computer, so nothing was sent to it; agree to the current one with 'finishup server use "
        "NAME' on your own terminal (an SSH or HTTPS server), or use a server on this computer ('finishup "
        "server use local')",
        _USAGE,
    ),
    "usage": (
        "give --local for a named local server on this computer, an ssh://[user@]host[:port] or "
        "https://host[:port] address for a server elsewhere, or --port PORT for one on this "
        "computer's HTTPS port",
        _USAGE,
    ),
    "remote_unreachable": (
        "the server could not be reached; check the address and your network, then retry",
        _UNAVAILABLE,
    ),
    "remote_auth_failed": (
        "the server answered and refused this client's key: load your SSH key (ssh-add) for an "
        "SSH server, or give a valid API key for an HTTPS server",
        _UNAVAILABLE,
    ),
    # 'server add ssh://' (ADR-052): a socket path OpenSSH would not take verbatim (it splits on
    # ':' and expands '%' tokens and '${VAR}'), here or on the server; spaces are fine.
    "ssh_path_unusable": (
        "OpenSSH cannot use a socket path of this server as written (this computer's FinishUP "
        "folder, or the server's FinishUP endpoint, holds ':', '%' or '$'), so nothing was added; "
        "move that FinishUP folder or give the server a --remote-root without those characters",
        _UNSAFE,
    ),
    # 'server add ssh://' (ADR-051 decision 7): OpenSSH asked to confirm a host key this computer
    # does not know yet, on the owner's terminal, and the owner declined or did not answer.
    "remote_host_key_unconfirmed": (
        "the server's SSH host key was not confirmed (OpenSSH's question was declined or not "
        "answered), so nothing was added; run 'finishup server add' again and answer yes to "
        "OpenSSH's question once you have checked the fingerprint with the server's own",
        _UNAVAILABLE,
    ),
    "remote_identity_changed": (
        "the server's host key or certificate was not accepted; verify it another way first",
        _UNAVAILABLE,
    ),
    "remote_incompatible": (
        "this client and the server run different FinishUP releases; install the same release "
        "on both",
        _UNAVAILABLE,
    ),
    "remote_service_not_running": (
        "the server answered but its FinishUP service is not running; start it there with "
        "'finishup service start'",
        _UNAVAILABLE,
    ),
    # The consent step (ADR-052): what the server offers or needs, against the owner's consent.
    "server_profile_changed": (
        "what that server offers or needs could not be agreed to here (it changed, it is not one "
        "this release understands, or it could not be read), so nothing was changed",
        _USAGE,
    ),
    "server_level_unavailable": (
        "that server does not offer the level or retention asked for, or it requires more than "
        "the level chosen (level L2, a copy of your code kept there, is offered only when the "
        "server's owner turns it on, with the retentions they allow), so nothing was changed",
        _USAGE,
    ),
    "style_invalid": ("give --style relay or --style direct", _USAGE),
    "style_not_applicable": (
        "only an SSH or HTTPS server has a connection style; a server on this computer is reached "
        "directly",
        _USAGE,
    ),
    # 'finishup server add official' (ADR-053, design v2 section 2.4): no official FinishUP
    # service is named by this release yet.
    "official_endpoint_unavailable": (
        "this release names no official FinishUP service yet, so nothing was added; add a server "
        "by its address with 'finishup server add NAME https://HOST'",
        _USAGE,
    ),
    "style_unavailable": (
        "that server's profile does not offer that connection style, so nothing was changed",
        _USAGE,
    ),
    "remote_launcher_not_found": (
        "no FinishUP launcher was found on that server at the usual install paths "
        "(~/.local/bin, /opt/homebrew/bin, /usr/local/bin, /usr/bin), so nothing was added; give "
        "its absolute path with --remote-launcher",
        _UNAVAILABLE,
    ),
    "target_still_connected": (
        "the connection this client runs for that target did not stop in time, so nothing was "
        "removed; run the same command again",
        _UNAVAILABLE,
    ),
    "target_partly_removed": (
        "the target's folder changed while it was being deleted, so only part of it was removed; "
        "run the same command again, or, if 'finishup server list' names a leftover folder "
        "instead, 'finishup server remove' with that folder's id",
        _UNAVAILABLE,
    ),
    # 'server repositories' (ADR-051 decision 8, 2026-11-07, round 4): fixed text, never a path.
    "repositories_not_applicable": (
        "name or select a server on another machine, a port or the web: a server on this "
        "computer applies this computer's own privacy policy to each repository, so nothing is "
        "held for it",
        _USAGE,
    ),
    "repository_invalid": (
        "give a folder inside a project FinishUP can name: not /, and one Git or this computer "
        "can resolve",
        _USAGE,
    ),
    "repository_limit": (
        "FinishUP already keeps the most repository choices it allows for that server (64); "
        "remove one first with 'finishup server repositories remove'",
        _USAGE,
    ),
    "repositories_record_invalid": (
        "the record of which repositories that server receives anyway or keeps here is damaged, "
        "so it receives none of them (each is held); repair it on this computer with 'finishup "
        "server repositories remove NAME --all', then run this command again",
        _UNSAFE,
    ),
    "repositories_record_unsafe": (
        "the record of which repositories that server receives anyway or keeps here is not "
        "owner-only or is a link, so it receives none of them (each is held); repair it on this "
        "computer with 'finishup server repositories remove NAME --all', then run this command "
        "again",
        _UNSAFE,
    ),
    # 'server code forget --all' and 'server remove' (level L2, ADR-054): fixed text, no path.
    "code_copy_forget_incomplete": (
        "not every copy on that server was forgotten; each line above says why and what to do, "
        "and each stays there until it expires or is forgotten",
        _UNAVAILABLE,
    ),
    "code_copy_deletion_unfinished": (
        "that server could not finish deleting its copy yet; what it deleted is named above, the "
        "rest stays fenced there and its deletion is retried; run the same command again later",
        _UNAVAILABLE,
    ),
    "code_copy_fence_unavailable": (
        "this computer could not stop sending copies of code to that server while it forgets "
        "them (its folder for that server could not be written), so the target was not removed "
        "and nothing more was forgotten; check that folder's owner and permissions, then run "
        "the same command again",
        _UNSAFE,
    ),
    "code_export_unsafe": (
        "this computer's record of the copies it sent that server is not owner-only or is a "
        "link, so which repositories they came from is not known; fix its permissions, or run "
        "'finishup server code forget' in each repository",
        _UNSAFE,
    ),
}

DISCLOSURE_LINES: Final = (
    "Authorize a FinishUP server target (disclosure {version})",
    "",
    "Sent to that server: task statements, published work, evidence, and check, respond,",
    "and receipt traffic.",
    "When it checks or reviews your work, the FinishUP workspace agent on this computer reads",
    "what it asks for (the change being checked, bounded file excerpts for review, declared",
    "task inputs, and results of checks you approved in .finishup/checks.toml) and sends it,",
    "labelled as read on this computer.",
    "Hook observations of projects where you gave observation consent are sent too. From",
    "Codex, and from Claude Code or Cursor once you turn on content capture for a project,",
    "they can hold what the agent was shown and did: your prompts, its messages, and tool",
    "inputs and outputs, which can name file paths on this computer and hold the contents",
    "of files it read, even outside your project or the folders you list for that server.",
    "That server keeps them as FinishUP on this computer would.",
    "Your project folder is named by a keyed label, not its path.",
    "A project whose privacy policy on this computer allows no network use is held: nothing from it",
    "is sent until you allow it with 'finishup server repositories add'.",
    "This is your decision on this terminal, not a vault re-authentication. Undo it with",
    "'finishup server use local' or 'finishup server remove'.",
    "",
)


class ServerCommandRefused(Exception):
    """A refused ``finishup server`` step: closed reason and detail tokens, fixed message text,
    and the registered recovery directive (``continuation``) its lines follow, when it has one."""

    def __init__(
        self,
        reason: str,
        *,
        detail: str | None = None,
        message: str | None = None,
        continuation: str | None = None,
    ) -> None:
        self.reason = reason
        self.detail = detail
        self.message = message
        self.continuation = continuation
        super().__init__(reason)


_DEFAULT_REMEDY: Final = "the server target did not respond as needed"
ROOT_UNUSABLE_MESSAGE: Final = (
    "this process's FinishUP root cannot be used; 'finishup service isolation' explains which "
    "source decided it"
)


def refusal_message(error: ServerCommandRefused) -> str:
    """The fixed text for a refusal (never owner-typed), with its closed detail."""

    remedy, _code = _REMEDIES.get(error.reason, (_DEFAULT_REMEDY, _UNAVAILABLE))
    text = error.message or remedy
    return text if error.detail is None else f"{text} ({error.detail})"


def _fail(
    reason: str,
    *,
    detail: str | None = None,
    message: str | None = None,
    continuation: str | None = None,
) -> NoReturn:
    _remedy, code = _REMEDIES.get(reason, (_DEFAULT_REMEDY, _UNAVAILABLE))
    text = refusal_message(ServerCommandRefused(reason, detail=detail, message=message))
    typer.echo(f"{reason}: {text}", err=True)
    if continuation is not None:
        from finishup.cli.render import render_recovery_directive_lines
        from finishup.protocol.recovery import directive_for

        directive = directive_for(continuation)
        if directive is not None:
            for line in render_recovery_directive_lines(directive):
                typer.echo(line, err=True)
    raise typer.Exit(code)


def _cli[**P](command: Callable[P, None]) -> Callable[P, None]:
    """Render a ``ServerCommandRefused`` as one bounded line and its exit code."""

    @functools.wraps(command)
    def run(*args: P.args, **kwargs: P.kwargs) -> None:
        try:
            command(*args, **kwargs)
        except ServerCommandRefused as error:
            _fail(
                error.reason,
                detail=error.detail,
                message=error.message,
                continuation=error.continuation,
            )
        except TargetError as error:
            _fail(error.reason)
        except PathSafetyError as error:
            # The everyday folders themselves cannot be chosen (for example data under both
            # product names): the registry lives there, so nothing can be read or written.
            _fail(error.reason_code, message=ROOT_UNUSABLE_MESSAGE)

    return run


def _runtime_failure(error: TargetRuntimeError) -> NoReturn:
    from finishup.protocol.errors import REMOTE_CONNECTION_PHASES

    if error.reason == "service_unavailable" and error.phase in REMOTE_CONNECTION_PHASES:
        # The phase is the reason; the connection's own ``service_unavailable`` adds nothing the
        # owner can act on (RE-7), so it is not printed beside it.
        raise ServerCommandRefused(error.phase)
    if error.phase == "runtime_unavailable":
        raise ServerCommandRefused(
            "runtime_unavailable", detail=f"{error.reason}, phase {error.phase}"
        )
    raise ServerCommandRefused(
        error.reason, detail=None if error.phase is None else f"phase {error.phase}"
    )


def _explicit_source_present() -> bool:
    """Whether the isolation variable or a runtime pin decides this process's root.

    Read without resolving the selection, so the ways back from a damaged or dangling selection
    (``use local``, ``remove --select-local``) still work. A variable or pin that cannot be used is
    still an explicit source: it fails closed with its own path-safety reason.
    """

    from finishup.config.paths import isolated_root_variable, read_runtime_pin

    try:
        return isolated_root_variable() is not None or read_runtime_pin() is not None
    except PathSafetyError as error:
        raise ServerCommandRefused(error.reason_code, message=ROOT_UNUSABLE_MESSAGE) from None


def _source() -> str:
    try:
        return selection_source()
    except PathSafetyError as error:
        if not _explicit_source_present():
            # Neither the variable nor a pin is set, so the selection is what cannot be used: a
            # damaged file, or a missing or unsafe target folder. Its remedy works from here.
            raise ServerCommandRefused("selection_invalid") from None
        raise ServerCommandRefused(error.reason_code, message=ROOT_UNUSABLE_MESSAGE) from None


def _require_selection_in_force() -> None:
    """Refuse while the isolation variable or a runtime pin outranks the selection."""

    if _source() in _EXPLICIT_SOURCES:
        raise ServerCommandRefused("selection_overridden")


def _require_no_explicit_source() -> None:
    """``_require_selection_in_force`` without resolving the selection (the ways back)."""

    if _explicit_source_present():
        raise ServerCommandRefused("selection_overridden")


def _target_or_fail(name: str) -> ServerTarget:
    try:
        return find_target(name)
    except TargetError as error:
        raise ServerCommandRefused(error.reason)


def _location(record: ServerTarget | None) -> str | None:
    if record is None or record.kind == "local":
        return None
    if record.kind == "ssh":
        host = cast(str, record.host)
        authority = f"[{host}]" if ":" in host else host
        user = "" if record.user is None else f"{record.user}@"
        return f"ssh://{user}{authority}:{record.port}"
    return record.base_url


def _selected_or_unknown(record: ServerTarget) -> bool:
    """Whether the selection on disk names ``record``, or cannot be read (so it may)."""

    try:
        return read_selected_target_id() == record.target_id
    except (TargetError, PathSafetyError):
        return True


@dataclass(frozen=True, slots=True)
class ZeroNetworkRefusal:
    """Why nothing is sent to a remote target now, and when this computer reported zero-network."""

    refused: ServerCommandRefused
    # The marker's fixed-shape UTC time (``client.everyday_policy``).
    reported_at: str


def zero_network_connection_refusal(record: ServerTarget | None) -> ServerCommandRefused | None:
    """The refusal of ``zero_network_refusal``, for a command that acts on ``record``."""

    found = zero_network_refusal(record)
    return None if found is None else found.refused


def zero_network_refusal(record: ServerTarget | None) -> ZeroNetworkRefusal | None:
    """Why nothing is sent to remote ``record`` now, when this computer last reported zero-network.

    The connection check (``targets.require_current_authorization``) refuses every remote target
    while this computer last reported a zero-network policy (ADR-051 decision 8). A command that
    acts on one target names that refusal with the one command that fixes it for that target:

    * the selected target, or any target while the selection cannot be read:
      ``zero_network_remote_selected``, fixed by ``finishup server use local``;
    * any other remote target: nothing uses it, so switching would change nothing. This
      computer's own policy is what stands in the way: ``zero_network_in_force``, saying when it
      was reported and that the privacy policy on this computer must change first.

    ``None`` for a record that is not remote, or while the marker does not say zero-network (it is
    never read under an isolation variable or runtime pin). Only generated ids and a fixed-shape
    time are in the text.
    """

    if record is None or not record.is_remote:
        return None
    from finishup.client.everyday_policy import last_reported_zero_network

    reported = last_reported_zero_network()
    if reported is None:
        return None
    if _selected_or_unknown(record):
        return ZeroNetworkRefusal(
            ServerCommandRefused("zero_network_remote_selected"), reported.reported_at
        )
    return ZeroNetworkRefusal(
        ServerCommandRefused(
            "zero_network_in_force",
            message=(
                f"this computer's FinishUP last reported, at {reported.reported_at}, that it "
                f"makes no network connections, so nothing was sent to server target "
                f"{record.target_id}; to use a server on another machine, change the privacy "
                "policy on this computer first, with 'finishup privacy setup'"
            ),
        ),
        reported.reported_at,
    )


def _open_kind(kind: str) -> bool:
    """Whether connections to ``kind`` are open in this release (none are: ADR-052)."""

    from finishup.client import authorization

    return kind in authorization.OPEN_REMOTE_KINDS


def _zero_network_in_force() -> bool:
    """Whether this computer is in the zero-network state that refuses a remote hop (ADR-051).

    Every remote kind is a hop, ``local_port`` included: a loopback port can forward anywhere.
    This computer's own FinishUP decides (``zero_network_selection.everyday_network_state``): its
    everyday installation's effective machine-scope policy, when it was set up. A policy that does
    not permit network egress is the zero-network state. One that cannot be read now (the service
    is stopped, locked, or does not answer, or the installation's identity cannot be read) falls
    back to what this computer last reported (``client.everyday_policy``, maintainer decision of
    2026-11-07): last reported zero-network refuses as ``zero_network_in_force``, saying when;
    anything else refuses with ``network_policy_unreadable``, never allows the hop. A computer
    whose everyday FinishUP was never set up has no policy of its own, so nothing here refuses it.
    Asked before any profile is fetched, any console opens or anything is written.
    """

    from finishup.cli.zero_network_selection import everyday_network_state

    state = everyday_network_state()
    if state == "unreadable":
        from finishup.client.everyday_policy import last_reported_zero_network

        reported = last_reported_zero_network()
        if reported is not None:
            raise ServerCommandRefused(
                "zero_network_in_force",
                message=(
                    f"this computer's FinishUP last reported, at {reported.reported_at}, that it "
                    "makes no network connections, and it cannot be asked now (its service is "
                    "stopped or locked), so it cannot use a server on another machine; change "
                    "the privacy policy on this computer first, with 'finishup privacy setup'"
                ),
            )
        # While any server is selected, 'service start' and 'service unlock' never reach this
        # computer's own FinishUP: they are refused (requires_server_host) for one elsewhere and
        # act on a named local one. Name the way that works from this state (SRV-3).
        raise ServerCommandRefused(
            "network_policy_unreadable",
            message=_POLICY_UNREADABLE_WHILE_SELECTED if _a_server_is_selected() else None,
        )
    return state == "zero_network"


def _a_server_is_selected() -> bool:
    """Whether this process uses a selected server, of any kind, rather than this computer's own.

    Never raises: a root whose record cannot be read counts (it may name a server elsewhere), and
    a root that cannot be resolved does not (the remedy every local root gets).
    """

    from finishup.client.targets import TargetRecordUnreadable

    try:
        return active_target_record() is not None
    except TargetRecordUnreadable:
        return True
    except TargetError:
        return False


_POLICY_UNREADABLE_WHILE_SELECTED: Final = (
    "this computer's FinishUP has its own privacy policy, which could not be read (its service "
    "is stopped, locked, or did not answer), so a server on another machine is refused; start "
    "it with 'finishup server connect local' and retry, or, if its vault is locked, run "
    "'finishup server use local', then 'finishup service unlock', then choose the server again"
)


def check_remote_hop() -> None:
    """Refuse a remote hop in the zero-network state, as ``server use`` does before its prompt.

    Asks this computer's FinishUP for its policy through its own event loop: call it off any
    running loop (the terminal interface runs it in a worker thread).
    """

    if _zero_network_in_force():
        raise ServerCommandRefused("zero_network_in_force")


def _absolute_option(value: str | None) -> str | None:
    """An absolute remote path option, checked before any profile is fetched or console opens
    (SRV-11)."""

    if value is not None and (
        not value.startswith("/")
        or len(value) > 1_024
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ServerCommandRefused("target_path_invalid")
    return value


# What the owner is told of a server's profile, in this release's own words only (design v2
# section 8.8: never the server's prose). Level L1 is the one level a server elsewhere offers here.
_LEVEL_LINES: Final[dict[str, tuple[str, ...]]] = {
    "L1": (
        "Level of use: that server keeps your tasks, its ledger and reviews; your code stays on",
        "this computer, and the server reads it only through the FinishUP workspace agent here.",
    ),
    # Level L2 (design v2 section 4.4, ADR-054): locally owned text only, never server prose.
    "L2": (
        "Level of use: that server keeps your tasks, its ledger and reviews, and a copy of each",
        "repository you use with it: its git-visible files (tracked, and untracked but not",
        "ignored), never its history, minus the names this release always leaves out, that",
        "server's own exclusions and your list for the repository. The names of the files left",
        "out are sent, never their contents. Before a file is sent its content is scanned for",
        "known secret formats, and a match is held back until you allow it. Names and scans are",
        "not a guarantee that no secret is sent.",
    ),
}
_RETENTION_LINES: Final[dict[str, str]] = {
    "task_close": "That server keeps each copy until the tasks that read it are closed.",
    "until_forgotten": "That server keeps each copy until you forget it.",
}
_PROVIDER_NAMES: Final[dict[str, str]] = {
    "anthropic": "Anthropic",
    "fireworks": "Fireworks",
    "google": "Google",
    "openai": "OpenAI",
    "openai-codex": "OpenAI Codex",
    "openai-compatible": "an OpenAI-compatible endpoint its owner declared",
    "openrouter": "OpenRouter",
    "vercel-ai-gateway": "Vercel AI Gateway",
    "xai": "xAI",
}


def _provider_name(token: str | None) -> str:
    return _PROVIDER_NAMES.get(token or "", "a provider this release does not name")


def profile_disclosure_lines(envelope: ConsentEnvelope) -> tuple[str, ...]:
    """The disclosure lines of what using a server under ``envelope`` means (ADR-052)."""

    review = envelope.review
    if review.ai_review == "none":
        review_lines: tuple[str, ...] = (
            "That server states it sends nothing it reads to an AI-powered review provider.",
        )
    else:
        provider = _provider_name(review.provider_disclosure)
        if review.fallback_disclosure is None:
            review_lines = (
                "That server's AI-powered review may send what it reads to a model provider",
                f"({provider}), as that server's own privacy policy decides.",
            )
        else:
            # Every provider it may send to is named: the fallback too (ADR-052).
            review_lines = (
                "That server's AI-powered review may send what it reads to a model provider",
                f"({provider}) and, when that one fails, to another "
                f"({_provider_name(review.fallback_disclosure)}),",
                "as that server's own privacy policy decides.",
            )
    copy_lines: tuple[str, ...] = ()
    if envelope.level == "L2" and envelope.retention is not None:
        retention = envelope.retention
        kept = (
            f"That server keeps each copy for {retention.days} days after its last sync."
            if retention.kind == "days"
            else _RETENTION_LINES[retention.kind]
        )
        copy_lines = (
            kept,
            "'finishup server code forget' deletes a copy there; 'finishup server code level L1'",
            "keeps one repository at level L1. Stopping or holding a repository later does not",
            "remove what was already sent; only forget does.",
        )
    return (
        *_LEVEL_LINES[envelope.level],
        *copy_lines,
        *review_lines,
        "Checks you approved still run on this computer.",
        "",
    )


# The add-time question may be answered wrongly a few times before nothing is added.
_MODE_ATTEMPTS: Final = 3


def _confirm_on_trusted_console(
    name: str,
    kind: str,
    profile_lines: tuple[str, ...],
    *,
    ask_mode: bool = False,
    decided: OutsideReadMode | None = None,
    official: bool = False,
) -> OutsideReadMode | None:
    """Show the versioned disclosure and require the owner to type the target name.

    ``profile_lines`` say, in this release's words, what the server's profile means here (the
    level and its review egress). At ``server add`` the owner also answers what the server may
    read outside their projects here (ADR-051 decision 5), before typing the name, which then
    authorizes both: with ``ask_mode`` the question is asked and the answer returned; otherwise the
    mode already decided, by ``--outside-reads`` (``decided``) or as an ``official`` endpoint, is
    shown. When the owner chooses ``local`` the notice of what that mode lets the server read
    comes before the typed name. ``server use`` asks no mode. Returns the mode answered, or None.
    """

    from finishup.cli.trusted_console import TrustedConsoleError, TrustedForegroundConsole

    answered: OutsideReadMode | None = None
    try:
        with TrustedForegroundConsole() as console:
            for line in DISCLOSURE_LINES:
                console.write(line.format(version=DISCLOSURE_VERSION) + "\n")
            for line in profile_lines:
                console.write(line + "\n")
            console.write(f"Target: {name}, {_kind_label(kind)}.\n")
            if ask_mode:
                answered = _ask_outside_reads(console, name)
            else:
                mode_line = _decided_mode_line(decided, official=official)
                if mode_line is not None:
                    console.write(mode_line + "\n")
            if (answered or decided) == "local":
                console.write("\n")
                for line in _LOCAL_MODE_BODY:
                    console.write(line.format(name=name) + "\n")
                console.write("\n")
            console.read_choice(
                "Type the target name to authorize it (anything else cancels): ",
                (name.encode("ascii"),),
            )
    except TrustedConsoleError as error:
        if error.reason == "trusted_console_required":
            raise ServerCommandRefused("trusted_console_required") from None
        raise ServerCommandRefused("authorization_declined") from None
    return answered


def _ask_outside_reads(console: TrustedForegroundConsole, name: str) -> OutsideReadMode:
    """Ask which outside-read mode the new target gets; an explicit answer is required.

    One plain line per mode, the same for every remote kind. Enter alone or another word asks
    again, a few times; then, or at end of input or an interrupt, nothing is added
    (``outside_reads_not_chosen``), with the way to answer next time.
    """

    from finishup.cli.trusted_console import TrustedConsoleError
    from finishup.client.server_folders import OUTSIDE_READ_MODE_LINES, OUTSIDE_READ_QUESTION

    console.write("\n" + OUTSIDE_READ_QUESTION + "\n")
    for mode in ("local", "listed"):
        console.write(f"  {mode.ljust(6)}  {OUTSIDE_READ_MODE_LINES[mode]}\n")
    console.write(
        f"You can change it later with 'finishup server folders mode {name} local' or "
        f"'finishup server folders mode {name} listed'.\n"
    )
    for attempt in range(_MODE_ATTEMPTS):
        if attempt:
            console.write("Please type local or listed.\n")
        try:
            answer = console.read_choice("Type local or listed: ", (b"local", b"listed"))
        except TrustedConsoleError as error:
            if error.reason in {"empty_input", "input_invalid"}:
                continue
            if error.reason == "trusted_console_required":
                raise
            raise ServerCommandRefused("outside_reads_not_chosen") from None
        return "local" if answer == b"local" else "listed"
    raise ServerCommandRefused("outside_reads_not_chosen")


def _decided_mode_line(mode: OutsideReadMode | None, *, official: bool) -> str | None:
    """The console line for a mode decided before ``server add`` asks: by ``--outside-reads``,
    or as an official FinishUP endpoint. None when the question is asked."""

    if mode == "local":
        return (
            "Outside your projects it will read what FinishUP on this computer would read "
            "(mode local, from --outside-reads)."
        )
    if mode == "listed":
        return (
            "Outside your projects it will read only folders you list for it (mode listed, from "
            "--outside-reads)."
        )
    if official:
        return (
            "Outside your projects it will read what FinishUP on this computer would read "
            "(mode local): it is an official FinishUP server."
        )
    return None


def confirm_use_on_this_thread(name: str, kind: str, profile_lines: tuple[str, ...]) -> None:
    """``server use``'s disclosure and typed confirmation, read on the calling thread (SRV-6).

    Call it on the main thread (the terminal interface's event loop thread, with the terminal
    handed over): Ctrl-C then reaches the read and cancels the confirmation, as it does for the
    zero-network choice, instead of a read in a worker thread that no interrupt reaches while the
    event loop tears the interface down.
    """

    from finishup.cli.zero_network_selection import interrupt_answers_the_prompt

    try:
        with interrupt_answers_the_prompt():
            _confirm_on_trusted_console(name, kind, profile_lines)
    except KeyboardInterrupt:
        raise ServerCommandRefused("authorization_declined") from None


def _fetch_profile(record: ServerTarget) -> FetchedProfile:
    """The profile of ``record``'s server over its own transport, after the zero-network check.

    No transport exists in this release for any kind (``client.server_profile.PROFILE_SOURCES``
    is empty), so a kind opened in a test without a source refuses ``remote_kind_unavailable``.
    """

    from finishup.cli.trusted_console import TrustedConsoleError
    from finishup.client.server_profile import PROFILE_SOURCES

    loader = PROFILE_SOURCES.get(record.kind)
    if loader is None:
        raise ServerCommandRefused("remote_kind_unavailable")
    try:
        return loader().fetch(record)
    except TrustedConsoleError:
        raise ServerCommandRefused("trusted_console_required") from None
    except TargetRuntimeError as error:
        if error.reason in {"remote_host_key_unconfirmed", "trusted_console_required"}:
            raise ServerCommandRefused(error.reason) from None
        _runtime_failure(error)
    except TargetError as error:
        raise ServerCommandRefused(error.reason) from None


@dataclass(frozen=True, slots=True)
class LevelChoice:
    """The level and retention the owner asked for (``--level``, ``--retention``); ``None``
    keeps level L1 (or, for ``server use``, the level already consented to)."""

    level: str | None = None
    retention: str | None = None


def _retention_of(value: str) -> Retention:
    from finishup.protocol.consent_envelope import EnvelopeError, retention_from_token

    try:
        return retention_from_token(value)
    except EnvelopeError:
        raise ServerCommandRefused(
            "usage", message="--retention is task_close, until_forgotten or days:N"
        ) from None


def _chosen_terms(
    fetched: FetchedProfile, choice: LevelChoice, stored: ServerTarget | None = None
) -> tuple[str, Retention | None]:
    """The level and retention to consent to (design v2 sections 2.3 and 4.3, U11)."""

    from finishup.protocol.server_copy import l2_released
    from finishup.protocol.server_profile import ProfileError, profile_from_json

    level = choice.level
    retention_text = choice.retention
    consent = None if stored is None else stored.consent
    if level is None and consent is not None and consent.level == "L2" and l2_released():
        # 'server use' keeps the level and retention already agreed to.
        level = "L2"
        if retention_text is None and consent.retention_kind is not None:
            retention_text = (
                f"days:{consent.retention_days}"
                if consent.retention_kind == "days"
                else consent.retention_kind
            )
    if level in {None, "L1"}:
        if retention_text is not None:
            raise ServerCommandRefused("usage", message="--retention applies to --level L2 only")
        return "L1", None
    if level != "L2":
        raise ServerCommandRefused("usage", message="--level is L1 or L2")
    if not l2_released():
        raise ServerCommandRefused("server_level_unavailable")
    try:
        profile = profile_from_json(fetched.document)
    except ProfileError:
        raise ServerCommandRefused("server_profile_changed") from None
    if "L2" not in profile.levels.offered or profile.retention is None:
        raise ServerCommandRefused("server_level_unavailable")
    if retention_text is None:
        return "L2", profile.retention.default
    retention = _retention_of(retention_text)
    if retention not in profile.retention.options:
        raise ServerCommandRefused(
            "usage",
            message="that server does not offer this retention; see 'finishup server status'",
        )
    return "L2", retention


def _consent_offer(
    record: ServerTarget,
    fetched: FetchedProfile,
    choice: LevelChoice | None = None,
    stored: ServerTarget | None = None,
) -> tuple[ConsentEnvelope, tuple[str, ...]]:
    """The envelope the owner is asked to consent to (level L1 unless ``choice`` asks for L2),
    and its disclosure lines.

    Refused before any console: a profile this release cannot read or understand
    (``server_profile_changed``), one requiring more than the level chosen, or a level or
    retention it does not offer (``server_level_unavailable``).
    """

    from finishup.client.server_profile import consent_envelope_for

    level, retention = _chosen_terms(fetched, choice or LevelChoice(), stored)
    try:
        envelope, _profile = consent_envelope_for(record, fetched, level=level, retention=retention)
    except TargetError as error:
        raise ServerCommandRefused(error.reason) from None
    return envelope, profile_disclosure_lines(envelope)


def _emit(lines: tuple[str, ...]) -> None:
    for line in lines:
        typer.echo(line)


def _warn_open_sessions() -> None:
    from finishup.cli.zero_network_selection import OPEN_SESSIONS_LINE

    typer.echo(OPEN_SESSIONS_LINE)


# Level L2 (ADR-054): the level and, at L2, the retention among those the server offers.
_LEVEL_OPTION = Annotated[
    str | None,
    typer.Option(
        "--level",
        help="L1 (the default) or L2: whether the server also keeps a copy of your code.",
    ),
]
_RETENTION_OPTION = Annotated[
    str | None,
    typer.Option(
        "--retention",
        help="L2: how long it keeps a copy (task_close, until_forgotten, days:N) among its options.",
    ),
]


@server_app.command("add")
@_cli
def server_add(
    name: Annotated[str, typer.Argument(help="Target name: 1-16 lowercase letters, digits, -.")],
    address: Annotated[
        str | None,
        typer.Argument(
            help="ssh://USER@HOST:PORT (user and port optional) or https://HOST:PORT/BASE (port "
            "and base optional); omit with --local or --port."
        ),
    ] = None,
    local: Annotated[
        bool, typer.Option("--local", help="A named local server on this computer.")
    ] = False,
    port: Annotated[
        int | None,
        typer.Option("--port", help="A FinishUP server on this computer's HTTPS port PORT."),
    ] = None,
    remote_root: Annotated[
        str | None,
        typer.Option(
            "--remote-root",
            help="SSH: the server's FinishUP root (absolute), when it runs an isolated one.",
        ),
    ] = None,
    remote_launcher: Annotated[
        str | None,
        typer.Option(
            "--remote-launcher",
            help="SSH: the absolute path of the server's finishup (else the usual install paths).",
        ),
    ] = None,
    ca_file: Annotated[
        Path | None,
        typer.Option("--ca-file", help="HTTPS: trust only this CA (PEM) for the server."),
    ] = None,
    tls_pin: Annotated[
        str | None,
        typer.Option("--tls-pin", help="HTTPS: trust only this certificate (sha256:HEX)."),
    ] = None,
    key_file: Annotated[
        Path | None,
        typer.Option("--key-file", help="HTTPS: read the API key once from an owner-only file."),
    ] = None,
    outside_reads: Annotated[
        str | None,
        typer.Option(
            "--outside-reads",
            help="local or listed: what the server may read outside your projects here.",
        ),
    ] = None,
    level: _LEVEL_OPTION = None,
    retention: _RETENTION_OPTION = None,
) -> None:
    """Add a server: a named local one on this computer, an SSH server, or an HTTPS server.

    'finishup server add official' adds the official FinishUP service this release names (none
    yet). An HTTPS server asks for its API key on your terminal (hidden) unless --key-file gives
    it, and the server is checked before anything is kept.
    """

    if name == "official" and address is None and port is None and not local:
        # The preset (design v2 section 2.4): the URL of the official FinishUP service this
        # release pins, never the server's own claim.
        from finishup.client.server_folders import official_preset_url

        address = official_preset_url()
        if address is None:
            raise ServerCommandRefused("official_endpoint_unavailable")
    if (port is not None or address is not None) and not local:
        from finishup.client import authorization

        # The kind is told by the arguments alone (the address is never parsed for this): a kind
        # closed in this build (an address this release names none of) is refused before the
        # selection, the name, any prompt, policy check, probe or write.
        if kind_of_arguments(address, port) not in authorization.OPEN_REMOTE_KINDS:
            raise ServerCommandRefused("remote_kind_unavailable")
        _add_remote(
            name,
            address,
            port,
            remote_root=remote_root,
            remote_launcher=remote_launcher,
            ca_file=ca_file,
            tls_pin=tls_pin,
            key_file=key_file,
            outside_reads=outside_reads,
            choice=LevelChoice(level, retention),
        )
        return
    if level is not None or retention is not None:
        raise ServerCommandRefused(
            "usage", message="--level and --retention apply to a server elsewhere"
        )
    _require_selection_in_force()
    try:
        validate_name(name)
    except TargetError as error:
        raise ServerCommandRefused(error.reason)
    if not local or port is not None or address is not None:
        raise ServerCommandRefused("usage")
    if any(
        option is not None
        for option in (remote_root, remote_launcher, ca_file, tls_pin, key_file, outside_reads)
    ):
        raise ServerCommandRefused(
            "usage",
            message=(
                "--remote-root, --remote-launcher, --ca-file, --tls-pin and --outside-reads are "
                "for a server on another machine, a port or the web; a server on this computer "
                "takes none of them"
            ),
        )
    try:
        taken = any(record.name == name for record in list_targets())
    except TargetError as error:
        raise ServerCommandRefused(error.reason)
    if taken:
        raise ServerCommandRefused("target_name_taken")
    try:
        with registry_lock():
            from finishup.client.targets import new_local_target

            record, _root = new_local_target(name)
    except TargetError as error:
        raise ServerCommandRefused(error.reason)
    typer.echo(f"Added server target {record.name} ({record.target_id}, {record.kind}).")
    _emit(
        (
            f"Select it with 'finishup server use {record.name}', then run 'finishup setup' "
            "to set up its vault.",
        )
    )


def kind_of_arguments(address: str | None, port: int | None) -> str:
    """The kind ``server add``'s arguments name, by their prefix alone (nothing is parsed):
    ``local_port`` for ``--port`` or an ``https://`` loopback address, ``https``, ``ssh``, or
    ``other`` for anything else (refused as a closed kind before anything is asked)."""

    if port is not None:
        return "local_port"
    text = address or ""
    if text.startswith("ssh://"):
        return "ssh"
    if text.startswith(("https://127.0.0.1:", "https://[::1]:")):
        return "local_port"
    if text.startswith("https://"):
        return "https"
    return "other"


def _remote_location(
    address: str | None, port: int | None
) -> tuple[TargetKind, str | None, str | None, str | None, int | None]:
    """The kind and location fields an address names: ``(kind, base_url, user, host, port)``."""

    from finishup.client.targets import normalize_https_url, parse_ssh_url

    try:
        if port is not None:
            if address is not None:
                raise ServerCommandRefused("usage")
            return (
                "local_port",
                normalize_https_url(f"https://127.0.0.1:{port}", loopback_only=True),
                None,
                None,
                None,
            )
        text = cast(str, address)
        if text.startswith("ssh://"):
            user, host, ssh_port = parse_ssh_url(text)
            return "ssh", None, user, host, ssh_port
        base_url = normalize_https_url(text)
    except TargetError as error:
        raise ServerCommandRefused(error.reason) from None
    # ``https://127.0.0.1:PORT`` and ``https://[::1]:PORT`` are this computer's loopback ports.
    loopback = base_url.startswith(("https://127.0.0.1:", "https://[::1]:"))
    return ("local_port" if loopback else "https"), base_url, None, None, None


def _add_remote(
    name: str,
    address: str | None,
    port: int | None,
    *,
    remote_root: str | None,
    remote_launcher: str | None,
    ca_file: Path | None,
    tls_pin: str | None,
    outside_reads: str | None,
    key_file: Path | None = None,
    choice: LevelChoice | None = None,
) -> None:
    """``server add`` for a server elsewhere, once its kind is open.

    In order, before anything is written: the selection in force and the name; the address and
    its options, remote paths absolute (SRV-11); the name not taken; this computer's zero-network
    state (SRV-3); the server's profile over its own transport (a kind with none is
    ``remote_kind_unavailable``); the envelope of using it at level L1, refused when this release
    cannot agree to it. Then, on the trusted console only, the disclosure with what the profile
    means here, the outside-read question (ADR-051 decision 5) and the typed name. Then, under the
    registry lock, the record, its consent (ADR-052) and the mode answered.
    """

    from finishup.client.server_folders import OUTSIDE_READ_MODES, official_address
    from finishup.client.targets import ServerTarget as _Target

    _require_selection_in_force()
    try:
        validate_name(name)
    except TargetError as error:
        raise ServerCommandRefused(error.reason) from None
    kind, base_url, user, host, ssh_port = _remote_location(address, port)
    if not _open_kind(kind):
        raise ServerCommandRefused("remote_kind_unavailable")
    if outside_reads is not None and outside_reads not in OUTSIDE_READ_MODES:
        raise ServerCommandRefused("outside_read_mode_invalid")
    if (remote_root is not None or remote_launcher is not None) and kind != "ssh":
        raise ServerCommandRefused("usage")
    if (ca_file is not None or tls_pin is not None) and kind == "ssh":
        raise ServerCommandRefused("target_tls_invalid")
    if key_file is not None and kind == "ssh":
        raise ServerCommandRefused("credential_not_applicable")
    if ca_file is not None and tls_pin is not None:
        raise ServerCommandRefused("target_tls_invalid")
    ca_text: str | None = None
    if ca_file is not None:
        resolved = ca_file.expanduser()
        resolved = resolved if resolved.is_absolute() else Path.cwd() / resolved
        if not resolved.is_file():
            raise ServerCommandRefused("target_path_invalid")
        ca_text = str(resolved)
    # Checked before the consent and before anything runs on the server (SRV-11).
    remote_root = _absolute_option(remote_root)
    remote_launcher = _absolute_option(remote_launcher)
    try:
        taken = any(record.name == name for record in list_targets())
    except TargetError as error:
        raise ServerCommandRefused(error.reason) from None
    if taken:
        raise ServerCommandRefused("target_name_taken")
    check_remote_hop()
    stamp = format_rfc3339_ms(datetime.now(UTC))
    try:
        # What the profile is fetched for: the location alone (nothing is written yet).
        provisional = _Target(
            "t_00000000",
            name,
            kind,
            stamp,
            base_url=base_url,
            ca_file=ca_text,
            tls_pin=tls_pin,
            user=user,
            host=host,
            port=ssh_port,
            remote_root=remote_root,
            remote_endpoint=None
            if remote_root is None
            else f"{remote_root.rstrip('/')}/run/control.sock",
            remote_launcher=remote_launcher,
            claim_salt="A" * 43 + "=",
            authorized_at=stamp,
            disclosure_version=DISCLOSURE_VERSION,
        )
    except TargetError as error:
        raise ServerCommandRefused(error.reason) from None
    session_bound = False
    api_key: str | None = None
    if kind == "ssh":
        # Every socket path OpenSSH will be given must be usable as written, checked before
        # anything reaches the server and again for the endpoint it reports, before a record.
        _require_ssh_paths(provisional.remote_endpoint)
        # SSH discovery (design v2 section 2.1): the endpoint and the profile, from the server's
        # own launcher; an unknown host key is asked about only on this trusted console.
        found = _discover_ssh(
            user, cast(str, host), cast(int, ssh_port), remote_root, remote_launcher
        )
        _require_ssh_paths(found.endpoint)
        remote_launcher, session_bound = found.launcher, found.session_bound
        try:
            provisional = replace(
                provisional, remote_endpoint=found.endpoint, remote_launcher=found.launcher
            )
        except TargetError as error:
            raise ServerCommandRefused(error.reason) from None
        fetched = found.profile
    elif kind in _REST_TARGET_KINDS:
        # HTTPS discovery without a key, then the key on this console, then the profile with it
        # (design v2 sections 2.1 and 2.2, ADR-053).
        fetched, api_key = _discover_rest(provisional, key_file)
    else:
        fetched = _fetch_profile(provisional)
    envelope, lines = _consent_offer(provisional, fetched, choice)
    mode = outside_reads
    official = official_address(kind, base_url, ca_file=ca_text, tls_pin=tls_pin)
    answered = _confirm_on_trusted_console(
        name, kind, lines, ask_mode=mode is None and not official, decided=mode, official=official
    )
    mode = mode or answered
    from finishup.client.server_profile import consent_envelope_for, record_consent
    from finishup.client.targets import new_remote_target, remove_target_root

    try:
        with registry_lock():
            if any(record.name == name for record in list_targets()):
                raise ServerCommandRefused("target_name_taken")
            record, _root = new_remote_target(
                name,
                kind,
                base_url=base_url,
                ca_file=ca_text,
                tls_pin=tls_pin,
                user=user,
                host=host,
                port=ssh_port,
                remote_root=remote_root,
                remote_launcher=remote_launcher,
                remote_endpoint=provisional.remote_endpoint,
            )
            try:
                # The envelope again for the record as written (its own id): the same terms.
                consented, _profile = consent_envelope_for(
                    record, fetched, level=envelope.level, retention=envelope.retention
                )
                if consented != envelope:
                    raise TargetError("server_profile_changed")
                record = record_consent(record, fetched, consented)
                if api_key is not None:
                    record = _store_added_key(record, _root, api_key)
            except BaseException:
                remove_target_root(record)
                raise
            recorded = _record_added_mode(record, mode)
    except TargetError as error:
        raise ServerCommandRefused(error.reason) from None
    typer.echo(f"Added server target {record.name} ({record.target_id}, {record.kind}).")
    _emit(_added_mode_lines(record, recorded=recorded))
    if session_bound:
        typer.echo(
            "Warning: that server's FinishUP endpoint lives in its login session's runtime folder "
            "and disappears at its last logout; enable linger for that account, or add it again "
            "with --remote-root."
        )
    _say_repository_hold(record)
    _emit((f"Use it with 'finishup server use {record.name}'.",))


_REST_TARGET_KINDS: Final = frozenset({"https", "local_port"})
_API_KEY_PROMPT: Final = "API key for this server (input hidden): "


def _read_api_key(key_file: Path | None) -> str:
    """The API key: once from an owner-only key file, or typed on this trusted console (hidden).

    Never from an argument, the environment or redirected input; never echoed.
    """

    from finishup.cli.trusted_console import TrustedConsoleError, TrustedForegroundConsole
    from finishup.client.credentials import CredentialError, read_key_file, validate_secret

    try:
        if key_file is not None:
            return read_key_file(key_file)
        with TrustedForegroundConsole() as console:
            raw = console.read_secret(_API_KEY_PROMPT, 512)
        try:
            return validate_secret(raw.decode("ascii"))
        except UnicodeDecodeError:
            raise CredentialError("credential_invalid") from None
        finally:
            raw[:] = b"\x00" * len(raw)
    except TrustedConsoleError:
        raise ServerCommandRefused("trusted_console_required") from None
    except CredentialError as error:
        raise ServerCommandRefused(error.reason) from None


def _rest_failure(reason: str) -> NoReturn:
    _runtime_failure(TargetRuntimeError("service_unavailable", phase=reason))


def _discover_rest(provisional: ServerTarget, key_file: Path | None) -> tuple[FetchedProfile, str]:
    """HTTPS discovery (no key), the key, then the profile with it; nothing is written."""

    from finishup.client.rest_client import RestUnavailable
    from finishup.client.rest_discovery import check_discovery, fetch_profile

    typer.echo("Asking the server at that address what it is (over HTTPS, without a key).")
    try:
        check_discovery(provisional)
    except RestUnavailable as error:
        _rest_failure(error.reason)
    key = _read_api_key(key_file)
    try:
        return fetch_profile(provisional, key=key), key
    except RestUnavailable as error:
        _rest_failure(error.reason)


def _store_added_key(record: ServerTarget, root: Path, key: str) -> ServerTarget:
    """Keep the key the server accepted for a target just added (under the registry lock)."""

    from finishup.client.authorization import bump_credential_generation
    from finishup.client.credentials import CredentialError, KeyringOrFileCredential

    try:
        location = KeyringOrFileCredential(record.target_id, root, recorded=None).store(key)
    except CredentialError as error:
        raise ServerCommandRefused(error.reason) from None
    stored = replace(record, credential=location)
    write_target(root, stored)
    # An owner action on the key (ADR-052, O8).
    bump_credential_generation(root)
    return stored


def _require_ssh_paths(remote_endpoint: str | None) -> None:
    """Refuse ``ssh_path_unusable`` unless OpenSSH can take every socket path of a new SSH
    target as written: its root's (named like every target root) and ``remote_endpoint``."""

    from finishup.client.ssh_transport import ssh_paths_usable
    from finishup.client.targets import servers_dir

    try:
        root = servers_dir() / "t_00000000"
    except TargetError as error:
        raise ServerCommandRefused(error.reason) from None
    if not ssh_paths_usable(root, remote_endpoint):
        raise ServerCommandRefused("ssh_path_unusable")


def _discover_ssh(
    user: str | None,
    host: str,
    port: int,
    remote_root: str | None,
    remote_launcher: str | None,
) -> SshDiscovery:
    """SSH discovery for ``server add`` (``client.ssh_discovery``), refused with closed reasons."""

    from finishup.cli.trusted_console import TrustedConsoleError
    from finishup.client.ssh_discovery import discover

    typer.echo("Asking the server over SSH where its FinishUP service listens and what it offers.")
    try:
        return discover(
            user=user,
            host=host,
            port=port,
            remote_root=remote_root,
            remote_launcher=remote_launcher,
            question=_host_key_question(),
        )
    except TrustedConsoleError:
        raise ServerCommandRefused("trusted_console_required") from None
    except TargetRuntimeError as error:
        if error.reason == "remote_host_key_unconfirmed":
            raise ServerCommandRefused("remote_host_key_unconfirmed") from None
        _runtime_failure(error)


# RE-7: printed only when OpenSSH will ask, never for a known or a changed key.
_HOST_KEY_QUESTION: Final = (
    "This computer does not know the server's SSH host key yet, so OpenSSH asks you to confirm "
    "it here: compare the fingerprint with the server's own before you answer yes."
)


def _host_key_question() -> HostKeyQuestion:
    """The owner is told, on the trusted console only, that OpenSSH is about to ask (RE-11)."""

    from finishup.client.ssh_discovery import HostKeyQuestion

    def before() -> None:
        from finishup.cli.trusted_console import TrustedForegroundConsole

        with TrustedForegroundConsole() as console:
            console.write(_HOST_KEY_QUESTION + "\n")

    return HostKeyQuestion(before)


def _say_repository_hold(record: ServerTarget) -> None:
    """After choosing or adding remote ``record``: whether this folder's repository is held or
    kept for it, else how many repositories are held for it (ADR-051 decision 8, FR-5). Best
    effort: it asks this computer's FinishUP about this folder when it can answer, and never
    fails the command."""

    if not record.is_remote or not _open_kind(record.kind):
        return
    try:
        here: RepositoryHere | None = repository_here()
    except (ServerCommandRefused, TargetError, PathSafetyError):
        here = None
    try:
        if here is not None:
            decision = _decision_here(record, here, _live_state(here))
            if decision.state == "held":
                typer.echo(
                    "This repository's privacy policy on this computer allows no network use, so "
                    f"FinishUP holds its work for {record.name}: nothing from it is sent. To send "
                    f"it anyway, run 'finishup server repositories add {record.name}' here; to "
                    "keep it here without being asked again, 'finishup server repositories keep "
                    f"{record.name}'."
                )
                return
            if decision.state == "kept":
                typer.echo(
                    f"This repository's work is kept on this computer for {record.name}, as you "
                    f"chose; 'finishup server repositories add {record.name}' here sends it anyway."
                )
                return
        held = len(repository_groups(record).held)
    except Exception:  # noqa: BLE001 - a hint that cannot be computed is left out
        return
    if held:
        noun = (
            "repository whose privacy policy on this computer allows no network use is"
            if held == 1
            else "repositories whose privacy policy on this computer allows no network use are"
        )
        typer.echo(
            f"{held} {noun} held for {record.name}; 'finishup server repositories list "
            f"{record.name}' shows them."
        )


def _record_added_mode(record: ServerTarget, mode: OutsideReadMode | None) -> bool:
    """Record the mode the owner answered for the new target; False when it could not be.

    Never refuses the add: a mode that could not be written leaves the target ``listed``, the
    fail-closed value of a target whose owner has not chosen, and ``server add`` says so and how
    to choose. Called under ``registry_lock``.
    """

    from finishup.client.server_folders import FolderError, set_mode

    if mode is None or not record.is_remote:
        return True
    try:
        set_mode(target_root(record.target_id), record.target_id, mode)
    except FolderError:
        return False
    return True


def _added_mode_lines(record: ServerTarget, *, recorded: bool = True) -> tuple[str, ...]:
    """What ``server add`` says of a new remote target's outside-read mode, and how to change it."""

    from finishup.client.server_folders import outside_reads_of

    found = outside_reads_of(target_root(record.target_id), record)
    if not recorded:
        return (
            "Its choice of what it may read outside your projects could not be saved, so for now "
            "it reads only folders you list there, none yet (mode listed).",
            f"Choose again with 'finishup server folders mode {record.name} local' or "
            f"'finishup server folders mode {record.name} listed'; trying again may help.",
        )
    origin = _mode_origin(found.source)
    if found.mode == "local":
        return (
            f"Outside your projects it reads what FinishUP on this computer would read (mode "
            f"local, {origin}).",
            f"To let it read only folders you list: 'finishup server folders mode {record.name} "
            "listed'.",
        )
    if found.source == "not_chosen":
        return (
            f"Outside your projects it reads only folders you list, none yet (mode listed, "
            f"{origin}).",
            _choose_line(record.name),
        )
    return (
        f"Outside your projects it reads only folders you list, none yet (mode listed, {origin}).",
        f"List one with 'finishup server folders add {record.name} FOLDER', or, if you trust it "
        f"as you trust FinishUP on this computer: 'finishup server folders mode {record.name} "
        "local'.",
    )


def _choose_line(name: str) -> str:
    """How the owner chooses the mode of a target with none chosen yet."""

    return (
        f"Choose what it may read there: 'finishup server folders mode {name} local' (what "
        f"FinishUP on this computer would read) or 'finishup server folders mode {name} listed' "
        "(only folders you list)."
    )


@dataclass(frozen=True, slots=True)
class TargetRow:
    """One owner-display row of ``finishup server list`` (and the terminal's ``/server``)."""

    selected: bool
    name: str
    kind: str
    target_id: str | None
    location: str | None


def target_rows() -> tuple[tuple[TargetRow, ...], str]:
    """Every target as a display row (``local`` first), and the deciding source."""

    source = _source()
    try:
        records = list_targets()
        selected = read_selected_target_id()
    except TargetError as error:
        raise ServerCommandRefused(error.reason) from None
    current = None if source in _EXPLICIT_SOURCES else selected
    rows = [TargetRow(current is None, "local", "local", None, None)]
    rows.extend(
        TargetRow(
            record.target_id == current,
            record.name,
            record.kind,
            record.target_id,
            _location(record),
        )
        for record in records
    )
    return tuple(rows), source


def render_target_rows(rows: tuple[TargetRow, ...], source: str) -> tuple[str, ...]:
    """The ``finishup server list`` lines; a record of a kind closed in this build is shown as not
    available (one another build wrote can be listed and removed)."""

    table = [
        (
            "*" if row.selected else " ",
            row.name,
            row.kind,
            row.target_id or "-",
            (row.location or "this computer")
            + (
                ""
                if row.kind == "local" or _open_kind(row.kind)
                else " (not available in this release)"
            ),
        )
        for row in rows
    ]
    widths = [max(len(line[index]) for line in table) for index in range(1, 4)]
    lines = [
        f"{mark} {name.ljust(widths[0])}  {kind.ljust(widths[1])}  "
        f"{target_id.ljust(widths[2])}  {where}"
        for mark, name, kind, target_id, where in table
    ]
    if source in _EXPLICIT_SOURCES:
        lines.append(f"The selection is not used here: the {source} decides this process's root.")
    return tuple(lines)


def _show_zero_network_item(*, machine_readable: bool) -> ZeroNetworkSelection | None:
    """Say so while this computer forbids network use and a remote server is selected.

    ADR-051 decision 8 (maintainer decision, 2026-11-06): the zero-network setting does not stop
    traffic to a server already selected, so the owner displays name it and the way out. Fixed
    text, a generated id and closed tokens only; on standard error beside a JSON answer. Returns
    the item it showed, so ``server status`` puts the same one in its document without asking
    this computer's service a second time.
    """

    from finishup.cli.zero_network_selection import find_zero_network_selection

    item = find_zero_network_selection()
    if item is None:
        return None
    if machine_readable:
        typer.echo(item.line(), err=True)
        return item
    _emit((*item.lines(), ""))
    return item


@server_app.command("list")
@_cli
def server_list() -> None:
    """List server targets; the selected one is marked with *."""

    _show_zero_network_item(machine_readable=False)
    rows, source = target_rows()
    _emit(render_target_rows(rows, source))
    _emit(_leftover_lines())


def _leftover_lines() -> tuple[str, ...]:
    """A line per registry folder that holds no target record, with the command that deletes it."""

    try:
        leftovers = leftover_target_ids()
    except TargetError:
        return ()
    return tuple(
        f"Folder {target_id} holds no server target record: adding or removing a server was "
        f"interrupted, and FinishUP does not use it. Delete it with 'finishup server remove "
        f"{target_id}'."
        for target_id in leftovers
    )


@dataclass(frozen=True, slots=True)
class TargetSwitch:
    """What ``use_target`` changed: the server now selected, and the remote one it left.

    ``record`` is the target now selected (``None``: this computer's everyday server). ``left``
    is the remote target the selection named before, when the switch moved away from it. What
    this client runs for that target was stopped as ``server disconnect`` stops it (its runtime,
    never a process pattern), so nothing here answers that server's requests for files on this
    computer once the switch returns; ``left_open`` says the stop did not finish (ADR-051
    decision 8: the way out of a remote selection under zero-network stops its traffic).
    """

    record: ServerTarget | None
    left: ServerTarget | None = None
    left_open: bool = False

    def left_lines(self) -> tuple[str, ...]:
        """What became of the left server's connection, by generated id and closed kind only."""

        if self.left is None:
            return ()
        server = f"{self.left.target_id} ({self.left.kind})"
        if not self.left_open:
            return (
                f"Closed this computer's connection to the server {server}: it no longer "
                "answers that server's requests for your files.",
            )
        return (
            f"The connection to the server {server} did not close in time, so it may still "
            "answer that server's requests for your files. Run 'finishup server disconnect' with "
            "that server's name ('finishup server list' shows it).",
        )


def _selected_remote() -> ServerTarget | None:
    """The remote target the selection file names now; ``None`` for none, local or unreadable.

    Read under the registry lock by the switch that replaces it. A selection or record that
    cannot be read names no target this could stop, and never keeps the switch from happening.
    """

    try:
        target_id = read_selected_target_id()
        if target_id is None:
            return None
        record = read_target(target_root(target_id))
    except (TargetError, PathSafetyError):
        return None
    return record if record is not None and record.is_remote else None


def _leave(record: ServerTarget | None, previous: ServerTarget | None) -> TargetSwitch:
    """Stop what this client runs for ``previous`` when the selection moved away from it.

    After the selection changed, so a new hook or command can no longer start it again. Only
    that target's runtime stops it, exactly as ``server disconnect`` does; nothing is found or
    signalled by a process pattern. A kind this build has no runtime for (every remote kind in
    this release) ran nothing here, so there is nothing to stop and nothing to report.
    """

    import subprocess

    if previous is None or (record is not None and record.target_id == previous.target_id):
        return TargetSwitch(record)
    try:
        runtime_for(previous.kind).stop(target_root(previous.target_id))
    except TargetRuntimeError as error:
        if error.phase == "runtime_unavailable":
            # No runtime for that kind: this client ran nothing for it.
            return TargetSwitch(record)
        return TargetSwitch(record, previous, left_open=True)
    except (TargetError, PathSafetyError, OSError, subprocess.SubprocessError):
        return TargetSwitch(record, previous, left_open=True)
    return TargetSwitch(record, previous)


def use_target(
    name: str,
    *,
    authorize: Callable[[str, str, tuple[str, ...]], None] | None = None,
    choice: LevelChoice | None = None,
) -> TargetSwitch:
    """Select ``name`` (``record`` ``None`` back means this computer's everyday server).

    A remote target (one another build wrote, or written by hand) is refused with
    ``remote_kind_unavailable`` before anything is asked or written: the remote kinds are closed
    in this release, so the selection stays as it was. A switch away from a remote target stops
    what this client runs for it (``TargetSwitch.left``); ``use local`` is always the way back.

    Once a kind is open (a later layer; a test here), selecting a remote target is the owner's
    consent to its server's current profile, asked every time: the zero-network state (SRV-3),
    the profile over the target's own transport, the envelope of using it at level L1, then the
    disclosure and the typed name on the trusted console (``authorize``, by default on this
    thread; the terminal interface passes one that reads it on its loop thread, SRV-6). The
    consent is then written onto the record as stored now, under the registry lock (SRV-12).
    """

    if name == "local":
        # The way back never resolves the selection it removes: a damaged selection, or one that
        # names a missing or unsafe target folder, is exactly what it must clear.
        _require_no_explicit_source()
        try:
            with registry_lock():
                previous = _selected_remote()
                clear_selection()
        except TargetError as error:
            raise ServerCommandRefused(error.reason) from None
        return _leave(None, previous)
    _require_selection_in_force()
    record = _target_or_fail(name)
    if record.is_remote:
        if not _open_kind(record.kind):
            raise ServerCommandRefused("remote_kind_unavailable", message=_USE_REFUSED)
        return _use_remote(record, authorize, choice)
    if choice is not None and (choice.level is not None or choice.retention is not None):
        raise ServerCommandRefused(
            "usage", message="--level and --retention apply to a server elsewhere"
        )
    try:
        with registry_lock():
            # Read again under the lock: a target removed meanwhile stays gone, and one whose
            # record another process rewrote as a remote kind meanwhile is refused here, before
            # the selection is written, exactly as it would have been on the first read.
            record = _stored_record(record)
            if record.is_remote:
                raise ServerCommandRefused("remote_kind_unavailable", message=_USE_REFUSED)
            previous = _selected_remote()
            write_selection(record)
    except TargetError as error:
        raise ServerCommandRefused(error.reason) from None
    return _leave(record, previous)


def _use_remote(
    record: ServerTarget,
    authorize: Callable[[str, str, tuple[str, ...]], None] | None,
    choice: LevelChoice | None = None,
) -> TargetSwitch:
    """``use_target`` for a remote target of an open kind (see there)."""

    from finishup.client.server_profile import consent_envelope_for, fetch_basis, record_consent

    check_remote_hop()
    # Read before the profile is fetched (and its key read): a login or logout while the owner is
    # asked means the profile answered another key, so nothing is recorded (C2).
    basis = fetch_basis(record)
    if authorize is None:
        # On the owner's terminal an unknown host key may be asked about (RE-11); the terminal
        # interface passes its own confirmation and never lets OpenSSH ask on its screen.
        from finishup.client.ssh_discovery import host_key_question

        with host_key_question(_host_key_question()):
            fetched = _fetch_profile(record)
    else:
        fetched = _fetch_profile(record)
    envelope, lines = _consent_offer(record, fetched, choice, stored=record)
    if authorize is None:
        _confirm_on_trusted_console(record.name, record.kind, lines)
    else:
        authorize(record.name, record.kind, lines)
    try:
        with registry_lock():
            # Read again: the confirmation may have taken minutes. Only the consent changes here
            # (a key stored meanwhile stays recorded; a removed target stays gone, SRV-12).
            stored = _stored_record(record)
            if not stored.is_remote or stored.kind != record.kind:
                raise ServerCommandRefused("server_profile_changed")
            consented, _profile = consent_envelope_for(
                stored, fetched, level=envelope.level, retention=envelope.retention
            )
            if consented != envelope:
                raise ServerCommandRefused("server_profile_changed")
            stored = record_consent(stored, fetched, consented, basis=basis)
            previous = _selected_remote()
            write_selection(stored)
    except TargetError as error:
        if error.reason == "server_authorization_changed":
            raise ServerCommandRefused(
                "server_profile_changed",
                message=(
                    f"the API key or record of {record.name} changed while you were asked (a "
                    "login, logout or another change), so nothing was changed; run 'finishup "
                    f"server use {record.name}' again"
                ),
            ) from None
        raise ServerCommandRefused(error.reason) from None
    return _leave(stored, previous)


_USE_REFUSED: Final = f"{REMOTE_KIND_UNAVAILABLE}; the selected server is unchanged"


def _stored_record(record: ServerTarget) -> ServerTarget:
    """``record`` as stored now, read under the registry lock (SRV-12).

    A command that read a target before a slow step (a typed confirmation, a key prompt, a
    server round trip) changes only its own field on what this returns, so a change another
    command made meanwhile is kept. A target removed meanwhile is ``target_unknown``, and
    nothing recreates its folder.
    """

    current = read_target(target_root(record.target_id))
    if current is None:
        raise TargetError("target_unknown")
    return current


@server_app.command("use")
@_cli
def server_use(
    name: Annotated[str, typer.Argument(help="A target name, or 'local' for this computer.")],
    level: _LEVEL_OPTION = None,
    retention: _RETENTION_OPTION = None,
) -> None:
    """Select the server new client processes use ('local' returns to this computer's)."""

    switch = use_target(
        name,
        choice=None if level is None and retention is None else LevelChoice(level, retention),
    )
    record = switch.record
    if record is None:
        typer.echo("Using this computer's everyday FinishUP server.")
    else:
        typer.echo(f"Using server target {record.name} ({record.target_id}, {record.kind}).")
    for line in switch.left_lines():
        typer.echo(line, err=switch.left_open)
    if record is not None:
        _say_repository_hold(record)
    _warn_open_sessions()


def _probe_document(result: ProbeResult | None, error: TargetRuntimeError | None) -> JsonValue:
    if error is not None:
        return {
            "outcome": "unavailable",
            "reason": error.reason,
            "phase": error.phase,
            "service_version": None,
            "service_instance_id": None,
            "service_state": None,
            "vault_mode": None,
            "round_trip_p95_ms": None,
            "samples": 0,
            "last_reported_at": None,
        }
    assert result is not None
    return {
        "outcome": result.outcome,
        "reason": result.reason,
        "phase": result.phase,
        "service_version": result.service_version,
        "service_instance_id": result.service_instance_id,
        "service_state": result.service_state,
        "vault_mode": result.vault_mode,
        "round_trip_p95_ms": result.round_trip_p95_ms,
        "samples": result.samples,
        "last_reported_at": None,
    }


def _not_probed(refusal: ZeroNetworkRefusal) -> JsonValue:
    """The probe of a target nothing was sent to: the closed reason why, and when this computer
    reported the zero-network policy that decided it."""

    return {
        "outcome": "not_probed",
        "reason": refusal.refused.reason,
        "phase": None,
        "service_version": None,
        "service_instance_id": None,
        "service_state": None,
        "vault_mode": None,
        "round_trip_p95_ms": None,
        "samples": 0,
        "last_reported_at": refusal.reported_at,
    }


def _resolve(name: str | None) -> tuple[ServerTarget | None, Path | None, bool]:
    """``(record, root, everyday)`` for ``name``, or for this process's own root when omitted."""

    if name is None:
        try:
            record = active_target_record()
        except TargetError as error:
            raise ServerCommandRefused(error.reason)
        if record is not None:
            return record, target_root(record.target_id), False
        from finishup.config.paths import active_root

        try:
            root = active_root()
        except PathSafetyError as error:
            raise ServerCommandRefused(error.reason_code, message=ROOT_UNUSABLE_MESSAGE) from None
        return None, root, root is None
    _require_selection_in_force()
    if name == "local":
        return None, None, True
    record = _target_or_fail(name)
    return record, target_root(record.target_id), False


def _runtime(record: ServerTarget | None) -> TargetRuntime:
    kind: TargetKind = "local" if record is None else record.kind
    return runtime_for(kind)


def _probe(record: ServerTarget | None, root: Path | None) -> ProbeResult:
    return _runtime(record).probe(root)


def build_status_document(
    name: str | None,
    *,
    now: Callable[[], datetime] | None = None,
    zero_network: Callable[[], ZeroNetworkSelection | None] | None = None,
    repository_here: bool = True,
    workspace: str | None = None,
) -> dict[str, JsonValue]:
    """The ``server-target-status`` 1.0.0 document for ``name`` (or this process's root).

    ``zero_network`` answers the zero-network item (ADR-051 decision 8) when the caller already
    found it (``server status`` the item it printed, the terminal interface the one ``/server``
    showed) or will not show it (``server test``); by default the document asks
    ``find_zero_network_selection`` itself, which may ask this computer's service.

    For a remote target ``target.repositories`` says which repositories it holds, keeps here or
    receives anyway (ADR-051 decision 8, 2026-11-07, round 4), from this client's records. With
    ``repository_here`` it also says what is true of the repository of ``workspace`` (the current
    folder when None), after asking this computer's FinishUP about it when it can answer; not
    while the zero-network item is shown (that refusal governs) or outside any repository.
    """

    source = _source()
    try:
        selected = read_selected_target_id()
    except TargetError:
        selected = None
    record, root, everyday = _resolve(name)
    result: ProbeResult | None = None
    failure: TargetRuntimeError | None = None
    refused = zero_network_refusal(record)
    if refused is None:
        try:
            result = _probe(record, root)
        except TargetRuntimeError as error:
            failure = error
    authorization: JsonValue = None
    if record is not None and record.is_remote:
        authorization = {
            "authorized_at": cast(str, record.authorized_at),
            "disclosure_version": cast(int, record.disclosure_version),
            "current": not record.needs_reauthorization,
        }
    consent: JsonValue = None
    if record is not None and record.is_remote and record.consent is not None:
        consent = _consent_document(record)
    credential: str = "not_applicable"
    if record is not None and record.kind in {"https", "local_port"}:
        credential = record.credential or "none"
    outside_reads: JsonValue = None
    if record is not None and record.is_remote and root is not None:
        # This client's own record (ADR-051 decision 5): what that server may read here outside
        # the claimed project. Never sent to the server.
        from finishup.client.server_folders import outside_reads_of

        found = outside_reads_of(root, record)
        outside_reads = {
            "mode": found.mode,
            "mode_source": found.source,
            "folders": list(found.folders),
        }
    zero_network_item = _zero_network_selection(zero_network)
    repositories: JsonValue = None
    if record is not None and record.is_remote:
        repositories = _repositories_document(
            record,
            here=repository_here and zero_network_item is None,
            workspace=workspace,
        )
    target: dict[str, JsonValue] = {
        "target_id": None if record is None else record.target_id,
        "name": "local" if everyday else (None if record is None else record.name),
        "kind": "local" if record is None else record.kind,
        "location": _location(record),
        "credential": credential,
        "authorization": authorization,
        "consent": consent,
        "connection": _connection_document(record, root),
        "outside_reads": outside_reads,
        "repositories": repositories,
    }
    stamp = (now or (lambda: datetime.now(UTC)))()
    document: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "source": source,
        "selection_overridden": source in _EXPLICIT_SOURCES and selected is not None,
        "client_version": __version__,
        "target": target,
        # Nothing is sent to probe it while this computer is zero-network (ADR-051 decision 8).
        "probe": (_probe_document(result, failure) if refused is None else _not_probed(refused)),
        "zero_network_selection": zero_network_item,
        "observed_at": format_rfc3339_ms(stamp),
    }
    from finishup.protocol.server_target_status import ServerTargetStatusContract

    ServerTargetStatusContract.model_validate(document)
    return document


def _connection_document(record: ServerTarget | None, root: Path | None) -> JsonValue:
    """How this computer reaches an SSH or HTTPS target (ADR-052, ADR-053): file reads only."""

    if record is None or root is None or record.kind not in _STYLE_KINDS:
        return None
    from finishup.client.helper_status import (
        helper_holder,
        read_connection_style,
        read_helper_status,
    )
    from finishup.client.server_profile import styles_offered

    status = read_helper_status(root)
    helper: JsonValue = None
    if status is not None:
        helper = {
            "running": helper_holder(root) is not None,
            "phase": status.phase,
            "reason": status.reason,
            "generation": status.generation,
        }
    return {
        "style": read_connection_style(root),
        "styles_offered": list(styles_offered(record)),
        "helper": helper,
    }


def connection_lines(target: Mapping[str, JsonValue]) -> tuple[str, ...]:
    """Owner-display lines of how this computer reaches an SSH or HTTPS target."""

    connection = target.get("connection")
    if not isinstance(connection, Mapping):
        return ()
    found = cast(Mapping[str, JsonValue], connection)
    style = found["style"]
    if target.get("kind") in {"https", "local_port"}:
        how = (
            "this computer's FinishUP helper keeps one HTTPS connection and reads the API key"
            if style == "relay"
            else "each program here reads the API key and opens its own HTTPS connection"
        )
    else:
        how = (
            "this computer's FinishUP helper keeps one SSH connection for every program here"
            if style == "relay"
            else "each program here opens its own SSH channel through a shared OpenSSH master"
        )
    lines = [f"Connection: {style} ({how})."]
    helper = found["helper"]
    if isinstance(helper, Mapping):
        state = cast(Mapping[str, JsonValue], helper)
        running = "running" if state["running"] else "not running"
        reason = "" if state["reason"] is None else f", {state['reason']}"
        lines.append(f"Helper: {running}; last {state['phase']}{reason}.")
    return tuple(lines)


def _consent_document(record: ServerTarget) -> JsonValue:
    """What ``server status`` says of a remote target's consent (ADR-052): file reads only."""

    from finishup.client.server_profile import consent_verdict

    consent = cast("ServerConsent", record.consent)
    phase = consent_verdict(record).phase
    state = {
        None: "current",
        "server_level_unavailable": "level_unavailable",
    }.get(phase, "changed")
    return {
        "level": consent.level,
        "profile_revision": consent.revision,
        "state": state,
        "adjusted_at": consent.adjusted_at,
        "coverage_reduced": list(consent.coverage_reduced),
    }


def consent_lines(target: Mapping[str, JsonValue]) -> tuple[str, ...]:
    """Owner-display lines of a remote target's consent, the narrowed notice among them."""

    consent = target.get("consent")
    if not isinstance(consent, Mapping):
        return ()
    found = cast(Mapping[str, JsonValue], consent)
    name = target.get("name") or "NAME"
    lines = [
        f"Consent: level {found['level']} under that server's profile revision "
        f"{found['profile_revision']}."
    ]
    if found["adjusted_at"] is not None:
        reduced = ", ".join(cast(list[str], found["coverage_reduced"])) or "nothing"
        lines.append(
            f"server_profile_narrowed: that server asks for less than you agreed to, so FinishUP "
            f"narrowed this computer's consent at {found['adjusted_at']} (no longer covered: "
            f"{reduced}); if it asks for more again, you are asked again."
        )
    if found["state"] == "changed":
        lines.append(
            "server_profile_changed: what that server offers or needs changed since you agreed, "
            f"so nothing is sent to it; agree again with 'finishup server use {name}'."
        )
    elif found["state"] == "level_unavailable":
        lines.append(
            "server_level_unavailable: that server requires more of this computer than you "
            f"agreed to, so nothing is sent to it; 'finishup server use {name}' shows what it "
            "requires."
        )
    return tuple(lines)


def _repositories_document(
    record: ServerTarget, *, here: bool, workspace: str | None
) -> dict[str, JsonValue]:
    """``target.repositories`` of a remote target (owner display: paths and fixed-shape times)."""

    from finishup.client.everyday_policy import worktree_storable

    here_value: JsonValue = None
    if here:
        try:
            found = repository_here(workspace)
        except ServerCommandRefused:
            found = None
        if found is not None:
            live = _live_state(found)
            decision = _decision_here(record, found, live)
            policy_read = None if decision.state == "not_reported" else decision.policy_read
            here_value = {
                "state": decision.state,
                "cause": decision.cause,
                "policy_read": policy_read,
                "reported_at": decision.reported_at if policy_read == "last_reported" else None,
            }
    groups = repository_groups(record)

    def path(value: str | None) -> JsonValue:
        return value if value is not None and worktree_storable(value) else None

    return {
        "reports": groups.reports,
        "record": groups.record,
        "held": [
            {"worktree": path(worktree), "reported_at": reported_at, "cause": cause}
            for worktree, reported_at, cause in groups.held
        ],
        "kept": [
            {"worktree": choice.worktree, "kept_at": choice.decided_at, "state": state}
            for choice, state in groups.kept()
        ],
        "allowed": [
            {"worktree": choice.worktree, "allowed_at": choice.decided_at, "state": state}
            for choice, state in groups.allowed()
        ],
        "here": here_value,
    }


def _zero_network_selection(
    find: Callable[[], ZeroNetworkSelection | None] | None = None,
) -> JsonValue:
    """The status document's ``zero_network_selection`` (ADR-051 decision 8): the item while this
    computer forbids all network use and a remote server is, or may be, selected.

    The item is the one ``cli.zero_network_selection.find_zero_network_selection`` reports (or
    ``find`` answers), as its fact: ``reason`` (``zero_network_remote_selected`` with
    ``target_id`` and ``kind``, or ``zero_network_selection_unreadable`` with ``detail``, the
    selection's closed reason), generated ids and closed tokens only. Null when there is nothing
    to say: nothing or a server on this computer is selected, an isolation variable or runtime
    pin decides this process's root, or this computer's policy permits network use, was never set
    up, or cannot be read (its service is stopped or locked).
    """

    if find is None:
        from finishup.cli.zero_network_selection import find_zero_network_selection

        find = find_zero_network_selection
    item = find()
    return None if item is None else cast(JsonValue, item.fact())


# Why a status document's target was not probed (ADR-051 decision 8), with when this computer
# reported its policy (``{at}``, the probe's ``last_reported_at``), and the one way out.
_NOT_PROBED_LINES: Final[Mapping[str, str]] = {
    "zero_network_remote_selected": (
        "This computer's FinishUP last reported, at {at}, that it makes no network connections, "
        "so it never uses the selected server elsewhere; run 'finishup server use local', then "
        "restart open agent sessions."
    ),
    "zero_network_in_force": (
        "This computer's FinishUP last reported, at {at}, that it makes no network connections, "
        "so it uses no server on another machine; to use one, change the privacy policy on this "
        "computer first, with 'finishup privacy setup'."
    ),
}


def target_in_use(name: str | None) -> bool:
    """Whether ``server status NAME`` describes the server this process uses.

    Without ``name`` the document is this process's own root: always. ``local`` is in use while
    this process uses the everyday server (no selection, no isolation root); any other name while
    its target is this process's root. Never raises: a root that cannot be read is not in use.
    """

    if name is None:
        return True
    try:
        active = active_target_record()
    except TargetError:
        return False
    if name == "local":
        if active is not None:
            return False
        from finishup.config.paths import active_root

        try:
            return active_root() is None
        except PathSafetyError:
            return False
    return active is not None and active.name == name


def _key_refused_line(kind: str, name: str) -> str:
    """What a server that answered and refused this client's key means, and the fix by kind."""

    if kind == "ssh":
        fix = (
            "load the SSH key it accepts (ssh-add) or add it to your OpenSSH configuration, then "
            f"run 'finishup server test {name}'"
        )
    else:
        fix = f"run 'finishup server login {name}' with an API key it accepts"
    return f"The server answered and refused this client's key; {fix}."


# What a direct-style connection that did not answer in time looks like in a probe: the
# connection's own deadline (``remote_unreachable``) or the probe's bound (``timeout``).
_DIRECT_TIMEOUT_PHASES: Final = frozenset({"remote_unreachable", "timeout"})


def _direct_style(target: Mapping[str, JsonValue]) -> bool:
    connection = target.get("connection")
    return isinstance(connection, Mapping) and connection.get("style") == "direct"


def direct_style_slow_line(name: str, *, answered: bool) -> str:
    """The plain line of a slow direct-style connection and its remedy (the owner's decision,
    2026-11-11): the direct style opens a connection per program, which a slow network makes
    slow; ``finishup server set NAME --style relay`` keeps one for every program instead."""

    head = (
        "The direct style is slow on this network"
        if answered
        else f"{name} did not answer in time in the direct style, which is slow on this network"
    )
    return (
        f"{head}: each program here opens its own connection to that server. Run 'finishup "
        f"server set {name} --style relay' (the default) so this computer's FinishUP helper keeps "
        "one connection for every program."
    )


def status_lines(document: dict[str, JsonValue], *, in_use: bool = True) -> tuple[str, ...]:
    """The owner display of a status document, a remote target's outside reads included.

    ``chosen by`` (the document's ``source``) says what decided the server this process uses, so
    it is shown only for that server (``in_use``, from ``target_in_use``); a target shown by name
    that is not in use says so instead.
    """

    target = cast(dict[str, JsonValue], document["target"])
    probe = cast(dict[str, JsonValue], document["probe"])
    name = target["name"] or "this process's isolated root"
    identity = "" if target["target_id"] is None else f"{target['target_id']}, "
    use = f"chosen by: {document['source']}" if in_use else "not the server in use"
    lines = [f"Server: {name} ({identity}{target['kind']}); {use}"]
    if target["kind"] != "local" and not _open_kind(str(target["kind"])):
        # A kind closed in this build: a record another build wrote is shown, never used.
        lines.append(f"Not available: {REMOTE_KIND_UNAVAILABLE}.")
    if target["location"] is not None:
        lines.append(f"Address: {target['location']}")
    if target["credential"] != "not_applicable":
        lines.append(f"API key: {target['credential']}")
    state = probe["service_state"] or probe["outcome"]
    reason = "" if probe["reason"] is None else f" ({probe['reason']}"
    if probe["phase"] is not None:
        reason += f", phase {probe['phase']}"
    reason += ")" if reason else ""
    not_sent = _NOT_PROBED_LINES.get(str(probe["reason"])) if state == "not_probed" else None
    if not_sent is not None:
        lines.append(f"State: not probed, nothing was sent ({probe['reason']})")
        lines.append(not_sent.format(at=probe["last_reported_at"]))
    elif probe["reason"] == "remote_auth_failed":
        # It answered: a refused key is not a server that could not be reached.
        lines.append(f"State: answered, key refused{reason}")
        lines.append(_key_refused_line(str(target["kind"]), str(target["name"] or "NAME")))
    else:
        lines.append(f"State: {state}{reason}")
    lines.append(
        f"Release: client {document['client_version']}, server "
        f"{probe['service_version'] or 'unknown'}"
    )
    if probe["vault_mode"] is not None:
        lines.append(f"Vault: {probe['vault_mode']}")
    if probe["round_trip_p95_ms"] is not None:
        lines.append(
            f"Round trip p95: {probe['round_trip_p95_ms']} ms over {probe['samples']} status calls"
        )
    lines.extend(consent_lines(target))
    lines.extend(connection_lines(target))
    if _direct_style(target) and probe["phase"] in _DIRECT_TIMEOUT_PHASES:
        lines.append(direct_style_slow_line(str(target["name"] or "NAME"), answered=False))
    lines.extend(outside_read_lines(target))
    lines.extend(repository_lines(target))
    if document["selection_overridden"]:
        lines.append("The server selection is not used here: an isolation root decides it.")
    return tuple(lines)


def repository_lines(target: Mapping[str, JsonValue]) -> tuple[str, ...]:
    """Owner-display lines of a status document's remote target: how many repositories it holds,
    keeps here and receives anyway, and what is true of this folder's repository. Empty for a
    target that is not remote."""

    repositories = target.get("repositories")
    if not isinstance(repositories, dict):
        return ()
    name = str(target.get("name") or "NAME")
    held = cast(list[JsonValue], repositories.get("held"))
    kept = [
        item
        for item in cast(list[JsonValue], repositories.get("kept"))
        if isinstance(item, dict) and item.get("state") == "applies"
    ]
    allowed = [
        item
        for item in cast(list[JsonValue], repositories.get("allowed"))
        if isinstance(item, dict) and item.get("state") == "applies"
    ]
    lines = [
        f"Repositories: {len(held)} held, {len(kept)} kept on this computer, {len(allowed)} sent "
        f"anyway as you allowed ('finishup server repositories list {name}' shows them)."
    ]
    if repositories.get("reports") == "unreadable":
        lines.append(_DAMAGED_REPORTS_LINE)
    if repositories.get("record") == "unreadable":
        lines.append(
            "The record of repositories it receives anyway or keeps here is damaged or not "
            "private to you, so it receives none of them: every repository whose policy here "
            "allows no network use is held for it. Repair it on this computer with 'finishup "
            f"server repositories remove {name} --all'."
        )
    here = repositories.get("here")
    if isinstance(here, dict):
        line = _here_line(here, name, kind=target.get("kind"))
        if line is not None:
            lines.append(line)
    return tuple(lines)


def sending_anyway_open(kind: object) -> bool:
    """Whether 'server repositories add' can act for a server of ``kind`` in this release.

    While the remote kinds are closed (ADR-052, O4) it refuses ``remote_kind_unavailable``, so no
    surface recommends it: they show what works (``keep``, ``remove``) and say that sending a held
    repository anyway arrives in a later release.
    """

    from finishup.client.authorization import OPEN_REMOTE_KINDS

    return kind in OPEN_REMOTE_KINDS


_SEND_ANYWAY_LATER: Final = "sending it anyway arrives in a later release, with servers elsewhere"


def _here_line(here: Mapping[str, JsonValue], name: str, *, kind: object = None) -> str | None:
    state = here.get("state")
    reported = (
        f", as this computer last reported at {here.get('reported_at')}"
        if here.get("policy_read") == "last_reported"
        else ""
    )
    sendable = sending_anyway_open(kind)
    if state == "held" and here.get("cause") == "grant_changed":
        if not sendable:
            return (
                "This folder's repository: held again — its privacy policy here changed after "
                f"you chose for it{reported}; 'finishup server repositories keep {name}' keeps "
                f"it here ({_SEND_ANYWAY_LATER})."
            )
        return (
            "This folder's repository: held again — its privacy policy here changed after you "
            f"chose for it{reported}; 'finishup server repositories add {name}' here sends it "
            f"anyway, and 'finishup server repositories keep {name}' keeps it here."
        )
    if state == "held":
        if not sendable:
            return (
                "This folder's repository: held — its privacy policy on this computer allows no "
                f"network use{reported}, so nothing from it is sent to this server. To keep it "
                f"here without being asked again: 'finishup server repositories keep {name}'; "
                f"{_SEND_ANYWAY_LATER}."
            )
        return (
            "This folder's repository: held — its privacy policy on this computer allows no "
            f"network use{reported}, so nothing from it is sent to this server. To send it anyway: "
            f"'finishup server repositories add {name}' here; to keep it here without being "
            f"asked again: 'finishup server repositories keep {name}'."
        )
    if state == "kept":
        undo = (
            f"'finishup server repositories add {name}' here sends it anyway."
            if sendable
            else f"'finishup server repositories remove {name}' here undoes that choice."
        )
        return (
            "This folder's repository: kept on this computer — its privacy policy here allows no "
            f"network use{reported}, and you chose to keep its work here, so nothing from it is "
            f"sent to this server and FinishUP does not ask again. {undo}"
        )
    if state == "sent_anyway":
        return (
            "This folder's repository: sent anyway — its privacy policy on this computer allows "
            f"no network use{reported}, and you allowed this server to receive its work. "
            f"'finishup server repositories remove {name}' here holds it again."
        )
    if state == "not_reported":
        return (
            "This folder's repository: not held — this computer's FinishUP has not reported its "
            "privacy policy and cannot be asked now."
        )
    return None


def _mode_origin(source: str) -> str:
    """Why a target is in its outside-read mode, in the owner's words."""

    if source == "owner":
        return "set by you"
    if source == "official_endpoint":
        return "an official FinishUP server"
    if source == "unreadable":
        return "because its record cannot be read"
    return "not chosen yet"


def _unreadable_record_lines(name: str) -> tuple[str, ...]:
    """What a target whose folders record cannot be read may read, and the one repair, in the
    owner's words: ``server status``, ``server folders list`` and the terminal's ``/server``."""

    return (
        "Folders it may read outside your projects: none, because its record of them on this "
        "computer is damaged or not private to you",
        f"Repair it on this computer with 'finishup server folders remove {name} --all'; it then "
        f"reads only folders you list, none yet (mode listed), and 'finishup server folders mode "
        f"{name} local' chooses local again.",
    )


# In mode local the listed folders still admit the files a task names (ADR-051 decision 5, amended
# 2026-11-07); everything else beneath them is read as FinishUP on this computer would read it.
_LOCAL_FOLDERS_LINE: Final = "Folders listed for it, whose files a task names it also reads:"


def outside_read_lines(target: Mapping[str, JsonValue]) -> tuple[str, ...]:
    """Owner-display lines of a status document's remote target: its outside-read mode, the
    folders listed for it, and how to choose a mode when none was chosen. Empty for a target that
    is not remote."""

    outside = target.get("outside_reads")
    if not isinstance(outside, dict):
        return ()
    mode = outside.get("mode")
    source = cast(str, outside.get("mode_source"))
    folders = [item for item in cast(list[JsonValue], outside.get("folders")) if type(item) is str]
    origin = _mode_origin(source)
    if mode == "local":
        lines = [
            f"Outside your projects: reads what FinishUP on this computer would read (mode local, "
            f"{origin})"
        ]
        if folders:
            lines.append(_LOCAL_FOLDERS_LINE)
            lines.extend(f"  {folder}" for folder in folders)
        return tuple(lines)
    lines = [f"Outside your projects: reads only folders you list (mode listed, {origin})"]
    if source == "unreadable":
        lines.extend(_unreadable_record_lines(str(target.get("name") or "NAME")))
    elif not folders:
        lines.append("Folders it may read outside your projects: none")
    else:
        lines.append("Folders it may read outside your projects:")
        lines.extend(f"  {folder}" for folder in folders)
    if source == "not_chosen":
        lines.append(_choose_line(str(target.get("name") or "NAME")))
    return tuple(lines)


@server_app.command("status")
@_cli
def server_status(
    name: Annotated[str | None, typer.Argument(help="A target name, or 'local'.")] = None,
    json_output: _JSON = False,
) -> None:
    """Show which source decides the server, the target, and one probe of it."""

    item = _show_zero_network_item(machine_readable=json_output or not sys.stdout.isatty())
    document = build_status_document(name, zero_network=lambda: item)
    if json_output or not sys.stdout.isatty():
        sys.stdout.buffer.write(canonical_encode(cast(JsonValue, document)) + b"\n")
        sys.stdout.flush()
        return
    _emit(status_lines(document, in_use=target_in_use(name)))


@server_app.command("test")
@_cli
def server_test(
    name: Annotated[str | None, typer.Argument(help="A target name, or 'local'.")] = None,
) -> None:
    """Probe a target and compare its round trip with the hook and startup-gate budgets."""

    record, root, _everyday = _resolve(name)
    # These lines never show the zero-network item (``status`` and ``list`` do), so this
    # computer's service is not asked for its policy, nor for this folder's repository.
    document = build_status_document(name, zero_network=lambda: None, repository_here=False)
    _emit(status_lines(document, in_use=target_in_use(name)))
    probe = cast(dict[str, JsonValue], document["probe"])
    if probe["outcome"] == "not_probed":
        # Nothing was sent (ADR-051 decision 8): say why and the one command that fixes it.
        refusal = zero_network_connection_refusal(record)
        raise refusal if refusal is not None else ServerCommandRefused(str(probe["reason"]))
    if probe["phase"] == "runtime_unavailable":
        # Nothing was asked: this build has no runtime for that kind (every remote kind in this
        # release), as 'connect' and 'disconnect' say, never "did not answer".
        raise ServerCommandRefused(
            "runtime_unavailable", detail=f"{probe['reason']}, phase runtime_unavailable"
        )
    if probe["outcome"] not in {"ready", "reachable"}:
        typer.echo(
            # A server that refused the key answered; the lines above say how to fix it.
            "The target answered and refused this client's key."
            if probe["reason"] == "remote_auth_failed"
            else "The target did not answer a status call.",
            err=True,
        )
        raise typer.Exit(_UNAVAILABLE)
    target = cast(dict[str, JsonValue], document["target"])
    direct = _direct_style(target)
    target_name = str(target["name"] or "NAME")
    # What the required startup gate times (design v2 section 8.9): a new process's connection
    # and a status, after its imports. The round trip above is one warm status only; a new
    # connection adds its handshake's round trips (and, relayed, the server's new channel) and
    # the process's own schema work, so only this is compared with the gate's bound.
    try:
        times = _runtime(record).time_new_connections(root, NEW_CONNECTION_SAMPLES)
    except TargetRuntimeError as error:
        phase = "" if error.phase is None else f", phase {error.phase}"
        typer.echo(
            f"A new connection did not answer a status call ({error.reason}{phase}).", err=True
        )
        if direct and error.phase in _DIRECT_TIMEOUT_PHASES:
            typer.echo(direct_style_slow_line(target_name, answered=False), err=True)
        raise typer.Exit(_UNAVAILABLE) from None
    bound = round(STARTUP_GATE_SECONDS * 1000)
    slowest = max(times)
    typer.echo(
        f"New connection and status: {slowest} ms at the slowest of {len(times)} new processes "
        f"(the required startup gate allows {bound} ms)."
    )
    if slowest > bound:
        typer.echo(
            f"Warning: {slowest} ms is above the {bound} ms the required startup gate allows for "
            "a connection and a status; agent tools would likely be denied."
        )
        if direct:
            typer.echo(direct_style_slow_line(target_name, answered=True))
    else:
        typer.echo(
            f"Within the startup gate's {bound} ms for a new connection and status; a task's "
            "status asks the server for more than this one."
        )


@server_app.command("remove")
@_cli
def server_remove(
    name: Annotated[
        str,
        typer.Argument(help="The target to remove, or a leftover folder id that 'list' reports."),
    ],
    select_local: Annotated[
        bool,
        typer.Option("--select-local", help="If it is selected, switch to 'local' first."),
    ] = False,
    forget_copies: Annotated[
        bool,
        typer.Option(
            "--forget-copies",
            help="L2: first forget every copy of code this computer sent it; if one is not "
            "forgotten, nothing is removed.",
        ),
    ] = False,
    keep_copies: Annotated[
        bool,
        typer.Option(
            "--keep-copies",
            help="L2: remove it and leave the copies of code this computer sent it there.",
        ),
    ] = False,
) -> None:
    """Remove a target: stop what this client runs for it, delete its key and its folder."""

    _require_no_explicit_source()
    if forget_copies and keep_copies:
        raise ServerCommandRefused(
            "usage", message="give --forget-copies or --keep-copies, not both"
        )
    if _LEFTOVER_ID.match(name):
        if forget_copies:
            raise ServerCommandRefused(
                "usage",
                message="a leftover folder names no server to ask, so nothing can be forgotten "
                "through it; remove it without --forget-copies",
            )
        _remove_leftover(name)
        return
    record = _target_or_fail(name)
    unreadable_selection = False
    try:
        selected = read_selected_target_id()
    except TargetError as error:
        if not select_local:
            raise ServerCommandRefused(
                "selection_invalid" if error.reason == "target_root_unsafe" else error.reason
            ) from None
        # A selection that cannot be read may name this target; --select-local clears it first.
        selected, unreadable_selection = None, True
    if selected == record.target_id and not select_local:
        raise ServerCommandRefused("target_selected")
    root = target_root(record.target_id)
    fence = False
    if record.is_remote and _copies_sent(root):
        # Level L2 (ADR-054): removing the target here leaves what it was sent there, and its
        # claim salt goes with it, so this is the last moment this computer can forget them.
        fence = _forget_or_keep_copies(record, root, forget=forget_copies, keep=keep_copies)
    elif forget_copies:
        typer.echo(
            f"This computer has no record of a copy of code it sent to {record.name}; nothing "
            "was forgotten."
        )
    key_left = cleared = finished = reports_removed = False
    try:
        if fence:
            # Still fenced while its helper is stopped and its folder deleted (with the fence).
            _renew_fence(root)
        with registry_lock():
            # The selection goes first, so a new hook or command can no longer dial the target
            # while its connection is stopped (as ``use_target`` does).
            if selected == record.target_id or unreadable_selection:
                clear_selection()
                cleared = True
            if record.is_remote:
                key_left = _remove_remote(record, root)
                reports_removed = _forget_reports_after_last_remote()
            else:
                from finishup.cli.instance import dispose_instance
                from finishup.config.installation import InstanceIdentityError

                try:
                    dispose_instance(root=root)
                except InstanceIdentityError as error:
                    typer.echo(
                        f"{error.reason}: the named local server could not be removed",
                        err=True,
                    )
                    raise typer.Exit(_UNSAFE) from None
        finished = True
    except TargetError as error:
        raise ServerCommandRefused(error.reason)
    except PathSafetyError as error:
        typer.echo(f"{error.reason_code}: the target folder is unsafe to remove", err=True)
        raise typer.Exit(_UNSAFE) from None
    finally:
        if fence and not finished:
            # The target stays, so does its way back to sending copies at level L2.
            from finishup.client.code_sync_fence import lower_fence

            lower_fence(root)
        if cleared and not finished:
            # A remove that did not finish keeps the switch it already made (SRV-2): say so.
            _say_using_everyday()
    typer.echo(f"Removed server target {record.name} ({record.target_id}).")
    if reports_removed:
        typer.echo(
            "No server elsewhere is left, so this computer no longer keeps what its FinishUP said "
            "of each repository's privacy policy; it is recorded again from when one is added."
        )
    if key_left:
        from finishup.client.credentials import SERVER_CREDENTIAL_SERVICE

        typer.echo(
            f"Its API key stays in the platform credential store, which could not be used now "
            f"(it may be locked, or this session cannot reach it): unlock it, then delete the "
            f"entry '{SERVER_CREDENTIAL_SERVICE}' for {record.target_id} with your system's "
            f"credential tool.",
            err=True,
        )
    if cleared:
        _say_using_everyday()


def _say_using_everyday() -> None:
    typer.echo("Using this computer's everyday FinishUP server.")
    _warn_open_sessions()


def _copies_sent(root: Path) -> bool:
    """Whether this computer's export records say it sent copies of code to the target at
    ``root`` (level L2): an export folder that cannot be listed may name some, so it counts."""

    folder = root / "state" / "code-export"
    try:
        return folder.is_dir() and any(folder.iterdir())
    except OSError:
        return True


def _copies_stay_line(record: ServerTarget) -> str:
    return (
        f"{record.name} may still keep copies of code this computer sent it. Removing it here does "
        "not delete them there, and afterwards this computer cannot ask it to forget them: they "
        "stay until they expire or that server's owner deletes them."
    )


def _ask_forget_first(record: ServerTarget) -> bool | None:
    """Ask on the trusted console whether to forget the copies before removing ``record``.

    True to forget them first, False to keep them there; None when there is no trusted console
    (a script or a pipe), so nothing could be asked. Any other answer cancels the remove.
    """

    from finishup.cli.trusted_console import TrustedConsoleError, TrustedForegroundConsole

    try:
        with TrustedForegroundConsole() as console:
            for line in (
                f"{record.name} may still keep copies of code this computer sent it.",
                f"Forget deletes those copies and their snapshots on {record.name} now.",
                f"Keeping them leaves them there: removing {record.name} here does not delete "
                "them, and once it is removed this computer cannot ask it to forget them, so they "
                "stay until they expire or that server's owner deletes them.",
                f"Forget the copies on {record.name} before removing it?",
            ):
                console.write(line + "\n")
            answer = console.read_choice(
                "Type yes to forget them first, or no to keep them there (anything else cancels): ",
                (b"yes", b"no"),
            )
    except TrustedConsoleError as error:
        if error.reason == "trusted_console_required":
            return None
        raise ServerCommandRefused(
            "authorization_declined",
            message="neither yes nor no was typed, so nothing was removed",
        ) from None
    return answer == b"yes"


def _renew_fence(root: Path) -> None:
    """Raise or renew the target's L2 sync fence (``client.code_sync_fence``), or refuse."""

    from finishup.client.code_sync_fence import CodeSyncFenceError, raise_fence

    try:
        raise_fence(root)
    except CodeSyncFenceError:
        raise ServerCommandRefused("code_copy_fence_unavailable") from None


def _forget_or_keep_copies(record: ServerTarget, root: Path, *, forget: bool, keep: bool) -> bool:
    """Before ``server remove`` changes anything: forget the copies sent, or say they stay.

    ``--forget-copies`` (or yes on the trusted console) forgets every repository as ``server
    code forget --all`` does, through this target's own root, and refuses the remove when one
    was not forgotten, so the owner can retry. ``--keep-copies`` (or no) and a run with no
    trusted console and no flag remove it and say the copies stay: never silent, and never a
    forget nobody asked for.

    Forgetting first raises the target's L2 sync fence before the repositories are listed and
    renews it before each one (``client.code_sync_fence``), so no check can make its helper sync
    a repository again, under its new epoch, while the others are forgotten; a fence that cannot
    be raised refuses the remove before anything is forgotten. Returns whether the fence is up:
    the caller keeps it through the removal, and lowers it when the target stays.
    """

    choice: bool | None
    if forget:
        choice = True
    elif keep:
        choice = False
    else:
        choice = _ask_forget_first(record)
    if choice:
        from finishup.cli.server_code import forget_every_copy, forget_lines
        from finishup.client.code_sync_fence import lower_fence

        _renew_fence(root)
        try:
            outcomes = forget_every_copy(record, renew=lambda: _renew_fence(root))
            for line in forget_lines(record, outcomes):
                typer.echo(line)
            if not all(outcome.forgotten for outcome in outcomes):
                raise ServerCommandRefused(
                    "code_copy_forget_incomplete",
                    message="not every copy on that server was forgotten (each line above says "
                    "why and what to do), so the target was not removed; run the same command "
                    "again once they are, or pass --keep-copies to remove it and leave them there",
                )
        except BaseException:
            lower_fence(root)
            raise
        return True
    typer.echo(_copies_stay_line(record), err=True)
    if choice is None:
        typer.echo(
            f"'finishup server remove {record.name} --forget-copies' forgets them before it "
            "removes a target; this command could not ask, since it does not run on your own "
            "terminal.",
            err=True,
        )
    return False


def _stop_for_remove(record: ServerTarget, root: Path) -> None:
    """Stop what this client runs for ``record``; refuse while it does not stop."""

    try:
        runtime_for(record.kind).stop(root)
    except TargetRuntimeError as error:
        if error.phase != "runtime_unavailable":
            # Never delete a root under a connection still serving it: its endpoint, status, lock
            # and SSH master would go while it runs.
            raise ServerCommandRefused("target_still_connected") from None


def _remove_remote(record: ServerTarget, root: Path) -> bool:
    """Remove remote ``record`` under the registry lock; True when its API key stays behind.

    The caller already cleared a selection that named it. Its connection is stopped, its key
    deleted, and its connection stopped once more right before the folder goes (SRV-2): a process
    that still remembers the target, an MCP bridge, may have started it again meanwhile, and a
    folder is never deleted under a connection still serving it. A first stop that does not
    finish removes nothing (the caller says that a selection it cleared stays cleared). A second
    one keeps the folder; a key already deleted stays deleted, the record says it holds none, and
    the refusal says so. A folder that something changed while it was deleted is only partly
    removed: the refusal says so, and how to finish (the same command, or the leftover's id).
    """

    from finishup.client.targets import remove_target_root

    _stop_for_remove(record, root)
    # An owner action on the key: a connection made under it ends even if the folder outlives
    # this remove (ADR-052, O8).
    bump_credential_generation(root)
    key_left = _delete_key_for_remove(record, root)
    key_deleted = record.credential is not None and not key_left
    try:
        _stop_for_remove(record, root)
    except ServerCommandRefused:
        _record_no_key(root, key_deleted)
        raise ServerCommandRefused(
            "target_still_connected",
            message=_STARTED_AGAIN_KEY_DELETED if key_deleted else _STARTED_AGAIN,
        ) from None
    try:
        remove_target_root(record)
    except OSError:
        # Something changed the folder while it was deleted (A-REMOVE-RACE): what is left is
        # either still this target or a leftover folder, and either is removed by running again.
        _record_no_key(root, key_deleted)
        raise ServerCommandRefused(
            "target_partly_removed", message=_PARTLY_REMOVED_KEY_DELETED if key_deleted else None
        ) from None
    return key_left


def _forget_reports_after_last_remote() -> bool:
    """Once no server elsewhere is recorded, delete the repository reports (ADR-052, O3).

    The reports exist only for the hold, which applies only to a server elsewhere; they are made
    from when the first one is recorded, so removing the last one is their way out. Whether a
    record was deleted; never raises.
    """

    from finishup.client.everyday_policy import remove_repository_reports
    from finishup.client.targets import remote_target_recorded

    if remote_target_recorded():
        return False
    return remove_repository_reports()


def _record_no_key(root: Path, key_deleted: bool) -> None:
    """After a remove that did not finish, record that a key it already deleted is gone.

    ``server status`` must not report a key that no longer exists. The registry lock is held. A
    record that is gone or cannot be rewritten still gets the refusal that says the key went.
    """

    if not key_deleted:
        return
    with contextlib.suppress(TargetError, OSError):
        current = read_target(root)
        if current is not None:
            write_target(root, replace(current, credential=None))


_STARTED_AGAIN: Final = (
    "the connection this client runs for that target started again and did not stop in time, so "
    "its folder was kept; run the same command again"
)
_STARTED_AGAIN_KEY_DELETED: Final = (
    "the connection this client runs for that target started again and did not stop in time, so "
    "its folder was kept, but its API key was already deleted; run the same command again, or "
    "'finishup server login' to keep using that server"
)
_PARTLY_REMOVED_KEY_DELETED: Final = (
    "the target's folder changed while it was being deleted, so only part of it was removed, and "
    "its API key was already deleted; run the same command again, or, if 'finishup server list' "
    "names a leftover folder instead, 'finishup server remove' with that folder's id"
)


def _delete_key_for_remove(record: ServerTarget, root: Path) -> bool:
    """Delete a removed target's API key; True when one stays behind (SRV-4).

    An SSH target never holds a key (OpenSSH authenticates), so no credential store is asked. A
    store the key is recorded in that cannot be used now (a locked platform store) never keeps
    the target from being removed: the caller says which entry stays, by generated id only.
    """

    from finishup.client.credentials import CredentialError, KeyringOrFileCredential

    if record.kind == "ssh":
        return False
    try:
        KeyringOrFileCredential(record.target_id, root, recorded=record.credential).delete()
    except CredentialError:
        return record.credential == "keyring"
    return False


# A target id (``t_`` and 8 hex digits): never a target name, which has no underscore.
_LEFTOVER_ID: Final = re.compile(r"^t_[0-9a-f]{8}$", re.ASCII)


def _remove_leftover(target_id: str) -> None:
    """``server remove ID`` for a registry folder that holds no target record (SRV-1).

    Only a folder ``server list`` reports as a leftover: an add or a remove that was interrupted
    left it, so nothing selects it and this client runs nothing for it. The record is checked
    again under the registry lock; a folder that holds one is a target, removed by its name.
    """

    try:
        with registry_lock():
            removed = remove_leftover_root(target_id)
    except TargetError as error:
        raise ServerCommandRefused(error.reason) from None
    except OSError:
        raise ServerCommandRefused("target_root_unsafe") from None
    if not removed:
        raise ServerCommandRefused("target_unknown")
    typer.echo(f"Removed the leftover server folder {target_id}.")


@server_app.command("login")
@_cli
def server_login(
    name: Annotated[str, typer.Argument(help="An HTTPS server target.")],
    key_file: Annotated[
        Path | None,
        typer.Option("--key-file", help="Read the key once from an owner-only (0600) file."),
    ] = None,
) -> None:
    """Store a new API key for an HTTPS server, checked with that server first.

    The key is typed on your own terminal (hidden) or read once from an owner-only key file. The
    server is asked about it before it is kept: a key it refuses, a server whose certificate does
    not match the trust you recorded, or one of another release stores nothing. A server that does
    not answer keeps the key, not verified yet. Storing it ends every connection made under the
    old key and stops this computer's helper for that server.
    """

    from finishup.client import authorization
    from finishup.client.credentials import CredentialError, KeyringOrFileCredential
    from finishup.client.rest_client import RestUnavailable
    from finishup.client.rest_discovery import check_key

    if not _REST_TARGET_KINDS & authorization.OPEN_REMOTE_KINDS:
        # No kind that takes a key is open: refused before the target, a key file or a prompt
        # is read, as in layers 1 to 4.
        raise ServerCommandRefused("remote_kind_unavailable", message=_LOGIN_REFUSED)
    _require_selection_in_force()
    record = _target_or_fail(name)
    if record.kind not in _REST_TARGET_KINDS:
        raise ServerCommandRefused("credential_not_applicable")
    if not _open_kind(record.kind):
        raise ServerCommandRefused("remote_kind_unavailable", message=_LOGIN_REFUSED)
    refusal = zero_network_connection_refusal(record)
    if refusal is not None:
        # The key is checked with the server before it is kept: a connection, and nothing is
        # sent to a server elsewhere while this computer is zero-network (ADR-051 decision 8).
        raise refusal
    key = _read_api_key(key_file)
    try:
        # The key and the profile it answers are checked (and the profile validated) before
        # anything is stored, over the consented trust when the owner consented already.
        checked = check_key(record, key)
    except RestUnavailable as error:
        raise ServerCommandRefused(
            error.reason, message=_LOGIN_NOT_STORED.get(error.reason)
        ) from None
    root = target_root(record.target_id)
    verdict_phase: str | None = None
    invalidated = False
    try:
        with registry_lock():
            # One registry-locked step (SRV-12): the record as stored now, then the key, the
            # credential generation and the profile together, so a concurrent login or logout
            # never pairs one key with another key's profile or deletes a key this one replaced.
            current = _stored_record(record)
            if current.kind not in _REST_TARGET_KINDS:
                raise ServerCommandRefused("credential_not_applicable")
            credential = KeyringOrFileCredential(
                record.target_id, root, recorded=current.credential
            )
            # Before the new key can be read by anyone: the cached profile (answered to the
            # previous key) is forgotten and the credential generation moves, so every connection
            # made under the old key ends (O8) and nothing is sent under either key until a
            # profile fetched with the key now stored is compared with the consent. Whatever
            # fails after this point leaves that pending state, never the new key paired with
            # the previous consent.
            from finishup.client.server_profile import forget_cached_profile

            forget_cached_profile(root)
            invalidated = True
            if not bump_credential_generation(root):
                raise ServerCommandRefused("target_root_unsafe")
            location = credential.store(key)
            current = replace(current, credential=location)
            write_target(root, current)
            if checked.profile is not None:
                from finishup.client.server_profile import refresh_profile

                verdict_phase = refresh_profile(current, checked.profile).phase
    except CredentialError as error:
        raise _login_refusal(error.reason, record, pending=invalidated) from None
    except TargetError as error:
        raise _login_refusal(error.reason, record, pending=invalidated) from None
    except ServerCommandRefused as refusal:
        if not invalidated:
            raise
        raise _login_refusal(refusal.reason, record, pending=True) from None
    except OSError:
        raise _login_refusal("target_root_unsafe", record, pending=invalidated) from None
    finally:
        if invalidated:
            # The helper may hold the earlier key: it stops, so the next client starts one with
            # the key stored now (A-CRED-STALE), whatever happened after the old key's profile
            # was forgotten.
            _stop_helper_for_key(record, root, which="earlier")
    where = "the platform credential store" if location == "keyring" else "an owner-only file"
    if checked.outcome == "accepted":
        typer.echo(
            f"Stored the API key for {record.name} ({record.target_id}) in {where}; the server "
            "accepted it."
        )
        if verdict_phase is not None:
            typer.echo(
                "This key is a different identity at that server than the one you agreed to, so "
                "FinishUP asks you again before it connects: run "
                f"'finishup server use {record.name}' here."
            )
    else:
        typer.echo(
            f"Stored the API key for {record.name} ({record.target_id}) in {where}, not verified "
            f"yet: the server did not answer ({checked.phase}). FinishUP sends nothing to that "
            "server until the key is checked: once the server is up, run "
            f"'finishup server use {record.name}' here (it checks the key and asks you again), "
            "or log in again."
        )


def _login_refusal(reason: str, record: ServerTarget, *, pending: bool) -> ServerCommandRefused:
    """A login that failed: before anything changed it stored nothing; after the previous key's
    profile was forgotten, nothing is sent to that server until a key is checked."""

    if not pending:
        return ServerCommandRefused(reason)
    return ServerCommandRefused(
        reason,
        message=(
            "the API key could not be stored completely, so FinishUP sends nothing to that "
            "server until a key is checked: run "
            f"'finishup server login {record.name}' again, then 'finishup server use "
            f"{record.name}' here"
        ),
    )


def _stop_helper_for_key(record: ServerTarget, root: Path, *, which: str) -> None:
    """Stop the target's helper so the next client starts one with the key stored now
    (A-CRED-STALE); a stop that does not finish in time is named, with its fix."""

    try:
        runtime_for(record.kind).stop(root)
    except TargetRuntimeError:
        typer.echo(
            f"The connection this computer keeps for {record.target_id} with the {which} key did "
            f"not stop in time; run 'finishup server disconnect {record.name}'.",
            err=True,
        )


_LOGIN_NOT_STORED: Final[dict[str, str]] = {
    "remote_auth_failed": (
        "the server refused this key (unknown, revoked or expired), so nothing was stored; ask "
        "the server's owner for a valid key ('finishup service api-key create' there)"
    ),
    "remote_identity_changed": (
        "the server's certificate did not match the trust recorded for this target, so nothing "
        "was stored; verify the server another way first"
    ),
    "remote_incompatible": (
        "that address is not a FinishUP server of this release's REST contract, so nothing was "
        "stored"
    ),
}


_LOGIN_REFUSED: Final = f"{REMOTE_KIND_UNAVAILABLE}; no key was read or stored"


@server_app.command("logout")
@_cli
def server_logout(name: Annotated[str, typer.Argument(help="An HTTPS server target.")]) -> None:
    """Delete an HTTPS target's stored API key (this computer only; nothing is sent)."""

    from finishup.client.credentials import CredentialError, KeyringOrFileCredential

    _require_selection_in_force()
    record = _target_or_fail(name)
    if record.kind not in {"https", "local_port"}:
        raise ServerCommandRefused("credential_not_applicable")
    root = target_root(record.target_id)
    recorded = record.credential
    try:
        with registry_lock():
            # Serialized with login (SRV-12): the key deleted is the one the record names now,
            # never one a concurrent login stored after this command read the record.
            current = read_target(root)
            recorded = record.credential if current is None else current.credential
            removed = KeyringOrFileCredential(record.target_id, root, recorded=recorded).delete()
            if current is not None:  # one removed meanwhile keeps no record to update
                write_target(root, replace(current, credential=None))
                # An owner action on the key: every connection made under it ends (ADR-052, O8).
                bump_credential_generation(root)
    except CredentialError as error:
        kept = error.reason == "credential_store_unavailable" and recorded == "keyring"
        raise ServerCommandRefused(error.reason, message=_KEY_KEPT if kept else None) from None
    except TargetError as error:
        raise ServerCommandRefused(error.reason)
    typer.echo(
        f"Deleted the API key for {record.target_id}."
        if removed
        else f"No API key was stored for {record.target_id}."
    )
    # The helper may hold the deleted key in memory: it stops, so nothing goes on with it
    # (A-CRED-STALE); every connection made under it already ended with the generation (O8).
    _stop_helper_for_key(record, root, which="deleted")


_KEY_KEPT: Final = (
    "the API key is in the platform credential store, which could not be used now (it may be "
    "locked, or this session cannot reach it), so it was kept; unlock it, then run the same "
    "command again"
)


_RECONSENT_AT_CONNECT: Final = (
    "what that server offers or needs changed since you agreed to use it, so FinishUP connected "
    "nothing and sent nothing; agree again on your own terminal with 'finishup server use NAME' "
    "(it shows what changed and asks you), then connect"
)


def _runtime_call(name: str | None, action: Literal["ensure_ready", "stop"]) -> str:
    record, root, everyday = _resolve(name)
    kind: TargetKind = "local" if record is None else record.kind
    if action == "ensure_ready":
        # Nothing is sent while this computer is zero-network, named for this target (ADR-051
        # decision 8), or to a target confirmed under an older disclosure; 'stop' stays usable.
        refusal = zero_network_connection_refusal(record)
        if refusal is not None:
            raise refusal
        require_current_authorization(record)
    # The everyday server starts here even while another is selected: a spawned service is told
    # its spawner's root (``service run --ambient-root``) and never reads the selection itself.
    try:
        runtime = runtime_for(kind)
        if action == "ensure_ready":
            runtime.ensure_ready(root)
        else:
            runtime.stop(root)
    except TargetRuntimeError as error:
        if error.reason == "service_unavailable" and error.phase == "server_profile_changed":
            # What the server offers changed since the owner agreed: only the owner agrees
            # again, on their own terminal; the registered directive says so (remote_reconsent).
            raise ServerCommandRefused(
                "server_profile_changed",
                message=_RECONSENT_AT_CONNECT,
                continuation="remote_reconsent",
            ) from None
        _runtime_failure(error)
    if record is not None:
        return f"{record.name} ({record.target_id})"
    return "this computer's everyday server" if everyday else "this process's isolated root"


@server_app.command("connect")
@_cli
def server_connect(
    name: Annotated[str | None, typer.Argument(help="A target name, or 'local'.")] = None,
) -> None:
    """Make a target usable now (start its service or its connection); it also starts on demand."""

    label = _runtime_call(name, "ensure_ready")
    typer.echo(f"Connected: {label}.")


@server_app.command("disconnect")
@_cli
def server_disconnect(
    name: Annotated[str | None, typer.Argument(help="A target name, or 'local'.")] = None,
) -> None:
    """Stop the service or connection this client runs for a target (never by pattern)."""

    label = _runtime_call(name, "stop")
    typer.echo(f"Disconnected: {label}.")


_STYLE_LINES: Final[dict[str, str]] = {
    "relay": (
        "this computer's FinishUP helper keeps one SSH connection to it for every program here "
        "(the default)"
    ),
    "direct": (
        "each program here (hooks, the MCP server, commands) opens its own SSH channel to it, "
        "through one OpenSSH connection shared for 15 minutes; FinishUP's helper still answers "
        "that server's background work"
    ),
}
# The same choice for a server reached over HTTPS (ADR-053).
_REST_STYLE_LINES: Final[dict[str, str]] = {
    "relay": (
        "this computer's FinishUP helper keeps one HTTPS connection to it for every program here "
        "and is the only program that reads its API key (the default)"
    ),
    "direct": (
        "each program here (hooks, the MCP server, commands) reads its API key and opens its own "
        "HTTPS connection to it; FinishUP's helper still answers that server's background work"
    ),
}
_STYLE_KINDS: Final = frozenset({"ssh", "https", "local_port"})


@server_app.command("set")
@_cli
def server_set(
    name: Annotated[str, typer.Argument(help="An SSH server target.")],
    style: Annotated[
        str,
        typer.Option(
            "--style",
            help="How this computer reaches it: relay (the default) or direct (advanced).",
        ),
    ],
) -> None:
    """Change how this computer reaches an SSH or HTTPS server (an advanced option)."""

    from finishup.client.helper_status import CONNECTION_STYLES, write_connection_style
    from finishup.client.server_profile import styles_offered

    # Like every command that changes a target: never from a process an isolation variable or a
    # pinned launcher points elsewhere (it would stop and restyle the ambient registry's target).
    _require_no_explicit_source()
    if style not in CONNECTION_STYLES:
        raise ServerCommandRefused("style_invalid")
    record = _target_or_fail(name)
    if record.kind not in _STYLE_KINDS:
        raise ServerCommandRefused("style_not_applicable")
    if not _open_kind(record.kind):
        raise ServerCommandRefused("remote_kind_unavailable")
    if style not in styles_offered(record):
        # Only a style the server's own profile offers (design v2 section 1.2).
        raise ServerCommandRefused("style_unavailable")
    root = target_root(record.target_id)
    try:
        with registry_lock():
            stored = _stored_record(record)
            if stored.kind not in _STYLE_KINDS:
                raise ServerCommandRefused("style_not_applicable")
            # What this client runs for the target ends first, so nothing keeps the old style.
            _stop_for_remove(stored, root)
            write_connection_style(root, style)
    except TargetError as error:
        raise ServerCommandRefused(error.reason) from None
    except OSError:
        raise ServerCommandRefused("target_root_unsafe") from None
    typer.echo(
        f"Server target {record.name} ({record.target_id}) is now reached in the {style} style: "
        f"{(_STYLE_LINES if record.kind == 'ssh' else _REST_STYLE_LINES)[style]}."
    )
    _warn_open_sessions()


# --- what a server may read outside your projects (ADR-051 decision 5) ------------------------

folders_app = typer.Typer(
    help="Choose what a server on another machine may read outside your projects on this computer.",
    no_args_is_help=True,
)
# Every folder it lists is for a server elsewhere (ADR-051 decision 5): an SSH server here.
server_app.add_typer(folders_app, name="folders")

_FOLDER_NOTICE: Final = (
    "Let server target {name} ({target_id}) read files beneath this folder on this computer:",
    "  {folder}",
    "",
    "When that server checks or reviews your work, the FinishUP workspace agent here may send it",
    "the text of files beneath this folder that a task names, that its reviewer asks to read, or",
    "that your agent declared as a test, within FinishUP's usual size limits. The files a task",
    "names beneath it are read in mode local too, even where the server's own privacy policy",
    "admits no folder; that policy still decides whether they may be sent for AI-powered review.",
    "Hidden and credential-named files are never read and links are never followed. A server",
    "that breaks FinishUP's rules could read any other such file beneath this folder and list",
    "the names in its folders. Allow only a folder you would let it see.",
    "Undo it with 'finishup server folders remove {name} FOLDER'.",
    "",
)

# What mode ``local`` lets a server read, a rule-breaking server included (ADR-051 decision 5):
# shown before the typed name whenever the owner chooses ``local``, at ``server add`` (the answer
# or ``--outside-reads local``) and with ``server folders mode NAME local``.
_LOCAL_MODE_BODY: Final = (
    "When that server checks or reviews your work, the FinishUP workspace agent here answers its",
    "reads outside your project folder as a FinishUP service on this computer answers them: the",
    "server's own privacy policy chooses the folders it reads task inputs from, and the agent does",
    "not limit it to folders you list for it. The files a task names beneath a folder you list",
    "for it ('finishup server folders add') are read too, even where that policy names no folder",
    "there. FinishUP's usual safety checks still hold: hidden, credential-named and system files,",
    "your home folder's private folders and FinishUP's own folders are never read, and links are",
    "never followed. But the server's policy does not bind a server that breaks FinishUP's rules:",
    "such a server could read any other such file on this computer and list the names in its",
    "folders. Choose this only for a server you trust as you trust FinishUP on this computer.",
    "Undo it with 'finishup server folders mode {name} listed'.",
)

_LOCAL_MODE_NOTICE: Final = (
    "Let server target {name} ({target_id}) read outside your projects on this computer as",
    "FinishUP on this computer would (mode local):",
    "",
    *_LOCAL_MODE_BODY,
    "",
)


def _remote_target_or_fail(name: str) -> ServerTarget:
    record = _target_or_fail(name)
    if not record.is_remote:
        raise ServerCommandRefused("folders_not_applicable")
    return record


def _confirm_folder_on_trusted_console(record: ServerTarget, folder: str) -> None:
    """Show what admitting ``folder`` lets ``record``'s server read; require the typed name."""

    _confirm_notice(record, _FOLDER_NOTICE, folder=folder)


def _confirm_local_mode_on_trusted_console(record: ServerTarget) -> None:
    """Show what ``local`` mode lets ``record``'s server read; require the typed name."""

    _confirm_notice(record, _LOCAL_MODE_NOTICE)


def _confirm_notice(
    record: ServerTarget, notice: tuple[str, ...], *, folder: str = "", state: str = ""
) -> None:
    from finishup.cli.trusted_console import TrustedConsoleError, TrustedForegroundConsole

    try:
        with TrustedForegroundConsole() as console:
            for line in notice:
                console.write(
                    line.format(
                        name=record.name, target_id=record.target_id, folder=folder, state=state
                    )
                    + "\n"
                )
            console.read_choice(
                "Type the target name to allow it (anything else cancels): ",
                (record.name.encode("ascii"),),
            )
    except TrustedConsoleError as error:
        if error.reason == "trusted_console_required":
            raise ServerCommandRefused("trusted_console_required") from None
        raise ServerCommandRefused("authorization_declined") from None


def _record_of(record: ServerTarget) -> FolderRecord:
    from finishup.client.server_folders import FolderError, read_record

    try:
        return read_record(target_root(record.target_id), record.target_id)
    except FolderError as error:
        raise ServerCommandRefused(error.reason) from None


def _mode_and_origin(record: ServerTarget, current: FolderRecord) -> tuple[str, str]:
    """The mode ``record`` is in, given its readable ``current`` record, and why."""

    from finishup.client.server_folders import mode_of

    mode, source = mode_of(record, current)
    return mode, _mode_origin(source)


def _still_local_line(record: ServerTarget) -> str:
    return (
        f"It is in mode local, so outside your projects it still reads what FinishUP on this "
        f"computer would read; 'finishup server folders mode {record.name} listed' limits it to "
        "the folders you list."
    )


def _removed_aftermath(*, every: bool) -> str:
    """What removing folders leaves (ADR-051 decision 5): the agent stops from its next read, but
    neither a read under way nor a review the server already prepared is undone."""

    them = "them" if every else "it"
    return (
        f"a read already under way may still return files from {them}, and a review the server "
        "already prepared may still send what it read there."
    )


@folders_app.command("add")
@_cli
def server_folders_add(
    name: Annotated[str, typer.Argument(help="A server on another machine, a port or the web.")],
    folder: Annotated[str, typer.Argument(help="An existing folder, by its full path.")],
) -> None:
    """List a folder a server may read: a task's files beneath it in either mode, and in mode
    listed all it reads outside your projects (you confirm it here)."""

    from finishup.cli.privacy_setup import admitted_root_from_path
    from finishup.client.server_folders import (
        MAX_FOLDERS,
        FolderError,
        add_folder,
        folder_admissible,
    )

    _require_selection_in_force()
    record = _remote_target_or_fail(name)
    # The rule the local service uses for an admitted input root: an existing directory named
    # by its absolute, normalized path with no link on the way, never hidden, the filesystem root
    # or beneath one of ``SYSTEM_DIRECTORY_PREFIXES``.
    # Then the home rules 'add_folder' applies again under the lock, checked before the owner is
    # asked, so consent is never collected for a folder that would then be refused.
    canonical = admitted_root_from_path(folder)
    if canonical is None or not folder_admissible(canonical):
        raise ServerCommandRefused("folder_invalid")
    current = _record_of(record)
    if canonical in current.folders:
        typer.echo(f"{record.name} ({record.target_id}) may already read that folder.")
        return
    if len(current.folders) >= MAX_FOLDERS:
        raise ServerCommandRefused("folder_limit")
    _confirm_folder_on_trusted_console(record, canonical)
    try:
        with registry_lock():
            add_folder(target_root(record.target_id), record.target_id, canonical)
    except FolderError as error:
        raise ServerCommandRefused(error.reason) from None
    typer.echo(f"{record.name} ({record.target_id}) may now read files beneath {canonical}.")
    if _mode_and_origin(record, current)[0] == "local":
        typer.echo(
            "It is in mode local, so outside your projects it also reads what FinishUP on this "
            "computer would read; the files a task names beneath this folder are read either way."
        )


@folders_app.command("list")
@_cli
def server_folders_list(
    name: Annotated[str, typer.Argument(help="A server on another machine, a port or the web.")],
) -> None:
    """Show what a server may read outside your projects: its mode and listed folders."""

    from finishup.client.server_folders import FolderError, read_record

    _require_no_explicit_source()
    record = _remote_target_or_fail(name)
    who = f"{record.name} ({record.target_id})"
    try:
        current = read_record(target_root(record.target_id), record.target_id)
    except FolderError:
        # Say what the server may read now, and the one repair, rather than refuse to show it.
        typer.echo(
            f"{who} may read no folder outside your projects on this computer (mode listed, "
            f"{_mode_origin('unreadable')})."
        )
        _emit(_unreadable_record_lines(record.name))
        return
    mode, origin = _mode_and_origin(record, current)
    if mode == "local":
        typer.echo(
            f"{who} reads outside your projects what FinishUP on this computer would read (mode "
            f"local, {origin})."
        )
        if current.folders:
            typer.echo(_LOCAL_FOLDERS_LINE)
            _emit(tuple(f"  {item}" for item in current.folders))
        typer.echo(
            f"To let it read only folders you list: 'finishup server folders mode {record.name} "
            "listed'."
        )
        return
    if not current.folders:
        typer.echo(
            f"{who} may read no folder outside your projects on this computer (mode listed, "
            f"{origin})."
        )
    else:
        typer.echo(f"{who} may read files beneath (mode listed, {origin}):")
        _emit(tuple(f"  {item}" for item in current.folders))
    if current.mode is None:
        # No choice recorded (an official endpoint's 'local' returned above): say how to choose.
        typer.echo(_choose_line(record.name))


@folders_app.command("remove")
@_cli
def server_folders_remove(
    name: Annotated[str, typer.Argument(help="A server on another machine, a port or the web.")],
    folder: Annotated[
        str | None, typer.Argument(help="A folder 'server folders list' shows.")
    ] = None,
    all_folders: Annotated[
        bool,
        typer.Option("--all", help="Remove every folder (also clears a damaged record)."),
    ] = False,
) -> None:
    """Stop listing a folder for a server (from the server's next read)."""

    from finishup.client.server_folders import (
        FolderError,
        clear_folders,
        outside_reads_of,
        remove_folder,
    )

    _require_no_explicit_source()
    if (folder is None) == (not all_folders):
        raise ServerCommandRefused("usage", message="give exactly one of FOLDER or --all")
    record = _remote_target_or_fail(name)
    root = target_root(record.target_id)
    try:
        with registry_lock():
            outcome = (
                clear_folders(root, record.target_id)
                if folder is None
                else ("cleared" if remove_folder(root, record.target_id, folder) else "absent")
            )
    except FolderError as error:
        raise ServerCommandRefused(error.reason) from None
    who = f"{record.name} ({record.target_id})"
    if outcome == "absent":
        typer.echo(f"No such folder was admitted for {who}.")
        return
    if outcome == "reset_to_listed":
        typer.echo(
            f"{who} may no longer read any folder on this computer: its record could not be "
            "read, so it now lists none, in mode listed. 'finishup server folders mode "
            f"{record.name} local' lets it read what FinishUP on this computer would read."
        )
        return
    which = "any folder" if folder is None else "that folder"
    if outside_reads_of(root, record).mode == "local":
        # In mode local a listed folder also admitted the files a task names beneath it, beyond
        # the server's own policy (ADR-051 decision 5, 2026-11-07): removing it stops that.
        beneath = "any folder you listed" if folder is None else "that folder"
        typer.echo(
            f"{who} no longer lists {which}: from its next read it no longer reads the files a "
            f"task names beneath {beneath}, unless the server's own privacy policy covers them; "
            + _removed_aftermath(every=folder is None)
        )
        typer.echo(_still_local_line(record))
        return
    typer.echo(
        f"{who} may no longer read {which} on this computer, from its next read; "
        + _removed_aftermath(every=folder is None)
    )


@folders_app.command("mode")
@_cli
def server_folders_mode(
    name: Annotated[str, typer.Argument(help="A server on another machine, a port or the web.")],
    mode: Annotated[
        str,
        typer.Argument(
            help="local: what FinishUP on this computer would read; listed: only folders you list."
        ),
    ],
) -> None:
    """Choose what a server may read outside your projects (local needs your confirmation)."""

    from finishup.client.server_folders import OUTSIDE_READ_MODES, FolderError, set_mode

    if mode not in OUTSIDE_READ_MODES:
        raise ServerCommandRefused("outside_read_mode_invalid")
    # Widening needs the selection in force and the typed name, as 'folders add' does; the way
    # back narrows and needs neither, as 'folders remove'.
    if mode == "local":
        _require_selection_in_force()
    else:
        _require_no_explicit_source()
    record = _remote_target_or_fail(name)
    current = _record_of(record)
    who = f"{record.name} ({record.target_id})"
    if current.mode == mode:
        typer.echo(f"{who} is already in mode {mode}, set by you.")
        return
    in_force, origin = _mode_and_origin(record, current)
    if mode == "local":
        # A recorded 'local' is the owner's own choice, kept whatever the reviewed list of
        # official endpoints says later, so recording it always takes the typed name, even for
        # an official endpoint, already 'local' unrecorded. Where no trusted console can ask
        # there, nothing is recorded and it stays 'local' as an official endpoint.
        try:
            _confirm_local_mode_on_trusted_console(record)
        except ServerCommandRefused as refusal:
            if refusal.reason != "trusted_console_required" or in_force != "local":
                raise
            typer.echo(
                f"{who} is already in mode local, as {origin}; nothing was recorded. To record "
                "mode local as your own choice, run this command in your own terminal and type "
                "the server's name."
            )
            return
    try:
        with registry_lock():
            set_mode(target_root(record.target_id), record.target_id, mode)
    except FolderError as error:
        raise ServerCommandRefused(error.reason) from None
    other = "listed" if mode == "local" else "local"
    if in_force == mode:
        typer.echo(
            f"{who} stays in mode {mode}, now set by you. 'finishup server folders mode "
            f"{record.name} {other}' changes it."
        )
        return
    if mode == "local":
        typer.echo(
            f"{who} now reads outside your projects what FinishUP on this computer would read "
            f"(mode local), from its next read. Undo it with 'finishup server folders mode "
            f"{record.name} listed'."
        )
        return
    count = len(current.folders)
    listed = "no folder" if count == 0 else f"{count} folder{'s' if count != 1 else ''}"
    typer.echo(
        f"{who} now reads outside your projects only beneath folders you list (mode listed), "
        f"from its next read (a read already under way may still finish): {listed} so far. "
        f"'finishup server folders list {record.name}' shows them."
    )


# --- a repository whose privacy policy here allows no network use (ADR-051 decision 8) --------
#
# Maintainer decision of 2026-11-07, round 4. While a server elsewhere is selected, a repository
# whose own policy on this computer allows no network use is held from it until the owner
# decides: 'add' sends it anyway (the trusted console, a disclosure and the typed target name),
# 'keep' keeps it here without asking again (it only tightens, so an agent may run it), 'remove'
# undoes either. 'list' and 'status' show them. The records are this client's own
# (``client.everyday_policy``, ``client.repository_hold``) and never sent to the server.

repositories_app = typer.Typer(
    help=(
        "Choose whether a server on another machine, a port or the web receives a repository "
        "whose privacy policy on this computer allows no network use."
    ),
    no_args_is_help=True,
)
# Shown since SSH servers open (the owner's answer O4, FR-5): 'add' acts for an SSH target and
# refuses before the console for a kind still closed; 'keep', 'list' and 'remove' always work.
server_app.add_typer(repositories_app, name="repositories")

_NAME_ARGUMENT = Annotated[
    str | None,
    typer.Argument(help="A server on another machine, a port or the web (default: the selected)."),
]
_REPOSITORY_OPTION = Annotated[
    str | None,
    typer.Option(
        "--repository", metavar="FOLDER", help="A folder of the repository (default: this one)."
    ),
]
# Shown in place of a worktree whose path is too long to keep.
_LONG_PATH: Final = "a folder whose path is too long to show"

_REPOSITORY_NOTICE: Final = (
    "Send this repository's work to server target {name} ({target_id}) anyway:",
    "  {folder}",
    "",
    "{state}",
    "While that server is selected, FinishUP sends nothing from this repository to it: its",
    "starts, checks and observations wait on this computer. If you allow it, that server",
    "receives this repository's work as it receives your other projects' work, as the",
    "disclosure you confirmed for it describes: task statements, published work, evidence,",
    "check, respond and receipt traffic, what the FinishUP workspace agent here reads for it",
    "(the change being checked, bounded file excerpts for review, declared task inputs and",
    "results of checks you approved), and the hook observations captured for it, including",
    "those captured here while it was held (without the content captured while it was held).",
    "That server's own privacy policy, not this repository's policy on this computer, then",
    "decides whether any of it goes on to an AI-powered review provider.",
    "Every linked worktree of this repository is included. This repository's privacy policy",
    "on this computer is not changed; if it changes, FinishUP holds the work again until you",
    "allow it again. The hold covers what FinishUP itself reads and claims for this",
    "repository, not what an agent in another folder reads and its hooks capture.",
    "This is your decision on this terminal, not a vault re-authentication.",
    "Undo it with 'finishup server repositories remove {name}' in this repository.",
    "",
)
_NOT_REPORTED_FOOTER: Final = (
    "A repository this computer's FinishUP has not reported is not held; it reports one "
    "whenever that repository's privacy policy is read or changed here, or a session starts in "
    "it while this computer's FinishUP runs. Reports are kept only since a server elsewhere was "
    "first recorded on this computer: there is none from before then."
)


@dataclass(frozen=True, slots=True)
class RepositoryHere:
    """One repository on this computer: the top of the worktree named, and its report key."""

    worktree: str
    key: str


def _repository_target(name: str | None) -> ServerTarget:
    """The remote target ``name`` names, or the selected one; refused for anything else."""

    if name is not None:
        record = _target_or_fail(name)
    else:
        from finishup.cli.zero_network_selection import read_selection_on_disk

        selected = read_selection_on_disk()
        if isinstance(selected, str):
            raise ServerCommandRefused(selected if selected in _REMEDIES else "selection_invalid")
        if selected is None:
            raise ServerCommandRefused("repositories_not_applicable")
        record = selected
    if not record.is_remote:
        raise ServerCommandRefused("repositories_not_applicable")
    return record


def repository_here(folder: str | None = None) -> RepositoryHere:
    """The repository of ``folder`` (the current folder when None), or ``repository_invalid``."""

    import asyncio
    import contextvars
    import os

    from finishup.adapters.workspace_binding import canonical_workspace_locator
    from finishup.client.everyday_policy import worktree_storable
    from finishup.client.everyday_repository import repository_key_for

    try:
        worktree = canonical_workspace_locator(os.getcwd() if folder is None else folder)
    except (OSError, ValueError):
        worktree = None
    if worktree is None or not worktree_storable(worktree):
        raise ServerCommandRefused("repository_invalid")
    key = contextvars.Context().run(asyncio.run, repository_key_for(worktree))
    if key is None:
        raise ServerCommandRefused("repository_invalid")
    return RepositoryHere(worktree, key)


def _live_state(here: RepositoryHere) -> str:
    """Ask this computer's FinishUP about ``here`` now (records what it says); never raises."""

    from finishup.cli.zero_network_selection import live_repository_state

    return live_repository_state(here.worktree)


def _choices_of(record: ServerTarget) -> tuple[RepositoryChoice, ...]:
    from finishup.client.repository_hold import RepositoryRecordError, read_overrides

    try:
        return read_overrides(target_root(record.target_id), record.target_id)
    except RepositoryRecordError as error:
        raise ServerCommandRefused(error.reason) from None


def _state_line(decision: HoldDecision) -> str:
    if decision.policy_read == "live":
        return (
            "Its privacy policy on this computer allows no network use (this computer's "
            "FinishUP said so now)."
        )
    return (
        "Its privacy policy on this computer allows no network use (this computer's FinishUP "
        f"last reported this at {decision.reported_at}; it cannot be asked now)."
    )


def _decision_here(record: ServerTarget, here: RepositoryHere, live: str) -> HoldDecision:
    from finishup.client.repository_hold import decide

    found = decide(target_root(record.target_id), record.target_id, here.key)
    if live in {"no_network", "network_permitted"}:
        return replace(found, policy_read="live")
    return found


def _confirm_repository_on_trusted_console(record: ServerTarget, worktree: str, state: str) -> None:
    """Show what allowing the repository at ``worktree`` sends; require the typed target name."""

    _confirm_notice(record, _REPOSITORY_NOTICE, folder=worktree, state=state)


def confirm_repository_on_this_thread(record: ServerTarget, worktree: str, state: str) -> None:
    """``server repositories add``'s disclosure and typed confirmation, read on the calling
    thread (the SRV-6 pattern): the terminal interface's event loop thread, with the terminal
    handed over, where Ctrl-C reaches the read and declines."""

    from finishup.cli.zero_network_selection import interrupt_answers_the_prompt

    try:
        with interrupt_answers_the_prompt():
            _confirm_repository_on_trusted_console(record, worktree, state)
    except KeyboardInterrupt:
        raise ServerCommandRefused("authorization_declined") from None


def allow_repository(
    record: ServerTarget,
    here: RepositoryHere,
    *,
    confirm: Callable[[ServerTarget, str, str], None] | None = None,
) -> bool:
    """``server repositories add``'s core: ask on the trusted console, then record the allow.

    The terminal interface runs the same core with the terminal handed over, its ``confirm``
    reading the typed name on its own event loop thread. Prints what happened; returns whether an
    allow was recorded. Refusals raise ``ServerCommandRefused``.
    """

    from finishup.client.everyday_policy import repository_report
    from finishup.client.repository_hold import (
        MAX_ALLOWED_REPOSITORIES,
        RepositoryRecordError,
        add_override,
    )

    who = f"{record.name} ({record.target_id})"
    live = _live_state(here)
    if live == "no_policy":
        typer.echo(
            "This computer's FinishUP was never set up, so it has no privacy policy for this "
            "repository and nothing of it is held; nothing was recorded."
        )
        return False
    decision = _decision_here(record, here, live)
    if decision.state == "not_reported":
        typer.echo(
            "This computer's FinishUP has not reported this repository's privacy policy and "
            "cannot be asked now (it is stopped or locked), so nothing of it is held for "
            f"{who}; nothing was recorded."
        )
        return False
    if decision.state == "not_held":
        typer.echo(
            "This repository's privacy policy on this computer allows network use, so "
            f"{who} already receives its work; nothing was recorded."
        )
        return False
    if decision.state == "sent_anyway":
        typer.echo(
            f"{who} already receives this repository's work (you allowed it at "
            f"{decision.decided_at})."
        )
        return False
    choices = _choices_of(record)
    if here.key not in {item.key for item in choices} and len(choices) >= MAX_ALLOWED_REPOSITORIES:
        raise ServerCommandRefused("repository_limit")
    state = _state_line(decision)
    if decision.cause == "grant_changed":
        state += (
            "\nYou chose for it before, but its privacy policy here changed since, so FinishUP "
            "asks again."
        )
    elif decision.state == "kept":
        state += "\nYou chose to keep it on this computer before; allowing it replaces that choice."
    (confirm or _confirm_repository_on_trusted_console)(record, here.worktree, state)
    try:
        with registry_lock():
            # Read again under the lock: the confirmation may have taken minutes.
            report = repository_report(here.key)
            if report is None or not report.no_network or report.no_network_since is None:
                typer.echo(
                    "This repository's privacy policy on this computer no longer allows no "
                    f"network use, so {who} receives its work; nothing was recorded."
                )
                return False
            add_override(
                target_root(record.target_id),
                record.target_id,
                here.key,
                here.worktree,
                report.no_network_since,
            )
    except RepositoryRecordError as error:
        raise ServerCommandRefused(error.reason) from None
    typer.echo(
        f"{who} now receives this repository's work although its privacy policy on this "
        f"computer allows no network use: {here.worktree}. Your agent can repeat its last "
        "FinishUP request now; new hooks and commands send it, and the observations recorded "
        "here while it was held are sent too, without the content captured while it was held. "
        f"Undo it with 'finishup server repositories remove {record.name}' in this repository."
    )
    return True


def allow_repository_here(
    folder: str | None = None,
    *,
    confirm: Callable[[ServerTarget, str, str], None] | None = None,
) -> tuple[ServerTarget, bool]:
    """``server repositories add`` for the selected server and the repository of ``folder`` (the
    current folder when None): the same checks and core. Returns the server and whether an allow
    was recorded; refusals raise ``ServerCommandRefused``."""

    _require_selection_in_force()
    record = _repository_target(None)
    require_open_kind(record)
    refused = zero_network_connection_refusal(record)
    if refused is not None:
        raise refused
    return record, allow_repository(record, repository_here(folder), confirm=confirm)


def keep_repository(record: ServerTarget, here: RepositoryHere, *, named: bool) -> bool:
    """``server repositories keep``'s core: record that this repository stays on this computer.

    It only tightens, so no console is needed and an agent may run it. Lines name the server by
    its generated id and kind, and the commands by the name only when the caller typed it
    (``named``). Returns whether a choice was recorded.
    """

    from finishup.client.everyday_policy import repository_report
    from finishup.client.repository_hold import (
        MAX_ALLOWED_REPOSITORIES,
        RepositoryRecordError,
        add_kept,
    )

    server = f"Server {record.target_id} ({record.kind})"
    suffix = f" {record.name}" if named else ""
    live = _live_state(here)
    decision = _decision_here(record, here, live)
    if decision.state in {"not_reported", "not_held"} or live == "no_policy":
        typer.echo(
            f"{server} holds nothing of this repository: its privacy policy on this computer "
            "allows network use, or this computer's FinishUP has not reported it, so there is "
            "nothing to keep; nothing was recorded."
        )
        return False
    if decision.state == "kept":
        typer.echo(
            f"This repository's work is already kept on this computer for {server}, as chosen "
            f"at {decision.decided_at}; FinishUP does not ask about it again."
        )
        return False
    choices = _choices_of(record)
    if here.key not in {item.key for item in choices} and len(choices) >= MAX_ALLOWED_REPOSITORIES:
        raise ServerCommandRefused("repository_limit")
    try:
        with registry_lock():
            report = repository_report(here.key)
            if report is None or not report.no_network or report.no_network_since is None:
                typer.echo(
                    f"{server} holds nothing of this repository now: its privacy policy on this "
                    "computer allows network use; nothing was recorded."
                )
                return False
            add_kept(
                target_root(record.target_id),
                record.target_id,
                here.key,
                here.worktree,
                report.no_network_since,
            )
    except RepositoryRecordError as error:
        raise ServerCommandRefused(error.reason) from None
    send_anyway = (
        f"'finishup server repositories add{suffix}' in this repository sends it anyway (you "
        "confirm it in your own terminal); "
        if sending_anyway_open(record.kind)
        else f"{_SEND_ANYWAY_LATER[:1].upper()}{_SEND_ANYWAY_LATER[1:]}; "
    )
    typer.echo(
        f"This repository's work is kept on this computer for {server}: while its privacy "
        "policy here allows no network use, nothing FinishUP reads or claims for it is sent "
        "there, and FinishUP does not ask about it again. What an agent in another folder reads "
        f"and its hooks capture is not covered. {send_anyway}"
        f"'finishup server repositories remove{suffix}' asks again."
    )
    if decision.state == "sent_anyway":
        typer.echo(
            "It was sent anyway until now: new connections from it are held from now on, and "
            "open ones close within about a second (a request under way may still finish). What "
            "that server already received stays there."
        )
    return True


@repositories_app.command("add")
@_cli
def server_repositories_add(
    name: _NAME_ARGUMENT = None, repository: _REPOSITORY_OPTION = None
) -> None:
    """Send this repository's work to a server anyway (you confirm it here)."""

    _require_selection_in_force()
    record = _repository_target(name)
    require_open_kind(record)
    refused = zero_network_connection_refusal(record)
    if refused is not None:
        raise refused
    allow_repository(record, repository_here(repository))


_REPOSITORIES_ADD_REFUSED: Final = (
    f"{REMOTE_KIND_UNAVAILABLE}; nothing of this repository is sent to it, and nothing was recorded"
)


def require_open_kind(record: ServerTarget) -> None:
    """Refuse to send a repository to a server whose kind this release does not open.

    ``remote_kind_unavailable`` before any console, prompt or read (the owner's answer O4): no
    server elsewhere can be connected to yet, so allowing one to receive a held repository would
    record a choice nothing can act on. The terminal interface's ``repo-send`` asks the same.
    """

    from finishup.client.authorization import OPEN_REMOTE_KINDS

    if record.kind not in OPEN_REMOTE_KINDS:
        raise ServerCommandRefused("remote_kind_unavailable", message=_REPOSITORIES_ADD_REFUSED)


@repositories_app.command("keep")
@_cli
def server_repositories_keep(
    name: _NAME_ARGUMENT = None, repository: _REPOSITORY_OPTION = None
) -> None:
    """Keep this repository's work on this computer for a server, without being asked again."""

    _require_no_explicit_source()
    record = _repository_target(name)
    keep_repository(record, repository_here(repository), named=name is not None)


def _gone(worktrees: tuple[str, ...]) -> bool:
    """Whether every recorded worktree of an entry is gone (none is a folder any more)."""

    import os

    return bool(worktrees) and not any(os.path.isdir(path) for path in worktrees)


def _forget_gone_reports() -> None:
    """Forget report entries whose recorded worktrees are all gone (moved or deleted)."""

    from finishup.client.everyday_policy import forget_repository_reports, read_repository_reports

    reading = read_repository_reports()
    if isinstance(reading, str):
        return
    gone = [report.key for report in reading if _gone(report.worktrees)]
    if gone:
        forget_repository_reports(gone)


def _shown(path: str | None) -> str:
    import os

    if path is None:
        return _LONG_PATH
    return path if os.path.isdir(path) else f"{path}  — folder not found"


def repository_groups(record: ServerTarget) -> RepositoryGroups:
    """What one remote target holds, keeps and receives anyway, from this computer's records."""

    from finishup.client.everyday_policy import read_repository_reports
    from finishup.client.repository_hold import RepositoryRecordError, decide, read_overrides

    root = target_root(record.target_id)
    reading = read_repository_reports()
    reports = () if isinstance(reading, str) else reading
    try:
        choices: tuple[RepositoryChoice, ...] | None = read_overrides(root, record.target_id)
    except RepositoryRecordError:
        choices = None
    held: list[tuple[str | None, str, str]] = []
    by_key = {report.key: report for report in reports}
    for report in sorted(reports, key=lambda item: item.reported_at, reverse=True):
        decision = decide(root, record.target_id, report.key)
        if decision.state == "held":
            worktree = report.worktrees[0] if report.worktrees else None
            held.append((worktree, report.reported_at, cast(str, decision.cause)))
    chosen: list[tuple[RepositoryChoice, str]] = []
    for choice in choices or ():
        report = by_key.get(choice.key)
        if report is None:
            state = "not_reported"
        elif not report.no_network:
            state = "not_needed"
        elif report.no_network_since != choice.no_network_since:
            state = "grant_changed"
        else:
            state = decide(root, record.target_id, choice.key).state
            state = "applies" if state in {"kept", "sent_anyway"} else "grant_changed"
        chosen.append((choice, state))
    return RepositoryGroups(
        reports="unreadable" if reading == "unreadable" else "readable",
        record="unreadable" if choices is None else "readable",
        held=tuple(held),
        chosen=tuple(chosen),
    )


@dataclass(frozen=True, slots=True)
class RepositoryGroups:
    """One target's repositories: ``held`` (worktree or None, reported at, cause) from reports,
    ``chosen`` (the owner's choice, and whether it applies) from the target's record."""

    reports: Literal["readable", "unreadable"]
    record: Literal["readable", "unreadable"]
    held: tuple[tuple[str | None, str, str], ...]
    chosen: tuple[tuple[RepositoryChoice, str], ...]

    def kept(self) -> tuple[tuple[RepositoryChoice, str], ...]:
        return tuple(item for item in self.chosen if item[0].choice == "keep")

    def allowed(self) -> tuple[tuple[RepositoryChoice, str], ...]:
        return tuple(item for item in self.chosen if item[0].choice == "send")


def _damaged_record_line(record: ServerTarget) -> str:
    return (
        f"The record of repositories {record.name} ({record.target_id}) receives anyway or keeps "
        "here is damaged or not private to you, so it receives none of them: every repository "
        "whose policy here allows no network use is held for it. Repair it on this computer with "
        f"'finishup server repositories remove {record.name} --all'."
    )


_REPORTS_FULL_LINE: Final = (
    "This computer's record of what its FinishUP reported about repositories is full: a report "
    "at {at} did not fit, so that repository is not held until a report of it fits. The record "
    "was kept as it was, and no repository it holds was dropped."
)
_DAMAGED_REPORTS_LINE: Final = (
    "This computer's record of what its FinishUP reported about repositories cannot be read, so "
    "FinishUP holds no repository from it now; it is written again the next time this "
    "computer's FinishUP reports one."
)


def _kind_label(kind: str) -> str:
    return {
        "local": "a named local server on this computer",
        "local_port": "a FinishUP server on this computer's loopback, over HTTPS",
        "ssh": "a FinishUP server on another machine, over SSH",
        "https": "a FinishUP server over HTTPS",
    }[kind]


def repository_list_lines(record: ServerTarget) -> tuple[str, ...]:
    """The owner display of one remote target's held, kept and allowed repositories."""

    groups = repository_groups(record)
    who = f"{record.name} ({record.target_id})"
    lines: list[str] = []
    if groups.record == "unreadable":
        lines.append(_damaged_record_line(record))
    applying = [item for item in groups.chosen if item[1] == "applies"]
    not_needed = [item for item in groups.chosen if item[1] == "not_needed"]
    # A choice whose repository has no report now (forgotten, or the record could not be read):
    # whether its policy allows network use is not known, so it is never said to.
    unreported = [item for item in groups.chosen if item[1] == "not_reported"]
    if not groups.held and not applying and not not_needed and not unreported:
        if groups.record == "readable":
            lines.append(
                f"{who} holds nothing: this computer's FinishUP has reported no repository whose "
                "privacy policy allows no network use, and you chose none."
            )
        return tuple(lines)
    lines.append(f"{who}, {_kind_label(record.kind)}:")
    if groups.held:
        lines.append("  Held (privacy policy here allows no network use):")
        for worktree, reported_at, cause in groups.held:
            changed = (
                "  — its policy changed after you chose for it" if cause == "grant_changed" else ""
            )
            lines.append(f"    {_shown(worktree)}  (reported {reported_at}){changed}")
    kept = [item for item in applying if item[0].choice == "keep"]
    if kept:
        lines.append("  Kept on this computer, as you chose:")
        lines.extend(f"    {_shown(c.worktree)}  (kept {c.decided_at})" for c, _state in kept)
    sent = [item for item in applying if item[0].choice == "send"]
    if sent:
        lines.append("  Sent anyway, as you allowed:")
        lines.extend(f"    {_shown(c.worktree)}  (allowed {c.decided_at})" for c, _state in sent)
    if not_needed:
        lines.append("  Chosen earlier, not needed now (its policy here allows network use):")
        lines.extend(f"    {_shown(c.worktree)}" for c, _state in not_needed)
    if unreported:
        lines.append(
            "  Chosen earlier, its policy here not reported now (this computer's FinishUP has no "
            "report of it, so it is not held until one is made):"
        )
        lines.extend(f"    {_shown(c.worktree)}" for c, _state in unreported)
    keep_and_undo = (
        f"To keep one here without being asked again: 'finishup server repositories keep "
        f"{record.name} --repository FOLDER'. To undo a choice: 'finishup server repositories "
        f"remove {record.name} --repository FOLDER' or '--all'."
    )
    if sending_anyway_open(record.kind):
        lines.append(
            f"To send a held repository anyway: 'finishup server repositories add {record.name} "
            f"--repository FOLDER'. {keep_and_undo}"
        )
    else:
        lines.append(
            f"Sending a held repository anyway arrives in a later release, with servers "
            f"elsewhere. {keep_and_undo}"
        )
    return tuple(lines)


@repositories_app.command("list")
@_cli
def server_repositories_list(name: _NAME_ARGUMENT = None) -> None:
    """Show which repositories each server elsewhere holds, keeps here, or receives anyway."""

    from finishup.client.everyday_policy import read_overflow, read_repository_reports

    _require_no_explicit_source()
    if name is not None:
        records = (_repository_target(name),)
    else:
        records = tuple(record for record in list_targets() if record.is_remote)
    # This folder's repository is read again first, when this computer's FinishUP can answer;
    # never while no server elsewhere is recorded (O3: nothing is asked or recorded before then).
    if remote_target_recorded():
        with contextlib.suppress(ServerCommandRefused):
            _live_state(repository_here())
    _forget_gone_reports()
    if read_repository_reports() == "unreadable":
        typer.echo(_DAMAGED_REPORTS_LINE)
    overflow = read_overflow()
    if overflow is not None:
        typer.echo(_REPORTS_FULL_LINE.format(at=overflow))
    if not records:
        typer.echo("No server on another machine, a port or the web was added.")
    for record in records:
        _emit(repository_list_lines(record))
    typer.echo(_NOT_REPORTED_FOOTER)


@repositories_app.command("remove")
@_cli
def server_repositories_remove(
    name: _NAME_ARGUMENT = None,
    repository: _REPOSITORY_OPTION = None,
    all_repositories: Annotated[
        bool,
        typer.Option("--all", help="Undo every choice (also repairs a damaged record)."),
    ] = False,
) -> None:
    """Undo a choice for a repository: held again, and FinishUP asks again."""

    import os
    import posixpath

    from finishup.cli.zero_network_selection import OPEN_SESSIONS_LINE
    from finishup.client.everyday_policy import forget_repository_reports, read_repository_reports
    from finishup.client.repository_hold import (
        RepositoryRecordError,
        clear_overrides,
        remove_override,
    )

    _require_no_explicit_source()
    if all_repositories and repository is not None:
        raise ServerCommandRefused("usage", message="give at most one of --repository or --all")
    record = _repository_target(name)
    root = target_root(record.target_id)
    who = f"{record.name} ({record.target_id})"
    if all_repositories:
        try:
            with registry_lock():
                outcome = clear_overrides(root, record.target_id)
        except RepositoryRecordError as error:
            raise ServerCommandRefused(error.reason) from None
        if outcome == "absent":
            typer.echo(f"{who} had no repository choice recorded; nothing changed.")
        elif outcome == "repaired":
            typer.echo(
                "The damaged record was replaced by an empty one: every repository whose policy "
                f"here allows no network use is held for {who}."
            )
        else:
            typer.echo(
                f"{who} no longer receives or keeps any repository by your choice: every "
                "repository whose policy here allows no network use is held for it, new "
                "connections from them are held from now on, and open ones close within about "
                "a second (a request under way may still finish). What that server already "
                "received stays there; FinishUP asks again."
            )
            typer.echo(OPEN_SESSIONS_LINE)
        return
    try:
        here: RepositoryHere | None = repository_here(repository)
    except ServerCommandRefused:
        here = None
    folder = os.getcwd() if repository is None else repository
    text = posixpath.normpath(os.path.abspath(folder))
    try:
        with registry_lock():
            removed = remove_override(
                root,
                record.target_id,
                key=None if here is None else here.key,
                worktree=text,
            )
    except RepositoryRecordError as error:
        raise ServerCommandRefused(error.reason) from None
    if here is None:
        # A moved or deleted repository: forget what was reported of it too.
        reading = read_repository_reports()
        if not isinstance(reading, str):
            stale = [
                report.key
                for report in reading
                if text in report.worktrees and _gone(report.worktrees)
            ]
            if stale:
                forget_repository_reports(stale)
    if not removed:
        typer.echo(f"{who} had no choice recorded for this repository; nothing changed.")
        return
    if any(item.choice == "send" for item in removed):
        typer.echo(
            f"{who} no longer receives this repository's work while its privacy policy on this "
            "computer allows no network use: new connections from it are held from now on, and "
            "open ones close within about a second (a request under way may still finish). What "
            "that server already received stays there."
        )
        typer.echo(OPEN_SESSIONS_LINE)
        return
    typer.echo(
        f"This repository is no longer kept on this computer by your choice for {who}: while "
        "its privacy policy here allows no network use it stays held, and FinishUP asks again "
        "whether to send it."
    )
