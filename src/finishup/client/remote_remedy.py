"""The remedy a surface names when the selected FinishUP server is on another machine (ADR-051).

For a remote target every local-service remedy is wrong: no service of this machine serves the
root, so "run 'finishup service run'", "unlock on a local terminal" or "restart the service" would
send the user to a command that cannot help (and on a remote root refuses with
``target_root_is_remote``). Every surface (the CLI, the menu, setup, the MCP bridge, the hooks
and the terminal interface) asks this module instead, so they all say the same thing:

* a failed connection names its remote phase (``remote_unreachable``, ``remote_auth_failed``,
  ``remote_identity_changed``, ``remote_service_not_running``, ``remote_incompatible``) with that
  phase's ADR-030 directive from ``protocol.recovery`` (the text lives there, once); a server
  that refused this client's key answered, so it is never "could not be reached" (and a web
  server this computer holds no API key for was sent nothing);
* a connection never opened names why nothing was sent: a target confirmed under an older
  disclosure (``target_reauthorization_required``), a local service asked for in a remote
  target's root (``target_root_is_remote``), or this computer last reporting a zero-network
  privacy policy (``zero_network_remote_selected``, ADR-051 decision 8);
* a workspace this computer's Git cannot resolve was never sent (the client claims the workspace
  itself before it dials, ``handshake`` / ``handshake_git_version``);
* a locked vault on the server is the server owner's to unlock, on the server host;
* a server that answered it is shutting down or restarting (``service_draining``) is waited
  for, never restarted from here.

Nothing here names a host, a user, a target name or a path: closed tokens and fixed words only.
Local roots get ``None`` everywhere, so their output is unchanged byte for byte. Hook-safe: it
loads only the target records and the protocol's dependency-root modules.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from finishup.protocol.recovery import RecoveryDirective

__all__ = [
    "REMOTE_DRAINING_SUMMARY",
    "REMOTE_KEY_REFUSED_SUMMARY",
    "REMOTE_LOCKED_SUMMARY",
    "REMOTE_NO_KEY_SUMMARY",
    "REMOTE_NOT_SENT_SUMMARIES",
    "REMOTE_UNAVAILABLE_SUMMARY",
    "REMOTE_UNCLAIMABLE_SUMMARY",
    "RemoteRemedy",
    "remote_connection_phase",
    "remote_key_was_sent",
    "remote_phase_summary",
    "remote_remedy",
    "remote_root_selected",
]

# Fixed words only (no host, user, name or path).
# A connection can fail after a request was sent: what the server received before that may be
# recorded, and only a repeat under the same request id recovers it without recording it twice.
REMOTE_UNAVAILABLE_SUMMARY: Final = (
    "the selected FinishUP server on another machine could not be reached, or the connection to "
    "it ended before it answered; a request it already received may be recorded, and repeating "
    "that request under the same request id returns that record instead of a second one"
)
# ``remote_auth_failed``: the server answered and refused this client's key. It was reached, so
# no surface says it could not be reached or did not answer. A key revoked while a connection was
# open can be refused after a request was sent, so the same-request replay stays open.
REMOTE_KEY_REFUSED_SUMMARY: Final = (
    "the selected FinishUP server on another machine answered and refused this client's key; a "
    "request it received before that may be recorded, and repeating that request under the same "
    "request id returns that record instead of a second one"
)
# ``remote_auth_failed`` for a web server this computer holds no API key for: nothing was sent.
REMOTE_NO_KEY_SUMMARY: Final = (
    "this computer holds no API key for the selected FinishUP server on another machine, so "
    "nothing was sent to it"
)
REMOTE_DRAINING_SUMMARY: Final = (
    "the selected FinishUP server on another machine answered that it is shutting down or "
    "restarting, so it did not serve this request; wait a few seconds, then repeat the request "
    "under the same request id"
)
REMOTE_LOCKED_SUMMARY: Final = (
    "the selected FinishUP server's vault is locked, so nothing was recorded; its owner unlocks "
    "it on the server host, then this request can be repeated"
)
REMOTE_UNCLAIMABLE_SUMMARY: Final = (
    "this folder could not be named to the selected FinishUP server as a workspace (this "
    "computer's Git could not resolve it), so nothing was sent; run FinishUP from the folder or "
    "repository you work in"
)
# The remote phases raised before any dial: nothing reached the server, so the summary says so.
REMOTE_NOT_SENT_SUMMARIES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "target_reauthorization_required": (
            "the selected FinishUP server on another machine was confirmed under an older "
            "disclosure of what leaves this computer, so nothing was sent to it"
        ),
        "target_root_is_remote": (
            "the selected FinishUP target is a server on another machine, so this computer has no "
            "FinishUP service of its own for it, and nothing was started"
        ),
        # This computer refused to connect while it is zero-network (ADR-051 decision 8): the
        # server did not fail. The same words as the edge relay's and the native API's.
        "zero_network_remote_selected": (
            "this computer's FinishUP is set to make no network connections, so nothing was sent "
            "to the selected FinishUP server"
        ),
    }
)
# The client-side claim failures ``service.client`` raises before any dial.
_CLAIM_PHASES: Final = frozenset({"handshake", "handshake_git_version"})


@dataclass(frozen=True, slots=True)
class RemoteRemedy:
    """What a surface says for one failure on a remote root.

    ``reason`` is the closed token to report (a remote phase, a claim phase, ``vault_locked`` or
    ``service_draining``); ``summary`` fixed words; ``directive`` the ADR-030 directive, or None
    where the remedy is the server owner's (a locked vault), the server's own (it is draining) or
    this folder's.
    """

    reason: str
    summary: str
    directive: RecoveryDirective | None

    def line(self) -> str:
        """``<reason>: <summary>``, the one-line form the CLI and the menu print first."""

        return f"{self.reason}: {self.summary}"

    def availability(self) -> str:
        """The menu's short state of the selected server: a server that refused the key answered."""

        if self.summary == REMOTE_KEY_REFUSED_SUMMARY:
            return "answered, key refused"
        if self.summary == REMOTE_NO_KEY_SUMMARY:
            return "no API key stored"
        return "not reachable"


def remote_root_selected() -> bool:
    """Whether the root this process uses is a FinishUP server on another machine.

    Read the way the connect seam reads it (``targets.active_root_may_be_remote``): a root that
    holds a target record this process cannot read may be a remote target's, so it counts as
    remote and no surface names a local remedy for it (the connect seam refuses it before any
    dial, ``isolation_root_invalid``, and never starts a local service there); a root that cannot
    be resolved at all keeps its local wording. Hook-safe: it loads only the target records.
    """

    from finishup.client.targets import active_root_may_be_remote

    return active_root_may_be_remote()


def remote_key_was_sent() -> bool:
    """Whether a ``remote_auth_failed`` of the selected server means it refused a key it was sent.

    False only for a web server (``https``, ``local_port``) this computer holds no API key for: the
    connection never opened, so nothing reached that server. Every other case (an SSH server, a
    stored key, a record that cannot be read) is the server's refusal. Hook-safe: it reads only the
    target records, never a key.
    """

    from finishup.client.targets import TargetError, active_target_record

    try:
        record = active_target_record()
    except TargetError:
        return True
    return not (
        record is not None
        and record.kind in {"https", "local_port"}
        and record.credential is None
    )


def remote_phase_summary(phase: str) -> str:
    """The fixed words a surface shows for one remote phase of the selected server."""

    if phase == "remote_auth_failed":
        return REMOTE_KEY_REFUSED_SUMMARY if remote_key_was_sent() else REMOTE_NO_KEY_SUMMARY
    return REMOTE_NOT_SENT_SUMMARIES.get(phase, REMOTE_UNAVAILABLE_SUMMARY)


def remote_connection_phase(error: object) -> str | None:
    """The remote connection phase a failed connection carries, or None for any other failure."""

    from finishup.ports.control import ControlError
    from finishup.protocol.errors import REMOTE_CONNECTION_PHASES

    if (
        isinstance(error, ControlError)
        and error.reason == "service_unavailable"
        and error.phase in REMOTE_CONNECTION_PHASES
    ):
        return error.phase
    return None


def remote_remedy(error: object, *, remote: bool | None = None) -> RemoteRemedy | None:
    """The remedy for ``error`` when the root is remote; None on a local root (unchanged output).

    A failure carrying a remote phase is remote by construction. Any other ``service_unavailable``
    or ``vault_locked`` is checked against the selected root (``remote`` when the caller already
    knows): on a remote root a claim failure is this folder's, any other ``service_unavailable``
    (a connection that closed: a service never answers one) is ``remote_unreachable``, a locked
    vault is the server owner's to unlock, and a server that answered ``service_draining`` is
    waited for.
    """

    from finishup.ports.control import ControlError
    from finishup.protocol.recovery import continuation_for_reason, directive_for

    phase = remote_connection_phase(error)
    if phase is None:
        if not isinstance(error, ControlError) or error.reason not in {
            "service_draining",
            "service_unavailable",
            "vault_locked",
        }:
            return None
        if not (remote_root_selected() if remote is None else remote):
            return None
        if error.reason == "vault_locked":
            return RemoteRemedy("vault_locked", REMOTE_LOCKED_SUMMARY, None)
        if error.reason == "service_draining":
            return RemoteRemedy("service_draining", REMOTE_DRAINING_SUMMARY, None)
        if error.phase in _CLAIM_PHASES:
            directive = (
                directive_for("system_git_upgrade_required")
                if error.phase == "handshake_git_version"
                else None
            )
            return RemoteRemedy(error.phase, REMOTE_UNCLAIMABLE_SUMMARY, directive)
        phase = "remote_unreachable"
    return RemoteRemedy(
        phase, remote_phase_summary(phase), directive_for(continuation_for_reason(phase))
    )
