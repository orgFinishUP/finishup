"""The remedy a surface names when the selected FinishUP server is on another machine (ADR-051).

For a remote target every local-service remedy is wrong: no service of this machine serves the
root, so "run 'finishup service run'", "unlock on a local terminal" or "restart the service" would
send the user to a command that cannot help (and on a remote root refuses with
``target_root_is_remote``). Every surface — the CLI, the menu, setup, the MCP bridge, the hooks
and the terminal interface — asks this module instead, so they all say the same thing:

* a failed connection names its remote phase (``remote_unreachable``, ``remote_auth_failed``,
  ``remote_identity_changed``, ``remote_service_not_running``, ``remote_incompatible``) with that
  phase's ADR-030 directive from ``protocol.recovery`` (the text lives there, once);
* a connection this computer refused because it last reported a zero-network policy
  (``zero_network_remote_selected``, ADR-051 decision 8) says so (``remote_summary``): the server
  did not fail to serve it, nothing was sent;
* a locked vault on the server is the server owner's to unlock, on the server host.

Nothing here names a host, a user, a target name or a path: closed tokens and fixed words only.
Local roots get ``None`` everywhere, so their output is unchanged byte for byte.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from finishup.protocol.recovery import RecoveryDirective

__all__ = [
    "REMOTE_LOCKED_SUMMARY",
    "REMOTE_UNAVAILABLE_SUMMARY",
    "ZERO_NETWORK_SUMMARY",
    "RemoteRemedy",
    "remote_connection_phase",
    "remote_remedy",
    "remote_root_directive",
    "remote_root_phase",
    "remote_root_selected",
    "remote_summary",
]

# Fixed words only (no host, user, name or path).
REMOTE_UNAVAILABLE_SUMMARY: Final = (
    "the selected FinishUP server on another machine could not serve this request, so nothing "
    "was recorded"
)
REMOTE_LOCKED_SUMMARY: Final = (
    "the selected FinishUP server's vault is locked, so nothing was recorded; its owner unlocks "
    "it on the server host, then this request can be repeated"
)
# This computer refusing to connect while it is zero-network (ADR-051 decision 8) is not the
# server failing to serve: the same words on every approach's surfaces.
ZERO_NETWORK_SUMMARY: Final = (
    "this computer's FinishUP is set to make no network connections, so nothing was sent to the "
    "selected FinishUP server"
)


def remote_summary(phase: str | None) -> str:
    """The fixed summary a surface shows for a remote phase (the CLI, the terminal, the hooks)."""

    return (
        ZERO_NETWORK_SUMMARY
        if phase == "zero_network_remote_selected"
        else (REMOTE_UNAVAILABLE_SUMMARY)
    )


@dataclass(frozen=True, slots=True)
class RemoteRemedy:
    """What a surface says for one failure on a remote root.

    ``reason`` is the closed token to report (a remote phase, or ``vault_locked``); ``summary``
    fixed words; ``directive`` the phase's ADR-030 directive, or None for the locked vault, whose
    remedy is the server owner's and has no client-side continuation.
    """

    reason: str
    summary: str
    directive: RecoveryDirective | None

    def line(self) -> str:
        """``<reason>: <summary>`` — the one-line form the CLI and the menu print first."""

        return f"{self.reason}: {self.summary}"


def remote_root_selected() -> bool:
    """Whether the root this process uses is a FinishUP server on another machine.

    Read the way the connect seam reads it: a root that holds a target record this process cannot
    read may be a remote target's, so it counts as remote (no surface then names a local remedy
    for it), while a root that cannot be resolved at all keeps its local wording. Hook-safe: it
    loads only the target records.
    """

    from finishup.client.targets import active_root_may_be_remote

    return active_root_may_be_remote()


def remote_root_phase() -> str:
    """The phase of a remote root's connection that named none (a closed one, or none yet).

    ``zero_network_remote_selected`` while this computer last reported a zero-network policy
    (ADR-051 decision 8): every connection to a server elsewhere is refused then, so the way out
    is ``finishup server use local``, never testing the server. ``remote_unreachable`` otherwise.
    Hook-safe: a file read only.
    """

    from finishup.client.everyday_policy import last_reported_zero_network

    if last_reported_zero_network() is not None:
        return "zero_network_remote_selected"
    return "remote_unreachable"


def remote_root_directive() -> RecoveryDirective | None:
    """The directive a remote root's unreachable service names (``remote_root_phase``'s)."""

    from finishup.protocol.recovery import continuation_for_reason, directive_for

    return directive_for(continuation_for_reason(remote_root_phase()))


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
    knows): on a remote root a bare ``service_unavailable`` (a connection that closed) is
    ``remote_root_phase()`` (``remote_unreachable``, or ``zero_network_remote_selected`` while this
    computer last reported a zero-network policy), and a locked vault is the server owner's to
    unlock.
    """

    from finishup.ports.control import ControlError
    from finishup.protocol.recovery import continuation_for_reason, directive_for

    phase = remote_connection_phase(error)
    if phase is None:
        if not isinstance(error, ControlError) or error.reason not in {
            "service_unavailable",
            "vault_locked",
        }:
            return None
        if not (remote_root_selected() if remote is None else remote):
            return None
        if error.reason == "vault_locked":
            return RemoteRemedy("vault_locked", REMOTE_LOCKED_SUMMARY, None)
        phase = remote_root_phase()
    return RemoteRemedy(phase, remote_summary(phase), directive_for(continuation_for_reason(phase)))
