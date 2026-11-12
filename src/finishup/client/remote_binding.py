"""The workspace binding a connection to a FinishUP server on another machine sends (ADR-051).

One call composes the pieces: the claim on the workspace under the target's own salt, and,
when the connection is to answer the server's workspace calls, the agent for that workspace.
``binding_for_active_root`` decides from the root this process uses: a local root (the everyday
installation, an isolated root that is not a target, or a named local server) sends its locator
exactly as before and needs none of this; a remote root (``local_port``, ``ssh``, ``https``)
claims under the ``claim_salt`` its ``target.json`` keeps. The agent's adapters load only when an
agent is asked for, so a connection that only claims (a short-lived hook, say) stays light.

Before anything is claimed, the hold of a repository whose privacy policy on this computer allows
no network use is decided here, once, for every remote kind alike (ADR-051 decision 8, maintainer
decision of 2026-11-07, round 4; ``client.repository_hold``): a held or kept repository raises its
``TargetError`` (``repository_egress_held`` or ``repository_egress_kept``), after the
authorization checks, so nothing is claimed, dialled, started or recorded; otherwise the binding
carries the ``SendHold`` a long-lived connection re-checks.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import posixpath
from collections.abc import Sequence
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal, cast

from finishup.adapters.workspace_root import RepositoryIdentityError, canonical_workspace_root
from finishup.client.authorization import ConnectionAuthorization, authorize_active_root
from finishup.client.repository_hold import require_sendable
from finishup.client.targets import (
    TargetError,
    active_target_record,
    require_current_authorization,
)
from finishup.client.workspace_claim import workspace_claim_for_root
from finishup.ports.control import WorkspaceLocator
from finishup.service.client import AuthorizationCheck, ClientWorkspaceBinding

if TYPE_CHECKING:
    from finishup.client.targets import ServerTarget

# Derives the agents' opened-workspace handle key from the target's claim salt (a client secret).
_OPENED_HANDLE_KEY_DOMAIN: Final = b"yoetz/opened-workspace-key/v1"

__all__ = ["binding_for_active_root", "is_remote_active_root", "remote_workspace_binding"]


async def remote_workspace_binding(
    workspace: WorkspaceLocator,
    claim_salt: bytes,
    *,
    serve_workspace: bool = True,
    protected: Sequence[str] | None = None,
    target: ServerTarget | None = None,
    authorization: ConnectionAuthorization | None = None,
    role: Literal["connection", "background"] = "connection",
    code_sync: bool = False,
) -> ClientWorkspaceBinding:
    """The claim on ``workspace`` under ``claim_salt``, with its agent when ``serve_workspace``.

    ``protected`` is passed to the agent (``WorkspaceAgentHandler``); by default it protects
    this client's own FinishUP directories and the everyday installation's. The agent answers
    outside reads as the owner chose for the target this process uses now (its outside-read mode
    and listed folders), and only when that target's claim salt is ``claim_salt``; otherwise it
    is ``listed`` with no folder. A locator the shared root rule
    cannot resolve raises its closed ``RepositoryIdentityError``; the caller must then not connect
    with a path instead.

    With ``target`` (the remote record whose salt ``claim_salt`` is), the repository's hold is
    decided once the root is resolved (its one Git read) and before the claim (the gate's last
    step, ``client.authorization``): ``repository_hold.require_sendable`` raises
    ``TargetError("repository_egress_held")`` or ``TargetError("repository_egress_kept")``.
    Otherwise the binding carries the check a long-lived holder makes before every frame and on
    its watch: ``authorization`` (the connection's admission) bound to this repository, or the
    repository's hold alone when no admission was passed.
    The agent then fences every other repository held from that target, or kept on this
    computer (``repository_hold.held_worktrees``, read per call), and answers nothing once that
    check lapses (``own_authorization``: its own repository held or kept, or, with an admission,
    any change that ends the connection).

    ``role`` is the agent's declared role: ``background`` for the helper's agent (ADR-052).
    ``code_sync`` (the helper only, ADR-054) gives a background agent of a target the owner
    consented to at level L2 the responder of the two code-sync operations, while L2 is released;
    every other agent never declares them.
    """

    if type(workspace) is not WorkspaceLocator:
        raise TypeError("workspace_locator_invalid")
    worktree = posixpath.normpath(workspace.path)
    if worktree == "/":
        raise RepositoryIdentityError("repository_locator_invalid")
    root = await canonical_workspace_root(workspace)
    hold = None if target is None else require_sendable(target, root)
    check: AuthorizationCheck | None = hold
    if authorization is not None:
        check = authorization if hold is None else authorization.for_repository(hold.key)
    claim = workspace_claim_for_root(root, claim_salt, worktree)
    key = None if hold is None else hold.key
    if not serve_workspace:
        return ClientWorkspaceBinding(
            claim, authorization=check, worktree=worktree, repository_key=key
        )
    from finishup.client.repository_hold import held_worktrees
    from finishup.client.server_folders import outside_reads_reader
    from finishup.client.targets import target_root
    from finishup.client.workspace_agent import WorkspaceAgentHandler

    # Every agent of this client for this target keys its opened-workspace handles alike, so a
    # handle one connection opened is answered by another (each process serves its own calls).
    opened_key = hmac.new(claim_salt, _OPENED_HANDLE_KEY_DOMAIN, hashlib.sha256).digest()
    # What the owner lets this connection's own target read outside the workspace (ADR-051
    # decision 5): bound now to the target whose salt the claim was made under, never to whichever
    # target this process selects later; another target, or none, reads no folder outside.
    outside = outside_reads_reader(claim_salt=claim_salt)
    # Every other repository held from that same target, or kept on this computer, is fenced
    # from this agent's reads like FinishUP's own directories, read on every call; and once this
    # connection's own authorization lapses (its repository held, say), the agent answers nothing
    # (ADR-051 decision 8, ADR-052).
    held = (
        None
        if target is None
        else partial(held_worktrees, target_root(target.target_id), target.target_id)
    )
    responder = None
    if code_sync and role == "background" and target is not None and hold is not None:
        from finishup.protocol.server_copy import l2_released

        consent = target.consent
        if l2_released() and consent is not None and consent.level == "L2":
            from finishup.client.code_sync import CodeSyncResponder

            responder = CodeSyncResponder(
                target_id=target.target_id,
                repository_key=hold.key,
                root=Path(worktree),
                worktree=claim.worktree,
                check=check,
            )
    return ClientWorkspaceBinding(
        claim,
        WorkspaceAgentHandler(
            workspace,
            protected=protected,
            opened_handle_key=opened_key,
            outside_reads=outside,
            held_roots=held,
            own_authorization=check,
            role=role,
            code_sync=responder,
        ),
        authorization=check,
        worktree=worktree,
        repository_key=key,
    )


def is_remote_active_root() -> bool:
    """Whether the root this process uses is a FinishUP server on another machine.

    True when the selected (or explicitly isolated) root's ``target.json`` names a remote kind:
    ``local_port``, ``ssh`` or ``https``. False for the everyday installation, an isolated root
    that is not a target, and a named local server. A root or record that cannot be read fails
    closed with its closed ``TargetError``; it never reads as local. A remote target the owner
    authorized under an older disclosure raises ``target_reauthorization_required``: nothing may be
    sent to it until the owner confirms the current disclosure (``finishup server use NAME``).
    """

    record = active_target_record()
    require_current_authorization(record)
    return record is not None and record.is_remote


async def binding_for_active_root(
    locator: WorkspaceLocator | None,
    *,
    serve_workspace: bool,
    authorization: ConnectionAuthorization | None = None,
) -> ClientWorkspaceBinding | None:
    """The workspace binding a connection from this process sends, or None to send the locator.

    None for a local root: connect with ``workspace_locator=locator`` exactly as before. For a
    remote root, the claim on ``locator`` under the target's own ``claim_salt`` and, when
    ``serve_workspace``, the workspace agent that answers for it (``remote_workspace_binding``);
    connect with ``workspace_binding=`` that and no locator. A remote root with no workspace
    (``locator`` None) has nothing to claim and also returns None, so the connection sends
    neither. A path is never sent to a remote root either way.

    Fails closed: a root or record that cannot be read raises its ``TargetError``, a remote
    target authorized under an older disclosure raises ``target_reauthorization_required`` (with
    or without a workspace), and a locator the shared root rule cannot resolve raises
    ``RepositoryIdentityError``; the caller must not fall back to sending the locator. Then a
    repository held from that target, or kept on this computer, raises
    ``repository_egress_held`` or ``repository_egress_kept`` (``remote_workspace_binding``).

    For a remote root the shared gate runs first (``client.authorization``; steps 1 to 4), unless
    the caller passes the ``authorization`` it already admitted: in this release no remote kind is
    open, so every remote root is refused there as ``target_root_is_remote``.
    """

    record = active_target_record()
    require_current_authorization(record)
    if record is None or not record.is_remote:
        return None
    if authorization is None:
        authorization = authorize_active_root()
        if authorization is None:
            raise TargetError("target_root_is_remote")
    if locator is None:
        return None
    try:
        salt = base64.b64decode(cast(str, record.claim_salt), validate=True)
    except (TypeError, ValueError, binascii.Error):
        raise TargetError("target_record_invalid") from None
    return await remote_workspace_binding(
        locator, salt, serve_workspace=serve_workspace, target=record, authorization=authorization
    )
