"""Name a task's workspace by its handle on a claim-bound connection (ADR-051).

A FinishUP server on another machine cannot read paths on this one, and the client never sends it
one: a ``start`` whose ``workspace_ref`` is an absolute path is rewritten, just before it is sent,
to the ``client:`` handle the server answered this connection's hello with. That handle is
derived from the connection's workspace claim, so every start through the same claim names the
same workspace and attach finds the task again. A connection bound by a local path, or not bound
at all, sends the request exactly as written, as does a ``workspace_ref`` that is no path.

A start that names no workspace goes as written too: the server opens it on the connection's
handle. A claim-bound connection with no handle exists for one reason: the server's vault was not
ready when the connection said hello, so the server could not key the claim. No start is sent on
it, whatever its ``workspace_ref``; the refusal is the retryable ``vault_locked`` the server
itself would give, so a caller discards that connection and the first call after the unlock opens
a fresh one that gets a handle.

Rule R (the owner's choice, run u8): the connection's own folder decides the repository and the
worktree, as on ``main``; ``workspace_ref`` never selects which repository is disclosed. So before
the swap, an absolute ``workspace_ref`` must name the worktree the connection serves: the folder
the caller made the connection from (``serving``), reduced to its worktree top. A subfolder, a
symlinked spelling and, on a case-insensitive file system, a case variant of that worktree are
the same folder (they are compared by file identity, never as strings). Any other folder (another
repository, another worktree of the same repository, a repository nested beneath it, a folder that
is no repository, a path that does not exist or is a file) is refused with
``WorkspaceRefNotServed`` and nothing is sent. Without the rule the swap would silently send the
connection's own handle, and the server would read, and at code level L2 copy, the connection's
repository for a task about another one. A connection bound by a local path, or not bound, is
``main``'s L0 behaviour and is untouched (issue #1349 owns L0).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final, Literal, cast

from finishup.adapters.workspace_binding import canonical_workspace_locator
from finishup.ports.control import (
    WORKSPACE_BINDINGS,
    ControlError,
    WorkspaceBinding,
    WorkspaceLocator,
)
from finishup.ports.workspace_agent import workspace_handle_valid
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import StartRequest, public_model_to_wire

__all__ = [
    "StartSurface",
    "WorkspaceRefNotPortable",
    "WorkspaceRefNotServed",
    "names_served_workspace",
    "portable_start_request",
    "portable_workspace_ref",
    "start_request_for_connection",
]

_NOT_PORTABLE_MESSAGE: Final = (
    "The selected FinishUP server is on another machine and gave this connection no workspace "
    "handle, so a start naming a workspace path was not sent."
)


class WorkspaceRefNotPortable(PublicOperationError):
    """A start would have sent a path to a server on another machine; nothing was sent.

    The message and details are fixed; neither names the path. A claim-bound connection without
    a handle raises the retryable ``vault_locked`` ``ControlError`` instead (see the module).
    """

    def __init__(self) -> None:
        super().__init__(
            PublicErrorCode.INVALID_REQUEST,
            _NOT_PORTABLE_MESSAGE,
            False,
            safe_details={"reason_code": "workspace_ref_not_portable"},
        )


# Who sent the start: a command run in a folder, or an MCP bridge a host started in a folder. The
# refusal's continuation differs, because an agent behind a bridge cannot restart it elsewhere.
type StartSurface = Literal["command", "bridge"]

_NOT_SERVED_MESSAGES: Final[dict[StartSurface, str]] = {
    "command": (
        "The selected FinishUP server is on another machine, and this command's connection serves "
        "only the repository worktree it runs in; workspace_ref names another folder, so the "
        "start was not sent. Run the command from the folder workspace_ref names."
    ),
    "bridge": (
        "The selected FinishUP server is on another machine, and this connection serves only the "
        "repository worktree its host started FinishUP in; workspace_ref names another folder, so "
        "the start was not sent. Tell the user, and carry on without FinishUP for that folder."
    ),
}
_NOT_SERVED_CONTINUATIONS: Final[dict[StartSurface, str]] = {
    "command": "workspace_folder_run_required",
    "bridge": "workspace_not_served_tell_user",
}


class WorkspaceRefNotServed(PublicOperationError):
    """Rule R: a start named a folder its connection does not serve; nothing was sent.

    The message and details are fixed: neither names a path, the served one included (the
    message says which folder is served by how the connection was made). ``field`` points at
    ``workspace_ref``; the continuation fits the surface that sent the start.
    """

    def __init__(self, *, surface: StartSurface = "command") -> None:
        if surface not in _NOT_SERVED_MESSAGES:
            raise ValueError("start_surface_invalid")
        super().__init__(
            PublicErrorCode.INVALID_REQUEST,
            _NOT_SERVED_MESSAGES[surface],
            False,
            safe_details={
                "continuation": _NOT_SERVED_CONTINUATIONS[surface],
                "field": "/workspace_ref",
                "reason_code": "workspace_ref_not_served",
            },
        )


def _worktree_top(path: str) -> Path | None:
    """The worktree top of an existing folder, after resolving every link; ``None`` otherwise.

    The top is found as the connection's own claim finds it (``canonical_workspace_locator``: the
    nearest ``.git`` entry, a file for a linked worktree or a submodule); a folder in no
    repository is its own top.
    """

    try:
        resolved = Path(path).resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None
    if not resolved.is_dir():
        return None
    top = canonical_workspace_locator(resolved)
    return None if top is None else Path(top)


def names_served_workspace(workspace_ref: str, serving: str) -> bool:
    """Whether ``workspace_ref`` names the worktree a connection made from ``serving`` serves.

    Both sides are resolved and reduced to their worktree tops, then compared by file identity
    (``os.path.samefile``: device and inode), so a symlinked spelling or, where the file system
    folds case, a case variant is the same folder and a lookalike string never is.
    """

    named, served = _worktree_top(workspace_ref), _worktree_top(serving)
    if named is None or served is None:
        return False
    try:
        return os.path.samefile(named, served)
    except OSError:
        return False


def _serving_path(serving: str | os.PathLike[str] | WorkspaceLocator | None) -> str | None:
    if serving is None:
        return None
    if type(serving) is WorkspaceLocator:
        return serving.path
    text = os.fspath(cast(str | os.PathLike[str], serving))
    return text if type(text) is str and text.startswith("/") else None


def portable_workspace_ref(
    workspace_ref: str | None,
    *,
    workspace_binding: WorkspaceBinding,
    workspace_handle: str | None,
    serving: str | os.PathLike[str] | WorkspaceLocator | None,
    surface: StartSurface = "command",
) -> str | None:
    """The ``workspace_ref`` to send: the handle in place of an absolute path when claim-bound.

    ``serving`` is the folder the connection was made from. On a claim-bound connection an
    absolute path that does not name that folder's worktree raises ``WorkspaceRefNotServed``
    (rule R); with no ``serving`` every path is refused.
    """

    if workspace_binding not in WORKSPACE_BINDINGS:
        raise ValueError("workspace_binding_invalid")
    if workspace_binding != "client_claim":
        return workspace_ref
    if not workspace_handle_valid(workspace_handle):
        # The server could not key this connection's claim at hello: its vault was not ready.
        # No start is sent, whether it names a path or no workspace at all (which the server
        # opens on the handle it could not give), and the caller replaces the connection once
        # the vault is unlocked.
        raise ControlError("vault_locked", retryable=True)
    if workspace_ref is None or not workspace_ref.startswith("/"):
        return workspace_ref
    served = _serving_path(serving)
    if served is None or not names_served_workspace(workspace_ref, served):
        raise WorkspaceRefNotServed(surface=surface)
    return workspace_handle


def portable_start_request(
    request: StartRequest,
    *,
    workspace_binding: WorkspaceBinding,
    workspace_handle: str | None,
    serving: str | os.PathLike[str] | WorkspaceLocator | None,
    surface: StartSurface = "command",
) -> StartRequest:
    """``request`` itself, or the same request naming its workspace by the connection's handle."""

    if type(request) is not StartRequest:
        raise TypeError("start_request_invalid")
    workspace_ref = portable_workspace_ref(
        request.workspace_ref,
        workspace_binding=workspace_binding,
        workspace_handle=workspace_handle,
        serving=serving,
        surface=surface,
    )
    if workspace_ref == request.workspace_ref:
        return request
    wire = public_model_to_wire(request)
    wire["workspace_ref"] = workspace_ref
    return StartRequest.model_validate(wire)


def start_request_for_connection(
    request: StartRequest,
    connection: object,
    *,
    serving: str | os.PathLike[str] | WorkspaceLocator | None,
    surface: StartSurface = "command",
) -> StartRequest:
    """``portable_start_request`` for the connection about to send ``request``.

    The binding and handle are the ones ``ServiceClient`` reports from its hello; ``serving`` is
    the workspace locator the caller made that connection from. A connection that reports none (a
    stand-in, or a client older than workspace binding) is treated as unbound, so the request goes
    out as written, exactly as before.
    """

    binding = getattr(connection, "workspace_binding", "none")
    handle = getattr(connection, "workspace_handle", None)
    if type(binding) is not str or binding not in WORKSPACE_BINDINGS:
        binding = "none"
    return portable_start_request(
        request,
        workspace_binding=cast(WorkspaceBinding, binding),
        workspace_handle=handle if type(handle) is str else None,
        serving=serving,
        surface=surface,
    )
