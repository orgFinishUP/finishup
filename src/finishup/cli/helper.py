"""``finishup helper run --target ID``: the background helper of an SSH server (hidden).

Started on demand by the clients of an SSH target, never by ``finishup service run`` (design v2
section 3, the unified helper; ADR-052). An owner may also run it in the foreground. Its scope is
``client_only``: it serves this computer's own target and never administers a server.
"""

from __future__ import annotations

from typing import Annotated, Final

import typer

__all__ = ["helper_app"]

helper_app = typer.Typer(
    help="Serve an SSH server target's background helper (started on demand).",
    no_args_is_help=True,
    hidden=True,
)

_REFUSALS: Final = {
    2: (
        "helper_target_invalid: give the id of an SSH or HTTPS server target on this computer; "
        "an isolation variable or runtime pin naming another root also refuses"
    ),
    20: "helper_failed: the target's local endpoint could not be bound safely",
}


@helper_app.command("run")
def helper_run(
    target: Annotated[str, typer.Option("--target", help="The SSH target's id (t_<8 hex>).")],
    idle_seconds: Annotated[float, typer.Option("--idle-seconds", hidden=True, min=1.0)] = 900.0,
    epoch: Annotated[str | None, typer.Option("--epoch", hidden=True)] = None,
) -> None:
    """Serve the SSH target until stopped or idle for 15 minutes."""

    from finishup.client.helper import run_helper

    code = run_helper(target, idle_seconds=idle_seconds, epoch=epoch)
    if code in _REFUSALS:
        typer.echo(_REFUSALS[code], err=True)
    raise typer.Exit(code)
