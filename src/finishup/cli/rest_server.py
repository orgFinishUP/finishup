"""``finishup service api-key`` and ``finishup service rest``: this server's REST edge (ADR-053).

Server-host commands (scope ``server_host``):

* ``api-key create (--label L --scope agent|operator | --rotate KEY_ID) [--expires-in-days N]
  [--output-file F]`` makes an API key and shows it exactly once: on this trusted console, or
  written owner-only (0600) to a new file ``F``. A new key whose secret could not be shown or
  written is revoked at once, so no active key is left that nobody holds. ``--rotate`` keeps the
  rotated key's principal (its client's tasks stay reachable) and leaves the old key valid until
  it is revoked;
* ``api-key list [--json]`` shows every key's id, label, scope, principal and times (never a
  secret);
* ``api-key revoke KEY_ID`` is ``create``'s reverse: the key fails its next request and its
  workspace agents end, on whichever edge serves it.

Refusals are closed tokens with fixed remedy text; no label, key or path is echoed.
"""

from __future__ import annotations

import contextlib
import os
import sys
from pathlib import Path
from typing import Annotated, Final, Literal, cast

import typer

from finishup.protocol.canonical import JsonValue, canonical_encode

__all__ = ["api_key_app", "rest_app"]

api_key_app = typer.Typer(
    help="Create, list and revoke the API keys clients on other computers use over REST.",
    no_args_is_help=True,
)
rest_app = typer.Typer(
    help="Serve this server to clients on other computers over HTTPS (REST v1).",
    no_args_is_help=True,
)

_USAGE: Final = 2
_UNSAFE: Final = 20
_REMEDIES: Final[dict[str, tuple[str, int]]] = {
    "api_keys_damaged": (
        "the API key file is damaged; restore it or move it aside and create new keys",
        _UNSAFE,
    ),
    "api_keys_unsafe": (
        "the API key folder or file is not owner-only; fix its permissions and retry",
        _UNSAFE,
    ),
    "api_key_unknown": ("no key has that id; see 'finishup service api-key list'", _USAGE),
    "api_key_label_invalid": (
        "a label is 1 to 48 letters, digits, spaces, dots, hyphens or underscores",
        _USAGE,
    ),
    "api_key_scope_invalid": ("--scope is agent or operator", _USAGE),
    "api_key_expiry_invalid": ("--expires-in-days takes 1 to 3650", _USAGE),
    "api_key_limit": ("this server holds its maximum of 256 keys; revoke unused ones", _USAGE),
    "api_key_output_exists": (
        "the output file already exists; choose a new path (a key is never written over a file)",
        _USAGE,
    ),
    "trusted_console_required": (
        "a key is shown only on your own interactive terminal; run this there or pass "
        "--output-file to write it to a new owner-only file",
        _USAGE,
    ),
    "api_key_not_shown": (
        "the key could not be shown on your own interactive terminal, so it was revoked; run this "
        "there or pass --output-file to write it to a new owner-only file",
        _USAGE,
    ),
    "api_key_output_failed": (
        "the key could not be written to the output file, so it was revoked and nobody can use "
        "it; give a new path with free space and run this again",
        _UNSAFE,
    ),
}


def _fail(reason: str) -> typer.Exit:
    text, code = _REMEDIES.get(reason, ("the server could not do that", _UNSAFE))
    typer.echo(f"{reason}: {text}", err=True)
    return typer.Exit(code)


def _store() -> object:
    from finishup.rest.api_keys import ApiKeyError, default_api_key_store

    try:
        return default_api_key_store()
    except ApiKeyError as error:
        raise _fail(error.reason) from None


def _open_new_owner_only(path: Path) -> int:
    """Create ``path`` owner-only (0600); an existing file is never written over."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        return os.open(path, flags, 0o600)
    except FileExistsError:
        raise _fail("api_key_output_exists") from None
    except OSError:
        raise _fail("api_keys_unsafe") from None


def _write_key_file(descriptor: int, text: str) -> None:
    """Write ``text`` and a newline in full and flush them to disk; ``OSError`` otherwise."""

    view = memoryview((text + "\n").encode("ascii"))
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short_write")
        view = view[written:]
    os.fsync(descriptor)


def _stdin_is_terminal() -> bool:
    return sys.stdin.isatty()


def _show_on_console(text: str) -> None:
    """Show ``text`` on the trusted console; ``TrustedConsoleError`` when it cannot."""

    from finishup.cli.trusted_console import TrustedForegroundConsole

    with TrustedForegroundConsole() as console:
        console.write("API key (shown once; store it now):\n")
        console.write(text + "\n")


def _revoke_undelivered(key_id: str, reason: str) -> typer.Exit:
    """Revoke a new key whose secret never reached the owner; return the failure to raise.

    Nobody holds that key, so it must not stay active. If the revoke fails too, the exact key id
    and the command that revokes it are named instead of the reason's remedy.
    """

    from finishup.rest.api_keys import ApiKeyError, ApiKeyStore

    try:
        cast(ApiKeyStore, _store()).revoke(key_id)
    except (ApiKeyError, OSError):
        typer.echo(
            f"{reason}: key {key_id} could not be revoked; run "
            f"'finishup service api-key revoke {key_id}'",
            err=True,
        )
        return typer.Exit(_UNSAFE)
    return _fail(reason)


@api_key_app.command("create")
def api_key_create(
    label: Annotated[
        str | None, typer.Option("--label", help="Your name for this key (list only).")
    ] = None,
    scope: Annotated[
        str | None,
        typer.Option("--scope", help="agent (workflow and status) or operator (adds support)."),
    ] = None,
    expires_in_days: Annotated[
        int | None, typer.Option("--expires-in-days", help="Expire after N days.")
    ] = None,
    rotate: Annotated[
        str | None,
        typer.Option(
            "--rotate", help="Keep this key's principal, label and scope; revoke it later."
        ),
    ] = None,
    output_file: Annotated[
        Path | None,
        typer.Option("--output-file", help="Write the key to this new owner-only (0600) file."),
    ] = None,
) -> None:
    """Create an API key and show it once (or write it to a new owner-only file)."""

    from finishup.cli.trusted_console import TrustedConsoleError
    from finishup.rest.api_keys import ApiKeyError, ApiKeyStore

    if scope is not None and scope not in {"agent", "operator"}:
        raise _fail("api_key_scope_invalid")
    store = cast(ApiKeyStore, _store())
    if rotate is not None and (label is None or scope is None):
        try:
            predecessor = next((item for item in store.records() if item.key_id == rotate), None)
        except ApiKeyError as error:
            raise _fail(error.reason) from None
        if predecessor is None:
            raise _fail("api_key_unknown")
        label = label or predecessor.label
        scope = scope or predecessor.scope
    if label is None or scope is None:
        typer.echo("usage: give --label and --scope, or --rotate KEY_ID", err=True)
        raise typer.Exit(_USAGE)
    if output_file is None and not _stdin_is_terminal():
        raise _fail("trusted_console_required")
    # The output file is made first, so a key is created only when there is somewhere to put it;
    # a new key whose secret then fails to reach the owner is revoked before this fails.
    descriptor = None if output_file is None else _open_new_owner_only(output_file)
    try:
        record, key = store.create(
            label,
            cast(Literal["agent", "operator"], scope),
            expires_in_days=expires_in_days,
            rotate=rotate,
        )
    except ApiKeyError as error:
        if descriptor is not None:
            os.close(descriptor)
            cast(Path, output_file).unlink(missing_ok=True)
        if error.active_key_id is not None:
            # Stored, then a later step failed and its own revocation too: nobody holds it.
            raise _revoke_undelivered(error.active_key_id, error.reason) from None
        raise _fail(error.reason) from None
    if descriptor is not None:
        try:
            try:
                _write_key_file(descriptor, key)
            finally:
                os.close(descriptor)
        except OSError:
            with contextlib.suppress(OSError):
                cast(Path, output_file).unlink(missing_ok=True)
            raise _revoke_undelivered(record.key_id, "api_key_output_failed") from None
    else:
        try:
            _show_on_console(key)
        except TrustedConsoleError:
            raise _revoke_undelivered(record.key_id, "api_key_not_shown") from None
    typer.echo(f"Created API key {record.key_id} (scope {record.scope}).")
    if rotate is not None:
        typer.echo(
            "Log its clients in with the new key ('finishup server login NAME' there), then run "
            f"'finishup service api-key revoke {rotate}'."
        )


@api_key_app.command("list")
def api_key_list(
    json_output: Annotated[bool, typer.Option("--json", help="Emit canonical JSON.")] = False,
) -> None:
    """List the API keys: id, label, scope, principal and times (never a secret)."""

    from datetime import UTC, datetime

    from finishup.rest.api_keys import ApiKeyError, ApiKeyStore

    try:
        records = cast(ApiKeyStore, _store()).records()
    except ApiKeyError as error:
        raise _fail(error.reason) from None
    now = datetime.now(UTC)
    rows: list[JsonValue] = [
        {
            "created_at": record.created_at,
            "expires_at": record.expires_at,
            "key_id": record.key_id,
            "label": record.label,
            "principal": record.principal,
            "revoked_at": record.revoked_at,
            "scope": record.scope,
            "state": record.state(now),
        }
        for record in records
    ]
    if json_output:
        sys.stdout.buffer.write(canonical_encode({"keys": rows}) + b"\n")
        sys.stdout.flush()
        return
    if not records:
        typer.echo("No API keys. Create one with 'finishup service api-key create'.")
        return
    for record in records:
        typer.echo(
            f"{record.key_id}  {record.scope:<8}  {record.state(now):<7}  "
            f"{record.principal}  created {record.created_at}  {record.label}"
        )


@api_key_app.command("revoke")
def api_key_revoke(key_id: Annotated[str, typer.Argument(help="The key id to revoke.")]) -> None:
    """Revoke an API key: its next request fails and its workspace agents end."""

    from finishup.rest.api_keys import ApiKeyError, ApiKeyStore

    try:
        changed = cast(ApiKeyStore, _store()).revoke(key_id)
    except ApiKeyError as error:
        raise _fail(error.reason) from None
    typer.echo(
        f"Revoked API key {key_id}." if changed else f"API key {key_id} was already revoked."
    )


_REMEDIES.update(
    {
        "rest_edge_invalid": ("--edge is gateway (the default) or native", _USAGE),
        "rest_listen_invalid": (
            "give --listen HOST:PORT with an IP address or localhost (port 0 picks a free one)",
            _USAGE,
        ),
        "rest_tls_required": (
            "give --tls-cert and --tls-key, or --behind-proxy on a loopback address behind a "
            "TLS-terminating proxy on this host",
            _USAGE,
        ),
        "rest_tls_unusable": (
            "the certificate and key could not be loaded together, the key file is not your own "
            "owner-only (0600) file, or they were given with --behind-proxy",
            _USAGE,
        ),
        "rest_proxy_not_loopback": (
            "--behind-proxy serves plain HTTP, so it listens on a loopback address only",
            _USAGE,
        ),
        "rest_listener_unavailable": (
            "that address could not be bound (in use, or not this host's); choose another",
            _UNSAFE,
        ),
        "service_already_running": (
            "the native edge runs this server's service itself; stop the running one first "
            "('finishup service stop'), or use the default gateway edge beside it",
            _UNSAFE,
        ),
    }
)


@rest_app.command("run")
def rest_run(
    listen: Annotated[
        str, typer.Option("--listen", help="HOST:PORT to listen on (an IP address or localhost).")
    ],
    edge: Annotated[
        str,
        typer.Option(
            "--edge",
            help="gateway (default: a separate process without the vault) or native (inside the "
            "service; your own security review).",
        ),
    ] = "gateway",
    tls_cert: Annotated[
        Path | None, typer.Option("--tls-cert", help="PEM certificate chain.")
    ] = None,
    tls_key: Annotated[
        Path | None, typer.Option("--tls-key", help="PEM private key (an owner-only 0600 file).")
    ] = None,
    behind_proxy: Annotated[
        bool,
        typer.Option(
            "--behind-proxy", help="Plain HTTP on loopback, behind a TLS-terminating proxy."
        ),
    ] = False,
) -> None:
    """Serve this server to clients on other computers over HTTPS (REST v1), in the foreground.

    The gateway edge (the default) is a separate process of your user that holds no vault and
    reaches this server's service over its owner-only control socket, starting it on demand. The
    native edge runs the service itself with the listener inside it; the process holding the vault
    is then on the network, and its security review is yours. Stop either with Ctrl-C or SIGTERM.
    """

    from finishup.config.paths import log_dir
    from finishup.rest.api_keys import ApiKeyError, ApiKeyStore
    from finishup.rest.audit import AUDIT_FILE_NAME, FileAuditSink
    from finishup.rest.listener import ListenerError, RestListener

    if edge not in {"gateway", "native"}:
        raise _fail("rest_edge_invalid")
    store = cast(ApiKeyStore, _store())
    try:
        keys = store.records()
    except ApiKeyError as error:
        raise _fail(error.reason) from None
    try:
        listener = RestListener.bind(
            listen, tls_cert=tls_cert, tls_key=tls_key, behind_proxy=behind_proxy
        )
    except ListenerError as error:
        raise _fail(error.reason) from None
    audit = FileAuditSink(log_dir() / AUDIT_FILE_NAME)
    typer.echo(
        f"Serving REST v1 ({edge} edge) on {listener.scheme} port {listener.port}; "
        "stop it with Ctrl-C.",
        err=True,
    )
    if not keys:
        typer.echo(
            "No API key exists yet: create one with 'finishup service api-key create'.", err=True
        )
    if edge == "gateway":
        _run_gateway(listener, store, audit)
        return
    _run_native(listener, store, audit)


def _run_gateway(listener: object, store: object, audit: object) -> None:
    import anyio

    from finishup.gateway.run import serve_gateway
    from finishup.rest.api_keys import ApiKeyStore
    from finishup.rest.audit import AuditSink
    from finishup.rest.listener import RestListener

    async def main() -> None:
        await serve_gateway(
            cast(RestListener, listener), cast(ApiKeyStore, store), audit=cast(AuditSink, audit)
        )

    anyio.run(main)


def _run_native(listener: object, store: object, audit: object) -> None:
    import anyio

    from finishup.rest.api_keys import ApiKeyStore
    from finishup.rest.audit import AuditSink
    from finishup.rest.listener import RestListener
    from finishup.service.daemon import run_service
    from finishup.service.rest_native import NativeRestEdge

    edge = NativeRestEdge(
        cast(RestListener, listener), cast(ApiKeyStore, store), audit=cast(AuditSink, audit)
    )

    async def main() -> None:
        await run_service(rest_edge=edge)

    try:
        anyio.run(main)
    except SystemExit:
        raise
    except Exception as error:  # noqa: BLE001 - name the closed reason, never the exception text
        reason = getattr(error, "reason", None)
        if reason in {"singleton_held", "service_already_running", "singleton_lock_held"}:
            raise _fail("service_already_running") from None
        raise _fail("rest_listener_unavailable") from None
