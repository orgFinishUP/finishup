"""``finishup service api-key create|list|revoke`` (ADR-053): a key is shown once, or revoked.

The commands edit the server root's own key file on the server host: ``create`` shows the key
once on the trusted console or writes a new owner-only file, ``list`` never shows a key,
``revoke`` is the reverse. A key that cannot reach its owner is never left active.
"""

from __future__ import annotations

import json
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner

from builders.server_targets import ambient_home
from finishup.cli import app as cli
from finishup.cli import rest_server
from finishup.rest.api_keys import default_api_key_store
from finishup.rest.contract import parse_api_key

_RUNNER = CliRunner()


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


def _rows() -> list[dict[str, object]]:
    listed = _RUNNER.invoke(cli.app, ["service", "api-key", "list", "--json"])
    assert listed.exit_code == 0, listed.output
    return cast(list[dict[str, object]], json.loads(listed.stdout)["keys"])


def test_create_writes_a_new_owner_only_file_list_never_shows_it_and_revoke_ends_it(
    home: Path,
) -> None:
    output = home / "laptop.key"
    created = _RUNNER.invoke(
        cli.app,
        [
            "service",
            "api-key",
            "create",
            "--label",
            "laptop",
            "--scope",
            "agent",
            "--output-file",
            str(output),
        ],
    )
    assert created.exit_code == 0, created.output
    token = output.read_text().strip()
    parsed = parse_api_key(token)
    assert parsed is not None and parsed.key_id in created.stdout
    assert token not in created.stdout
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert token.encode() not in default_api_key_store().path.read_bytes()
    (row,) = _rows()
    assert (row["key_id"], row["label"], row["scope"], row["state"]) == (
        parsed.key_id,
        "laptop",
        "agent",
        "active",
    )
    assert str(row["principal"]).startswith("p_")
    assert _RUNNER.invoke(cli.app, ["service", "api-key", "revoke", parsed.key_id]).exit_code == 0
    again = _RUNNER.invoke(cli.app, ["service", "api-key", "revoke", parsed.key_id])
    assert "already revoked" in again.stdout
    assert [row["state"] for row in _rows()] == ["revoked"]


def test_an_existing_output_file_is_never_written_over_and_no_key_is_made(home: Path) -> None:
    output = home / "taken.key"
    output.write_text("keep me\n")
    created = _RUNNER.invoke(
        cli.app,
        [
            "service",
            "api-key",
            "create",
            "--label",
            "x",
            "--scope",
            "agent",
            "--output-file",
            str(output),
        ],
    )
    assert created.exit_code == 2
    assert "api_key_output_exists" in created.output
    assert output.read_text() == "keep me\n"
    assert _rows() == []


def test_without_a_console_or_an_output_file_nothing_is_created(home: Path) -> None:
    created = _RUNNER.invoke(
        cli.app, ["service", "api-key", "create", "--label", "x", "--scope", "operator"]
    )
    assert created.exit_code == 2
    assert "trusted_console_required" in created.output
    assert _rows() == []


def test_a_key_the_console_could_not_show_is_revoked_at_once(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.cli.trusted_console import TrustedConsoleError

    def refuse(_text: str) -> None:
        raise TrustedConsoleError("eof")

    monkeypatch.setattr(rest_server, "_stdin_is_terminal", lambda: True)
    monkeypatch.setattr(rest_server, "_show_on_console", refuse)
    created = _RUNNER.invoke(
        cli.app, ["service", "api-key", "create", "--label", "x", "--scope", "agent"]
    )
    assert created.exit_code == 2
    assert "api_key_not_shown" in created.output
    assert [row["state"] for row in _rows()] == ["revoked"]


def test_rotation_keeps_the_principal_label_and_scope(home: Path) -> None:
    first = home / "first.key"
    second = home / "second.key"
    base = ["service", "api-key", "create"]
    assert (
        _RUNNER.invoke(
            cli.app,
            [*base, "--label", "ci", "--scope", "operator", "--output-file", str(first)],
        ).exit_code
        == 0
    )
    first_id = cast(object, parse_api_key(first.read_text().strip()))
    assert first_id is not None
    old = _rows()[0]
    rotated = _RUNNER.invoke(
        cli.app, [*base, "--rotate", str(old["key_id"]), "--output-file", str(second)]
    )
    assert rotated.exit_code == 0, rotated.output
    assert f"finishup service api-key revoke {old['key_id']}" in rotated.stdout
    new = [row for row in _rows() if row["key_id"] != old["key_id"]][0]
    assert (new["principal"], new["label"], new["scope"]) == (
        old["principal"],
        "ci",
        "operator",
    )


def test_the_key_commands_run_only_on_the_server_host() -> None:
    from finishup.cli.command_scope import command_scope

    assert command_scope("service api-key create") == "server_host"


@pytest.mark.parametrize(
    ("arguments", "reason"),
    [
        (["--listen", "127.0.0.1:0", "--edge", "proxy"], "rest_edge_invalid"),
        (["--listen", "example.com:443"], "rest_listen_invalid"),
        (["--listen", "127.0.0.1:0"], "rest_tls_required"),
        (["--listen", "0.0.0.0:0", "--behind-proxy"], "rest_proxy_not_loopback"),
    ],
)
def test_rest_run_refuses_before_anything_listens(
    home: Path, arguments: list[str], reason: str
) -> None:
    result = _RUNNER.invoke(cli.app, ["service", "rest", "run", *arguments])
    assert result.exit_code == 2, result.output
    assert reason in result.output
    assert "Serving REST v1" not in result.output
