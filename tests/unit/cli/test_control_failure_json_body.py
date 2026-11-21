"""A command asked for ``--json`` prints the JSON failure body when the service refuses it.

``privacy receipts list --json`` answers an incompatible or mismatched service with
``{"ok": false, "public_code": ..., "reason": ...}`` on stdout. Every other command that takes
``--json`` and fails at the same control boundary must print that same body, never leave a script
reading stdout with nothing but an exit code (issue #1425).
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest
from tests.unit.config.test_privacy_desired import _policy
from typer.testing import CliRunner

import finishup.cli.app as cli
import finishup.config.paths as paths
from finishup.config.privacy_desired import write_privacy_desired_toml
from finishup.ports.control import ControlError


def _commands(tmp_path: Path) -> dict[str, list[str]]:
    desired = write_privacy_desired_toml(
        _policy(network=False, telemetry=False), tmp_path / "desired.toml"
    )
    return {
        "privacy receipts list": ["privacy", "receipts", "list", "--json"],
        "privacy pending": ["privacy", "pending", "--json"],
        "privacy export-desired": [
            "privacy",
            "export-desired",
            "--output",
            str(tmp_path / "exported.toml"),
            "--json",
        ],
        "privacy apply-desired": ["privacy", "apply-desired", "--input", str(desired), "--json"],
        "integrate codex skill status": ["integrate", "codex", "skill", "status", "--json"],
        "service unlock": ["service", "unlock", "--json"],
        "service auto-unlock repair": ["service", "auto-unlock", "repair", "--json"],
        "service auto-unlock enable": ["service", "auto-unlock", "enable", "--json"],
    }


@pytest.mark.parametrize("reason", ["service_incompatible", "protocol_mismatch"])
def test_json_commands_print_the_control_failure_body(
    reason: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def refuse(*_args: object, **_kwargs: object) -> object:
        raise ControlError(reason, retryable=False)

    def state_dir(**_kwargs: object) -> Path:
        return tmp_path / "state"

    monkeypatch.setattr(paths, "state_dir", state_dir)
    monkeypatch.setattr(cli, "build_service_client", refuse)
    monkeypatch.setattr(cli, "_machine_scope_request_or_none", lambda: {"scope": "machine"})
    runner = CliRunner()
    answers: dict[str, tuple[int, dict[str, object] | None]] = {}
    for name, argv in _commands(tmp_path).items():
        result = runner.invoke(cli.app, argv)
        stdout = result.stdout.strip()
        body = cast(dict[str, object], json.loads(stdout)) if stdout else None
        if body is not None:
            # Each refusal carries its own correlation ID; the rest of the body is fixed.
            body = {key: value for key, value in body.items() if key != "correlation_id"}
        answers[name] = (result.exit_code, body)

    expected_code, expected = answers["privacy receipts list"]
    assert expected_code != 0
    assert expected is not None
    assert expected.get("ok") is False
    assert expected.get("reason") == reason
    differing = {
        name: answer for name, answer in answers.items() if answer != (expected_code, expected)
    }
    assert differing == {}
