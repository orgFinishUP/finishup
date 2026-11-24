"""``finishup.cli.ai`` loads the configuration models only inside the commands that read them.

The full CLI imports ``finishup.cli.ai`` to register the ``ai`` command group, so a module-level
``finishup.config.models`` import made every command (help, the six operations, service) pay for
the configuration graph. Each ``ai`` command still binds ``ConfigError`` before its ``try`` runs,
so a configuration failure keeps the same message and exit code.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from finishup.cli import ai
from finishup.cli import app as cli
from finishup.config.models import ConfigError

_PROBE = r"""
import json, sys
import finishup.cli.app
print(json.dumps(sorted(n for n in ("finishup.config.models", "finishup.config.privacy") if n in sys.modules)))
"""


def test_importing_the_full_cli_does_not_load_the_configuration_models() -> None:
    result = subprocess.run(
        [sys.executable, "-c", _PROBE], capture_output=True, text=True, check=True
    )
    assert json.loads(result.stdout) == []


def _raise_config_error() -> None:
    raise ConfigError("config_invalid")


def test_ai_status_reports_a_configuration_failure_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def report() -> None:
        _raise_config_error()

    monkeypatch.setattr(ai, "ai_status_report", report)
    result = CliRunner().invoke(cli.app, ["ai", "status"])
    assert result.exit_code == 20
    assert "AI review status is unavailable; run finishup provider status for details." in (
        result.output
    )


def test_ai_key_reports_a_configuration_failure_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def action() -> None:
        _raise_config_error()

    monkeypatch.setattr(ai, "key_action", action)
    result = CliRunner().invoke(cli.app, ["ai", "key"])
    assert result.exit_code == 20
    assert "The provider configuration could not be read. Run finishup ai setup." in result.output


def test_ai_forget_key_reports_a_configuration_failure_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def configured() -> None:
        _raise_config_error()

    monkeypatch.setattr(ai, "_configured_key", configured)
    result = CliRunner().invoke(cli.app, ["ai", "forget-key"])
    assert result.exit_code == 20
    assert "Key removal was not confirmed. Run finishup provider status --json" in result.output


def test_ai_model_reports_a_configuration_failure_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.config.write as config_write

    monkeypatch.setattr(config_write, "config_write_snapshot", _raise_config_error)
    result = CliRunner().invoke(cli.app, ["ai", "model", "gpt-x"])
    assert result.exit_code == 20
    assert "Model setup did not complete. Check the model ID and run finishup ai status." in (
        result.output
    )


def test_a_rollback_refused_by_configuration_says_so_unchanged(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import finishup.config.write as config_write

    def refuse(_config: object, *, expected_bytes: bytes | None) -> None:
        del expected_bytes
        _raise_config_error()

    monkeypatch.setattr(config_write, "write_config_toml_if_unchanged", refuse)
    ai._restore_previous_model(object(), b"")  # pyright: ignore[reportPrivateUsage]
    assert "the settings changed meanwhile, so the previous model was not restored" in (
        capsys.readouterr().err
    )
