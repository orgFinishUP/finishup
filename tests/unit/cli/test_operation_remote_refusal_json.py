"""An operation command refused by a server elsewhere answers a JSON caller in JSON (ADR-052).

A connection to a server elsewhere refused or ended with one of its phases (the shared gate's
refusals) used to reach ``start --json`` (and every other operation command) as text on stderr
only, with nothing on stdout, while ``service status --json`` printed the refusal's JSON body: an
agent or a script reading stdout got nothing to parse. Now every operation command prints that
same body on stdout, with the same exit code and stderr lines. A local control failure renders as
on ``main``, on stderr only.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from builders.server_targets import ambient_home
from finishup.cli import app as app_module
from finishup.cli import bootstrap
from finishup.client import targets
from finishup.client.authorization import AUTHORIZATION_REFUSALS
from finishup.config.paths import reset_selection_memo
from finishup.ports.control import ControlError
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import StartRequest, StatusRequest

_START = json.dumps(
    {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": "req_00000000-0000-4000-8000-000000000071",
        "actor": {"actor_id": "harness:cli", "actor_type": "harness"},
        "client": {"kind": "yoetz_cli", "version": "0.1.0", "integration": "local_cli"},
        "mode": "create_or_attach",
        "task_title": "Remote task",
        "requested_view": "compact",
    }
)
_STATUS = json.dumps(
    {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": "req_00000000-0000-4000-8000-000000000072",
        "actor": {"actor_id": "harness:cli", "actor_type": "harness"},
        "client": {"kind": "yoetz_cli", "version": "0.1.0", "integration": "local_cli"},
        "session_id": "ses_00000000-0000-4000-8000-000000000001",
        "writer_id": "wri_00000000-0000-4000-8000-000000000001",
        "view": "compact",
    }
)


@pytest.fixture
def selected(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as home:
        with targets.registry_lock():
            record, _root = targets.new_remote_target(
                "privbox", "ssh", user="owner", host="secret-host.example", port=22
            )
        targets.write_selection(record)
        reset_selection_memo()
        yield home


def _refusing(monkeypatch: pytest.MonkeyPatch, error: ControlError) -> None:
    async def build(*_args: object, **_kwargs: object) -> object:
        raise error

    monkeypatch.setattr(app_module, "build_service_client", build)


def _expected(error: ControlError) -> tuple[int, list[JsonValue], list[str]]:
    out: list[JsonValue] = []
    err: list[str] = []
    code = bootstrap.control_failure(
        error, json_output=True, stderr_writer=err.append, stdout_writer=out.append
    )
    return code, out, err


@pytest.mark.parametrize("phase", sorted(AUTHORIZATION_REFUSALS))
@pytest.mark.parametrize(
    ("method", "request_type", "body"),
    [("start", StartRequest, _START), ("status", StatusRequest, _STATUS)],
)
def test_an_operation_refused_by_a_server_elsewhere_prints_its_json_body_on_stdout(
    selected: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    phase: str,
    method: str,
    request_type: type,
    body: str,
) -> None:
    error = ControlError("service_unavailable", retryable=True, phase=phase)
    code, out, err = _expected(error)
    _refusing(monkeypatch, error)
    for json_output in (True, False):  # stdout here is not a terminal: JSON either way
        exit_code = asyncio.run(
            app_module._call_workflow(method, request_type, None, body, json_output, None)  # pyright: ignore[reportPrivateUsage]
        )
        captured = capsys.readouterr()
        assert exit_code == code == 20
        assert json.loads(captured.out) == json.loads(json.dumps(out[0]))
        assert captured.err.strip() == "\n".join(err).strip()
    assert str(selected) not in json.dumps(out)


def test_a_support_command_refused_by_a_server_elsewhere_prints_its_json_body_on_stdout(
    selected: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    del selected
    error = ControlError("service_unavailable", retryable=True, phase="target_root_is_remote")
    code, out, _err = _expected(error)
    _refusing(monkeypatch, error)
    exit_code = asyncio.run(
        app_module._call_support("backup_preview", None, "{}", True, None)  # pyright: ignore[reportPrivateUsage]
    )
    captured = capsys.readouterr()
    assert exit_code == code
    assert json.loads(captured.out) == json.loads(json.dumps(out[0]))


@pytest.mark.parametrize(
    "error",
    [
        ControlError("service_unavailable", retryable=True),
        ControlError("invalid_request"),
    ],
)
def test_a_local_control_failure_still_prints_nothing_on_stdout(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], error: ControlError
) -> None:
    """As on ``main``: only a refusal by a server elsewhere gained the JSON body."""

    _refusing(monkeypatch, error)
    asyncio.run(
        app_module._call_workflow("start", StartRequest, None, _START, True, None)  # pyright: ignore[reportPrivateUsage]
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err
