"""``finishup service status`` answers without importing pydantic or the protocol models.

The exact ``service status`` forms connect before loading the Typer command graph. The control
client they use names the protocol models only for workflow calls (start, publish, check, ...),
so a status read, which sends none, must not import the model graph or pydantic: that import was
most of the command's start-up cost. The hermetic conftest rebases ``HOME`` and drops the product
variables, so no service is reachable and the command reports that through its ordinary error.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

_HEAVY = ("pydantic", "finishup.protocol.models", "finishup.config.models")
# The control client the status read loads: its presence proves the run reached the connection.
_CLIENT = "finishup.service.client"

_STATUS_PROBE = r"""
import atexit, json, sys
probe = json.loads(sys.argv[1])
def report():
    print("LOADED=" + json.dumps(sorted(name for name in probe if name in sys.modules)),
          file=sys.__stderr__)
atexit.register(report)
sys.argv = ["finishup", *sys.argv[2:]]
from finishup.cli.entry import main
main()
"""


@pytest.mark.parametrize("arguments", [(), ("--json",)], ids=["human", "json"])
def test_service_status_without_a_service_stays_off_protocol_models(
    arguments: tuple[str, ...],
) -> None:
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and probe source
        [
            sys.executable,
            "-c",
            _STATUS_PROBE,
            json.dumps([*_HEAVY, _CLIENT]),
            "service",
            "status",
            *arguments,
        ],
        capture_output=True,
        check=False,
        env=dict(os.environ),
    )
    stderr = completed.stderr.decode()
    lines = stderr.splitlines()
    loaded = [line for line in lines if line.startswith("LOADED=")]
    assert loaded, stderr
    assert json.loads(loaded[-1].removeprefix("LOADED=")) == [_CLIENT]
    assert completed.returncode == 20, stderr
    assert completed.stdout == b""
    assert [line for line in lines if not line.startswith("LOADED=")] == [
        "service_unavailable: run 'finishup service run' under your selected user supervisor"
    ]
