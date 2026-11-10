"""The acceptance matrix's end-to-end smoke: a few of the design's section 1.2 cells, for real.

Each case runs one cell of ``scripts/acceptance/matrix.py`` in its own process, exactly as the
runbook (``docs/runbooks/acceptance-matrix.md``) runs the whole matrix: a client with private XDG
folders, isolated server roots, real TLS, a private ``sshd`` for the SSH cell, every process
stopped by its own PID and the run's folder removed. A cell passes only when every recorded step
passed (the add's handshake and consent, the claim-bound start, publish, check and receipt, the
hold and zero network refusing before any dial, the re-consent after a changed profile, logout,
L2 sync and forget, disconnect and remove); the failing steps are named otherwise.

The SSH cell skips where ``ssh``, ``sshd`` or ``ssh-keygen`` is missing, as the OpenSSH capability
tests do. Slow (each cell takes about a minute); run alone, never beside another real-service run.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_MATRIX = _REPO / "scripts" / "acceptance" / "matrix.py"
_LAUNCHER = _REPO / ".venv" / "bin" / "finishup"
_SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_OPENSSH = all(shutil.which(tool, path=_SYSTEM_PATH) for tool in ("ssh", "sshd", "ssh-keygen"))

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(sys.platform != "linux", reason="the acceptance harness runs on Linux"),
    pytest.mark.skipif(not _LAUNCHER.exists(), reason="no checkout launcher (run uv sync)"),
]


@pytest.mark.parametrize(
    "cell",
    [
        "local",
        pytest.param(
            "ssh-relay-L2",
            marks=pytest.mark.skipif(not _OPENSSH, reason="OpenSSH client or server missing"),
        ),
        "https-gateway-relay-L2",
        "port-native-direct-L2",
    ],
)
def test_an_acceptance_cell_passes_every_step(cell: str, tmp_path: Path) -> None:
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in {"FINISHUP_ISOLATED_ROOT", "YOETZ_ISOLATED_ROOT"}
    }
    result = subprocess.run(  # noqa: S603 - this checkout's own harness and launcher
        [
            sys.executable,
            str(_MATRIX),
            "run",
            "--cells",
            cell,
            "--out",
            str(tmp_path),
            "--launcher",
            str(_LAUNCHER),
        ],
        env=env,
        cwd=_REPO,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    record = tmp_path / f"{cell}.json"
    assert record.exists(), result.stdout[-2000:] + result.stderr[-2000:]
    document = json.loads(record.read_text())
    failed = [
        f"{step['name']}: {step['detail']}"
        for step in document["steps"]
        if step["verdict"] == "fail"
    ]
    assert not failed, "\n".join(failed)
    assert document["verdict"] == "pass"
    assert result.returncode == 0
    names = {step["name"] for step in document["steps"]}
    if cell != "local":
        # The refusals were proven before any dial, and the L2 copy was synced and forgotten.
        assert {"hold refuses before any dial", "zero network refuses before any dial"} <= names
        assert {"sync", "forget", "content forgotten marker", "re-consent", "remove"} <= names
