"""A Codex connection plan probes the Codex executable once for all of its reads."""

from __future__ import annotations

from pathlib import Path

import pytest

from finishup.adapters.integrations import codex_marketplace
from finishup.adapters.integrations.host_discovery import HostInstallation
from finishup.cli import codex_connection


class _Stop(Exception):
    pass


@pytest.mark.parametrize("action", ["connect", "disconnect"])
def test_preparing_a_codex_plan_reads_inside_one_probe_window(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, action: str
) -> None:
    window = codex_marketplace._PROBE_WINDOW  # pyright: ignore[reportPrivateUsage]
    seen: list[bool] = []

    def runtime(**_: object) -> object:
        seen.append(window.get() is not None)
        raise _Stop

    monkeypatch.setattr(codex_connection, "FinishUpRuntime", runtime)
    installation = HostInstallation("codex", tmp_path / "codex", "0.162.1", tmp_path, "Codex")
    with pytest.raises(_Stop):
        codex_connection.prepare_codex_connection(
            installation,
            tmp_path,
            action="connect" if action == "connect" else "disconnect",
            route="strict",
            request_value="req_50000000-0000-4000-8000-000000000001",
        )
    # Open while the plan reads; closed again once it returns or raises.
    assert seen == [True]
    assert window.get() is None
