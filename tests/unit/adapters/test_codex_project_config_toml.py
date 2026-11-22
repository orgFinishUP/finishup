"""A project's Codex config that ``tomllib`` cannot load is reported, not raised (issue #1484).

``<project>/.codex/config.toml`` in a cloned repository is content the repository controls. An
integer past the interpreter's integer string conversion limit (``ValueError``) or deep inline
nesting (``RecursionError``) fits well inside the 64 KiB bound; the project scan behind
``codex connect``, ``disconnect`` and ``status`` must still classify the project with its closed
tokens (``unknown``, ``not_valid_toml``) and carry on.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from finishup.adapters.integrations.codex_mcp import (
    home_project_candidates,
    legacy_registration_dependents,
    project_config_unreadable_reason,
    project_transport_dependence,
    read_bounded_toml,
)

HUGE_INTEGER = "x = " + "1" * 4301 + "\n"
DEEP_ARRAY = "x = " + "[" * 5000 + "]" * 5000 + "\n"
UNLOADABLE = pytest.mark.parametrize("body", [HUGE_INTEGER, DEEP_ARRAY], ids=["huge_int", "deep"])


def _project(root: Path, body: str) -> Path:
    project = root / "cloned"
    (project / ".codex").mkdir(parents=True)
    (project / ".codex" / "config.toml").write_text(body, encoding="utf-8")
    return project


@UNLOADABLE
def test_project_config_reason_is_not_valid_toml(tmp_path: Path, body: str) -> None:
    assert project_config_unreadable_reason(_project(tmp_path, body)) == "not_valid_toml"


@UNLOADABLE
def test_project_transport_dependence_is_unknown(tmp_path: Path, body: str) -> None:
    project = _project(tmp_path, body)
    assert project_transport_dependence(project, after_sweep=False) == "unknown"
    assert project_transport_dependence(project, after_sweep=True) == "unknown"


@UNLOADABLE
def test_bounded_reader_returns_nothing(tmp_path: Path, body: str) -> None:
    assert read_bounded_toml(_project(tmp_path, body) / ".codex" / "config.toml") is None


@UNLOADABLE
def test_home_scan_reports_the_project_unreadable(tmp_path: Path, body: str) -> None:
    project = _project(tmp_path, body)
    home = tmp_path / "codex-home"
    home.mkdir()
    (home / "config.toml").write_text(
        f'[projects."{project}"]\ntrust_level = "trusted"\n', encoding="utf-8"
    )
    use = legacy_registration_dependents(home)
    assert use.unreadable == (str(project),)


@UNLOADABLE
def test_home_scan_names_an_unloadable_user_config(tmp_path: Path, body: str) -> None:
    home = tmp_path / "codex-home"
    home.mkdir()
    (home / "config.toml").write_text(body, encoding="utf-8")
    assert home_project_candidates(home) == ((), ("user_config_unreadable",))
