"""`finishup privacy export-desired --output` names an unwritable path instead of failing inside."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from tests.unit.config.test_privacy_desired import (
    _policy,  # pyright: ignore[reportPrivateUsage]
)

import finishup.cli.app as app
import finishup.config.paths as paths
from finishup.config.privacy_desired import (
    _to_json,  # pyright: ignore[reportPrivateUsage]
    load_privacy_desired_canonical,
)

_REMEDY = (
    "privacy_desired_output_unwritable: Nothing was saved. Choose a writable file path in an "
    "existing directory and export again."
)


class _Client:
    def __init__(self, policy: object) -> None:
        self._policy = policy

    async def privacy_get_effective(self, _request: object) -> object:
        return {"policy": self._policy}

    async def close(self) -> None:
        return None


def _run_export(
    target: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *extra: str,
) -> int | str | None:
    def state_dir(**_kwargs: object) -> Path:
        return tmp_path / "state"

    monkeypatch.setattr(paths, "state_dir", state_dir)
    policy = _to_json(_policy(network=False, telemetry=False))

    async def connect(*_args: object, **_kwargs: object) -> _Client:
        return _Client(policy)

    monkeypatch.setattr(app, "build_service_client", connect)
    monkeypatch.setattr(app, "_machine_scope_request_or_none", lambda: {"scope": "machine"})
    monkeypatch.setattr(
        sys, "argv", ["finishup", "privacy", "export-desired", "--output", str(target), *extra]
    )
    with pytest.raises(SystemExit) as raised:
        app.main()
    return raised.value.code


def _unwritable_target(kind: str, tmp_path: Path) -> Path:
    if kind == "directory":
        target = tmp_path / "existing-directory"
        target.mkdir()
        return target
    if kind == "parent_is_file":
        parent = tmp_path / "plain-file"
        parent.write_text("x", encoding="utf-8")
        return parent / "policy.toml"
    parent = tmp_path / "read-only"
    parent.mkdir()
    parent.chmod(0o500)
    return parent / "policy.toml"


@pytest.mark.parametrize("json_flag", [(), ("--json",)])
@pytest.mark.parametrize("kind", ["directory", "parent_is_file", "read_only_parent"])
def test_unwritable_output_is_a_named_refusal_and_saves_nothing(
    kind: str,
    json_flag: tuple[str, ...],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    if kind == "read_only_parent" and os.geteuid() == 0:
        pytest.skip("a superuser can write beneath a read-only directory")
    target = _unwritable_target(kind, tmp_path)
    try:
        code = _run_export(target, tmp_path, monkeypatch, *json_flag)
    finally:
        if kind == "read_only_parent":
            target.parent.chmod(0o700)
    captured = capsys.readouterr()
    assert code == 2, captured.err
    assert captured.err.strip() == _REMEDY
    assert "internal_error" not in captured.err
    assert str(target) not in captured.err
    assert captured.out == ""
    if kind == "read_only_parent":
        assert list(target.parent.iterdir()) == []
    if kind == "directory":
        assert list(target.iterdir()) == []


def test_export_writes_the_whole_file_and_leaves_no_temporary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "out"
    destination.mkdir()
    target = destination / "policy.toml"
    target.write_text("stale", encoding="utf-8")

    code = _run_export(target, tmp_path, monkeypatch, "--json")

    assert code == 0, capsys.readouterr().err
    assert [entry.name for entry in destination.iterdir()] == ["policy.toml"]
    load_privacy_desired_canonical(target)
