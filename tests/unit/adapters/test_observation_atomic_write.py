"""A failed write of observation state leaves no temporary file behind."""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from finishup.adapters.integrations import finishup_call_rejections, observation_local
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.domain.values import Timestamp

_STAMP = Timestamp("2026-01-01T00:00:00.000Z")
_ARGUMENTS = {
    "request_id": "req_4a3b2c1d-0e9f-4a8b-9c7d-6e5f4a3b2c1d",
    "session_id": "ses_1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
    "writer_id": "wri_6f5e4d3c-2b1a-4c9d-8e7f-6a5b4c3d2e1f",
    "mode": "semantic_required",
}


def _store(tmp_path: Path) -> tuple[LocalObservationStore, str, Path]:
    state = tmp_path / "state"
    store = LocalObservationStore(_state=state, _wall=lambda: _STAMP.as_datetime().timestamp())
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace, _STAMP)
    return store, workspace, state / "observation"


def _temporaries(directory: Path) -> list[str]:
    return sorted(path.name for path in directory.rglob(".*.tmp"))


def _snapshot(directory: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(directory)): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def _no_space(_descriptor: int) -> None:
    raise OSError(errno.ENOSPC, "No space left on device")


def _no_progress(_descriptor: int, _data: object) -> int:
    return 0


@pytest.mark.parametrize(
    ("function", "replacement"),
    [("fsync", _no_space), ("write", _no_progress)],
    ids=["fsync-enospc", "short-write"],
)
def test_failed_state_write_removes_its_temporary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    function: str,
    replacement: object,
) -> None:
    store, workspace, observation = _store(tmp_path)
    committed = _snapshot(observation)

    monkeypatch.setattr(observation_local.os, function, replacement)
    for _ in range(3):
        with pytest.raises(OSError):
            store.note_coverage_gap(workspace, "source_lag")
    monkeypatch.undo()

    assert _temporaries(observation) == []
    assert _snapshot(observation) == committed


def test_failed_replace_still_removes_its_temporary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, workspace, observation = _store(tmp_path)

    def refuse(_source: object, _target: object) -> None:
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(observation_local.os, "replace", refuse)
    with pytest.raises(OSError):
        store.note_coverage_gap(workspace, "source_lag")
    monkeypatch.undo()

    assert _temporaries(observation) == []
    assert os.path.isdir(observation)


@pytest.mark.parametrize(
    ("function", "replacement"),
    [("fsync", _no_space), ("write", _no_progress)],
    ids=["fsync-enospc", "short-write"],
)
def test_failed_rejection_record_write_removes_its_temporary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    function: str,
    replacement: object,
) -> None:
    _, _, observation = _store(tmp_path)
    assert finishup_call_rejections.record_rejected_finishup_call(
        "check", _ARGUMENTS, state_root=tmp_path / "state", now_ms=1
    )
    committed = _snapshot(observation)

    monkeypatch.setattr(finishup_call_rejections.os, function, replacement)
    for attempt in range(3):
        assert not finishup_call_rejections.record_rejected_finishup_call(
            "check", _ARGUMENTS, state_root=tmp_path / "state", now_ms=2 + attempt
        )
    monkeypatch.undo()

    assert _temporaries(observation) == []
    assert _snapshot(observation) == committed
