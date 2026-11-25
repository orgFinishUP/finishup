"""Closed hook failure reasons for unexpected exceptions and drain preflight stages (tb4n2 N-3)."""

from __future__ import annotations

import errno
import io
import json
import os
from pathlib import Path
from typing import Any

import pytest

from builders.codex_rollout import failed_shell_rollout
from finishup.adapters.integrations import codex_session_stream as stream_module
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.cli import observe_hooks as observe_hooks_module
from finishup.cli.hook_diagnostics import observe_exception_reason, record_hook_diagnostic
from finishup.cli.observe_hooks import handle_observe, handle_spool, map_hook_payload_to_envelope
from finishup.domain.observation import ObservationGapCode, ObservationStatusQuery
from finishup.observability.exception_reasons import EXCEPTION_REASON_TOKENS


def _reasons(state: Path) -> list[str]:
    path = state / "observation/hook-diagnostics.jsonl"
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text().splitlines() if line]
    return [row["reason"] for row in rows if "reason" in row]


class _Leaky(ValueError):
    """A subclass whose name is not in the reviewed vocabulary."""


def test_observe_exception_reason_is_closed() -> None:
    assert observe_exception_reason(ValueError("/secret/path")) == "observe_exception_value_error"
    assert observe_exception_reason(OSError("x")) == "observe_exception_os_error"
    # An unreviewed class never reaches the row, even when it subclasses a reviewed one.
    assert observe_exception_reason(_Leaky("x")) == "observe_exception_unavailable"
    assert all(token.startswith("exception_") for token in EXCEPTION_REASON_TOKENS)


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (ValueError("/srv/user/secret"), "observe_exception_value_error"),
        (OSError("disk"), "observe_exception_os_error"),
        (_Leaky("named"), "observe_exception_unavailable"),
    ],
)
def test_unexpected_observe_pass_exception_records_its_class(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: Exception, expected: str
) -> None:
    def explode(**_kwargs: object) -> object:
        raise failure

    monkeypatch.setattr(observe_hooks_module, "LocalObservationStore", explode)
    stdout = io.BytesIO()
    code = handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps({"session_id": "s1", "tool_name": "shell"}).encode(),
        stdout=stdout,
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert code == 0
    assert json.loads(stdout.getvalue().decode()) == {}
    reasons = _reasons(tmp_path)
    assert expected in reasons
    assert "observe" not in reasons
    raw = (tmp_path / "observation/hook-diagnostics.jsonl").read_text()
    assert "secret" not in raw and "named" not in raw


def test_unexpected_spool_exception_records_its_class(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(*_args: object, **_kwargs: object) -> None:
        raise OSError("spool")

    store = LocalObservationStore(_state=tmp_path)
    store.grant_consent(store.workspace_commitment(str(tmp_path.resolve())))
    monkeypatch.setattr(observe_hooks_module.HookSpool, "append", explode)
    handle_spool(
        event_name="PreToolUse",
        stdin_bytes=b'{"session_id":"spool","tool_name":"shell"}',
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
    )
    assert _reasons(tmp_path) == ["observe_exception_os_error"]


def test_legacy_bare_observe_reason_is_still_admitted(tmp_path: Path) -> None:
    record_hook_diagnostic("observe", "PostToolUse", _state=tmp_path)
    assert _reasons(tmp_path) == ["observe"]


def _store_with_row(state: Path) -> tuple[LocalObservationStore, str]:
    store = LocalObservationStore(_state=state)
    workspace = store.workspace_commitment(str(state.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "sess")
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {
            "session_id": "sess",
            "hook_event_name": "PostToolUse",
            "tool_name": "shell",
            "correlation_id": "corr-1",
            "exit_status": 0,
        },
        session_commitment=store.session_commitment("sess"),
        event_ordinal=1,
        key_material=store.key_material(),
    )
    store.enqueue_outbox(workspace, "sess", envelope)
    return store, workspace


class _Client:
    closed = False

    async def close(self) -> None:
        _Client.closed = True


async def _timeout(_kind: object) -> object:
    raise TimeoutError


async def _refused(_kind: object) -> object:
    raise ConnectionRefusedError("socket")


async def _connected(_kind: object) -> object:
    return _Client()


async def _held(_kind: object) -> object:
    # The connection seam refused before anything was claimed or dialled (ADR-051 decision 8).
    from finishup.ports.control import ControlError

    raise ControlError("service_unavailable", retryable=True, phase="repository_egress_held")


async def _kept(_kind: object) -> object:
    from finishup.ports.control import ControlError

    raise ControlError("service_unavailable", retryable=True, phase="repository_egress_kept")


_CONNECT_FAILURES = [
    (_timeout, "drain_connect_timeout"),
    (_refused, "drain_connect_failed"),
    (_held, "repository_egress_held"),
    (_kept, "repository_egress_kept"),
]


@pytest.mark.anyio
@pytest.mark.parametrize(("connect", "expected"), _CONNECT_FAILURES)
async def test_leased_drain_connect_failures_are_split(
    tmp_path: Path, connect: object, expected: str
) -> None:
    store, workspace = _store_with_row(tmp_path)
    await observe_hooks_module._drain_outbox(  # pyright: ignore[reportPrivateUsage]
        store,
        workspace_commitment=workspace,
        codex_session_id="sess",
        connect=connect,  # type: ignore[arg-type]
        _state=tmp_path,
    )
    assert _reasons(tmp_path) == [expected]
    assert store.pending_outbox_count(workspace) == 1


@pytest.mark.anyio
async def test_leased_native_content_stage_failure_is_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, workspace = _store_with_row(tmp_path)

    async def broken_stage(*_args: object, **_kwargs: object) -> object:
        raise KeyError("manifest")

    monkeypatch.setattr(observe_hooks_module, "_stage_native_content", broken_stage)
    _Client.closed = False
    await observe_hooks_module._drain_outbox(  # pyright: ignore[reportPrivateUsage]
        store,
        workspace_commitment=workspace,
        codex_session_id="sess",
        content_by_source_identity={"source": ()},
        connect=_connected,  # type: ignore[arg-type]
        _state=tmp_path,
    )
    assert _reasons(tmp_path) == ["native_content_stage_failed"]
    assert _Client.closed
    assert store.pending_outbox_count(workspace) == 1
    gaps = store.status(ObservationStatusQuery(workspace)).gaps
    assert ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value in gaps


async def _stage_without_lease(
    state: Path, store: LocalObservationStore, workspace: str, connect: object
) -> None:
    await observe_hooks_module._stage_content_without_lease(  # pyright: ignore[reportPrivateUsage]
        store,
        workspace_commitment=workspace,
        content_by_source_identity={"source": ()},
        content_capture_profile=None,
        connect=connect,  # type: ignore[arg-type]
        event_name="PostToolUse",
        _state=state,
        budget_seconds=1.0,
        monotonic=lambda: 0.0,
    )


@pytest.mark.anyio
@pytest.mark.parametrize(("connect", "expected"), _CONNECT_FAILURES)
async def test_contended_content_stage_connect_failures_are_split(
    tmp_path: Path, connect: object, expected: str
) -> None:
    store, workspace = _store_with_row(tmp_path)
    await _stage_without_lease(tmp_path, store, workspace, connect)
    assert _reasons(tmp_path) == [expected]
    # The rows wait in this computer's outbox for the next owner (or an allow).
    assert store.pending_outbox_count(workspace) == 1
    gaps = store.status(ObservationStatusQuery(workspace)).gaps
    assert ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value in gaps


@pytest.mark.anyio
async def test_contended_content_stage_failure_is_not_a_connect_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, workspace = _store_with_row(tmp_path)

    async def broken_stage(*_args: object, **_kwargs: object) -> object:
        raise ValueError("spool")

    monkeypatch.setattr(observe_hooks_module, "_stage_native_content", broken_stage)
    await _stage_without_lease(tmp_path, store, workspace, _connected)
    assert _reasons(tmp_path) == ["native_content_stage_failed"]


@pytest.mark.anyio
async def test_contended_local_outbox_read_failure_keeps_preflight_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, workspace = _store_with_row(tmp_path)

    def broken_read(_commitment: str) -> object:
        raise OSError("read")

    monkeypatch.setattr(store, "list_pending_outbox_rows", broken_read)
    await _stage_without_lease(tmp_path, store, workspace, _connected)
    assert _reasons(tmp_path) == ["drain_preflight_failed"]


def test_invalid_key_material_fails_the_pass_instead_of_reading_as_unconsented(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    store.grant_consent(store.workspace_commitment(str(tmp_path.resolve())))
    key_path = tmp_path / "observation" / "key-material.bin"
    key_path.write_bytes(b"\x01" * 16)
    stdout = io.BytesIO()
    code = handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps({"session_id": "s1", "tool_name": "shell"}).encode(),
        stdout=stdout,
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert code == 0
    assert json.loads(stdout.getvalue().decode()) == {}
    assert _reasons(tmp_path) == ["observe_exception_public_operation_error"]
    assert key_path.read_bytes() == b"\x01" * 16


def test_corrupt_workspace_state_fails_the_pass_and_is_not_replaced(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    state_path = (
        tmp_path / "observation" / "workspaces" / (workspace.removeprefix("hmac-sha256:") + ".json")
    )
    state_path.write_bytes(b"{")
    stdout = io.BytesIO()
    code = handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps({"session_id": "s1", "tool_name": "shell"}).encode(),
        stdout=stdout,
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert code == 0
    assert json.loads(stdout.getvalue().decode()) == {}
    assert _reasons(tmp_path) == ["observe_exception_public_operation_error"]
    assert state_path.read_bytes() == b"{"


def _make_unreadable(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    """From now on every open of ``path`` fails with EIO, a read failure that may pass."""

    real_open = os.open

    def failing_open(
        target: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if os.fspath(target) == os.fspath(path):
            raise OSError(errno.EIO, os.strerror(errno.EIO))
        return real_open(target, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", failing_open)


def _state_path(state: Path, workspace: str) -> Path:
    return state / "observation" / "workspaces" / (workspace.removeprefix("hmac-sha256:") + ".json")


def test_another_workspaces_unreadable_state_fails_the_pass_as_storage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hook pass that cannot read another workspace's state records the storage failure.

    The hook ingests at its own workspace and still reads every workspace document to find the
    session's owners. A transient failure to read one of them fails the pass under its own
    reason; the pass is not recorded as a workspace without consent.
    """

    store = LocalObservationStore(_state=tmp_path)
    store.grant_consent(store.workspace_commitment(str(tmp_path.resolve())))
    (tmp_path / "other").mkdir()
    other = store.workspace_commitment(str((tmp_path / "other").resolve()))
    store.grant_consent(other)
    other_path = _state_path(tmp_path, other)
    before = other_path.read_bytes()
    stdout = io.BytesIO()
    with monkeypatch.context() as failing:
        _make_unreadable(failing, other_path)
        code = handle_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps({"session_id": "s1", "tool_name": "shell"}).encode(),
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
    assert code == 0
    assert json.loads(stdout.getvalue().decode()) == {}
    assert _reasons(tmp_path) == ["observe_exception_public_operation_error"]
    assert other_path.read_bytes() == before


def test_stream_reconcile_storage_failure_keeps_the_hook_row_and_is_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A storage failure inside the hook's stream reconcile discards only that reconcile.

    Another workspace's document becomes unreadable after the hook admitted its own row. The
    stream pass must fail as a whole and leave no cursor and no reconcile stamp, so the next
    hook reads the rollout again. Before, its first row was refused as ``consent_missing`` and
    the pass was recorded as done with nothing accepted.
    """

    state = tmp_path / "state"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    (tmp_path / "other").mkdir()
    home = tmp_path / "codex-home"
    (home / "sessions").mkdir(parents=True)
    monkeypatch.setenv("CODEX_HOME", str(home))
    session_id = "hook-stream-storage-failure"
    rollout = home / "sessions" / f"rollout-{session_id}.jsonl"
    rollout.write_bytes(failed_shell_rollout())
    seed = LocalObservationStore(_state=state)
    workspace = seed.workspace_commitment(str(workspace_dir.resolve()))
    other = seed.workspace_commitment(str((tmp_path / "other").resolve()))
    seed.grant_consent(workspace)
    seed.grant_consent(other)
    session = seed.session_commitment(session_id)
    other_path = _state_path(state, other)
    real_pass = stream_module._reconcile_session_stream_path  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    def hook_pass(call_id: str) -> int:
        return handle_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps(
                {
                    "session_id": session_id,
                    "tool_name": "shell",
                    "tool_use_id": call_id,
                    "cwd": str(workspace_dir),
                    "transcript_path": str(rollout),
                }
            ).encode(),
            stdout=io.BytesIO(),
            workspace=str(workspace_dir),
            _state=state,
            skip_service=True,
        )

    with monkeypatch.context() as failing:

        def pass_after_the_document_changed(*args: Any, **kwargs: Any) -> dict[str, Any]:
            # A new modification time makes the store read the document again, not its cache.
            os.utime(other_path, ns=(1, 1))
            _make_unreadable(failing, other_path)
            return real_pass(*args, **kwargs)

        failing.setattr(
            stream_module, "_reconcile_session_stream_path", pass_after_the_document_changed
        )
        assert hook_pass("call-1") == 0
    after = LocalObservationStore(_state=state)
    assert after.pending_outbox_count(workspace) == 1
    assert after.get_stream_cursor(workspace, session) is None
    assert after.last_stream_reconcile_mono(workspace) is None

    assert hook_pass("call-2") == 0
    cursor = LocalObservationStore(_state=state).get_stream_cursor(workspace, session)
    assert cursor is not None
    assert cursor.byte_position == rollout.stat().st_size
