"""A workspace state file that exists but cannot be read is never replaced by an empty state.

Each consented workspace keeps its consent, accepted pending outbox rows, quarantine, loss ranges,
and session bindings in ``observation/workspaces/<digest>.json``. Only a truly absent file starts a
fresh state. A file that cannot be read, is not a regular file, or holds bytes that are empty,
oversize, or not a valid state document must surface a typed storage error on every read and every
write, and stay byte-identical (ADR-029: a write that cannot preserve accepted records fails
without replacing the previous durable state).
"""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from finishup.adapters.integrations import observation_local as local
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationSource,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.protocol.errors import PublicErrorCode, PublicOperationError


def _envelope(session: str) -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=session,
        event_kind="PostToolUse",
        source_identity="hook:accepted-row",
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(1, 0, 1, f"hmac-sha256:{'ab' * 32}", "codex-obs-hook/1.0.0"),
        receipt_time=Timestamp("2026-01-01T00:00:00.000Z"),
        structural_payload=JsonObject(
            {"tool_name": "shell", "tool_call_id": "c1", "correlation_id": "c1", "exit_status": 1}
        ),
        content_object_refs=(),
        gap_codes=(),
    )


def _seeded(state: Path) -> tuple[str, Path]:
    store = LocalObservationStore(_state=state)
    workspace = store.workspace_commitment(str(state))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "sess-1")
    assert store.enqueue_outbox(workspace, "sess-1", _envelope(session)) is None
    assert store.pending_outbox_count(workspace) == 1
    path = state / "observation" / "workspaces" / (workspace.removeprefix("hmac-sha256:") + ".json")
    assert path.is_file()
    return workspace, path


def _assert_refused(
    state: Path, workspace: str, code: PublicErrorCode
) -> list[PublicOperationError]:
    """Every read and write through a fresh store (as a one-shot hook has) raises ``code``."""

    raised: list[PublicOperationError] = []
    fresh = LocalObservationStore(_state=state)
    for operation in (
        lambda: fresh.note_coverage_gap(workspace, "source_lag"),
        lambda: fresh.grant_consent(workspace),
        lambda: fresh.consent_for(workspace),
        lambda: fresh.pending_outbox_count(workspace),
    ):
        with pytest.raises(PublicOperationError) as failure:
            operation()
        assert failure.value.code is code
        raised.append(failure.value)
    return raised


def _assert_intact(state: Path, workspace: str) -> None:
    reader = LocalObservationStore(_state=state)
    assert reader.consent_for(workspace) is not None
    assert reader.pending_outbox_count(workspace) == 1


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-0 file")
def test_unreadable_state_file_fails_writes_and_keeps_consent_and_outbox(tmp_path: Path) -> None:
    workspace, path = _seeded(tmp_path)
    before = path.read_bytes()
    os.chmod(path, 0)
    try:
        _assert_refused(tmp_path, workspace, PublicErrorCode.STORAGE_UNSAFE)
    finally:
        os.chmod(path, 0o600)
    assert path.read_bytes() == before
    _assert_intact(tmp_path, workspace)


@pytest.mark.parametrize("content", ("garbage", "empty", "not_an_object", "invalid_document"))
def test_corrupt_state_file_fails_writes_and_is_left_for_repair(
    tmp_path: Path, content: str
) -> None:
    workspace, path = _seeded(tmp_path)
    corrupt = {
        "garbage": b"\x00not json\xff",
        "empty": b"",
        "not_an_object": b"[]\n",
        "invalid_document": path.read_bytes().replace(b'"pending_outbox"', b'"bad\\u0000key"'),
    }[content]
    path.write_bytes(corrupt)
    path.chmod(0o600)
    for failure in _assert_refused(tmp_path, workspace, PublicErrorCode.STORAGE_CORRUPT):
        assert failure.retryable is False
    assert path.read_bytes() == corrupt


def test_oversize_state_file_fails_writes_and_is_left_for_repair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, path = _seeded(tmp_path)
    before = path.read_bytes()
    monkeypatch.setattr(local, "_MAX_LEGACY_STATE_BYTES", len(before) - 1)
    _assert_refused(tmp_path, workspace, PublicErrorCode.STORAGE_CORRUPT)
    assert path.read_bytes() == before
    monkeypatch.undo()
    _assert_intact(tmp_path, workspace)


def test_symlinked_state_file_is_refused_and_not_replaced(tmp_path: Path) -> None:
    workspace, path = _seeded(tmp_path)
    target = tmp_path / "elsewhere.json"
    target.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(target)
    _assert_refused(tmp_path, workspace, PublicErrorCode.STORAGE_UNSAFE)
    assert path.is_symlink()


def test_absent_state_file_still_starts_fresh(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path))
    assert store.consent_for(workspace) is None
    assert store.pending_outbox_count(workspace) == 0
    store.grant_consent(workspace)
    assert LocalObservationStore(_state=tmp_path).consent_for(workspace) is not None


def test_corrupt_workspace_does_not_hide_healthy_workspaces(tmp_path: Path) -> None:
    workspace, _path = _seeded(tmp_path)
    store = LocalObservationStore(_state=tmp_path)
    (tmp_path / "other").mkdir()
    other = store.workspace_commitment(str(tmp_path / "other"))
    store.grant_consent(other)
    other_path = (
        tmp_path / "observation" / "workspaces" / (other.removeprefix("hmac-sha256:") + ".json")
    )
    other_path.write_bytes(b"{")
    other_path.chmod(0o600)
    fresh = LocalObservationStore(_state=tmp_path)
    assert fresh.list_consented_workspaces() == (workspace,)
    assert other_path.read_bytes() == b"{"


def _other_consented(state: Path) -> tuple[str, Path]:
    """Consent a second workspace under the same state root; return it and its document."""

    store = LocalObservationStore(_state=state)
    (state / "other").mkdir()
    other = store.workspace_commitment(str(state / "other"))
    store.grant_consent(other)
    return other, (
        state / "observation" / "workspaces" / (other.removeprefix("hmac-sha256:") + ".json")
    )


def _fail_opens(monkeypatch: pytest.MonkeyPatch, path: Path, code: int) -> None:
    """Make every open of one workspace state document fail with ``code``."""

    real_open = os.open

    def failing_open(
        target: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if os.fspath(target) == os.fspath(path):
            raise OSError(code, os.strerror(code))
        return real_open(target, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", failing_open)


@pytest.mark.parametrize("code", (errno.EIO, errno.EMFILE))
def test_ingest_keeps_another_workspaces_transient_read_failure_a_storage_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    """A read failure that may pass is a retryable storage failure, not a consent answer.

    Ingest without an explicit workspace finds the envelope's workspace by scanning every
    workspace document for the session. When another workspace's document cannot be read for a
    transient reason, the owner cannot be decided. Answering ``consent_missing`` would report a
    consent decision nobody made, for a workspace whose consent is active, and would tell the
    caller not to retry.
    """

    workspace, path = _seeded(tmp_path)
    _other, other_path = _other_consented(tmp_path)
    before = (path.read_bytes(), other_path.read_bytes())
    fresh = LocalObservationStore(_state=tmp_path)
    envelope = _envelope(fresh.session_commitment("sess-1"))

    with monkeypatch.context() as failing:
        _fail_opens(failing, other_path, code)
        with pytest.raises(PublicOperationError) as failure:
            fresh.ingest(envelope)
        assert failure.value.code is PublicErrorCode.STORAGE_UNSAFE
        assert failure.value.retryable is True
        consent = fresh.consent_for(workspace)
        assert consent is not None and consent.active
    assert (path.read_bytes(), other_path.read_bytes()) == before

    # The same call succeeds once the document can be read again.
    assert fresh.ingest(envelope).disposition is ObservationIngestDisposition.ACCEPTED


def test_ingest_resolves_past_a_permanently_refused_other_workspace(tmp_path: Path) -> None:
    """A document refused for good is skipped by the scan, so a healthy workspace still ingests."""

    _workspace, _path = _seeded(tmp_path)
    _other, other_path = _other_consented(tmp_path)
    other_path.write_bytes(b"{")
    other_path.chmod(0o600)
    fresh = LocalObservationStore(_state=tmp_path)

    result = fresh.ingest(_envelope(fresh.session_commitment("sess-1")))

    assert result.disposition is ObservationIngestDisposition.ACCEPTED
    assert other_path.read_bytes() == b"{"


@pytest.mark.parametrize("decision", ("no_single_consented_workspace", "several_owners"))
def test_ingest_still_answers_consent_missing_for_a_consent_decision(
    tmp_path: Path, decision: str
) -> None:
    """Readable documents that do not name one consented owner are a real consent refusal."""

    _workspace, _path = _seeded(tmp_path)
    other, _other_path = _other_consented(tmp_path)
    store = LocalObservationStore(_state=tmp_path)
    if decision == "several_owners":
        session = store.session_commitment("sess-1")
        state = store._load(other)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        assert state.session_workspaces is not None
        state.session_workspaces[session] = other
        store._save(other, state)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    else:
        session = store.session_commitment("never-bound")

    result = LocalObservationStore(_state=tmp_path).ingest(_envelope(session))

    assert result.disposition is ObservationIngestDisposition.REJECTED
    assert result.reason == ObservationGapCode.CONSENT_MISSING.value
