"""Durable generation-fenced observation verification repository behavior."""

from __future__ import annotations

from typing import Any, cast

import apsw

from finishup.adapters.approved_checks import (
    ApprovedCheckOutcome,
    ApprovedCheckResult,
    ApprovedCheckStatus,
)
from finishup.adapters.sqlite.migrations import initialize_bundle
from finishup.adapters.sqlite.observation import SqliteObservationStore
from finishup.adapters.sqlite.observation_verification import (
    SqliteObservationVerificationRepository,
)
from finishup.application.observation_verification import (
    ObservationVerificationJob,
    ObservationVerificationWorker,
)
from finishup.ports.approved_checks import ApprovedCheckApproval, approval_commitment

_WORKSPACE = "hmac-sha256:" + "a" * 64
_POLICY = "sha256:" + "b" * 64
_APPROVAL = "sha256:" + "c" * 64
_STATE_A = "sha256:" + "d" * 64
_STATE_B = "sha256:" + "e" * 64
_NOW = "2026-07-23T10:00:00.000Z"
_SMOKE = ApprovedCheckApproval(
    approval_id="smoke",
    argv=("true",),
    allow_network=False,
    timeout_seconds=1.0,
    approval_commitment=approval_commitment("smoke", ("true",), allow_network=False),
)
_LATER = "2026-07-23T10:05:00.000Z"


def _repository() -> tuple[apsw.Connection, SqliteObservationVerificationRepository]:
    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "task_verification", "owner_generation": "1"})
    return db, SqliteObservationVerificationRepository(db)


def _result() -> ApprovedCheckResult:
    return ApprovedCheckResult(
        status=ApprovedCheckStatus.PASSED,
        outcome=ApprovedCheckOutcome.SUCCESS,
        exit_status=0,
        output_digest="sha256:" + "f" * 64,
        output_bytes=0,
        subject_state_digest=_STATE_B,
        approval_commitment=_APPROVAL,
        result_digest="sha256:" + "1" * 64,
        duration_ms=1,
    )


def test_rapid_changes_coalesce_and_identical_state_is_cached() -> None:
    db, repository = _repository()
    first = repository.enqueue_latest(
        workspace=_WORKSPACE,
        policy_digest=_POLICY,
        approvals=(_APPROVAL,),
        subject_state_digest=_STATE_A,
        enqueued_at=_NOW,
    )
    second = repository.enqueue_latest(
        workspace=_WORKSPACE,
        policy_digest=_POLICY,
        approvals=(_APPROVAL,),
        subject_state_digest=_STATE_B,
        enqueued_at=_LATER,
    )
    duplicate = repository.enqueue_latest(
        workspace=_WORKSPACE,
        policy_digest=_POLICY,
        approvals=(_APPROVAL,),
        subject_state_digest=_STATE_B,
        enqueued_at=_LATER,
    )
    assert len(first) == len(second) == 1
    assert duplicate == ()
    assert db.execute(
        "SELECT subject_state_digest,status FROM observation_verification_jobs ORDER BY state_token"
    ).fetchall() == [(_STATE_A, "stale"), (_STATE_B, "pending")]


def test_new_service_generation_recovers_abandoned_lease_and_result_is_immutable() -> None:
    db, repository = _repository()
    repository.enqueue_latest(
        workspace=_WORKSPACE,
        policy_digest=_POLICY,
        approvals=(_APPROVAL,),
        subject_state_digest=_STATE_B,
        enqueued_at=_NOW,
    )
    first = repository.claim_next(
        service_generation=1,
        lease_owner="service-one",
        lease_expires_at=_LATER,
        now=_NOW,
    )
    assert first is not None
    recovered = repository.claim_next(
        service_generation=2,
        lease_owner="service-two",
        lease_expires_at="2026-07-23T10:10:00.000Z",
        now="2026-07-23T10:01:00.000Z",
    )
    assert recovered == first
    assert recovered is not None
    repository.complete(
        job=recovered,
        service_generation=2,
        lease_owner="service-two",
        check_id="smoke",
        result=_result(),
        subject_state_after=_STATE_B,
        result_commitment=_result().result_digest,
        output_object_id=None,
        limitations_json=b"[]",
        is_current=True,
        recorded_at=_LATER,
    )
    assert db.execute(
        "SELECT status,is_current,result_commitment FROM observation_verification_results"
    ).fetchone() == ("passed", 1, _result().result_digest)
    assert (
        repository.claim_next(
            service_generation=2,
            lease_owner="service-two",
            lease_expires_at="2026-07-23T10:15:00.000Z",
            now=_LATER,
        )
        is None
    )


def _observer(
    db: apsw.Connection,
) -> tuple[SqliteObservationStore, ObservationVerificationWorker]:
    store = SqliteObservationStore(db)
    worker = ObservationVerificationWorker(
        repository=store.verification_repository(),
        runner=cast(Any, None),
        workspace_provider=cast(Any, None),
        policy_provider=cast(Any, None),
        capture_subject_state=cast(Any, None),
        persist_output=cast(Any, None),
        service_generation=1,
        lease_owner="service-one",
        now=lambda: _NOW,
        lease_expires_at=lambda: _LATER,
    )
    return store, worker


def _observe(
    store: SqliteObservationStore, worker: ObservationVerificationWorker, digest: str
) -> tuple[str, ...]:
    return worker.enqueue_if_changed(
        workspace=_WORKSPACE,
        policy_digest=_POLICY,
        approvals=(_SMOKE,),
        previous_subject_state_digest=store.latest_verification_subject_digest(_WORKSPACE),
        subject_state_digest=digest,
    )


def _claim(repository: SqliteObservationVerificationRepository) -> ObservationVerificationJob:
    job = repository.claim_next(
        service_generation=1, lease_owner="service-one", lease_expires_at=_LATER, now=_NOW
    )
    assert job is not None
    return job


def _complete(
    repository: SqliteObservationVerificationRepository,
    job: ObservationVerificationJob,
    *,
    is_current: bool,
) -> None:
    repository.complete(
        job=job,
        service_generation=1,
        lease_owner="service-one",
        check_id="smoke",
        result=_result(),
        subject_state_after=job.subject_state_digest if is_current else _STATE_B,
        result_commitment=_result().result_digest,
        output_object_id=None,
        limitations_json=b"[]",
        is_current=is_current,
        recorded_at=_LATER,
    )


def test_returning_to_a_superseded_state_verifies_it_again() -> None:
    db, repository = _repository()
    store, worker = _observer(db)
    assert len(_observe(store, worker, _STATE_A)) == 1
    assert len(_observe(store, worker, _STATE_B)) == 1
    # The edit is undone before state A ever ran: A is the current state again.
    assert len(_observe(store, worker, _STATE_A)) == 1
    assert store.latest_verification_subject_digest(_WORKSPACE) == _STATE_A
    # Later observations of the same state stay coalesced.
    assert _observe(store, worker, _STATE_A) == ()
    assert db.execute(
        "SELECT subject_state_digest,status FROM observation_verification_jobs ORDER BY state_token"
    ).fetchall() == [(_STATE_B, "stale"), (_STATE_A, "pending")]
    assert _claim(repository).subject_state_digest == _STATE_A


def test_returning_to_a_state_with_a_non_current_result_records_a_current_one() -> None:
    db, repository = _repository()
    store, worker = _observer(db)
    assert len(_observe(store, worker, _STATE_A)) == 1
    # The workspace moved while state A's check ran, so its result is not current.
    _complete(repository, _claim(repository), is_current=False)
    assert len(_observe(store, worker, _STATE_B)) == 1
    assert len(_observe(store, worker, _STATE_A)) == 1
    job = _claim(repository)
    assert job.subject_state_digest == _STATE_A
    _complete(repository, job, is_current=True)
    facts = store.load_check_facts(_WORKSPACE)
    assert [(fact.subject_state_digest, fact.is_current) for fact in facts] == [(_STATE_A, True)]
    assert facts[0].cursor_event_position == job.state_token
    # A current result for the state is a cache hit, not new work.
    assert (
        repository.enqueue_latest(
            workspace=_WORKSPACE,
            policy_digest=_POLICY,
            approvals=(_SMOKE.approval_commitment,),
            subject_state_digest=_STATE_A,
            enqueued_at=_LATER,
        )
        == ()
    )
