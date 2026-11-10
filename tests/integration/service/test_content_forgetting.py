"""ADR-054 (owner ruling U20): forgetting a task's server-copy content, on real storage.

A ready service (real vault, catalog, encrypted object store and SQLite task ledger) runs one
AI-powered check whose reviewer returns a challenge and a verified row that quote the packet, so
the task holds a check-time change object, a reviewer response object and excerpts in its
records. ``forget_task_content`` then records ``content_forgotten`` and erases the content
objects; every view, result, receipt and a reopened ledger read the excerpts as absent.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, cast

import pytest

from builders.multi_agent import relock_and_reopen_multi_agent_service
from finishup.adapters.objects.encrypted_files import EncryptedFilesObjectStore
from finishup.adapters.sqlite.repository import SqliteLedger
from finishup.application.check_change import recover_check_time_change
from finishup.application.content_forgetting import (
    TaskContentForgetReport,
    forget_task_content,
    new_forget_id,
)
from finishup.application.lineage_recovery import lineage_recovery_runtime
from finishup.domain.events import AcceptedEvent, ContentForgottenPayload, LedgerRecord
from finishup.domain.evidence_provenance import ContentForgotten, EvidenceProvenance
from finishup.kernel.forgotten_content import FORGOTTEN_EXCERPT, content_forgotten_provenance
from finishup.kernel.projections import ProjectionState, projection_snapshot
from finishup.ports.change_capture import CHECK_CHANGE_MEDIA_TYPE
from finishup.ports.ledger import ProjectionView
from finishup.ports.objects import ObjectKind, ObjectRef
from finishup.ports.runtime import TaskRuntime
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import ReceiptRequest, StatusRequest
from integration.service import test_reviewer_conversation_service as conversation

pytestmark = pytest.mark.anyio

_QUOTE = "return b + a"
_SUMMARY = "SUMMARY-QUOTE: calc.py shows `return a + b`, which the reviewer read."
_ACCOUNT = EvidenceProvenance({"server_copy_read": 3, "outside_read": 1}, 2)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def work_has_begun(monkeypatch: pytest.MonkeyPatch) -> None:
    """The review runs as if the first edit were recorded (no pre-edit deferral)."""

    conversation.work_has_begun.__wrapped__(monkeypatch)  # type: ignore[attr-defined]


def _replies(final: dict[str, JsonValue]) -> tuple[dict[str, JsonValue], ...]:
    return (conversation._read_file("calc.py"), {"reply": {"final_judgment": final}})


def _final_judgment() -> dict[str, JsonValue]:
    """The reviewer's last reply; its cited refs are filled in once the plan event exists."""

    return {
        "conclusion": "challenges_returned",
        "review_summary": _SUMMARY,
        "verified": [
            {
                "requirement_or_claim": "The statement asks for the sum",
                "verdict": "supported",
                "cited_refs": [],
                "snippet": _QUOTE,
            }
        ],
        "reviewer_challenges": [
            {
                "finding_kind": "task_requirement_unmet",
                "summary": "The sum is not yet verified by a recorded run",
                "cited_refs": [],
                "discrepancy": "The statement asks for a passing test; no run is recorded.",
                "alternative_interpretation": "The test may have been run outside FinishUP.",
                "message_to_main_agent": "Run test_calc.py and record the result.",
                "requested_next_step": "act",
                "uncertainty": "A run outside FinishUP would settle it.",
                "snippet": _QUOTE,
                "restates": None,
            }
        ],
        "prior_finding_verdicts": [],
    }


async def _runtime(service: Any, task: str) -> TaskRuntime:
    return await lineage_recovery_runtime(service.app, task)


async def _records(runtime: TaskRuntime) -> tuple[LedgerRecord, ...]:
    return tuple([record async for record in runtime.ledger.load_events(runtime.session_id)])


async def _content_objects(runtime: TaskRuntime) -> tuple[ObjectRef, ...]:
    store = cast(EncryptedFilesObjectStore, runtime.objects)
    found: list[ObjectRef] = []
    for object_id in await store.published_object_ids():
        ref = await store.describe_published(object_id)
        if ref.metadata.kind is ObjectKind.SEMANTIC_RESPONSE or (
            ref.metadata.kind is ObjectKind.CHANGE_CAPTURE
            and ref.metadata.media_type == CHECK_CHANGE_MEDIA_TYPE
        ):
            found.append(ref)
    return tuple(found)


async def _projection(runtime: TaskRuntime) -> ProjectionState:
    stored = await runtime.ledger.load_projection(
        runtime.session_id, ProjectionView.CANDIDATE_FINDINGS
    )
    assert stored is not None and type(stored.state) is ProjectionState
    return stored.state


async def _checked_review(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Enter the review harness and run the check; the caller exits the returned context."""

    final = _final_judgment()
    context = conversation._reviewing(tmp_path, monkeypatch, _replies(final))
    review = await context.__aenter__()
    # Quote the task statement the packet carries, citing its plan event.
    runtime = await _runtime(review.service, review.started.task_id)
    try:
        plan = next(
            str(record.event_id)
            for record in await _records(runtime)
            if record.schema.name == "plan_published"
        )
    finally:
        await review.service.app.runtime.release(runtime)
    cast(list[dict[str, Any]], final["verified"])[0]["cited_refs"] = [plan]
    cast(list[dict[str, Any]], final["reviewer_challenges"])[0]["cited_refs"] = [plan]
    # The working tree changes after the task's base, so the check captures a real diff.
    (tmp_path / "work" / "calc.py").write_text("def add(a, b):\n    return b + a\n")
    checked = await review.check()
    assert type(checked).__name__ == "CheckCommitResult", checked
    return context, review, checked


def _json(value: object) -> str:
    return json.dumps(value, default=str, sort_keys=True)


async def _receipt_text(review: Any, frontier: Mapping[str, JsonValue]) -> str:
    receipt = await review.service.app.receipt(
        ReceiptRequest.model_validate(
            {
                **review.common,
                "request_id": new_id(IdKind.REQUEST),
                "session_id": review.started.session_id,
                "writer_id": review.started.writer_id,
                "expected_frontier": dict(frontier),
                "task_id": review.started.task_id,
                "format": "json",
                "redaction_profile": "full_local",
                "include": "full",
            }
        ),
        repository_privacy_context=review.repository,
    )
    return canonical_encode(getattr(receipt, "document")).decode()


async def _status_text(review: Any, view: str, at_frontier: int) -> tuple[str, Any]:
    status = await review.service.app.status(
        StatusRequest.model_validate(
            {
                **review.common,
                "request_id": new_id(IdKind.REQUEST),
                "session_id": review.started.session_id,
                "writer_id": review.started.writer_id,
                "view": view,
                "limit": "10",
                "at_frontier": str(at_frontier),
            }
        ),
        repository_privacy_context=review.repository,
    )
    return canonical_encode(status.as_json()).decode(), status


async def test_forget_records_the_marker_erases_content_and_masks_every_view(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    context, review, checked = await _checked_review(tmp_path, monkeypatch)
    try:
        service, task = review.service, review.started.task_id
        assert checked.review_summary == _SUMMARY
        assert [row.get("snippet") for row in checked.verified] == [_QUOTE]
        assert [f.challenge.snippet for f in checked.findings if f.challenge] == [_QUOTE]
        assert _SUMMARY in await _receipt_text(review, checked.result_frontier.as_wire())
        checked_at = checked.result_frontier.sequence
        pinned_before, _ = await _status_text(review, "findings", checked_at)
        assert _QUOTE in pinned_before

        runtime = await _runtime(service, task)
        try:
            before = await _content_objects(runtime)
            kinds = {ref.metadata.kind for ref in before}
            assert kinds == {ObjectKind.SEMANTIC_RESPONSE, ObjectKind.CHANGE_CAPTURE}
            store = cast(EncryptedFilesObjectStore, runtime.objects)
            paths = [store._path_for(ref.object_id) for ref in before]
            assert all(path.is_file() for path in paths)
            projection_before = await _projection(runtime)
            records_before = await _records(runtime)
        finally:
            await service.app.runtime.release(runtime)

        forget_id = new_forget_id()
        report = await forget_task_content(
            service.app, task, forget_id=forget_id, reason="owner", provenance=_ACCOUNT
        )
        assert report == TaskContentForgetReport("forgotten", len(before), False)
        assert report.complete

        runtime = await _runtime(service, task)
        try:
            # The content objects are gone from disk and the inventory records them erased.
            assert not any(path.exists() for path in paths)
            assert await _content_objects(runtime) == ()
            ledger = cast(SqliteLedger, runtime.ledger)
            assert {ref.object_id for ref in before} <= await ledger.erased_object_ids()
            # Every event stays; exactly one more, the service's content_forgotten.
            records = await _records(runtime)
            assert records[: len(records_before)] == records_before
            (added,) = records[len(records_before) :]
            assert type(added) is AcceptedEvent and added.schema.name == "content_forgotten"
            payload = cast(ContentForgottenPayload, added.payload)
            assert (payload.forget_id, payload.reason, payload.objects_erased) == (
                forget_id,
                "owner",
                len(before),
            )
            assert payload.provenance == _ACCOUNT
            # Findings and checks stay; their excerpts do not.
            projection = await _projection(runtime)
            assert projection.findings.keys() == projection_before.findings.keys()
            assert projection.latest_tested_state == projection_before.latest_tested_state
            snapshot = _json(projection_snapshot(projection))
            assert _QUOTE in _json(projection_snapshot(projection_before))
            assert _QUOTE not in snapshot and _SUMMARY not in snapshot
            assert content_forgotten_provenance(projection) == EvidenceProvenance(
                _ACCOUNT.reads, 2, None, ContentForgotten(added.occurred_at.wire, "owner")
            )
            replayed = await runtime.ledger.load_check_result(
                review.started.writer_id, checked.request_id
            )
            assert replayed is not None and replayed.review_summary is None
            assert [row.get("snippet") for row in replayed.verified] == [FORGOTTEN_EXCERPT]
            assert [f.challenge.snippet for f in replayed.findings if f.challenge] == [None]
            assert len(replayed.findings) == len(checked.findings)
            frontier = (await runtime.ledger.load_frontier()).as_wire()
        finally:
            await service.app.runtime.release(runtime)
        receipt = await _receipt_text(review, frontier)
        assert _SUMMARY not in receipt and _QUOTE not in receipt
        # Status: the head views, and a findings view pinned before the forget, quote nothing;
        # history (a released contract that cannot name the family) omits the event's row.
        head = int(cast(str, frontier["sequence"]))
        for view, at in (("findings", head), ("findings", checked_at), ("history", head)):
            text, status = await _status_text(review, view, at)
            assert _QUOTE not in text and _SUMMARY not in text, (view, at)
            if view == "history":
                names = {item.schema_name for item in status.page.items}
                assert "check_recorded" in names and "content_forgotten" not in names

        # A second call records nothing new and finds nothing left to erase. (The receipt above
        # recorded its own receipt_recorded event, so count from here.)
        runtime = await _runtime(service, task)
        try:
            settled = len(await _records(runtime))
        finally:
            await service.app.runtime.release(runtime)
        again = await forget_task_content(
            service.app, task, forget_id=forget_id, reason="owner", provenance=_ACCOUNT
        )
        assert again == TaskContentForgetReport("forgotten", 0, True)
        runtime = await _runtime(service, task)
        try:
            assert len(await _records(runtime)) == settled
        finally:
            await service.app.runtime.release(runtime)

        # A reopened service replays the whole ledger: no corrupt storage, objects verify, masked.
        await relock_and_reopen_multi_agent_service(service)
        runtime = await _runtime(service, task)
        try:
            assert await cast(SqliteLedger, runtime.ledger).verify_recovery_objects() > 0
            reopened = await _projection(runtime)
            assert reopened.content_forgotten == projection.content_forgotten
            assert _QUOTE not in _json(projection_snapshot(reopened))
            rebuilt = await runtime.ledger.load_check_result(
                review.started.writer_id, checked.request_id
            )
            assert rebuilt is not None and rebuilt.review_summary is None
            assert [row.get("snippet") for row in rebuilt.verified] == [FORGOTTEN_EXCERPT]
        finally:
            await service.app.runtime.release(runtime)
    finally:
        await context.__aexit__(None, None, None)


async def test_a_forget_interrupted_before_the_deletes_completes_on_the_retry(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    context, review, _checked = await _checked_review(tmp_path, monkeypatch)
    try:
        service, task = review.service, review.started.task_id
        runtime = await _runtime(service, task)
        try:
            before = await _content_objects(runtime)
            store = cast(EncryptedFilesObjectStore, runtime.objects)
            paths = [store._path_for(ref.object_id) for ref in before]
        finally:
            await service.app.runtime.release(runtime)
        original = EncryptedFilesObjectStore.erase_published
        failures = [OSError("simulated crash before the delete")]

        async def erase_once(self: EncryptedFilesObjectStore, ref: ObjectRef) -> bool:
            if failures:
                raise failures.pop()
            return await original(self, ref)

        monkeypatch.setattr(EncryptedFilesObjectStore, "erase_published", erase_once)
        forget_id = new_forget_id()
        first = await forget_task_content(
            service.app, task, forget_id=forget_id, reason="expired", provenance=_ACCOUNT
        )
        assert first == TaskContentForgetReport("erasure_incomplete", 0, False)
        assert not first.complete
        assert all(path.exists() for path in paths)  # recorded and marked, not yet deleted
        runtime = await _runtime(service, task)
        try:
            marker = (await _projection(runtime)).content_forgotten
            assert marker is not None and marker.payload is not None
            assert marker.payload.reason == "expired"
            ledger = cast(SqliteLedger, runtime.ledger)
            assert {ref.object_id for ref in before} <= await ledger.erased_object_ids()
        finally:
            await service.app.runtime.release(runtime)

        retry = await forget_task_content(
            service.app, task, forget_id=forget_id, reason="expired", provenance=_ACCOUNT
        )
        assert retry == TaskContentForgetReport("forgotten", len(before), True)
        assert not any(path.exists() for path in paths)
        runtime = await _runtime(service, task)
        try:
            forgotten = [
                record
                for record in await _records(runtime)
                if record.schema.name == "content_forgotten"
            ]
            assert len(forgotten) == 1
        finally:
            await service.app.runtime.release(runtime)
    finally:
        await context.__aexit__(None, None, None)


async def test_a_recovered_job_whose_change_was_erased_reads_the_typed_gap(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    context, review, _checked = await _checked_review(tmp_path, monkeypatch)
    try:
        service, task = review.service, review.started.task_id
        runtime = await _runtime(service, task)
        try:
            store = cast(EncryptedFilesObjectStore, runtime.objects)
            bindings: list[object] = []
            for object_id in await store.published_object_ids():
                ref = await store.describe_published(object_id)
                if ref.metadata.kind is ObjectKind.SEMANTIC_CASE:
                    body = strict_json_parse(
                        b"".join([chunk async for chunk in store.open_verified(ref)])
                    )
                    binding = cast(Mapping[str, object], body).get("check_change")
                    if binding is not None:
                        bindings.append(json.loads(json.dumps(binding, default=dict)))
            assert bindings
            # Before the forget the job's own change object recovers as a change.
            recovered = await recover_check_time_change(runtime, bindings[0])
            assert recovered.unavailable is False and recovered.change is not None
        finally:
            await service.app.runtime.release(runtime)
        await forget_task_content(
            service.app, task, forget_id=new_forget_id(), reason="owner", provenance=_ACCOUNT
        )
        runtime = await _runtime(service, task)
        try:
            outcome = await recover_check_time_change(runtime, bindings[0])
            assert (outcome.unavailable, outcome.reason, outcome.change) == (
                True,
                "content_forgotten",
                None,
            )
            # A change object that is merely missing, never erased, still refuses as before.
            unknown = dict(cast(dict[str, Any], bindings[0]))
            unknown["object"] = {
                **cast(dict[str, Any], unknown["object"]),
                "object_id": new_id(IdKind.OBJECT),
            }
            with pytest.raises(ValueError):
                await recover_check_time_change(runtime, unknown)
        finally:
            await service.app.runtime.release(runtime)
    finally:
        await context.__aexit__(None, None, None)


async def test_a_task_that_does_not_exist_is_a_typed_outcome_and_arguments_are_checked(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    context, review, _checked = await _checked_review(tmp_path, monkeypatch)
    try:
        app = review.service.app
        missing = await forget_task_content(
            app,
            new_id(IdKind.TASK),
            forget_id=new_forget_id(),
            reason="owner",
            provenance=_ACCOUNT,
        )
        assert missing == TaskContentForgetReport("task_not_found")
        assert missing.complete
        task = review.started.task_id
        for changes in (
            {"forget_id": "not-a-forget-id"},
            {"reason": "manual"},
            {"provenance": {"server_copy_read": 1}},
        ):
            arguments: dict[str, Any] = {
                "forget_id": new_forget_id(),
                "reason": "owner",
                "provenance": _ACCOUNT,
                **changes,
            }
            with pytest.raises(ValueError):
                await forget_task_content(app, task, **arguments)
        with pytest.raises(ValueError):
            await forget_task_content(
                app, "not-a-task", forget_id=new_forget_id(), reason="owner", provenance=_ACCOUNT
            )
        runtime = await _runtime(review.service, task)
        try:
            records = await _records(runtime)
            assert not any(record.schema.name == "content_forgotten" for record in records)
            # The inventory never marks an event's payload object erased.
            store = cast(EncryptedFilesObjectStore, runtime.objects)
            payload = await store.describe_published(records[-1].payload_ref.object_id)
            ledger = cast(SqliteLedger, runtime.ledger)
            with pytest.raises(ValueError, match="erased_object_is_event_payload"):
                await ledger.record_erased_objects((payload,))
            assert payload.object_id not in await ledger.erased_object_ids()
        finally:
            await review.service.app.runtime.release(runtime)
    finally:
        await context.__aexit__(None, None, None)


async def _later_content(service: Any, task: str) -> ObjectRef:
    """A content object a later check publishes after the forget (an L1 capture, say)."""

    from finishup.ports.objects import ObjectMetadata, ObjectSource

    runtime = await _runtime(service, task)
    try:
        data = b'{"later": "a check after the forget read this"}'
        staged = await runtime.objects.stage(
            ObjectSource(data=data, declared_size=len(data)),
            ObjectMetadata(
                ObjectKind.CHANGE_CAPTURE,
                CHECK_CHANGE_MEDIA_TYPE,
                runtime.task_id,
                service.app.clock.now_utc(),
            ),
        )
        return await runtime.objects.finalize(staged)
    finally:
        await service.app.runtime.release(runtime)


async def test_a_retry_erases_only_the_scope_the_forget_recorded_never_later_content(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """E3: a later check's content, published after the event, is neither marked nor erased."""

    context, review, _checked = await _checked_review(tmp_path, monkeypatch)
    try:
        service, task = review.service, review.started.task_id
        runtime = await _runtime(service, task)
        try:
            before = await _content_objects(runtime)
            store = cast(EncryptedFilesObjectStore, runtime.objects)
            paths = [store._path_for(ref.object_id) for ref in before]
        finally:
            await service.app.runtime.release(runtime)
        original = EncryptedFilesObjectStore.erase_published
        failures = [OSError("simulated crash before the delete")]

        async def erase_once(self: EncryptedFilesObjectStore, ref: ObjectRef) -> bool:
            if failures:
                raise failures.pop()
            return await original(self, ref)

        monkeypatch.setattr(EncryptedFilesObjectStore, "erase_published", erase_once)
        forget_id = new_forget_id()
        first = await forget_task_content(
            service.app, task, forget_id=forget_id, reason="owner", provenance=_ACCOUNT
        )
        assert first.outcome == "erasure_incomplete" and all(path.exists() for path in paths)
        later = await _later_content(service, task)
        runtime = await _runtime(service, task)
        try:
            later_path = cast(EncryptedFilesObjectStore, runtime.objects)._path_for(later.object_id)
        finally:
            await service.app.runtime.release(runtime)
        retry = await forget_task_content(
            service.app, task, forget_id=forget_id, reason="owner", provenance=_ACCOUNT
        )
        assert retry == TaskContentForgetReport("forgotten", len(before), True)
        assert not any(path.exists() for path in paths)
        runtime = await _runtime(service, task)
        try:
            assert later_path.is_file()
            assert await _content_objects(runtime) == (later,)
            ledger = cast(SqliteLedger, runtime.ledger)
            assert later.object_id not in await ledger.erased_object_ids()
        finally:
            await service.app.runtime.release(runtime)
    finally:
        await context.__aexit__(None, None, None)


async def test_a_forget_interrupted_while_it_records_its_scope_erases_everything_on_the_retry(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """E3: the scope is recorded before the event, so no interruption leaves it unknown."""

    context, review, _checked = await _checked_review(tmp_path, monkeypatch)
    try:
        service, task = review.service, review.started.task_id
        runtime = await _runtime(service, task)
        try:
            before = await _content_objects(runtime)
            store = cast(EncryptedFilesObjectStore, runtime.objects)
            paths = [store._path_for(ref.object_id) for ref in before]
        finally:
            await service.app.runtime.release(runtime)
        original = SqliteLedger.record_erased_objects
        failures = [OSError("simulated crash while the scope is recorded")]

        async def record_once(self: SqliteLedger, refs: tuple[ObjectRef, ...]) -> None:
            if failures:
                raise failures.pop()
            await original(self, refs)

        monkeypatch.setattr(SqliteLedger, "record_erased_objects", record_once)
        forget_id = new_forget_id()
        first = await forget_task_content(
            service.app, task, forget_id=forget_id, reason="owner", provenance=_ACCOUNT
        )
        assert first == TaskContentForgetReport("erasure_incomplete", 0, False)
        runtime = await _runtime(service, task)
        try:
            # Nothing is recorded as forgotten yet, so nothing reads as masked or erased.
            assert (await _projection(runtime)).content_forgotten is None
        finally:
            await service.app.runtime.release(runtime)
        retry = await forget_task_content(
            service.app, task, forget_id=forget_id, reason="owner", provenance=_ACCOUNT
        )
        assert retry == TaskContentForgetReport("forgotten", len(before), False)
        assert not any(path.exists() for path in paths)
        runtime = await _runtime(service, task)
        try:
            forgotten = [
                record
                for record in await _records(runtime)
                if record.schema.name == "content_forgotten"
            ]
            assert len(forgotten) == 1
        finally:
            await service.app.runtime.release(runtime)
    finally:
        await context.__aexit__(None, None, None)


# --- the content fence: nothing published across a forget, nor for work it came after (E1) ----


async def _review_with(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> tuple[Any, Any, dict[str, JsonValue]]:
    """Enter the review harness with the statement quoted; the caller runs the check."""

    final = _final_judgment()
    context = conversation._reviewing(tmp_path, monkeypatch, _replies(final))
    review = await context.__aenter__()
    runtime = await _runtime(review.service, review.started.task_id)
    try:
        plan = next(
            str(record.event_id)
            for record in await _records(runtime)
            if record.schema.name == "plan_published"
        )
    finally:
        await review.service.app.runtime.release(runtime)
    cast(list[dict[str, Any]], final["verified"])[0]["cited_refs"] = [plan]
    cast(list[dict[str, Any]], final["reviewer_challenges"])[0]["cited_refs"] = [plan]
    (tmp_path / "work" / "calc.py").write_text("def add(a, b):\n    return b + a\n")
    return context, review, final


async def test_a_review_of_a_frontier_a_forget_came_after_publishes_no_response(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A review still running when its task's copy content was forgotten (its frontier is before
    the event) ends failed, and leaves no response object: every view masks its excerpts."""

    from finishup.application import content_fence

    context, review, _final = await _review_with(tmp_path, monkeypatch)
    try:
        service, task = review.service, review.started.task_id
        asked: list[int] = []
        held: list[bool] = []

        async def forgotten_after(runtime: TaskRuntime, subject_sequence: int) -> bool:
            import asyncio

            fences = content_fence._FENCES.get(asyncio.get_running_loop(), {})
            held.append(task in fences and fences[task].lock.locked())
            asked.append(subject_sequence)
            return True

        monkeypatch.setattr(content_fence, "content_forgotten_after", forgotten_after)
        checked = await review.check()
        assert asked and held and all(held)
        assert checked.review_summary is None
        runtime = await _runtime(service, task)
        try:
            kinds = {ref.metadata.kind for ref in await _content_objects(runtime)}
            assert ObjectKind.SEMANTIC_RESPONSE not in kinds
        finally:
            await service.app.runtime.release(runtime)
    finally:
        await context.__aexit__(None, None, None)


async def test_the_forget_holds_the_content_fence_from_its_inventory_through_its_erasure(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio

    from finishup.application import content_fence, content_forgetting
    from finishup.ports.objects import ObjectMetadata, ObjectSource

    context, review, _checked = await _checked_review(tmp_path, monkeypatch)
    try:
        service, task = review.service, review.started.task_id
        runtime = await _runtime(service, task)
        try:
            before = await _content_objects(runtime)
            tested = (await runtime.ledger.load_frontier()).sequence
        finally:
            await service.app.runtime.release(runtime)
        listing = content_forgetting._erasable_objects
        held: list[bool] = []
        publishers: list[asyncio.Task[str]] = []

        async def publish() -> str:
            """A publisher of work that tested the frontier before the forget, as each one does."""

            runtime = await _runtime(service, task)
            try:
                async with content_fence.content_publication_fence(task):
                    if await content_fence.content_forgotten_after(runtime, tested):
                        return "refused"
                    data = b'{"late": "published while the forget ran"}'
                    staged = await runtime.objects.stage(
                        ObjectSource(data=data, declared_size=len(data)),
                        ObjectMetadata(
                            ObjectKind.SEMANTIC_RESPONSE,
                            "application/json",
                            task,
                            service.app.clock.now_utc(),
                        ),
                    )
                    await runtime.objects.finalize(staged)
                    return "published"
            finally:
                await service.app.runtime.release(runtime)

        async def listing_then_publish(runtime: TaskRuntime) -> tuple[ObjectRef, ...]:
            found = await listing(runtime)
            fences = content_fence._FENCES.get(asyncio.get_running_loop(), {})
            held.append(task in fences and fences[task].lock.locked())
            publishers.append(asyncio.create_task(publish()))
            return found

        monkeypatch.setattr(content_forgetting, "_erasable_objects", listing_then_publish)
        report = await forget_task_content(
            service.app, task, forget_id=new_forget_id(), reason="owner", provenance=_ACCOUNT
        )
        assert report == TaskContentForgetReport("forgotten", len(before), False)
        assert held == [True]
        (publisher,) = publishers
        assert await publisher == "refused"
        runtime = await _runtime(service, task)
        try:
            assert await _content_objects(runtime) == ()
        finally:
            await service.app.runtime.release(runtime)
    finally:
        await context.__aexit__(None, None, None)
