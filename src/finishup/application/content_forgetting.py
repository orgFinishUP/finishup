"""Forget the repository content a task derived from a server copy (ADR-054, owner ruling U20).

When a server copy is forgotten (by its owner, or when its retention runs out), the service
forgets, in every task that read it, the content derived from it. Per task, holding the task's
content fence (``application.content_fence``) throughout, so no content object is published
meanwhile, in this order:

1. list the task's content objects and mark them erased in its object inventory (``redacted``):
   this forget's scope, recorded before anything else;
2. record one service-written ``content_forgotten`` event (the forget's id, its closed reason, the
   source ``server_copy``, how many objects the erasure sets out to delete, and the task's evidence
   account then). From that event on, every projection, result and receipt reads the quoted
   excerpts as absent (``kernel.forgotten_content``); findings and checks stay, and the content
   publishers refuse work that tested a frontier before it (a check or review in flight then);
3. delete their files.

The content objects are the check-time change objects (``vnd.yoetz.check-change+json``: the
captured diff and the task inputs inside the repository root) and the reviewer's
``SEMANTIC_RESPONSE`` objects (its judgment, with the snippets it quoted). Never an event's payload
object (the ledger is hash-chained: the event stays exactly as written, its excerpts masked in
every view), never the task-start base (paths and metadata only), the task-input snapshot sets
(copies of files outside the repository that the client sent), the session or receipt records.

Idempotent by ``forget_id``: a second call records nothing new and erases what is left of the
objects the inventory marks erased, so a forget interrupted between the event and the deletes
completes on the retry, and never erases the content of a later check (published after the
event, so neither marked nor masked). A call interrupted before the event records it on the
retry, over whatever is then on disk. Every outcome is typed; a task that does not exist or
cannot be routed is one of them, never an exception.
"""

from __future__ import annotations

import re
import secrets
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Literal, cast

from finishup.application.content_fence import content_publication_fence
from finishup.application.lineage_recovery import lineage_recovery_runtime
from finishup.application.unit_of_work import PreparedMutation, run_prepared_append
from finishup.domain.events import (
    CONTENT_FORGOTTEN_EVENT_SCHEMA_VERSION,
    OBSERVATION_COORDINATOR_ACTOR_ID,
    AcceptedEvent,
    ContentForgottenPayload,
    EventDraft,
    EventSchema,
    encode_payload,
    is_content_forgotten_record,
    media_type_for,
)
from finishup.domain.evidence_provenance import EvidenceProvenance
from finishup.domain.values import (
    Actor,
    ActorType,
    actor_id,
    event_id,
    task_id,
    timestamp_from_datetime,
)
from finishup.observability.logging import (
    record_bounded_event_without_raising,
    record_unexpected_exception_without_raising,
)
from finishup.ports.change_capture import CHECK_CHANGE_MEDIA_TYPE
from finishup.ports.ledger import AppendCommand, AppendEntry, OperationKind
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectRef, ObjectSource
from finishup.ports.runtime import TaskRuntime
from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.coverage import AuthorshipAssurance, PublicationChannel, coverage_for_channel
from finishup.protocol.errors import PublicErrorCode, PublicOperationError

if TYPE_CHECKING:
    from finishup.application.service import Application

__all__ = [
    "ForgetReason",
    "TaskContentForgetOutcome",
    "TaskContentForgetReport",
    "forget_task_content",
    "new_forget_id",
]

type ForgetReason = Literal["owner", "expired"]
type TaskContentForgetOutcome = Literal[
    "forgotten", "task_not_found", "task_unavailable", "erasure_incomplete"
]
_COMPONENT: Final = "content_forgetting"
_FORGET_ID: Final = re.compile(r"^[0-9a-f]{32}$", re.ASCII)
_SCHEMA: Final = EventSchema("content_forgotten", CONTENT_FORGOTTEN_EVENT_SCHEMA_VERSION)
_APPEND_ATTEMPTS: Final = 3


@dataclass(frozen=True, slots=True)
class TaskContentForgetReport:
    """What one task's forget did.

    ``outcome``: ``forgotten`` (recorded, every content object erased), ``task_not_found`` (no
    such task: nothing to forget), ``task_unavailable`` (its ledger cannot be opened now; retry
    later) or ``erasure_incomplete`` (recording or an erasure failed part way; retry with the
    same ``forget_id``). ``objects_erased``: the files this call deleted. ``already_recorded``:
    the task's ledger held this forget's event before the call.
    """

    outcome: TaskContentForgetOutcome
    objects_erased: int = 0
    already_recorded: bool = False

    @property
    def complete(self) -> bool:
        """Whether nothing is left to retry for this task."""

        return self.outcome in {"forgotten", "task_not_found"}


def new_forget_id() -> str:
    """A fresh random forget identity (32 lowercase hex characters)."""

    return secrets.token_hex(16)


async def forget_task_content(
    app: Application,
    task: str,
    *,
    forget_id: str,
    reason: ForgetReason,
    provenance: EvidenceProvenance,
) -> TaskContentForgetReport:
    """Record that ``task``'s server-copy content was forgotten, then erase its content objects.

    ``provenance`` is the task's evidence account when the copy was forgotten; only its counts
    per token and fenced reads are recorded (the snapshot and any marker are dropped). Invalid
    arguments are a caller error (``ValueError``); every storage outcome is typed.
    """

    validated_task = task_id(task)
    if type(forget_id) is not str or _FORGET_ID.fullmatch(forget_id) is None:
        raise ValueError("forget_id_invalid")
    if reason not in {"owner", "expired"}:
        raise ValueError("forget_reason_invalid")
    if type(provenance) is not EvidenceProvenance:
        raise ValueError("forget_provenance_invalid")
    recorded_account = EvidenceProvenance(provenance.reads, provenance.fenced_reads)

    if await app.start_catalog.task_route(validated_task) is None:
        return TaskContentForgetReport("task_not_found")
    try:
        runtime = await lineage_recovery_runtime(app, validated_task)
    except PublicOperationError as exc:
        _incomplete("task_route_unavailable", exc.code.value.lower())
        return TaskContentForgetReport("task_unavailable")
    erased = 0
    already = False
    try:
        # No content object of the task is published from the inventory through the erasure.
        async with content_publication_fence(runtime.task_id):
            already = await _recorded(app, runtime, forget_id)
            inventory = await _erasable_objects(runtime)
            if already:
                # A retry erases what is left of the scope this forget recorded, never a later
                # check's content, which the event leaves unmasked.
                marked = await _erased_ids(runtime)
                plan = tuple(ref for ref in inventory if ref.object_id in marked)
            else:
                plan = inventory
                recorder = getattr(runtime.ledger, "record_erased_objects", None)
                if plan and callable(recorder):
                    # The scope, durably, before the event that makes it the forget's own.
                    await cast(Callable[[tuple[ObjectRef, ...]], Awaitable[None]], recorder)(plan)
                await _record_forget(
                    app,
                    runtime,
                    ContentForgottenPayload(
                        forget_id=forget_id,
                        reason=reason,
                        source="server_copy",
                        objects_erased=len(plan),
                        provenance=recorded_account,
                    ),
                )
            eraser = getattr(runtime.objects, "erase_published", None)
            if plan and not callable(eraser):
                _incomplete("object_erasure_unsupported", "object_store")
                return TaskContentForgetReport("erasure_incomplete", 0, already)
            for ref in plan:
                if await cast(Callable[[ObjectRef], Awaitable[bool]], eraser)(ref):
                    erased += 1
    except PublicOperationError as exc:
        _incomplete("task_content_forget_failed", exc.code.value.lower())
        return TaskContentForgetReport("erasure_incomplete", erased, already)
    except (OSError, ValueError) as exc:
        record_unexpected_exception_without_raising(
            exc, component=_COMPONENT, operation="task_content_forget_failed"
        )
        return TaskContentForgetReport("erasure_incomplete", erased, already)
    finally:
        await app.runtime.release(runtime)
    return TaskContentForgetReport("forgotten", erased, already)


def _incomplete(operation: str, reason: str) -> None:
    record_bounded_event_without_raising(component=_COMPONENT, operation=operation, reason=reason)


async def _recorded(app: Application, runtime: TaskRuntime, forget_id: str) -> bool:
    """Whether any of the task's sessions already holds this forget's event."""

    sessions = await app.start_catalog.task_session_states(runtime.task_id)
    for session in {runtime.session_id, *(state.session_id for state in sessions)}:
        async for record in runtime.ledger.load_events(session):
            if (
                is_content_forgotten_record(record)
                and type(cast(AcceptedEvent, record).payload) is ContentForgottenPayload
                and cast(ContentForgottenPayload, cast(AcceptedEvent, record).payload).forget_id
                == forget_id
            ):
                return True
    return False


async def _erased_ids(runtime: TaskRuntime) -> frozenset[str]:
    """The objects the task's inventory records as erased (``redacted``): every forget's scope."""

    reader = getattr(runtime.ledger, "erased_object_ids", None)
    if not callable(reader):
        return frozenset()
    return await cast(Callable[[], Awaitable[frozenset[str]]], reader)()


async def _erasable_objects(runtime: TaskRuntime) -> tuple[ObjectRef, ...]:
    """The task's content objects that are still on disk, authenticated, in id order.

    Every published object of the task's store is read; the check-time change objects and the
    reviewer's responses are the ones forgotten. A store that cannot list its objects has none
    to erase here (the in-memory stores of tests and embedders).
    """

    lister = getattr(runtime.objects, "published_object_ids", None)
    describer = getattr(runtime.objects, "describe_published", None)
    if not callable(lister) or not callable(describer):
        return ()
    selected: list[ObjectRef] = []
    for object_id in await cast(Callable[[], Awaitable[tuple[str, ...]]], lister)():
        try:
            ref = await cast(Callable[[str], Awaitable[ObjectRef]], describer)(object_id)
        except ValueError:
            # Gone since it was listed, or not one this store authenticates: never erased here.
            continue
        if ref.metadata.task_id != runtime.task_id:
            continue
        kind, media_type = ref.metadata.kind, ref.metadata.media_type
        if kind is ObjectKind.SEMANTIC_RESPONSE or (
            kind is ObjectKind.CHANGE_CAPTURE and media_type == CHECK_CHANGE_MEDIA_TYPE
        ):
            selected.append(ref)
    return tuple(selected)


async def _record_forget(
    app: Application, runtime: TaskRuntime, payload: ContentForgottenPayload
) -> None:
    """Append the one ``content_forgotten`` event, with an identity derived from the forget.

    The task and forget identities fix the event and operation ids, so a retry after a crash
    during the append replays the same operation instead of recording a second event.
    """

    writer_id = runtime.writer_id
    if writer_id is None:
        raise PublicOperationError(
            PublicErrorCode.STORAGE_CORRUPT, "The task recovery identity is inconsistent.", False
        )
    digest = canonical_digest(
        {"task_id": runtime.task_id, "kind": "content_forgotten", "forget_id": payload.forget_id}
    )
    raw = bytearray(bytes.fromhex(digest.removeprefix("sha256:")[:32]))
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    identity = str(uuid.UUID(bytes=bytes(raw)))
    operation_id = "req_" + identity
    occurred_at = app.clock.now_utc()
    metadata = ObjectMetadata(
        ObjectKind.EVENT_PAYLOAD, media_type_for(_SCHEMA.name), runtime.task_id, occurred_at
    )
    payload_ref = await runtime.objects.finalize(
        await runtime.objects.stage(
            ObjectSource(data=canonical_encode(encode_payload(payload))), metadata
        )
    )
    draft = EventDraft(
        event_id=event_id("evt_" + identity),
        schema=_SCHEMA,
        occurred_at=timestamp_from_datetime(occurred_at),
        causal_parents=(),
        payload=payload,
        artifact_refs=(),
        evidence_refs=(),
    )
    entry = AppendEntry(
        draft=draft,
        author=Actor(
            actor_id(OBSERVATION_COORDINATOR_ACTOR_ID),
            ActorType.HARNESS,
            AuthorshipAssurance.HARNESS_OBSERVED,
        ),
        payload_object=payload_ref,
        payload_commitment=payload_ref.commitment,
        media_type=metadata.media_type,
        plaintext_size=payload_ref.plaintext_size,
        publication_channel=PublicationChannel.ENGINE_DERIVED,
        coverage=coverage_for_channel(PublicationChannel.ENGINE_DERIVED),
        projection_status="projected",
    )
    for attempt in range(_APPEND_ATTEMPTS):
        # The task may be live: an agent's publish can land between the frontier read and the
        # append. The same operation identity makes each retry, and any concurrent forget's,
        # replay one event instead of recording a second.
        frontier = await runtime.ledger.load_frontier()
        try:
            await run_prepared_append(
                runtime.ledger,
                PreparedMutation(
                    writer_id=writer_id,
                    operation_id=operation_id,
                    request_digest=digest,
                    expected_frontier=frontier.sequence,
                    finalized_object_refs=(payload_ref,),
                    command=AppendCommand(
                        task_id=runtime.task_id,
                        session_id=runtime.session_id,
                        writer_id=writer_id,
                        operation_id=operation_id,
                        operation_kind=OperationKind.PUBLISH_WORK,
                        request_digest=digest,
                        expected_frontier=frontier.sequence,
                        entries=(entry,),
                    ),
                ),
            )
        except PublicOperationError as exc:
            if exc.code is not PublicErrorCode.FRONTIER_CONFLICT or attempt + 1 == _APPEND_ATTEMPTS:
                raise
            continue
        return
