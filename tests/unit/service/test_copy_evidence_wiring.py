"""Level L2's receipt source and erasure wiring (ADR-054, U20).

``ready_composition._copy_evidence_source`` gives a claim-bound task's receipt its evidence
account: what the server's copy recorded while it serves the task, what the task's own ledger
keeps of a forgotten copy, and the hook observations the ledger accepted. ``daemon._copy_erasure``
runs the ledger erasure of a forgotten task on the service loop from the erasure's own thread.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import AsyncIterator, Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any

import pytest

from builders.observed_runs import ObservedLedger
from finishup.application import content_forgetting
from finishup.application.content_forgetting import TaskContentForgetReport
from finishup.domain.events import (
    CONTENT_FORGOTTEN_EVENT_SCHEMA_VERSION,
    ContentForgottenPayload,
    EventSchema,
)
from finishup.domain.evidence_provenance import (
    ContentForgotten,
    CopySnapshotRef,
    EvidenceProvenance,
)
from finishup.domain.values import freeze_json
from finishup.ports.ledger import LedgerRecord
from finishup.protocol.coverage import PublicationChannel
from finishup.service.code_store import PendingErasure
from finishup.service.daemon import _copy_erasure  # pyright: ignore[reportPrivateUsage]
from finishup.service.ready_composition import (
    _copy_evidence_source,  # pyright: ignore[reportPrivateUsage]
)

_SCHEMA = EventSchema("content_forgotten", CONTENT_FORGOTTEN_EVENT_SCHEMA_VERSION)
_FORGET_ID = "0123456789abcdef0123456789abcdef"
_AT = "2026-11-10T11:00:00.000Z"
_LIVE = EvidenceProvenance(
    {"server_copy_read": 5, "client_check": 1}, 1, CopySnapshotRef(_AT, "c" * 40)
)
_RECORDED = EvidenceProvenance({"server_copy_read": 4, "outside_read": 1}, 2)


@dataclass
class _Copies:
    account: EvidenceProvenance | None
    asked: list[str] = field(default_factory=lambda: [])

    def provenance(self, task_id: str) -> EvidenceProvenance | None:
        self.asked.append(task_id)
        return self.account


@dataclass
class _Hub:
    code_copies: _Copies | None


class _Ledger:
    def __init__(self, records: list[LedgerRecord]) -> None:
        self._records = records

    async def load_events(self, session_id: str) -> AsyncIterator[LedgerRecord]:
        del session_id
        for record in self._records:
            yield record


@dataclass
class _Runtime:
    ledger: _Ledger
    task_id: str = "tsk_00000000-0000-4000-8000-000000000001"
    session_id: str = "ses_00000000-0000-4000-8000-000000000001"


def _forget(ledger: ObservedLedger) -> None:
    payload = ContentForgottenPayload(_FORGET_ID, "expired", "server_copy", 2, _RECORDED)
    ledger._append(  # pyright: ignore[reportPrivateUsage]
        _SCHEMA, payload, observed=True, channel=PublicationChannel.ENGINE_DERIVED
    )


async def _account(hub: _Hub | None, records: list[LedgerRecord]) -> EvidenceProvenance | None:
    source = _copy_evidence_source(hub)  # pyright: ignore[reportArgumentType]
    assert source is not None
    return await source("client:" + "a" * 16, _Runtime(_Ledger(records)))  # pyright: ignore[reportArgumentType]


def test_no_hub_means_no_source() -> None:
    assert _copy_evidence_source(None) is None


@pytest.mark.anyio
async def test_a_task_with_neither_copy_nor_marker_has_no_account() -> None:
    assert await _account(_Hub(None), []) is None
    copies = _Copies(None)
    assert await _account(_Hub(copies), []) is None
    assert copies.asked == ["tsk_00000000-0000-4000-8000-000000000001"]


@pytest.mark.anyio
async def test_the_copy_account_is_the_live_one() -> None:
    assert await _account(_Hub(_Copies(_LIVE)), []) == _LIVE


@pytest.mark.anyio
async def test_a_forgotten_copy_is_read_from_the_task_ledger() -> None:
    ledger = ObservedLedger()
    _forget(ledger)
    account = await _account(_Hub(_Copies(None)), list(ledger.records))
    assert account is not None
    assert account.content_forgotten is not None
    assert account.content_forgotten.reason == "expired"
    assert account.count("server_copy_read") == 4
    assert account.fenced_reads == 2
    assert account.snapshot is None


@pytest.mark.anyio
async def test_a_forgotten_then_synced_again_task_keeps_both() -> None:
    ledger = ObservedLedger()
    _forget(ledger)
    account = await _account(_Hub(_Copies(_LIVE)), list(ledger.records))
    assert account is not None
    assert account.count("server_copy_read") == 9
    assert account.fenced_reads == 3
    assert account.snapshot == _LIVE.snapshot
    assert isinstance(account.content_forgotten, ContentForgotten)


@pytest.mark.anyio
async def test_hook_observations_are_counted_from_the_ledger_for_a_level_l2_task() -> None:
    ledger = ObservedLedger()
    ledger.passes("pytest -q")
    observed = sum(
        1
        for record in ledger.records
        if getattr(record, "publication_channel", None) is PublicationChannel.HOOK_OBSERVED
    )
    assert observed > 0
    account = await _account(_Hub(_Copies(_LIVE)), list(ledger.records))
    assert account is not None
    assert account.count("client_observation") == observed
    # A task the copy never served gets no account, observations or not.
    assert await _account(_Hub(_Copies(None)), list(ledger.records)) is None


@pytest.mark.anyio
async def test_an_unreadable_forget_event_is_never_read_as_level_l1() -> None:
    ledger = ObservedLedger()
    _forget(ledger)
    unreadable = [_without_payload(record) for record in ledger.records]
    source = _copy_evidence_source(_Hub(_Copies(None)))  # pyright: ignore[reportArgumentType]
    assert source is not None
    with pytest.raises(LookupError, match="content_forgotten_unreadable"):
        await source("client:" + "a" * 16, _Runtime(_Ledger(unreadable)))  # pyright: ignore[reportArgumentType]


def _without_payload(record: LedgerRecord) -> LedgerRecord:
    from dataclasses import replace

    return replace(record, payload=None)  # pyright: ignore[reportArgumentType]


# --- the erasure's wiring -------------------------------------------------------------------


def _pending() -> PendingErasure:
    return PendingErasure(
        _FORGET_ID, "owner", "tsk_00000000-0000-4000-8000-000000000001", _RECORDED, _AT
    )


def _with_loop(work: Callable[[asyncio.AbstractEventLoop], bool]) -> bool:
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    try:
        return work(loop)
    finally:
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=10)
        loop.close()


@pytest.mark.parametrize(
    ("report", "expected"),
    [
        (TaskContentForgetReport("forgotten", 2), True),
        (TaskContentForgetReport("task_not_found"), True),
        (TaskContentForgetReport("task_unavailable"), False),
        (TaskContentForgetReport("erasure_incomplete"), False),
    ],
)
def test_the_erasure_is_done_only_when_nothing_is_left_to_retry(
    report: TaskContentForgetReport, expected: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[object, ...]] = []

    async def forget(app: object, task: str, **fields: object) -> TaskContentForgetReport:
        calls.append((app, task, freeze_json(str(sorted(fields)))))
        return report

    monkeypatch.setattr(content_forgetting, "forget_task_content", forget)
    application = object()
    done = _with_loop(lambda loop: _copy_erasure(application, loop)(_pending()))
    assert done is expected
    assert calls and calls[0][0] is application
    assert calls[0][1] == "tsk_00000000-0000-4000-8000-000000000001"


def test_a_failing_erasure_is_never_claimed_done(monkeypatch: pytest.MonkeyPatch) -> None:
    async def forget(*_args: object, **_fields: object) -> Coroutine[Any, Any, None]:
        raise RuntimeError("ledger_unavailable")

    monkeypatch.setattr(content_forgetting, "forget_task_content", forget)
    assert _with_loop(lambda loop: _copy_erasure(object(), loop)(_pending())) is False


def test_an_erasure_asked_from_the_loop_itself_waits_for_the_next_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def forget(*_args: object, **_fields: object) -> TaskContentForgetReport:
        return TaskContentForgetReport("forgotten")

    monkeypatch.setattr(content_forgetting, "forget_task_content", forget)

    async def from_the_loop() -> bool:
        return _copy_erasure(object(), asyncio.get_running_loop())(_pending())

    assert asyncio.run(from_the_loop()) is False
    closed = asyncio.new_event_loop()
    closed.close()
    assert _copy_erasure(object(), closed)(_pending()) is False
