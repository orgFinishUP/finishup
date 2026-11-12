"""The workspace-agent hub: bounded, typed calls to a claim-bound connection's agent (ADR-051)."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable

import pytest

from finishup.ports.approved_checks import ApprovedCheckApproval, approval_commitment
from finishup.ports.change_capture import TaskChangeBase
from finishup.ports.control import WorkspaceAgentDeclaration, WorkspaceCall, WorkspaceReply
from finishup.ports.workspace_agent import (
    WORKSPACE_OPERATION_NAMES,
    CodeSyncReadArguments,
    RunApprovedCheckArguments,
    WorkspaceAgentUnavailable,
    WorkspaceOnlyArguments,
    WorkspaceOperation,
    operation_spec,
    workspace_handle_for_claim,
)
from finishup.service.workspace_hub import (
    MAX_CALLS_PER_CHANNEL,
    WorkspaceAgentChannel,
    WorkspaceAgentHub,
    in_live_call,
    live_call_scope,
    workspace_call_deadline,
)

pytestmark = pytest.mark.anyio

_HANDLE = "client:0123456789abcdef"
_INSTANCE = "svc_00000000-0000-4000-8000-000000000051"
_BASE = TaskChangeBase("sha1", "a" * 40)
_ARGS = WorkspaceOnlyArguments(_HANDLE)


def _declaration(*operations: str) -> WorkspaceAgentDeclaration:
    names = operations or WORKSPACE_OPERATION_NAMES
    return WorkspaceAgentDeclaration(tuple(sorted(names, key=str.encode)), 6_291_456)


def _ok(call: WorkspaceCall, value: object) -> WorkspaceReply:
    spec = operation_spec(call.operation)
    assert spec is not None
    return WorkspaceReply(
        "workspace_reply", "1.0", call.call_id, "ok", spec.encode_result(value), None
    )


def _failure(call: WorkspaceCall, outcome: str, reason: str) -> WorkspaceReply:
    return WorkspaceReply("workspace_reply", "1.0", call.call_id, outcome, None, reason)  # pyright: ignore[reportArgumentType]


async def _register(
    hub: WorkspaceAgentHub,
    answer: Callable[[WorkspaceCall], WorkspaceReply | None],
    *,
    declaration: WorkspaceAgentDeclaration | None = None,
    sent: list[WorkspaceCall] | None = None,
    handle: str = _HANDLE,
    worktree: str | None = None,
) -> WorkspaceAgentChannel:
    holder: list[WorkspaceAgentChannel] = []

    async def writer(call: WorkspaceCall) -> None:
        if sent is not None:
            sent.append(call)
        reply = answer(call)
        if reply is not None:
            asyncio.get_running_loop().call_soon(hub.deliver, holder[0], reply)

    channel = await hub.register(
        handle=handle,
        declaration=declaration or _declaration(),
        service_instance_id=_INSTANCE,
        service_generation="7",
        writer=writer,
        worktree=worktree,
    )
    holder.append(channel)
    return channel


def _hub(wait: float = 0.2) -> WorkspaceAgentHub:
    return WorkspaceAgentHub(inline_wait_seconds=wait, background_wait_seconds=wait)


_DEADLINE_SECONDS = 10.0


async def _until(condition: Callable[[], bool], *, interval: float = 0.0) -> None:
    """Yield to the loop until ``condition`` holds; fail once the deadline passes without it."""

    loop = asyncio.get_running_loop()
    deadline = loop.time() + _DEADLINE_SECONDS
    while not condition():
        assert loop.time() < deadline, "deadline passed before the state was observed"
        await asyncio.sleep(interval)


async def test_a_call_is_framed_for_the_agents_connection_and_decodes_its_answer() -> None:
    hub = _hub()
    sent: list[WorkspaceCall] = []
    await _register(hub, lambda call: _ok(call, _BASE), sent=sent)

    base = await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=2.0)

    assert base == _BASE
    (call,) = sent
    assert call.operation == "read_task_base"
    assert call.service_instance_id == _INSTANCE and call.service_generation == "7"
    assert call.arguments == {"workspace": _HANDLE}
    assert 1 <= call.deadline_ms <= 2_000


async def test_no_agent_within_the_wait_is_typed_no_agent() -> None:
    hub = _hub(0.05)
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
    assert caught.value.reason == "no_agent" and caught.value.agent_reason is None


async def test_a_call_waits_for_an_agent_that_connects_within_the_bound() -> None:
    hub = _hub(2.0)
    pending = asyncio.create_task(
        hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=2.0)
    )
    await asyncio.sleep(0)
    await _register(hub, lambda call: _ok(call, _BASE))
    assert await pending == _BASE


async def test_live_calls_wait_less_than_background_work() -> None:
    hub = WorkspaceAgentHub(inline_wait_seconds=0.01, background_wait_seconds=5.0)
    assert not in_live_call()
    with live_call_scope():
        assert in_live_call()
        with pytest.raises(WorkspaceAgentUnavailable):
            await asyncio.wait_for(
                hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0),
                1.0,
            )
    background = asyncio.create_task(
        hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
    )
    with live_call_scope():
        live = asyncio.create_task(
            hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
        )
        # Started just after the background call, the live call has already given up waiting.
        with pytest.raises(WorkspaceAgentUnavailable) as caught:
            await asyncio.wait_for(live, 1.0)
    assert caught.value.reason == "no_agent"
    assert not background.done()  # still inside the longer background wait
    await _register(hub, lambda call: _ok(call, _BASE))
    assert await background == _BASE


async def _left_running(
    hub: WorkspaceAgentHub, entered: str, channel: WorkspaceAgentChannel | None = None
) -> tuple[asyncio.Task[object], dict[str, object]]:
    """A live call that starts work and returns while the work goes on (a detached review).

    ``entered`` says whether the work entered its own handler scope while the call was still
    live, or only after it returned. The task is returned once the call has returned.
    """

    begun, returned = asyncio.Event(), asyncio.Event()
    seen: dict[str, object] = {}

    async def detached() -> object:
        if entered == "after_return":
            await returned.wait()
        with workspace_call_deadline():  # the detached operation's own handler scope
            begun.set()
            await returned.wait()
            seen["live"] = in_live_call()
            return await hub.call(
                _HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0
            )

    with live_call_scope(channel):
        task = asyncio.create_task(detached())
        if entered == "while_live":
            await begun.wait()
            assert in_live_call()
    returned.set()  # the call returned: its caller stopped waiting, the work goes on
    return task, seen


@pytest.mark.parametrize("entered", ("while_live", "after_return"))
async def test_work_a_live_call_left_running_waits_as_background_work(
    entered: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-051: the detached review its caller stopped waiting for waits 30 s for an agent, not
    the live call's 5 s."""

    hub = WorkspaceAgentHub(inline_wait_seconds=0.01, background_wait_seconds=5.0)
    waits: list[float] = []
    choose = WorkspaceAgentHub._channel_for  # pyright: ignore[reportPrivateUsage]

    async def recording(
        self: WorkspaceAgentHub,
        handle: str,
        operation: WorkspaceOperation,
        wait_seconds: float,
        preferred: WorkspaceAgentChannel | None = None,
    ) -> WorkspaceAgentChannel:
        waits.append(wait_seconds)  # the agent wait the call chose
        return await choose(self, handle, operation, wait_seconds, preferred)

    monkeypatch.setattr(WorkspaceAgentHub, "_channel_for", recording)
    await _register(hub, lambda call: _ok(call, _BASE))
    task, seen = await _left_running(hub, entered)
    assert await asyncio.wait_for(task, _DEADLINE_SECONDS) == _BASE
    assert waits == [5.0]  # the background bound, never the live call's
    assert seen == {"live": False}


@pytest.mark.parametrize("entered", ("while_live", "after_return"))
async def test_work_a_live_call_left_running_no_longer_prefers_its_connection(
    entered: str,
) -> None:
    hub = _hub()
    own: list[WorkspaceCall] = []
    newer: list[WorkspaceCall] = []
    channel = await _register(hub, lambda call: _ok(call, _BASE), sent=own)
    await _register(hub, lambda call: _ok(call, _BASE), sent=newer)
    task, _seen = await _left_running(hub, entered, channel)
    assert await asyncio.wait_for(task, _DEADLINE_SECONDS) == _BASE
    # Background work has no serving connection: the newest agent for the worktree answers.
    assert (len(own), len(newer)) == (0, 1)


@pytest.mark.parametrize(
    ("outcome", "agent_reason", "reason"),
    (
        ("refused", "workspace_not_claimed", "agent_refused"),
        ("unavailable", "not_git", "agent_unavailable"),
        ("failed", "internal_error", "agent_failed"),
    ),
)
async def test_an_agents_own_answer_keeps_its_closed_reason(
    outcome: str, agent_reason: str, reason: str
) -> None:
    hub = _hub()
    await _register(hub, lambda call: _failure(call, outcome, agent_reason))
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
    assert (caught.value.reason, caught.value.agent_reason) == (reason, agent_reason)
    assert caught.value.refused is (reason == "agent_refused")


async def test_a_reply_that_is_not_the_operations_result_is_reply_invalid() -> None:
    hub = _hub()
    await _register(
        hub,
        lambda call: WorkspaceReply(
            "workspace_reply", "1.0", call.call_id, "ok", {"not": "a base"}, None
        ),
    )
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
    assert caught.value.reason == "reply_invalid"


async def test_no_reply_by_the_deadline_is_deadline_exceeded_and_a_late_reply_is_dropped() -> None:
    hub = _hub()
    sent: list[WorkspaceCall] = []
    channel = await _register(hub, lambda _call: None, sent=sent)
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=0.05)
    assert caught.value.reason == "deadline_exceeded"
    assert channel.pending_count == 0
    hub.deliver(channel, _ok(sent[0], _BASE))  # nothing awaits it any more; ignored


async def test_a_dropped_connection_fails_its_pending_calls_at_once() -> None:
    hub = _hub()
    channel = await _register(hub, lambda _call: None)
    pending = asyncio.create_task(
        hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=30.0)
    )
    await _until(lambda: channel.pending_count > 0)
    await hub.unregister(channel)
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await asyncio.wait_for(pending, 1.0)
    assert caught.value.reason == "agent_disconnected"
    assert not hub.has_agent(_HANDLE)


async def test_a_connection_that_cannot_take_the_frame_is_disconnected() -> None:
    hub = _hub()

    async def broken(_call: WorkspaceCall) -> None:
        raise ConnectionResetError("gone")

    await hub.register(
        handle=_HANDLE,
        declaration=_declaration(),
        service_instance_id=_INSTANCE,
        service_generation="7",
        writer=broken,
    )
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
    assert caught.value.reason == "agent_disconnected"


async def test_an_agent_that_declared_other_operations_is_not_asked() -> None:
    hub = _hub()
    sent: list[WorkspaceCall] = []
    await _register(
        hub, lambda call: _ok(call, _BASE), declaration=_declaration("capture"), sent=sent
    )
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
    assert caught.value.reason == "operation_not_declared"
    assert sent == []


async def test_one_connection_serves_a_bounded_number_of_calls_at_once() -> None:
    hub = _hub()
    held: list[WorkspaceCall] = []
    channel = await _register(hub, lambda _call: None, sent=held)
    calls = [
        asyncio.create_task(
            hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=5.0)
        )
        for _ in range(MAX_CALLS_PER_CHANNEL)
    ]
    await _until(lambda: len(held) == MAX_CALLS_PER_CHANNEL)
    # One call more waits for a slot within its own bound, is never sent, and says so.
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=0.1)
    assert caught.value.reason == "agent_busy"
    assert len(held) == MAX_CALLS_PER_CHANNEL
    for call in held:
        hub.deliver(channel, _ok(call, _BASE))
    assert await asyncio.gather(*calls) == [_BASE] * MAX_CALLS_PER_CHANNEL


_COMMITMENT = "hmac-sha256:" + "0a" * 32
_WORKTREE_MAIN = "sha256:" + "1" * 64
_WORKTREE_LINKED = "sha256:" + "2" * 64


async def test_linked_worktrees_have_their_own_handles_and_their_own_agents() -> None:
    """ADR-051: one repository commitment, one handle per worktree; never another tree's agent."""

    hub = _hub()
    main = workspace_handle_for_claim(_COMMITMENT, _WORKTREE_MAIN)
    linked = workspace_handle_for_claim(_COMMITMENT, _WORKTREE_LINKED)
    assert main != linked
    main_calls: list[WorkspaceCall] = []
    linked_calls: list[WorkspaceCall] = []
    await _register(
        hub, lambda call: _ok(call, _BASE), sent=main_calls, handle=main, worktree=_WORKTREE_MAIN
    )
    # The linked worktree's agent connects later: it must never answer the main tree's task.
    await _register(
        hub,
        lambda call: _ok(call, _BASE),
        sent=linked_calls,
        handle=linked,
        worktree=_WORKTREE_LINKED,
    )
    for handle in (main, main, linked):
        arguments = WorkspaceOnlyArguments(handle)
        await hub.call(handle, WorkspaceOperation.READ_TASK_BASE, arguments, timeout_seconds=1.0)
    assert [call.arguments["workspace"] for call in main_calls] == [main, main]
    assert [call.arguments["workspace"] for call in linked_calls] == [linked]


async def test_an_agent_of_another_worktree_is_never_admitted_under_a_handle() -> None:
    hub = _hub()
    first: list[WorkspaceCall] = []
    await _register(hub, lambda call: _ok(call, _BASE), sent=first, worktree=_WORKTREE_MAIN)
    with pytest.raises(ValueError, match="workspace_agent_worktree_conflict"):
        await _register(hub, lambda call: _ok(call, _BASE), worktree=_WORKTREE_LINKED)
    # Another connection from the same worktree is admitted beside it.
    await _register(hub, lambda call: _ok(call, _BASE), worktree=_WORKTREE_MAIN)
    with pytest.raises(ValueError, match="workspace_worktree_invalid"):
        await _register(hub, lambda call: _ok(call, _BASE), worktree="/srv/dev/repo")


async def test_a_live_call_prefers_its_own_connections_agent() -> None:
    hub = _hub()
    own: list[WorkspaceCall] = []
    newer: list[WorkspaceCall] = []
    channel = await _register(hub, lambda call: _ok(call, _BASE), sent=own)
    await _register(hub, lambda call: _ok(call, _BASE), sent=newer)
    with live_call_scope(channel):
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)

        def blocking() -> object:
            return hub.call_blocking(
                _HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0
            )

        # A worker thread serving the same call keeps the preference.
        assert await asyncio.to_thread(blocking) == _BASE
    assert (len(own), len(newer)) == (2, 0)
    # Background work has no serving connection; every channel serves the one worktree.
    await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
    assert (len(own), len(newer)) == (2, 1)
    # A preference for a channel that is gone, or for another handle, is ignored.
    other = workspace_handle_for_claim(_COMMITMENT, _WORKTREE_LINKED)
    elsewhere: list[WorkspaceCall] = []
    await _register(hub, lambda call: _ok(call, _BASE), sent=elsewhere, handle=other)
    await hub.unregister(channel)
    with live_call_scope(channel):
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
        await hub.call(
            other,
            WorkspaceOperation.READ_TASK_BASE,
            WorkspaceOnlyArguments(other),
            timeout_seconds=1.0,
        )
    assert (len(own), len(newer), len(elsewhere)) == (2, 2, 1)


async def test_a_read_whose_connection_dropped_is_asked_once_of_another_live_one() -> None:
    """Two connections of one client serve the claim; the newest goes away mid-call."""

    hub = _hub()
    older: list[WorkspaceCall] = []
    await _register(hub, lambda call: _ok(call, _BASE), sent=older)
    newest = await _register(hub, lambda _call: None)
    pending = asyncio.create_task(
        hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=5.0)
    )
    await _until(lambda: newest.pending_count > 0)
    await hub.unregister(newest)
    assert await asyncio.wait_for(pending, 1.0) == _BASE
    assert [call.operation for call in older] == ["read_task_base"]


async def test_an_approved_check_whose_connection_dropped_is_never_run_twice() -> None:
    hub = _hub()
    older: list[WorkspaceCall] = []
    await _register(hub, lambda _call: None, sent=older)
    newest = await _register(hub, lambda _call: None)
    arguments = RunApprovedCheckArguments(
        "rws_" + "0" * 32,
        ApprovedCheckApproval(
            approval_id="unit",
            argv=("/usr/bin/true",),
            allow_network=False,
            timeout_seconds=10.0,
            approval_commitment=approval_commitment(
                "unit", ("/usr/bin/true",), allow_network=False
            ),
        ),
        "sha256:" + "4" * 64,
        None,
    )
    pending = asyncio.create_task(
        hub.call(_HANDLE, WorkspaceOperation.RUN_APPROVED_CHECK, arguments, timeout_seconds=5.0)
    )
    await _until(lambda: newest.pending_count > 0)
    await hub.unregister(newest)
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await asyncio.wait_for(pending, 1.0)
    assert caught.value.reason == "agent_disconnected"
    assert older == []


async def test_a_blocking_call_from_a_worker_thread_reaches_the_loop() -> None:
    hub = _hub()
    await _register(hub, lambda call: _ok(call, _BASE))

    def blocking() -> object:
        return hub.call_blocking(
            _HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0
        )

    assert await asyncio.to_thread(blocking) == _BASE


async def test_a_blocking_call_on_the_loops_own_thread_is_refused_not_deadlocked() -> None:
    hub = _hub()
    await _register(hub, lambda call: _ok(call, _BASE))
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        hub.call_blocking(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
    assert caught.value.reason == "hub_unavailable"


def test_a_hub_no_loop_serves_is_unavailable() -> None:
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        _hub().call_blocking(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
    assert caught.value.reason == "hub_unavailable"


async def test_arguments_the_catalog_refuses_are_typed_and_never_sent() -> None:
    hub = _hub()
    sent: list[WorkspaceCall] = []
    await _register(hub, lambda call: _ok(call, _BASE), sent=sent)
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, object(), timeout_seconds=1.0)
    assert caught.value.reason == "arguments_invalid"
    assert sent == []


def test_unavailability_reasons_are_closed_and_name_nothing() -> None:
    with pytest.raises(ValueError, match="workspace_agent_unavailable_reason_invalid"):
        WorkspaceAgentUnavailable("/srv/dev/repo")
    with pytest.raises(ValueError, match="workspace_agent_reason_invalid"):
        WorkspaceAgentUnavailable("agent_refused", "not a token")
    with pytest.raises(ValueError, match="workspace_agent_reason_invalid"):
        WorkspaceAgentUnavailable("no_agent", "not_git")
    assert str(WorkspaceAgentUnavailable("agent_refused", "root_not_admitted")) == "agent_refused"


def test_representations_name_no_handle() -> None:
    assert repr(_hub()) == "WorkspaceAgentHub(<redacted>)"


# --- the control call a workspace call serves bounds and cancels it (ADR-051) ---------------


async def test_a_cancelled_handler_cancels_its_blocking_workspace_call_at_once() -> None:
    hub = _hub(1.0)
    channel = await _register(hub, lambda _call: None)
    returned = threading.Event()
    reasons: list[str] = []

    def blocking() -> object:
        try:
            return hub.call_blocking(
                _HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=60.0
            )
        except WorkspaceAgentUnavailable as exc:
            reasons.append(exc.reason)
            raise
        finally:
            returned.set()

    async def handler() -> object:
        with live_call_scope(), workspace_call_deadline():
            return await asyncio.to_thread(blocking)

    task = asyncio.create_task(handler())
    await _until(lambda: channel.pending_count > 0, interval=0.005)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # The worker thread and the agent slot are free at once, not after the call's 60 s.
    assert await asyncio.to_thread(returned.wait, 2.0)
    assert reasons == ["call_cancelled"]
    await _until(lambda: channel.pending_count == 0, interval=0.005)


async def test_a_workspace_call_never_waits_past_its_handlers_deadline() -> None:
    hub = _hub(1.0)
    sent: list[WorkspaceCall] = []
    await _register(hub, lambda _call: None, sent=sent)
    loop = asyncio.get_running_loop()

    def blocking() -> object:
        return hub.call_blocking(
            _HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=60.0
        )

    started = loop.time()
    with live_call_scope(), workspace_call_deadline(loop.time() + 0.3):
        with pytest.raises(WorkspaceAgentUnavailable) as caught:
            await asyncio.to_thread(blocking)
    assert caught.value.reason == "deadline_exceeded"
    # Told only the handler's remaining time, and waited about that long (plus the reply grace).
    (call,) = sent
    assert 1 <= call.deadline_ms <= 300
    assert loop.time() - started < 5.0
    # A handler with no time left sends nothing at all.
    with live_call_scope(), workspace_call_deadline(loop.time() - 1.0):
        with pytest.raises(WorkspaceAgentUnavailable) as caught:
            await asyncio.to_thread(blocking)
        with pytest.raises(WorkspaceAgentUnavailable):
            await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
    assert caught.value.reason == "deadline_exceeded"
    assert len(sent) == 1


async def test_work_a_handler_started_is_not_bounded_by_it_once_it_returned() -> None:
    """A task the handler spawned copies its context; it is not the handler's call any more."""

    hub = _hub(1.0)
    sent: list[WorkspaceCall] = []
    await _register(hub, lambda call: _ok(call, _BASE), sent=sent)
    loop = asyncio.get_running_loop()
    release = asyncio.Event()

    async def later() -> object:
        await release.wait()
        return await asyncio.to_thread(
            hub.call_blocking,
            _HANDLE,
            WorkspaceOperation.READ_TASK_BASE,
            _ARGS,
            timeout_seconds=30.0,
        )

    handler_deadline = loop.time() + 0.05
    with workspace_call_deadline(handler_deadline):
        spawned = asyncio.create_task(later())
    # The handler's deadline has passed; its scope ended normally.
    await _until(lambda: loop.time() > handler_deadline, interval=0.01)
    release.set()
    assert await spawned == _BASE
    (call,) = sent
    assert call.deadline_ms > 1_000


async def test_a_queued_call_is_told_only_the_time_it_has_left() -> None:
    hub = _hub()
    held: list[WorkspaceCall] = []
    channel = await _register(hub, lambda _call: None, sent=held)
    blockers = [
        asyncio.create_task(
            hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=5.0)
        )
        for _ in range(MAX_CALLS_PER_CHANNEL)
    ]
    await _until(lambda: len(held) == MAX_CALLS_PER_CHANNEL)
    loop = asyncio.get_running_loop()
    queued = asyncio.create_task(
        hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=2.0)
    )
    await asyncio.sleep(0)  # one step: the queued call fixed its 2 s budget and waits for a slot
    budget_fixed_by = loop.time()
    # Let the slot wait cost a measurable part of that budget before one slot frees.
    await _until(lambda: loop.time() >= budget_fixed_by + 0.5, interval=0.01)
    freed_at = loop.time()
    hub.deliver(channel, _ok(held[0], _BASE))
    await _until(lambda: len(held) == MAX_CALLS_PER_CHANNEL + 1)
    late = held[-1]
    # Not the full 2 s: told at most what was left once the slot freed.
    assert 1 <= late.deadline_ms <= int((budget_fixed_by + 2.0 - freed_at) * 1000) + 1
    # The agent answers as soon as it is asked, within the deadline it was told.
    hub.deliver(channel, _ok(late, _BASE))
    assert await queued == _BASE
    for blocker in blockers:
        blocker.cancel()
    await asyncio.gather(*blockers, return_exceptions=True)


async def test_a_frame_is_written_whole_when_its_caller_stops_waiting() -> None:
    hub = _hub()
    release = asyncio.Event()
    finished: list[str] = []

    entered: list[str] = []

    async def slow_writer(_call: WorkspaceCall) -> None:
        entered.append("writing")
        try:
            await release.wait()  # a peer that drains slowly, or a long result ahead on the line
            finished.append("written")
        except asyncio.CancelledError:
            finished.append("cut off")
            raise

    channel = await hub.register(
        handle=_HANDLE,
        declaration=_declaration(),
        service_instance_id=_INSTANCE,
        service_generation="7",
        writer=slow_writer,
    )
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=0.1)
    assert caught.value.reason == "deadline_exceeded"
    assert channel.pending_count == 0
    # Cancelling the waiting caller does not cut the write either.
    pending = asyncio.create_task(
        hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=5.0)
    )
    await _until(lambda: len(entered) == 2)  # its frame is being written
    pending.cancel()
    await asyncio.gather(pending, return_exceptions=True)
    assert finished == []
    release.set()
    await _until(lambda: len(finished) == 2)
    assert finished == ["written", "written"]


async def test_an_agent_whose_authorization_lapsed_mid_task_leaves_the_typed_gap(
    tmp_path: object,
) -> None:
    """ADR-052: an agent whose own connection's authorization lapses (its repository held, the
    selection moved) answers ``workspace_unavailable`` between the connection's checks; the hub
    types that loss, and a check that needed the read records the existing
    ``workspace_agent_unavailable`` gap every receipt format names (no new receipt field)."""

    import os
    import subprocess
    from pathlib import Path

    from finishup.application import check_change
    from finishup.client.workspace_agent import WorkspaceAgentHandler
    from finishup.domain.receipts import (
        check_time_change_gap_sentence,
        check_time_change_unavailable_reason_gap,
    )
    from finishup.ports.control import WorkspaceLocator

    root = Path(str(tmp_path)) / "project"
    root.mkdir()
    subprocess.run(
        ("git", "init", "--quiet"),
        cwd=root,
        check=True,
        env={"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1", "HOME": os.fspath(root)},
    )

    class _Authorization:
        def __init__(self) -> None:
            self.phase: str | None = None

        def refusal(self) -> str | None:
            return self.phase

    authorization = _Authorization()
    agent = WorkspaceAgentHandler(
        WorkspaceLocator(os.fspath(root.resolve())),
        protected=(os.fspath(Path(str(tmp_path)) / "state"),),
        own_authorization=authorization,
    )
    hub = _hub()
    await _register(
        hub,
        lambda call: agent.answer(call, workspace_handle=_HANDLE),
        declaration=agent.declaration,
    )
    # Before the lapse the agent answers from the workspace.
    await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=5.0)

    authorization.phase = "repository_egress_held"
    with pytest.raises(WorkspaceAgentUnavailable) as lapsed:
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=5.0)
    assert (lapsed.value.reason, lapsed.value.agent_reason) == (
        "agent_unavailable",
        "workspace_unavailable",
    )
    reason = check_change._agent_loss_reason(lapsed.value)  # pyright: ignore[reportPrivateUsage]
    assert reason == "workspace_agent_unavailable"
    sentence = check_time_change_gap_sentence(check_time_change_unavailable_reason_gap(reason))
    assert sentence is not None and "workspace agent on the client machine" in sentence
    assert os.fspath(root) not in sentence


# --- ADR-052: a connection's agent and the helper's background agent never compete -------------


def _background(*operations: str) -> WorkspaceAgentDeclaration:
    names = operations or WORKSPACE_OPERATION_NAMES
    return WorkspaceAgentDeclaration(
        tuple(sorted(names, key=str.encode)), 6_291_456, role="background"
    )


async def test_background_work_goes_to_the_helpers_agent_over_a_newer_connection() -> None:
    hub = _hub()
    helper: list[WorkspaceCall] = []
    connection: list[WorkspaceCall] = []
    await _register(hub, lambda call: _ok(call, _BASE), sent=helper, declaration=_background())
    await _register(hub, lambda call: _ok(call, _BASE), sent=connection)

    await hub.call(
        _HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=2.0, background=True
    )

    assert (len(helper), len(connection)) == (1, 0)


async def test_a_live_call_goes_to_its_own_connections_agent_never_the_helpers() -> None:
    hub = _hub()
    helper: list[WorkspaceCall] = []
    own: list[WorkspaceCall] = []
    await _register(hub, lambda call: _ok(call, _BASE), sent=helper, declaration=_background())
    channel = await _register(hub, lambda call: _ok(call, _BASE), sent=own)

    with live_call_scope(channel):
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=2.0)

    assert (len(helper), len(own)) == (0, 1)


async def test_a_live_call_whose_connection_offered_no_agent_goes_to_the_helper() -> None:
    hub = _hub()
    helper: list[WorkspaceCall] = []
    other: list[WorkspaceCall] = []
    await _register(hub, lambda call: _ok(call, _BASE), sent=helper, declaration=_background())
    await _register(hub, lambda call: _ok(call, _BASE), sent=other)

    with live_call_scope(None):
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=2.0)

    assert (len(helper), len(other)) == (1, 0)


async def test_with_no_helper_background_work_is_answered_by_a_connection_as_before() -> None:
    hub = _hub()
    connection: list[WorkspaceCall] = []
    await _register(hub, lambda call: _ok(call, _BASE), sent=connection)

    base = await hub.call(
        _HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=2.0, background=True
    )

    assert base == _BASE and len(connection) == 1


async def test_a_helper_that_does_not_declare_the_operation_leaves_it_to_a_connection() -> None:
    hub = _hub()
    helper: list[WorkspaceCall] = []
    connection: list[WorkspaceCall] = []
    await _register(
        hub, lambda call: _ok(call, _BASE), sent=helper, declaration=_background("capture")
    )
    await _register(hub, lambda call: _ok(call, _BASE), sent=connection)

    await hub.call(
        _HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=2.0, background=True
    )

    assert (len(helper), len(connection)) == (0, 1)


# --- ADR-054: only the helper syncs; a call waits (bounded) for the helper's agent --------------

_COPY_OPERATIONS = frozenset({"code_sync_prepare", "code_sync_read"})
_READ = CodeSyncReadArguments(_HANDLE, "0" * 32, 0, 4)


def _connection_agent() -> WorkspaceAgentDeclaration:
    return _declaration(
        *(name for name in WORKSPACE_OPERATION_NAMES if name not in _COPY_OPERATIONS)
    )


async def test_a_sync_waits_for_the_helpers_agent_while_only_the_connection_is_up() -> None:
    hub = _hub(wait=5.0)
    own: list[WorkspaceCall] = []
    helper: list[WorkspaceCall] = []
    await _register(hub, lambda call: _ok(call, _BASE), sent=own, declaration=_connection_agent())
    pending = asyncio.create_task(
        hub.call(_HANDLE, WorkspaceOperation.CODE_SYNC_READ, _READ, timeout_seconds=2.0)
    )
    for _ in range(8):  # let the call reach its wait (a refusal would finish it here)
        await asyncio.sleep(0)
    assert not pending.done()  # waiting for the helper's agent, not refused
    await _register(hub, lambda call: _ok(call, b"abcd"), sent=helper, declaration=_background())

    assert await asyncio.wait_for(pending, 5.0) == b"abcd"
    assert (len(own), len(helper)) == (0, 1)


async def test_a_helper_agent_that_does_not_declare_the_sync_is_refused_at_once() -> None:
    hub = _hub(wait=5.0)
    await _register(hub, lambda call: _ok(call, _BASE), declaration=_connection_agent())
    level_l1_helper = _background(
        *(name for name in WORKSPACE_OPERATION_NAMES if name not in _COPY_OPERATIONS)
    )
    await _register(hub, lambda call: _ok(call, _BASE), declaration=level_l1_helper)
    loop = asyncio.get_running_loop()
    began = loop.time()
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await hub.call(_HANDLE, WorkspaceOperation.CODE_SYNC_READ, _READ, timeout_seconds=2.0)
    assert caught.value.reason == "operation_not_declared"
    assert loop.time() - began < 2.0


async def test_a_helper_that_never_comes_is_not_declared_and_no_client_is_offline() -> None:
    hub = _hub(wait=0.2)
    channel = await _register(hub, lambda call: _ok(call, _BASE), declaration=_connection_agent())
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await hub.call(_HANDLE, WorkspaceOperation.CODE_SYNC_READ, _READ, timeout_seconds=2.0)
    assert caught.value.reason == "operation_not_declared"
    await hub.unregister(channel)
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await hub.call(_HANDLE, WorkspaceOperation.CODE_SYNC_READ, _READ, timeout_seconds=2.0)
    assert caught.value.reason == "no_agent"
    # Every other operation keeps its exact answer: refused at once, never waited for.
    await _register(hub, lambda call: _ok(call, _BASE), declaration=_declaration("capture"))
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
    assert caught.value.reason == "operation_not_declared"


# --- u5: a newer helper agent takes over a call an older one left unanswered -------------------


async def test_a_call_left_on_a_silent_helper_agent_goes_on_at_a_newer_one() -> None:
    """A helper stopped without unregistering its agent (the edge keeps it until its lease ends):
    the call goes on at the replacement's agent once it registers, with the time it has left,
    not after the whole deadline. The older channel stays open; its late answer is dropped."""

    hub = _hub()
    stale: list[WorkspaceCall] = []
    fresh: list[WorkspaceCall] = []
    older = await _register(hub, lambda _call: None, sent=stale, declaration=_background())
    pending = asyncio.create_task(
        hub.call(
            _HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=60.0, background=True
        )
    )
    await _until(lambda: older.pending_count > 0)
    await asyncio.sleep(0.2)  # the replacement registers some time into the call
    await _register(hub, lambda call: _ok(call, _BASE), sent=fresh, declaration=_background())

    assert await asyncio.wait_for(pending, 2.0) == _BASE
    assert [call.operation for call in fresh] == ["read_task_base"]
    assert fresh[0].deadline_ms <= stale[0].deadline_ms - 150  # the deadline is unchanged
    assert older.pending_count == 0 and not older.closed
    hub.deliver(older, _ok(stale[0], _BASE))  # its late answer is unmatched, and dropped


async def test_an_approved_check_is_never_sent_to_a_newer_helper_agent() -> None:
    hub = _hub()
    fresh: list[WorkspaceCall] = []
    older = await _register(hub, lambda _call: None, declaration=_background())
    arguments = RunApprovedCheckArguments(
        "rws_" + "0" * 32,
        ApprovedCheckApproval(
            approval_id="unit",
            argv=("/usr/bin/true",),
            allow_network=False,
            timeout_seconds=10.0,
            approval_commitment=approval_commitment(
                "unit", ("/usr/bin/true",), allow_network=False
            ),
        ),
        "sha256:" + "4" * 64,
        None,
    )
    pending = asyncio.create_task(
        hub.call(
            _HANDLE,
            WorkspaceOperation.RUN_APPROVED_CHECK,
            arguments,
            timeout_seconds=0.3,
            background=True,
        )
    )
    await _until(lambda: older.pending_count > 0)
    await _register(hub, lambda call: _ok(call, None), sent=fresh, declaration=_background())
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await asyncio.wait_for(pending, 5.0)
    assert caught.value.reason == "deadline_exceeded"
    assert fresh == []


async def test_only_a_newer_helper_agent_declaring_the_operation_takes_a_call_over() -> None:
    """A connection's agent never competes with the helper's (ADR-052 decision 12), and a helper
    agent that does not declare the operation cannot answer it."""

    hub = _hub()
    others: list[WorkspaceCall] = []
    older = await _register(hub, lambda _call: None, declaration=_background())
    pending = asyncio.create_task(
        hub.call(
            _HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=0.3, background=True
        )
    )
    await _until(lambda: older.pending_count > 0)
    await _register(hub, lambda call: _ok(call, _BASE), sent=others)
    await _register(
        hub, lambda call: _ok(call, _BASE), sent=others, declaration=_background("capture")
    )
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await asyncio.wait_for(pending, 5.0)
    assert caught.value.reason == "deadline_exceeded"
    assert others == []


async def test_a_code_sync_read_is_never_taken_over_by_a_newer_helper_agent() -> None:
    """ADR-054: a read names a snapshot only the agent that prepared it holds; a prepare is taken
    over (``test_code_copy``), a read waits out its own deadline on the agent asked."""

    hub = _hub()
    fresh: list[WorkspaceCall] = []
    older = await _register(hub, lambda _call: None, declaration=_background())
    pending = asyncio.create_task(
        hub.call(_HANDLE, WorkspaceOperation.CODE_SYNC_READ, _READ, timeout_seconds=0.3)
    )
    await _until(lambda: older.pending_count > 0)
    await _register(hub, lambda call: _ok(call, b"abcd"), sent=fresh, declaration=_background())
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await asyncio.wait_for(pending, 5.0)
    assert caught.value.reason == "deadline_exceeded"
    assert fresh == []
