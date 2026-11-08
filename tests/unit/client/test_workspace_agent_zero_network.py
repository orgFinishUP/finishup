"""``finishup agent run`` under this computer's zero-network record (ADR-051 decision 8).

The workspace agent is approach C's long-lived client process: it holds a long-poll to the
server, answers its workspace calls, delivers what the hooks captured, and supervises an SSH
target's master. It reads this computer's last reported policy before everything it sends and at
least once a second. On finding zero-network it stops within about a second: the long-poll and
the delivery under way are abandoned, no reply, no last delivery and no deregistration is sent,
and the SSH master it supervises is closed. It never starts under that record, and names
``zero_network_remote_selected`` with the fix 'finishup server use local'.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from builders.network_api import FakeHub, FakeService, claim, context_for, key_store, make_api
from builders.server_targets import ambient_home
from finishup.client import agent as agent_module
from finishup.client import rest_runtime, targets
from finishup.client.agent import (
    WorkspaceAgentLoop,
    agent_pid,
    note_workspace,
    run_workspace_agent,
)
from finishup.client.everyday_policy import record_reported_policy
from finishup.client.targets import ServerTarget
from finishup.domain.values import JsonObject
from finishup.ports.control import (
    WorkspaceAgentDeclaration,
    WorkspaceCall,
    WorkspaceClaim,
    WorkspaceLocator,
    WorkspaceReply,
)
from finishup.ports.workspace_agent import WORKSPACE_OPERATION_NAMES
from finishup.service.network_protocol import claim_principal_digest

_WORKSPACE = WorkspaceLocator("/srv/me/repo")
_ZERO = "zero_network_remote_selected"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def remote(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[ServerTarget, Path]]:
    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, root = targets.new_remote_target("lab", "https", base_url="https://lab.example")
        yield record, root


class _Recording(httpx.AsyncBaseTransport):
    """The API in process, recording every request the agent sends."""

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self._inner = inner
        self.sent: list[str] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.sent.append(f"{request.method} {request.url.path}")
        return await self._inner.handle_async_request(request)


class _Handler:
    """Answers each call once ``release`` is set, from a worker thread."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self.started = threading.Event()

    @property
    def declaration(self) -> WorkspaceAgentDeclaration:
        return WorkspaceAgentDeclaration(
            tuple(sorted(WORKSPACE_OPERATION_NAMES, key=str.encode)), 65_536
        )

    def answer(self, call: WorkspaceCall, *, workspace_handle: str | None) -> WorkspaceReply:
        del workspace_handle
        self.started.set()
        self.release.wait(10)
        return WorkspaceReply(
            kind="workspace_reply",
            protocol_version="1.0",
            call_id=call.call_id,
            outcome="ok",
            result=JsonObject({"answered": call.operation}),
            reason=None,
        )


class _Delivery:
    def __init__(self) -> None:
        self.passes = 0
        self.after_marker = 0
        self.closed = False

    async def deliver(self) -> None:
        self.passes += 1
        if agent_module.zero_network_reported():
            self.after_marker += 1

    async def close(self) -> None:
        self.closed = True


def _serving_loop(
    record: ServerTarget,
    root: Path,
    *,
    handler: _Handler,
    delivery: _Delivery,
    closed: list[tuple[str, Path]],
) -> tuple[WorkspaceAgentLoop, _Recording, FakeHub, WorkspaceClaim, str, Any]:
    keys = key_store(root.parent.parent)
    key, token = keys.create("laptop", "agent")
    hub = FakeHub()
    api = make_api(FakeService(), keys, hub=hub)
    workspace = claim("repo")
    handle = context_for(claim_principal_digest(workspace, key.principal)).workspace_handle
    assert handle is not None
    transport = _Recording(httpx.ASGITransport(app=api.asgi("https")))  # type: ignore[arg-type]
    http = httpx.AsyncClient(transport=transport, base_url="https://lab.example")

    async def claim_for(_record: ServerTarget, _locator: WorkspaceLocator) -> WorkspaceClaim:
        return workspace

    async def close_transport(at_record: ServerTarget, at_root: Path) -> None:
        closed.append((at_record.target_id, at_root))

    def deliver_for(
        _record: ServerTarget, _root: Path, _locator: WorkspaceLocator, _claim: WorkspaceClaim
    ) -> _Delivery:
        return delivery

    loop = WorkspaceAgentLoop(
        root,
        record,
        http=http,
        headers={"authorization": f"Bearer {token}"},
        claim_factory=claim_for,
        handler_factory=lambda _locator, _root: handler,
        delivery_factory=deliver_for,
        transport_closer=close_transport,
        scan_seconds=0.05,
    )
    return loop, transport, hub, workspace, handle, api


async def _until(condition: Any, seconds: float = 10.0) -> None:  # noqa: ANN401
    async with asyncio.timeout(seconds):
        while not condition():
            await asyncio.sleep(0.01)


@pytest.mark.anyio
async def test_the_agent_stops_within_a_second_and_sends_nothing_more(
    remote: tuple[ServerTarget, Path],
) -> None:
    record, root = remote
    note_workspace(root, _WORKSPACE)
    handler = _Handler()
    delivery = _Delivery()
    closed: list[tuple[str, Path]] = []
    loop, transport, hub, _workspace, handle, api = _serving_loop(
        record, root, handler=handler, delivery=delivery, closed=closed
    )
    running = asyncio.create_task(loop.run())
    call = asyncio.ensure_future(hub.call(handle, "capture", {"workspace": handle}))
    try:
        # Registered, delivering, and answering a call the server is waiting on.
        await _until(lambda: handler.started.is_set() and delivery.passes > 0)
        sent_before = list(transport.sent)
        assert "POST /v1/agents" in sent_before
        assert record_reported_policy(zero_network=True)
        started = asyncio.get_running_loop().time()
        assert await asyncio.wait_for(running, 5) == 0
        elapsed = asyncio.get_running_loop().time() - started
    finally:
        handler.release.set()
        call.cancel()
        await asyncio.gather(call, return_exceptions=True)
        await api.close()
    assert elapsed < 1.5
    assert loop.stopped_for == _ZERO
    # Nothing more reached the server: no reply to the call it was answering, no deregistration,
    # no delivery after the record, and no new long-poll.
    after = transport.sent[len(sent_before) :]
    assert not any(sent.endswith("/replies") for sent in after), after
    assert not any(sent.startswith("DELETE") for sent in after), after
    assert not any(sent.startswith("GET /v1/agents/") for sent in after), after
    assert delivery.after_marker == 0
    assert delivery.closed
    # The SSH master it supervises is closed (a no-op for this kind).
    assert closed == [(record.target_id, root)]


@pytest.mark.anyio
async def test_the_agent_starts_nothing_under_the_record(remote: tuple[ServerTarget, Path]) -> None:
    record, root = remote
    note_workspace(root, _WORKSPACE)
    assert record_reported_policy(zero_network=True)
    sent: list[str] = []

    def refuse(request: httpx.Request) -> httpx.Response:
        sent.append(request.url.path)
        raise AssertionError("nothing is sent")

    closed: list[tuple[str, Path]] = []

    async def close_transport(at_record: ServerTarget, at_root: Path) -> None:
        closed.append((at_record.target_id, at_root))

    loop = WorkspaceAgentLoop(
        root,
        record,
        http=httpx.AsyncClient(transport=httpx.MockTransport(refuse), base_url="https://x"),
        headers={},
        transport_closer=close_transport,
        scan_seconds=0.05,
    )
    assert await asyncio.wait_for(loop.run(), 5) == 0
    assert loop.stopped_for == _ZERO
    assert sent == []
    assert closed == [(record.target_id, root)]


def test_agent_run_refuses_to_start_and_names_the_fix(
    remote: tuple[ServerTarget, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    record, root = remote
    assert record_reported_policy(zero_network=True)
    closed: list[str] = []

    async def close_transport(at_record: ServerTarget, _root: Path) -> None:
        closed.append(at_record.target_id)

    def never(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("nothing is opened")

    monkeypatch.setattr(agent_module, "_close_transport", close_transport)
    monkeypatch.setattr(agent_module, "WorkspaceAgentLoop", never)

    assert run_workspace_agent(root) == 2

    err = capsys.readouterr().err
    assert err.startswith(
        f"{_ZERO}: this computer's FinishUP is set to make no network connections, so nothing "
        "was sent to the selected FinishUP server."
    )
    assert "'finishup server use local'" in err
    assert closed == [record.target_id]
    # It never held the agent lock.
    assert agent_pid(root) is None


@pytest.mark.anyio
async def test_an_idle_agent_stays_while_the_ssh_master_it_supervises_runs(
    remote: tuple[ServerTarget, Path],
) -> None:
    record, root = remote
    alive = [True, True, False]
    asked: list[int] = []

    async def master_alive(_record: ServerTarget, _root: Path) -> bool:
        asked.append(1)
        return alive.pop(0)

    loop = WorkspaceAgentLoop(
        root,
        record,
        http=object(),
        headers={},
        transport_alive=master_alive,
        scan_seconds=0.01,
        idle_exit_seconds=0.02,
    )
    assert await asyncio.wait_for(loop.run(), 5) == 0
    # It exits idle only once the master is gone, so the zero-network record could still close
    # it while it ran.
    assert len(asked) == 3 and alive == []
    assert loop.stopped_for is None


@pytest.mark.anyio
async def test_the_ssh_master_closes_through_its_control_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, root = targets.new_remote_target(
                "box", "ssh", user="srv", host="127.0.0.1", port=2222
            )
        ran: list[list[str]] = []

        class _Done:
            returncode = 0
            stdout = b""
            stderr = b""

        def run(argv: list[str], **_options: object) -> object:
            ran.append(argv)
            return _Done()

        monkeypatch.setattr(rest_runtime, "_run", run)
        (root / "run").mkdir(mode=0o700, exist_ok=True)
        # No control socket: nothing runs, and the master reads as gone.
        assert await rest_runtime.ssh_master_alive(record, root) is False
        await rest_runtime.close_ssh_transport(record, root)
        assert ran == []
        (root / "run" / rest_runtime.MASTER_SOCKET_NAME).touch()
        assert await rest_runtime.ssh_master_alive(record, root) is True
        await rest_runtime.close_ssh_transport(record, root)
        assert [argv[argv.index("-O") + 1] for argv in ran] == ["check", "exit"]


def test_no_master_or_remote_start_and_no_probe_under_the_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, root = targets.new_remote_target(
                "box", "ssh", user="srv", host="127.0.0.1", port=2222, remote_launcher="/opt/f"
            )

        def never(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("ssh never runs")

        monkeypatch.setattr(rest_runtime, "_run", never)
        assert record_reported_policy(zero_network=True)
        runtime = rest_runtime.SshTargetRuntime()
        from finishup.client.target_runtime import TargetRuntimeError

        with pytest.raises(TargetRuntimeError) as master:
            runtime.ensure_master(record, root)
        assert master.value.reason == _ZERO
        with pytest.raises(TargetRuntimeError) as started:
            runtime.start_remote_service(record, root)
        assert started.value.reason == _ZERO
        probe = runtime.probe(root)
        assert (probe.outcome, probe.reason) == ("unavailable", _ZERO)
