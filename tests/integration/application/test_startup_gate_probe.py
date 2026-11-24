"""Gate reads the real projected status contract, without inferring capture or closure."""

from __future__ import annotations

from typing import cast

import pytest

from builders.projection_workflow import ProjectionCase, project_case, run_projection_workflow
from builders.scripted_service_client import result_frame, run_in_new_process
from finishup.cli.startup_gate_probe import STARTUP_GATE_SECONDS, probe
from finishup.ports.control import ControlClientKind, ControlMethod, WorkspaceLocator
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import (
    StatusCompactPageModel,
    StatusRequest,
    StatusResult,
    StatusSuccessModel,
)


@pytest.mark.anyio
async def test_probe_requires_live_exact_plan_route_and_readable_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow = await run_projection_workflow()
    compact = await project_case(workflow.app, workflow.case("status/compact"), 8000)
    model = StatusResult.model_validate(compact).root
    assert isinstance(model, StatusSuccessModel)
    assert isinstance(model.page, StatusCompactPageModel)
    item = model.page.items[0]
    assert item.current_plan_event_id is not None
    assert item.declared_obligation_count is not None
    seen: list[StatusRequest] = []

    class Client:
        async def status(self, request: StatusRequest, *, deadline_ms: int) -> StatusResult:
            assert deadline_ms == 500
            seen.append(request)
            internal = await workflow.app.status(request)
            case = ProjectionCase(
                "gate",
                ControlMethod.STATUS,
                cast(dict[str, JsonValue], request.model_dump(mode="json")),
                internal,
            )
            projected = await project_case(workflow.app, case, 8100 + len(seen) * 2)
            return StatusResult.model_validate(projected)

        async def close(self) -> None:
            pass

    async def connect(kind: ControlClientKind, *, workspace_locator: WorkspaceLocator) -> Client:
        assert kind is ControlClientKind.CLI
        assert workspace_locator.path == "/project"
        return Client()

    monkeypatch.setattr("finishup.service.client.connect_service", connect)
    request: dict[str, JsonValue] = {
        "route": [model.task_id, model.session_id, model.writer_id],
        "workspace": "/project",
        "plan_id": item.current_plan_event_id,
        "obligation_count": int(item.declared_obligation_count),
    }
    # This workflow has open obligations/findings: readiness is not completion.
    assert int(item.open_obligation_count or "0") > 0
    assert await probe(request)
    assert not await probe({**request, "plan_id": "evt_11111111-1111-4111-8111-111111111111"})
    assert not await probe({**request, "obligation_count": 0})
    assert not await probe(
        {
            **request,
            "route": [
                "tsk_11111111-1111-4111-8111-111111111111",
                model.session_id,
                model.writer_id,
            ],
        }
    )
    assert all(read.view == "compact" for read in seen)


# One probe in a new process, as the gate runs it, over the scripted client. ``anyio.fail_after``
# is replaced to record which FinishUP models finish building while the probe's bound is open.
# Neither the bound nor the call's deadline can expire here: the test observes what is built
# inside the bound, not how long this machine takes.
_PROBE_IN_A_NEW_PROCESS = r"""
import contextlib, json, sys

import anyio
import pydantic

import finishup.cli.startup_gate_probe as gate_probe

spec = json.loads(sys.stdin.read())
report = {}


def built():
    found, pending = set(), [pydantic.BaseModel]
    while pending:
        model = pending.pop()
        pending.extend(model.__subclasses__())
        if model.__module__.startswith("finishup.") and model.__pydantic_complete__:
            found.add(model.__name__)
    return found


class WithoutDeadline:
    def __init__(self, client):
        self._client = client

    async def status(self, request, *, deadline_ms):
        report["deadline_ms"] = deadline_ms
        return await self._client.status(request)

    async def close(self):
        await self._client.close()


async def connect(kind, *, workspace_locator):
    return WithoutDeadline(scripted_client(kind, spec["reply"]))


fail_after = anyio.fail_after


@contextlib.contextmanager
def recorded_bound(delay, shield=False):
    before = built()
    with fail_after(None, shield) as scope:
        try:
            yield scope
        finally:
            report["bound_seconds"] = delay
            report["built_inside_bound"] = sorted(built() - before)


service_client.connect_service = connect
anyio.fail_after = recorded_bound
report["ready"] = anyio.run(gate_probe.probe, spec["request"])
report["built"] = sorted(built())
print(json.dumps(report))
"""


@pytest.mark.anyio
async def test_a_new_probe_process_builds_no_model_inside_its_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The probe's bound covers its connection and its status, never a model's first-use build.

    The protocol models build on first use, and the probe is a new process for every gate
    decision. A model that finished building while the bound was open would spend, on every
    decision, part of the 650 ms meant for the server's answer; before the models were deferred
    the import built them all, ahead of the bound. The probe still builds only the models its
    own exchange uses: the other operations' results stay unbuilt.
    """

    workflow = await run_projection_workflow()
    compact = await project_case(workflow.app, workflow.case("status/compact"), 8000)
    model = StatusResult.model_validate(compact).root
    assert isinstance(model, StatusSuccessModel)
    assert isinstance(model.page, StatusCompactPageModel)
    item = model.page.items[0]
    assert item.current_plan_event_id is not None
    assert item.declared_obligation_count is not None
    answered: list[StatusResult] = []

    class Client:
        async def status(self, request: StatusRequest, *, deadline_ms: int) -> StatusResult:
            del deadline_ms
            case = ProjectionCase(
                "gate",
                ControlMethod.STATUS,
                cast(dict[str, JsonValue], request.model_dump(mode="json")),
                await workflow.app.status(request),
            )
            projected = await project_case(workflow.app, case, 8300)
            answered.append(StatusResult.model_validate(projected))
            return answered[-1]

        async def close(self) -> None:
            pass

    async def connect(kind: ControlClientKind, *, workspace_locator: WorkspaceLocator) -> Client:
        del kind, workspace_locator
        return Client()

    monkeypatch.setattr("finishup.service.client.connect_service", connect)
    request: dict[str, JsonValue] = {
        "route": [model.task_id, model.session_id, model.writer_id],
        "workspace": "/project",
        "plan_id": item.current_plan_event_id,
        "obligation_count": int(item.declared_obligation_count),
    }
    assert await probe(request)

    # The same request in a new process, answered with the result this probe just read as ready.
    report = run_in_new_process(
        _PROBE_IN_A_NEW_PROCESS,
        {"request": request, "reply": result_frame(ControlMethod.STATUS, answered[0])},
    )
    assert report["ready"] is True
    assert report["bound_seconds"] == STARTUP_GATE_SECONDS
    assert report["deadline_ms"] == 500
    assert report["built_inside_bound"] == []
    built = set(cast(list[str], report["built"]))
    assert {"StatusRequestModel", "StatusResultModel"} <= built
    assert not built & {"StartResultModel", "CheckResultModel", "ReceiptResultModel"}
