"""A status read pinned before the task's first record is invalid query input (#1395).

``at_frontier`` admits ``"0"``, but a started task has no state at genesis: the task did not exist
yet. Status answers that with the same typed ``INVALID_REQUEST`` it gives a future frontier, on
every view, instead of an internal failure; the earliest recorded frontier still reads normally.
"""

from __future__ import annotations

import pytest

from builders.projection_workflow import build_projection_application, request_base
from builders.start_application import protocol_id, start_request
from finishup.application.start import StartInternalResult
from finishup.application.status import StatusInternalResult
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import StatusRequest

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.parametrize("view", ["compact", "findings", "history", "obligations"])
async def test_status_at_genesis_on_a_started_task_is_a_typed_refusal(view: str) -> None:
    app, _policy = await build_projection_application(seed=9700)
    started = await app.start(start_request(9701, title="Genesis read", refs=True))
    assert type(started) is StartInternalResult
    base = {
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "view": view,
    }

    with pytest.raises(PublicOperationError) as refused:
        await app.status(
            StatusRequest.model_validate(
                {**request_base(protocol_id("req_", 9702)), **base, "at_frontier": "0"}
            )
        )
    assert refused.value.code is PublicErrorCode.INVALID_REQUEST
    assert refused.value.retryable is False

    earliest = await app.status(
        StatusRequest.model_validate(
            {**request_base(protocol_id("req_", 9703)), **base, "at_frontier": "1"}
        )
    )
    assert type(earliest) is StatusInternalResult
