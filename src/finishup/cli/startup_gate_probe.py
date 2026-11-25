"""Bounded read-only service probe, isolated from the host-critical hook process."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from typing import Final

from finishup.protocol.canonical import JsonValue

# The bound on the probe's connection and the task's status (design v2 section 8.9); its imports
# and the build of its status models (``build_status_models``) come before it. ``server test``
# compares a new process's connection and status with it.
STARTUP_GATE_SECONDS: Final = 0.65


def build_status_models() -> None:
    """Finish building the models one compact status exchange builds on first use.

    The protocol models build on first use (``protocol.deferred_build``), and this process is new
    for every gate decision. Left to first use, four builds would run while the bound is open:
    the request's when it is validated, the result's when the reply is decoded, the compact
    page's when the status view routes the page to it, and the success model's when its
    validator serializes it to check it against the schema. Building them first keeps the bound
    for the connection and the status, as it was when importing the models built them all.
    Every other model the exchange touches validates inside one of these four. A reply that is
    not a successful compact page is not ready whether or not the bound holds, so nothing is
    built for it, and building every model would cost this process most of what deferring them
    saved.
    """

    from finishup.protocol.deferred_build import ensure_built
    from finishup.protocol.models import (
        StatusCompactPageModel,
        StatusRequest,
        StatusResult,
        StatusSuccessModel,
    )

    # Definition order, as an import-time build ran: a model is complete before one that holds it.
    for model in (StatusRequest, StatusCompactPageModel, StatusSuccessModel, StatusResult):
        ensure_built(model)


async def probe(request: Mapping[str, JsonValue]) -> bool:
    import anyio

    from finishup import __version__
    from finishup.ports.control import ControlClientKind, WorkspaceLocator
    from finishup.protocol.ids import IdKind, new_id
    from finishup.protocol.models import StatusCompactPageModel, StatusRequest, StatusSuccessModel
    from finishup.service.client import connect_service

    route, workspace = request.get("route"), request.get("workspace")
    if not isinstance(route, list) or len(route) != 3 or not isinstance(workspace, str):
        return False
    build_status_models()
    client = None
    try:
        with anyio.fail_after(STARTUP_GATE_SECONDS):
            client = await connect_service(
                ControlClientKind.CLI, workspace_locator=WorkspaceLocator(workspace)
            )
            response = await client.status(
                StatusRequest.model_validate(
                    {
                        "protocol_version": "0.1",
                        "schema_version": "1.0.0",
                        "request_id": new_id(IdKind.REQUEST),
                        # Frozen legacy identifier (ADR-048): a recorded actor id existing
                        # ledgers carry.
                        "actor": {"actor_id": "yoetz:startup-gate", "actor_type": "harness"},
                        "client": {
                            # Frozen legacy identifier (ADR-048): the released client-kind
                            # wire value.
                            "kind": "yoetz_cli",
                            "version": __version__,
                            "integration": "local_cli",
                        },
                        "session_id": route[1],
                        "writer_id": route[2],
                        "view": "compact",
                        "limit": "1",
                    }
                ),
                deadline_ms=500,
            )
            result = response.root
            if not isinstance(result, StatusSuccessModel) or not isinstance(
                result.page, StatusCompactPageModel
            ):
                return False
            if (
                [result.task_id, result.session_id, result.writer_id] != route
                or result.rebuild_state != "current"
                or result.projection_lag != "0"
                or len(result.page.items) != 1
            ):
                return False
            item = result.page.items[0]
            return (
                item.current_plan_event_id == request.get("plan_id")
                and item.declared_obligation_count == str(request.get("obligation_count"))
                and item.declared_obligation_count not in {None, "0"}
                and item.open_obligation_count is not None
            )
    finally:
        if client is not None:
            with anyio.move_on_after(0.05, shield=True):
                await client.close()


def main() -> None:
    ready = False
    try:
        raw = sys.stdin.buffer.read(16_385)
        if len(raw) <= 16_384:
            request: JsonValue = json.loads(raw)
            if isinstance(request, dict):
                import anyio

                ready = anyio.run(probe, request)
    except Exception:
        pass
    # No exception text, task prose, identities, or workspace leaves the probe.
    print(json.dumps({"ready": ready}))


if __name__ == "__main__":
    main()
