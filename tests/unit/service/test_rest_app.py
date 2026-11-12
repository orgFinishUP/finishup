"""The REST v1 routes over a backend (ADR-053, design v2 sections 2.1, 8.2, 8.4 and 8.8).

One application serves both edges. These tests drive it over real HTTP semantics
(``httpx.ASGITransport``) with a scripted backend: the order of refusals (Origin, the
unauthenticated budget, the key, the API manifest, the revision) before any work; discovery that
names no release, instance or key; the caller's key in the profile; claims namespaced by the key's
principal before the backend sees them; scope gaps answered as control results; idempotent
operations, long-polls and cancellation; agents' work, replies, end and loss; no redirect.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

from builders.rest_backend import (
    AGENT_DECLARATION,
    STATUS,
    ScriptedRestBackend,
    asgi_client,
    handle_for,
)
from builders.server_profiles import TEST_REVISION
from finishup.domain.values import freeze_json
from finishup.ports.control import WorkspaceCall, WorkspaceClaim
from finishup.protocol.canonical import JsonValue
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.server_profile import ServerProfileRevision, profile_from_json
from finishup.rest.api_keys import ApiKeyStore
from finishup.rest.app import RestApp, UnauthenticatedBudget
from finishup.rest.contract import (
    agent_declaration_document,
    claim_for_principal,
    current_api_manifest,
    encode_claim_header,
    encode_revision_header,
    parse_agent_registration,
    parse_agent_work,
    parse_discovery,
    parse_operation_pending,
    parse_session,
)
from finishup.service.control_protocol import workspace_reply_frame

pytestmark = pytest.mark.anyio

_CLAIM = WorkspaceClaim(
    identity_kind="git_common_root", digest="sha256:" + "a" * 64, worktree="sha256:" + "b" * 64
)
_STALE = ServerProfileRevision(
    TEST_REVISION.issuer, TEST_REVISION.revision + 1, "sha256:" + "c" * 64
)


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


class _Sink:
    def __init__(self) -> None:
        self.lines: list[dict[str, JsonValue]] = []

    def write(self, record: dict[str, JsonValue]) -> None:
        self.lines.append(record)


@dataclass
class _Edge:
    backend: ScriptedRestBackend
    app: RestApp
    client: httpx.AsyncClient
    keys: ApiKeyStore
    operator: str
    agent: str
    principal: str
    audit: _Sink
    clock: _Clock

    def headers(
        self,
        *,
        key: str | None = None,
        revision: ServerProfileRevision | None = TEST_REVISION,
        claim: WorkspaceClaim | None = None,
        manifest: str | None = None,
        **extra: str,
    ) -> dict[str, str]:
        headers = {
            "authorization": f"Bearer {key or self.operator}",
            "finishup-api-manifest": manifest or current_api_manifest(),
            **extra,
        }
        if revision is not None:
            headers["finishup-server-profile"] = encode_revision_header(revision)
        if claim is not None:
            headers["finishup-workspace-claim"] = encode_claim_header(claim)
        return headers

    def call_headers(self, **arguments: Any) -> dict[str, str]:
        return {
            **self.headers(**arguments),
            "finishup-service-instance": STATUS.service_instance_id,
            "finishup-service-generation": STATUS.service_generation,
        }


@pytest.fixture
def keys_dir() -> Iterator[Path]:
    base = Path.home() / f".yz-rest-app-{os.getpid()}-{id(object())}"
    base.mkdir(mode=0o700)
    try:
        yield base
    finally:
        shutil.rmtree(base, ignore_errors=True)


@pytest.fixture
async def edge(keys_dir: Path) -> AsyncIterator[_Edge]:
    keys = ApiKeyStore(keys_dir / "rest")
    operator_record, operator = keys.create("op", "operator")
    _agent_record, agent = keys.create("ag", "agent")
    backend = ScriptedRestBackend()
    clock = _Clock()
    sink = _Sink()
    app = RestApp(backend, keys, audit=sink, clock=clock, budget=UnauthenticatedBudget(clock))
    async with asgi_client(app.asgi()) as client:
        yield _Edge(
            backend, app, client, keys, operator, agent, operator_record.principal, sink, clock
        )
    await app.aclose()


async def _until(condition: Any, *, seconds: float = 10.0) -> None:
    """Yield to the loop until ``condition()`` holds; fail on the deadline (no sleep infers)."""

    deadline = asyncio.get_running_loop().time() + seconds
    while not condition():
        assert asyncio.get_running_loop().time() < deadline, "condition not reached"
        await asyncio.sleep(0)


def _reason(response: httpx.Response) -> str:
    return cast(str, json.loads(response.content)["reason"])


async def test_discovery_is_minimal_unauthenticated_and_never_a_redirect(edge: _Edge) -> None:
    response = await edge.client.get("/.well-known/finishup")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    discovery = parse_discovery(response.content)
    assert discovery.api_manifests == (current_api_manifest(),)
    assert discovery.profile_endpoint == "/v1/server" and discovery.official is False
    text = response.text
    assert set(json.loads(text)) == {
        "api_manifests",
        "auth",
        "official",
        "product",
        "profile_endpoint",
        "rest_majors",
        "schema_version",
    }
    for absent in ("release", "0.3.0", STATUS.service_instance_id, "fuk_"):
        assert absent not in text
    assert (await edge.client.post("/.well-known/finishup")).status_code == 405
    assert edge.backend.sessions == [] and edge.backend.calls == []
    slash = await edge.client.get("/v1/server/", headers=edge.headers())
    assert slash.status_code == 404 and _reason(slash) == "route_unknown"


async def test_an_origin_header_is_refused_before_the_key_is_even_read(edge: _Edge) -> None:
    for path in ("/.well-known/finishup", "/v1/server", "/v1/session"):
        response = await edge.client.get(
            path, headers={**edge.headers(), "origin": "https://evil.test"}
        )
        assert response.status_code == 403 and _reason(response) == "origin_forbidden"
    assert edge.backend.sessions == []


@pytest.mark.parametrize(
    ("authorization", "reason"),
    [
        (None, "api_key_invalid"),
        ("Bearer fuk_000000000000_" + "A" * 43, "api_key_invalid"),
        ("Basic abc", "api_key_invalid"),
    ],
)
async def test_a_request_without_a_valid_key_is_refused(
    edge: _Edge, authorization: str | None, reason: str
) -> None:
    headers = {} if authorization is None else {"authorization": authorization}
    response = await edge.client.get("/v1/server", headers=headers)
    assert response.status_code == 401 and _reason(response) == reason


async def test_a_revoked_key_fails_its_next_request(edge: _Edge) -> None:
    assert (await edge.client.get("/v1/server", headers=edge.headers())).status_code == 200
    key_id = edge.operator.split("_")[1]
    edge.keys.revoke(key_id)
    response = await edge.client.get("/v1/server", headers=edge.headers())
    assert response.status_code == 401 and _reason(response) == "api_key_revoked"


async def test_unauthenticated_requests_are_bounded_and_audited_once_per_window(
    edge: _Edge,
) -> None:
    answers = [
        (await edge.client.get("/v1/server", headers={"authorization": "Bearer x" * 2}))
        for _ in range(25)
    ]
    statuses = [answer.status_code for answer in answers]
    assert statuses[:20] == [401] * 20
    assert set(statuses[20:]) == {429}
    assert _reason(answers[-1]) == "rate_limited"
    refusals = [line for line in edge.audit.lines if line.get("event") == "rest_refusal"]
    assert [line["reason"] for line in refusals] == ["api_key_invalid", "rate_limited"]
    edge.clock.now += 61.0
    await edge.client.get("/v1/server")
    later = [line for line in edge.audit.lines if line.get("event") == "rest_refusal"]
    assert later[-1]["reason"] == "api_key_invalid" and later[-1]["suppressed"] == 19
    rendered = json.dumps(edge.audit.lines)
    assert (
        "Bearer" not in rendered and "127.0.0.1" not in rendered and edge.operator not in rendered
    )


async def test_the_api_manifest_is_required_and_must_be_one_this_server_serves(
    edge: _Edge,
) -> None:
    headers = edge.headers()
    del headers["finishup-api-manifest"]
    missing = await edge.client.get("/v1/server", headers=headers)
    assert missing.status_code == 400 and _reason(missing) == "header_invalid"
    other = await edge.client.get(
        "/v1/session", headers=edge.headers(manifest="sha256:" + "0" * 64)
    )
    assert other.status_code == 412 and _reason(other) == "api_manifest_unsupported"
    assert edge.backend.sessions == []


async def test_the_profile_names_the_callers_key_and_the_rest_edge(edge: _Edge) -> None:
    response = await edge.client.get("/v1/server", headers=edge.headers(key=edge.agent))
    assert response.status_code == 200
    profile = profile_from_json(response.content)
    assert profile.key.scope == "agent"
    assert profile.key.id == edge.agent.split("_")[1]
    assert profile.key.principal.startswith("p_")
    assert profile.edges == ("rest-1",)
    assert profile.revision == TEST_REVISION


async def test_a_session_needs_the_current_revision_before_anything_is_keyed(
    edge: _Edge,
) -> None:
    missing = await edge.client.get("/v1/session", headers=edge.headers(revision=None))
    assert missing.status_code == 400 and _reason(missing) == "header_invalid"
    stale = await edge.client.get(
        "/v1/session", headers=edge.headers(revision=_STALE, claim=_CLAIM)
    )
    assert stale.status_code == 409 and _reason(stale) == "server_profile_changed"
    assert edge.backend.sessions == []
    current = await edge.client.get("/v1/session", headers=edge.headers(claim=_CLAIM))
    session = parse_session(current.content)
    keyed = claim_for_principal(_CLAIM, edge.principal)
    assert edge.backend.sessions == [(edge.backend.sessions[0][0], keyed)]
    assert session.workspace_handle == handle_for(keyed)
    assert session.server_profile == TEST_REVISION


async def test_a_call_out_of_the_keys_scope_is_answered_method_forbidden_and_never_run(
    edge: _Edge,
) -> None:
    response = await edge.client.post(
        "/v1/review", headers=edge.call_headers(key=edge.agent), content=b"{}"
    )
    assert response.status_code == 200
    assert response.headers["finishup-outcome"] == "error"
    assert json.loads(response.content)["code"] == "method_forbidden"
    assert edge.backend.calls == []


async def test_a_network_call_never_names_a_path(edge: _Edge) -> None:
    unclaimed = await edge.client.post(
        "/v1/start", headers=edge.call_headers(), content=b'{"workspace_ref": null}'
    )
    assert unclaimed.status_code == 403 and _reason(unclaimed) == "workspace_claim_required"
    path = await edge.client.post(
        "/v1/status",
        headers=edge.call_headers(claim=_CLAIM),
        content=json.dumps({"workspace_ref": "/srv/work/project"}).encode(),
    )
    assert path.status_code == 400 and _reason(path) == "frame_invalid"
    assert edge.backend.calls == []


async def test_a_call_answers_the_control_result_body_and_claims_are_namespaced(
    edge: _Edge,
) -> None:
    response = await edge.client.post(
        "/v1/service_status", headers=edge.call_headers(claim=_CLAIM), content=b"{}"
    )
    assert response.status_code == 200
    assert response.headers["finishup-outcome"] == "ok"
    assert response.headers["finishup-service-instance"] == STATUS.service_instance_id
    assert json.loads(response.content)["service_instance_id"] == STATUS.service_instance_id
    ((_call, claim, start_service),) = edge.backend.calls
    assert claim == claim_for_principal(_CLAIM, edge.principal)
    assert start_service is True


async def test_an_operation_is_idempotent_long_polled_and_cancelled_in_order(
    edge: _Edge,
) -> None:
    edge.backend.gate = asyncio.Event()
    operation_id = new_id(IdKind.CONTROL_RPC)
    headers = edge.call_headers(**{"finishup-operation-id": operation_id})
    pending = await edge.client.post(
        "/v1/service_status", params={"wait_ms": "0"}, headers=headers, content=b"{}"
    )
    assert pending.status_code == 202
    assert parse_operation_pending(pending.content) == operation_id
    assert pending.headers["location"] == f"/v1/operations/{operation_id}"
    again = await edge.client.post(
        "/v1/service_status", params={"wait_ms": "0"}, headers=headers, content=b"{}"
    )
    assert again.status_code == 202
    await _until(lambda: edge.backend.calls)
    assert len(edge.backend.calls) == 1
    stale_poll = await edge.client.get(
        f"/v1/operations/{operation_id}",
        params={"wait_ms": "0"},
        headers=edge.headers(revision=_STALE),
    )
    assert stale_poll.status_code == 409
    other_key = await edge.client.get(
        f"/v1/operations/{operation_id}", headers=edge.headers(key=edge.agent)
    )
    assert other_key.status_code == 404 and _reason(other_key) == "operation_unknown"
    cancelled = await edge.client.delete(f"/v1/operations/{operation_id}", headers=edge.headers())
    assert cancelled.status_code == 204
    answered = await edge.client.get(
        f"/v1/operations/{operation_id}", params={"wait_ms": "5000"}, headers=edge.headers()
    )
    assert answered.status_code == 200
    assert json.loads(answered.content)["code"] == "request_cancelled"
    assert edge.backend.cancelled == [operation_id]


async def test_a_long_poll_returns_the_answer_once_the_call_ends(edge: _Edge) -> None:
    edge.backend.gate = asyncio.Event()
    operation_id = new_id(IdKind.CONTROL_RPC)
    await edge.client.post(
        "/v1/service_status",
        params={"wait_ms": "0"},
        headers=edge.call_headers(**{"finishup-operation-id": operation_id}),
        content=b"{}",
    )
    poll = asyncio.create_task(
        edge.client.get(
            f"/v1/operations/{operation_id}", params={"wait_ms": "20000"}, headers=edge.headers()
        )
    )
    await _until(lambda: edge.backend.calls)
    edge.backend.gate.set()
    answered = await asyncio.wait_for(poll, timeout=10)
    assert answered.status_code == 200 and answered.headers["finishup-outcome"] == "ok"


async def test_a_backend_refusal_is_the_requests_rest_error(edge: _Edge) -> None:
    edge.backend.refuse_dispatch = "service_unavailable"
    response = await edge.client.post(
        "/v1/service_status", headers=edge.call_headers(), content=b"{}"
    )
    assert response.status_code == 503 and _reason(response) == "service_unavailable"


async def test_the_pending_operations_of_one_key_are_capped(edge: _Edge) -> None:
    edge.backend.gate = asyncio.Event()
    for _ in range(32):
        response = await edge.client.post(
            "/v1/service_status",
            params={"wait_ms": "0"},
            headers=edge.call_headers(),
            content=b"{}",
        )
        assert response.status_code == 202
    over = await edge.client.post(
        "/v1/service_status", params={"wait_ms": "0"}, headers=edge.call_headers(), content=b"{}"
    )
    assert over.status_code == 429 and _reason(over) == "operation_limit"
    edge.backend.gate.set()


async def test_an_agent_registers_for_its_claim_takes_work_replies_and_ends(
    edge: _Edge,
) -> None:
    body = agent_declaration_document(AGENT_DECLARATION)
    unclaimed = await edge.client.post("/v1/agents", headers=edge.headers(), content=body)
    assert unclaimed.status_code == 403 and _reason(unclaimed) == "workspace_claim_required"
    created = await edge.client.post("/v1/agents", headers=edge.headers(claim=_CLAIM), content=body)
    assert created.status_code == 201
    registration = parse_agent_registration(created.content)
    (recorded,) = edge.backend.agents
    assert recorded.claim == claim_for_principal(_CLAIM, edge.principal)
    call = WorkspaceCall(
        kind="workspace_call",
        protocol_version="1.0",
        call_id=new_id(IdKind.CONTROL_RPC),
        service_instance_id=STATUS.service_instance_id,
        service_generation=STATUS.service_generation,
        operation="inspect",
        arguments=cast(Any, freeze_json({"opaque": True})),
        deadline_ms=5_000,
    )
    poll = asyncio.create_task(
        edge.client.get(
            f"/v1/agents/{registration.agent_id}/work",
            params={"wait_ms": "20000"},
            headers=edge.headers(),
        )
    )
    await asyncio.sleep(0)
    await recorded.writer(call)
    work = parse_agent_work((await asyncio.wait_for(poll, timeout=10)).content, max_bytes=1 << 20)
    assert [frame["call_id"] for frame in work.calls] == [call.call_id]
    other = await edge.client.get(
        f"/v1/agents/{registration.agent_id}/work",
        params={"wait_ms": "0"},
        headers=edge.headers(key=edge.agent),
    )
    assert other.status_code == 404 and _reason(other) == "agent_unknown"
    ended = await edge.client.delete(f"/v1/agents/{registration.agent_id}", headers=edge.headers())
    assert ended.status_code == 204 and recorded.closed


async def test_an_agent_gone_on_the_services_side_answers_agent_unknown(edge: _Edge) -> None:
    created = await edge.client.post(
        "/v1/agents",
        headers=edge.headers(claim=_CLAIM),
        content=agent_declaration_document(AGENT_DECLARATION),
    )
    registration = parse_agent_registration(created.content)
    poll = asyncio.create_task(
        edge.client.get(
            f"/v1/agents/{registration.agent_id}/work",
            params={"wait_ms": "20000"},
            headers=edge.headers(),
        )
    )
    await asyncio.sleep(0)
    edge.backend.agents[0].handle.ended.set()
    gone = await asyncio.wait_for(poll, timeout=10)
    assert gone.status_code == 404 and _reason(gone) == "agent_unknown"
    assert edge.backend.agents[0].closed


async def test_a_reply_reaches_the_backend_and_a_stale_revision_does_not(edge: _Edge) -> None:
    created = await edge.client.post(
        "/v1/agents",
        headers=edge.headers(claim=_CLAIM),
        content=agent_declaration_document(AGENT_DECLARATION),
    )
    registration = parse_agent_registration(created.content)
    from finishup.ports.control import WorkspaceReply

    reply = WorkspaceReply(
        kind="workspace_reply",
        protocol_version="1.0",
        call_id=new_id(IdKind.CONTROL_RPC),
        outcome="refused",
        result=None,
        reason="arguments_invalid",
    )
    body = json.dumps(dict(workspace_reply_frame(reply))).encode()
    stale = await edge.client.post(
        f"/v1/agents/{registration.agent_id}/replies",
        headers=edge.headers(revision=_STALE),
        content=body,
    )
    assert stale.status_code == 409
    sent = await edge.client.post(
        f"/v1/agents/{registration.agent_id}/replies", headers=edge.headers(), content=body
    )
    assert sent.status_code == 202
    assert edge.backend.agents[0].replies == [reply]


async def test_routes_and_methods_are_closed(edge: _Edge) -> None:
    unknown = await edge.client.post(
        "/v1/no_such_method", headers=edge.call_headers(), content=b"{}"
    )
    assert unknown.status_code == 404 and _reason(unknown) == "route_unknown"
    wrong = await edge.client.post("/v1/server", headers=edge.headers(), content=b"{}")
    assert wrong.status_code == 405 and _reason(wrong) == "method_not_allowed"
    nowhere = await edge.client.get("/elsewhere", headers=edge.headers())
    assert nowhere.status_code == 404 and _reason(nowhere) == "route_unknown"


async def test_a_stale_revision_is_refused_before_a_body_is_read_or_a_call_admitted(
    edge: _Edge,
) -> None:
    """A1-1: the backend's revision check runs before the body is read, so a stale call never
    gets a ``202`` (or a 6 MiB read) and is never dispatched."""

    stale_call = await edge.client.post(
        "/v1/service_status",
        params={"wait_ms": "0"},
        headers=edge.call_headers(revision=_STALE),
        content=b"{}",
    )
    assert stale_call.status_code == 409 and _reason(stale_call) == "server_profile_changed"
    oversized = await edge.client.post(
        "/v1/service_status",
        headers=edge.call_headers(revision=_STALE),
        content=b" " * (6_291_456 + 1),
    )
    assert oversized.status_code == 409 and _reason(oversized) == "server_profile_changed"
    stale_agent = await edge.client.post(
        "/v1/agents",
        headers=edge.headers(revision=_STALE, claim=_CLAIM),
        content=b" " * (65_536 + 1),
    )
    assert stale_agent.status_code == 409 and _reason(stale_agent) == "server_profile_changed"
    assert edge.backend.calls == [] and edge.backend.agents == []
    assert edge.backend.admissions == []
    current = await edge.client.post(
        "/v1/service_status", headers=edge.call_headers(), content=b"{}"
    )
    assert current.status_code == 200
    assert edge.backend.admissions == [TEST_REVISION]


async def test_concurrent_registrations_of_one_key_never_pass_the_agent_cap(
    edge: _Edge,
) -> None:
    """A1-2: a registration holds its slot while it waits for the backend; a failed one gives
    it back."""

    edge.backend.register_gate = asyncio.Event()
    body = agent_declaration_document(AGENT_DECLARATION)
    tasks = [
        asyncio.create_task(
            edge.client.post("/v1/agents", headers=edge.headers(claim=_CLAIM), content=body)
        )
        for _ in range(17)
    ]
    await _until(lambda: any(task.done() for task in tasks))
    (refused,) = [task.result() for task in tasks if task.done()]
    assert refused.status_code == 429 and _reason(refused) == "agent_limit"
    edge.backend.register_gate.set()
    answers = await asyncio.wait_for(asyncio.gather(*tasks), timeout=10)
    assert sorted(answer.status_code for answer in answers) == [201] * 16 + [429]
    assert len(edge.backend.agents) == 16
    for answer in answers:
        if answer.status_code == 201:
            agent_id = parse_agent_registration(answer.content).agent_id
            ended = await edge.client.delete(f"/v1/agents/{agent_id}", headers=edge.headers())
            assert ended.status_code == 204
    edge.backend.unkeyed = True
    failed = await edge.client.post("/v1/agents", headers=edge.headers(claim=_CLAIM), content=body)
    assert failed.status_code == 503
    edge.backend.unkeyed = False
    again = await edge.client.post("/v1/agents", headers=edge.headers(claim=_CLAIM), content=body)
    assert again.status_code == 201


async def test_every_unauthenticated_refusal_draws_from_the_budget_whatever_its_reason(
    edge: _Edge,
) -> None:
    """A1-3: duplicate ``authorization`` headers (``header_invalid``) and a discovery request of
    another method (``method_not_allowed``) are charged like a wrong key."""

    duplicated = [
        await edge.client.get(
            "/v1/server", headers=[("authorization", "Bearer a"), ("authorization", "Bearer b")]
        )
        for _ in range(25)
    ]
    assert [answer.status_code for answer in duplicated[:20]] == [400] * 20
    assert {answer.status_code for answer in duplicated[20:]} == {429}
    edge.clock.now += 61.0
    posted = [await edge.client.post("/.well-known/finishup") for _ in range(25)]
    assert [answer.status_code for answer in posted[:20]] == [405] * 20
    assert {answer.status_code for answer in posted[20:]} == {429}
    assert _reason(posted[-1]) == "rate_limited"


async def test_a_call_naming_its_connections_agent_is_sent_to_that_agent(edge: _Edge) -> None:
    """A1-4: the call carries its own agent's registration to the backend; another key's, a
    gone one or one of another claim is ``agent_unknown``."""

    created = await edge.client.post(
        "/v1/agents",
        headers=edge.headers(claim=_CLAIM),
        content=agent_declaration_document(AGENT_DECLARATION),
    )
    registration = parse_agent_registration(created.content)
    (recorded,) = edge.backend.agents
    named = await edge.client.post(
        "/v1/service_status",
        headers=edge.call_headers(claim=_CLAIM, **{"finishup-agent": registration.agent_id}),
        content=b"{}",
    )
    assert named.status_code == 200
    plain = await edge.client.post(
        "/v1/service_status", headers=edge.call_headers(claim=_CLAIM), content=b"{}"
    )
    assert plain.status_code == 200
    assert edge.backend.call_agents == [recorded.handle, None]
    other_claim = WorkspaceClaim(
        identity_kind="git_common_root", digest="sha256:" + "e" * 64, worktree=_CLAIM.worktree
    )
    for headers in (
        edge.call_headers(
            key=edge.agent, claim=_CLAIM, **{"finishup-agent": registration.agent_id}
        ),
        edge.call_headers(claim=other_claim, **{"finishup-agent": registration.agent_id}),
        edge.call_headers(claim=_CLAIM, **{"finishup-agent": "agt_" + "0" * 32}),
    ):
        refused = await edge.client.post("/v1/service_status", headers=headers, content=b"{}")
        assert refused.status_code == 404 and _reason(refused) == "agent_unknown"
    malformed = await edge.client.post(
        "/v1/service_status",
        headers=edge.call_headers(claim=_CLAIM, **{"finishup-agent": "agent-1"}),
        content=b"{}",
    )
    assert malformed.status_code == 400 and _reason(malformed) == "header_invalid"
    await edge.client.delete(f"/v1/agents/{registration.agent_id}", headers=edge.headers())
    gone = await edge.client.post(
        "/v1/service_status",
        headers=edge.call_headers(claim=_CLAIM, **{"finishup-agent": registration.agent_id}),
        content=b"{}",
    )
    assert gone.status_code == 404 and _reason(gone) == "agent_unknown"
    assert len(edge.backend.call_agents) == 2


# --- review fixes, second round -------------------------------------------------------------------


async def test_a_background_agents_registration_never_starts_a_stopped_service(
    keys_dir: Path,
) -> None:
    """Item 8: the registration's revision is admitted before its body without starting the
    service; a stopped one is started only for an agent that is not ``background``, over the
    gateway's own backend (its service stopped: nothing answers its socket)."""

    from finishup.gateway.backend import ControlSocketBackend
    from finishup.rest.contract import agent_declaration_document

    started: list[bool] = []

    async def refuse() -> Any:
        raise OSError("no service answers")

    async def start() -> None:
        started.append(True)
        raise OSError("still nothing answers")

    keys = ApiKeyStore(keys_dir / "rest")
    _record, key = keys.create("helper", "agent")
    app = RestApp(ControlSocketBackend(connect=refuse, start=start), keys)
    headers = {
        "authorization": f"Bearer {key}",
        "finishup-api-manifest": current_api_manifest(),
        "finishup-server-profile": encode_revision_header(TEST_REVISION),
        "finishup-workspace-claim": encode_claim_header(_CLAIM),
    }
    background = replace(AGENT_DECLARATION, role="background")
    try:
        async with asgi_client(app.asgi()) as client:
            refused = await client.post(
                "/v1/agents", headers=headers, content=agent_declaration_document(background)
            )
            assert refused.status_code == 503 and _reason(refused) == "service_unavailable"
            assert started == []
            foreground = await client.post(
                "/v1/agents", headers=headers, content=agent_declaration_document(AGENT_DECLARATION)
            )
            assert foreground.status_code == 503
            assert started == [True]  # a client's agent starts it on demand, as before
    finally:
        await app.aclose()
