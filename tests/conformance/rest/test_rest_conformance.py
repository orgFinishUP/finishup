"""The REST v1 server conformance kit (ADR-053, design v2 section 6; U9, U18).

Black-box HTTP against a server (``conftest.rest_target``: any URL with a test key, or this
checkout's gateway and native edges over real TLS). It proves what a client of this release relies
on: discovery that is minimal and needs no key; the order of refusals; the caller's key in the
profile; a session and every call bound to the consented revision, refused before any work when
stale; the API manifest a server serves; scopes as control-result refusals; idempotent operation
ids; agents' lifecycle; bounded bodies; no redirects; ``no-store``. And, for every REST API
manifest the server advertises, the frozen request/response vectors of that manifest
(``fixtures/service/rest-api-manifests.case.json``): the cross-version conformance of U18.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any, cast

import pytest

from builders.rest_kit import RestTarget
from finishup.client.rest_client import RestAnswer, RestTransport
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.schemas import validate_schema_instance
from finishup.protocol.server_profile import ServerProfileRevision, profile_from_json
from finishup.rest.contract import (
    HEADER_API_MANIFEST,
    HEADER_CLAIM,
    HEADER_OPERATION_ID,
    HEADER_SERVER_PROFILE,
    HEADER_SERVICE_GENERATION,
    HEADER_SERVICE_INSTANCE,
    current_api_manifest,
    encode_revision_header,
    parse_discovery,
    parse_session,
)

pytestmark = pytest.mark.anyio

_REPO = Path(__file__).resolve().parents[3]
_VECTORS = json.loads((_REPO / "fixtures" / "service" / "rest-api-manifests.case.json").read_text())
_CLAIM = "git_common_root:sha256:" + "a" * 64 + ":sha256:" + "b" * 64


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
async def http(rest_target: RestTarget) -> AsyncIterator[RestTransport]:
    transport = RestTransport(
        rest_target.url,
        key=None,
        ca_file=rest_target.ca_file,
        tls_pin=rest_target.tls_pin,
    )
    try:
        yield transport
    finally:
        await transport.aclose()


def _auth(key: str, **extra: str) -> dict[str, str]:
    return {"authorization": f"Bearer {key}", HEADER_API_MANIFEST: current_api_manifest(), **extra}


async def _revision(http: RestTransport, key: str) -> ServerProfileRevision:
    answer = await http.request("GET", "/v1/server", headers=_auth(key))
    assert answer.status == 200, answer.body
    return profile_from_json(answer.body).revision


def _reason(answer: RestAnswer) -> str:
    return cast(str, json.loads(answer.body)["reason"])


async def test_discovery_is_minimal_needs_no_key_and_serves_this_manifest(
    http: RestTransport,
) -> None:
    answer = await http.request("GET", "/.well-known/finishup")
    assert answer.status == 200
    document = json.loads(answer.body)
    validate_schema_instance("rest-discovery", "1.0.0", document)
    discovery = parse_discovery(answer.body)
    assert "1" in discovery.rest_majors and "api_key" in discovery.auth
    assert discovery.profile_endpoint == "/v1/server"
    assert current_api_manifest() in discovery.api_manifests
    assert not {"release", "service_instance_id", "key"} & set(document)


async def test_refusals_come_in_order_before_any_work(
    http: RestTransport, rest_target: RestTarget
) -> None:
    origin = await http.request(
        "GET", "/v1/server", headers={**_auth(rest_target.operator_key), "origin": "https://x.test"}
    )
    assert (origin.status, _reason(origin)) == (403, "origin_forbidden")
    no_key = await http.request("GET", "/v1/server")
    assert (no_key.status, _reason(no_key)) == (401, "api_key_invalid")
    wrong = await http.request("GET", "/v1/server", headers=_auth("fuk_000000000000_" + "A" * 43))
    assert (wrong.status, _reason(wrong)) == (401, "api_key_invalid")
    other_manifest = await http.request(
        "GET",
        "/v1/session",
        headers=_auth(rest_target.operator_key, **{HEADER_API_MANIFEST: "sha256:" + "0" * 64}),
    )
    assert (other_manifest.status, _reason(other_manifest)) == (412, "api_manifest_unsupported")


async def test_the_profile_names_the_callers_key(
    http: RestTransport, rest_target: RestTarget
) -> None:
    answer = await http.request("GET", "/v1/server", headers=_auth(rest_target.operator_key))
    assert answer.status == 200
    assert answer.headers.get("cache-control", "no-store") == "no-store"
    validate_schema_instance("server-profile", "1.0.0", json.loads(answer.body))
    profile = profile_from_json(answer.body)
    assert profile.key.scope == "operator"
    assert profile.key.id == rest_target.operator_key.split("_")[1]
    assert profile.key.principal.startswith("p_")
    assert "rest-1" in profile.edges


async def test_a_session_and_a_call_are_bound_to_the_consented_revision(
    http: RestTransport, rest_target: RestTarget
) -> None:
    revision = await _revision(http, rest_target.operator_key)
    stale = ServerProfileRevision(revision.issuer, revision.revision + 1, "sha256:" + "c" * 64)
    refused = await http.request(
        "GET",
        "/v1/session",
        headers=_auth(
            rest_target.operator_key, **{HEADER_SERVER_PROFILE: encode_revision_header(stale)}
        ),
    )
    assert (refused.status, _reason(refused)) == (409, "server_profile_changed")
    current = _auth(
        rest_target.operator_key, **{HEADER_SERVER_PROFILE: encode_revision_header(revision)}
    )
    answer = await http.request("GET", "/v1/session", headers={**current, HEADER_CLAIM: _CLAIM})
    assert answer.status == 200, answer.body
    validate_schema_instance("rest-session", "1.0.0", json.loads(answer.body))
    session = parse_session(answer.body)
    assert session.workspace_binding == "client_claim" and session.server_profile == revision
    addressed = {
        HEADER_SERVICE_INSTANCE: session.status.service_instance_id,
        HEADER_SERVICE_GENERATION: session.status.service_generation,
    }
    call = await http.request(
        "POST", "/v1/service_status", headers={**current, **addressed}, content=b"{}"
    )
    assert call.status == 200 and call.headers["finishup-outcome"] == "ok"
    stale_call = await http.request(
        "POST",
        "/v1/service_status",
        headers={
            **_auth(
                rest_target.operator_key,
                **{HEADER_SERVER_PROFILE: encode_revision_header(stale)},
            ),
            **addressed,
        },
        content=b"{}",
    )
    assert stale_call.status == 409


async def test_an_operation_id_is_answered_at_most_once(
    http: RestTransport, rest_target: RestTarget
) -> None:
    revision = await _revision(http, rest_target.operator_key)
    current = _auth(
        rest_target.operator_key, **{HEADER_SERVER_PROFILE: encode_revision_header(revision)}
    )
    session = parse_session((await http.request("GET", "/v1/session", headers=current)).body)
    operation = new_id(IdKind.CONTROL_RPC)
    headers = {
        **current,
        HEADER_SERVICE_INSTANCE: session.status.service_instance_id,
        HEADER_SERVICE_GENERATION: session.status.service_generation,
        HEADER_OPERATION_ID: operation,
    }
    first = await http.request("POST", "/v1/service_status", headers=headers, content=b"{}")
    second = await http.request("POST", "/v1/service_status", headers=headers, content=b"{}")
    assert first.status == second.status == 200
    assert first.body == second.body
    polled = await http.request("GET", f"/v1/operations/{operation}", headers=current)
    assert polled.status == 200 and polled.body == first.body
    unknown = await http.request(
        "GET", f"/v1/operations/{new_id(IdKind.CONTROL_RPC)}", headers=current
    )
    assert (unknown.status, _reason(unknown)) == (404, "operation_unknown")


async def test_a_keys_scope_bounds_its_methods(
    http: RestTransport, rest_target: RestTarget
) -> None:
    if rest_target.agent_key is None:
        pytest.skip("no agent key given (FINISHUP_REST_AGENT_KEY)")
    revision = await _revision(http, rest_target.agent_key)
    current = _auth(
        rest_target.agent_key, **{HEADER_SERVER_PROFILE: encode_revision_header(revision)}
    )
    session = parse_session((await http.request("GET", "/v1/session", headers=current)).body)
    answer = await http.request(
        "POST",
        "/v1/review",
        headers={
            **current,
            HEADER_SERVICE_INSTANCE: session.status.service_instance_id,
            HEADER_SERVICE_GENERATION: session.status.service_generation,
        },
        content=b"{}",
    )
    assert answer.status == 200 and answer.headers["finishup-outcome"] == "error"
    assert json.loads(answer.body)["code"] == "method_forbidden"


async def test_an_agent_registers_for_a_keyed_claim_polls_and_ends(
    http: RestTransport, rest_target: RestTarget
) -> None:
    revision = await _revision(http, rest_target.operator_key)
    current = _auth(
        rest_target.operator_key, **{HEADER_SERVER_PROFILE: encode_revision_header(revision)}
    )
    declaration = json.dumps(
        {
            "max_reply_bytes": 1_048_576,
            "operations": ["capture_metadata", "inspect"],
            "role": "background",
            "schema_version": "1.0.0",
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    created = await http.request(
        "POST", "/v1/agents", headers={**current, HEADER_CLAIM: _CLAIM}, content=declaration
    )
    assert created.status == 201, created.body
    registration = json.loads(created.body)
    validate_schema_instance("rest-agent", "1.0.0", registration)
    work = await http.request(
        "GET",
        f"/v1/agents/{registration['agent_id']}/work",
        headers=current,
        params={"wait_ms": "0"},
    )
    assert work.status == 200
    validate_schema_instance("rest-agent-work", "1.0.0", json.loads(work.body))
    ended = await http.request(
        "DELETE", f"/v1/agents/{registration['agent_id']}", headers=_auth(rest_target.operator_key)
    )
    assert ended.status == 204
    gone = await http.request(
        "GET",
        f"/v1/agents/{registration['agent_id']}/work",
        headers=current,
        params={"wait_ms": "0"},
    )
    assert (gone.status, _reason(gone)) == (404, "agent_unknown")


async def test_an_oversized_body_is_refused(http: RestTransport, rest_target: RestTarget) -> None:
    revision = await _revision(http, rest_target.operator_key)
    current = _auth(
        rest_target.operator_key, **{HEADER_SERVER_PROFILE: encode_revision_header(revision)}
    )
    answer = await http.request(
        "POST",
        "/v1/agents",
        headers={**current, HEADER_CLAIM: _CLAIM},
        content=b"{" + b" " * 70_000 + b"}",
    )
    assert (answer.status, _reason(answer)) == (413, "frame_too_large")


def _headers_for(
    request: Mapping[str, Any],
    target: RestTarget,
    revision: ServerProfileRevision,
    manifest: str,
) -> dict[str, str]:
    headers: dict[str, str] = {}
    auth = request.get("auth", "none")
    if auth == "operator":
        headers["authorization"] = f"Bearer {target.operator_key}"
    elif auth == "wrong":
        headers["authorization"] = "Bearer fuk_000000000000_" + "A" * 43
    if auth != "none":
        headers[HEADER_API_MANIFEST] = cast(str, request.get("api_manifest", manifest))
    if request.get("origin"):
        headers["origin"] = "https://elsewhere.test"
    which = request.get("revision")
    if which == "current":
        headers[HEADER_SERVER_PROFILE] = encode_revision_header(revision)
    elif which == "stale":
        headers[HEADER_SERVER_PROFILE] = encode_revision_header(
            ServerProfileRevision(revision.issuer, revision.revision + 1, "sha256:" + "c" * 64)
        )
    return headers


async def test_the_frozen_vectors_of_every_advertised_api_manifest(
    http: RestTransport, rest_target: RestTarget
) -> None:
    """U18: a server serving a window of client releases passes each one's frozen vectors."""

    discovery = parse_discovery((await http.request("GET", "/.well-known/finishup")).body)
    revision = await _revision(http, rest_target.operator_key)
    session = parse_session(
        (
            await http.request(
                "GET",
                "/v1/session",
                headers=_auth(
                    rest_target.operator_key,
                    **{HEADER_SERVER_PROFILE: encode_revision_header(revision)},
                ),
            )
        ).body
    )
    versions = {version["api_manifest"]: version for version in _VECTORS["versions"]}
    for manifest in discovery.api_manifests:
        assert manifest in versions, "an advertised API manifest without frozen vectors"
        for vector in versions[manifest]["vectors"]:
            request = vector["request"]
            headers = _headers_for(request, rest_target, revision, manifest)
            if (
                request["method"] == "POST"
                and request["path"].startswith("/v1/")
                and (request["path"] != "/v1/agents")
            ):
                headers[HEADER_SERVICE_INSTANCE] = session.status.service_instance_id
                headers[HEADER_SERVICE_GENERATION] = session.status.service_generation
            body = (
                None
                if "body" not in request
                else json.dumps(request["body"], separators=(",", ":"), sort_keys=True).encode()
            )
            answer = await http.request(
                request["method"], request["path"], headers=headers, content=body
            )
            expected = vector["response"]
            assert answer.status == expected["status"], (vector["name"], answer.body)
            document = json.loads(answer.body) if answer.body else None
            if expected["schema"] in {
                "rest-error",
                "rest-discovery",
                "rest-session",
                "server-profile",
            }:
                validate_schema_instance(expected["schema"], "1.0.0", document)
            if "reason" in expected:
                assert cast(dict[str, Any], document)["reason"] == expected["reason"], vector[
                    "name"
                ]
            if "outcome" in expected:
                assert answer.headers["finishup-outcome"] == expected["outcome"], vector["name"]
