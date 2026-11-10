"""Closed schema contracts for the REST v1 documents (ADR-053, design v2 U9, section 6).

The generator derives ``schemas/service/rest-*-1.0.0.schema.json`` from these models. Runtime
parsing never imports this module: ``rest.contract`` is the parser, and a conformance test keeps
both agreeing on the golden vectors (``fixtures/service/rest.case.json``). What a schema cannot say
(sorted unique lists, the revision triple's own checks, a handle only beside a claim) the parser
enforces.
"""

import json
from importlib import resources
from typing import Annotated, Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, WithJsonSchema

__all__ = [
    "RestAgentContract",
    "RestAgentDeclarationContract",
    "RestAgentWorkContract",
    "RestDiscoveryContract",
    "RestErrorContract",
    "RestOperationContract",
    "RestSessionContract",
]

type Sha256 = Annotated[str, Field(min_length=71, max_length=71, pattern=r"^sha256:[0-9a-f]{64}$")]
type Handle = Annotated[str, Field(pattern=r"^client:[0-9a-f]{16}$")]
type AgentId = Annotated[str, Field(pattern=r"^agt_[0-9a-f]{32}$")]
type OperationId = Annotated[
    str,
    Field(pattern=r"^rpc_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"),
]
type ServiceStatusRef = Annotated[
    dict[str, Any],
    WithJsonSchema(
        {"$ref": "https://schemas.yoetz.dev/0.1/service/service-status-1.0.0.schema.json"}
    ),
]


def _workspace_call_frame() -> dict[str, Any]:
    """The control wire's own ``workspace_call`` frame (``control-result`` 2.10.0, packaged),
    so a REST agent's work admits exactly the frames the control socket admits, every member
    bound as there (a schema that admitted ``{}`` would leave a server's call undefined)."""

    path = resources.files("finishup").joinpath(
        "resources", "schemas", "service", "control-result-2.10.0.schema.json"
    )
    for branch in cast(list[dict[str, Any]], json.loads(path.read_bytes())["oneOf"]):
        if branch.get("properties", {}).get("kind") == {"const": "workspace_call"}:
            return {**branch, "description": "One control workspace_call frame."}
    raise RuntimeError("workspace_call_frame_schema_missing")


type WorkspaceCallRef = Annotated[dict[str, Any], WithJsonSchema(_workspace_call_frame())]


class RestErrorContract(BaseModel):
    """``rest-error`` 1.0.0: a transport or authentication refusal, by its closed reason."""

    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal["1.0.0"]
    reason: Literal[
        "frame_invalid",
        "header_invalid",
        "api_key_invalid",
        "api_key_revoked",
        "api_key_expired",
        "origin_forbidden",
        "workspace_claim_required",
        "route_unknown",
        "operation_unknown",
        "agent_unknown",
        "method_not_allowed",
        "server_profile_changed",
        "api_manifest_unsupported",
        "frame_too_large",
        "operation_limit",
        "agent_limit",
        "rate_limited",
        "internal_failure",
        "service_unavailable",
        "server_keys_unusable",
        "workspace_agent_unavailable",
    ]


class RestDiscoveryContract(BaseModel):
    """``rest-discovery`` 1.0.0 (``GET /.well-known/finishup``): what a server is, before any
    credential. No release, no instance id, no key; ``official`` is the server's claim only."""

    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal["1.0.0"]
    product: Literal["finishup"]
    rest_majors: list[Annotated[str, Field(pattern=r"^[0-9]{1,3}$")]] = Field(
        min_length=1, max_length=8, json_schema_extra={"uniqueItems": True}
    )
    api_manifests: list[Sha256] = Field(
        min_length=1, max_length=16, json_schema_extra={"uniqueItems": True}
    )
    auth: list[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")]] = Field(
        min_length=1, max_length=8, json_schema_extra={"uniqueItems": True}
    )
    profile_endpoint: Annotated[str, Field(pattern=r"^/[A-Za-z0-9/._-]{1,127}$")]
    official: bool


class RestRevisionContract(BaseModel):
    """The server-profile revision a session was admitted under (ADR-052)."""

    model_config = ConfigDict(extra="forbid", strict=True)

    issuer: Annotated[str, Field(min_length=32, max_length=32, pattern=r"^[0-9a-f]{32}$")]
    revision: int = Field(ge=1, le=2**53 - 1)
    profile_digest: Sha256


class RestSessionContract(BaseModel):
    """``rest-session`` 1.0.0 (``GET /v1/session``): what a control hello answers, for one claim.

    The service status, the request's workspace binding and handle (none while the server cannot
    key the claim), and the profile revision the request was admitted under.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal["1.0.0"]
    status: ServiceStatusRef
    workspace_binding: Literal["none", "client_claim"]
    workspace_handle: Handle | None
    server_profile: RestRevisionContract


class RestOperationContract(BaseModel):
    """``rest-operation`` 1.0.0 (``202``): the call is still running at ``/v1/operations/{id}``."""

    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal["1.0.0"]
    operation_id: OperationId
    state: Literal["pending"]


class RestAgentDeclarationContract(BaseModel):
    """``rest-agent-declaration`` 1.0.0 (``POST /v1/agents`` body): the operations the agent
    answers, its largest reply, and its role (``connection`` or the helper's ``background``)."""

    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal["1.0.0"]
    operations: list[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]] = Field(
        min_length=1, max_length=64, json_schema_extra={"uniqueItems": True}
    )
    max_reply_bytes: int = Field(ge=1, le=6_291_456)
    role: Literal["connection", "background"]


class RestAgentContract(BaseModel):
    """``rest-agent`` 1.0.0 (``201``): the registered agent, the handle it answers for, its lease."""

    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal["1.0.0"]
    agent_id: AgentId
    workspace_handle: Handle
    lease_ms: int = Field(ge=1_000, le=600_000)


class RestAgentWorkContract(BaseModel):
    """``rest-agent-work`` 1.0.0: the agent's pending ``workspace_call`` frames, oldest first."""

    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal["1.0.0"]
    calls: list[WorkspaceCallRef] = Field(max_length=64)
