"""Closed schema contract for ``server-profile`` 1.0.0 (ADR-052, design v2 §2.2).

The generator derives ``schemas/service/server-profile-1.0.0.schema.json`` from these models.
Runtime parsing never imports this module: ``protocol.server_profile`` is the hook-safe parser,
and a conformance test keeps both agreeing on the golden vectors. What the schema cannot say (the
digest recomputed over the consent subset, sorted arrays, a default among the options, the copy
members present exactly when L2 is offered) the parser enforces.
"""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "SERVER_PROFILE_SCHEMA_VERSION",
    "ServerProfileCodeSync",
    "ServerProfileContract",
    "ServerProfileExclusions",
    "ServerProfileKey",
    "ServerProfileLevels",
    "ServerProfileRetention",
    "ServerProfileRetentionChoice",
    "ServerProfileReview",
    "ServerProfileRevisionContract",
]

SERVER_PROFILE_SCHEMA_VERSION: Literal["1.0.0"] = "1.0.0"

type Sha256 = Annotated[str, Field(min_length=71, max_length=71, pattern=r"^sha256:[0-9a-f]{64}$")]
type Token = Annotated[
    str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
]
type Level = Literal["L1", "L2"]


class ServerProfileKey(BaseModel):
    """Whom the server knows the caller as: no key id for a peer-authenticated owner session."""

    model_config = ConfigDict(extra="forbid", strict=True)

    id: Token | None
    scope: Literal["operator", "agent", "read"]
    principal: Token


class ServerProfileLevels(BaseModel):
    """The levels offered (rank order, unique) and the minimum required (one offered, or none)."""

    model_config = ConfigDict(extra="forbid", strict=True)

    offered: list[Level] = Field(
        min_length=1, max_length=2, json_schema_extra={"uniqueItems": True}
    )
    required_min: Level | None


class ServerProfileCodeSync(BaseModel):
    """How code reaches a server keeping a copy, and the caps (level L2 only)."""

    model_config = ConfigDict(extra="forbid", strict=True)

    methods: list[Token] = Field(
        min_length=1, max_length=256, json_schema_extra={"uniqueItems": True}
    )
    max_repo_bytes: int = Field(ge=0, le=2**53 - 1)
    max_file_bytes: int = Field(ge=0, le=2**53 - 1)


class ServerProfileRetentionChoice(BaseModel):
    """One retention: until the task closes, ``days`` days, or until the owner forgets it."""

    model_config = ConfigDict(extra="forbid", strict=True)

    kind: Literal["task_close", "days", "until_forgotten"]
    days: int | None = Field(ge=1, le=36_500)


class ServerProfileRetention(BaseModel):
    """The retention options offered and the default among them (level L2 only)."""

    model_config = ConfigDict(extra="forbid", strict=True)

    options: list[ServerProfileRetentionChoice] = Field(min_length=1, max_length=16)
    default: ServerProfileRetentionChoice


class ServerProfileExclusions(BaseModel):
    """Patterns the server also excludes from every copy, as exact strings (level L2 only)."""

    model_config = ConfigDict(extra="forbid", strict=True)

    always: list[
        Annotated[str, Field(min_length=1, max_length=512, pattern=r"^[^\x00-\x1f\x7f]+$")]
    ] = Field(max_length=256, json_schema_extra={"uniqueItems": True})


class ServerProfileReview(BaseModel):
    """Whether the server's own AI review may send what it reads to a model provider, and which:
    ``none`` names no provider; ``server_policy`` (its owner's privacy policy decides) names the
    provider it sends to first and, when it pairs two, the fallback it sends to when the first
    fails, each by a token the client shows in its own words."""

    model_config = ConfigDict(extra="forbid", strict=True)

    ai_review: Literal["none", "server_policy"]
    provider_disclosure: Token | None
    fallback_disclosure: Token | None


class ServerProfileRevisionContract(BaseModel):
    """The server's profile revision: its issuer, the number, and the digest it stands for."""

    model_config = ConfigDict(extra="forbid", strict=True)

    issuer: Annotated[str, Field(min_length=32, max_length=32, pattern=r"^[0-9a-f]{32}$")]
    revision: int = Field(ge=1, le=2**53 - 1)
    profile_digest: Sha256


class ServerProfileContract(BaseModel):
    """``server-profile`` 1.0.0: what a FinishUP server offers and requires.

    ``profile_digest`` covers ``levels``, ``code_sync``, ``retention``, ``exclusions`` and
    ``review`` in canonical JSON; ``official`` is the server's claim only. Closed tokens,
    digests, a release and a service instance id only: no path, host or name.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal["1.0.0"]
    release: Annotated[str, Field(min_length=5, max_length=128)]
    schema_manifest_digest: Sha256
    service_instance_id: Annotated[
        str,
        Field(pattern=r"^svc_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"),
    ]
    key: ServerProfileKey
    edges: list[Literal["rest-1", "ssh-control"]] = Field(
        min_length=1, max_length=2, json_schema_extra={"uniqueItems": True}
    )
    levels: ServerProfileLevels
    code_sync: ServerProfileCodeSync | None
    retention: ServerProfileRetention | None
    exclusions: ServerProfileExclusions | None
    review: ServerProfileReview
    official: bool
    profile_revision: ServerProfileRevisionContract
    profile_digest: Sha256
