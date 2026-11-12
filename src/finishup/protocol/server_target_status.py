"""Closed contract for ``finishup server status --json`` (ADR-051).

``server-target-status`` 1.0.0 names which source decided the root this client uses (the
isolation variable, the runtime pin, the owner-only selection, or the everyday ambient install),
the target it resolves to, and what one probe of that target observed. For a remote target it
also carries what that target's server may read outside the claimed project on this computer
(ADR-051 decision 5): the outside-read mode, where the mode came from, and the folders listed for
it, from this client's own record. ``zero_network_selection`` says when this computer forbids
all network use while a remote server is, or may be, selected (ADR-051 decision 8), by generated
id and closed tokens, and whether this computer said so now or last reported it (with when); it
is null otherwise. For a remote target ``repositories`` says which repositories it holds
because their privacy policy on this computer allows no network use, which the owner kept on this
computer, and which it receives anyway, and what is true of the repository in the current folder
(ADR-051 decision 8, maintainer decision of 2026-11-07, round 4). It is an owner display: the
target name, its location (a host, a URL), the listed folders and the repositories' worktree
paths appear here and in ``server list``, ``server status``, ``server folders list`` and
``server repositories list`` only, never in errors, logs, hook output, or MCP text. The claim salt
and any credential never appear.
"""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

__all__ = [
    "SERVER_TARGET_STATUS_SCHEMA_VERSION",
    "ServerTargetAllowedRepository",
    "ServerTargetAuthorization",
    "ServerTargetConnection",
    "ServerTargetConsent",
    "ServerTargetDescription",
    "ServerTargetHelper",
    "ServerTargetHeldRepository",
    "ServerTargetKeptRepository",
    "ServerTargetOutsideReads",
    "ServerTargetProbe",
    "ServerTargetRepositories",
    "ServerTargetRepositoryHere",
    "ServerTargetStatusContract",
    "ServerTargetZeroNetworkSelection",
]

SERVER_TARGET_STATUS_SCHEMA_VERSION: Literal["1.0.0"] = "1.0.0"

type Token = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
type Timestamp = Annotated[
    str, Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$")
]
type TargetId = Annotated[str, Field(pattern=r"^t_[0-9a-f]{8}$")]
# A folder an owner listed: an absolute path in the input-root shape (at most 190 characters).
type ListedFolder = Annotated[
    str, Field(min_length=2, max_length=190, pattern=r"^/[^\x00-\x1f\x7f]+$")
]
# A repository's worktree top as this computer recorded it (owner display, at most 1024).
type RepositoryPath = Annotated[
    str, Field(min_length=2, max_length=1024, pattern=r"^/[^\x00-\x1f\x7f]+$")
]
# Whether an owner's choice for a repository applies now: it does, its policy here changed since
# (FinishUP asks again), its policy here allows network use, or this computer never reported it.
type RepositoryChoiceState = Literal["applies", "grant_changed", "not_needed", "not_reported"]


class ServerTargetAuthorization(BaseModel):
    """The owner's trusted-console authorization of a remote target."""

    model_config = ConfigDict(extra="forbid", strict=True)

    authorized_at: Timestamp
    disclosure_version: int = Field(ge=1)
    current: bool


class ServerTargetConsent(BaseModel):
    """The owner's consent to a remote target's server profile (ADR-052; amended in place, as
    1.0.0 is unreleased).

    ``level`` agreed and the ``profile_revision`` number it stands under now; ``state`` is what
    the consent step decides from this computer's records alone: ``current`` (the server's last
    known profile is the one agreed to, or narrower), ``changed`` (only the owner agrees again:
    ``server_profile_changed``) or ``level_unavailable`` (it requires more than agreed:
    ``server_level_unavailable``). ``adjusted_at`` is when a narrowed profile adjusted the consent
    since the owner last confirmed it (the ``server_profile_narrowed`` notice), and
    ``coverage_reduced`` what that narrowing no longer covers; both null and empty otherwise.
    """

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        json_schema_extra={
            "if": {"properties": {"adjusted_at": {"type": "null"}}, "required": ["adjusted_at"]},
            "then": {"properties": {"coverage_reduced": {"maxItems": 0}}},
        },
    )

    level: Literal["L1", "L2"]
    profile_revision: int = Field(ge=1)
    state: Literal["current", "changed", "level_unavailable"]
    adjusted_at: Timestamp | None
    coverage_reduced: list[Literal["code_sync", "exclusions", "level", "review"]] = Field(
        max_length=4
    )

    @model_validator(mode="after")
    def _reduction_comes_with_an_adjustment(self) -> "ServerTargetConsent":
        if self.adjusted_at is None and self.coverage_reduced:
            raise ValueError("consent_reduction_without_adjustment")
        return self


class ServerTargetOutsideReads(BaseModel):
    """What a remote target's server may read outside the claimed project on this computer.

    ``mode`` ``local``: as a FinishUP service on this computer would read; ``listed``: only beneath
    ``folders``. Every remote kind has the same two modes. ``mode_source`` says where the mode
    came from: the owner (at ``server add`` or with ``server folders mode``); with none recorded,
    an official FinishUP endpoint (``local``) or no choice yet (``not_chosen``, ``listed``); or a
    record that cannot be read (then ``listed`` with no folder).
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    mode: Literal["local", "listed"]
    mode_source: Literal["owner", "official_endpoint", "not_chosen", "unreadable"]
    folders: list[ListedFolder] = Field(max_length=32)


class ServerTargetHeldRepository(BaseModel):
    """A repository held from the target: its policy on this computer allows no network use and
    the owner has not decided (``not_allowed``), or their choice was for an earlier stretch of it
    (``grant_changed``). ``worktree`` is null when its path is too long to keep."""

    model_config = ConfigDict(extra="forbid", strict=True)

    worktree: RepositoryPath | None
    reported_at: Timestamp
    cause: Literal["not_allowed", "grant_changed"]


class ServerTargetKeptRepository(BaseModel):
    """A repository the owner chose to keep on this computer for the target, and since when."""

    model_config = ConfigDict(extra="forbid", strict=True)

    worktree: RepositoryPath
    kept_at: Timestamp
    state: RepositoryChoiceState


class ServerTargetAllowedRepository(BaseModel):
    """A repository the owner allowed the target to receive anyway, and since when."""

    model_config = ConfigDict(extra="forbid", strict=True)

    worktree: RepositoryPath
    allowed_at: Timestamp
    state: RepositoryChoiceState


class ServerTargetRepositoryHere(BaseModel):
    """What is true of the repository in the current folder for the target.

    ``held`` (with ``cause``), ``kept`` on this computer, ``sent_anyway``, ``not_held`` (its policy
    here allows network use), or ``not_reported`` (this computer's FinishUP never said and cannot
    be asked now). ``policy_read`` is ``live`` when this computer's FinishUP answered now and
    ``last_reported`` (at ``reported_at``) when it could not be asked; null when not reported.
    """

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        json_schema_extra={
            "allOf": [
                {
                    "if": {"properties": {"state": {"const": "held"}}, "required": ["state"]},
                    "then": {"properties": {"cause": {"not": {"type": "null"}}}},
                    "else": {"properties": {"cause": {"type": "null"}}},
                },
                {
                    "if": {
                        "properties": {"state": {"const": "not_reported"}},
                        "required": ["state"],
                    },
                    "then": {"properties": {"policy_read": {"type": "null"}}},
                    "else": {"properties": {"policy_read": {"not": {"type": "null"}}}},
                },
                {
                    "if": {
                        "properties": {"policy_read": {"const": "last_reported"}},
                        "required": ["policy_read"],
                    },
                    "then": {"properties": {"reported_at": {"not": {"type": "null"}}}},
                    "else": {"properties": {"reported_at": {"type": "null"}}},
                },
            ]
        },
    )

    state: Literal["held", "kept", "sent_anyway", "not_held", "not_reported"]
    cause: Literal["not_allowed", "grant_changed"] | None
    policy_read: Literal["live", "last_reported"] | None
    reported_at: Timestamp | None

    @model_validator(mode="after")
    def _facts_match_the_state(self) -> "ServerTargetRepositoryHere":
        if (self.state == "held") != (self.cause is not None):
            raise ValueError("repository_here_cause_mismatch")
        if (self.state == "not_reported") != (self.policy_read is None):
            raise ValueError("repository_here_policy_read_mismatch")
        if (self.policy_read == "last_reported") != (self.reported_at is not None):
            raise ValueError("repository_here_reported_at_mismatch")
        return self


class ServerTargetRepositories(BaseModel):
    """A remote target's repositories whose privacy policy on this computer allows no network
    use: ``held`` from it, ``kept`` here by the owner's choice, ``allowed`` to it anyway, and
    ``here`` (null outside a repository or while the zero-network item is shown). ``reports`` and
    ``record`` say whether this computer's two records could be read; one that cannot holds
    nothing (reports) or allows nothing (record)."""

    model_config = ConfigDict(extra="forbid", strict=True)

    reports: Literal["readable", "unreadable"]
    record: Literal["readable", "unreadable"]
    held: list[ServerTargetHeldRepository] = Field(max_length=256)
    kept: list[ServerTargetKeptRepository] = Field(max_length=64)
    allowed: list[ServerTargetAllowedRepository] = Field(max_length=64)
    here: ServerTargetRepositoryHere | None


class ServerTargetHelper(BaseModel):
    """What the target's helper last recorded (ADR-052): closed tokens and its generation.

    ``running`` says whether a helper holds the target's lock now; ``phase`` and ``reason`` are
    its last record (``ready``, ``unavailable`` with the remote phase, ``stopped`` with why).
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    running: bool
    phase: Literal["starting", "ready", "unavailable", "stopped"]
    reason: Token | None
    generation: Annotated[int, Field(ge=1)]


class ServerTargetConnection(BaseModel):
    """How this computer reaches an SSH target (ADR-052, design v2 section 1.2): the owner's
    connection ``style``, the styles the server's last profile offers, and its helper, if one
    ever recorded anything."""

    model_config = ConfigDict(extra="forbid", strict=True)

    style: Literal["relay", "direct"]
    styles_offered: list[Literal["relay", "direct"]] = Field(max_length=2)
    helper: ServerTargetHelper | None


class ServerTargetDescription(BaseModel):
    """The target the deciding source resolves to (``target_id`` null: not a named target)."""

    model_config = ConfigDict(extra="forbid", strict=True)

    target_id: TargetId | None
    name: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,15}$")] | None
    kind: Literal["local", "local_port", "ssh", "https"]
    location: Annotated[str, Field(min_length=1, max_length=2048)] | None
    credential: Literal["keyring", "file", "none", "not_applicable"]
    authorization: ServerTargetAuthorization | None
    # Null for a target that is not remote, or one never consented to a server profile (ADR-052).
    consent: ServerTargetConsent | None
    # Null for a target that is not an SSH server (ADR-052): how this computer reaches it.
    connection: ServerTargetConnection | None
    # Null for a target that is not remote: a local server reads under its own privacy policy.
    outside_reads: ServerTargetOutsideReads | None
    # Null for a target that is not remote: a server on this computer applies this computer's
    # own privacy policy to each repository, so nothing is held for it (ADR-051 decision 8).
    repositories: ServerTargetRepositories | None


class ServerTargetProbe(BaseModel):
    """One probe: closed outcome and reason tokens, the server's release, and timing.

    ``not_probed``: nothing was sent, because this computer last reported a zero-network privacy
    policy (ADR-051 decision 8); ``reason`` is ``zero_network_remote_selected`` (the selected
    server) or ``zero_network_in_force`` (any other server elsewhere), and ``last_reported_at``
    is when this computer reported that policy, as ``server login``, ``connect`` and ``test``
    say. ``last_reported_at`` is set exactly for ``not_probed`` (amended in place, 2026-11-07,
    as 1.0.0 is unreleased). ``continuation`` (amended in place, 2026-11-11) is the registered
    way back of a probe that a server elsewhere did not answer: its phase's own continuation, or
    ``remote_direct_slow`` for a target reached in the direct style that did not answer in time
    (the owner's WAN-gate decision); ``null`` otherwise.
    """

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        json_schema_extra={
            "if": {
                "properties": {"outcome": {"const": "not_probed"}},
                "required": ["outcome"],
            },
            "then": {"properties": {"last_reported_at": {"not": {"type": "null"}}}},
            "else": {"properties": {"last_reported_at": {"type": "null"}}},
        },
    )

    outcome: Literal["ready", "reachable", "not_running", "unavailable", "not_probed"]
    reason: Token | None
    phase: Token | None
    service_version: Annotated[str, Field(min_length=5, max_length=128)] | None
    service_instance_id: (
        Annotated[
            str,
            Field(pattern=r"^svc_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
        ]
        | None
    )
    service_state: Token | None
    vault_mode: Token | None
    round_trip_p95_ms: int | None = Field(ge=0)
    samples: int = Field(ge=0)
    # Set exactly when ``outcome`` is ``not_probed``.
    last_reported_at: Timestamp | None
    # The registered continuation of a failed probe of a server elsewhere (see the class text).
    continuation: Token | None

    @model_validator(mode="after")
    def _reported_time_matches_the_outcome(self) -> "ServerTargetProbe":
        if (self.outcome == "not_probed") != (self.last_reported_at is not None):
            raise ValueError("probe_last_reported_at_mismatch")
        return self


class ServerTargetZeroNetworkSelection(BaseModel):
    """This computer forbids all network use while the selection names, or may name, a server on
    another machine, a port or the web (ADR-051 decision 8). FinishUP never uses such a server in
    that state: connections to it are refused until ``finishup server use local``.

    ``zero_network_remote_selected``: ``target_id`` and ``kind`` name the selected server.
    ``zero_network_selection_unreadable``: the selection could not be read; ``detail`` is its
    closed reason and the server is unknown. ``policy_read`` is ``live`` when this computer's
    service answered now, or ``last_reported`` when it could not be asked (stopped or locked) and
    it last reported zero-network at ``last_reported_at`` (maintainer decision, 2026-11-07).
    Generated ids, closed tokens and a fixed-shape UTC time only.
    """

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        json_schema_extra={
            "if": {
                "properties": {"policy_read": {"const": "last_reported"}},
                "required": ["policy_read"],
            },
            "then": {"properties": {"last_reported_at": {"not": {"type": "null"}}}},
            "else": {"properties": {"last_reported_at": {"type": "null"}}},
        },
    )

    reason: Literal["zero_network_remote_selected", "zero_network_selection_unreadable"]
    target_id: TargetId | None
    kind: Literal["local_port", "ssh", "https"] | None
    detail: Token | None
    policy_read: Literal["live", "last_reported"]
    # Set exactly when ``policy_read`` is ``last_reported``.
    last_reported_at: Timestamp | None

    @model_validator(mode="after")
    def _reported_time_matches_how_it_was_read(self) -> "ServerTargetZeroNetworkSelection":
        if (self.policy_read == "last_reported") != (self.last_reported_at is not None):
            raise ValueError("zero_network_last_reported_at_mismatch")
        return self


class ServerTargetStatusContract(BaseModel):
    """``server-target-status`` 1.0.0."""

    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal["1.0.0"]
    source: Literal["ambient", "environment", "runtime_pin", "environment_and_pin", "selection"]
    selection_overridden: bool
    client_version: Annotated[str, Field(min_length=1, max_length=128)]
    target: ServerTargetDescription
    probe: ServerTargetProbe
    # Null unless this computer is (or last reported being) in the zero-network state while a
    # remote server is (or may be) selected: connections to it are refused.
    zero_network_selection: ServerTargetZeroNetworkSelection | None
    observed_at: Timestamp
