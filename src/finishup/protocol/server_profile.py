"""The server profile: what a FinishUP server offers and requires (ADR-052, design v2 §2.2).

``server-profile`` 1.0.0 is the document a server returns once a client is authenticated: over
SSH from its own ``finishup service profile --json`` (layer 4), over REST from ``GET /v1/server``
(layer 5), and on any peer-authenticated control session from the ``server_profile`` operation. It
states the server's release and schema manifest, the service instance, the caller's key, the
edges it serves, the **levels** it offers (and the minimum it requires), how code reaches it and
how long it keeps it (level L2 only), the exclusions it enforces, its AI-review egress (every
provider its review may send to: the first, and the fallback when it pairs two), its
``official`` claim (a claim only: it never counts on its own, design v2 §2.4), and its **profile
revision**.

* ``profile_digest`` is ``sha256:`` over ``yoetz/server-profile/v1\\x00`` and the canonical JSON
  of the consent-relevant subset ``{levels, code_sync, retention, exclusions, review}``; each
  shared member is encoded exactly as a consent envelope encodes it
  (``protocol.consent_envelope``). A client recomputes it and refuses a profile whose stated
  digest differs.
* The **revision** (``ServerProfileRevision``) is the server's own: a random ``issuer`` it keeps
  in its state, a ``revision`` number it advances whenever the digest changes, and that digest.
  A client binds its consent to the whole triple and sends it on every remote connection; the
  server refuses any other triple before any work (``server_profile_changed``).
* Parsing is strict and bounded: every member is required, typed and closed, an unknown member or
  value refuses the whole document (``ProfileError``, a closed reason), so nothing a client does
  not understand can be consented to. Level-L2 members are present exactly when L2 is offered.

``envelope_for`` builds the consent envelope a client compares (design v2 §8.2) from a profile,
the endpoint identity the client observed, the level chosen and the retention chosen.

Pure: the standard library, ``protocol.canonical`` and ``protocol.consent_envelope`` only, so a
hook may import it (no pydantic; the schema's pydantic contract is
``protocol.server_profile_contract``).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, cast

from finishup.protocol.canonical import (
    JsonValue,
    ProtocolValueError,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.consent_envelope import (
    LEVELS,
    CodeSync,
    ConsentEnvelope,
    EndpointIdentity,
    EnvelopeError,
    Principal,
    Retention,
    ReviewEgress,
    code_sync_to_json,
    exclusions_to_json,
    parse_shared_member,
    retention_to_json,
    review_to_json,
)

__all__ = [
    "EDGES",
    "KEY_SCOPES",
    "PROFILE_DIGEST_DOMAIN",
    "PROFILE_SCHEMA_VERSION",
    "ProfileError",
    "ProfileKey",
    "ProfileLevels",
    "ProfileRetention",
    "ServerProfile",
    "ServerProfileRevision",
    "consent_subset",
    "envelope_for",
    "profile_digest",
    "profile_from_json",
    "profile_to_json",
    "revision_from_json",
    "revision_to_json",
]

PROFILE_SCHEMA_VERSION: Final = "1.0.0"
PROFILE_DIGEST_DOMAIN: Final = b"yoetz/server-profile/v1\x00"
# The edges a server may serve (design v2 §1): REST v1 (layer 5) and owner control over SSH.
EDGES: Final = ("rest-1", "ssh-control")
# The scopes a key may carry: a peer-authenticated owner session is ``operator``.
KEY_SCOPES: Final = ("operator", "agent", "read")
MAX_PROFILE_BYTES: Final = 65_536

_SHA256: Final = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_ISSUER: Final = re.compile(r"^[0-9a-f]{32}$", re.ASCII)
_RELEASE: Final = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$",
    re.ASCII,
)
_INSTANCE: Final = re.compile(
    r"^svc_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.ASCII
)
_TOKEN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$", re.ASCII)
_MAX_REVISION: Final = 2**53 - 1
_MAX_OPTIONS: Final = 16
_MAX_PATTERNS: Final = 256
_PATTERN_LIMIT: Final = 512

_TOP_FIELDS: Final = frozenset(
    {
        "schema_version",
        "release",
        "schema_manifest_digest",
        "service_instance_id",
        "key",
        "edges",
        "levels",
        "code_sync",
        "retention",
        "exclusions",
        "review",
        "official",
        "profile_revision",
        "profile_digest",
    }
)


class ProfileError(ValueError):
    """A server profile this release refuses; ``reason`` is a closed token, never input text."""

    reason: str

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class ServerProfileRevision:
    """The server's profile revision: who issued it, its number, and the digest it stands for.

    A consent is bound to the whole triple; the server compares the whole triple.
    """

    issuer: str
    revision: int
    profile_digest: str

    def __post_init__(self) -> None:
        if type(self.issuer) is not str or not _ISSUER.match(self.issuer):
            raise ProfileError("profile_revision_invalid")
        if type(self.revision) is not int or not 1 <= self.revision <= _MAX_REVISION:
            raise ProfileError("profile_revision_invalid")
        if type(self.profile_digest) is not str or not _SHA256.match(self.profile_digest):
            raise ProfileError("profile_revision_invalid")


@dataclass(frozen=True, slots=True)
class ProfileKey:
    """Whom the server knows the caller as: its key id (``None`` for an owner session), the
    key's scope and the principal."""

    id: str | None
    scope: str
    principal: str


@dataclass(frozen=True, slots=True)
class ProfileLevels:
    """The levels offered, in rank order, and the minimum the server requires (or none)."""

    offered: tuple[str, ...]
    required_min: str | None


@dataclass(frozen=True, slots=True)
class ProfileRetention:
    """The retention options a server keeping a copy offers, and its default among them."""

    options: tuple[Retention, ...]
    default: Retention


@dataclass(frozen=True, slots=True)
class ServerProfile:
    """One validated ``server-profile`` 1.0.0 document."""

    release: str
    schema_manifest_digest: str
    service_instance_id: str
    key: ProfileKey
    edges: tuple[str, ...]
    levels: ProfileLevels
    code_sync: CodeSync | None
    retention: ProfileRetention | None
    exclusions: frozenset[str] | None
    review: ReviewEgress
    official: bool
    revision: ServerProfileRevision

    @property
    def profile_digest(self) -> str:
        return self.revision.profile_digest


# --- the consent subset and its digest -------------------------------------------------------


def _retention_key(retention: Retention) -> bytes:
    return canonical_encode(retention_to_json(retention))


def _levels_json(levels: ProfileLevels) -> dict[str, JsonValue]:
    return {"offered": list(levels.offered), "required_min": levels.required_min}


def _retention_json(retention: ProfileRetention | None) -> JsonValue:
    if retention is None:
        return None
    options = sorted(retention.options, key=_retention_key)
    return {
        "options": [retention_to_json(option) for option in options],
        "default": retention_to_json(retention.default),
    }


def _exclusions_json(exclusions: frozenset[str] | None) -> JsonValue:
    return None if exclusions is None else {"always": exclusions_to_json(exclusions)}


def consent_subset(
    *,
    levels: ProfileLevels,
    code_sync: CodeSync | None,
    retention: ProfileRetention | None,
    exclusions: frozenset[str] | None,
    review: ReviewEgress,
) -> dict[str, JsonValue]:
    """The consent-relevant subset of a profile, in its canonical JSON shape."""

    return {
        "levels": _levels_json(levels),
        "code_sync": code_sync_to_json(code_sync),
        "retention": _retention_json(retention),
        "exclusions": _exclusions_json(exclusions),
        "review": review_to_json(review),
    }


def profile_digest(subset: Mapping[str, JsonValue]) -> str:
    """``sha256:<hex>`` over the domain-separated canonical bytes of a consent subset."""

    encoded = canonical_encode(cast(JsonValue, dict(subset)))
    return "sha256:" + hashlib.sha256(PROFILE_DIGEST_DOMAIN + encoded).hexdigest()


# --- parsing -----------------------------------------------------------------------------------


def _object(value: JsonValue, fields: frozenset[str]) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise ProfileError("profile_member_invalid")
    source = cast(Mapping[str, JsonValue], value)
    if frozenset(source) != fields:
        raise ProfileError(
            "profile_member_unknown" if frozenset(source) > fields else "profile_member_missing"
        )
    return source


def _token(value: JsonValue, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if type(value) is not str or not _TOKEN.match(value):
        raise ProfileError("profile_member_invalid")
    return value


def _matched(value: JsonValue, pattern: re.Pattern[str]) -> str:
    if type(value) is not str or not pattern.match(value):
        raise ProfileError("profile_member_invalid")
    return value


def _closed(value: JsonValue, allowed: tuple[str, ...]) -> str:
    if type(value) is not str:
        raise ProfileError("profile_member_invalid")
    if value not in allowed:
        raise ProfileError("profile_value_unknown")
    return value


def _array(value: JsonValue, *, maximum: int) -> list[JsonValue]:
    if not isinstance(value, list) or len(cast(list[JsonValue], value)) > maximum:
        raise ProfileError("profile_member_invalid")
    return cast(list[JsonValue], value)


def _shared(name: str, value: JsonValue) -> CodeSync | Retention | ReviewEgress | None:
    try:
        return parse_shared_member(name, value)
    except EnvelopeError as error:
        raise ProfileError(
            "profile_value_unknown"
            if error.reason == "envelope_value_unknown"
            else "profile_member_invalid"
        ) from None


def _key(value: JsonValue) -> ProfileKey:
    source = _object(value, frozenset({"id", "scope", "principal"}))
    return ProfileKey(
        _token(source["id"], nullable=True),
        _closed(source["scope"], KEY_SCOPES),
        cast(str, _token(source["principal"])),
    )


def _edges(value: JsonValue) -> tuple[str, ...]:
    items = _array(value, maximum=len(EDGES))
    edges = tuple(_closed(item, EDGES) for item in items)
    if not edges or len(set(edges)) != len(edges) or list(edges) != sorted(edges):
        raise ProfileError("profile_member_invalid")
    return edges


def _levels(value: JsonValue) -> ProfileLevels:
    source = _object(value, frozenset({"offered", "required_min"}))
    offered = tuple(_closed(item, LEVELS) for item in _array(source["offered"], maximum=8))
    if not offered or list(offered) != sorted(set(offered), key=LEVELS.index):
        raise ProfileError("profile_member_invalid")
    required = source["required_min"]
    required_min = None if required is None else _closed(required, LEVELS)
    if required_min is not None and required_min not in offered:
        raise ProfileError("profile_member_invalid")
    return ProfileLevels(offered, required_min)


def _retention_option(value: JsonValue) -> Retention:
    retention = _shared("retention", value)
    if type(retention) is not Retention:
        raise ProfileError("profile_member_invalid")
    return retention


def _profile_retention(value: JsonValue) -> ProfileRetention | None:
    if value is None:
        return None
    source = _object(value, frozenset({"options", "default"}))
    options = tuple(
        _retention_option(item) for item in _array(source["options"], maximum=_MAX_OPTIONS)
    )
    keys = [_retention_key(option) for option in options]
    if not options or keys != sorted(set(keys)):
        raise ProfileError("profile_member_invalid")
    default = _retention_option(source["default"])
    if default not in options:
        raise ProfileError("profile_member_invalid")
    return ProfileRetention(options, default)


def _exclusions(value: JsonValue) -> frozenset[str] | None:
    if value is None:
        return None
    source = _object(value, frozenset({"always"}))
    patterns: list[str] = []
    for item in _array(source["always"], maximum=_MAX_PATTERNS):
        if (
            type(item) is not str
            or not item
            or len(item) > _PATTERN_LIMIT
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in item)
        ):
            raise ProfileError("profile_member_invalid")
        patterns.append(item)
    if patterns != sorted(set(patterns), key=str.encode):
        raise ProfileError("profile_member_invalid")
    return frozenset(patterns)


def revision_from_json(value: JsonValue) -> ServerProfileRevision:
    """A ``{issuer, revision, profile_digest}`` object; malformed raises ``ProfileError``."""

    source = _object(value, frozenset({"issuer", "revision", "profile_digest"}))
    return ServerProfileRevision(
        cast(str, source["issuer"]),
        cast(int, source["revision"]),
        cast(str, source["profile_digest"]),
    )


def revision_to_json(revision: ServerProfileRevision) -> dict[str, JsonValue]:
    return {
        "issuer": revision.issuer,
        "revision": revision.revision,
        "profile_digest": revision.profile_digest,
    }


def profile_from_json(value: JsonValue | bytes) -> ServerProfile:
    """Parse and verify one profile (a JSON value or strict JSON bytes, at most 64 KiB).

    Strict and closed: anything missing, malformed or unknown raises ``ProfileError``. The
    profile's stated digest and its revision's digest must both equal the digest recomputed over
    its consent subset (``profile_digest_mismatch``).
    """

    if isinstance(value, bytes):
        if len(value) > MAX_PROFILE_BYTES:
            raise ProfileError("profile_too_large")
        try:
            value = strict_json_parse(value)
        except ProtocolValueError:
            raise ProfileError("profile_not_json") from None
    source = _object(value, _TOP_FIELDS)
    if source["schema_version"] != PROFILE_SCHEMA_VERSION:
        raise ProfileError("profile_schema_unsupported")
    levels = _levels(source["levels"])
    code_sync = _shared("code_sync", source["code_sync"])
    retention = _profile_retention(source["retention"])
    exclusions = _exclusions(source["exclusions"])
    review = _shared("review", source["review"])
    if type(review) is not ReviewEgress or (
        code_sync is not None and type(code_sync) is not CodeSync
    ):
        raise ProfileError("profile_member_invalid")
    copy = "L2" in levels.offered
    if copy != (code_sync is not None) or copy != (retention is not None):
        # The members of a server copy are present exactly when that level is offered.
        raise ProfileError("profile_member_invalid")
    if copy != (exclusions is not None):
        raise ProfileError("profile_member_invalid")
    official = source["official"]
    if type(official) is not bool:
        raise ProfileError("profile_member_invalid")
    try:
        revision = revision_from_json(source["profile_revision"])
    except ProfileError:
        raise ProfileError("profile_member_invalid") from None
    stated = _matched(source["profile_digest"], _SHA256)
    computed = profile_digest(
        consent_subset(
            levels=levels,
            code_sync=code_sync,
            retention=retention,
            exclusions=exclusions,
            review=review,
        )
    )
    if stated != computed or revision.profile_digest != computed:
        raise ProfileError("profile_digest_mismatch")
    profile = ServerProfile(
        release=_matched(source["release"], _RELEASE),
        schema_manifest_digest=_matched(source["schema_manifest_digest"], _SHA256),
        service_instance_id=_matched(source["service_instance_id"], _INSTANCE),
        key=_key(source["key"]),
        edges=_edges(source["edges"]),
        levels=levels,
        code_sync=code_sync,
        retention=retention,
        exclusions=exclusions,
        review=review,
        official=official,
        revision=revision,
    )
    if len(canonical_encode(profile_to_json(profile))) > MAX_PROFILE_BYTES:
        raise ProfileError("profile_too_large")
    return profile


def profile_to_json(profile: ServerProfile) -> dict[str, JsonValue]:
    """The profile as its canonical JSON object."""

    return {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "release": profile.release,
        "schema_manifest_digest": profile.schema_manifest_digest,
        "service_instance_id": profile.service_instance_id,
        "key": {
            "id": profile.key.id,
            "scope": profile.key.scope,
            "principal": profile.key.principal,
        },
        "edges": list(profile.edges),
        **consent_subset(
            levels=profile.levels,
            code_sync=profile.code_sync,
            retention=profile.retention,
            exclusions=profile.exclusions,
            review=profile.review,
        ),
        "official": profile.official,
        "profile_revision": revision_to_json(profile.revision),
        "profile_digest": profile.profile_digest,
    }


# --- the consent envelope a client compares ---------------------------------------------------


def envelope_for(
    profile: ServerProfile,
    *,
    endpoint: EndpointIdentity,
    level: str,
    retention: Retention | None,
    disclosure_version: int,
) -> ConsentEnvelope:
    """The consent envelope of using ``profile`` at ``level`` (design v2 §8.2).

    ``endpoint`` is what the client itself observed (kind, origin, TLS or SSH identity), never
    what the server says. Level L1 sends no copy: no code sync, no retention, no exclusions.
    Level L2 takes the profile's code sync and exclusions and the ``retention`` chosen, which must
    be one the profile offers. A level the profile does not offer raises
    ``ProfileError("profile_level_not_offered")``.
    """

    if level not in profile.levels.offered:
        raise ProfileError("profile_level_not_offered")
    copy = level == "L2"
    if copy:
        if profile.retention is None or retention not in profile.retention.options:
            raise ProfileError("profile_retention_not_offered")
    elif retention is not None:
        raise ProfileError("profile_retention_not_offered")
    return ConsentEnvelope(
        endpoint=endpoint,
        principal=Principal(profile.key.id, profile.key.principal),
        key_scope=frozenset({profile.key.scope}),
        level=level,
        required_min=profile.levels.required_min,
        code_sync=profile.code_sync if copy else None,
        retention=retention if copy else None,
        exclusions=(profile.exclusions or frozenset()) if copy else frozenset(),
        review=profile.review,
        disclosure_version=disclosure_version,
    )
