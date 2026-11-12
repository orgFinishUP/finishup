"""Consent envelopes: what a client agreed to send to and keep on a FinishUP server (ADR-052).

A consent envelope is the client's canonical record of everything a server connection may send
or keep: the level, code sync, retention, exclusions and review egress, and the principal,
endpoint origin, TLS or SSH identity and key scope they are sent under (design v2 section 8.2).
It is computed on the client; the server never supplies one. Layer 2 of the unification lands the
types, their canonical form, digest and the explicit partial order, and nothing reads them yet:
wiring a server profile into an envelope, recording the consented digest and refusing a widened
one (``server_profile_changed``) arrive with profiles in the next layer.

* ``envelope_from_json`` is strict for every known member and never drops an unknown one: an
  unknown member or an unknown enumerated value is kept, in place, in the canonical form and the
  digest, and its path is named in ``unknown_paths``. Malformed input raises ``EnvelopeError``
  with a closed reason.
* ``consentable`` is false for an envelope with anything unknown, so nothing a client does not
  understand can be agreed to.
* ``precedes(a, b)`` is the partial order ``a ⊑ b``: *a sends or keeps no more than b*. It is the
  product of one order per field, listed in ``FIELD_ORDERS``; anything incomparable is not
  ordered.
* ``compare(consented, current)`` returns a typed verdict: ``same`` (identical canonical bytes),
  ``level_unavailable`` (the server requires a higher level than was agreed: never a silent
  upgrade), ``narrower`` (``current ⊑ consented``: it sends or keeps less; ``coverage_reduced``
  names the fields whose narrowing reduces what a check or review can see) or ``ask_again``
  (anything wider, incomparable or unknown). Moving from L1 to L2 is never narrowing.

The module is pure: the standard library and ``protocol.canonical`` only.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Final, Literal, cast

from finishup.protocol.canonical import (
    JsonValue,
    ProtocolValueError,
    canonical_encode,
    strict_json_parse,
)

__all__ = [
    "AI_REVIEW_VALUES",
    "ENDPOINT_KINDS",
    "ENVELOPE_SCHEMA",
    "FIELD_ORDERS",
    "IDENTITY_TYPES",
    "LEVELS",
    "RETENTION_KINDS",
    "CodeSync",
    "ConsentEnvelope",
    "EndpointIdentity",
    "EnvelopeComparison",
    "EnvelopeError",
    "FieldOrder",
    "Principal",
    "Retention",
    "ReviewEgress",
    "Verdict",
    "canonical_bytes",
    "code_sync_to_json",
    "compare",
    "consentable",
    "envelope_digest",
    "envelope_from_json",
    "envelope_to_json",
    "exclusions_to_json",
    "parse_shared_member",
    "precedes",
    "retention_from_token",
    "retention_to_json",
    "review_to_json",
]

ENVELOPE_SCHEMA: Final = "yoetz.consent-envelope/1"
_DIGEST_DOMAIN: Final = b"yoetz/consent-envelope/v1\x00"

ENDPOINT_KINDS: Final = frozenset({"ssh", "https", "local_port"})
IDENTITY_TYPES: Final = frozenset({"tls_system_ca", "tls_ca_file", "tls_pin", "ssh_host_key"})
# The levels in rank order (design v2 section 1): L1 keeps tasks on the server while this
# computer's workspace agent answers its reads; L2 also keeps a copy of the code there.
LEVELS: Final = ("L1", "L2")
RETENTION_KINDS: Final = frozenset({"task_close", "days", "until_forgotten"})
AI_REVIEW_VALUES: Final = frozenset({"none", "server_policy"})

_TOKEN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$", re.ASCII)
_MEMBER: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$", re.ASCII)
_IDENTITY: Final = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_PATTERN_LIMIT: Final = 512
_SET_LIMIT: Final = 256
_ORIGIN_LIMIT: Final = 512
_MAX_ENVELOPE_BYTES: Final = 65_536
_MAX_DAYS: Final = 36_500
_DAYS_TOKEN: Final = re.compile(r"days:([1-9][0-9]{0,4})", re.ASCII)

_TOP_FIELDS: Final = (
    "schema",
    "endpoint",
    "principal",
    "key_scope",
    "level",
    "required_min",
    "code_sync",
    "retention",
    "exclusions",
    "review",
    "disclosure_version",
)
_ENDPOINT_FIELDS: Final = ("kind", "origin", "identity_type", "identity")
_PRINCIPAL_FIELDS: Final = ("key_id", "principal")
_CODE_SYNC_FIELDS: Final = ("methods", "max_repo_bytes", "max_file_bytes")
_RETENTION_FIELDS: Final = ("kind", "days")
_REVIEW_FIELDS: Final = ("ai_review", "provider_disclosure", "fallback_disclosure")

type Verdict = Literal["same", "narrower", "ask_again", "level_unavailable"]
type FieldOrder = Literal["equal", "narrower", "wider", "incomparable"]


class EnvelopeError(ValueError):
    """A malformed consent envelope; ``reason`` is a closed token, never input text."""

    reason: str

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class EndpointIdentity:
    """Where the server is and how it is recognised: equal or asked again, never ordered."""

    kind: str
    origin: str
    identity_type: str
    identity: str | None


@dataclass(frozen=True, slots=True)
class Principal:
    """Whom the server knows this client as, and under which key."""

    key_id: str | None
    principal: str | None


@dataclass(frozen=True, slots=True)
class CodeSync:
    """How code reaches a server that keeps a copy (L2), and the caps on what is sent."""

    methods: frozenset[str]
    max_repo_bytes: int
    max_file_bytes: int


@dataclass(frozen=True, slots=True)
class Retention:
    """How long the server keeps what it was sent: until the task closes, N days, or until the
    owner forgets it."""

    kind: str
    days: int | None


@dataclass(frozen=True, slots=True)
class ReviewEgress:
    """Whether the server may send what it holds to an AI provider for review, and to which.

    ``provider_disclosure`` names the provider its review sends to first; ``fallback_disclosure``
    the one it may send to when that provider fails (a server whose review pairs two providers),
    or ``None``. Every provider a server's review may send to is named, so adding, removing or
    swapping one changes the envelope (ADR-052).
    """

    ai_review: str
    provider_disclosure: str | None
    fallback_disclosure: str | None = None


@dataclass(frozen=True, slots=True)
class ConsentEnvelope:
    """One canonical consent envelope (``yoetz.consent-envelope/1``).

    ``unknown_members`` keeps every member this release does not know, as ``(parent, name,
    canonical value text)`` with ``parent`` empty at the top level; ``unknown_paths`` names those
    and every known field holding a value this release does not know. Both stay in the canonical
    form, so nothing unknown is ever dropped from what is compared.
    """

    endpoint: EndpointIdentity
    principal: Principal
    key_scope: frozenset[str]
    level: str
    required_min: str | None
    code_sync: CodeSync | None
    retention: Retention | None
    exclusions: frozenset[str]
    review: ReviewEgress
    disclosure_version: int
    unknown_members: tuple[tuple[str, str, str], ...] = ()
    unknown_paths: frozenset[str] = field(default=frozenset())


@dataclass(frozen=True, slots=True)
class EnvelopeComparison:
    """The typed result of ``compare``.

    ``widened`` names the fields the current envelope sends or keeps more of; ``changed`` the
    fields that differ without an order (an endpoint, a principal, a disclosure version, or two
    retentions such as ``task_close`` and ``days:N``); ``unknown`` the unknown paths of either
    envelope; ``coverage_reduced`` the narrowed fields that reduce what checks and reviews can see
    (``level``, ``code_sync``, ``exclusions``, ``review``), for a receipt to name.
    """

    verdict: Verdict
    widened: frozenset[str] = frozenset()
    changed: frozenset[str] = frozenset()
    unknown: frozenset[str] = frozenset()
    coverage_reduced: frozenset[str] = frozenset()


# --- parsing -------------------------------------------------------------------------------------


def _object(value: JsonValue, reason: str) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise EnvelopeError(reason)
    return cast(Mapping[str, JsonValue], value)


def _member(source: Mapping[str, JsonValue], name: str) -> JsonValue:
    if name not in source:
        raise EnvelopeError("envelope_field_missing")
    return source[name]


def _unknown(
    source: Mapping[str, JsonValue], known: tuple[str, ...], parent: str
) -> list[tuple[str, str, str]]:
    found: list[tuple[str, str, str]] = []
    for name, value in source.items():
        if name in known:
            continue
        if type(name) is not str or not _MEMBER.match(name):
            raise EnvelopeError("envelope_member_invalid")
        try:
            text = canonical_encode(value).decode("utf-8")
        except ProtocolValueError:
            raise EnvelopeError("envelope_member_invalid") from None
        found.append((parent, name, text))
    return found


def _token(value: JsonValue, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if type(value) is not str or not _TOKEN.match(value):
        raise EnvelopeError("envelope_field_invalid")
    return value


def _required_token(value: JsonValue) -> str:
    token = _token(value)
    assert token is not None
    return token


def _string_set(value: JsonValue, *, pattern: bool = False) -> frozenset[str]:
    if not isinstance(value, list):
        raise EnvelopeError("envelope_field_invalid")
    items = cast(list[JsonValue], value)
    if len(items) > _SET_LIMIT:
        raise EnvelopeError("envelope_field_invalid")
    result: set[str] = set()
    for item in items:
        if pattern:
            if (
                type(item) is not str
                or not item
                or len(item) > _PATTERN_LIMIT
                or any(ord(character) < 0x20 or ord(character) == 0x7F for character in item)
            ):
                raise EnvelopeError("envelope_field_invalid")
            text = item
        else:
            text = _required_token(item)
        if text in result:
            raise EnvelopeError("envelope_field_invalid")
        result.add(text)
    return frozenset(result)


def _count(value: JsonValue, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise EnvelopeError("envelope_field_invalid")
    return value


def _endpoint(
    value: JsonValue, unknown: list[tuple[str, str, str]], paths: set[str]
) -> EndpointIdentity:
    source = _object(value, "envelope_field_invalid")
    unknown.extend(_unknown(source, _ENDPOINT_FIELDS, "endpoint"))
    kind = _required_token(_member(source, "kind"))
    if kind not in ENDPOINT_KINDS:
        paths.add("endpoint.kind")
    origin = _member(source, "origin")
    if (
        type(origin) is not str
        or not origin
        or len(origin) > _ORIGIN_LIMIT
        or any(ord(character) <= 0x20 or ord(character) >= 0x7F for character in origin)
    ):
        raise EnvelopeError("envelope_field_invalid")
    identity_type = _required_token(_member(source, "identity_type"))
    identity = _member(source, "identity")
    if identity is not None and (type(identity) is not str or not _IDENTITY.match(identity)):
        raise EnvelopeError("envelope_field_invalid")
    if identity_type not in IDENTITY_TYPES:
        paths.add("endpoint.identity_type")
    elif (identity_type == "tls_system_ca") != (identity is None):
        # The system store is named by no digest; a pin, a CA file or a host key always is.
        raise EnvelopeError("envelope_field_invalid")
    return EndpointIdentity(kind, origin, identity_type, identity)


def _principal(value: JsonValue, unknown: list[tuple[str, str, str]]) -> Principal:
    source = _object(value, "envelope_field_invalid")
    unknown.extend(_unknown(source, _PRINCIPAL_FIELDS, "principal"))
    return Principal(
        _token(_member(source, "key_id"), nullable=True),
        _token(_member(source, "principal"), nullable=True),
    )


def _level(value: JsonValue, path: str, paths: set[str], *, nullable: bool) -> str | None:
    level = _token(value, nullable=nullable)
    if level is not None and level not in LEVELS:
        paths.add(path)
    return level


def _code_sync(value: JsonValue, unknown: list[tuple[str, str, str]]) -> CodeSync | None:
    if value is None:
        return None
    source = _object(value, "envelope_field_invalid")
    unknown.extend(_unknown(source, _CODE_SYNC_FIELDS, "code_sync"))
    methods = _string_set(_member(source, "methods"))
    if not methods:
        raise EnvelopeError("envelope_field_invalid")
    limit = 2**53 - 1
    return CodeSync(
        methods,
        _count(_member(source, "max_repo_bytes"), minimum=0, maximum=limit),
        _count(_member(source, "max_file_bytes"), minimum=0, maximum=limit),
    )


def _retention(
    value: JsonValue, unknown: list[tuple[str, str, str]], paths: set[str]
) -> Retention | None:
    if value is None:
        return None
    source = _object(value, "envelope_field_invalid")
    unknown.extend(_unknown(source, _RETENTION_FIELDS, "retention"))
    kind = _required_token(_member(source, "kind"))
    days_value = _member(source, "days")
    if kind not in RETENTION_KINDS:
        paths.add("retention.kind")
        days = None if days_value is None else _count(days_value, minimum=1, maximum=_MAX_DAYS)
    elif kind == "days":
        days = _count(days_value, minimum=1, maximum=_MAX_DAYS)
    elif days_value is not None:
        raise EnvelopeError("envelope_field_invalid")
    else:
        days = None
    return Retention(kind, days)


def _review(value: JsonValue, unknown: list[tuple[str, str, str]], paths: set[str]) -> ReviewEgress:
    source = _object(value, "envelope_field_invalid")
    unknown.extend(_unknown(source, _REVIEW_FIELDS, "review"))
    ai_review = _required_token(_member(source, "ai_review"))
    disclosure = _token(_member(source, "provider_disclosure"), nullable=True)
    fallback = _token(_member(source, "fallback_disclosure"), nullable=True)
    if fallback is not None and disclosure is None:
        # A fallback is the provider used when the first one fails: there is a first one.
        raise EnvelopeError("envelope_field_invalid")
    if ai_review not in AI_REVIEW_VALUES:
        paths.add("review.ai_review")
    elif ai_review == "none" and disclosure is not None:
        # No review egress names no provider; one canonical form for "nothing is sent".
        raise EnvelopeError("envelope_field_invalid")
    return ReviewEgress(ai_review, disclosure, fallback)


def parse_shared_member(name: str, value: JsonValue) -> CodeSync | Retention | ReviewEgress | None:
    """Parse one member the server profile shares with the envelope, strictly.

    ``name`` is ``code_sync``, ``retention`` or ``review``. Anything this release does not know
    (an unknown member or enumerated value) raises ``EnvelopeError("envelope_value_unknown")``:
    unlike an envelope, a profile with anything unknown in a shared member is refused outright.
    """

    unknown: list[tuple[str, str, str]] = []
    paths: set[str] = set()
    parsed: CodeSync | Retention | ReviewEgress | None
    if name == "code_sync":
        parsed = _code_sync(value, unknown)
    elif name == "retention":
        parsed = _retention(value, unknown, paths)
    elif name == "review":
        parsed = _review(value, unknown, paths)
    else:
        raise EnvelopeError("envelope_member_invalid")
    if unknown or paths:
        raise EnvelopeError("envelope_value_unknown")
    return parsed


def envelope_from_json(value: JsonValue | bytes) -> ConsentEnvelope:
    """Parse one envelope from its JSON value (or strict JSON bytes); malformed raises.

    Strict for every known member (present, typed and bounded); an unknown member or enumerated
    value is kept and named in ``unknown_paths``, never dropped.
    """

    if isinstance(value, bytes):
        if len(value) > _MAX_ENVELOPE_BYTES:
            raise EnvelopeError("envelope_too_large")
        try:
            value = strict_json_parse(value)
        except ProtocolValueError:
            raise EnvelopeError("envelope_not_json") from None
    source = _object(value, "envelope_not_object")
    if _member(source, "schema") != ENVELOPE_SCHEMA:
        raise EnvelopeError("envelope_schema_invalid")
    unknown = _unknown(source, _TOP_FIELDS, "")
    paths: set[str] = set()
    envelope = ConsentEnvelope(
        endpoint=_endpoint(_member(source, "endpoint"), unknown, paths),
        principal=_principal(_member(source, "principal"), unknown),
        key_scope=_string_set(_member(source, "key_scope")),
        level=cast(str, _level(_member(source, "level"), "level", paths, nullable=False)),
        required_min=_level(_member(source, "required_min"), "required_min", paths, nullable=True),
        code_sync=_code_sync(_member(source, "code_sync"), unknown),
        retention=_retention(_member(source, "retention"), unknown, paths),
        exclusions=_string_set(_member(source, "exclusions"), pattern=True),
        review=_review(_member(source, "review"), unknown, paths),
        disclosure_version=_count(
            _member(source, "disclosure_version"), minimum=1, maximum=2**31 - 1
        ),
        unknown_members=tuple(sorted(unknown)),
        unknown_paths=frozenset(
            paths | {name if not parent else f"{parent}.{name}" for parent, name, _ in unknown}
        ),
    )
    if len(canonical_bytes(envelope)) > _MAX_ENVELOPE_BYTES:
        raise EnvelopeError("envelope_too_large")
    return envelope


# --- canonical form ------------------------------------------------------------------------------


def _sorted(values: frozenset[str]) -> list[JsonValue]:
    return list(sorted(values, key=str.encode))


def code_sync_to_json(code_sync: CodeSync | None) -> JsonValue:
    """``code_sync`` in the envelope's canonical shape (shared with the server profile)."""

    if code_sync is None:
        return None
    return {
        "methods": _sorted(code_sync.methods),
        "max_repo_bytes": code_sync.max_repo_bytes,
        "max_file_bytes": code_sync.max_file_bytes,
    }


def retention_to_json(retention: Retention | None) -> JsonValue:
    """``retention`` in the envelope's canonical shape (shared with the server profile)."""

    if retention is None:
        return None
    return {"kind": retention.kind, "days": retention.days}


def retention_from_token(token: object) -> Retention:
    """The retention a written token names: ``task_close``, ``until_forgotten`` or ``days:N``.

    ``N`` is a whole number of days from 1 to 36,500 written without a sign or leading zeros, the
    bounds the envelope itself admits, so a token this accepts is always a retention a profile
    and a consent can carry. The one parser behind ``--retention`` and ``[server.code_copy]``.
    Raises ``EnvelopeError("retention_token_invalid")``.
    """

    if type(token) is str:
        if token in {"task_close", "until_forgotten"}:
            return Retention(token, None)
        found = _DAYS_TOKEN.fullmatch(token)
        if found is not None and int(found.group(1)) <= _MAX_DAYS:
            return Retention("days", int(found.group(1)))
    raise EnvelopeError("retention_token_invalid")


def review_to_json(review: ReviewEgress) -> dict[str, JsonValue]:
    """``review`` in the envelope's canonical shape (shared with the server profile)."""

    return {
        "ai_review": review.ai_review,
        "provider_disclosure": review.provider_disclosure,
        "fallback_disclosure": review.fallback_disclosure,
    }


def exclusions_to_json(exclusions: frozenset[str]) -> list[JsonValue]:
    """Exclusion patterns in the envelope's canonical shape: byte-sorted, exact strings."""

    return _sorted(exclusions)


def envelope_to_json(envelope: ConsentEnvelope) -> dict[str, JsonValue]:
    """The envelope as a JSON object: sets as byte-sorted arrays, explicit nulls, unknown members
    restored where they were found."""

    endpoint = envelope.endpoint
    document: dict[str, JsonValue] = {
        "schema": ENVELOPE_SCHEMA,
        "endpoint": {
            "kind": endpoint.kind,
            "origin": endpoint.origin,
            "identity_type": endpoint.identity_type,
            "identity": endpoint.identity,
        },
        "principal": {
            "key_id": envelope.principal.key_id,
            "principal": envelope.principal.principal,
        },
        "key_scope": _sorted(envelope.key_scope),
        "level": envelope.level,
        "required_min": envelope.required_min,
        "code_sync": code_sync_to_json(envelope.code_sync),
        "retention": retention_to_json(envelope.retention),
        "exclusions": exclusions_to_json(envelope.exclusions),
        "review": review_to_json(envelope.review),
        "disclosure_version": envelope.disclosure_version,
    }
    for parent, name, text in envelope.unknown_members:
        restored = strict_json_parse(text.encode("utf-8"))
        if not parent:
            document[name] = restored
            continue
        holder = document.get(parent)
        if isinstance(holder, dict):
            holder[name] = restored
    return document


def canonical_bytes(envelope: ConsentEnvelope) -> bytes:
    """The envelope's canonical encoding (``protocol.canonical``)."""

    return canonical_encode(envelope_to_json(envelope))


def envelope_digest(envelope: ConsentEnvelope) -> str:
    """``sha256:<hex>`` over the domain-separated canonical bytes."""

    digest = hashlib.sha256(_DIGEST_DOMAIN + canonical_bytes(envelope)).hexdigest()
    return f"sha256:{digest}"


def consentable(envelope: ConsentEnvelope) -> bool:
    """Whether an owner may agree to this envelope: never with anything unknown in it."""

    return not envelope.unknown_paths


# --- the partial order ---------------------------------------------------------------------------


def _rank(level: str | None) -> int:
    return 0 if level is None else LEVELS.index(level) + 1


def _subset_order(narrow: frozenset[str], wide: frozenset[str]) -> FieldOrder:
    if narrow == wide:
        return "equal"
    if narrow < wide:
        return "narrower"
    if narrow > wide:
        return "wider"
    return "incomparable"


def _equal_only(current: object, consented: object) -> FieldOrder:
    return "equal" if current == consented else "incomparable"


def _ranked(current: int, consented: int) -> FieldOrder:
    if current == consented:
        return "equal"
    return "narrower" if current < consented else "wider"


def _level_order(current: ConsentEnvelope, consented: ConsentEnvelope) -> FieldOrder:
    return _ranked(_rank(current.level), _rank(consented.level))


def _required_min_order(current: ConsentEnvelope, consented: ConsentEnvelope) -> FieldOrder:
    # A server that requires less asks no more of this computer; one that requires more is asked
    # about again, even within the level agreed (``compare`` refuses one beyond it).
    return _ranked(_rank(current.required_min), _rank(consented.required_min))


def _code_sync_order(current: ConsentEnvelope, consented: ConsentEnvelope) -> FieldOrder:
    now, then = current.code_sync, consented.code_sync
    if now == then:
        return "equal"
    if now is None:
        return "narrower"
    if then is None:
        return "wider"
    if (
        now.methods <= then.methods
        and now.max_repo_bytes <= then.max_repo_bytes
        and now.max_file_bytes <= then.max_file_bytes
    ):
        return "narrower"
    if (
        now.methods >= then.methods
        and now.max_repo_bytes >= then.max_repo_bytes
        and now.max_file_bytes >= then.max_file_bytes
    ):
        return "wider"
    return "incomparable"


def _retention_leq(narrow: Retention | None, wide: Retention | None) -> bool:
    # Nothing kept is below everything; until the owner forgets is the top. ``task_close`` and
    # ``days:N`` are incomparable: a long task can outlive any number of days.
    if narrow is None:
        return True
    if wide is None:
        return False
    if narrow == wide or wide.kind == "until_forgotten":
        return narrow.kind in RETENTION_KINDS
    if narrow.kind == "days" and wide.kind == "days":
        return cast(int, narrow.days) <= cast(int, wide.days)
    return False


def _retention_order(current: ConsentEnvelope, consented: ConsentEnvelope) -> FieldOrder:
    now, then = current.retention, consented.retention
    if now == then:
        return "equal"
    if _retention_leq(now, then):
        return "narrower"
    if _retention_leq(then, now):
        return "wider"
    return "incomparable"


def _exclusions_order(current: ConsentEnvelope, consented: ConsentEnvelope) -> FieldOrder:
    # More exclusions send less, compared as exact pattern strings: no pattern is read as
    # covering another.
    return _subset_order(consented.exclusions, current.exclusions)


def _review_order(current: ConsentEnvelope, consented: ConsentEnvelope) -> FieldOrder:
    now, then = current.review, consented.review
    if now == then:
        return "equal"
    if now.ai_review == "none" and then.ai_review == "server_policy":
        return "narrower"
    if now.ai_review == "server_policy" and then.ai_review == "none":
        return "wider"
    # Another provider, a fallback added, removed or swapped with the first: asked again.
    return "incomparable"


# Each field's order, in the order they are reported. ``endpoint``, ``principal`` and
# ``disclosure_version`` are equal or asked about again; ``key_scope`` narrows by subset only.
FIELD_ORDERS: Final[
    tuple[tuple[str, Callable[[ConsentEnvelope, ConsentEnvelope], FieldOrder]], ...]
] = (
    ("endpoint", lambda now, then: _equal_only(now.endpoint, then.endpoint)),
    ("principal", lambda now, then: _equal_only(now.principal, then.principal)),
    ("key_scope", lambda now, then: _subset_order(now.key_scope, then.key_scope)),
    ("level", _level_order),
    ("required_min", _required_min_order),
    ("code_sync", _code_sync_order),
    ("retention", _retention_order),
    ("exclusions", _exclusions_order),
    ("review", _review_order),
    (
        "disclosure_version",
        lambda now, then: _equal_only(now.disclosure_version, then.disclosure_version),
    ),
)
# The fields whose narrowing reduces what a check or a review can see, so a receipt can say so.
_COVERAGE_FIELDS: Final = frozenset({"level", "code_sync", "exclusions", "review"})


def _orders(current: ConsentEnvelope, consented: ConsentEnvelope) -> dict[str, FieldOrder]:
    return {name: order(current, consented) for name, order in FIELD_ORDERS}


def precedes(narrow: ConsentEnvelope, wide: ConsentEnvelope) -> bool:
    """``narrow ⊑ wide``: ``narrow`` sends or keeps no more than ``wide``, field by field.

    An envelope with anything unknown in it is ordered only with itself.
    """

    if narrow.unknown_paths or wide.unknown_paths:
        return canonical_bytes(narrow) == canonical_bytes(wide)
    return all(order in {"equal", "narrower"} for order in _orders(narrow, wide).values())


def compare(consented: ConsentEnvelope, current: ConsentEnvelope) -> EnvelopeComparison:
    """The verdict on ``current`` against what the owner ``consented`` to.

    Anything unknown in either envelope asks again. A server requiring a level above the one
    agreed is ``level_unavailable``. Otherwise identical canonical bytes are ``same``, a current
    envelope below the consented one is ``narrower``, and anything else asks again.
    """

    unknown = consented.unknown_paths | current.unknown_paths
    if unknown:
        return EnvelopeComparison("ask_again", unknown=unknown)
    if _rank(current.required_min) > _rank(consented.level):
        return EnvelopeComparison("level_unavailable", widened=frozenset({"required_min"}))
    if canonical_bytes(current) == canonical_bytes(consented):
        return EnvelopeComparison("same")
    orders = _orders(current, consented)
    widened = frozenset(name for name, order in orders.items() if order == "wider")
    changed = frozenset(name for name, order in orders.items() if order == "incomparable")
    if widened or changed:
        return EnvelopeComparison("ask_again", widened=widened, changed=changed)
    narrowed = frozenset(name for name, order in orders.items() if order == "narrower")
    return EnvelopeComparison("narrower", coverage_reduced=narrowed & _COVERAGE_FIELDS)
