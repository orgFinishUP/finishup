"""This client's consent to a server's profile, and the check every connection makes (ADR-052).

Design v2 sections 2.3 and 8.2: the client records what the owner consented to on the trusted
console, compares it with the server's current profile before every connection, adjusts quietly
when the server now asks for less, and refuses before anything is sent when it asks for more or
for something else.

Three owner-only records beneath a remote target's root:

* ``target.json`` (``yoetz.server-target/2``): the consent summary (``targets.ServerConsent``):
  level, the profile digest and revision, retention, the consented envelope's digest, and whether
  a narrowing adjusted it.
* ``config/consent-envelope.json``: the consented envelope itself (``protocol.consent_envelope``,
  canonical, ``yoetz.consent-envelope/1``), bound to the record by its digest. Written only by the
  owner's consent on the trusted console and by a narrowing adjustment.
* ``state/server-profile.json`` (``yoetz.server-profile-cache/1``): the last profile fetched from
  the server, with the endpoint identity the transport observed while fetching it (never what the
  server says of itself). Written by whoever fetches a profile (``server add`` and ``server use``
  here; the helper from layer 4). Hooks only read it.

``consent_verdict`` (hook-safe: file reads only) builds the current envelope from the cached
profile and compares it with the consented one (``consent_envelope.compare``):

* ``same`` or ``narrower``: admitted, and the connection names the cached profile's revision in
  its hello (the server refuses any other); a narrower one says which coverage it reduces;
* ``level_unavailable`` (the server requires more than the owner agreed to):
  ``server_level_unavailable``;
* anything else (wider, changed, unknown, a revision from another issuer, or a record that is
  missing, unreadable or inconsistent): ``server_profile_changed``. Only the owner agrees again,
  on the trusted console.

``refresh_profile`` records a newly fetched profile only while what it was fetched under still
holds (``FetchBasis``, read before the key was: the target's identity and its credential
generation), so a fetch made with a key the owner has since replaced, logged out or removed is
never recorded for the key stored now; on a narrowing it adjusts the stored consent
down to it (stricter: a later widening, even back to what the owner once confirmed, asks again)
and keeps the notice ``server status`` shows (``server_profile_narrowed``); on the same offer under
a new revision it records only the revision. It changes only the consent of the record as stored
now, under the registry lock (SRV-12). A narrower profile is cached only after the reduced consent
is committed (the envelope, then the record): readers never admit the narrower revision under the
broader consent, so a refresh that stops part way can never let the broader offer back as
``same`` later. Stopping between the two consent writes leaves them disagreeing, which refuses
(``server_profile_changed``) until the owner agrees again; stopping after them leaves the older
cache, wider than the consent now, which refuses until the next refresh records the profile.

``PROFILE_SOURCES`` holds SSH (``service profile --json`` on the server, fetched over OpenSSH by
``server add``, ``server use`` and the target's helper) and HTTPS and ``local_port``
(``GET /v1/server``, layer 5).
"""

from __future__ import annotations

import os
import secrets
import stat
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol, cast

from finishup.client.targets import (
    DISCLOSURE_VERSION,
    ServerConsent,
    ServerTarget,
    TargetError,
    read_target,
    target_root,
    write_target,
)
from finishup.config.installation import format_rfc3339_ms, parse_rfc3339_ms
from finishup.config.paths import PathSafetyError, ensure_owner_only_dir
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.consent_envelope import (
    LEVELS,
    ConsentEnvelope,
    EndpointIdentity,
    EnvelopeError,
    Retention,
    canonical_bytes,
    compare,
    consentable,
    envelope_digest,
    envelope_from_json,
)
from finishup.protocol.server_profile import (
    ProfileError,
    ServerProfile,
    ServerProfileRevision,
    envelope_for,
    profile_from_json,
    profile_to_json,
)

if TYPE_CHECKING:
    from finishup.protocol.consent_envelope import EnvelopeComparison

__all__ = [
    "CACHE_NAME",
    "CACHE_SCHEMA",
    "ENVELOPE_NAME",
    "PROFILE_SOURCES",
    "ConsentVerdict",
    "FetchBasis",
    "FetchedProfile",
    "ProfileSource",
    "consent_verdict",
    "consented_endpoint_identity",
    "consented_host_key",
    "endpoint_origin",
    "fetch_basis",
    "forget_cached_profile",
    "read_cached_profile",
    "read_consented_envelope",
    "record_consent",
    "refresh_profile",
    "styles_offered",
]

CACHE_NAME: Final = "server-profile.json"
CACHE_SCHEMA: Final = "yoetz.server-profile-cache/1"
ENVELOPE_NAME: Final = "consent-envelope.json"
_MAX_FILE_BYTES: Final = 131_072
_PROFILE_CHANGED: Final = "server_profile_changed"
_LEVEL_UNAVAILABLE: Final = "server_level_unavailable"


@dataclass(frozen=True, slots=True)
class FetchedProfile:
    """A profile as fetched, with the endpoint identity the transport itself observed.

    ``identity_type`` is ``ssh_host_key`` (OpenSSH's pinned host key), ``tls_pin``,
    ``tls_ca_file`` or ``tls_system_ca``; ``identity`` its ``sha256:`` digest (``None`` for the
    system store). The server never supplies either.
    """

    document: bytes
    identity_type: str
    identity: str | None


@dataclass(frozen=True, slots=True)
class FetchBasis:
    """What a profile fetch was made under, read before its key was read: the target's identity
    (``authorization.identity_digest``) and its credential generation."""

    identity: str
    credential: object


def fetch_basis(record: ServerTarget) -> FetchBasis:
    """The basis a fetch for ``record`` starts from now (read it before the key). Never raises
    for an unreadable generation: it then equals no later one."""

    from finishup.client.authorization import credential_generation, identity_digest

    return FetchBasis(identity_digest(record), credential_generation(target_root(record.target_id)))


def _basis_holds(stored: ServerTarget, basis: FetchBasis) -> bool:
    from finishup.client.authorization import credential_generation, identity_digest

    return (
        identity_digest(stored) == basis.identity
        and credential_generation(target_root(stored.target_id)) == basis.credential
    )


class ProfileSource(Protocol):
    """Fetches the profile of one remote target over its own transport (layers 4 and 5)."""

    def fetch(self, record: ServerTarget) -> FetchedProfile: ...


def _ssh_source() -> ProfileSource:
    # Loaded only when a profile is fetched (never on a hook's path, design v2 section 8.9).
    from finishup.client.ssh_discovery import SshProfileSource

    return SshProfileSource()


def _rest_source() -> ProfileSource:
    # Loaded only when a profile is fetched (never on a hook's path, design v2 section 8.9).
    from finishup.client.rest_discovery import RestProfileSource

    return RestProfileSource()


# The profile source of each remote kind: SSH (``service profile --json`` on the server, over
# OpenSSH) and, over REST v1 (layer 5, ADR-053), HTTPS and ``local_port`` (``GET /v1/server``).
PROFILE_SOURCES: Final[dict[str, Callable[[], ProfileSource]]] = {
    "ssh": _ssh_source,
    "https": _rest_source,
    "local_port": _rest_source,
}


@dataclass(frozen=True, slots=True)
class ConsentVerdict:
    """The consent step's answer for one remote target (see the module text).

    ``phase`` is ``None`` when a connection may be made, under ``revision``; else the closed
    refusal. ``coverage_reduced`` names what a narrower profile no longer covers.
    """

    phase: str | None
    revision: ServerProfileRevision | None = None
    narrowed: bool = False
    coverage_reduced: frozenset[str] = frozenset()


# The connection styles each server edge offers (design v2 section 1.2): a server reached through
# its owner-only control socket over SSH offers the relay and the direct style.
_STYLES_BY_EDGE: Final[dict[str, tuple[str, ...]]] = {
    "ssh-control": ("relay", "direct"),
    # REST v1 over HTTPS (ADR-053): the helper's REST upstream, or each process's own stream.
    "rest-1": ("relay", "direct"),
}
# The edge each remote kind reaches the server through: only that edge's styles are offered.
_EDGE_OF_KIND: Final[dict[str, str]] = {
    "ssh": "ssh-control",
    "https": "rest-1",
    "local_port": "rest-1",
}


def styles_offered(record: ServerTarget) -> tuple[str, ...]:
    """The connection styles the last profile fetched for ``record`` offers; ``()`` for none.

    The owner may choose only among these (``finishup server set NAME --style``). A target with
    no readable profile offers none. File reads only.
    """

    try:
        cached = read_cached_profile(target_root(record.target_id))
    except Exception:  # noqa: BLE001 - a profile that cannot be read offers nothing
        return ()
    edge_of_kind = _EDGE_OF_KIND.get(record.kind)
    if cached is None or edge_of_kind is None:
        return ()
    offered: list[str] = []
    for edge in cached.profile.edges:
        if edge != edge_of_kind:
            continue
        for style in _STYLES_BY_EDGE.get(edge, ()):
            if style not in offered:
                offered.append(style)
    return tuple(offered)


def endpoint_origin(record: ServerTarget) -> str:
    """The canonical origin of a remote target, from its own record (design v2 section 8.8)."""

    if record.kind == "ssh":
        user = "" if record.user is None else f"{record.user}@"
        host = cast(str, record.host)
        authority = f"[{host}]" if ":" in host else host
        return f"ssh://{user}{authority}:{record.port}{record.remote_root or ''}"
    return cast(str, record.base_url)


def _endpoint(record: ServerTarget, identity_type: str, identity: str | None) -> EndpointIdentity:
    return EndpointIdentity(record.kind, endpoint_origin(record), identity_type, identity)


# --- owner-only files -------------------------------------------------------------------------


def _read(path: Path) -> bytes | None:
    """An owner-only regular file's bytes; ``None`` when absent or unsafe (never follows)."""

    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        facts = os.fstat(descriptor)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != os.geteuid()
            or stat.S_IMODE(facts.st_mode) & 0o077
            or facts.st_size > _MAX_FILE_BYTES
        ):
            return None
        chunks: list[bytes] = []
        remaining = _MAX_FILE_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError:
        return None
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    return None if len(data) > _MAX_FILE_BYTES else data


def _write(path: Path, encoded: bytes) -> None:
    """Replace ``path`` atomically with an owner-only file; raises ``TargetError`` on failure."""

    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    try:
        ensure_owner_only_dir(path.parent)
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
        )
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short_write")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
    except (OSError, PathSafetyError):
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise TargetError("target_root_unsafe") from None


def _cache_path(root: Path) -> Path:
    return root / "state" / CACHE_NAME


def _envelope_path(root: Path) -> Path:
    return root / "config" / ENVELOPE_NAME


@dataclass(frozen=True, slots=True)
class _Cached:
    profile: ServerProfile
    identity_type: str
    identity: str | None
    fetched_at: str


def _encode_cache(fetched: _Cached) -> bytes:
    document: dict[str, JsonValue] = {
        "schema": CACHE_SCHEMA,
        "fetched_at": fetched.fetched_at,
        "endpoint": {"identity_type": fetched.identity_type, "identity": fetched.identity},
        "profile": profile_to_json(fetched.profile),
    }
    return canonical_encode(document) + b"\n"


def read_cached_profile(root: Path) -> _Cached | None:
    """The last profile fetched for the target at ``root``; ``None`` when absent or unusable."""

    encoded = _read(_cache_path(root))
    if encoded is None or not encoded.endswith(b"\n"):
        return None
    try:
        value = strict_json_parse(encoded[:-1])
        if type(value) is not dict:
            return None
        source = cast(dict[str, JsonValue], value)
        if set(source) != {"schema", "fetched_at", "endpoint", "profile"}:
            return None
        if source["schema"] != CACHE_SCHEMA:
            return None
        endpoint = source["endpoint"]
        if type(endpoint) is not dict or set(cast(dict[str, JsonValue], endpoint)) != {
            "identity_type",
            "identity",
        }:
            return None
        identity_type = cast(dict[str, JsonValue], endpoint)["identity_type"]
        identity = cast(dict[str, JsonValue], endpoint)["identity"]
        fetched_at = source["fetched_at"]
        if type(identity_type) is not str or (identity is not None and type(identity) is not str):
            return None
        if type(fetched_at) is not str:
            return None
        parse_rfc3339_ms(fetched_at)
        cached = _Cached(profile_from_json(source["profile"]), identity_type, identity, fetched_at)
    except (ValueError, TypeError, ProfileError):
        return None
    return cached if _encode_cache(cached) == encoded else None


def read_consented_envelope(root: Path, consent: ServerConsent) -> ConsentEnvelope | None:
    """The consented envelope, only when it is the one ``consent`` names; else ``None``."""

    encoded = _read(_envelope_path(root))
    if encoded is None or not encoded.endswith(b"\n"):
        return None
    try:
        envelope = envelope_from_json(encoded[:-1])
    except EnvelopeError:
        return None
    if canonical_bytes(envelope) + b"\n" != encoded or not consentable(envelope):
        return None
    if envelope_digest(envelope) != consent.envelope_digest:
        return None
    return envelope


# --- the verdict --------------------------------------------------------------------------------


def _rank(level: str) -> int:
    return LEVELS.index(level)


def _retention_of(consent: ServerConsent) -> Retention | None:
    if consent.retention_kind is None:
        return None
    return Retention(consent.retention_kind, consent.retention_days)


def _current_envelope(
    record: ServerTarget, consent: ServerConsent, cached: _Cached
) -> ConsentEnvelope | str:
    """The envelope of using the cached profile within the consent, or the refusal it gives."""

    profile = cached.profile
    within = [level for level in profile.levels.offered if _rank(level) <= _rank(consent.level)]
    if not within:
        # Every level the server offers now is above the one agreed: never a silent upgrade.
        return _LEVEL_UNAVAILABLE
    level = within[-1]
    retention = _retention_of(consent) if level == "L2" else None
    try:
        return envelope_for(
            profile,
            endpoint=_endpoint(record, cached.identity_type, cached.identity),
            level=level,
            retention=retention,
            disclosure_version=DISCLOSURE_VERSION,
        )
    except (ProfileError, EnvelopeError):
        return _PROFILE_CHANGED


def _verdict_of(comparison: EnvelopeComparison, revision: ServerProfileRevision) -> ConsentVerdict:
    if comparison.verdict == "same":
        return ConsentVerdict(None, revision)
    if comparison.verdict == "narrower":
        return ConsentVerdict(
            None, revision, narrowed=True, coverage_reduced=comparison.coverage_reduced
        )
    if comparison.verdict == "level_unavailable":
        return ConsentVerdict(_LEVEL_UNAVAILABLE)
    return ConsentVerdict(_PROFILE_CHANGED)


def consented_host_key(root: Path) -> str | None:
    """The SSH host key the owner's consent for the target at ``root`` is bound to, or ``None``.

    The ``sha256:`` digest the consented envelope's endpoint names (``ssh_host_key``): every new
    OpenSSH connection to that target must have verified exactly this key before anything is
    sent over it (``client.ssh_transport``). ``None`` when the record, its consent or the
    envelope cannot be read, or names no SSH host key: a transport then refuses (fail closed).
    Never raises; file reads only.
    """

    try:
        record = read_target(root)
        if record is None or record.kind != "ssh" or record.consent is None:
            return None
        envelope = read_consented_envelope(root, record.consent)
    except Exception:  # noqa: BLE001 - a consent that cannot be read verifies nothing
        return None
    if envelope is None or envelope.endpoint.identity_type != "ssh_host_key":
        return None
    return envelope.endpoint.identity


def consented_endpoint_identity(root: Path) -> tuple[str, str | None] | None:
    """The endpoint identity the owner's consent for the target at ``root`` is bound to.

    ``(identity_type, identity)`` of the consented envelope's endpoint: for an HTTPS or port
    target, ``tls_pin`` and the pin, ``tls_ca_file`` and the ``sha256:`` of the CA file's bytes,
    or ``tls_system_ca`` and ``None``. A transport compares it with the trust it actually loaded
    before any credential is sent (``client.rest_client``). ``None`` when the record, its consent
    or the envelope cannot be read (fail closed). Never raises; file reads only.
    """

    try:
        record = read_target(root)
        if record is None or record.consent is None:
            return None
        envelope = read_consented_envelope(root, record.consent)
    except Exception:  # noqa: BLE001 - a consent that cannot be read binds nothing
        return None
    if envelope is None:
        return None
    return envelope.endpoint.identity_type, envelope.endpoint.identity


def consent_verdict(record: ServerTarget) -> ConsentVerdict:
    """The consent step for remote ``record`` (see the module text). Never raises; reads only."""

    consent = record.consent
    if consent is None:
        return ConsentVerdict(_PROFILE_CHANGED)
    try:
        root = target_root(record.target_id)
        consented = read_consented_envelope(root, consent)
        cached = read_cached_profile(root)
    except Exception:  # noqa: BLE001 - a consent that cannot be read is no consent
        return ConsentVerdict(_PROFILE_CHANGED)
    if consented is None or cached is None:
        return ConsentVerdict(_PROFILE_CHANGED)
    return _verdict_against(record, consent, consented, cached)


def _verdict_against(
    record: ServerTarget, consent: ServerConsent, consented: ConsentEnvelope, cached: _Cached
) -> ConsentVerdict:
    """``consent_verdict`` for a given consented envelope and profile (cached or just fetched)."""

    if cached.profile.revision.issuer != consent.issuer:
        # Another issuer is another server installation's revisions (its state was made anew):
        # whatever it offers, the owner agrees again.
        return ConsentVerdict(_PROFILE_CHANGED)
    current = _current_envelope(record, consent, cached)
    if isinstance(current, str):
        return ConsentVerdict(current)
    return _verdict_of(compare(consented, current), cached.profile.revision)


# --- the owner's consent and a refreshed profile -------------------------------------------------


def _now() -> str:
    return format_rfc3339_ms(datetime.now(UTC))


def _cached_from(fetched: FetchedProfile, now: str) -> _Cached:
    try:
        profile = profile_from_json(fetched.document)
    except ProfileError:
        raise TargetError(_PROFILE_CHANGED) from None
    return _Cached(profile, fetched.identity_type, fetched.identity, now)


def _consent_for(
    envelope: ConsentEnvelope,
    profile: ServerProfile,
    *,
    adjusted_at: str | None = None,
    coverage_reduced: frozenset[str] = frozenset(),
) -> ServerConsent:
    retention = envelope.retention
    return ServerConsent(
        level=envelope.level,
        profile_digest=profile.profile_digest,
        issuer=profile.revision.issuer,
        revision=profile.revision.revision,
        retention_kind=None if retention is None else retention.kind,
        retention_days=None if retention is None else retention.days,
        envelope_digest=envelope_digest(envelope),
        adjusted_at=adjusted_at,
        coverage_reduced=tuple(sorted(coverage_reduced)),
    )


def consent_envelope_for(
    record: ServerTarget, fetched: FetchedProfile, *, level: str, retention: Retention | None
) -> tuple[ConsentEnvelope, ServerProfile]:
    """The envelope the owner is asked to consent to, and the profile it was built from.

    Refuses (``TargetError``) a profile that cannot be read (``server_profile_changed``), a level
    above what the server offers or below what it requires (``server_level_unavailable``), and an
    envelope with anything this release does not understand (``server_profile_changed``).
    """

    cached = _cached_from(fetched, _now())
    profile = cached.profile
    required = profile.levels.required_min
    if level not in profile.levels.offered or (
        required is not None and _rank(required) > _rank(level)
    ):
        raise TargetError(_LEVEL_UNAVAILABLE)
    try:
        envelope = envelope_for(
            profile,
            endpoint=_endpoint(record, fetched.identity_type, fetched.identity),
            level=level,
            retention=retention,
            disclosure_version=DISCLOSURE_VERSION,
        )
    except (ProfileError, EnvelopeError):
        raise TargetError(_PROFILE_CHANGED) from None
    if not consentable(envelope):
        raise TargetError(_PROFILE_CHANGED)
    return envelope, profile


def record_consent(
    record: ServerTarget,
    fetched: FetchedProfile,
    envelope: ConsentEnvelope,
    *,
    now: str | None = None,
    basis: FetchBasis | None = None,
) -> ServerTarget:
    """Record the owner's typed consent to ``envelope`` (built by ``consent_envelope_for``).

    Writes the profile cache, then the consented envelope, then the record (``/2``) with a fresh
    authorization of the current disclosure; returns the record as written. The caller holds the
    registry lock, read the record again under it (SRV-12), and asked on the trusted console.
    With ``basis`` (read before the profile was fetched), nothing is recorded once the target or
    its credential generation changed meanwhile (``TargetError("server_authorization_changed")``):
    a consent to a profile answered to one key is never recorded for another.
    """

    stamp = now or _now()
    cached = _cached_from(fetched, stamp)
    root = target_root(record.target_id)
    if basis is not None and not _basis_holds(record, basis):
        raise TargetError("server_authorization_changed")
    _write(_cache_path(root), _encode_cache(cached))
    _write(_envelope_path(root), canonical_bytes(envelope) + b"\n")
    consented = replace(
        record,
        authorized_at=stamp,
        disclosure_version=DISCLOSURE_VERSION,
        consent=_consent_for(envelope, cached.profile),
    )
    write_target(root, consented)
    return consented


def forget_cached_profile(root: Path) -> None:
    """Remove the target's cached profile: what it says no longer describes this computer's
    credential (a key stored without the server's answer, ``server login``). Until a profile is
    fetched with the key now stored and compared with the consent, the consent step refuses
    (``server_profile_changed``) and nothing is sent. The caller holds the registry lock; raises
    ``TargetError`` when the cache cannot be removed."""

    try:
        _cache_path(root).unlink(missing_ok=True)
    except OSError:
        raise TargetError("target_root_unsafe") from None


def refresh_profile(
    record: ServerTarget,
    fetched: FetchedProfile,
    *,
    now: str | None = None,
    basis: FetchBasis | None = None,
) -> ConsentVerdict:
    """Record a newly fetched profile and adjust the consent to it where that is quiet.

    Compared with the consent as stored now: the same offer under a new revision records the
    revision; a narrower one adjusts the consent down to it and keeps the notice; anything else
    leaves the consent as it is (the next connection is refused and only the owner agrees again).
    The profile is cached last when it narrows the consent, after the reduced consent is
    committed, and first otherwise (see the module text). The caller holds the registry lock.
    Returns the verdict.

    With ``basis`` (a background fetch: the helper's refresh), nothing is recorded unless the
    target is still the one it was fetched for and its credential generation has not moved since
    (a login, logout or remove meanwhile): ``TargetError("server_authorization_changed")``, and
    the profile answered to another key never becomes this one's.
    """

    stamp = now or _now()
    root = target_root(record.target_id)
    cached = _cached_from(fetched, stamp)
    stored = read_target(root)
    if stored is None or stored.target_id != record.target_id:
        raise TargetError("target_unknown")
    if basis is not None and not _basis_holds(stored, basis):
        raise TargetError("server_authorization_changed")
    consent = stored.consent
    try:
        consented = None if consent is None else read_consented_envelope(root, consent)
    except Exception:  # noqa: BLE001 - a consent that cannot be read is no consent
        consented = None
    if consent is None or consented is None:
        verdict = ConsentVerdict(_PROFILE_CHANGED)
    else:
        verdict = _verdict_against(stored, consent, consented, cached)
    if verdict.phase is not None or consent is None:
        # Refused either way: caching it only makes the next connection refuse before the dial.
        _write(_cache_path(root), _encode_cache(cached))
        return verdict
    current = _current_envelope(stored, consent, cached)
    if isinstance(current, str):  # pragma: no cover - the verdict already passed
        return ConsentVerdict(current)
    if verdict.narrowed:
        # Never exposed before the reduced consent is committed: a reader would admit the
        # narrower revision under the broader consent, and a refresh that stopped here would let
        # the broader offer back later as ``same`` (D8).
        reduced = verdict.coverage_reduced | frozenset(consent.coverage_reduced)
        adjusted = _consent_for(
            current, cached.profile, adjusted_at=stamp, coverage_reduced=reduced
        )
        _write(_envelope_path(root), canonical_bytes(current) + b"\n")
        write_target(root, replace(stored, consent=adjusted))
        _write(_cache_path(root), _encode_cache(cached))
        return verdict
    # The same offer: cached first, so a reader never names a revision the server no longer
    # issues; the record then follows it.
    _write(_cache_path(root), _encode_cache(cached))
    if (consent.issuer, consent.revision) != (
        cached.profile.revision.issuer,
        cached.profile.revision.revision,
    ) or consent.profile_digest != cached.profile.profile_digest:
        adjusted = replace(
            consent,
            profile_digest=cached.profile.profile_digest,
            issuer=cached.profile.revision.issuer,
            revision=cached.profile.revision.revision,
        )
        write_target(root, replace(stored, consent=adjusted))
    return verdict
