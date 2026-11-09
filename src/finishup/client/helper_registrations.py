"""Which workspaces the helper of a server elsewhere serves: its registration API (ADR-052).

Design v2 section 8.5: every client process that works with a server elsewhere (an MCP bridge, a
command, the terminal interface) registers, and renews, the workspaces the target's helper is to
serve for it in the background (layer 4 builds the helper; it reads this API). The helper's agent
answers background work; the connection's own agent answers its live calls
(``service.workspace_hub``), so they never compete.

**The record.** ``<target root>/state/registrations/<claim hex>-<worktree hex>-<registrant>.json``
(``yoetz.helper-registration/1``): owner-only canonical JSON, renamed into place, one per
registering process and workspace, at most ``MAX_REGISTRATIONS`` per target. It names the claim,
the worktree on this computer (it never leaves it), the repository's hold key, and what the
registering connection was admitted under: the target's identity and consent digests, the
credential generation, and the server-profile revision its hello named. It holds a lease
(``LEASE_SECONDS``, the helper's idle exit), renewed by its registrant at half-life; an expired
one is removed by whoever reads it.

**Owner authentication.** Only the owner's processes can write beneath an owner-only target root;
every read checks the folder and the file are owner-only, regular, not links, and bounded, and a
record is served only when its claim derives again from its own worktree under the target's own
claim salt (a client secret in ``target.json``): a record copied from another target, or edited to
name another folder, is never served.

**Served only while still authorized.** ``served_workspaces`` (the helper's read) serves a
registration only while the target's record, credential generation and consent are those it was
made under, the consent admits the same profile revision, and the gate passes for its repository
(the hold included). Anything else drops it with a closed reason; its registrant renews (which
admits again) or releases it.

Cursor's workspace-root invalidation is kept: a bridge whose host says its roots changed releases
every registration it made (``release_registrant``) as it retires, so the helper stops serving the
old root.

File reads and writes only: never a service, never a network.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import secrets
import stat
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

from finishup.client.targets import TargetError, read_target, target_root
from finishup.config.installation import format_rfc3339_ms, parse_rfc3339_ms
from finishup.config.paths import PathSafetyError, ensure_owner_only_dir
from finishup.ports.control import WorkspaceClaim
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.server_profile import (
    ProfileError,
    ServerProfileRevision,
    revision_from_json,
    revision_to_json,
)

if TYPE_CHECKING:
    from finishup.client.authorization import ConnectionAuthorization
    from finishup.client.targets import ServerTarget

__all__ = [
    "LEASE_SECONDS",
    "MAX_REGISTRATIONS",
    "REGISTRATION_SCHEMA",
    "REGISTRATION_SOURCES",
    "Registration",
    "RegistrationError",
    "ServedWorkspace",
    "new_registrant",
    "register",
    "registrations_dir",
    "release",
    "release_registrant",
    "renew",
    "served_workspaces",
]

REGISTRATION_SCHEMA: Final = "yoetz.helper-registration/1"
LEASE_SECONDS: Final = 900
MAX_REGISTRATIONS: Final = 64
# Who registered: the MCP bridge (its workspace from the launch folder, the host's roots, or a
# registered project), a command, a hook or the terminal interface.
REGISTRATION_SOURCES: Final = frozenset(
    {"cli", "hook", "mcp_bridge", "mcp_roots", "registered_project", "ui"}
)
_DIRECTORY: Final = "registrations"
_MAX_RECORD_BYTES: Final = 8_192
_REGISTRANT: Final = re.compile(r"^[0-9a-f]{16}$", re.ASCII)
_DIGEST: Final = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_GENERATION: Final = re.compile(r"^[0-9a-f]{32}$", re.ASCII)
_KEY: Final = re.compile(r"^[A-Za-z0-9:_-]{1,128}$", re.ASCII)
_FIELDS: Final = frozenset(
    {
        "schema",
        "target_id",
        "registrant",
        "source",
        "claim",
        "worktree",
        "repository_key",
        "grant",
        "server_profile",
        "registered_at",
        "expires_at",
    }
)
_REASONS: Final = frozenset(
    {
        # Refused before anything was written: the connection's authorization refuses now.
        "registration_refused",
        "registration_limit",
        "registration_unsafe",
        "registration_invalid",
    }
)


class RegistrationError(Exception):
    """A refused registration; ``reason`` and ``phase`` are closed tokens, never paths."""

    def __init__(self, reason: str, *, phase: str | None = None) -> None:
        if reason not in _REASONS:
            raise ValueError("registration_reason_invalid")
        self.reason = reason
        self.phase = phase
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class Registration:
    """One registration (see the module text)."""

    target_id: str
    registrant: str
    source: str
    claim: WorkspaceClaim
    worktree: str
    repository_key: str | None
    identity_digest: str
    consent_digest: str
    credential_generation: str | None
    server_profile: ServerProfileRevision
    registered_at: str
    expires_at: str

    def __post_init__(self) -> None:
        if (
            type(self.registrant) is not str
            or not _REGISTRANT.match(self.registrant)
            or self.source not in REGISTRATION_SOURCES
            or type(self.claim) is not WorkspaceClaim
            or type(self.worktree) is not str
            or not self.worktree.startswith("/")
            or len(self.worktree) > 1_024
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in self.worktree)
            or (self.repository_key is not None and not _KEY.match(self.repository_key))
            or not _DIGEST.match(self.identity_digest)
            or not _DIGEST.match(self.consent_digest)
            or (
                self.credential_generation is not None
                and not _GENERATION.match(self.credential_generation)
            )
            or type(self.server_profile) is not ServerProfileRevision
        ):
            raise RegistrationError("registration_invalid")
        try:
            parse_rfc3339_ms(self.registered_at)
            parse_rfc3339_ms(self.expires_at)
        except (TypeError, ValueError):
            raise RegistrationError("registration_invalid") from None

    def body(self) -> dict[str, JsonValue]:
        return {
            "schema": REGISTRATION_SCHEMA,
            "target_id": self.target_id,
            "registrant": self.registrant,
            "source": self.source,
            "claim": {
                "identity_kind": self.claim.identity_kind,
                "digest": self.claim.digest,
                "worktree": self.claim.worktree,
            },
            "worktree": self.worktree,
            "repository_key": self.repository_key,
            "grant": {
                "identity_digest": self.identity_digest,
                "consent_digest": self.consent_digest,
                "credential_generation": self.credential_generation,
            },
            "server_profile": revision_to_json(self.server_profile),
            "registered_at": self.registered_at,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True, slots=True)
class ServedWorkspace:
    """A registration the helper may serve now."""

    registration: Registration


def new_registrant() -> str:
    """A fresh registrant id: one per registering process."""

    return secrets.token_hex(8)


def registrations_dir(target_id: str) -> Path:
    return target_root(target_id) / "state" / _DIRECTORY


def _path(target_id: str, claim: WorkspaceClaim, registrant: str) -> Path:
    digest = claim.digest.removeprefix("sha256:")
    worktree = claim.worktree.removeprefix("sha256:")
    return registrations_dir(target_id) / f"{digest}-{worktree}-{registrant}.json"


def _now() -> datetime:
    return datetime.now(UTC)


def _credential_generation(root: Path) -> str | None:
    """The credential generation recorded for the target at ``root``; ``None`` for none."""

    from finishup.client.authorization import credential_generation_path

    encoded = _read(credential_generation_path(root))
    if encoded is None:
        return None
    try:
        value = strict_json_parse(encoded.rstrip(b"\n"))
    except ValueError:
        return None
    if type(value) is not dict:
        return None
    generation = cast(dict[str, JsonValue], value).get("generation")
    return generation if type(generation) is str and _GENERATION.match(generation) else None


def _read(path: Path) -> bytes | None:
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
            or facts.st_size > _MAX_RECORD_BYTES
        ):
            return None
        data = os.read(descriptor, _MAX_RECORD_BYTES + 1)
    except OSError:
        return None
    finally:
        os.close(descriptor)
    return None if len(data) > _MAX_RECORD_BYTES else data


def _owner_only_directory(path: Path) -> bool:
    try:
        facts = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(facts.st_mode)
        and facts.st_uid == os.geteuid()
        and not stat.S_IMODE(facts.st_mode) & 0o077
    )


def _write(path: Path, encoded: bytes) -> None:
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
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
    except (OSError, PathSafetyError):
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise RegistrationError("registration_unsafe") from None


def _decode(encoded: bytes) -> Registration | None:
    try:
        if not encoded.endswith(b"\n"):
            return None
        value = strict_json_parse(encoded[:-1])
        if type(value) is not dict:
            return None
        source = cast(dict[str, JsonValue], value)
        if frozenset(source) != _FIELDS or source["schema"] != REGISTRATION_SCHEMA:
            return None
        claim = cast(dict[str, JsonValue], source["claim"])
        grant = cast(dict[str, JsonValue], source["grant"])
        if set(claim) != {"identity_kind", "digest", "worktree"} or set(grant) != {
            "identity_digest",
            "consent_digest",
            "credential_generation",
        }:
            return None
        registration = Registration(
            target_id=cast(str, source["target_id"]),
            registrant=cast(str, source["registrant"]),
            source=cast(str, source["source"]),
            claim=WorkspaceClaim(
                cast(object, claim["identity_kind"]),  # pyright: ignore[reportArgumentType]
                cast(str, claim["digest"]),
                cast(str, claim["worktree"]),
            ),
            worktree=cast(str, source["worktree"]),
            repository_key=cast(str | None, source["repository_key"]),
            identity_digest=cast(str, grant["identity_digest"]),
            consent_digest=cast(str, grant["consent_digest"]),
            credential_generation=cast(str | None, grant["credential_generation"]),
            server_profile=revision_from_json(source["server_profile"]),
            registered_at=cast(str, source["registered_at"]),
            expires_at=cast(str, source["expires_at"]),
        )
    except (TypeError, ValueError, KeyError, ProfileError, RegistrationError):
        return None
    if canonical_encode(registration.body()) + b"\n" != encoded:
        return None
    return registration


def _live_records(target_id: str) -> list[tuple[Path, Registration | None]]:
    directory = registrations_dir(target_id)
    if not _owner_only_directory(directory):
        return []
    found: list[tuple[Path, Registration | None]] = []
    for entry in sorted(os.scandir(directory), key=lambda item: item.name):
        if not entry.name.endswith(".json") or entry.name.startswith("."):
            continue
        path = Path(entry.path)
        encoded = _read(path)
        found.append((path, None if encoded is None else _decode(encoded)))
    return found


def register(
    authorization: ConnectionAuthorization,
    claim: WorkspaceClaim,
    worktree: str,
    *,
    registrant: str,
    source: str,
    now: datetime | None = None,
) -> Registration:
    """Register ``worktree`` (claimed as ``claim``) for the helper of the connection's target.

    Only under an admission that refuses nothing now and named a profile revision: otherwise
    ``RegistrationError("registration_refused", phase=...)`` and nothing is written. Idempotent
    for the same registrant and workspace (it renews). At most ``MAX_REGISTRATIONS`` live ones
    per target (``registration_limit``).
    """

    phase = authorization.refusal()
    grant = authorization.grant
    if phase is not None or grant.profile_revision is None:
        raise RegistrationError("registration_refused", phase=phase or "server_profile_changed")
    stamp = now or _now()
    root = target_root(grant.target_id)
    registration = Registration(
        target_id=grant.target_id,
        registrant=registrant,
        source=source,
        claim=claim,
        worktree=worktree,
        repository_key=grant.repository_key,
        identity_digest=grant.identity_digest,
        consent_digest=grant.consent_digest,
        credential_generation=_credential_generation(root),
        server_profile=grant.profile_revision,
        registered_at=format_rfc3339_ms(stamp),
        expires_at=format_rfc3339_ms(stamp + timedelta(seconds=LEASE_SECONDS)),
    )
    path = _path(grant.target_id, claim, registrant)
    live = [
        item
        for item_path, item in _live_records(grant.target_id)
        if item is not None and item_path != path and not _expired(item, stamp)
    ]
    if len(live) >= MAX_REGISTRATIONS:
        raise RegistrationError("registration_limit")
    _write(path, canonical_encode(registration.body()) + b"\n")
    return registration


def _expired(registration: Registration, now: datetime) -> bool:
    return parse_rfc3339_ms(registration.expires_at) <= now


def renew(
    registration: Registration,
    authorization: ConnectionAuthorization,
    *,
    now: datetime | None = None,
) -> Registration | str:
    """Extend ``registration``'s lease under ``authorization`` as it stands now.

    When the authorization refuses now (the selection, the record, the key, the consent or the
    hold changed), the registration is released and the closed phase returned; otherwise the
    renewed registration (re-made under the current admission).
    """

    phase = authorization.refusal()
    if phase is not None:
        release(registration.target_id, registration.claim, registration.registrant)
        return phase
    try:
        return register(
            authorization,
            registration.claim,
            registration.worktree,
            registrant=registration.registrant,
            source=registration.source,
            now=now,
        )
    except RegistrationError as error:
        release(registration.target_id, registration.claim, registration.registrant)
        return error.phase or error.reason


def release(target_id: str, claim: WorkspaceClaim, registrant: str) -> bool:
    """Remove one registration; whether one was there. Never raises."""

    try:
        path = _path(target_id, claim, registrant)
        path.unlink()
    except (OSError, TargetError):
        return False
    return True


def release_registrant(target_id: str, registrant: str) -> int:
    """Remove every registration ``registrant`` made for ``target_id`` (a bridge retiring, or
    Cursor's roots changing); how many. Never raises."""

    removed = 0
    try:
        for path, registration in _live_records(target_id):
            if registration is not None and registration.registrant == registrant:
                path.unlink(missing_ok=True)
                removed += 1
    except (OSError, TargetError):
        return removed
    return removed


async def served_workspaces(
    record: ServerTarget,
    *,
    now: datetime | None = None,
    drop: Callable[[str], None] | None = None,
) -> tuple[ServedWorkspace, ...]:
    """The registrations of ``record`` the helper may serve now (see the module text).

    Every other one is dropped: removed when expired, unreadable or no longer bound to what it was
    registered under; ``drop`` is told each closed reason (``expired``, ``unreadable``,
    ``target_changed``, ``credential_changed``, ``consent_changed``, ``claim_mismatch``, or the
    gate's own phase). Never raises for a record.
    """

    from finishup.adapters.workspace_root import RepositoryIdentityError, canonical_workspace_root
    from finishup.client.authorization import consent_digest, gate, identity_digest
    from finishup.client.workspace_claim import workspace_claim_for_root
    from finishup.ports.control import WorkspaceLocator

    stamp = now or _now()

    def ignore(_reason: str) -> None:
        return None

    note = drop or ignore
    root = target_root(record.target_id)
    current = read_target(root)
    if current is None or current.target_id != record.target_id:
        return ()
    try:
        salt = base64.b64decode(cast(str, current.claim_salt), validate=True)
    except (TypeError, ValueError, binascii.Error):
        return ()
    generation = _credential_generation(root)
    served: list[ServedWorkspace] = []
    for path, registration in _live_records(record.target_id):
        reason: str | None = None
        if registration is None:
            reason = "unreadable"
        elif registration.target_id != current.target_id or (
            registration.identity_digest != identity_digest(current)
        ):
            reason = "target_changed"
        elif _expired(registration, stamp):
            reason = "expired"
        elif registration.credential_generation != generation:
            reason = "credential_changed"
        elif registration.consent_digest != consent_digest(current):
            reason = "consent_changed"
        else:
            try:
                revision = gate(current, repository_key=registration.repository_key)
            except TargetError as error:
                reason = error.reason
            else:
                if revision != registration.server_profile:
                    reason = "consent_changed"
        if reason is None and registration is not None:
            try:
                canonical = await canonical_workspace_root(WorkspaceLocator(registration.worktree))
                derived = workspace_claim_for_root(canonical, salt, registration.worktree)
            except (RepositoryIdentityError, ValueError, OSError):
                derived = None
            if derived != registration.claim:
                reason = "claim_mismatch"
        if reason is None and registration is not None:
            served.append(ServedWorkspace(registration))
            continue
        note(cast(str, reason))
        if reason in {"expired", "unreadable", "target_changed", "claim_mismatch"}:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
    return tuple(served)
