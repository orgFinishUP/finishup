"""One authorization gate and generation for every connection to a server elsewhere (ADR-052).

Design v2 sections 8.2 and 8.3: before anything is claimed, dialled or synced for a remote target
(``local_port``, ``ssh``, ``https``), one gate decides, in one order, on every path; and a
connection that was admitted watches the owner-controlled records its admission read, so a change
the owner makes ends it before more is sent.

**The gate** (``gate``), first refusal wins:

1. the record is readable (an unreadable one may name a remote kind: ``target_root_is_remote``);
2. ``zero_network_remote_selected``: this computer last reported a zero-network policy;
3. ``target_reauthorization_required``: the owner authorized it under an older disclosure
   (layer 3 adds the consent-envelope comparison here);
4. the kind is open in this release (``OPEN_REMOTE_KINDS``); layer 2 opens none, so every remote
   root stops here as ``target_root_is_remote``, the refusal layer 1 gave every connection and
   spawn path for a remote root;
5. (layer 5) a credential is present for a kind that needs one;
6. ``repository_egress_held`` or ``repository_egress_kept``: the repository hold
   (``client.repository_hold``), when the repository is known.

``preflight_refusal`` is its hook-safe, record-only form for the root this process uses.

**The generation** (``AuthorizationGeneration``) is the identity stamps (``lstat``: device,
inode, size, modification and change times) of every record a decision reads: the selection file
(or ``pinned`` when an isolation variable or pin names the root), the target root and its
``target.json``, the credential generation, this computer's zero-network marker, its repository
reports and the target's repository choices. Every FinishUP writer renames a new file into place,
so each write changes a stamp; so does a hand edit. ``ConnectionAuthorization.refusal`` compares
the current generation with the one it accepted: unchanged is a pass; a selection that no longer
names the target, a replaced or removed target, or a new credential generation is
``server_authorization_changed``; anything else re-runs gate steps 2 to 6 and accepts the new
generation when they pass, so a rewrite with the same content never ends a connection. A check
that cannot be made keeps the last decision. A refusal is final for that connection.

**The credential generation** (``<target root>/config/credential-generation``,
``yoetz.credential-generation/1``) is bumped only by the owner's own commands: ``server login``
(once a key can be stored), ``server logout`` and ``server remove``; never by an automatic token
refresh (the owner's answer O8). A key changed in the platform store outside FinishUP is not seen.

Local roots (the everyday server, a named local server, an isolated root that is not a target)
get no authorization and no generation check at all (the owner's answer O2).

This module imports only the standard library and lean client modules, so a hook may import it;
``client.repository_hold`` loads only when a repository is decided. Never ``client.credentials``.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
import threading
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal

from finishup.client.targets import (
    TargetError,
    TargetRecordUnreadable,
    read_selected_target_id,
    read_target,
    require_current_authorization,
    selection_path,
    selection_source,
    target_root,
)
from finishup.config.paths import (
    SERVER_TARGET_FILE_NAME,
    PathSafetyError,
    active_root,
    ensure_owner_only_dir,
)
from finishup.protocol.canonical import JsonValue, canonical_encode

if TYPE_CHECKING:
    from finishup.client.targets import ServerTarget

__all__ = [
    "AUTHORIZATION_REFUSALS",
    "CHANGED",
    "CREDENTIAL_GENERATION_NAME",
    "CREDENTIAL_GENERATION_SCHEMA",
    "OPEN_REMOTE_KINDS",
    "AuthorizationGeneration",
    "ConnectionAuthorization",
    "Grant",
    "authorize_active_root",
    "bump_credential_generation",
    "credential_generation_path",
    "gate",
    "preflight_refusal",
    "read_generation",
]

# The remote kinds a connection may be made to in this release. Layer 2 opens none: layer 4
# opens ``ssh`` once the helper exists, layer 5 ``https`` and ``local_port`` once the REST client
# does. A test that exercises a claim-bound connection opens one on purpose, in process only.
OPEN_REMOTE_KINDS: Final[frozenset[str]] = frozenset()
CHANGED: Final = "server_authorization_changed"
# Every phase the gate or a generation check refuses a remote connection with.
AUTHORIZATION_REFUSALS: Final = frozenset(
    {
        "zero_network_remote_selected",
        "target_reauthorization_required",
        "target_root_is_remote",
        "repository_egress_held",
        "repository_egress_kept",
        CHANGED,
    }
)
CREDENTIAL_GENERATION_SCHEMA: Final = "yoetz.credential-generation/1"
CREDENTIAL_GENERATION_NAME: Final = "credential-generation"
_IDENTITY_DOMAIN: Final = b"yoetz/target-identity/v1\x00"
_CONSENT_DOMAIN: Final = b"yoetz/target-consent/v1\x00"

type Stamp = tuple[int, int, int, int, int] | None


def _stamp(path: Path) -> Stamp:
    """The identity of whatever is at ``path`` now (``lstat``: never follows a link); None when
    nothing is. Any other failure raises: a check that cannot be made decides nothing."""

    try:
        facts = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None
    return (facts.st_dev, facts.st_ino, facts.st_size, facts.st_mtime_ns, facts.st_ctime_ns)


@dataclass(frozen=True, slots=True)
class AuthorizationGeneration:
    """The stamps of every record one authorization decision reads (see the module text)."""

    selection: Stamp | Literal["pinned"]
    target: tuple[Stamp, Stamp]
    credential: Stamp
    policy: Stamp
    hold: tuple[Stamp, Stamp]


def credential_generation_path(root: Path) -> Path:
    """``<target root>/config/credential-generation``."""

    return root / "config" / CREDENTIAL_GENERATION_NAME


def read_generation(root: Path, *, selection_bound: bool) -> AuthorizationGeneration:
    """The current generation of the remote target at ``root``; about seven ``lstat`` calls.

    Raises ``OSError`` or ``PathSafetyError`` when a record's place cannot be examined.
    """

    from finishup.client.everyday_policy import marker_path, reports_path
    from finishup.client.repository_hold import overrides_path

    return AuthorizationGeneration(
        selection=_stamp(selection_path()) if selection_bound else "pinned",
        target=(_stamp(root), _stamp(root / SERVER_TARGET_FILE_NAME)),
        credential=_stamp(credential_generation_path(root)),
        policy=_stamp(marker_path()),
        hold=(_stamp(reports_path()), _stamp(overrides_path(root))),
    )


def _digest(domain: bytes, value: dict[str, JsonValue]) -> str:
    return "sha256:" + hashlib.sha256(domain + canonical_encode(value)).hexdigest()


def _identity_digest(record: ServerTarget) -> str:
    """What makes a target the same server: its id, kind, location and claim salt."""

    return _digest(
        _IDENTITY_DOMAIN,
        {
            "target_id": record.target_id,
            "kind": record.kind,
            "base_url": record.base_url,
            "ca_file": record.ca_file,
            "tls_pin": record.tls_pin,
            "user": record.user,
            "host": record.host,
            "port": record.port,
            "remote_root": record.remote_root,
            "remote_endpoint": record.remote_endpoint,
            "remote_launcher": record.remote_launcher,
            "claim_salt": record.claim_salt,
        },
    )


def _consent_digest(record: ServerTarget) -> str:
    """What the owner confirmed for it (layer 3 adds the consented envelope and revision)."""

    return _digest(
        _CONSENT_DOMAIN,
        {"authorized_at": record.authorized_at, "disclosure_version": record.disclosure_version},
    )


@dataclass(frozen=True, slots=True)
class Grant:
    """What one connection was admitted under."""

    target_id: str
    kind: str
    identity_digest: str
    consent_digest: str
    repository_key: str | None
    selection_bound: bool


def _phase(error: TargetError) -> str:
    return error.reason if error.reason in AUTHORIZATION_REFUSALS else "target_root_is_remote"


def gate(record: ServerTarget, *, repository_key: str | None = None) -> None:
    """Refuse a connection to remote ``record`` with the first closed reason, in one order.

    Steps 2 to 6 of the module text (step 1, reading the record, is the caller's). Raises
    ``TargetError``; a local record passes. File reads only, never a service.
    """

    if not record.is_remote:
        return
    require_current_authorization(record)
    if record.kind not in OPEN_REMOTE_KINDS:
        raise TargetError("target_root_is_remote")
    if repository_key is not None:
        from finishup.client.repository_hold import decide

        phase = decide(target_root(record.target_id), record.target_id, repository_key).phase
        if phase is not None:
            raise TargetError(phase)


class ConnectionAuthorization:
    """One admitted connection's authorization, re-checked before every frame and on a watch.

    ``refusal()`` is ``None`` while the connection may go on, else the closed phase that ends it
    (see the module text). Thread-safe; never raises.
    """

    __slots__ = ("_accepted", "_grant", "_lock", "_refused")

    def __init__(self, grant: Grant, generation: AuthorizationGeneration) -> None:
        self._grant = grant
        self._accepted = generation
        self._refused: str | None = None
        self._lock = threading.Lock()

    @property
    def grant(self) -> Grant:
        return self._grant

    def for_repository(self, key: str) -> ConnectionAuthorization:
        """The same admission, now also bound to repository ``key``'s hold."""

        with self._lock:
            bound = ConnectionAuthorization(
                replace(self._grant, repository_key=key), self._accepted
            )
            bound._refused = self._refused
        return bound

    def refusal(self) -> str | None:
        with self._lock:
            if self._refused is not None:
                return self._refused
            try:
                root = target_root(self._grant.target_id)
                current = read_generation(root, selection_bound=self._grant.selection_bound)
                if current == self._accepted:
                    return None
                phase = self._evaluate(root, current)
            except Exception:  # noqa: BLE001 - a check that cannot be made keeps the last decision
                return None
            if phase is None:
                self._accepted = current
            else:
                self._refused = phase
            return phase

    def _evaluate(self, root: Path, current: AuthorizationGeneration) -> str | None:
        grant, accepted = self._grant, self._accepted
        if grant.selection_bound and current.selection != accepted.selection:
            try:
                if read_selected_target_id() != grant.target_id:
                    return CHANGED
            except TargetError:
                return CHANGED
        if current.credential != accepted.credential:
            # The owner logged in, logged out or removed: the connection must authenticate again
            # under whatever key is current (the owner's answer O8).
            return CHANGED
        try:
            record = read_target(root)
        except TargetError:
            return CHANGED
        if (
            record is None
            or not record.is_remote
            or record.target_id != grant.target_id
            or _identity_digest(record) != grant.identity_digest
        ):
            return CHANGED
        try:
            gate(record, repository_key=grant.repository_key)
        except TargetError as error:
            return _phase(error)
        return None


def authorize_active_root() -> ConnectionAuthorization | None:
    """Admit a connection from this process to its root, or refuse it before anything is sent.

    ``None`` for a local root: nothing is checked and nothing watched (O2). For a remote root,
    the generation is read first (so a change made while the gate runs is seen at the first
    frame), then the record and the gate (steps 1 to 4); a refusal raises ``TargetError`` with
    its closed phase. A root that cannot be resolved raises ``target_root_unsafe``.
    """

    try:
        root = active_root()
    except PathSafetyError:
        raise TargetError("target_root_unsafe") from None
    if root is None:
        return None
    try:
        record = read_target(root)
    except TargetError:
        raise TargetError("target_root_is_remote") from None
    if record is None or not record.is_remote:
        return None
    selection_bound = selection_source() == "selection"
    try:
        generation = read_generation(root, selection_bound=selection_bound)
    except (OSError, PathSafetyError):
        raise TargetError("target_root_is_remote") from None
    # Read again after the stamps: the record admitted is never newer than the generation.
    try:
        record = read_target(root)
    except TargetError:
        raise TargetError("target_root_is_remote") from None
    if record is None or not record.is_remote:
        raise TargetError("target_root_is_remote")
    gate(record)
    grant = Grant(
        target_id=record.target_id,
        kind=record.kind,
        identity_digest=_identity_digest(record),
        consent_digest=_consent_digest(record),
        repository_key=None,
        selection_bound=selection_bound,
    )
    return ConnectionAuthorization(grant, generation)


def preflight_refusal() -> str | None:
    """The closed phase a connection from this process would be refused with now, or None.

    The record-only form of the gate for the root this process uses (steps 1 to 4): hook-safe,
    never a service, never raises. ``None`` for a local root and for one the gate admits; a root
    that cannot be resolved at all is left to the caller's own path-safety refusal. In this
    release every remote root is refused (no remote kind is open), exactly as layer 1 named it.
    """

    try:
        authorize_active_root()
    except TargetRecordUnreadable:
        return "target_root_is_remote"
    except TargetError as error:
        if error.reason == "target_root_unsafe":
            return None
        return _phase(error)
    except Exception:  # noqa: BLE001 - a refusal that cannot be decided names a remote root
        return "target_root_is_remote"
    return None


def bump_credential_generation(root: Path) -> bool:
    """Record a new credential generation for the target at ``root``; whether it was written.

    Called by the owner's own commands only (``server logout``, ``server remove``, and ``server
    login`` once it stores a key), never by an automatic token refresh (the owner's answer O8).
    An owner-only canonical JSON file, renamed into place. Never raises: the command it belongs
    to is the owner's way out and is never blocked by it.
    """

    path = credential_generation_path(root)
    encoded = (
        canonical_encode(
            {"generation": secrets.token_hex(16), "schema": CREDENTIAL_GENERATION_SCHEMA}
        )
        + b"\n"
    )
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    try:
        if not root.is_dir() or root.is_symlink():
            return False
        ensure_owner_only_dir(path.parent)
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            stat.S_IRUSR | stat.S_IWUSR,
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
        return False
    return True
