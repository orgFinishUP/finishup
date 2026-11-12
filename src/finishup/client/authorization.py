"""One authorization gate and generation for every connection to a server elsewhere (ADR-052).

Design v2 sections 8.2 and 8.3: before anything is claimed, dialled or synced for a remote target
(``local_port``, ``ssh``, ``https``), one gate decides, in one order, on every path; and a
connection that was admitted watches the owner-controlled records its admission read, so a change
the owner makes ends it before more is sent.

**The gate** (``gate``), first refusal wins:

1. the record is readable (an unreadable one may name a remote kind: ``target_root_is_remote``);
2. ``zero_network_remote_selected``: this computer last reported a zero-network policy;
3. ``target_reauthorization_required``: the owner authorized it under an older disclosure;
4. the kind is open in this release (``OPEN_REMOTE_KINDS``: ``ssh``, ``https`` and ``local_port``);
   any other remote root stops here as ``target_root_is_remote``, the refusal layer 1 gave every
   connection and spawn path for a remote root;
5. the consent (``client.server_profile.consent_verdict``, ADR-052): the server's current profile,
   compared with the envelope the owner consented to, is the same or narrower (admitted under its
   revision), requires a level the owner did not agree to (``server_level_unavailable``), or is
   anything else (``server_profile_changed``). After the kind step, because its way on (``finishup
   server use NAME`` on the trusted console) exists only for a kind that is open;
6. (layer 5, ADR-053) a credential is present for a kind that needs one: checked by the REST
   transport where the key is read, before its first byte (``remote_auth_failed``), so this gate
   stays file reads only;
7. ``repository_egress_held`` or ``repository_egress_kept``: the repository hold
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
``server_authorization_changed``; anything else re-runs gate steps 2 to 7 (a consent now under
another profile revision than the one the connection named in its hello is
``server_authorization_changed`` too) and accepts the new
generation when they pass, so a rewrite with the same content never ends a connection. A check
that cannot be made keeps the last decision. A refusal is final for that connection. An open
connection (``service.client``) ends with ``server_authorization_changed`` whatever the refusal
names: it already sent something, so FinishUP says it stopped sending; the next connection's
admission names the refusal now in force, before anything is sent.

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
from typing import TYPE_CHECKING, Final, Literal, Protocol

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
    ensure_owner_only_dir,
    selection_override_active,
)
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.errors import AUTHORIZATION_REFUSAL_PHASES

if TYPE_CHECKING:
    from finishup.client.targets import ServerTarget
    from finishup.protocol.server_profile import ServerProfileRevision

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
    "authorize_target",
    "bind_prebuilt_check",
    "bump_credential_generation",
    "consent_digest",
    "credential_generation",
    "credential_generation_path",
    "gate",
    "identity_digest",
    "preflight_refusal",
    "read_generation",
    "refusal_summary",
]

# The remote kinds a connection may be made to in this release: ``ssh`` (layer 4) and, over REST
# v1, ``https`` and ``local_port`` (layer 5, ADR-053), each through the target's helper (design v2
# section 3) or directly.
OPEN_REMOTE_KINDS: Final[frozenset[str]] = frozenset({"ssh", "https", "local_port"})
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
        "server_profile_changed",
        "server_level_unavailable",
    }
)
assert AUTHORIZATION_REFUSALS == AUTHORIZATION_REFUSAL_PHASES
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
    # The consented envelope and the last profile fetched (ADR-052, ``client.server_profile``).
    consent: tuple[Stamp, Stamp] = (None, None)


def credential_generation_path(root: Path) -> Path:
    """``<target root>/config/credential-generation``."""

    return root / "config" / CREDENTIAL_GENERATION_NAME


def credential_generation(root: Path) -> object:
    """The identity of the target's credential generation now (``_stamp``); compared with one read
    earlier, a difference means the owner logged in, out or removed meanwhile. One that cannot be
    read equals nothing, not even itself read again. Never raises."""

    try:
        return _stamp(credential_generation_path(root))
    except OSError:
        return object()


def read_generation(root: Path, *, selection_bound: bool) -> AuthorizationGeneration:
    """The current generation of the remote target at ``root``; about seven ``lstat`` calls.

    Raises ``OSError`` or ``PathSafetyError`` when a record's place cannot be examined.
    """

    from finishup.client.everyday_policy import marker_path, reports_path
    from finishup.client.repository_hold import overrides_path
    from finishup.client.server_profile import CACHE_NAME, ENVELOPE_NAME

    return AuthorizationGeneration(
        selection=_stamp(selection_path()) if selection_bound else "pinned",
        target=(_stamp(root), _stamp(root / SERVER_TARGET_FILE_NAME)),
        credential=_stamp(credential_generation_path(root)),
        policy=_stamp(marker_path()),
        hold=(_stamp(reports_path()), _stamp(overrides_path(root))),
        consent=(_stamp(root / "config" / ENVELOPE_NAME), _stamp(root / "state" / CACHE_NAME)),
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
    """What the owner confirmed for it: the authorization and the consent to a server profile."""

    return _digest(
        _CONSENT_DOMAIN,
        {
            "authorized_at": record.authorized_at,
            "disclosure_version": record.disclosure_version,
            "consent": None if record.consent is None else record.consent.body(),
        },
    )


def identity_digest(record: ServerTarget) -> str:
    """What makes ``record`` the same server (its grant's identity digest)."""

    return _identity_digest(record)


def consent_digest(record: ServerTarget) -> str:
    """What the owner confirmed for ``record`` (its grant's consent digest)."""

    return _consent_digest(record)


@dataclass(frozen=True, slots=True)
class Grant:
    """What one connection was admitted under."""

    target_id: str
    kind: str
    identity_digest: str
    consent_digest: str
    repository_key: str | None
    selection_bound: bool
    # The server-profile revision the consent admitted this connection under, named in its hello
    # (ADR-052); ``None`` only where no consent step ran.
    profile_revision: ServerProfileRevision | None = None


def _phase(error: TargetError) -> str:
    return error.reason if error.reason in AUTHORIZATION_REFUSALS else "target_root_is_remote"


def gate(
    record: ServerTarget, *, repository_key: str | None = None
) -> ServerProfileRevision | None:
    """Refuse a connection to remote ``record`` with the first closed reason, in one order.

    Steps 2 to 7 of the module text (step 1, reading the record, is the caller's). Raises
    ``TargetError``; a local record passes (``None``). File reads only, never a service. Returns
    the server-profile revision the consent admits the connection under.
    """

    if not record.is_remote:
        return None
    require_current_authorization(record)
    if record.kind not in OPEN_REMOTE_KINDS:
        raise TargetError("target_root_is_remote")
    from finishup.client.server_profile import consent_verdict

    verdict = consent_verdict(record)
    if verdict.phase is not None:
        raise TargetError(verdict.phase)
    if repository_key is not None:
        from finishup.client.repository_hold import decide

        phase = decide(target_root(record.target_id), record.target_id, repository_key).phase
        if phase is not None:
            raise TargetError(phase)
    return verdict.revision


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

    @property
    def server_profile(self) -> ServerProfileRevision | None:
        """The profile revision this connection names in its hello (ADR-052)."""

        return self._grant.profile_revision

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
            revision = gate(record, repository_key=grant.repository_key)
        except TargetError as error:
            return _phase(error)
        if revision != grant.profile_revision:
            # The consent now admits connections under another revision than the one this
            # connection named in its hello: what it was admitted under changed (ADR-052).
            return CHANGED
        return None


def _selected_now() -> str | None:
    """The target id the selection file names now; ``None`` when none can be read."""

    try:
        return read_selected_target_id()
    except TargetError:
        return None


def _active_record() -> ServerTarget | None:
    """The active root's record; an unreadable one (which may name a remote kind) refuses."""

    from finishup.client import targets

    try:
        # Looked up on the module at call time, like every other reader of the active record.
        return targets.active_target_record()
    except TargetRecordUnreadable:
        raise TargetError("target_root_is_remote") from None


def authorize_active_root() -> ConnectionAuthorization | None:
    """Admit a connection from this process to its root, or refuse it before anything is sent.

    ``None`` for a local root: nothing is checked and nothing watched (O2). For a remote root,
    the generation is read, then the record again and the gate (steps 1 to 4), so the record
    admitted is never newer than the generation and a change made while the gate runs is seen at
    the first check; a refusal raises ``TargetError`` with its closed phase. A root the selection
    named is admitted only while the selection file, read after the generation, still names it:
    a process that remembers a root another process has since unselected is refused
    ``server_authorization_changed`` (the MCP bridge then follows the selection, O1). A root that
    cannot be resolved at all raises its own ``TargetError`` (``target_root_unsafe``).
    """

    record = _active_record()
    if record is None or not record.is_remote:
        return None
    # A ``selection_override`` block names its root on purpose; only a root the selection file
    # named is bound to that file.
    selection_bound = selection_source() == "selection" and not selection_override_active()
    try:
        generation = read_generation(target_root(record.target_id), selection_bound=selection_bound)
    except (OSError, PathSafetyError):
        raise TargetError("target_root_is_remote") from None
    admitted = _active_record()
    if admitted is None or not admitted.is_remote or admitted.target_id != record.target_id:
        # The root changed while it was being admitted: refuse rather than guess.
        raise TargetError("target_root_is_remote")
    if selection_bound and _selected_now() != admitted.target_id:
        # This process remembers the root it started with (``config.paths``' selection memo),
        # so another process may have selected another server before the generation was read:
        # its stamp is then the new selection's, and no later check would see the change. The
        # selection on disk, read after the generation, must name the admitted target; a change
        # after this read changes the stamp and is seen at the first check.
        raise TargetError(CHANGED)
    revision = gate(admitted)
    grant = Grant(
        target_id=admitted.target_id,
        kind=admitted.kind,
        identity_digest=_identity_digest(admitted),
        consent_digest=_consent_digest(admitted),
        repository_key=None,
        selection_bound=selection_bound,
        profile_revision=revision,
    )
    return ConnectionAuthorization(grant, generation)


def authorize_target(record: ServerTarget) -> ConnectionAuthorization:
    """Admit a connection to remote ``record`` from a process that serves that target itself.

    The target's helper (design v2 section 3) admits its relay, its background agents and its
    profile refresh this way: pinned to the target's own root, never bound to the selection file
    (the owner's ``server use`` of another server stops the helper instead). The generation is
    read first, then the record again and the gate (steps 2 to 5), exactly as
    ``authorize_active_root`` does; a record removed, replaced or changed meanwhile is
    ``server_authorization_changed``, and any other refusal raises its closed phase.
    """

    if not record.is_remote:
        raise TargetError("target_root_is_remote")
    root = target_root(record.target_id)
    try:
        generation = read_generation(root, selection_bound=False)
        current = read_target(root)
    except (OSError, PathSafetyError):
        raise TargetError("target_root_is_remote") from None
    if (
        current is None
        or not current.is_remote
        or current.target_id != record.target_id
        or _identity_digest(current) != _identity_digest(record)
    ):
        raise TargetError(CHANGED)
    revision = gate(current)
    grant = Grant(
        target_id=current.target_id,
        kind=current.kind,
        identity_digest=_identity_digest(current),
        consent_digest=_consent_digest(current),
        repository_key=None,
        selection_bound=False,
        profile_revision=revision,
    )
    return ConnectionAuthorization(grant, generation)


class _BoundCheck:
    """An admission and a prebuilt workspace binding's own check, both asked before every frame.

    The first refusal wins: the admission's (the selection, the record, the key, zero-network),
    then the binding's (its repository's hold). A check that cannot be made refuses nothing new.
    """

    __slots__ = ("_admission", "_binding")

    def __init__(self, admission: ConnectionAuthorization, binding: _Check) -> None:
        self._admission = admission
        self._binding = binding

    @property
    def grant(self) -> Grant:
        return self._admission.grant

    @property
    def server_profile(self) -> ServerProfileRevision | None:
        return self._admission.server_profile

    def refusal(self) -> str | None:
        phase = self._admission.refusal()
        if phase is not None:
            return phase
        try:
            return self._binding.refusal()
        except Exception:  # noqa: BLE001 - a check that cannot be made refuses nothing new
            return None


class _Check(Protocol):
    def refusal(self) -> str | None: ...


def _checked_target(check: object) -> str | None:
    """The target a binding's check was made for, when it names one."""

    from finishup.client.repository_hold import SendHold

    if isinstance(check, SendHold):
        return check.target_id
    if isinstance(check, (ConnectionAuthorization, _BoundCheck)):
        return check.grant.target_id
    return None


def bind_prebuilt_check(
    admission: ConnectionAuthorization, check: _Check | None
) -> ConnectionAuthorization | _BoundCheck:
    """What a connection with a prebuilt workspace binding is checked against (ADR-052).

    The binding was made earlier, with its own check (its repository's hold, or an earlier
    admission bound to that repository): the connection keeps that check beside the admission
    just made, so a repository held after the binding was made is still refused before the dial
    and ends the connection afterwards. A binding made for another target than the one admitted
    now is refused ``server_authorization_changed``: its claim and its hold are that target's.
    A binding with no check names no repository the client knows, and only the admission is
    checked.
    """

    if check is None or check is admission:
        return admission
    target = _checked_target(check)
    if target is not None and target != admission.grant.target_id:
        raise TargetError(CHANGED)
    return _BoundCheck(admission, check)


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


# What stopped, in fixed words, for every authorization refusal: the line every CLI surface shows
# before the phase's directive (``<phase>: <summary>``). No path, name or host. Every phase but
# two refuses a connection before anything is sent over it, and says so. ``server_profile_changed``
# is also the server's own refusal of a hello or request it was sent, before it did any work for
# it, so it says only that no work was done. ``server_authorization_changed`` ends a connection
# that was open (and every call already sent over one the server refused), and says FinishUP
# stopped sending over it.
_REFUSAL_SUMMARIES: Final[dict[str, str]] = {
    "zero_network_remote_selected": (
        "FinishUP refused the selected server's connection before anything was sent"
    ),
    "target_reauthorization_required": (
        "FinishUP refused the selected server's connection before anything was sent"
    ),
    "target_root_is_remote": (
        "FinishUP refused the selected server's connection before anything was sent"
    ),
    "repository_egress_held": (
        "this repository's privacy policy on this computer allows no network use, so FinishUP "
        "refused this connection to the selected FinishUP server before anything from it was sent"
    ),
    "repository_egress_kept": (
        "this repository's work is kept on this computer, as its owner chose, so FinishUP refused "
        "this connection to the selected FinishUP server before anything from it was sent"
    ),
    "server_profile_changed": (
        "what the selected FinishUP server offers or needs changed since this computer agreed to "
        "use it, so this request was refused before that server did any work for it"
    ),
    "server_level_unavailable": (
        "the selected FinishUP server requires more of this computer than its owner agreed to, "
        "so FinishUP refused this connection before anything was sent"
    ),
    # An open connection ends with this phase whatever changed (``service.client``): it already
    # sent something, so it says FinishUP stopped sending, never that nothing was sent, and that
    # what the server received stays there (design v2 section 8.10).
    CHANGED: (
        "what this connection to the selected FinishUP server was authorized under changed, so "
        "FinishUP stopped sending over it; what that server already received stays there"
    ),
}
assert set(_REFUSAL_SUMMARIES) == AUTHORIZATION_REFUSALS


# What happened, in fixed words, when a server elsewhere could not be reached through its
# transport (an SSH target, ADR-052): not a refusal of this computer, an outage of that server or
# of the way to it. Each phase's continuation names the owner's repair.
_TRANSPORT_SUMMARIES: Final[dict[str, str]] = {
    "remote_unreachable": (
        "FinishUP could not reach the selected FinishUP server elsewhere, or the connection to "
        "it ended"
    ),
    "remote_auth_failed": (
        "the selected FinishUP server elsewhere refused this computer's credentials (for an SSH "
        "server, the keys OpenSSH offered)"
    ),
    "remote_identity_changed": (
        "the selected FinishUP server elsewhere could not be verified (an SSH server's host key, "
        "or an HTTPS server's certificate or the CA file chosen for it, is not the one this "
        "computer agreed to), so FinishUP did not connect to it"
    ),
    "remote_service_not_running": (
        "the selected FinishUP server elsewhere is reachable, but its FinishUP service is not "
        "running"
    ),
    "remote_incompatible": (
        "the selected FinishUP server elsewhere runs another FinishUP release, so nothing was "
        "recorded there"
    ),
}


def refusal_summary(phase: str) -> str | None:
    """The fixed one-line summary of a remote ``phase``: an authorization refusal, or a server
    elsewhere that could not be reached; None for any other."""

    return _REFUSAL_SUMMARIES.get(phase) or _TRANSPORT_SUMMARIES.get(phase)


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
