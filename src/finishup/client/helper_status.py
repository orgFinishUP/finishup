"""The helper's owner-only records in an SSH target root, and how clients start or stop it.

A server elsewhere is reached through one background helper per target (design v2 section 3, the
unified helper; ADR-051, ADR-052): ``finishup helper run --target <id>``. This module is what every
client needs to know about it, and nothing more, so it stays light (the standard library, the
target and path helpers, the protocol's closed phase sets): a hook may import it.

Records beneath ``<target root>``, every one owner-only and holding closed tokens, generated ids,
integers and timestamps only (no host, name, path or remote text):

* ``state/helper.lock``: the singleton flock, stamped with the holder's pid, package version and
  schema-manifest digest. The stamp is advisory (a status record, the release a client compares);
  a client stops or supersedes a helper through the stop epoch below, never by signalling a pid
  and never by matching a process name or path.
* ``state/helper-status.json`` (``yoetz.helper-status/1``): ``generation``, ``phase``, ``reason``,
  ``correlation_id``, ``pid``, ``started_at`` and the connection ``style``. The generation moves on
  every change of phase or reason and with every new helper process, so a client that latched an
  outage (the MCP bridge) sees the repair (the availability latch).
* ``config/connection-style.json`` (``yoetz.connection-style/1``): ``relay`` (the default, also
  when the record is absent) or ``direct``, the owner's choice (``finishup server set NAME
  --style``).
* ``state/profile-refresh-requested``: an empty marker a client leaves when the server refused it
  with ``server_profile_changed``; the helper refreshes the profile and removes it.
* ``state/helper-epoch`` (``yoetz.helper-epoch/1``): a random token every stop replaces. A helper
  is spawned with the token its spawner read (``--epoch``); one that finds another token once it
  holds the lock (a stop came while it was starting) exits without serving anything, and a
  running helper stops on its next tick when the token moves.

**The relay's repository binding** (``RELAY_BINDING``). A client that names a workspace through the
helper's relay (its claim) first writes, on that local connection only, the repository key its own
admission is bound to (``client.repository_hold.repository_key``): ``0xFF``, ``yoetz-relay/1``, a
space, the key, a newline (``relay_binding``). The byte ``0xFF`` can never begin a control frame
(their length prefix is far below 2**24), so a helper reads it apart from the hello that follows,
and the helper never forwards it: it binds that relay, its every frame and its REST stream's own
retries and polls, to the hold of exactly that repository (``ConnectionAuthorization.for_repository``),
whatever worktrees the everyday record still lists. A relayed hello that claims a workspace without
it is never forwarded. Nothing else reads it; anything but a helper (a service, an older helper)
refuses it as an oversized frame before anything is relayed.

Ownership and reaping never depend on the process that started a helper: the lock and its stamp
in the target root are the ownership, and the spawner reaps its own child (exactly that pid) on a
daemon thread while it lives; a spawner that exits first leaves the helper to the system, which
reaps it. A stop never signals a process: the stamp's pid is advisory (it may be reused once the
helper exits), so a stop moves the owner-only epoch, which only that target's helper reads, and
succeeds only once the lock is proven free.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import os
import re
import secrets
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal, cast

from finishup.config.installation import format_rfc3339_ms, parse_rfc3339_ms
from finishup.config.paths import PathSafetyError, existing_owner_only_dir
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.errors import REMOTE_CONNECTION_PHASES

if TYPE_CHECKING:
    from finishup.protocol.server_profile import ServerProfileRevision

__all__ = [
    "CONNECTION_STYLES",
    "CONNECTION_STYLE_NAME",
    "CONNECTION_STYLE_SCHEMA",
    "HELPER_CONSENT_NAME",
    "HELPER_CONSENT_SCHEMA",
    "HELPER_EPOCH_NAME",
    "HELPER_EPOCH_SCHEMA",
    "HELPER_IDLE_SECONDS",
    "HELPER_LOCK_NAME",
    "HELPER_PHASES",
    "HELPER_REASONS",
    "HELPER_STATUS_NAME",
    "HELPER_STATUS_SCHEMA",
    "PROFILE_REFRESH_MARKER",
    "PROFILE_REFRESH_SCHEMA",
    "RELAY_BINDING_BYTES",
    "ConnectionStyle",
    "HelperLock",
    "HelperLockBusy",
    "HelperPhase",
    "HelperStamp",
    "HelperStatus",
    "ProfileRefreshRequest",
    "helper_environment",
    "helper_holder",
    "new_status",
    "now_stamp",
    "read_connection_style",
    "read_followed_consent",
    "read_helper_epoch",
    "read_helper_status",
    "read_relay_binding",
    "relay_binding",
    "request_profile_refresh",
    "spawn_helper",
    "start_fenced",
    "starts_relay_binding",
    "stop_helper",
    "take_named_profile_refresh_request",
    "take_profile_refresh_request",
    "write_connection_style",
    "write_followed_consent",
    "write_helper_status",
]

HELPER_STATUS_SCHEMA: Final = "yoetz.helper-status/1"
HELPER_STATUS_NAME: Final = "helper-status.json"
HELPER_LOCK_NAME: Final = "helper.lock"
CONNECTION_STYLE_SCHEMA: Final = "yoetz.connection-style/1"
CONNECTION_STYLE_NAME: Final = "connection-style.json"
PROFILE_REFRESH_MARKER: Final = "profile-refresh-requested"
# ``state/helper-consent`` (``yoetz.helper-consent/1``): the consent the running helper's agents
# were opened under (``client.authorization.consent_digest``), written once it followed a change.
HELPER_CONSENT_SCHEMA: Final = "yoetz.helper-consent/1"
HELPER_CONSENT_NAME: Final = "helper-consent"
# The marker's optional content: the profile revision the refused hello named.
PROFILE_REFRESH_SCHEMA: Final = "yoetz.profile-refresh-request/1"
HELPER_EPOCH_SCHEMA: Final = "yoetz.helper-epoch/1"
HELPER_EPOCH_NAME: Final = "helper-epoch"
# The epoch of a target root no stop has moved yet (no file).
_NO_EPOCH: Final = "none"
# A helper with no client for this long exits; the next client starts a new one (design v2 §3).
HELPER_IDLE_SECONDS: Final = 900.0
HELPER_PHASES: Final = frozenset({"starting", "ready", "unavailable", "stopped"})
CONNECTION_STYLES: Final = ("relay", "direct")

# The relay's repository binding (see the module text): its first byte, never a frame's.
_RELAY_BINDING_MARK: Final = b"\xff"
_RELAY_BINDING_LEAD: Final = _RELAY_BINDING_MARK + b"yoetz-relay/1 "
_REPOSITORY_KEY: Final = re.compile(rb"^sha256:[0-9a-f]{64}$")
RELAY_BINDING_BYTES: Final = len(_RELAY_BINDING_LEAD) + len(b"sha256:") + 64 + 1

type HelperPhase = Literal["starting", "ready", "unavailable", "stopped"]
type ConnectionStyle = Literal["relay", "direct"]

# ``unavailable`` names one remote connection phase (``protocol.errors``): an outage of the server
# or its transport, or the shared gate's refusal of the helper's own admission (ADR-052).
_UNAVAILABLE_REASONS: Final = REMOTE_CONNECTION_PHASES
# ``stopped`` names why the process ended; ``zero_network_remote_selected`` is both: the helper
# relays nothing while this computer last reported a zero-network policy, then stops for it.
_STOPPED_REASONS: Final = frozenset(
    {
        "idle_timeout",
        "stop_requested",
        "helper_failed",
        "target_removed",
        "zero_network_remote_selected",
    }
)
HELPER_REASONS: Final = _UNAVAILABLE_REASONS | _STOPPED_REASONS

_MAX_RECORD_BYTES: Final = 2_048
_CORRELATION: Final = "err_"
_STOP_POLL_SECONDS: Final = 0.05
# The helper's scrubbed environment: what OpenSSH and the interpreter need, nothing secret and no
# FinishUP variable. ``SSH_AUTH_SOCK`` lets OpenSSH use the owner's agent (the key stays in
# OpenSSH). The XDG base directories decide where this machine's server registry lives, so the
# helper resolves the same target root its client did.
_ENVIRONMENT_NAMES: Final = (
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LOGNAME",
    "PATH",
    # The keyring backend the client is pinned to: the helper reads the key from the same store.
    "PYTHON_KEYRING_BACKEND",
    "SSH_AUTH_SOCK",
    "TMPDIR",
    "USER",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR",
    "XDG_STATE_HOME",
)


@dataclass(frozen=True, slots=True)
class HelperStatus:
    """One validated ``yoetz.helper-status/1`` record."""

    generation: int
    phase: HelperPhase
    reason: str | None
    correlation_id: str | None
    pid: int
    started_at: str
    style: ConnectionStyle = "relay"

    def __post_init__(self) -> None:
        if type(self.generation) is not int or self.generation < 1:
            raise ValueError("helper_status_invalid")
        if self.phase not in HELPER_PHASES:
            raise ValueError("helper_status_invalid")
        allowed = {
            "starting": frozenset[str](),
            "ready": frozenset[str](),
            "unavailable": _UNAVAILABLE_REASONS,
            "stopped": _STOPPED_REASONS,
        }[self.phase]
        if (self.reason is None) is bool(allowed) or (
            self.reason is not None and self.reason not in allowed
        ):
            raise ValueError("helper_status_invalid")
        if self.correlation_id is not None and (
            type(self.correlation_id) is not str
            or not self.correlation_id.startswith(_CORRELATION)
            or not 4 < len(self.correlation_id) <= 64
            or not self.correlation_id.isascii()
        ):
            raise ValueError("helper_status_invalid")
        if type(self.pid) is not int or not 1 <= self.pid < 2**31:
            raise ValueError("helper_status_invalid")
        if self.style not in CONNECTION_STYLES:
            raise ValueError("helper_status_invalid")
        parse_rfc3339_ms(self.started_at)

    def body(self) -> dict[str, JsonValue]:
        return {
            "schema": HELPER_STATUS_SCHEMA,
            "generation": self.generation,
            "phase": self.phase,
            "reason": self.reason,
            "correlation_id": self.correlation_id,
            "pid": self.pid,
            "started_at": self.started_at,
            "style": self.style,
        }

    def encode(self) -> bytes:
        return canonical_encode(cast(JsonValue, self.body())) + b"\n"


def _status_path(root: Path) -> Path:
    return root / "state" / HELPER_STATUS_NAME


def _lock_path(root: Path) -> Path:
    return root / "state" / HELPER_LOCK_NAME


def _style_path(root: Path) -> Path:
    return root / "config" / CONNECTION_STYLE_NAME


def _read_owner_only(path: Path) -> bytes | None:
    """A regular, owner-owned, owner-only file's bytes; ``None`` when absent or unsafe.

    Opened without following a link and without waiting on a special file (``O_NONBLOCK``), and
    read bounded: a hook may call it.
    """

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
    return data if len(data) <= _MAX_RECORD_BYTES else None


def _write_owner_only(path: Path, encoded: bytes) -> None:
    """Atomically replace ``path`` beneath an existing owner-only folder (temp, fsync, rename).

    The folder is never created here: a target folder that ``server remove`` deleted is never
    made again by a helper still ending (A-REMOVE-RACE). Raises ``OSError`` when it is gone.
    """

    try:
        if not existing_owner_only_dir(path.parent):
            raise FileNotFoundError(errno.ENOENT, "folder_missing")
    except PathSafetyError:
        raise PermissionError(errno.EPERM, "folder_unsafe") from None
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
    )
    try:
        try:
            view = memoryview(encoded)
            while view:
                view = view[os.write(descriptor, view) :]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


_STATUS_FIELDS: Final = frozenset(
    {"schema", "generation", "phase", "reason", "correlation_id", "pid", "started_at", "style"}
)


def read_helper_status(root: Path) -> HelperStatus | None:
    """The status in ``root``; ``None`` when absent, unsafe or malformed (never a guess)."""

    data = _read_owner_only(_status_path(root))
    if data is None or not data.endswith(b"\n"):
        return None
    try:
        parsed = strict_json_parse(data[:-1])
        if type(parsed) is not dict:
            return None
        source = cast(dict[str, JsonValue], parsed)
        if frozenset(source) != _STATUS_FIELDS or source["schema"] != HELPER_STATUS_SCHEMA:
            return None
        status = HelperStatus(
            cast(int, source["generation"]),
            cast(HelperPhase, source["phase"]),
            cast(str | None, source["reason"]),
            cast(str | None, source["correlation_id"]),
            cast(int, source["pid"]),
            cast(str, source["started_at"]),
            cast(ConnectionStyle, source["style"]),
        )
    except (TypeError, ValueError):
        return None
    return status if status.encode() == data else None


def write_helper_status(root: Path, status: HelperStatus) -> None:
    """Atomically replace the status; raises ``OSError`` when the target folder is gone."""

    _write_owner_only(_status_path(root), status.encode())


def read_connection_style(root: Path) -> ConnectionStyle:
    """The owner's connection style for the SSH target at ``root``: ``relay`` unless ``direct``.

    An absent record is ``relay`` (the default, design v2 U21). A record that cannot be read
    safely is ``relay`` too: the style the helper serves, which asks nothing more of this
    computer than the other.
    """

    data = _read_owner_only(_style_path(root))
    if data is None or not data.endswith(b"\n"):
        return "relay"
    try:
        parsed = strict_json_parse(data[:-1])
    except ValueError:
        return "relay"
    if (
        type(parsed) is not dict
        or set(cast(dict[str, JsonValue], parsed)) != {"schema", "style"}
        or cast(dict[str, JsonValue], parsed)["schema"] != CONNECTION_STYLE_SCHEMA
    ):
        return "relay"
    style = cast(dict[str, JsonValue], parsed)["style"]
    return "direct" if style == "direct" else "relay"


def write_connection_style(root: Path, style: ConnectionStyle) -> None:
    """Record the owner's connection style for the target at ``root`` (``config/`` must exist)."""

    if style not in CONNECTION_STYLES:
        raise ValueError("connection_style_invalid")
    body: dict[str, JsonValue] = {"schema": CONNECTION_STYLE_SCHEMA, "style": style}
    _write_owner_only(_style_path(root), canonical_encode(body) + b"\n")


@dataclass(frozen=True, slots=True)
class ProfileRefreshRequest:
    """A refused client's request to fetch the server's profile again.

    ``revision`` is the profile revision the refused hello named (``yoetz.profile-refresh-
    request/1``); ``None`` for a marker that names none (an older client's empty one, or content
    that cannot be read). The refusal proves the server issues another revision now, so a helper
    whose cached profile still holds ``revision`` knows its cache is stale (``client.helper``).
    """

    revision: ServerProfileRevision | None


def request_profile_refresh(root: Path, revision: ServerProfileRevision | None = None) -> None:
    """Leave the marker that asks the target's helper to fetch the server's profile again.

    Written by a client the server refused with ``server_profile_changed``; never a fetch itself
    (design v2 section 8.9: no profile refresh on a hook's path). ``revision`` is the revision
    the refused hello named, written into the marker (replaced atomically: the latest refusal's
    revision is the one kept); without it the marker is left empty, as before. Never raises.
    """

    path = root / "state" / PROFILE_REFRESH_MARKER
    try:
        if not existing_owner_only_dir(path.parent):
            return
        if revision is not None:
            from finishup.protocol.server_profile import revision_to_json

            document: dict[str, JsonValue] = {
                "schema": PROFILE_REFRESH_SCHEMA,
                "server_profile": revision_to_json(revision),
            }
            _write_owner_only(path, canonical_encode(document) + b"\n")
            return
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600
        )
        os.close(descriptor)
    except (OSError, PathSafetyError, ValueError):
        return


def write_followed_consent(root: Path, digest: str) -> None:
    """Record that the helper's background agents are opened under the consent ``digest`` (any
    agent opened under an earlier one that declared less is closed): what ``server use`` waits
    for after a new level. Never raises."""

    payload = {"schema": HELPER_CONSENT_SCHEMA, "consent_digest": digest}
    try:
        _write_owner_only(
            root / "state" / HELPER_CONSENT_NAME,
            canonical_encode(cast(JsonValue, payload)) + b"\n",
        )
    except (OSError, ValueError):
        return


def read_followed_consent(root: Path) -> str | None:
    """The consent digest the running helper last said its agents follow; ``None`` when none
    was recorded or the record cannot be read."""

    data = _read_owner_only(root / "state" / HELPER_CONSENT_NAME)
    if data is None or not data.endswith(b"\n"):
        return None
    try:
        parsed = strict_json_parse(data[:-1])
    except ValueError:
        return None
    if (
        type(parsed) is not dict
        or set(cast(dict[str, JsonValue], parsed)) != {"schema", "consent_digest"}
        or cast(dict[str, JsonValue], parsed)["schema"] != HELPER_CONSENT_SCHEMA
    ):
        return None
    digest = cast(dict[str, JsonValue], parsed)["consent_digest"]
    return digest if type(digest) is str else None


def relay_binding(repository_key: str) -> bytes:
    """What a client writes first on a relayed connection that claims a workspace (see the module
    text). Raises ``ValueError`` for anything but a repository key."""

    encoded = repository_key.encode("ascii", "strict") if type(repository_key) is str else b""
    if not _REPOSITORY_KEY.match(encoded):
        raise ValueError("repository_key_invalid")
    return _RELAY_BINDING_LEAD + encoded + b"\n"


def read_relay_binding(data: bytes) -> str | None:
    """The repository key of exactly one relay binding (``RELAY_BINDING_BYTES`` long); ``None`` for
    anything else."""

    if (
        type(data) is not bytes
        or len(data) != RELAY_BINDING_BYTES
        or not data.startswith(_RELAY_BINDING_LEAD)
        or not data.endswith(b"\n")
    ):
        return None
    key = data[len(_RELAY_BINDING_LEAD) : -1]
    return key.decode("ascii") if _REPOSITORY_KEY.match(key) else None


def starts_relay_binding(first: bytes) -> bool:
    """Whether a relayed connection's first byte begins a relay binding (never a frame)."""

    return first == _RELAY_BINDING_MARK


_EPOCH_TOKEN: Final = re.compile(r"^[0-9a-f]{32}$")


def read_helper_epoch(root: Path) -> str:
    """The target's stop epoch: a token every stop replaces, ``none`` before the first.

    A record that cannot be read safely reads as ``unreadable``: never the epoch a spawner saw,
    so a helper that cannot tell whether a stop came does not serve. Never raises.
    """

    path = root / "state" / HELPER_EPOCH_NAME
    if not os.path.lexists(path):
        return _NO_EPOCH
    data = _read_owner_only(path)
    if data is None or not data.endswith(b"\n"):
        return "unreadable"
    try:
        parsed = strict_json_parse(data[:-1])
    except ValueError:
        return "unreadable"
    if type(parsed) is not dict:
        return "unreadable"
    body = cast(dict[str, JsonValue], parsed)
    token = body.get("epoch")
    if (
        set(body) != {"schema", "epoch"}
        or body["schema"] != HELPER_EPOCH_SCHEMA
        or type(token) is not str
        or not _EPOCH_TOKEN.match(token)
    ):
        return "unreadable"
    return token


def _move_helper_epoch(root: Path) -> bool:
    """Replace the target's stop epoch with a fresh token; whether it was written. Never raises.

    The folder is never made here (a removed target stays removed).
    """

    body: dict[str, JsonValue] = {"schema": HELPER_EPOCH_SCHEMA, "epoch": secrets.token_hex(16)}
    try:
        _write_owner_only(root / "state" / HELPER_EPOCH_NAME, canonical_encode(body) + b"\n")
    except OSError:
        return False
    return True


def start_fenced(root: Path, epoch: str | None) -> bool:
    """Whether a helper spawned with ``epoch`` must not serve: a stop moved it since.

    Asked by the helper right after it took the lock, before anything else; ``None`` (a helper
    the owner started by hand) is never fenced.
    """

    return epoch is not None and read_helper_epoch(root) != epoch


def take_named_profile_refresh_request(root: Path) -> ProfileRefreshRequest | None:
    """Remove the refresh marker and return what it asked; ``None`` when none was there.

    A marker that names no readable revision (an older client's empty one) is a request whose
    ``revision`` is ``None``. Never raises.
    """

    path = root / "state" / PROFILE_REFRESH_MARKER
    data = _read_owner_only(path)
    try:
        os.unlink(path)
    except OSError:
        return None
    return ProfileRefreshRequest(_named_revision(data))


def _named_revision(data: bytes | None) -> ServerProfileRevision | None:
    if not data or not data.endswith(b"\n"):
        return None
    from finishup.protocol.server_profile import ProfileError, revision_from_json

    try:
        parsed = strict_json_parse(data[:-1])
        if (
            type(parsed) is not dict
            or set(cast(dict[str, JsonValue], parsed)) != {"schema", "server_profile"}
            or cast(dict[str, JsonValue], parsed)["schema"] != PROFILE_REFRESH_SCHEMA
        ):
            return None
        return revision_from_json(cast(dict[str, JsonValue], parsed)["server_profile"])
    except (ValueError, TypeError, ProfileError):
        return None


def take_profile_refresh_request(root: Path) -> bool:
    """Remove the refresh marker; whether one was there. Never raises."""

    return take_named_profile_refresh_request(root) is not None


@dataclass(frozen=True, slots=True)
class HelperStamp:
    """The advisory identity a live helper stamped into its lock file."""

    pid: int
    version: str
    schema_manifest_digest: str


class HelperLockBusy(Exception):
    """Another live helper holds this target root's singleton lock."""


class HelperLock:
    """The helper singleton: an exclusive flock on ``state/helper.lock``, stamped."""

    __slots__ = ("_descriptor", "_path")

    def __init__(self, root: Path) -> None:
        self._path = _lock_path(root)
        self._descriptor: int | None = None

    def acquire(self, *, version: str, schema_manifest_digest: str) -> None:
        descriptor = os.open(
            self._path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
        )
        try:
            facts = os.fstat(descriptor)
            if (
                not stat.S_ISREG(facts.st_mode)
                or facts.st_uid != os.geteuid()
                or stat.S_IMODE(facts.st_mode) & 0o077
            ):
                raise HelperLockBusy
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in {errno.EWOULDBLOCK, errno.EAGAIN}:
                    raise HelperLockBusy from None
                raise
            stamp: dict[str, JsonValue] = {
                "pid": os.getpid(),
                "version": version,
                "schema_manifest_digest": schema_manifest_digest,
            }
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
            os.write(descriptor, canonical_encode(stamp) + b"\n")
        except BaseException:
            os.close(descriptor)
            raise
        self._descriptor = descriptor

    def assert_held(self) -> None:
        """For ``unix_socket.remove_stale_endpoint``: only the holder clears a stale endpoint."""

        if self._descriptor is None:
            raise RuntimeError("helper_lock_not_held")

    def release(self) -> None:
        descriptor = self._descriptor
        self._descriptor = None
        if descriptor is None:
            return
        try:
            with contextlib.suppress(OSError):
                os.ftruncate(descriptor, 0)
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _lock_held(path: Path) -> bool | None:
    """Whether some process holds the exclusive flock (``None``: cannot be inspected)."""

    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return False
    except OSError:
        return None
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError as exc:
            return True if exc.errno in {errno.EWOULDBLOCK, errno.EAGAIN} else None
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return False
    finally:
        os.close(descriptor)


def helper_holder(root: Path) -> HelperStamp | None:
    """The stamp of the live helper holding ``root``'s lock, or ``None``.

    The stamp alone is advisory: it is returned only while the flock is held and the stamped pid
    is alive.
    """

    path = _lock_path(root)
    data = _read_owner_only(path)
    if data is None or _lock_held(path) is not True:
        return None
    try:
        parsed = strict_json_parse(data.rstrip(b"\n"))
    except ValueError:
        return None
    if type(parsed) is not dict:
        return None
    stamp = cast(dict[str, JsonValue], parsed)
    pid = stamp.get("pid")
    version = stamp.get("version")
    digest = stamp.get("schema_manifest_digest")
    if (
        type(pid) is not int
        or not 1 <= pid < 2**31
        or type(version) is not str
        or not 0 < len(version) <= 128
        or type(digest) is not str
        or len(digest) != 71
    ):
        return None
    try:
        os.kill(pid, 0)
    except OSError:
        return None
    return HelperStamp(pid, version, digest)


def helper_environment() -> dict[str, str]:
    """The scrubbed environment a helper runs with: no product variable, no secret.

    The target travels as ``--target``; no isolation variable is set, so neither the helper nor
    its OpenSSH children inherit anything that could point a FinishUP process at another root.
    """

    return {name: os.environ[name] for name in _ENVIRONMENT_NAMES if name in os.environ}


def _helper_command(target_id: str, epoch: str) -> tuple[str, ...]:
    return (
        sys.executable,
        "-m",
        "finishup",
        "helper",
        "run",
        "--target",
        target_id,
        "--epoch",
        epoch,
    )


def _reap(process: subprocess.Popen[bytes]) -> None:
    """Wait for this process's own helper child, so it never lingers as a zombie (RE-3).

    ``Popen.wait`` waits on that one pid (``waitpid``), never on any other child, and tolerates a
    child something else already reaped. Errors are dropped: the reaper has nothing to report.
    """

    with contextlib.suppress(BaseException):
        process.wait()


def spawn_helper(root: Path, target_id: str) -> subprocess.Popen[bytes]:
    """Start one detached helper for the target at ``root``; its stderr goes to ``log/helper.stderr``.

    The helper outlives the call (its own session) and stops on another process's word (``server
    use``, ``disconnect``, ``remove``, a zero-network policy) or at its idle exit, while this
    process may keep running (an MCP bridge, the terminal interface): a daemon thread waits on
    exactly the spawned pid, so a stopped helper is reaped at once instead of staying
    ``<defunct>``; nothing here waits on, or signals, a process by pattern. The log folder is made
    only beneath an existing target folder (a removed target is never made again).
    """

    log = root / "log"
    try:
        if not existing_owner_only_dir(root):
            raise FileNotFoundError(errno.ENOENT, "target_missing")
    except PathSafetyError:
        raise PermissionError(errno.EPERM, "target_unsafe") from None
    # The epoch read now travels with the helper: a stop between this spawn and its lock fences
    # it (``start_fenced``).
    epoch = read_helper_epoch(root)
    with contextlib.suppress(FileExistsError):
        log.mkdir(mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(log / "helper.stderr", flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        process = subprocess.Popen(  # noqa: S603 - fixed interpreter, module and arguments
            _helper_command(target_id, epoch),
            close_fds=True,
            env=helper_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=descriptor,
            start_new_session=True,
        )
    finally:
        os.close(descriptor)
    threading.Thread(
        target=_reap, args=(process,), name="finishup-helper-reaper", daemon=True
    ).start()
    return process


def stop_helper(root: Path, *, timeout_seconds: float = 5.0) -> bool:
    """Stop ``root``'s helper and wait until its lock is free; ``True`` once proven free.

    No process is signalled (AGENTS.md: never by pattern, and a stamped pid may belong to another
    process once the helper exited): the stop moves the target's owner-only epoch, which its
    helper reads on its next tick, and which also fences a helper spawned before the stop that
    has not taken the lock yet (it exits without serving). ``True`` only when the lock is seen
    free; ``False`` when it is still held at the bound, cannot be inspected, or the epoch could
    not be moved while a holder runs.
    """

    moved = _move_helper_epoch(root)
    path = _lock_path(root)
    deadline = time.monotonic() + timeout_seconds
    while True:
        held = _lock_held(path)
        if held is False:
            return True
        if held is True and not moved:
            # A holder that was never told to stop: it is not reported stopped.
            return False
        if time.monotonic() >= deadline:
            return False
        time.sleep(_STOP_POLL_SECONDS)


def new_status(
    previous: HelperStatus | None,
    phase: HelperPhase,
    reason: str | None,
    *,
    correlation_id: str | None = None,
    started_at: str,
    style: ConnectionStyle = "relay",
) -> HelperStatus:
    """The next status: the generation moves only when the phase or the reason changes, and with
    every new helper process (so a latch keyed on it moves)."""

    generation = 1 if previous is None else previous.generation
    if previous is not None and (previous.phase, previous.reason) != (phase, reason):
        generation += 1
    if previous is not None and previous.pid != os.getpid():
        generation = previous.generation + 1
    return HelperStatus(generation, phase, reason, correlation_id, os.getpid(), started_at, style)


def now_stamp() -> str:
    return format_rfc3339_ms(datetime.now(UTC))
