"""Server targets: the FinishUP servers this client can use, and which one is selected (ADR-051).

A *target* is one root beneath ``<ambient state dir>/servers/t_<8 hex>/`` holding an owner-only
``target.json`` (``yoetz.server-target/1``) with an exact field set per kind:

* ``local`` — a named local server: an ADR-028 persistent instance root with its own vault,
  ledger, and service, started on demand like the everyday one.
* ``local_port`` — a FinishUP server reached over HTTPS on this machine's loopback
  (``https://127.0.0.1:<port>`` or ``https://[::1]:<port>``).
* ``ssh`` — a server on another machine reached over OpenSSH (``ssh://[user@]host[:port]``).
* ``https`` — a server reached over HTTPS (``https://host[:port][/base]``); plain HTTP is refused.

Non-local kinds also record a per-target ``claim_salt`` (32 random bytes) and the owner's
authorization (``authorized_at``, ``disclosure_version``). A remote root holds client state only.

A remote record the owner consented to under a server profile (ADR-052, layer 3) is
``yoetz.server-target/2``: the same fields plus an exact ``consent`` object (``ServerConsent``:
the level, the profile digest and the issuer and number of its revision, the retention chosen,
the digest of the consented envelope kept beside it in ``config/consent-envelope.json``, and
whether a narrowed profile adjusted it since). A local record is always ``/1``, byte for byte as
before; a remote ``/1`` record (written before profiles) still reads, and is refused
``target_reauthorization_required`` (its disclosure is older than this release's).

The owner-only selection file ``<ambient config dir>/server-selection.json``
(``yoetz.server-selection/1``) names one target; absent, the everyday server is used exactly as
before. ``config.paths.active_root()`` reads it. Names match ``[a-z0-9][a-z0-9-]{0,15}``, ``local``
is reserved, and a name appears only in ``target.json`` and owner displays; everything else
names a target by its id. Every failure is a closed ``TargetError`` reason.

This module imports only the standard library and lean SHARED modules, so a hook may import it.
"""

from __future__ import annotations

import base64
import binascii
import fcntl
import ipaddress
import os
import re
import secrets
import shutil
import stat
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, cast
from urllib.parse import urlsplit

from finishup.config.installation import (
    format_rfc3339_ms,
    instance_root_fits,
    parse_rfc3339_ms,
    socket_path_fits,
)
from finishup.config.paths import (
    SERVER_SELECTION_NAME,
    SERVER_SELECTION_SCHEMA,
    SERVER_TARGET_FILE_NAME,
    SERVERS_DIR_NAME,
    IsolationBinding,
    PathSafetyError,
    active_root,
    ambient_registry_dirs,
    ensure_owner_only_dir,
    isolation_binding,
    reset_selection_memo,
    verify_private_local_bundle,
)
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.errors import REMOTE_ROOT_REFUSAL_PHASES

__all__ = [
    "CLAIM_SALT_BYTES",
    "DISCLOSURE_VERSION",
    "PRE_DIAL_REFUSALS",
    "PROFILE_CHECKING_CONTINUATION",
    "REMOTE_KINDS",
    "REMOTE_ROOT_OVERRIDE_CONTINUATION",
    "REMOTE_ROOT_REFUSALS",
    "RESERVED_NAMES",
    "TARGET_KINDS",
    "TARGET_SCHEMA",
    "CredentialLocation",
    "SelectionSource",
    "ServerTarget",
    "TargetError",
    "TargetKind",
    "TargetRecordUnreadable",
    "active_remote_refusal",
    "active_root_may_be_remote",
    "active_target_record",
    "clear_selection",
    "find_target",
    "leftover_target_ids",
    "list_targets",
    "new_local_target",
    "new_remote_target",
    "normalize_https_url",
    "parse_ssh_url",
    "read_selected_target_id",
    "read_target",
    "reauthorized",
    "profile_change_continuation",
    "registry_lock",
    "remote_root_continuation",
    "root_named_explicitly",
    "reconcile_remote_presence",
    "remote_target_recorded",
    "remove_leftover_root",
    "remove_target_root",
    "require_current_authorization",
    "selection_path",
    "selection_source",
    "servers_dir",
    "target_root",
    "validate_name",
    "write_selection",
    "write_target",
]

TARGET_SCHEMA: Final = "yoetz.server-target/1"
# A remote record with the owner's consent to a server profile (ADR-052).
CONSENTED_TARGET_SCHEMA: Final = "yoetz.server-target/2"
TARGET_KINDS: Final = ("local", "local_port", "ssh", "https")
REMOTE_KINDS: Final = frozenset({"local_port", "ssh", "https"})
RESERVED_NAMES: Final = frozenset({"local"})
# The versioned disclosure the owner confirmed for a remote target (design section 6). A new
# version forces the owner to confirm again before the target is used. Version 2 names the hook
# observations sent to the server, the captured content among them (ADR-051 decision 12).
# Version 3 names the level of use and the server's AI-review egress from its profile, and binds
# the consent to that profile's revision (ADR-052).
DISCLOSURE_VERSION: Final = 3
CLAIM_SALT_BYTES: Final = 32

type TargetKind = Literal["local", "local_port", "ssh", "https"]
type CredentialLocation = Literal["keyring", "file"]
# Which source decided this process's root (``config.paths.isolation_binding``).
type SelectionSource = IsolationBinding

_NAME: Final = re.compile(r"^[a-z0-9][a-z0-9-]{0,15}$", re.ASCII)
_TARGET_ID: Final = re.compile(r"^t_[0-9a-f]{8}$", re.ASCII)
_TLS_PIN: Final = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_SSH_USER: Final = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,31}$", re.ASCII)
_DNS_NAME: Final = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$",
    re.ASCII,
)
_URL_PATH: Final = re.compile(r"^(?:/[A-Za-z0-9._~-]+)*/?$", re.ASCII)
_MAX_RECORD_BYTES: Final = 8_192
_MAX_PATH_TEXT: Final = 1_024
# The sockets a client may bind beneath a remote target root, each with the temporary suffix it
# is bound under first. A remote root runs no service, so the service's endpoints (the instance
# bound a ``local`` root is held to) never apply to it. OpenSSH binds its ControlMaster ``run/m``
# at ``run/m.<16 random characters>`` and renames it into place, the longest of these; a relay or
# forwarded socket (``run/control.sock``, ``run/upstream.sock``, ``run/api.sock``, as the
# topology needs) binds directly. An HTTPS or ``local_port`` target may bind none.
_REMOTE_CLIENT_SOCKETS: Final = (
    (Path("run") / "m", 17),
    (Path("run") / "control.sock", 0),
    (Path("run") / "upstream.sock", 0),
    (Path("run") / "api.sock", 0),
)
_REGISTRY_LOCK_NAME: Final = ".registry.lock"
# Present while any remote target record is (``remote_target_recorded``, ADR-052 O3).
_REMOTE_PRESENCE_NAME: Final = "remote-target-recorded"
_COMMON_FIELDS: Final = frozenset({"schema", "target_id", "name", "kind", "created_at"})
_REMOTE_FIELDS: Final = frozenset({"claim_salt", "authorized_at", "disclosure_version"})
_CONSENT_FIELDS: Final = frozenset(
    {"level", "profile_digest", "profile_revision", "retention", "envelope_digest", "adjusted"}
)
_LEVELS: Final = ("L1", "L2")
_RETENTION_KINDS: Final = frozenset({"task_close", "days", "until_forgotten"})
_DIGEST: Final = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_ISSUER: Final = re.compile(r"^[0-9a-f]{32}$", re.ASCII)
_COVERAGE: Final = frozenset({"level", "code_sync", "exclusions", "review"})
_HTTPS_FIELDS: Final = frozenset({"base_url", "ca_file", "tls_pin", "credential"})
_SSH_FIELDS: Final = frozenset(
    {"user", "host", "port", "remote_root", "remote_endpoint", "remote_launcher"}
)
_FIELDS_BY_KIND: Final[dict[str, frozenset[str]]] = {
    "local": _COMMON_FIELDS,
    "local_port": _COMMON_FIELDS | _HTTPS_FIELDS | _REMOTE_FIELDS,
    "https": _COMMON_FIELDS | _HTTPS_FIELDS | _REMOTE_FIELDS,
    "ssh": _COMMON_FIELDS | _SSH_FIELDS | _REMOTE_FIELDS,
}
_REASONS: Final = frozenset(
    {
        "selection_overridden",
        "target_name_invalid",
        "target_name_reserved",
        "target_name_taken",
        "target_unknown",
        "target_selected",
        "target_record_invalid",
        "target_reauthorization_required",
        "target_url_invalid",
        "target_tls_invalid",
        "target_path_invalid",
        "target_root_too_long",
        "target_root_unsafe",
        "selection_invalid",
        "zero_network_remote_selected",
        # A repository whose privacy policy on this computer allows no network use, held from a
        # server elsewhere until the owner decides, or kept here as they chose
        # (``finishup.client.repository_hold``).
        "repository_egress_held",
        "repository_egress_kept",
        # The authorization gate (``client.authorization``, ADR-052): a remote root no connection
        # may reach in this release, and a connection whose selection, record or key changed.
        "target_root_is_remote",
        "server_authorization_changed",
        # The consent step (``client.server_profile``, ADR-052): what the server offers or needs
        # changed since the owner consented, or it requires a level they did not agree to.
        "server_profile_changed",
        "server_level_unavailable",
    }
)
# The refusals ``require_current_authorization`` makes before anything is sent to a remote target.
PRE_DIAL_REFUSALS: Final = frozenset(
    {"target_reauthorization_required", "zero_network_remote_selected"}
)
# Every closed reason a remote target's root is refused with before anything is sent or started
# in this release (``active_remote_refusal``, and the connect seams of ``finishup.service.client``):
# the two above, and ``target_root_is_remote`` for any other remote root, since this release
# reaches no server on another machine. Each is a protocol reason code with its own directive,
# and the one remote ``phase`` a structured error keeps (``protocol.errors``).
REMOTE_ROOT_REFUSALS: Final = PRE_DIAL_REFUSALS | frozenset({"target_root_is_remote"})
assert REMOTE_ROOT_REFUSALS == REMOTE_ROOT_REFUSAL_PHASES
# The continuation of any of those refusals while an isolation variable or a pinned launcher names
# the root (``remote_root_continuation``): 'finishup server use local' answers
# ``selection_overridden`` there, so the way back is to clear that override instead.
REMOTE_ROOT_OVERRIDE_CONTINUATION: Final = "remote_root_override_clear"
# The continuation of ``server_profile_changed`` while this computer's copy of that server's
# profile still agrees with the owner's consent (``profile_change_continuation``): the server
# refused a revision this computer has not fetched, so what changed is not known yet and the
# request may be repeated; ``remote_reconsent`` stays for a consent known to need the owner.
PROFILE_CHECKING_CONTINUATION: Final = "remote_profile_checking"
_PROFILE_CHANGED_PHASE: Final = "server_profile_changed"


class TargetError(Exception):
    """A bounded target failure; ``reason`` is a closed token, never user text."""

    reason: str

    def __init__(self, reason: str) -> None:
        if reason not in _REASONS:
            raise ValueError("target_reason_invalid")
        self.reason = reason
        super().__init__(reason)


class TargetRecordUnreadable(TargetError):
    """The active root resolves, but the server target record it holds cannot be read.

    Its ``reason`` is the record's own closed refusal (``target_root_unsafe`` or
    ``target_record_invalid``). Whether such a root is this machine's server or a remote one is
    unknown, so a caller deciding where something may run fails closed on it, while a root that
    cannot be resolved at all stays a plain ``TargetError`` its own path reports. ``target_id`` is
    the root's generated ``t_<8 hex>`` folder name when it has one, never other folder text.
    """

    target_id: str | None

    def __init__(self, reason: str, target_id: str | None) -> None:
        super().__init__(reason)
        self.target_id = (
            target_id if target_id is not None and _TARGET_ID.match(target_id) else None
        )


def _absolute_text(value: str | None, *, required: bool = False) -> None:
    if value is None:
        if required:
            raise TargetError("target_path_invalid")
        return
    if (
        type(value) is not str
        or not value.startswith("/")
        or len(value) > _MAX_PATH_TEXT
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise TargetError("target_path_invalid")


def _port(value: object) -> int:
    if type(value) is not int or not 1 <= value <= 65_535:
        raise TargetError("target_url_invalid")
    return value


def _host(value: object) -> str:
    """A DNS name or an IP literal; never anything ``ssh`` or a URL parser could read as an option."""

    if type(value) is not str or not value:
        raise TargetError("target_url_invalid")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if not _DNS_NAME.match(value):
            raise TargetError("target_url_invalid") from None
    return value


def validate_name(name: str) -> str:
    """Return ``name`` when it is a usable target name, else raise a closed reason."""

    if type(name) is not str or not _NAME.match(name):
        raise TargetError("target_name_invalid")
    if name in RESERVED_NAMES:
        raise TargetError("target_name_reserved")
    return name


def normalize_https_url(raw: str, *, loopback_only: bool = False) -> str:
    """Normalize ``https://host[:port][/base]``; refuse plain HTTP, userinfo, query, fragment
    and a ``.`` or ``..`` path segment.

    ``loopback_only`` additionally requires ``127.0.0.1`` or ``[::1]`` with an explicit port
    (the ``local_port`` kind).
    """

    if type(raw) is not str or len(raw) > 2_048 or any(ord(c) <= 0x20 for c in raw):
        raise TargetError("target_url_invalid")
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        raise TargetError("target_url_invalid") from None
    if (
        parts.scheme.lower() != "https"
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or "@" in parts.netloc
        or parts.hostname is None
        or not _URL_PATH.match(parts.path)
        # A dot segment is resolved away by the client library before a request is sent, so
        # the recorded path (official matching, the consented origin) would name another one.
        or any(segment in {".", ".."} for segment in parts.path.split("/"))
    ):
        raise TargetError("target_url_invalid")
    host = parts.hostname.lower()
    if ":" in host:
        try:
            literal = ipaddress.IPv6Address(host)
        except ValueError:
            raise TargetError("target_url_invalid") from None
        authority = f"[{literal.compressed}]"
    else:
        authority = _host(host)
    if port is not None:
        _port(port)
    if loopback_only:
        if port is None or authority not in {"127.0.0.1", "[::1]"}:
            raise TargetError("target_url_invalid")
    path = parts.path.rstrip("/")
    return f"https://{authority}{'' if port is None else f':{port}'}{path}"


def parse_ssh_url(raw: str) -> tuple[str | None, str, int]:
    """Parse ``ssh://[user@]host[:port]`` into ``(user, host, port)``; nothing else is accepted."""

    if type(raw) is not str or len(raw) > 512 or any(ord(c) <= 0x20 for c in raw):
        raise TargetError("target_url_invalid")
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        raise TargetError("target_url_invalid") from None
    if (
        parts.scheme != "ssh"
        or parts.password is not None
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
        or parts.hostname is None
    ):
        raise TargetError("target_url_invalid")
    user = parts.username
    if user is not None and not _SSH_USER.match(user):
        raise TargetError("target_url_invalid")
    host = parts.hostname
    if ":" in host:
        try:
            host = ipaddress.IPv6Address(host).compressed
        except ValueError:
            raise TargetError("target_url_invalid") from None
    else:
        host = _host(host)
    return user, host, 22 if port is None else _port(port)


@dataclass(frozen=True, slots=True)
class ServerConsent:
    """What the owner consented to for a remote target, under which server profile (ADR-052).

    ``level`` (``L1``; ``L2`` arrives with the server copy), the ``profile_digest`` and the
    ``issuer`` and ``revision`` of the server's profile revision the consent was given or last
    adjusted under, the ``retention`` chosen (``None`` at L1: nothing is kept), the digest of the
    consented envelope (``config/consent-envelope.json``), and, when a narrowed profile adjusted
    the consent since the owner last confirmed it, when (``adjusted_at``) and which coverage it
    reduced (``coverage_reduced``). The disclosure version is the record's own.
    """

    level: str
    profile_digest: str
    issuer: str
    revision: int
    retention_kind: str | None
    retention_days: int | None
    envelope_digest: str
    adjusted_at: str | None = None
    coverage_reduced: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.level not in _LEVELS:
            raise TargetError("target_record_invalid")
        for digest in (self.profile_digest, self.envelope_digest):
            if type(digest) is not str or not _DIGEST.match(digest):
                raise TargetError("target_record_invalid")
        if type(self.issuer) is not str or not _ISSUER.match(self.issuer):
            raise TargetError("target_record_invalid")
        if type(self.revision) is not int or not 1 <= self.revision <= 2**53 - 1:
            raise TargetError("target_record_invalid")
        if self.retention_kind is None:
            if self.retention_days is not None:
                raise TargetError("target_record_invalid")
        elif self.retention_kind not in _RETENTION_KINDS or (
            (self.retention_kind == "days")
            != (type(self.retention_days) is int and 1 <= self.retention_days <= 36_500)
        ):
            raise TargetError("target_record_invalid")
        if (self.level == "L1") != (self.retention_kind is None):
            # Level L1 keeps no copy, so nothing is retained; L2 always names a retention.
            raise TargetError("target_record_invalid")
        if self.adjusted_at is None:
            if self.coverage_reduced:
                raise TargetError("target_record_invalid")
        else:
            try:
                parse_rfc3339_ms(self.adjusted_at)
            except (TypeError, ValueError):
                raise TargetError("target_record_invalid") from None
            if (
                type(self.coverage_reduced) is not tuple
                or list(self.coverage_reduced) != sorted(set(self.coverage_reduced))
                or not set(self.coverage_reduced) <= _COVERAGE
            ):
                raise TargetError("target_record_invalid")

    def body(self) -> dict[str, JsonValue]:
        """The exact ``consent`` object of a ``/2`` record."""

        return {
            "level": self.level,
            "profile_digest": self.profile_digest,
            "profile_revision": {"issuer": self.issuer, "revision": self.revision},
            "retention": None
            if self.retention_kind is None
            else {"kind": self.retention_kind, "days": self.retention_days},
            "envelope_digest": self.envelope_digest,
            "adjusted": None
            if self.adjusted_at is None
            else {"at": self.adjusted_at, "coverage_reduced": list(self.coverage_reduced)},
        }


def _consent_from(value: JsonValue) -> ServerConsent:
    if type(value) is not dict:
        raise ValueError("consent")
    source = cast(dict[str, JsonValue], value)
    if frozenset(source) != _CONSENT_FIELDS:
        raise ValueError("consent")
    revision = source["profile_revision"]
    if type(revision) is not dict or set(cast(dict[str, JsonValue], revision)) != {
        "issuer",
        "revision",
    }:
        raise ValueError("consent")
    revision_source = cast(dict[str, JsonValue], revision)
    retention = source["retention"]
    kind: object = None
    days: object = None
    if retention is not None:
        if type(retention) is not dict or set(cast(dict[str, JsonValue], retention)) != {
            "kind",
            "days",
        }:
            raise ValueError("consent")
        kind = cast(dict[str, JsonValue], retention)["kind"]
        days = cast(dict[str, JsonValue], retention)["days"]
        if type(kind) is not str or (days is not None and type(days) is not int):
            raise ValueError("consent")
    adjusted = source["adjusted"]
    adjusted_at: object = None
    reduced: tuple[str, ...] = ()
    if adjusted is not None:
        if type(adjusted) is not dict or set(cast(dict[str, JsonValue], adjusted)) != {
            "at",
            "coverage_reduced",
        }:
            raise ValueError("consent")
        adjusted_at = cast(dict[str, JsonValue], adjusted)["at"]
        fields = cast(dict[str, JsonValue], adjusted)["coverage_reduced"]
        if type(fields) is not list or any(type(item) is not str for item in fields):
            raise ValueError("consent")
        reduced = tuple(cast(list[str], fields))
    for name in ("level", "profile_digest", "envelope_digest"):
        if type(source[name]) is not str:
            raise ValueError(name)
    if type(revision_source["issuer"]) is not str or type(revision_source["revision"]) is not int:
        raise ValueError("consent")
    if adjusted_at is not None and type(adjusted_at) is not str:
        raise ValueError("consent")
    return ServerConsent(
        cast(str, source["level"]),
        cast(str, source["profile_digest"]),
        revision_source["issuer"],
        revision_source["revision"],
        kind,
        days,
        cast(str, source["envelope_digest"]),
        adjusted_at,
        reduced,
    )


@dataclass(frozen=True, slots=True)
class ServerTarget:
    """One validated ``yoetz.server-target/1`` (or, with a consent, ``/2``) record."""

    target_id: str
    name: str
    kind: TargetKind
    created_at: str
    base_url: str | None = None
    ca_file: str | None = None
    tls_pin: str | None = None
    credential: CredentialLocation | None = None
    user: str | None = None
    host: str | None = None
    port: int | None = None
    remote_root: str | None = None
    remote_endpoint: str | None = None
    remote_launcher: str | None = None
    claim_salt: str | None = None
    authorized_at: str | None = None
    disclosure_version: int | None = None
    # The owner's consent to a server profile (ADR-052): remote kinds only, ``/2`` records only.
    consent: ServerConsent | None = None

    def __post_init__(self) -> None:
        if type(self.target_id) is not str or not _TARGET_ID.match(self.target_id):
            raise TargetError("target_record_invalid")
        validate_name(self.name)
        if self.kind not in TARGET_KINDS:
            raise TargetError("target_record_invalid")
        try:
            parse_rfc3339_ms(self.created_at)
        except (TypeError, ValueError):
            raise TargetError("target_record_invalid") from None
        fields = _FIELDS_BY_KIND[self.kind]
        for name in ("base_url", "ca_file", "tls_pin", "credential", "user", "host", "port"):
            if name not in fields and getattr(self, name) is not None:
                raise TargetError("target_record_invalid")
        for name in ("remote_root", "remote_endpoint", "remote_launcher"):
            if name not in fields and getattr(self, name) is not None:
                raise TargetError("target_record_invalid")
        if self.kind == "local":
            if any(
                value is not None
                for value in (
                    self.claim_salt,
                    self.authorized_at,
                    self.disclosure_version,
                    self.consent,
                )
            ):
                raise TargetError("target_record_invalid")
            return
        if self.consent is not None and type(self.consent) is not ServerConsent:
            raise TargetError("target_record_invalid")
        self._validate_authorization()
        if self.kind == "ssh":
            if self.host is None or self.port is None:
                raise TargetError("target_record_invalid")
            if self.user is not None and (
                type(self.user) is not str or not _SSH_USER.match(self.user)
            ):
                raise TargetError("target_record_invalid")
            if ":" not in self.host:
                _host(self.host)
            else:
                try:
                    ipaddress.IPv6Address(self.host)
                except ValueError:
                    raise TargetError("target_record_invalid") from None
            _port(self.port)
            for value in (self.remote_root, self.remote_endpoint, self.remote_launcher):
                _absolute_text(value)
            return
        if self.base_url is None:
            raise TargetError("target_record_invalid")
        if normalize_https_url(self.base_url, loopback_only=self.kind == "local_port") != (
            self.base_url
        ):
            raise TargetError("target_record_invalid")
        if self.ca_file is not None and self.tls_pin is not None:
            raise TargetError("target_tls_invalid")
        _absolute_text(self.ca_file)
        if self.tls_pin is not None and (
            type(self.tls_pin) is not str or not _TLS_PIN.match(self.tls_pin)
        ):
            raise TargetError("target_tls_invalid")
        if self.credential not in {None, "keyring", "file"}:
            raise TargetError("target_record_invalid")

    def _validate_authorization(self) -> None:
        try:
            salt = base64.b64decode(cast(str, self.claim_salt), validate=True)
            parse_rfc3339_ms(self.authorized_at)
        except (TypeError, ValueError, binascii.Error):
            raise TargetError("target_record_invalid") from None
        if len(salt) != CLAIM_SALT_BYTES:
            raise TargetError("target_record_invalid")
        version = self.disclosure_version
        if type(version) is not int or version < 1:
            raise TargetError("target_record_invalid")

    @property
    def is_remote(self) -> bool:
        return self.kind in REMOTE_KINDS

    @property
    def needs_reauthorization(self) -> bool:
        """True when the owner confirmed an older disclosure than this release shows."""

        return self.is_remote and self.disclosure_version != DISCLOSURE_VERSION

    @property
    def schema(self) -> str:
        """``/2`` for a record with a consent to a server profile, else ``/1``."""

        return TARGET_SCHEMA if self.consent is None else CONSENTED_TARGET_SCHEMA

    def body(self) -> dict[str, JsonValue]:
        """The exact ``target.json`` object for this kind."""

        values: dict[str, JsonValue] = {
            "schema": self.schema,
            "target_id": self.target_id,
            "name": self.name,
            "kind": self.kind,
            "created_at": self.created_at,
            "base_url": self.base_url,
            "ca_file": self.ca_file,
            "tls_pin": self.tls_pin,
            "credential": self.credential,
            "user": self.user,
            "host": self.host,
            "port": self.port,
            "remote_root": self.remote_root,
            "remote_endpoint": self.remote_endpoint,
            "remote_launcher": self.remote_launcher,
            "claim_salt": self.claim_salt,
            "authorized_at": self.authorized_at,
            "disclosure_version": self.disclosure_version,
        }
        fields = _FIELDS_BY_KIND[self.kind]
        body = {key: value for key, value in values.items() if key in fields}
        if self.consent is not None:
            body["consent"] = self.consent.body()
        return body

    def encode(self) -> bytes:
        return canonical_encode(cast(JsonValue, self.body())) + b"\n"


def _decode_target(encoded: bytes) -> ServerTarget:
    try:
        if not encoded.endswith(b"\n"):
            raise ValueError("trailer")
        value = strict_json_parse(encoded[:-1])
        if type(value) is not dict:
            raise ValueError("shape")
        source = cast(dict[str, JsonValue], value)
        kind = source.get("kind")
        if type(kind) is not str or kind not in _FIELDS_BY_KIND:
            raise ValueError("kind")
        consented = source.get("schema") == CONSENTED_TARGET_SCHEMA and kind in REMOTE_KINDS
        expected: frozenset[str] = _FIELDS_BY_KIND[kind] | (
            frozenset({"consent"}) if consented else frozenset[str]()
        )
        if frozenset(source) != expected or source["schema"] not in {
            TARGET_SCHEMA,
            CONSENTED_TARGET_SCHEMA,
        }:
            raise ValueError("fields")
        if canonical_encode(cast(JsonValue, source)) != encoded[:-1]:
            raise ValueError("canonical")
        for name in ("target_id", "name", "created_at"):
            if type(source[name]) is not str:
                raise ValueError(name)

        def text(name: str) -> str | None:
            value = source.get(name)
            if value is not None and type(value) is not str:
                raise ValueError(name)
            return value

        port = source.get("port")
        version = source.get("disclosure_version")
        if (port is not None and type(port) is not int) or (
            version is not None and type(version) is not int
        ):
            raise ValueError("integer")
        record = ServerTarget(
            cast(str, source["target_id"]),
            cast(str, source["name"]),
            cast(TargetKind, kind),
            cast(str, source["created_at"]),
            base_url=text("base_url"),
            ca_file=text("ca_file"),
            tls_pin=text("tls_pin"),
            credential=cast(CredentialLocation | None, text("credential")),
            user=text("user"),
            host=text("host"),
            port=port,
            remote_root=text("remote_root"),
            remote_endpoint=text("remote_endpoint"),
            remote_launcher=text("remote_launcher"),
            claim_salt=text("claim_salt"),
            authorized_at=text("authorized_at"),
            disclosure_version=version,
            consent=_consent_from(source["consent"]) if consented else None,
        )
    except TargetError:
        raise TargetError("target_record_invalid") from None
    except (TypeError, ValueError):
        raise TargetError("target_record_invalid") from None
    if record.encode() != encoded:
        raise TargetError("target_record_invalid")
    return record


def _read_owner_only(path: Path, maximum: int) -> bytes | None:
    """Read a regular, owner-owned, owner-only file; ``None`` when absent; fail closed otherwise."""

    try:
        facts = path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError:
        raise TargetError("target_root_unsafe") from None
    if (
        not stat.S_ISREG(facts.st_mode)
        or facts.st_uid != os.geteuid()
        or stat.S_IMODE(facts.st_mode) & 0o077
        or facts.st_size > maximum
    ):
        raise TargetError("target_root_unsafe")
    # The file can still change between the check and the read (replaced by a link, removed,
    # made unreadable): that is the same unsafe record, never a raw ``OSError``.
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise TargetError("target_root_unsafe") from None
    try:
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError:
        raise TargetError("target_root_unsafe") from None
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    if len(data) > maximum:
        raise TargetError("target_root_unsafe")
    return data


def _write_owner_only(path: Path, encoded: bytes) -> None:
    """Atomically replace ``path`` with ``encoded`` (owner-only temp file, fsync, rename)."""

    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
    )
    try:
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
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def servers_dir() -> Path:
    """``<ambient state dir>/servers``: where every target root lives."""

    _config, state = ambient_registry_dirs()
    return state / SERVERS_DIR_NAME


def selection_path() -> Path:
    """``<ambient config dir>/server-selection.json``."""

    config, _state = ambient_registry_dirs()
    return config / SERVER_SELECTION_NAME


def target_root(target_id: str) -> Path:
    if type(target_id) is not str or not _TARGET_ID.match(target_id):
        raise TargetError("target_unknown")
    return servers_dir() / target_id


def _check_root_length(root: Path, kind: TargetKind) -> None:
    """Refuse a root whose longest socket would not fit this platform's ``sun_path`` bound.

    A ``local`` root is an instance root, held to the service's own endpoints exactly as
    ``finishup instance create`` holds it (``instance_root_too_long``); a remote root only to the
    sockets a client binds there.
    """

    if kind in REMOTE_KINDS:
        fits = all(
            socket_path_fits(root / name, temporary_suffix_bytes=suffix)
            for name, suffix in _REMOTE_CLIENT_SOCKETS
        )
    else:
        fits = instance_root_fits(root)
    if not fits:
        raise TargetError("target_root_too_long")


def read_target(root: Path) -> ServerTarget | None:
    """Return the record in ``root``, ``None`` when it has none, or fail closed."""

    encoded = _read_owner_only(root / SERVER_TARGET_FILE_NAME, _MAX_RECORD_BYTES)
    if encoded is None:
        return None
    record = _decode_target(encoded)
    if record.target_id != root.name:
        raise TargetError("target_record_invalid")
    return record


def write_target(root: Path, record: ServerTarget) -> None:
    """Write ``record`` into its own root (owner-only, atomic)."""

    if record.target_id != root.name:
        raise TargetError("target_record_invalid")
    try:
        verify_private_local_bundle(root)
        ensure_owner_only_dir(root)
    except PathSafetyError:
        raise TargetError("target_root_unsafe") from None
    if record.is_remote:
        # First, so the hold's dormancy check never misses a remote record (ADR-052, O3).
        _note_remote_recorded()
    _write_owner_only(root / SERVER_TARGET_FILE_NAME, record.encode())


@contextmanager
def registry_lock() -> Generator[None]:
    """Serialize registry changes (add, remove, select) across processes on this machine."""

    directory = servers_dir()
    try:
        ensure_owner_only_dir(directory)
    except PathSafetyError:
        raise TargetError("target_root_unsafe") from None
    descriptor = os.open(
        directory / _REGISTRY_LOCK_NAME,
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        facts = os.fstat(descriptor)
        if not stat.S_ISREG(facts.st_mode) or facts.st_uid != os.geteuid():
            raise TargetError("target_root_unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def _registry_roots() -> tuple[tuple[Path, ServerTarget | None], ...]:
    """Every ``t_`` folder in the registry with its record (``None``: it holds no record)."""

    directory = servers_dir()
    try:
        entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
    except FileNotFoundError:
        return ()
    except OSError:
        raise TargetError("target_root_unsafe") from None
    found: list[tuple[Path, ServerTarget | None]] = []
    for entry in entries:
        if not _TARGET_ID.match(entry.name):
            continue
        if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
            raise TargetError("target_root_unsafe")
        root = Path(entry.path)
        found.append((root, read_target(root)))
    return tuple(found)


def list_targets() -> tuple[ServerTarget, ...]:
    """Every target, ordered by name; a damaged root fails closed instead of being skipped.

    A folder that holds no ``target.json`` at all is not a target (``leftover_target_ids``): an
    add or a remove that was interrupted left it, nothing can select it, and it never keeps the
    registry from being read.
    """

    records = [record for _root, record in _registry_roots() if record is not None]
    return tuple(sorted(records, key=lambda record: record.name))


def _remote_presence_path() -> Path:
    """``<ambient state dir>/servers/remote-target-recorded``: present while a remote record is."""

    return servers_dir() / _REMOTE_PRESENCE_NAME


def remote_target_recorded() -> bool:
    """Whether this computer records any server elsewhere (a ``local_port``, ``ssh`` or ``https``
    target), selected or not.

    The repository hold's own reads and records stay dormant until it is true (ADR-052, the
    owner's answer O3): with no remote target, a session start, a privacy ceremony and a policy
    change behave exactly as before the hold existed. A session-start hook asks, so the answer is
    a bounded presence check, two ``lstat`` calls however many targets or leftover folders the
    registry holds: the presence file every remote record is written after
    (``write_target``) and that goes once the last one is removed (``remove_target_root``). A
    registry folder or presence file that cannot be examined fails toward the hold (true). Never
    raises.
    """

    try:
        directory = servers_dir()
        facts = os.lstat(directory)
    except FileNotFoundError:
        return False
    except Exception:
        return True
    if not stat.S_ISDIR(facts.st_mode):
        return True
    try:
        os.lstat(directory / _REMOTE_PRESENCE_NAME)
    except FileNotFoundError:
        return False
    except Exception:
        return True
    return True


def _note_remote_recorded() -> None:
    """Make the presence file before a remote record is written, so a crash in between fails
    toward the hold. Refused as ``target_root_unsafe`` when it cannot be made."""

    try:
        descriptor = os.open(
            _remote_presence_path(),
            os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            0o600,
        )
    except OSError:
        raise TargetError("target_root_unsafe") from None
    os.close(descriptor)


def reconcile_remote_presence() -> bool:
    """After a remote target is removed: drop the presence file once no remote record is left.

    Whether a remote target is still recorded. The whole registry is read here (an owner command,
    never a hook); a registry that cannot be read keeps the file. Never raises.
    """

    try:
        if any(record.is_remote for record in _remote_scan()):
            return True
        _remote_presence_path().unlink(missing_ok=True)
    except Exception:
        return True
    return False


def _remote_scan() -> Generator[ServerTarget]:
    """Each registry record, lazily, so a scan stops at the first remote one. A folder that holds
    no record (an interrupted add or remove) is skipped: nothing can select it."""

    directory = servers_dir()
    try:
        entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
    except FileNotFoundError:
        return
    for entry in entries:
        if not _TARGET_ID.match(entry.name):
            continue
        if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
            raise TargetError("target_root_unsafe")
        record = read_target(Path(entry.path))
        if record is not None:
            yield record


def leftover_target_ids() -> tuple[str, ...]:
    """The ids of registry folders that hold no ``target.json``, in id order.

    Left by an add or a remove that was interrupted. ``finishup server list`` reports them and
    ``finishup server remove ID`` deletes one (``remove_leftover_root``).
    """

    return tuple(root.name for root, record in _registry_roots() if record is None)


def find_target(name: str) -> ServerTarget:
    """The target named ``name``; ``target_unknown`` when there is none."""

    validate_name(name)
    for record in list_targets():
        if record.name == name:
            return record
    raise TargetError("target_unknown")


def _new_target_id(directory: Path) -> str:
    for _attempt in range(16):
        candidate = f"t_{secrets.token_hex(4)}"
        if not (directory / candidate).exists():
            return candidate
    raise TargetError("target_root_unsafe")


def _now() -> str:
    return format_rfc3339_ms(datetime.now(UTC))


def new_local_target(name: str, *, now: str | None = None) -> tuple[ServerTarget, Path]:
    """Create a named local server: a persistent instance root plus its ``target.json``.

    The instance root is made by ``finishup instance``'s own creation path, so it gets the same
    root-shape checks (including the socket path bound) and an instance identity a later
    ``remove`` can dispose of. Callers hold ``registry_lock()``.
    """

    from finishup.cli.instance import create_instance
    from finishup.config.installation import InstanceIdentityError

    validate_name(name)
    if any(record.name == name for record in list_targets()):
        raise TargetError("target_name_taken")
    directory = servers_dir()
    target_id = _new_target_id(directory)
    root = directory / target_id
    _check_root_length(root, "local")
    try:
        create_instance(root=root, lifecycle="persistent")
    except InstanceIdentityError as error:
        if error.reason == "instance_root_too_long":
            raise TargetError("target_root_too_long") from None
        raise TargetError("target_root_unsafe") from None
    except PathSafetyError:
        raise TargetError("target_root_unsafe") from None
    record = ServerTarget(target_id, name, "local", now or _now())
    try:
        write_target(root, record)
    except BaseException:
        shutil.rmtree(root, ignore_errors=True)
        raise
    return record, root


def new_remote_target(
    name: str,
    kind: TargetKind,
    *,
    base_url: str | None = None,
    ca_file: str | None = None,
    tls_pin: str | None = None,
    user: str | None = None,
    host: str | None = None,
    port: int | None = None,
    remote_root: str | None = None,
    remote_launcher: str | None = None,
    remote_endpoint: str | None = None,
    now: str | None = None,
) -> tuple[ServerTarget, Path]:
    """Create a remote target root (client state only) with a fresh claim salt.

    The caller has already obtained the owner's typed confirmation of the current disclosure on
    the trusted console; ``authorized_at`` records when. Callers hold ``registry_lock()``.
    ``remote_endpoint`` is the SSH server's control endpoint its own launcher reported (SSH
    discovery, ADR-052); without one it is ``<remote_root>/run/control.sock`` when a remote root
    is given.
    """

    if kind not in REMOTE_KINDS:
        raise TargetError("target_record_invalid")
    validate_name(name)
    if any(record.name == name for record in list_targets()):
        raise TargetError("target_name_taken")
    stamp = now or _now()
    if remote_endpoint is None and remote_root is not None:
        remote_endpoint = f"{remote_root.rstrip('/')}/run/control.sock"
    directory = servers_dir()
    target_id = _new_target_id(directory)
    root = directory / target_id
    _check_root_length(root, kind)
    record = ServerTarget(
        target_id,
        name,
        kind,
        stamp,
        base_url=base_url,
        ca_file=ca_file,
        tls_pin=tls_pin,
        user=user,
        host=host,
        port=port,
        remote_root=remote_root,
        remote_endpoint=remote_endpoint,
        remote_launcher=remote_launcher,
        claim_salt=base64.b64encode(secrets.token_bytes(CLAIM_SALT_BYTES)).decode("ascii"),
        authorized_at=stamp,
        disclosure_version=DISCLOSURE_VERSION,
    )
    try:
        verify_private_local_bundle(directory)
        ensure_owner_only_dir(directory)
        root.mkdir(mode=0o700)
    except (PathSafetyError, OSError):
        # Nothing was made here (an existing root is never adopted or removed).
        raise TargetError("target_root_unsafe") from None
    try:
        for child in ("state", "config", "run", "log"):
            (root / child).mkdir(mode=0o700)
        write_target(root, record)
    except BaseException:
        shutil.rmtree(root, ignore_errors=True)
        raise
    return record, root


def reauthorized(record: ServerTarget, *, now: str | None = None) -> ServerTarget:
    """``record`` with a fresh authorization of the current disclosure version."""

    if not record.is_remote:
        raise TargetError("target_record_invalid")
    return replace(record, authorized_at=now or _now(), disclosure_version=DISCLOSURE_VERSION)


def require_current_authorization(record: ServerTarget | None) -> None:
    """Refuse a remote target that nothing may be sent to now (ADR-051 decision 8).

    Two refusals, before anything is sent, with or without a workspace:

    * ``zero_network_remote_selected``: this computer last reported that its privacy policy
      forbids all network use (``client.everyday_policy``, a file read, never a service round
      trip). This computer's zero-network policy and a server on another machine, a port or the
      web are never in force together (maintainer decision, 2026-11-07); this is the last line of
      defence for a process whose selection predates the change. ``finishup server use local``
      is the way out. A process whose root an isolation variable or runtime pin decides keeps its
      own policy and is not refused here.
    * ``target_reauthorization_required``: the owner authorized the target under an older
      disclosure. A new disclosure version needs a fresh typed confirmation of the current one
      (``reauthorized``). The remote kinds are closed in this release, so ``finishup server use
      NAME`` cannot give it (``remote_kind_unavailable``): the way on is a server on this
      computer, and a later release can authorize the target again.

    ``None`` and a local record pass. Every path that opens a connection to a remote target calls
    this; the display and reverse paths (``server status``, ``list``, ``test``, ``remove``,
    ``logout``) do not, so the owner can still see and remove a stale target.
    """

    if record is None or not record.is_remote:
        return
    from finishup.client.everyday_policy import last_reported_zero_network

    if last_reported_zero_network() is not None:
        raise TargetError("zero_network_remote_selected")
    if record.needs_reauthorization:
        raise TargetError("target_reauthorization_required")


def remove_target_root(record: ServerTarget) -> None:
    """Delete a remote target's root; local roots go through ``dispose_instance`` instead."""

    root = target_root(record.target_id)
    if record.kind == "local":
        raise TargetError("target_record_invalid")
    if root.is_symlink() or not root.is_dir():
        raise TargetError("target_root_unsafe")
    shutil.rmtree(root)
    reconcile_remote_presence()


def remove_leftover_root(target_id: str) -> bool:
    """Delete the registry folder ``target_id`` when it still holds no ``target.json``.

    Callers hold ``registry_lock()`` and have stopped what this client ran there. Returns False
    when it is not a leftover (no such folder, or it holds a record), and changes nothing then.
    """

    root = target_root(target_id)
    if root.is_symlink() or not root.is_dir():
        return False
    if read_target(root) is not None:
        return False
    shutil.rmtree(root)
    return True


def read_selected_target_id() -> str | None:
    """The target id the selection file names, ``None`` when there is none, or fail closed."""

    encoded = _read_owner_only(selection_path(), 1_024)
    if encoded is None:
        return None
    try:
        value = strict_json_parse(encoded.rstrip(b"\n"))
    except ValueError:
        raise TargetError("selection_invalid") from None
    if type(value) is not dict:
        raise TargetError("selection_invalid")
    source = cast(dict[str, JsonValue], value)
    target_id = source.get("target_id")
    if (
        set(source) != {"schema", "target_id"}
        or source.get("schema") != SERVER_SELECTION_SCHEMA
        or type(target_id) is not str
        or not _TARGET_ID.match(target_id)
    ):
        raise TargetError("selection_invalid")
    return target_id


def write_selection(record: ServerTarget) -> None:
    """Select ``record`` for every new client process (hooks at once; a bridge on restart)."""

    path = selection_path()
    try:
        ensure_owner_only_dir(path.parent)
    except PathSafetyError:
        raise TargetError("target_root_unsafe") from None
    body: dict[str, JsonValue] = {"schema": SERVER_SELECTION_SCHEMA, "target_id": record.target_id}
    _write_owner_only(path, canonical_encode(body) + b"\n")
    reset_selection_memo()


def clear_selection() -> bool:
    """Return to the everyday server; returns whether a selection was removed.

    A selection that cannot be read (damaged, foreign-mode, or a symlink, which the root
    resolution refuses) is removed too: this is the documented way back from it. Unlinking a
    symlink removes the link, never what it points to. Anything but a file or a link is refused.
    """

    path = selection_path()
    try:
        facts = path.lstat()
    except FileNotFoundError:
        reset_selection_memo()
        return False
    if not (stat.S_ISREG(facts.st_mode) or stat.S_ISLNK(facts.st_mode)):
        raise TargetError("selection_invalid")
    path.unlink()
    reset_selection_memo()
    return True


def selection_source() -> SelectionSource:
    """Which source decided this process's root: the variable, the pin, the selection, ambient."""

    return isolation_binding()


def active_remote_refusal() -> str | None:
    """The closed reason every connection from this process is refused with before any dial.

    Exactly the phase the connect seams refuse with (``finishup.service.client``), one of
    ``REMOTE_ROOT_REFUSALS``: ``zero_network_remote_selected`` or
    ``target_reauthorization_required`` when ``require_current_authorization`` refuses the
    remote target this process's root is, and ``target_root_is_remote`` for any other remote
    root and for a root whose record cannot be read (it may name a remote kind), since this
    release reaches no server on another machine. ``None`` for a local root (the everyday server,
    a named local server, an isolated root that is not a target) and for a root that cannot be
    resolved at all, which the caller's own path-safety refusal names. Hook-safe: it reads only
    the target record and this computer's last-reported policy marker, never a service, so a
    hook or a setup entry can name the refusal without spending its budget or asking anything
    (ADR-051 decision 8). Never raises.
    """

    try:
        record = active_target_record()
    except TargetRecordUnreadable:
        return "target_root_is_remote"
    except Exception:
        return None
    if record is None or not record.is_remote:
        return None
    try:
        require_current_authorization(record)
    except TargetError as error:
        return error.reason if error.reason in PRE_DIAL_REFUSALS else "target_root_is_remote"
    except Exception:
        return "target_root_is_remote"
    return "target_root_is_remote"


def remote_root_continuation(phase: str) -> str | None:
    """The continuation a remote-root refusal ``phase`` resolves to in this process.

    For one of ``REMOTE_ROOT_REFUSALS``, the way back depends on what named the root. When the
    saved selection did, it is the phase's own registry continuation: 'finishup server use local'
    (``remote_target_no_local_service``, ``server_reauthorization_required``,
    ``zero_network_local_server_required``), then a new agent session, since an open one keeps
    the root its MCP bridge started with. When an isolation variable or a pinned launcher did, the
    selection is not in force ('finishup server use local' answers ``selection_overridden``), so
    it is ``REMOTE_ROOT_OVERRIDE_CONTINUATION``: unset that variable or use an unpinned launcher.
    A variable or pin that cannot be read still names the root (it fails closed on its own path).
    ``server_profile_changed`` resolves by the active target's consent
    (``profile_change_continuation``). Any other phase resolves as ``continuation_for_reason``
    does. Every surface that names a remote-root refusal or a remote connection phase (the CLI,
    setup, the menu, the terminal interface, hooks and MCP) reads its continuation here.
    Hook-safe: environment, pin and target-file reads only.
    """

    from finishup.protocol.recovery import continuation_for_reason

    if phase in REMOTE_ROOT_REFUSALS and _root_named_explicitly():
        return REMOTE_ROOT_OVERRIDE_CONTINUATION
    if phase == _PROFILE_CHANGED_PHASE:
        try:
            record = active_target_record()
        except Exception:  # noqa: BLE001 - an unreadable record is no known consent
            record = None
        return profile_change_continuation(record)
    return continuation_for_reason(phase)


def profile_change_continuation(record: ServerTarget | None) -> str:
    """The continuation of a ``server_profile_changed`` refusal for the server ``record`` names.

    ``remote_reconsent`` when the consent step already refuses ``record`` on what this computer
    holds (``server_profile.consent_verdict``: a wider or changed profile, a level above the
    consent, another issuer, or a consent that is missing or cannot be read): only the owner
    agrees again. ``PROFILE_CHECKING_CONTINUATION`` when it admits it: the refusal came from
    the server, naming a revision this computer has not fetched yet, so what changed is not
    known, and the refresh such a refusal asks for may show only a narrowing this computer adjusts
    to by itself; the agent repeats the same request instead of asking the owner. A ``record``
    that is ``None`` or not remote has no consent to read: ``remote_reconsent``. Hook-safe: file
    reads only; never raises.
    """

    if record is None or not record.is_remote:
        return "remote_reconsent"
    from finishup.client.server_profile import consent_verdict

    try:
        verdict = consent_verdict(record)
    except Exception:  # noqa: BLE001 - a verdict that cannot be read is no known consent
        return "remote_reconsent"
    return "remote_reconsent" if verdict.phase is not None else PROFILE_CHECKING_CONTINUATION


def _root_named_explicitly() -> bool:
    """Whether an isolation variable or a runtime pin, not the selection, names this root."""

    from finishup.config.paths import isolated_root_variable, read_runtime_pin

    try:
        return isolated_root_variable() is not None or read_runtime_pin() is not None
    except PathSafetyError:
        return True


def root_named_explicitly() -> bool:
    """Whether an isolation variable or a runtime pin, not the selection, names this root.

    Then 'finishup server use local' answers ``selection_overridden``: the way back to this
    computer's own server is to unset that variable or use an unpinned launcher.
    """

    return _root_named_explicitly()


def active_root_may_be_remote() -> bool:
    """Whether a connection from this process must claim its workspace instead of naming a path.

    True when the root's ``target.json`` names a remote kind, and also when the root resolves but
    its record cannot be read: that record may name a server on another machine, so a caller
    fails closed (it never sends a path there, and the connect seam then refuses on its own).
    False for the everyday installation, an isolated root that is not a target, a named local
    server, and a root that cannot be resolved at all, whose own path reports it exactly as
    before. Hook-safe: it reads only the target records.
    """

    try:
        record = active_target_record()
    except TargetRecordUnreadable:
        return True
    except TargetError:
        return False
    return record is not None and record.is_remote


def active_target_record() -> ServerTarget | None:
    """The target record of the root this process uses, or ``None`` for an ordinary local root.

    ``None`` covers the everyday server and an explicitly isolated root that is not a target.
    A path-safety refusal of the root is reported as ``target_root_unsafe``; a root that resolves
    but holds a record that cannot be read raises ``TargetRecordUnreadable``.
    """

    try:
        root = active_root()
    except PathSafetyError:
        raise TargetError("target_root_unsafe") from None
    if root is None:
        return None
    try:
        return read_target(root)
    except TargetError as error:
        raise TargetRecordUnreadable(error.reason, root.name) from None
