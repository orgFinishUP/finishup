"""The owner's per-repository choices for a server's copy of the code (level L2, ADR-054).

One owner-only record per remote target, ``<target root>/config/code-copy.json``
(``yoetz.server-code-copy/1``, canonical JSON), keyed by the repository key the round-5 hold uses
(``client.repository_hold.repository_key``). For each repository the owner may record:

* ``level``: ``"L1"`` keeps that repository at level L1 on a server the owner agreed to use at L2
  (the per-repository override, design v2 U3). Only a step **down** can be recorded: a repository
  never gets more than the server's consent allows. Removing the override is its reverse.
* ``exclude``: further patterns left out of that repository's copy (``client.code_secrets``
  matching), on top of the always-excluded list and the server's own.
* ``allow``: exact contents the owner allowed after the content scan held them out: each entry is
  a repository path and the ``sha256:`` of the bytes allowed, so any other content of that path
  is scanned again.

Reading never raises for a missing record (no choices) and raises ``CodeCopySettingsError`` with a
closed reason for one that is not owner-only, a link, too large, malformed or another target's;
the exporter then refuses to build anything (fail closed). Writers hold
``targets.registry_lock()``; paths and patterns appear only on owner displays.
"""

from __future__ import annotations

import os
import re
import secrets
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Literal, cast

from finishup.client.code_secrets import valid_pattern
from finishup.config.paths import PathSafetyError, ensure_owner_only_dir
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse

__all__ = [
    "SETTINGS_FILE_NAME",
    "SETTINGS_SCHEMA",
    "CodeCopySettingsError",
    "RepositoryCodeSettings",
    "read_settings",
    "settings_for",
    "settings_path",
    "update_settings",
]

SETTINGS_SCHEMA: Final = "yoetz.server-code-copy/1"
SETTINGS_FILE_NAME: Final = "code-copy.json"
_MAX_RECORD_BYTES: Final = 1_048_576
_MAX_REPOSITORIES: Final = 256
_MAX_ENTRIES: Final = 256
_KEY: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_TARGET_ID: Final = re.compile(r"^t_[0-9a-f]{8,64}$")
_DIGEST: Final = re.compile(r"^sha256:[0-9a-f]{64}$")


class CodeCopySettingsError(Exception):
    """The record cannot be used; ``reason`` is ``code_copy_settings_unsafe`` or ``_invalid``."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class RepositoryCodeSettings:
    """One repository's choices (empty by default)."""

    level: Literal["L1"] | None = None
    exclude: tuple[str, ...] = ()
    allow: tuple[tuple[str, str], ...] = field(default=())

    def __post_init__(self) -> None:
        if self.level not in {None, "L1"}:
            raise CodeCopySettingsError("code_copy_settings_invalid")
        if (
            type(self.exclude) is not tuple
            or len(self.exclude) > _MAX_ENTRIES
            or list(self.exclude) != sorted(set(self.exclude))
            or not all(valid_pattern(pattern) for pattern in self.exclude)
        ):
            raise CodeCopySettingsError("code_copy_settings_invalid")
        if (
            type(self.allow) is not tuple
            or len(self.allow) > _MAX_ENTRIES
            or list(self.allow) != sorted(set(self.allow))
            or not all(
                type(path) is str
                and 0 < len(path) <= 4_096
                and "\x00" not in path
                and type(digest) is str
                and bool(_DIGEST.match(digest))
                for path, digest in self.allow
            )
        ):
            raise CodeCopySettingsError("code_copy_settings_invalid")

    @property
    def empty(self) -> bool:
        return self.level is None and not self.exclude and not self.allow

    def allows(self, path: str, digest: str) -> bool:
        """Whether the owner allowed exactly this content at ``path``."""

        return (path, digest) in self.allow


def settings_path(root: Path) -> Path:
    """``<target root>/config/code-copy.json``."""

    return root / "config" / SETTINGS_FILE_NAME


def _encode(target_id: str, settings: Mapping[str, RepositoryCodeSettings]) -> bytes:
    repositories: list[JsonValue] = []
    for key in sorted(settings):
        entry = settings[key]
        if entry.empty:
            continue
        repositories.append(
            {
                "repository": key,
                "level": entry.level,
                "exclude": list(entry.exclude),
                "allow": [[path, digest] for path, digest in entry.allow],
            }
        )
    return (
        canonical_encode(
            {"schema": SETTINGS_SCHEMA, "target_id": target_id, "repositories": repositories}
        )
        + b"\n"
    )


def _read_owner_only(path: Path) -> bytes | None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError:
        raise CodeCopySettingsError("code_copy_settings_unsafe") from None
    try:
        facts = os.fstat(descriptor)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != os.geteuid()
            or stat.S_IMODE(facts.st_mode) & 0o077
            or facts.st_size > _MAX_RECORD_BYTES
        ):
            raise CodeCopySettingsError("code_copy_settings_unsafe")
        data = os.read(descriptor, _MAX_RECORD_BYTES + 1)
    except OSError:
        raise CodeCopySettingsError("code_copy_settings_unsafe") from None
    finally:
        os.close(descriptor)
    if len(data) > _MAX_RECORD_BYTES:
        raise CodeCopySettingsError("code_copy_settings_unsafe")
    return data


def _decode_entry(item: JsonValue) -> tuple[str, RepositoryCodeSettings]:
    if type(item) is not dict:
        raise CodeCopySettingsError("code_copy_settings_invalid")
    source = cast(dict[str, JsonValue], item)
    if set(source) != {"repository", "level", "exclude", "allow"}:
        raise CodeCopySettingsError("code_copy_settings_invalid")
    key = source["repository"]
    exclude = source["exclude"]
    allow = source["allow"]
    if type(key) is not str or not _KEY.match(key):
        raise CodeCopySettingsError("code_copy_settings_invalid")
    if type(exclude) is not list or type(allow) is not list:
        raise CodeCopySettingsError("code_copy_settings_invalid")
    pairs: list[tuple[str, str]] = []
    for pair in cast(list[JsonValue], allow):
        if type(pair) is not list or len(cast(list[JsonValue], pair)) != 2:
            raise CodeCopySettingsError("code_copy_settings_invalid")
        path, digest = cast(list[JsonValue], pair)
        pairs.append((cast(str, path), cast(str, digest)))
    try:
        entry = RepositoryCodeSettings(
            level=cast(Literal["L1"] | None, source["level"]),
            exclude=tuple(cast(list[str], exclude)),
            allow=tuple(pairs),
        )
    except TypeError:
        raise CodeCopySettingsError("code_copy_settings_invalid") from None
    return key, entry


def read_settings(root: Path, target_id: str) -> dict[str, RepositoryCodeSettings]:
    """Every repository's choices on the target at ``root`` (``{}`` when there is no record)."""

    encoded = _read_owner_only(settings_path(root))
    if encoded is None:
        return {}
    try:
        value = strict_json_parse(encoded[:-1] if encoded.endswith(b"\n") else b"")
    except ValueError:
        raise CodeCopySettingsError("code_copy_settings_invalid") from None
    if type(value) is not dict:
        raise CodeCopySettingsError("code_copy_settings_invalid")
    source = cast(dict[str, JsonValue], value)
    if (
        set(source) != {"schema", "target_id", "repositories"}
        or source["schema"] != SETTINGS_SCHEMA
        or source["target_id"] != target_id
        or type(source["repositories"]) is not list
        or len(cast(list[JsonValue], source["repositories"])) > _MAX_REPOSITORIES
    ):
        raise CodeCopySettingsError("code_copy_settings_invalid")
    settings: dict[str, RepositoryCodeSettings] = {}
    for item in cast(list[JsonValue], source["repositories"]):
        key, entry = _decode_entry(item)
        if key in settings or entry.empty:
            raise CodeCopySettingsError("code_copy_settings_invalid")
        settings[key] = entry
    if _encode(target_id, settings) != encoded:
        raise CodeCopySettingsError("code_copy_settings_invalid")
    return settings


def settings_for(root: Path, target_id: str, key: str) -> RepositoryCodeSettings:
    """One repository's choices (empty when none were recorded); raises like ``read_settings``."""

    return read_settings(root, target_id).get(key, RepositoryCodeSettings())


def update_settings(
    root: Path,
    target_id: str,
    key: str,
    change: Callable[[RepositoryCodeSettings], RepositoryCodeSettings],
) -> RepositoryCodeSettings:
    """Apply ``change`` to one repository's choices and write the record atomically.

    The caller holds ``targets.registry_lock()``. A record that cannot be read is never
    overwritten (``CodeCopySettingsError``): the owner removes it first.
    """

    if not _TARGET_ID.match(target_id) or not _KEY.match(key):
        raise CodeCopySettingsError("code_copy_settings_invalid")
    settings = read_settings(root, target_id)
    updated = change(settings.get(key, RepositoryCodeSettings()))
    settings[key] = updated
    if len([entry for entry in settings.values() if not entry.empty]) > _MAX_REPOSITORIES:
        raise CodeCopySettingsError("code_copy_settings_invalid")
    path = settings_path(root)
    try:
        ensure_owner_only_dir(path.parent)
    except PathSafetyError:
        raise CodeCopySettingsError("code_copy_settings_unsafe") from None
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    encoded = _encode(target_id, settings)
    try:
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
    except OSError:
        temporary.unlink(missing_ok=True)
        raise CodeCopySettingsError("code_copy_settings_unsafe") from None
    return updated
