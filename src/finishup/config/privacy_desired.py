"""Privacy desired-state TOML encoding (ADR-014).

Desired-state files declare nonsecret policy intent. Apply maps onto existing
``propose`` / ``tighten`` / ``decide`` gates — file edits alone never widen egress.
"""

from __future__ import annotations

import errno
import os
import stat
import sys
import tomllib
from dataclasses import fields, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Final, cast

from finishup.config.models import ConfigError
from finishup.config.toml_text import load_toml_text
from finishup.domain.privacy import PrivacyPolicy, policy_field_omitted
from finishup.domain.values import format_rfc3339_millis
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse

__all__ = [
    "PRIVACY_DESIRED_OUTPUT_INCOMPLETE",
    "PRIVACY_DESIRED_OUTPUT_INCOMPLETE_REMEDY",
    "PRIVACY_DESIRED_OUTPUT_UNWRITABLE",
    "PRIVACY_DESIRED_OUTPUT_UNWRITABLE_REMEDY",
    "PRIVACY_DESIRED_SCHEMA",
    "PrivacyDesiredOutputUnwritable",
    "load_privacy_desired_canonical",
    "render_privacy_desired_toml",
    "write_privacy_desired_toml",
]

# Frozen legacy identifier (ADR-048): the schema tag stored in existing desired-privacy files.
PRIVACY_DESIRED_SCHEMA: Final = "yoetz.privacy-desired/1"

# How an export can fail after the policy was read. Almost always the chosen path cannot be
# written and nothing changed there.
PRIVACY_DESIRED_OUTPUT_UNWRITABLE: Final = "privacy_desired_output_unwritable"
PRIVACY_DESIRED_OUTPUT_UNWRITABLE_REMEDY: Final = (
    "Nothing was saved. Choose a writable file path in an existing directory and export again."
)
# Only a destination that had to be written in place can be left part-written; saying
# "nothing was saved" about it would be false.
PRIVACY_DESIRED_OUTPUT_INCOMPLETE: Final = "privacy_desired_output_incomplete"
PRIVACY_DESIRED_OUTPUT_INCOMPLETE_REMEDY: Final = (
    "The write stopped part-way, so the file may be incomplete. "
    "Export again, or choose another writable file path."
)

# Errors that mean a finished file cannot be renamed into place here, although the destination
# itself may still be writable: its folder takes no new entry or lets none be replaced, the
# destination is its own mount, or its name leaves no room for the temporary file's longer one.
# None of them says the storage is failing, so writing in place is still safe to try.
_RENAME_UNAVAILABLE: Final = frozenset(
    {errno.EACCES, errno.EPERM, errno.EROFS, errno.EBUSY, errno.EXDEV, errno.ENAMETOOLONG}
)
# What `fsync` answers on a file system that cannot be told to flush. The flush did not fail;
# there is none to ask for.
_FLUSH_UNAVAILABLE: Final = frozenset({errno.EINVAL, errno.ENOSYS, errno.ENOTSUP})


class PrivacyDesiredOutputUnwritable(Exception):
    """The export could not be written; ``reason_code`` and ``remedy`` say what is at the path.

    ``incomplete`` is for an in-place write that stopped after it began. Every other failure
    changed nothing. Carries only fixed text, never the caller's path or the operating-system
    message.
    """

    def __init__(self, *, incomplete: bool = False) -> None:
        self.reason_code: Final = (
            PRIVACY_DESIRED_OUTPUT_INCOMPLETE if incomplete else PRIVACY_DESIRED_OUTPUT_UNWRITABLE
        )
        self.remedy: Final = (
            PRIVACY_DESIRED_OUTPUT_INCOMPLETE_REMEDY
            if incomplete
            else PRIVACY_DESIRED_OUTPUT_UNWRITABLE_REMEDY
        )
        super().__init__(self.reason_code)


def _to_json(value: object) -> object:
    if value is None or type(value) in {bool, int, str}:
        return value
    if type(value) is bytes:
        return value.hex()
    if isinstance(value, Enum):
        return value.value
    if type(value) is datetime:
        return format_rfc3339_millis(value)
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _to_json(getattr(value, field.name))
            for field in fields(value)
            # Defaults that predate their fields are never written (issues #982, ADR-049), so
            # every policy, case and receipt from before them keeps its exact canonical bytes.
            if not policy_field_omitted(field.name, getattr(value, field.name))
        }
    if type(value) is tuple:
        return [_to_json(member) for member in cast(tuple[object, ...], value)]
    raise TypeError("privacy_desired_value_invalid")


# TOML basic strings may not carry a raw control character (U+0000-U+001F, U+007F), but the
# loader accepts one spelled as an escape; spell every one back as an escape so a loaded value
# always renders to a loadable file.
_TOML_BASIC_ESCAPES: Final = str.maketrans(
    {
        **{code: f"\\u{code:04X}" for code in (*range(0x20), 0x7F)},
        ord("\\"): "\\\\",
        ord('"'): '\\"',
        ord("\n"): "\\n",
        ord("\r"): "\\r",
        ord("\t"): "\\t",
    }
)


def _escape_basic(value: str) -> str:
    return value.translate(_TOML_BASIC_ESCAPES)


def render_privacy_desired_toml(policy: PrivacyPolicy) -> str:
    """Render durable nonsecret policy desired-state as a documented TOML document."""

    if type(policy) is not PrivacyPolicy:
        raise TypeError("privacy_desired_policy_invalid")
    payload = cast(dict[str, object], _to_json(policy))
    encoded = canonical_encode(cast(JsonValue, payload)).decode("utf-8")
    lines = [
        f'schema = "{PRIVACY_DESIRED_SCHEMA}"',
        "",
        "[privacy.desired]",
        f'policy_json = "{_escape_basic(encoded)}"',
        "",
        "# Ceremony note: editing this file never silently widens egress.",
        "# Run `finishup privacy apply-desired` — tighten may apply; widen requires decide.",
        "",
    ]
    return "\n".join(lines)


def _replace_whole(path: Path, data: bytes) -> bool:
    """Put *data* where *path* points by renaming a finished file into place.

    Returns False, having changed nothing, when a rename would not leave what a plain write
    leaves; the caller then writes in place. An error while the bytes are written, flushed or
    renamed for any other reason is raised: the storage is failing and the old file is whole.
    """

    try:
        existing = path.stat()  # follows symlinks, as opening the path does
    except FileNotFoundError:
        existing = None
    if existing is not None and (
        not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1 or not os.access(path, os.W_OK)
    ):
        # Only opening the path leaves the right result for these: a device or pipe is written
        # itself, a file with other hard links stays shared with them, and a file that may not
        # be written is refused instead of replaced.
        return False
    # Rename over the file a symlink names, never over the link.
    destination = Path(os.path.realpath(path))
    try:
        resolved = destination.lstat()
    except FileNotFoundError:
        resolved = None
    if existing is None:
        names_it = resolved is None
    else:
        names_it = resolved is not None and os.path.samestat(existing, resolved)
    if not names_it:
        # The resolved name is not the file the path opens (a link into /proc to a file that
        # has no name any more); only opening the path reaches it.
        return False
    temporary = destination.with_name(f".{destination.name}.{os.urandom(8).hex()}.tmp")
    try:
        # Mode 0666 less the umask is what a plain write gives a new file.
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
    except OSError as error:
        if error.errno in _RENAME_UNAVAILABLE:
            return False
        raise
    replaced = False
    try:
        with os.fdopen(descriptor, "wb") as handle:
            if existing is not None and not _made_like(handle.fileno(), path, existing):
                return False
            handle.write(data)
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError as error:
                # Without a flush the rename still leaves the old file or the whole new one
                # unless the machine stops, and the plain write never flushed either.
                if error.errno not in _FLUSH_UNAVAILABLE:
                    raise
        try:
            os.replace(temporary, destination)
        except OSError as error:
            if error.errno in _RENAME_UNAVAILABLE:
                return False
            raise
        replaced = True
    finally:
        # Never leave a stray temporary beside the target, even on an interrupt.
        if not replaced:
            temporary.unlink(missing_ok=True)
    return True


def _made_like(descriptor: int, path: Path, existing: os.stat_result) -> bool:
    """Give the still-empty replacement the old file's owner, group and permissions.

    Returns False when it may not have them, or when its extended attributes would still differ
    from the old file's, so the old file is written in place and keeps what it has. The
    attributes are compared, not copied: an access-control list is one of them, and under one
    the group permission bits stand for the list's mask, so a file made with the same bits can
    grant the owning group more than the old file did and drop the users the list named.
    """

    try:
        created = os.fstat(descriptor)
        if (created.st_uid, created.st_gid) != (existing.st_uid, existing.st_gid):
            os.fchown(descriptor, existing.st_uid, existing.st_gid)
        os.fchmod(descriptor, stat.S_IMODE(existing.st_mode))
        # Compared last: changing the permission bits rewrites an access-control list's mask.
        return _extended_attributes(path) == _extended_attributes(descriptor)
    except OSError:
        return False


def _extended_attributes(file: Path | int) -> dict[str, bytes]:
    """Every extended attribute of *file* that this process can read, by name.

    On Linux these hold a file's access-control list (also the one its folder gave it when it
    was made), its security label and anything a program attached to it. Python reads them only
    on Linux, so elsewhere a file looks as if it had none.
    """

    if sys.platform != "linux":
        return {}
    try:
        names = os.listxattr(file)
    except OSError as error:
        if error.errno == errno.ENOTSUP:  # this file system keeps none
            return {}
        raise
    return {name: os.getxattr(file, name) for name in names}


def _write_in_place(path: Path, data: bytes) -> None:
    """Write *data* into whatever *path* opens, as a plain write does."""

    try:
        handle = path.open("wb")
    except OSError as error:
        raise PrivacyDesiredOutputUnwritable from error
    try:
        with handle:
            handle.write(data)
    except OSError as error:
        # Opening a regular file already emptied it, and a pipe may have taken some bytes.
        raise PrivacyDesiredOutputUnwritable(incomplete=True) from error


def write_privacy_desired_toml(policy: PrivacyPolicy, path: Path) -> Path:
    """Write the desired-state TOML to the file *path* names and return *path*.

    A regular file, or a path with no file yet, is written whole or not at all: the bytes go to
    a temporary file beside it, are flushed, and are renamed into place, so a failed export
    leaves the old file as it was. What is left is otherwise what a plain write leaves: a
    symlink is followed and stays a link, an existing file keeps its owner, group and
    permissions, and a new file gets the process's default mode.

    Where a rename cannot leave that, the bytes are written in place instead: into a device or
    pipe, a file that has another hard link, a file whose owner a new file may not be given, a
    file whose access-control list or other extended attributes a new file there would not have
    (Linux only; they cannot be read elsewhere, so there a replaced file loses them), and a
    file whose folder does not allow the rename. Only such a write can stop part-way.

    A path that cannot be written (an existing directory, a parent that is a file, a file that
    may not be written, a forbidden or read-only parent with no writable file at the path)
    raises ``PrivacyDesiredOutputUnwritable``; the path and the operating-system message are
    never carried in the error.
    """

    data = render_privacy_desired_toml(policy).encode("utf-8")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        replaced = _replace_whole(path, data)
    except OSError as error:
        raise PrivacyDesiredOutputUnwritable from error
    if not replaced:
        _write_in_place(path, data)
    return path


def load_privacy_desired_canonical(path: Path) -> bytes:
    """Load desired-state TOML and return the embedded canonical policy JSON bytes."""

    try:
        raw = load_toml_text(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError("config_value_invalid") from exc
    if raw.get("schema") != PRIVACY_DESIRED_SCHEMA:
        raise ConfigError("config_schema_unsupported")
    section = raw.get("privacy")
    if type(section) is not dict:
        raise ConfigError("config_value_invalid")
    privacy = cast(dict[str, object], section)
    desired_raw = privacy.get("desired")
    if type(desired_raw) is not dict:
        raise ConfigError("config_value_invalid")
    desired = cast(dict[str, object], desired_raw)
    policy_json = desired.get("policy_json")
    if type(policy_json) is not str:
        raise ConfigError("config_value_invalid")
    try:
        parsed = strict_json_parse(policy_json.encode("utf-8"))
    except Exception as exc:
        raise ConfigError("config_value_invalid") from exc
    return canonical_encode(parsed)
