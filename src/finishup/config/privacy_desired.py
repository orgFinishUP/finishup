"""Privacy desired-state TOML encoding (ADR-014).

Desired-state files declare nonsecret policy intent. Apply maps onto existing
``propose`` / ``tighten`` / ``decide`` gates — file edits alone never widen egress.
"""

from __future__ import annotations

import ctypes
import errno
import functools
import os
import stat
import sys
import tomllib
from collections.abc import Callable
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
# Folders whose entries stand for a device or for a file a process already has open, such as
# `/dev/fd/1`, which macOS resolves `/dev/stdout` to, or a Linux `/proc/<pid>/fd` entry a path
# still names once resolved. Writing to such a name means writing into what it stands for: no
# file can be made beside it, and a file renamed over it would not be the one the process holds.
_DEVICES: Final = Path("/dev")
_DESCRIPTOR_FOLDERS: Final = frozenset({_DEVICES, _DEVICES / "fd"})
_PROCESSES: Final = Path("/proc")


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
    if _stands_for_an_open_file(destination):
        # macOS resolves `/dev/stdout` sent to a file to `/dev/fd/1`, which reports that file
        # but where nothing can be made. Linux resolves it to the file's own name, which is
        # renamed over as any other name is.
        return False
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


def _stands_for_an_open_file(destination: Path) -> bool:
    """Whether the resolved *destination* names a device or a file a process already has open.

    It does when it is an entry of `/dev`, `/dev/fd` or a process's `fd` folder under `/proc`.
    Only the resolved name is checked: on Linux `/dev/stdout` sent to a file resolves to that
    file's own name and is replaced like any other path.
    """

    folder = destination.parent
    return folder in _DESCRIPTOR_FOLDERS or (folder.name == "fd" and _PROCESSES in folder.parents)


def _made_like(descriptor: int, path: Path, existing: os.stat_result) -> bool:
    """Give the still-empty replacement the old file's owner, group and permissions.

    Returns False when it may not have them, or when what else the old file carries (its
    extended attributes and access-control list, and on macOS its file flags) would differ on
    the replacement or cannot be read here, so the old file is written in place and keeps what
    it has. They are compared, not copied: under a Linux access-control list the group
    permission bits stand for the list's mask, so a file made with the same bits can grant the
    owning group more than the old file did and drop the users the list named.
    """

    try:
        created = os.fstat(descriptor)
        if (created.st_uid, created.st_gid) != (existing.st_uid, existing.st_gid):
            os.fchown(descriptor, existing.st_uid, existing.st_gid)
        os.fchmod(descriptor, stat.S_IMODE(existing.st_mode))
        # Compared last: changing the permission bits rewrites an access-control list's mask.
        carried = _carried(path)
        return carried is not None and carried == _carried(descriptor)
    except OSError:
        return False


def _carried(file: Path | int) -> object | None:
    """What *file* carries besides its bytes, owner, group and permission bits, or None.

    Two files that answer alike carry the same. None means this platform cannot tell: Python
    reads extended attributes only on Linux, macOS is read through its C library, and nothing
    else is read at all.
    """

    if sys.platform == "linux":
        return _extended_attributes(file)
    if sys.platform == "darwin":
        security = _darwin_security()
        return None if security is None else security.read(file)
    return None


def _extended_attributes(file: Path | int) -> dict[str, bytes]:
    """Every extended attribute of *file* that this process can read, by name.

    On Linux these hold a file's access-control list (also the one its folder gave it when it
    was made), its security label and anything a program attached to it. Python reads them only
    on Linux; `_DarwinSecurity` reads macOS's.
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


# <sys/acl.h>: the one kind of access-control list macOS keeps.
_ACL_TYPE_EXTENDED: Final = 0x00000100
# What the reads below answer for a file that has no list, or a file system that keeps none.
_NONE_KEPT: Final = frozenset({errno.ENOENT, errno.ENOTSUP})
type _Buffer = ctypes.Array[ctypes.c_char]


def _file_flags(file: Path | int) -> int:
    """The flags `chflags` sets on *file*, such as `hidden`; there are none off macOS."""

    if sys.platform != "darwin":
        return 0
    return os.stat(file).st_flags


def _last_error() -> OSError:
    code = ctypes.get_errno()
    return OSError(code, os.strerror(code))


class _DarwinSecurity:
    """The C library calls that read a macOS file's extended attributes and access-control list.

    Python offers neither on macOS. Each call follows a symlink, as opening the path does, and
    the list is not among the attributes `listxattr` names there, so both are read.
    """

    def __init__(self) -> None:
        library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        text, size, pointer = ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p
        self._list_path = library.listxattr
        self._list_path.argtypes = [text, text, size, ctypes.c_int]
        self._list_path.restype = ctypes.c_ssize_t
        self._list_open = library.flistxattr
        self._list_open.argtypes = [ctypes.c_int, text, size, ctypes.c_int]
        self._list_open.restype = ctypes.c_ssize_t
        self._get_path = library.getxattr
        self._get_path.argtypes = [text, text, pointer, size, ctypes.c_uint32, ctypes.c_int]
        self._get_path.restype = ctypes.c_ssize_t
        self._get_open = library.fgetxattr
        self._get_open.argtypes = [ctypes.c_int, text, pointer, size, ctypes.c_uint32, ctypes.c_int]
        self._get_open.restype = ctypes.c_ssize_t
        self._list_of_path = library.acl_get_file
        self._list_of_path.argtypes = [text, ctypes.c_int]
        self._list_of_path.restype = pointer
        self._list_of_open = library.acl_get_fd_np
        self._list_of_open.argtypes = [ctypes.c_int, ctypes.c_int]
        self._list_of_open.restype = pointer
        self._list_text = library.acl_to_text
        self._list_text.argtypes = [pointer, pointer]
        self._list_text.restype = pointer
        self._free = library.acl_free
        self._free.argtypes = [pointer]
        self._free.restype = ctypes.c_int

    def read(self, file: Path | int) -> tuple[int, dict[bytes, bytes], bytes | None]:
        """*file*'s flags, its extended attributes by name, and its access-control list."""

        if isinstance(file, int):
            target: bytes | int = file
        else:
            target = os.fsencode(file)
        return _file_flags(file), self._attributes(target), self._access_list(target)

    def _attributes(self, file: bytes | int) -> dict[bytes, bytes]:
        def names(buffer: _Buffer | None, size: int) -> int:
            if isinstance(file, int):
                return self._list_open(file, buffer, size, 0)
            return self._list_path(file, buffer, size, 0)

        try:
            listed = _read_sized(names)
        except OSError as error:
            if error.errno == errno.ENOTSUP:  # this file system keeps none
                return {}
            raise
        return {name: self._attribute(file, name) for name in listed.split(b"\0") if name}

    def _attribute(self, file: bytes | int, name: bytes) -> bytes:
        def value(buffer: _Buffer | None, size: int) -> int:
            if isinstance(file, int):
                return self._get_open(file, name, buffer, size, 0, 0)
            return self._get_path(file, name, buffer, size, 0, 0)

        return _read_sized(value)

    def _access_list(self, file: bytes | int) -> bytes | None:
        if isinstance(file, int):
            found = self._list_of_open(file, _ACL_TYPE_EXTENDED)
        else:
            found = self._list_of_path(file, _ACL_TYPE_EXTENDED)
        if not found:
            error = _last_error()
            if error.errno in _NONE_KEPT:
                return None
            raise error
        try:
            text = self._list_text(found, None)
            if not text:
                raise _last_error()
            try:
                return ctypes.string_at(text)
            finally:
                self._free(text)
        finally:
            self._free(found)


def _read_sized(read: Callable[[_Buffer | None, int], int]) -> bytes:
    """Ask *read* for the size, then for the bytes, as the extended-attribute calls want.

    A size that grew in between fails with ERANGE, which leaves the file to be written in place.
    """

    size = read(None, 0)
    if size < 0:
        raise _last_error()
    if size == 0:
        return b""
    buffer = ctypes.create_string_buffer(size)
    filled = read(buffer, size)
    if filled < 0:
        raise _last_error()
    return buffer.raw[:filled]


@functools.cache
def _darwin_security() -> _DarwinSecurity | None:
    """The macOS reader, or None where the C library lacks one of its calls."""

    try:
        return _DarwinSecurity()
    except (OSError, AttributeError):
        return None


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
    pipe, a path that resolves to a name in `/dev`, `/dev/fd` or `/proc/<pid>/fd` (such as
    `/dev/stdout` on macOS, which resolves to `/dev/fd/1`), a file that has another hard link,
    a file whose owner a new file may not be given, a file whose access-control list, other
    extended attributes or (on macOS) file flags such as `hidden` a new file there would not
    have, and a file whose folder does not allow the rename. Linux and macOS are read for those;
    on any other platform, or where they cannot be read, an existing file is written in place so
    it keeps them. Only such a write can stop part-way.

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
