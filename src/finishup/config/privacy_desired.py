"""Privacy desired-state TOML encoding (ADR-014).

Desired-state files declare nonsecret policy intent. Apply maps onto existing
``propose`` / ``tighten`` / ``decide`` gates — file edits alone never widen egress.
"""

from __future__ import annotations

import os
import tempfile
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

# The one way an export can fail after the policy was read: the chosen path cannot be written.
PRIVACY_DESIRED_OUTPUT_UNWRITABLE: Final = "privacy_desired_output_unwritable"
PRIVACY_DESIRED_OUTPUT_UNWRITABLE_REMEDY: Final = (
    "Nothing was saved. Choose a writable file path in an existing directory and export again."
)


class PrivacyDesiredOutputUnwritable(Exception):
    """The export destination could not be written; nothing was saved.

    Carries only its fixed reason code, never the caller's path or the operating-system message.
    """

    reason_code: Final = PRIVACY_DESIRED_OUTPUT_UNWRITABLE

    def __init__(self) -> None:
        super().__init__(PRIVACY_DESIRED_OUTPUT_UNWRITABLE)


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


def write_privacy_desired_toml(policy: PrivacyPolicy, path: Path) -> Path:
    """Write the desired-state TOML to *path* whole, or raise without leaving anything behind.

    The file is written to a temporary file in the same directory, flushed, and renamed into
    place, so a failed export never leaves a truncated file. A path that cannot be written (an
    existing directory, a forbidden or read-only parent, a parent that is a file) raises
    ``PrivacyDesiredOutputUnwritable``; the path and the operating-system
    message are never carried in the error.
    """

    data = render_privacy_desired_toml(policy).encode("utf-8")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
    except OSError as error:
        raise PrivacyDesiredOutputUnwritable from error
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException as error:
        # Never leave a stray temporary beside the target, even on an interrupt.
        temporary.unlink(missing_ok=True)
        if isinstance(error, OSError):
            raise PrivacyDesiredOutputUnwritable from error
        raise
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
