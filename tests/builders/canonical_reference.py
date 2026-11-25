"""The canonical walker as it stood before the plain-value fast path, frozen for tests.

It checks every node as it emits it and builds the text by string joins in Python. Tests use it
as the behavioral reference for ``finishup.protocol.canonical`` and as a pure-Python unit of
work whose cost does not move when the production encoder gets faster.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

import finishup.protocol.canonical as canonical
from finishup.protocol.errors import ProtocolValueError

_MAX_SAFE = 2**53 - 1


def reference_canonical_text(value: object, depth: int = 0) -> str:
    """Render *value* exactly as the pre-fast-path walker did, raising its errors in its order."""

    if type(value) is canonical.CanonicalFragment:
        if value.levels >= 0 and depth + value.levels >= canonical.MAX_JSON_DEPTH:
            raise ProtocolValueError("nesting_too_deep")
        return value.text
    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        if not -_MAX_SAFE <= value <= _MAX_SAFE:
            raise ProtocolValueError("integer_out_of_safe_range")
        return str(value)
    if canonical._is_actual_float(value):  # pyright: ignore[reportPrivateUsage]
        raise ProtocolValueError("float_forbidden")
    if type(value) is str:
        return canonical._encode_string(value)  # pyright: ignore[reportPrivateUsage]
    if type(value) in {list, tuple}:
        if depth >= canonical.MAX_JSON_DEPTH:
            raise ProtocolValueError("nesting_too_deep")
        sequence = cast("list[object]", value)
        return "[" + ",".join(reference_canonical_text(item, depth + 1) for item in sequence) + "]"
    if canonical._is_actual_mapping(value):  # pyright: ignore[reportPrivateUsage]
        if depth >= canonical.MAX_JSON_DEPTH:
            raise ProtocolValueError("nesting_too_deep")
        source = cast("Mapping[object, object]", value)
        items: list[tuple[bytes, str, object]] = []
        for key, item in source.items():
            if type(key) is not str:
                raise ProtocolValueError("object_key_not_string")
            canonical._validate_string(key)  # pyright: ignore[reportPrivateUsage]
            items.append((key.encode("utf-16-be"), key, item))
        items.sort(key=lambda entry: entry[0])
        return (
            "{"
            + ",".join(
                f"{canonical._encode_string(key)}:{reference_canonical_text(item, depth + 1)}"  # pyright: ignore[reportPrivateUsage]
                for _, key, item in items
            )
            + "}"
        )
    raise ProtocolValueError("unsupported_json_type")
