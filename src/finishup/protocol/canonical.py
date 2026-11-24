"""Restricted-JCS canonicalization and digest helpers for FinishUP protocol values."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from itertools import compress, count, islice, repeat
from operator import is_
from typing import Final, NoReturn, cast

from finishup.protocol.errors import ProtocolValueError

__all__ = [
    "CanonicalFragment",
    "JsonValue",
    "MAX_JSON_DEPTH",
    "canonical_digest",
    "canonical_encode",
    "canonical_fragment",
    "container_levels",
    "canonical_integer_string",
    "ensure_canonical_set",
    "ensure_canonical_value",
    "entry_digest",
    "parse_canonical_integer_string",
    "request_digest",
    "strict_json_parse",
]

type JsonValue = (
    None | bool | int | str | list[JsonValue] | tuple[JsonValue, ...] | Mapping[str, JsonValue]
)

MAX_JSON_DEPTH: Final = 64

_MAX_SAFE_INTEGER: Final = 2**53 - 1
# JSON integer literals carry no leading zero, so a literal with more digits than the largest
# safe integer is out of range before conversion; checking the length first keeps ``int()`` off
# literals past the interpreter's integer-string conversion limit (and its quadratic cost).
_MAX_SAFE_INTEGER_DIGITS: Final = len(str(_MAX_SAFE_INTEGER))
_MAX_SQLITE_SIGNED_INTEGER: Final = 2**63 - 1
_MIN_SQLITE_SIGNED_INTEGER: Final = -(2**63)
_REQUEST_DIGEST_FENCE_KEYS: Final = frozenset(
    {
        "ingestion_sequence",
        "accepted_at",
        "previous_entry_digest",
        "object_id",
        "ledger",
    }
)
_ACCEPTED_ENTRY_PREIMAGE_KEYS: Final = frozenset(
    {
        "artifact_refs",
        "author",
        "causal_parents",
        "coverage",
        "event_id",
        "evidence_refs",
        "ledger",
        "occurred_at",
        "operation_id",
        "payload_ref",
        "protocol",
        "protocol_version",
        "publication_channel",
        "redaction",
        "schema",
        "session_id",
        "task_id",
        "writer",
    }
)


class CanonicalFragment:
    """The canonical text of one already-validated value, for splicing into a larger value.

    Canonical encoding is compositional: a value's text inside any enclosing document is exactly
    its own canonical text. A caller that re-encodes a large document whose members rarely change
    (the local observation state, issue #689) can therefore encode each immutable member once and
    splice it. Only :func:`canonical_fragment` builds one, from a value this module validated, so
    a fragment can never carry text the profile would reject; parsing never produces one.

    ``levels`` is the deepest relative nesting level that holds a container (``-1`` for a
    scalar), so splicing enforces exactly the nesting bound inline encoding would.
    """

    __slots__ = ("byte_length", "levels", "text")

    def __init__(self, text: str, levels: int, *, _token: object = None) -> None:
        if _token is not _FRAGMENT_TOKEN:
            raise TypeError("canonical_fragment_private")
        self.text = text
        self.levels = levels
        self.byte_length = len(text.encode("utf-8"))

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("canonical_fragment_immutable")
        object.__setattr__(self, name, value)


_FRAGMENT_TOKEN: Final = object()


def canonical_fragment(value: JsonValue | CanonicalFragment) -> CanonicalFragment:
    """Validate and encode *value* once, returning a splice-ready fragment."""

    if type(value) is CanonicalFragment:
        return value
    return CanonicalFragment(
        _canonical_text(value),
        container_levels(value),
        _token=_FRAGMENT_TOKEN,
    )


def container_levels(value: object) -> int:
    """Return the deepest relative level holding a container, or ``-1`` for a scalar.

    A value whose root sits at depth ``d`` satisfies the nesting bound exactly when
    ``d + container_levels(value) < MAX_JSON_DEPTH``.
    """

    if type(value) is CanonicalFragment:
        return value.levels
    if type(value) in {list, tuple}:
        items = cast(Sequence[object], value)
        return 1 + max((container_levels(item) for item in items), default=-1)
    if _is_actual_mapping(value):
        source = cast(Mapping[str, object], value)
        return 1 + max((container_levels(item) for item in source.values()), default=-1)
    return -1


def canonical_encode(value: JsonValue) -> bytes:
    """Encode a restricted canonical JSON value to UTF-8 bytes."""

    return _canonical_text(value).encode("utf-8")


def canonical_digest(value: JsonValue) -> str:
    """Return the SHA-256 digest of the canonical bytes for *value*."""

    return f"sha256:{hashlib.sha256(canonical_encode(value)).hexdigest()}"


def strict_json_parse(data: bytes | bytearray, *, validate: bool = True) -> JsonValue:
    """Parse strict wire JSON into the FinishUP JSON profile.

    ``validate=False`` keeps every lexical check (UTF-8, no NUL byte or BOM, no duplicate key,
    no float or non-finite constant, safe integers) and skips only the final profile walk; the
    caller then owns :func:`ensure_canonical_value` for every subtree it accepts.
    """

    if type(data) is bytearray:
        raw = bytes(data)
    elif type(data) is bytes:
        raw = data
    else:
        raise ProtocolValueError("input_not_bytes")

    if b"\x00" in raw:
        raise ProtocolValueError("nul_byte_forbidden")

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProtocolValueError("invalid_utf8") from exc

    if text.startswith("\ufeff"):
        raise ProtocolValueError("byte_order_mark_forbidden")

    def _reject_float(_: str) -> NoReturn:
        raise ProtocolValueError("float_forbidden")

    def _reject_constant(_: str) -> NoReturn:
        raise ProtocolValueError("float_forbidden")

    def _parse_int(literal: str) -> int:
        if literal == "-0":
            raise ProtocolValueError("float_forbidden")
        if len(literal) - literal.startswith("-") > _MAX_SAFE_INTEGER_DIGITS:
            raise ProtocolValueError("integer_out_of_safe_range")
        value = int(literal)
        if not -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER:
            raise ProtocolValueError("integer_out_of_safe_range")
        return value

    def _decode_object_pairs(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        # dict() collapses duplicate keys, so a length mismatch is exactly the
        # duplicate case; the C constructor keeps this hook off the profile of
        # every large-state parse (#290).
        result: dict[str, object] = dict(pairs)
        if len(result) != len(pairs):
            raise ProtocolValueError("duplicate_object_key")
        return result

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_decode_object_pairs,
            parse_float=_reject_float,
            parse_int=_parse_int,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise ProtocolValueError("malformed_json") from exc
    except RecursionError as exc:
        raise ProtocolValueError("nesting_too_deep") from exc

    if validate:
        ensure_canonical_value(cast(JsonValue, parsed))
    return cast(JsonValue, parsed)


def ensure_canonical_value(value: JsonValue, *, depth: int = 0) -> None:
    """Validate a parsed value against the canonical JSON profile.

    ``depth`` is the value's nesting depth inside an enclosing document, so validating a
    document's members one by one enforces exactly the bound validating it whole would.
    """

    failure = _plain_failure(value, depth)
    if failure is None:
        return
    _canonical_text(value, depth=depth, failure=failure)


def ensure_canonical_set(values: list[str] | tuple[str, ...]) -> None:
    """Validate a set-valued field without normalizing its order."""

    if not isinstance(cast(object, values), list | tuple):
        raise ProtocolValueError("unsupported_json_type")

    previous: bytes | None = None
    for member in values:
        if type(member) is not str:
            raise ProtocolValueError("set_member_not_ascii")
        try:
            encoded = member.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ProtocolValueError("set_member_not_ascii") from exc
        if previous is not None:
            if encoded == previous:
                raise ProtocolValueError("duplicate_set_member")
            if encoded < previous:
                raise ProtocolValueError("unsorted_set_field")
        previous = encoded


def canonical_integer_string(value: int) -> str:
    """Render a nonnegative integer in canonical decimal form."""

    if type(value) is not int or not 0 <= value <= _MAX_SQLITE_SIGNED_INTEGER:
        raise ProtocolValueError("integer_out_of_sqlite_range")
    return str(value)


def parse_canonical_integer_string(value: str, *, signed: bool = False) -> int:
    """Parse a canonical decimal integer string."""

    if type(value) is not str:
        raise ProtocolValueError("noncanonical_integer_string")

    if not value or len(value) > (20 if signed else 19):
        raise ProtocolValueError("noncanonical_integer_string")

    if signed:
        if value == "-0" or not _matches_integer_pattern(value, signed=True):
            raise ProtocolValueError("noncanonical_integer_string")
    elif not _matches_integer_pattern(value, signed=False):
        raise ProtocolValueError("noncanonical_integer_string")

    parsed = int(value)
    if signed:
        if not _MIN_SQLITE_SIGNED_INTEGER <= parsed <= _MAX_SQLITE_SIGNED_INTEGER:
            raise ProtocolValueError("noncanonical_integer_string")
    elif not 0 <= parsed <= _MAX_SQLITE_SIGNED_INTEGER:
        raise ProtocolValueError("noncanonical_integer_string")
    return parsed


def request_digest(identity: JsonValue) -> str:
    """Digest a logical publication request identity tree."""

    _reject_ledger_assigned_fields(identity)
    ensure_canonical_value(identity)
    return canonical_digest(identity)


def entry_digest(preimage: JsonValue) -> str:
    """Digest an accepted-entry preimage after its exact top-level envelope gate."""

    if not _is_actual_mapping(preimage):
        raise ProtocolValueError("not_an_accepted_envelope")
    source = cast(Mapping[str, JsonValue], preimage)
    try:
        if frozenset(source) != _ACCEPTED_ENTRY_PREIMAGE_KEYS:
            raise ProtocolValueError("not_an_accepted_envelope")
        protocol = source["protocol"]
    except ProtocolValueError:
        raise
    except Exception as exc:
        raise ProtocolValueError("not_an_accepted_envelope") from exc

    # Frozen legacy identifier (ADR-048): the recorded event envelope protocol tag.
    if type(protocol) is not str or protocol != "yoetz.event":
        raise ProtocolValueError("not_an_accepted_envelope")

    ensure_canonical_value(source)
    return canonical_digest(source)


def _matches_integer_pattern(value: str, *, signed: bool) -> bool:
    if signed:
        if value == "0":
            return True
        if value.startswith("-"):
            digits = value[1:]
        else:
            digits = value
        return bool(digits) and digits[0] != "0" and _is_ascii_digits(digits)
    return value == "0" or (value[0] != "0" and _is_ascii_digits(value))


def _is_ascii_digits(value: str) -> bool:
    return all("0" <= character <= "9" for character in value)


def _reject_ledger_assigned_fields(value: JsonValue) -> None:
    def _walk(node: JsonValue, depth: int) -> None:
        if _is_actual_mapping(node):
            if depth >= MAX_JSON_DEPTH:
                raise ProtocolValueError("nesting_too_deep")
            source = cast(Mapping[str, JsonValue], node)
            for key, item in source.items():
                if type(key) is str and key in _REQUEST_DIGEST_FENCE_KEYS:
                    raise ProtocolValueError("ledger_assigned_field_in_request_identity")
                _walk(item, depth + 1)
            return
        if type(node) is list:
            if depth >= MAX_JSON_DEPTH:
                raise ProtocolValueError("nesting_too_deep")
            for item in node:
                _walk(cast(JsonValue, item), depth + 1)
        elif type(node) is tuple:
            if depth >= MAX_JSON_DEPTH:
                raise ProtocolValueError("nesting_too_deep")
            for item in node:
                _walk(cast(JsonValue, item), depth + 1)

    _walk(value, 0)


def _canonical_text(
    value: JsonValue | CanonicalFragment,
    *,
    depth: int = 0,
    failure: _PlainFailure | None = None,
) -> str:
    """Render *value* canonically.

    ``failure`` is what ``_plain_failure`` already reported for *value* (None: not checked yet).
    It lets the walker skip re-checking a subtree a failed check has already scanned.
    """

    kind = type(value)
    if failure is None and (kind is dict or kind is list or kind is tuple):
        failure = _plain_failure(value, depth)
        if failure is None:
            return _PLAIN_JSON_TEXT(value)
    out: list[str] = []
    _write(value, depth, failure, out)
    return "".join(out)


def _write(
    value: object,
    depth: int,
    failure: _PlainFailure | None,
    out: list[str],
) -> None:
    """Append *value*'s canonical text to *out*; ``failure`` as for ``_canonical_text``.

    Pieces go to one list joined once at the top, so a deep value's text is copied once rather
    than once per enclosing level.
    """

    kind = type(value)
    if kind is dict or kind is list or kind is tuple:
        # The exact containers take the same branches as in the chain below, without its checks.
        if failure is None:
            failure = _plain_failure(value, depth)
            if failure is None:
                out.append(_PLAIN_JSON_TEXT(value))
                return
        if depth >= MAX_JSON_DEPTH:
            raise ProtocolValueError("nesting_too_deep")
        if kind is dict:
            _write_mapping(cast(dict[str, object], value), depth + 1, failure, out)
        else:
            _write_sequence(cast(Sequence[object], value), depth + 1, failure, out)
    elif kind is CanonicalFragment:
        fragment = cast(CanonicalFragment, value)
        if fragment.levels >= 0 and depth + fragment.levels >= MAX_JSON_DEPTH:
            raise ProtocolValueError("nesting_too_deep")
        out.append(fragment.text)
    elif value is None:
        out.append("null")
    elif kind is bool:
        out.append("true" if value else "false")
    elif kind is int:
        if not -_MAX_SAFE_INTEGER <= cast(int, value) <= _MAX_SAFE_INTEGER:
            raise ProtocolValueError("integer_out_of_safe_range")
        out.append(str(value))
    elif _is_actual_float(value):
        raise ProtocolValueError("float_forbidden")
    elif kind is str:
        out.append(_encode_string(cast(str, value)))
    elif kind in {list, tuple}:
        # Not dead: a type whose metaclass compares equal to list or tuple lands here, as in the
        # walker's own ``in {list, tuple}`` test; the exact types took the first branch.
        if depth >= MAX_JSON_DEPTH:
            raise ProtocolValueError("nesting_too_deep")
        _write_sequence(
            cast(Sequence[object], value), depth + 1, failure or (_NO_MEMBER, None), out
        )
    elif _is_actual_mapping(value):
        if depth >= MAX_JSON_DEPTH:
            raise ProtocolValueError("nesting_too_deep")
        _write_mapping(
            cast(Mapping[str, object], value), depth + 1, failure or (_NO_MEMBER, None), out
        )
    else:
        raise ProtocolValueError("unsupported_json_type")


# How the walker writes a container's members once its check failed. Each member is still
# checked at the moment the walker emits it, exactly as walking it would:
#
# - a member the failed check accepted stays accepted while no code outside this module has
#   run since the check. Consecutive such members, and members that pass their own check (in a
#   mapping, containers under keys below U+10000; scalars there are written directly), are
#   gathered into one run that a single C encoder call renders before anything else happens,
#   so no outside code (a Mapping's iteration, say) can change a member between its check and
#   its encoding;
# - the failing member is walked with its own report while that report is still current;
# - once anything that may have run outside code has been walked, every remaining member is
#   checked again when it is reached.
#
# A sequence emits in scan order, so its accepted prefix precedes the failing member. A dict
# emits in key order, so an accepted member can come after a member that ran outside code.


def _write_sequence(
    sequence: Sequence[object],
    depth: int,
    failure: _PlainFailure,
    out: list[str],
) -> None:
    """Write a sequence whose members sit at *depth*, given its failed check."""

    marker, member_failure = failure if failure else (_NO_MEMBER, None)
    run: list[object] = []
    failed_at = 0
    if marker is not _NO_MEMBER:
        # Only an exact list or tuple has a marker, so scanning and slicing it run nothing.
        if sequence[0] is not marker:
            found = next(compress(count(), map(is_, sequence, repeat(marker))), None)
            if found is None:
                member_failure = None
            else:
                failed_at = found
                run = list(sequence[:failed_at])
    # Every member and run is written after a comma; the first comma is dropped at the end.
    out.append("[")
    opened = len(out)
    for item in islice(sequence, failed_at, None):
        report = member_failure
        if report is None:
            kind = type(item)
            if kind is int:
                if -_MAX_SAFE_INTEGER <= cast(int, item) <= _MAX_SAFE_INTEGER:
                    run.append(item)
                    continue
                report = ()
            elif kind is str:
                if _INVALID_STRING_CHARS.search(cast(str, item)) is None:
                    run.append(item)
                    continue
                report = ()
            else:
                report = _plain_failure(item, depth)
                if report is None:
                    run.append(item)
                    continue
        else:
            member_failure = None
        if run:
            out.append(",")
            out.append(_PLAIN_JSON_TEXT(run)[1:-1])
            run = []
        out.append(",")
        _write(item, depth, report, out)
    if run:
        out.append(",")
        out.append(_PLAIN_JSON_TEXT(run)[1:-1])
    if len(out) > opened:
        out[opened] = ""
    out.append("]")


def _write_mapping(
    source: Mapping[str, object],
    depth: int,
    failure: _PlainFailure,
    out: list[str],
) -> None:
    """Write a mapping whose members sit at *depth* in key order, given its failed check."""

    marker, member_failure = failure if failure else (_NO_MEMBER, None)
    entries: list[tuple[str, object]]
    if type(source) is dict:
        # Iterating an exact dict runs no outside code, and its failed check accepted every key
        # before the marker's, so only the rest need checking and the order is decided at once.
        exact = cast(dict[str, object], source)
        keys = list(exact)
        # The marker is one of these keys and every key before it is a distinct exact string, so
        # finding it by equality is exact and runs no outside code. A marker that is not a
        # string is the first key that is not one, and the check below rejects it.
        failed_at = keys.index(marker) if type(marker) is str else 0
        unchecked = keys[failed_at:] if failed_at else keys
        for key in unchecked:
            if type(key) is not str:
                raise ProtocolValueError("object_key_not_string")
            if _INVALID_STRING_CHARS.search(key) is not None:
                _validate_string(key)
        # Every key is now a valid string, so a match here is a character above U+FFFF.
        if _UNPLAIN_KEY_CHARS.search("".join(unchecked)) is not None:
            entries = sorted(exact.items(), key=_entry_order)
        else:
            # Code point order is UTF-16 order below U+10000, and distinct keys decide every
            # comparison, so no value is ever compared.
            entries = sorted(exact.items())
        accepted = failed_at > 0
        pending = frozenset(unchecked) if accepted else _NO_KEYS
    else:
        entries = []
        for key, item in source.items():
            if type(key) is not str:
                raise ProtocolValueError("object_key_not_string")
            _validate_string(key)
            entries.append((key, item))
        entries.sort(key=_entry_order)
        accepted = False
        pending = _NO_KEYS
    # Every member and run is written after a comma; the first comma is dropped at the end.
    out.append("{")
    opened = len(out)
    run: dict[str, object] = {}  # checked members not yet written
    current = True  # nothing outside this module has run since the check
    for key, item in entries:
        if current and accepted and key not in pending:
            run[key] = item
            continue
        kind = type(item)
        text: str | None = None  # a scalar member's own text, written in place
        report: _PlainFailure | None = None
        if current and key is marker and member_failure is not None:
            report = member_failure
        elif kind is str:
            text = f",{_encode_string(key)}:{_encode_string(cast(str, item))}"
        elif kind is int:
            if not -_MAX_SAFE_INTEGER <= cast(int, item) <= _MAX_SAFE_INTEGER:
                raise ProtocolValueError("integer_out_of_safe_range")
            text = f",{_encode_string(key)}:{item}"
        else:
            report = _plain_failure(item, depth)
            # A key above U+FFFF sorts differently in the C encoder, so it never joins a run.
            if report is None and _UNPLAIN_KEY_CHARS.search(key) is None:
                if key in run:  # only a Mapping that repeats a key; each one is written
                    out.append(",")
                    out.append(_PLAIN_JSON_TEXT(run)[1:-1])
                    run = {}
                run[key] = item
                continue
        if run:
            out.append(",")
            out.append(_PLAIN_JSON_TEXT(run)[1:-1])
            run = {}
        if text is not None:
            out.append(text)
            continue
        out.append(f",{_encode_string(key)}:")
        if report is None:
            out.append(_PLAIN_JSON_TEXT(item))
        else:
            _write(item, depth, report, out)
            # Of the members that do not raise, only a fragment is known to run nothing
            # outside this module; any other walked a container, which may have.
            current = current and type(item) is CanonicalFragment
    if run:
        out.append(",")
        out.append(_PLAIN_JSON_TEXT(run)[1:-1])
    if len(out) > opened:
        out[opened] = out[opened][1:]
    out.append("}")


# The plain fast path (#290 follow-up): one checking walk, then the C json encoder. It is taken
# only when the walker (_canonical_text) would accept the whole value, so every error still comes
# from the walker in its own order. For such a value the C encoder emits identical text: it
# escapes exactly '"', '\\', \b \t \n \f \r and the other C0 controls as lowercase \u00xx, passes
# everything else through raw under ensure_ascii=False, renders an exact int with int.__repr__,
# and encodes an exact tuple as a list. sort_keys orders keys by code point, which equals the
# walker's UTF-16BE order only when no key holds a character above U+FFFF, so such keys take the
# walker.
#
# Known gap (open for a maintainer decision): the check and the C encoder read the value twice,
# where the walker reads each node once as it emits it. Another thread or a finalizer that mutates
# the value between the two reads can get text the walker would have rejected (a float, say), or
# the C encoder's ValueError for a NaN. Nothing here can close that without dropping the fast
# path, so a value must not be mutated while it is being encoded.
_PLAIN_ENCODER: Final = json.JSONEncoder(
    ensure_ascii=False,
    separators=(",", ":"),
    sort_keys=True,
    check_circular=False,
    allow_nan=False,
)


def _one_shot_text() -> Callable[[object], str]:
    """Return the encoder's text function, built once instead of on every call.

    ``JSONEncoder.encode`` builds a fresh C encoder with exactly these arguments for every value;
    building it once keeps the text identical and drops that cost from each small value.
    """

    try:
        from _json import make_encoder
    except ImportError:  # no C accelerator: the encoder's own pure-Python path
        return _PLAIN_ENCODER.encode
    one_shot = make_encoder(
        None,  # check_circular=False
        _PLAIN_ENCODER.default,
        json.encoder.encode_basestring,  # ensure_ascii=False
        None,
        ":",
        ",",
        True,
        False,
        False,
    )

    def text(value: object) -> str:
        return "".join(one_shot(value, 0))

    return text


_PLAIN_JSON_TEXT: Final = _one_shot_text()
_UNPLAIN_KEY_CHARS: Final = re.compile("[\\u0000\\ud800-\\udfff\\U00010000-\\U0010ffff]")


# What a failed check knows, so the walker never scans a subtree twice: () when *value* itself
# failed, otherwise (marker, member) for the first failing member in iteration order, where
# member is that member's own report, or None when the member was not checked (its key failed).
# The marker is the member's key in a dict and the member itself in a list or tuple; an object
# held earlier in the same container would have failed there first, so the walker finds the
# failing position as the first member that is the marker, without the check counting positions.
type _PlainFailure = tuple[()] | tuple[object, _PlainFailure | None]
_NO_MEMBER: Final = object()


def _entry_order(entry: tuple[str, object]) -> bytes:
    return entry[0].encode("utf-16-be")


_NO_KEYS: Final = frozenset[str]()


def _plain_failure(value: object, depth: int) -> _PlainFailure | None:
    """Return None only when the walker would accept *value* and the C encoder matches its text.

    Accepts exact ``dict`` (exact ``str`` keys), ``list``, ``tuple``, ``str``, ``int``, ``bool``
    and ``None`` within the profile; anything else, including subclasses, other mappings,
    fragments and floats, fails so the walker decides.
    """

    kind = type(value)
    if kind is dict:
        if depth >= MAX_JSON_DEPTH:
            return ()
        source = cast(dict[object, object], value)
        for key, item in source.items():
            if type(key) is not str or _UNPLAIN_KEY_CHARS.search(key) is not None:
                return (key, None)
            item_kind = type(item)
            if item_kind is str:
                if _INVALID_STRING_CHARS.search(cast(str, item)) is not None:
                    return (key, ())
            elif item_kind is int:
                if not -_MAX_SAFE_INTEGER <= cast(int, item) <= _MAX_SAFE_INTEGER:
                    return (key, ())
            elif item is not None and item_kind is not bool:
                member = _plain_failure(item, depth + 1)
                if member is not None:
                    return (key, member)
        return None
    if kind is list or kind is tuple:
        if depth >= MAX_JSON_DEPTH:
            return ()
        for item in cast(Sequence[object], value):
            item_kind = type(item)
            if item_kind is str:
                if _INVALID_STRING_CHARS.search(cast(str, item)) is not None:
                    return (item, ())
            elif item_kind is int:
                if not -_MAX_SAFE_INTEGER <= cast(int, item) <= _MAX_SAFE_INTEGER:
                    return (item, ())
            elif item is not None and item_kind is not bool:
                member = _plain_failure(item, depth + 1)
                if member is not None:
                    return (item, member)
        return None
    if kind is str:
        return None if _INVALID_STRING_CHARS.search(cast(str, value)) is None else ()
    if kind is int:
        return None if -_MAX_SAFE_INTEGER <= cast(int, value) <= _MAX_SAFE_INTEGER else ()
    return None if value is None or kind is bool else ()


def _is_actual_mapping(value: object) -> bool:
    try:
        return issubclass(type(value), Mapping)
    except BaseException:
        return False


def _is_actual_float(value: object) -> bool:
    try:
        return issubclass(type(value), float)
    except BaseException:
        return False


# One C-level scan replaces the per-character Python loops below for the
# overwhelmingly common plain string; both fall back to the exact original
# logic when a match is found, so output and error identity never change.
# The per-character loops dominated hook wall time on a ~1 MiB state (#290).
_INVALID_STRING_CHARS: Final = re.compile("[\\u0000\\ud800-\\udfff]")
_ESCAPED_STRING_CHARS: Final = re.compile("[\\u0000-\\u001f\\u0022\\u005c\\ud800-\\udfff]")


def _validate_string(value: str) -> None:
    matched = _INVALID_STRING_CHARS.search(value)
    if matched is None:
        return
    if matched.group() == "\x00":
        raise ProtocolValueError("nul_byte_forbidden")
    raise ProtocolValueError("lone_surrogate")


def _encode_string(value: str) -> str:
    if _ESCAPED_STRING_CHARS.search(value) is None:
        # Nothing to escape and nothing to reject: the escaped-character
        # class is a superset of the invalid-character class.
        return f'"{value}"'
    _validate_string(value)
    parts: list[str] = ['"']
    for character in value:
        codepoint = ord(character)
        if character == '"':
            parts.append(r"\"")
        elif character == "\\":
            parts.append(r"\\")
        elif codepoint == 0x08:
            parts.append(r"\b")
        elif codepoint == 0x09:
            parts.append(r"\t")
        elif codepoint == 0x0A:
            parts.append(r"\n")
        elif codepoint == 0x0C:
            parts.append(r"\f")
        elif codepoint == 0x0D:
            parts.append(r"\r")
        elif 0x01 <= codepoint <= 0x1F:
            parts.append(f"\\u{codepoint:04x}")
        else:
            parts.append(character)
    parts.append('"')
    return "".join(parts)
