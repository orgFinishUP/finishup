"""Host-owned JSON configuration is observed despite values the wire profile rejects (#1278)."""

from __future__ import annotations

import pytest

from finishup.adapters.integrations.host_config_json import parse_host_config_json
from finishup.protocol.canonical import strict_json_parse
from finishup.protocol.errors import ProtocolValueError


def test_decimals_and_unsafe_integers_read_as_null_and_the_rest_is_kept() -> None:
    raw = (
        b'{"numStartups": 3, "lastCost": 22.0157, "flags": {"rate": 0.15, "big": 9007199254740993,'
        b' "neg": -0, "inf": Infinity}, "mcpServers": {"finishup": {"command": "finishup",'
        b' "args": ["mcp", "serve"]}}, "list": [1, 2.5, "x"]}'
    )
    with pytest.raises(ProtocolValueError):
        strict_json_parse(raw)

    parsed = parse_host_config_json(raw)

    assert parsed == {
        "numStartups": 3,
        "lastCost": None,
        "flags": {"rate": None, "big": None, "neg": None, "inf": None},
        "mcpServers": {"finishup": {"command": "finishup", "args": ["mcp", "serve"]}},
        "list": [1, None, "x"],
    }


@pytest.mark.parametrize("escape", [b"\\ud83d", b"\\udc00", b"\\u0000"])
def test_escaped_nul_or_lone_surrogate_in_a_string_value_reads_as_null(escape: bytes) -> None:
    raw = (
        b'{"history": [{"display": "cut ' + escape + b'"}], "note": "' + escape + b'",'
        b' "mcpServers": {"finishup": {"command": "finishup", "args": ["mcp", "serve"]}},'
        b' "emoji": "\\ud83d\\ude00"}'
    )
    with pytest.raises(ProtocolValueError):
        strict_json_parse(raw)

    parsed = parse_host_config_json(raw)

    assert parsed == {
        "history": [{"display": None}],
        "note": None,
        "mcpServers": {"finishup": {"command": "finishup", "args": ["mcp", "serve"]}},
        "emoji": "\U0001f600",
    }


def test_integers_longer_than_any_safe_integer_read_as_null() -> None:
    # 5000 digits is past the interpreter's integer-string conversion limit.
    raw = b'{"huge": ' + b"1" * 5000 + b', "negative": -' + b"1" * 5000 + b', "kept": 7}'

    assert parse_host_config_json(raw) == {"huge": None, "negative": None, "kept": 7}


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b'{"a": 1, "a": 2}', "duplicate_object_key"),
        (b"\xef\xbb\xbf{}", "byte_order_mark_forbidden"),
        (b'{"a": "\x00"}', "nul_byte_forbidden"),
        (b'{"a\\u0000b": 1}', "nul_byte_forbidden"),
        (b'{"mcpServers": {"x\\ud83d": {}}}', "lone_surrogate"),
        (b"\xff", "invalid_utf8"),
        (b"{", "malformed_json"),
        (b"[" * 200 + b"]" * 200, "nesting_too_deep"),
    ],
)
def test_structural_problems_still_make_the_file_unreadable(raw: bytes, reason: str) -> None:
    with pytest.raises(ProtocolValueError) as error:
        parse_host_config_json(raw)
    assert str(error.value) == reason or reason in repr(error.value)
