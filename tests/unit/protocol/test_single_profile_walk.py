"""Schema documents, the schema manifest and control frames are walked through the canonical
profile once, not twice (design v2 section 8.9: about 40% of the schema work a hook does before
its hello is answered), and refuse exactly what they refused before, for the same reason."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest

from finishup.ports.control import ControlClientKind
from finishup.protocol import canonical, schemas
from finishup.protocol.canonical import MAX_JSON_DEPTH, canonical_encode, strict_json_parse
from finishup.protocol.errors import ProtocolValueError
from finishup.service import control_protocol

_CATALOG = schemas.load_schema_catalog()
_SCHEMA_ROOT = schemas._schema_root()


@pytest.fixture
def parse_walks(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[int]]:
    """Counts the profile walks ``strict_json_parse`` makes to validate what it parsed."""

    walks: list[int] = []
    original = canonical.ensure_canonical_value

    def counted(value: object, *, depth: int = 0) -> None:
        walks.append(depth)
        original(value, depth=depth)  # type: ignore[arg-type]

    monkeypatch.setattr(canonical, "ensure_canonical_value", counted)
    yield walks


def _member_bytes(name: str) -> bytes:
    document = next(item for item in _CATALOG.documents if item.schema_name == name)
    path = document.schema_id.removeprefix(schemas.SCHEMA_NAMESPACE)
    return _SCHEMA_ROOT.joinpath(path).read_bytes()


def test_a_schema_document_is_walked_once(parse_walks: list[int]) -> None:
    plain = schemas._plain_schema(_member_bytes("control-result"), digest_verified=True)
    assert plain["$id"] == next(
        item.schema_id for item in _CATALOG.documents if item.schema_name == "control-result"
    )
    assert parse_walks == []  # the one walk is ``canonical_encode``'s


def test_the_schema_manifest_is_walked_once(parse_walks: list[int]) -> None:
    members = schemas._parse_manifest(_SCHEMA_ROOT.joinpath("manifest.json").read_bytes())
    assert len(members) == len(_CATALOG.documents)
    assert parse_walks == []


def test_a_control_frame_is_walked_once_by_its_parse(parse_walks: list[int]) -> None:
    hello = control_protocol.encode_control_frame(
        {
            "protocol_version": control_protocol.CONTROL_PROTOCOL_VERSION,
            "client_kind": ControlClientKind.CLI.value,
            "client_version": "0.3.0",
            "connection_nonce": "a" * 64,
            "schema_manifest_digest": control_protocol._manifest_digest(),
            "presentation_context": {
                "render_mode": "machine_readable",
                "output_is_controlling_tty": False,
            },
        }
    )
    parse_walks.clear()
    decoded = control_protocol._decode_control_payload(hello[4:])
    assert decoded["client_version"] == "0.3.0"
    assert parse_walks == []


def _outcome(parse: Callable[[bytes], object], data: bytes) -> str:
    try:
        parse(data)
    except ProtocolValueError as error:
        return f"refused:{error.reason_code}"
    return "accepted"


def _two_walks(data: bytes) -> object:
    parsed = strict_json_parse(data)
    if canonical_encode(parsed) != data:
        raise ProtocolValueError("schema_bytes_invalid")
    return parsed


def _one_walk(data: bytes) -> object:
    parsed = strict_json_parse(data, validate=False)
    if canonical_encode(parsed) != data:
        raise ProtocolValueError("schema_bytes_invalid")
    return parsed


_INPUTS: tuple[bytes, ...] = (
    b'{"a":1,"b":[true,false,null],"c":"x"}',
    b'{"b":1,"a":2}',
    b'{"a": 1}',
    b'{"a":1.5}',
    b'{"a":1e3}',
    b'{"a":-0}',
    b'{"a":9007199254740992}',
    b'{"a":-9007199254740992}',
    b'{"a":1,"a":2}',
    b'{"a":"\\ud800"}',
    b'{"a":"\\u0000"}',
    b'{"a":"\x00"}',
    b'\xef\xbb\xbf{"a":1}',
    b'{"a":"\xff"}',
    b'{"a":NaN}',
    b'{"a":Infinity}',
    b'["x",{"\\u00e9":1,"e":2}]',
    b'{"\\ud83d\\ude00":1,"\\uffff":2}',
    b'{"\\uffff":2,"\\ud83d\\ude00":1}',
    b'"plain"',
    b"[",
    b"",
    b"[" * MAX_JSON_DEPTH + b"]" * MAX_JSON_DEPTH,
    b"[" * (MAX_JSON_DEPTH + 1) + b"]" * (MAX_JSON_DEPTH + 1),
    b'{"a":' * MAX_JSON_DEPTH + b"1" + b"}" * MAX_JSON_DEPTH,
    b'{"a":' * (MAX_JSON_DEPTH + 1) + b"1" + b"}" * (MAX_JSON_DEPTH + 1),
)


@pytest.mark.parametrize("data", _INPUTS)
def test_one_walk_refuses_exactly_what_two_walks_refused_for_the_same_reason(data: bytes) -> None:
    assert _outcome(_one_walk, data) == _outcome(_two_walks, data)


def test_every_packaged_schema_reads_the_same_with_one_walk() -> None:
    for document in _CATALOG.documents:
        path = document.schema_id.removeprefix(schemas.SCHEMA_NAMESPACE)
        data = _SCHEMA_ROOT.joinpath(path).read_bytes()
        assert _one_walk(data) == _two_walks(data), document.schema_id
