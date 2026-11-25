"""The verified resource manifest is reused only for byte-identical manifest bytes.

``_load_resource_manifest`` re-reads ``manifest.json`` on every call and returns the previously
verified manifest only when the bytes are exactly the same; any other bytes are verified afresh,
and a failure is never stored. These tests lock that the reused result equals a fresh
verification, that changed or tampered bytes still fail exactly as before, and that repeated
loads and resource reads verify the manifest once (a deterministic count, not a timing).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

import pytest

import finishup.version as version_module
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.version import ResourceIntegrityError, read_verified_resource

_load = cast(
    Callable[[], object],
    version_module._load_resource_manifest,  # pyright: ignore[reportPrivateUsage]
)
_fresh = cast(
    Callable[[bytes], object],
    version_module._resource_manifest_from,  # pyright: ignore[reportPrivateUsage]
)
_real_bytes = cast(
    Callable[[str], bytes],
    version_module._package_bytes,  # pyright: ignore[reportPrivateUsage]
)


@pytest.fixture(autouse=True)
def empty_memo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(version_module, "_verified_manifest", None)


def _count_verifications(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    seen: list[bytes] = []

    def _counting(raw: bytes) -> object:
        seen.append(raw)
        return _fresh(raw)

    monkeypatch.setattr(version_module, "_resource_manifest_from", _counting)
    return seen


def _serve_manifest(monkeypatch: pytest.MonkeyPatch, payload: bytes) -> None:
    def _fake(package_path: str) -> bytes:
        if package_path == "manifest.json":
            return payload
        return _real_bytes(package_path)

    monkeypatch.setattr(version_module, "_package_bytes", _fake)


def _outcome(operation: Callable[[], object]) -> tuple[object, ...]:
    try:
        return ("ok", operation())
    except ResourceIntegrityError as exc:
        return ("error", type(exc).__name__, str(exc), exc.args)


def test_reused_manifest_equals_a_fresh_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _real_bytes("manifest.json")
    first = _load()
    second = _load()
    assert second is first
    assert first == _fresh(raw)


def test_repeated_loads_and_reads_verify_the_manifest_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _count_verifications(monkeypatch)
    for _ in range(5):
        _load()
    read_verified_resource("support/runtime-support.json")
    version_module.build_version_manifest()
    assert len(seen) == 1


def test_changed_bytes_are_verified_afresh_and_failures_are_not_stored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _real_bytes("manifest.json")
    seen = _count_verifications(monkeypatch)
    good = _load()

    doc = cast(dict[str, JsonValue], strict_json_parse(raw))
    entries = cast(list[JsonValue], doc["entries"])
    tampered: dict[str, JsonValue] = {**doc, "entries": entries[:-1]}
    bad_payloads = (
        canonical_encode(tampered) + b"\n",
        raw.replace(b'"package":"finishup"', b'"package":"finishuq"'),
        raw[:-1],
        raw + b"\n",
    )
    for payload in bad_payloads:
        assert payload != raw
        _serve_manifest(monkeypatch, payload)
        expected = _outcome(lambda payload=payload: _fresh(payload))
        assert expected[0] == "error"
        before = len(seen)
        # A failure is evaluated afresh on every load, never served from the stored manifest.
        assert _outcome(_load) == expected
        assert _outcome(_load) == expected
        assert len(seen) == before + 2

    _serve_manifest(monkeypatch, raw)
    assert _load() is good
