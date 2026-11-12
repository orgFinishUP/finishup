"""The REST edge's API keys (ADR-053): hashed at rest, closed reasons, re-read on change.

Keys are stored only as salted hashes in an owner-only canonical file beneath the server root's
state (``<state>/rest``), compared in constant time, re-read by an edge when the file changes,
and every failure is a closed reason that never carries the key. A rotated key keeps its
predecessor's principal, so its client's tasks stay reachable.
"""

from __future__ import annotations

import os
import shutil
import stat
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from finishup.rest.api_keys import API_KEYS_SCHEMA, ApiKeyError, ApiKeyStore
from finishup.rest.contract import parse_api_key

_NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)


@pytest.fixture
def store() -> Iterator[ApiKeyStore]:
    base = Path.home() / f".yz-keys-{os.getpid()}-{id(object())}"
    base.mkdir(mode=0o700)
    try:
        yield ApiKeyStore(base / "rest")
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_a_created_key_is_stored_hashed_owner_only_and_shown_once(store: ApiKeyStore) -> None:
    record, token = store.create("laptop", "agent", now=_NOW)
    parsed = parse_api_key(token)
    assert parsed is not None
    data = store.path.read_bytes()
    assert token.encode() not in data
    assert parsed.secret not in data
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700
    assert API_KEYS_SCHEMA.encode() in data
    assert API_KEYS_SCHEMA == "yoetz.rest-api-keys/1"
    assert store.authenticate(token, now=_NOW) == record
    assert token not in repr(record) and record.hash not in repr(record)
    assert record.created_at == "2026-11-05T12:00:00.000Z"
    assert record.principal.startswith("p_") and len(record.principal) == 18


def test_failures_are_closed_reasons_without_the_key(store: ApiKeyStore) -> None:
    record, token = store.create("laptop", "operator", now=_NOW)
    for candidate in ("", "fuk_short", token.replace(record.key_id, "f" * 12), "x" * 80):
        with pytest.raises(ApiKeyError) as raised:
            store.authenticate(candidate, now=_NOW)
        assert raised.value.reason == "api_key_invalid"
        assert token not in str(raised.value)
    # The right id with another secret is refused the same way.
    other = "fuk_" + record.key_id + "_" + "A" * 43
    with pytest.raises(ApiKeyError, match="api_key_invalid"):
        store.authenticate(other, now=_NOW)
    assert store.revoke(record.key_id, now=_NOW) is True
    assert store.revoke(record.key_id, now=_NOW) is False
    with pytest.raises(ApiKeyError, match="api_key_revoked"):
        store.authenticate(token, now=_NOW)
    with pytest.raises(ApiKeyError, match="api_key_unknown"):
        store.revoke("0" * 12)


def test_expiry_and_rotation(store: ApiKeyStore) -> None:
    first, first_token = store.create("laptop", "agent", expires_in_days=1, now=_NOW)
    assert store.authenticate(first_token, now=_NOW + timedelta(hours=23)).key_id == first.key_id
    with pytest.raises(ApiKeyError, match="api_key_expired"):
        store.authenticate(first_token, now=_NOW + timedelta(days=1))
    second, _second_token = store.create("laptop-2", "operator", rotate=first.key_id, now=_NOW)
    third, _third_token = store.create("other", "agent", now=_NOW)
    assert second.principal == first.principal != third.principal
    assert not store.is_active(first.key_id, now=_NOW + timedelta(days=2))
    assert store.is_active(second.key_id, now=_NOW)
    with pytest.raises(ApiKeyError, match="api_key_unknown"):
        store.create("x", "agent", rotate="0" * 12)


@pytest.mark.parametrize(
    ("arguments", "reason"),
    [
        ({"label": "", "scope": "agent"}, "api_key_label_invalid"),
        ({"label": "bad\nlabel", "scope": "agent"}, "api_key_label_invalid"),
        ({"label": "ok", "scope": "root"}, "api_key_scope_invalid"),
        ({"label": "ok", "scope": "agent", "expires_in_days": 0}, "api_key_expiry_invalid"),
    ],
)
def test_creation_inputs_are_validated(
    store: ApiKeyStore, arguments: dict[str, object], reason: str
) -> None:
    with pytest.raises(ApiKeyError) as raised:
        store.create(**arguments)  # type: ignore[arg-type]
    assert raised.value.reason == reason
    assert not store.path.exists()


def test_an_edge_rereads_the_file_when_it_changes(store: ApiKeyStore) -> None:
    edge = ApiKeyStore(store.path.parent)
    record, token = store.create("laptop", "agent", now=_NOW)
    assert edge.authenticate(token, now=_NOW).key_id == record.key_id
    store.revoke(record.key_id, now=_NOW)
    with pytest.raises(ApiKeyError, match="api_key_revoked"):
        edge.authenticate(token, now=_NOW)


def test_an_unsafe_or_damaged_file_fails_closed(store: ApiKeyStore) -> None:
    _record, token = store.create("laptop", "agent", now=_NOW)
    store.path.chmod(0o644)
    with pytest.raises(ApiKeyError, match="api_keys_unsafe"):
        ApiKeyStore(store.path.parent).authenticate(token)
    store.path.chmod(0o600)
    store.path.write_bytes(b'{"keys":[],"schema":"other"}\n')
    with pytest.raises(ApiKeyError, match="api_keys_damaged"):
        ApiKeyStore(store.path.parent).records()


def test_keys_in_a_folder_others_could_change_are_never_trusted(store: ApiKeyStore) -> None:
    """A2-1: the folder is owner-only and link-free, or no key authenticates."""

    _record, token = store.create("laptop", "agent", now=_NOW)
    folder = store.path.parent
    folder.chmod(0o770)
    try:
        with pytest.raises(ApiKeyError) as widened:
            store.authenticate(token, now=_NOW)
        assert widened.value.reason == "api_keys_unsafe"
    finally:
        folder.chmod(0o700)
    assert store.authenticate(token, now=_NOW).key_id == _record.key_id
    link = folder.parent / "linked"
    link.symlink_to(folder.parent, target_is_directory=True)
    with pytest.raises(ApiKeyError) as linked:
        ApiKeyStore(link / "rest").authenticate(token, now=_NOW)
    assert linked.value.reason == "api_keys_unsafe"


def test_a_key_file_swapped_after_its_check_is_judged_by_what_was_opened(
    store: ApiKeyStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A2-1: what is decoded is what the opened descriptor is (``fstat``), so a file swapped in
    between a path check and the open (here: another store's database, readable by others) is
    refused rather than trusted."""

    _record, _token = store.create("laptop", "agent", now=_NOW)
    other = ApiKeyStore(store.path.parent.parent / "other")
    _intruder, intruder_key = other.create("intruder", "operator", now=_NOW)
    planted = other.path.read_bytes()
    real_open = os.open

    def swapping_open(path: object, flags: int, *rest: int, **options: object) -> int:
        if os.fspath(cast(str, path)) == os.fspath(store.path):
            swap = store.path.with_name("swap")
            swap.write_bytes(planted)
            swap.chmod(0o644)
            os.replace(swap, store.path)
        return real_open(path, flags, *rest, **options)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", swapping_open)
    try:
        with pytest.raises(ApiKeyError) as refused:
            store.authenticate(intruder_key, now=_NOW)
    finally:
        monkeypatch.undo()
    assert refused.value.reason == "api_keys_unsafe"


def test_a_key_stored_but_not_flushed_is_revoked_before_create_fails(
    store: ApiKeyStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A2-4: the new key is in place when its folder cannot be flushed; ``create`` fails, so
    nobody receives it, and it is revoked first (no active key is left that nobody holds)."""

    store.create("first", "agent", now=_NOW)
    real_fsync = os.fsync

    def failing_fsync(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("folder_sync_failed")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", failing_fsync)
    with pytest.raises(ApiKeyError) as failed:
        store.create("second", "agent", now=_NOW)
    assert failed.value.reason == "api_keys_unsafe"
    monkeypatch.setattr(os, "fsync", real_fsync)
    second = [record for record in store.records() if record.label == "second"]
    assert len(second) == 1 and second[0].revoked_at is not None
