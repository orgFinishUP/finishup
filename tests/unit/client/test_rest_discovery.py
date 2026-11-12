"""HTTPS discovery, the HTTPS profile source and the key check (ADR-053, design v2 §2.1, §8.8).

Discovery sends no credential and accepts only a FinishUP REST v1 server of this release's API
manifest whose profile route is the fixed same-origin one; the profile is fetched with the key and
bound to the identity this client's trust observed; a key check stores nothing for a refused key,
a mismatched identity or another contract, and keeps an unverified key when the server does not
answer.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from collections.abc import AsyncIterator, Iterator, MutableMapping
from pathlib import Path
from typing import Any

import httpx
import pytest

from builders.rest_backend import ScriptedRestBackend
from builders.server_targets import ambient_home
from finishup.client import rest_discovery
from finishup.client.rest_client import RestTransport, RestUnavailable
from finishup.client.rest_discovery import check_key, discover, fetch_profile_async
from finishup.client.targets import ServerTarget, new_remote_target, registry_lock
from finishup.protocol.server_profile import profile_from_json
from finishup.rest.api_keys import ApiKeyStore
from finishup.rest.app import RestApp
from finishup.rest.contract import Discovery, discovery_document

pytestmark = pytest.mark.anyio


@pytest.fixture
def keys_dir() -> Iterator[Path]:
    base = Path.home() / f".yz-rest-disc-{os.getpid()}-{id(object())}"
    base.mkdir(mode=0o700)
    try:
        yield base
    finally:
        shutil.rmtree(base, ignore_errors=True)


@pytest.fixture
async def app_and_key(keys_dir: Path) -> AsyncIterator[tuple[RestApp, str]]:
    keys = ApiKeyStore(keys_dir / "rest")
    _record, key = keys.create("laptop", "agent")
    app = RestApp(ScriptedRestBackend(), keys)
    yield app, key
    await app.aclose()


def _record(monkeypatch: pytest.MonkeyPatch) -> ServerTarget:
    with registry_lock():
        record, _root = new_remote_target(
            "lab", "https", base_url="https://lab.example", tls_pin="sha256:" + "e" * 64
        )
    return record


class _Watching:
    """An ASGI app that records the headers of every request before passing it on."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.seen: list[tuple[str, dict[bytes, bytes]]] = []

    async def __call__(self, scope: MutableMapping[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") == "http":
            self.seen.append((scope["path"], dict(scope["headers"])))
        await self.inner(scope, receive, send)


async def test_discovery_sends_no_credential_and_the_profile_is_bound_to_the_observed_pin(
    monkeypatch: pytest.MonkeyPatch, app_and_key: tuple[RestApp, str]
) -> None:
    app, key = app_and_key
    watching = _Watching(app.asgi())
    with ambient_home(monkeypatch):
        record = _record(monkeypatch)
        transport = RestTransport.for_target(
            record, key=key, transport=httpx.ASGITransport(app=watching)
        )
        try:
            fetched = await fetch_profile_async(record, transport=transport)
        finally:
            await transport.aclose()
    assert [path for path, _headers in watching.seen] == ["/.well-known/finishup", "/v1/server"]
    assert b"authorization" not in watching.seen[0][1]
    assert watching.seen[1][1][b"authorization"].startswith(b"Bearer fuk_")
    assert (fetched.identity_type, fetched.identity) == ("tls_pin", "sha256:" + "e" * 64)
    profile = profile_from_json(fetched.document)
    assert profile.key.scope == "agent" and profile.edges == ("rest-1",)


async def test_a_refused_key_is_remote_auth_failed(
    monkeypatch: pytest.MonkeyPatch, app_and_key: tuple[RestApp, str]
) -> None:
    app, _key = app_and_key
    with ambient_home(monkeypatch):
        record = _record(monkeypatch)
        transport = RestTransport(
            "https://lab.example",
            key="fuk_000000000000_" + "A" * 43,
            transport=httpx.ASGITransport(app=app.asgi()),
        )
        try:
            with pytest.raises(RestUnavailable) as refused:
                await fetch_profile_async(record, transport=transport)
        finally:
            await transport.aclose()
    assert refused.value.reason == "remote_auth_failed"


def _discovery_app(body: bytes, status: int = 200) -> Any:
    async def app(scope: MutableMapping[str, Any], receive: Any, send: Any) -> None:
        del receive
        if scope.get("type") != "http":
            return
        await send({"type": "http.response.start", "status": status, "headers": []})
        await send({"type": "http.response.body", "body": body})

    return app


@pytest.mark.parametrize(
    "body",
    [
        discovery_document(Discovery(rest_majors=("1",), api_manifests=("sha256:" + "0" * 64,))),
        discovery_document(
            Discovery(
                rest_majors=("1",),
                api_manifests=("sha256:" + "0" * 64,),
                profile_endpoint="/elsewhere/profile",
            )
        ),
        discovery_document(Discovery(rest_majors=("2",), api_manifests=("sha256:" + "0" * 64,))),
        json.dumps({"product": "other"}).encode(),
        b"{" + b" " * 8_000 + b"}",
    ],
    ids=["other_manifest", "other_profile_route", "other_major", "not_finishup", "unbounded"],
)
async def test_discovery_refuses_anything_but_this_contract(body: bytes) -> None:
    transport = RestTransport(
        "https://lab.example", key=None, transport=httpx.ASGITransport(app=_discovery_app(body))
    )
    try:
        with pytest.raises(RestUnavailable) as refused:
            await discover(transport)
    finally:
        await transport.aclose()
    assert refused.value.reason == "remote_incompatible"


async def test_discovery_of_a_server_with_this_manifest_but_another_route_is_refused() -> None:
    from finishup.rest.contract import current_api_manifest

    body = discovery_document(
        Discovery(
            rest_majors=("1",),
            api_manifests=(current_api_manifest(),),
            profile_endpoint="/v2/server",
        )
    )
    transport = RestTransport(
        "https://lab.example", key=None, transport=httpx.ASGITransport(app=_discovery_app(body))
    )
    try:
        with pytest.raises(RestUnavailable) as refused:
            await discover(transport)
    finally:
        await transport.aclose()
    assert refused.value.reason == "remote_incompatible"


@pytest.mark.parametrize(
    ("raised", "expected"),
    [
        ("remote_unreachable", "unanswered"),
        ("remote_service_not_running", "unanswered"),
        ("remote_auth_failed", None),
        ("remote_identity_changed", None),
        ("remote_incompatible", None),
    ],
)
def test_a_key_check_keeps_a_key_only_when_the_server_could_not_judge_it(
    monkeypatch: pytest.MonkeyPatch, raised: str, expected: str | None
) -> None:
    def refuse(_record: object, *, key: str | None = None, consented: bool = False) -> object:
        del key, consented
        raise RestUnavailable(raised)

    monkeypatch.setattr(rest_discovery, "fetch_profile", refuse)
    with ambient_home(monkeypatch):
        record = _record(monkeypatch)
        if expected is None:
            with pytest.raises(RestUnavailable) as refused:
                check_key(record, "fuk_0123456789ab_" + "A" * 43)
            assert refused.value.reason == raised
        else:
            checked = check_key(record, "fuk_0123456789ab_" + "A" * 43)
            assert (checked.outcome, checked.phase) == (expected, raised)


@pytest.mark.parametrize("profile", [b"{}", b"not json", None], ids=["empty", "garbled", "other"])
async def test_a_profile_answer_this_release_cannot_use_is_incompatible(
    monkeypatch: pytest.MonkeyPatch, app_and_key: tuple[RestApp, str], profile: bytes | None
) -> None:
    """B7: a ``200`` from ``/v1/server`` is a key check's success only for a valid profile that
    names the key sent; anything else is ``remote_incompatible`` (so ``login`` stores nothing)."""

    from builders.server_profiles import profile_document
    from finishup.client.server_profile import FetchedProfile

    app, key = app_and_key
    if profile is None:
        document = profile_document()
        document["key"] = {"id": "0" * 12, "scope": "agent", "principal": "p_" + "1" * 16}
        profile = json.dumps(document).encode()
    inner = app.asgi()

    async def answering(scope: MutableMapping[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") == "http" and scope["path"] == "/v1/server":
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": profile})
            return
        await inner(scope, receive, send)

    with ambient_home(monkeypatch):
        record = _record(monkeypatch)
        transport = RestTransport.for_target(
            record, key=key, transport=httpx.ASGITransport(app=answering)
        )
        try:
            with pytest.raises(RestUnavailable) as refused:
                await fetch_profile_async(record, transport=transport)
        finally:
            await transport.aclose()
        assert refused.value.reason == "remote_incompatible"

        async def fetched_with(*_arguments: object, **_options: object) -> FetchedProfile:
            own = RestTransport.for_target(
                record, key=key, transport=httpx.ASGITransport(app=answering)
            )
            try:
                return await fetch_profile_async(record, transport=own)
            finally:
                await own.aclose()

        monkeypatch.setattr(rest_discovery, "fetch_profile_async", fetched_with)
        with pytest.raises(RestUnavailable) as check:
            await asyncio.to_thread(check_key, record, key)
        assert check.value.reason == "remote_incompatible"
