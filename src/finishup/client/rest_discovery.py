"""HTTPS discovery, the server profile of an HTTPS target, and the key check (ADR-053).

Design v2 sections 2.1, 2.2 and 8.8, for ``https`` and ``local_port`` targets:

1. **Discovery, before any credential.** ``GET /.well-known/finishup`` over a TLS connection the
   owner's trust already verified (the CA file, the ``sha256:`` pin, or the system store), with
   no key (ADR-008's narrow discovery exception). The answer is bounded (4 KiB) and strict: it must
   be a FinishUP server speaking REST major 1 with API keys, name exactly the fixed same-origin
   profile route ``/v1/server``, and serve this release's REST API manifest (U18); anything else
   is ``remote_incompatible`` and the key is never asked for. A redirect is never followed.
2. **The profile, with the key.** ``GET /v1/server`` answers ``server-profile`` 1.0.0 with the
   caller's key (id, scope, principal). It is validated here, before anything is made of it: a
   document this release cannot read, or one naming another key than the one sent, is
   ``remote_incompatible``. The endpoint identity the consent binds to is the identity of the trust
   the transport verified with (``rest_client.TlsTrust``: the CA file's bytes as loaded into its
   TLS context), never what the server says. A fetch made after the consent (the helper's
   refresh, a login check) is bound to the consented identity before its first byte, and asks
   ``may_send`` before each of its requests.
3. **The key check** (``server login``, approach A's ``96cc87298``): the same profile fetch with
   the key being stored. A key the server refuses, a server whose certificate does not match the
   recorded trust, or one of another contract (an invalid profile included) stores nothing; a
   server that does not answer keeps the key as not verified yet.

``RestProfileSource`` is the ``client.server_profile.ProfileSource`` of both kinds. Never imported
or run on a hook's path (design v2 section 8.9).
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from finishup.client.rest_client import RestTransport, RestUnavailable, load_key
from finishup.client.server_profile import FetchedProfile
from finishup.protocol.server_profile import ProfileError, profile_from_json
from finishup.rest.contract import (
    MAX_DISCOVERY_BYTES,
    MAX_DOCUMENT_BYTES,
    PROFILE_PATH,
    REST_MAJOR,
    WELL_KNOWN_PATH,
    Discovery,
    RestDocumentError,
    current_api_manifest,
    parse_discovery,
)

if TYPE_CHECKING:
    from finishup.client.targets import ServerTarget

__all__ = [
    "KeyCheck",
    "RestProfileSource",
    "check_discovery",
    "check_key",
    "discover",
    "fetch_profile",
    "fetch_profile_async",
]


async def discover(transport: RestTransport) -> Discovery:
    """The server's discovery document, validated; ``RestUnavailable`` otherwise."""

    answer = await transport.request(
        "GET",
        WELL_KNOWN_PATH,
        headers=transport.headers(authenticated=False),
        limit=MAX_DISCOVERY_BYTES,
    )
    if answer.status == 429:
        raise RestUnavailable("remote_unreachable")
    if answer.status != 200:
        raise RestUnavailable("remote_incompatible")
    try:
        discovery = parse_discovery(answer.body)
    except RestDocumentError:
        raise RestUnavailable("remote_incompatible") from None
    if (
        REST_MAJOR not in discovery.rest_majors
        or "api_key" not in discovery.auth
        # The profile route is fixed and same-origin: a document naming another is not followed.
        or discovery.profile_endpoint != PROFILE_PATH
        or current_api_manifest() not in discovery.api_manifests
    ):
        raise RestUnavailable("remote_incompatible")
    return discovery


def _ask(may_send: Callable[[], bool] | None) -> None:
    """Withhold the next request when ``may_send`` refuses (a background refresh's own gate)."""

    if may_send is not None and not may_send():
        raise RestUnavailable("remote_unreachable")


def _validated(document: bytes, transport: RestTransport) -> None:
    """The profile is one this release reads, naming the key that was sent; else
    ``remote_incompatible`` (nothing is recorded or stored from it)."""

    try:
        profile = profile_from_json(document)
    except ProfileError:
        raise RestUnavailable("remote_incompatible") from None
    if profile.key.id is None or profile.key.id != transport.key_id:
        raise RestUnavailable("remote_incompatible")


async def _profile(
    transport: RestTransport, record: ServerTarget, *, may_send: Callable[[], bool] | None = None
) -> FetchedProfile:
    del record
    _ask(may_send)
    await discover(transport)
    _ask(may_send)
    answer = await transport.request(
        "GET", PROFILE_PATH, headers=transport.headers(), limit=MAX_DOCUMENT_BYTES
    )
    if answer.status in {401, 403}:
        raise RestUnavailable("remote_auth_failed")
    if answer.status == 503:
        raise RestUnavailable(
            "remote_auth_failed"
            if answer.rest_error == "server_keys_unusable"
            else "remote_service_not_running"
        )
    if answer.status != 200:
        raise RestUnavailable("remote_incompatible")
    _validated(answer.body, transport)
    identity_type, identity = transport.identity
    return FetchedProfile(answer.body, identity_type, identity)


async def fetch_profile_async(
    record: ServerTarget,
    *,
    key: str | None = None,
    transport: RestTransport | None = None,
    consented: bool = False,
    may_send: Callable[[], bool] | None = None,
) -> FetchedProfile:
    """``record``'s profile: discovery, then ``GET /v1/server`` with ``key`` (else the stored
    one, read off the event loop). ``consented`` binds the transport to the consented identity
    (``RestTransport.for_target``); ``may_send`` is asked before each request. Raises
    ``RestUnavailable`` with a closed phase."""

    if transport is not None:
        return await _profile(transport, record, may_send=may_send)
    chosen = key if key is not None else await load_key(record.target_id)
    own = RestTransport.for_target(record, key=chosen, consented=consented)
    try:
        return await _profile(own, record, may_send=may_send)
    finally:
        await own.aclose()


def _run[T](coroutine: Coroutine[Any, Any, T]) -> T:
    """Run ``coroutine`` to its end on a fresh event loop in its own thread (callable from any
    thread, inside an event loop or not)."""

    outcome: list[T] = []
    failure: list[BaseException] = []

    def target() -> None:
        try:
            outcome.append(asyncio.run(coroutine))
        except BaseException as error:  # noqa: BLE001 - handed back to the caller's thread
            failure.append(error)

    thread = threading.Thread(target=target, name="finishup-rest-fetch", daemon=True)
    thread.start()
    thread.join()
    if failure:
        raise failure[0]
    return outcome[0]


def check_discovery(record: ServerTarget) -> Discovery:
    """``discover`` for a synchronous caller, over ``record``'s trust, with no key at all."""

    async def run() -> Discovery:
        transport = RestTransport.for_target(record, key=None)
        try:
            return await discover(transport)
        finally:
            await transport.aclose()

    return _run(run())


def fetch_profile(
    record: ServerTarget, *, key: str | None = None, consented: bool = False
) -> FetchedProfile:
    """``fetch_profile_async`` for a synchronous caller (``server add``, ``server use``,
    ``server login``)."""

    return _run(fetch_profile_async(record, key=key, consented=consented))


class RestProfileSource:
    """The profile source of ``https`` and ``local_port`` targets (``PROFILE_SOURCES``)."""

    def fetch(self, record: ServerTarget) -> FetchedProfile:
        from finishup.client.target_runtime import TargetRuntimeError

        try:
            return fetch_profile(record)
        except RestUnavailable as error:
            raise TargetRuntimeError("remote_unreachable", phase=error.reason) from None


type KeyOutcome = Literal["accepted", "unanswered"]


@dataclass(frozen=True, slots=True)
class KeyCheck:
    """What the server said of a key: ``accepted`` (with the profile it answered) or
    ``unanswered`` (with the phase: the server could not judge it now)."""

    outcome: KeyOutcome
    profile: FetchedProfile | None
    phase: str | None = None


def check_key(record: ServerTarget, key: str) -> KeyCheck:
    """Check ``key`` with ``record``'s server before it is stored (``server login``).

    A refused key (``remote_auth_failed``), a certificate that does not match the recorded trust
    or, for a target the owner consented to, the consented identity (``remote_identity_changed``),
    or another contract, an invalid profile included (``remote_incompatible``), raise
    ``RestUnavailable``: nothing is stored. A server that does not answer is ``unanswered``.
    """

    try:
        return KeyCheck(
            "accepted", fetch_profile(record, key=key, consented=record.consent is not None)
        )
    except RestUnavailable as error:
        if error.reason in {"remote_unreachable", "remote_service_not_running"}:
            return KeyCheck("unanswered", None, error.reason)
        raise
