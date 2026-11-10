"""This server's own profile and the revision it issues (ADR-052, design v2 §2.2, §8.2).

A FinishUP service states what it offers a client elsewhere in a ``server-profile`` 1.0.0
document (``protocol.server_profile``), answered by the ``server_profile`` control operation and
by ``finishup service profile --json`` (the SSH discovery of layer 4). The server offers; the
client decides (design v2 §1).

**Where the offer comes from** (layer 3's decision D2):

* ``levels``: L1 is always offered and required (a server elsewhere always keeps the tasks). L2,
  the server keeping a copy of the code, is offered only when the service is given a code-copy
  offer (``CodeCopyOffer``: the caps of ``code_sync``, the ``retention`` options and the
  ``exclusions`` it enforces, which always include the client's own always-excluded list) **and**
  level L2 is released (``protocol.server_copy.l2_released``); otherwise ``code_sync``,
  ``retention`` and ``exclusions`` are null, as in layers 3 to 5.
* ``review``: derived from this service's own ``config.toml``, from the same settings that decide
  whether it can reach an AI provider at all, so the profile never understates it: a profile whose
  semantic capability is an external provider states ``server_policy`` (its owner's privacy policy
  decides what is sent) and names, by closed tokens, every provider its review may send to: the
  one it sends to first and, with a ``[semantic_fallback]`` pairing, the one it falls back to; any
  other states ``none``. A configuration the profile cannot state exactly (a provider id that is
  not a profile token) offers **no profile** rather than one that understates it: the
  ``server_profile`` operation is refused, and so is every hello that names a revision or a claim.
* ``official`` is always false here (the official service is built elsewhere, and the claim never
  counts on its own); ``edges`` is ``ssh-control``; a peer-authenticated session is the owner's
  (``operator``, no key id).

**The revision** (``ProfileRevisionStore``): ``<state dir>/server-profile-revision.json``
(``yoetz.server-profile-revision/1``, owner-only canonical JSON, renamed into place) keeps a random
``issuer``, the revision number and the digest it stands for. When the service starts, the digest
of its current offer is compared with the record: a new digest advances the number; a missing
record starts at 1 under a new issuer; a record that cannot be read is replaced under a new issuer,
so every consent made under the old one asks again. A record that cannot be written keeps the
revision in memory: the digest in the triple keeps a reused number from matching another offer.
The service admits a remote client only under the current triple and re-checks it on every request
(``service.control_protocol``, ``service.daemon``).

No path, host or name is in the profile: closed tokens, digests, a release and an instance id.
"""

from __future__ import annotations

import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.consent_envelope import CodeSync, Retention, ReviewEgress
from finishup.protocol.server_copy import CODE_SYNC_METHOD, l2_released
from finishup.protocol.server_profile import (
    ProfileError,
    ProfileKey,
    ProfileLevels,
    ProfileRetention,
    ServerProfile,
    ServerProfileRevision,
    consent_subset,
    profile_digest,
    profile_to_json,
)

if TYPE_CHECKING:
    from finishup.config.models import FinishUpConfig
    from finishup.ports.control import ServiceStatus

__all__ = [
    "COPY_LEVELS",
    "OFFERED_LEVELS",
    "CodeCopyOffer",
    "REVISION_FILE_NAME",
    "REVISION_SCHEMA",
    "ProfileRevisionStore",
    "ProfileUnavailable",
    "ServerProfileSource",
    "offer_digest",
    "review_offer",
]

REVISION_FILE_NAME: Final = "server-profile-revision.json"
REVISION_SCHEMA: Final = "yoetz.server-profile-revision/1"
# L1 is always offered and required; L2 is added only by a code-copy offer while L2 is released.
OFFERED_LEVELS: Final = ProfileLevels(("L1",), "L1")
COPY_LEVELS: Final = ProfileLevels(("L1", "L2"), "L1")
_EDGES: Final = ("ssh-control",)
_OWNER_KEY: Final = ProfileKey(None, "operator", "owner")
_PROVIDER_TOKEN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$", re.ASCII)
_MAX_RECORD_BYTES: Final = 1_024


@dataclass(frozen=True, slots=True)
class CodeCopyOffer:
    """What a server that keeps copies of code offers (level L2; design v2 §2.2, §4.3, U11).

    ``exclusions`` are the patterns the server itself enforces; the client always adds its own
    always-excluded list, and the profile states both (``with_client_list``). ``retention`` holds
    the options its owner allows, the default among them.
    """

    max_repo_bytes: int
    max_file_bytes: int
    retention: tuple[Retention, ...]
    retention_default: Retention
    exclusions: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not 1 <= self.max_file_bytes <= self.max_repo_bytes <= 1 << 40:
            raise ValueError("code_copy_offer_invalid")
        if not self.retention or self.retention_default not in self.retention:
            raise ValueError("code_copy_offer_invalid")

    def code_sync(self) -> CodeSync:
        return CodeSync(frozenset({CODE_SYNC_METHOD}), self.max_repo_bytes, self.max_file_bytes)

    def profile_retention(self) -> ProfileRetention:
        return ProfileRetention(tuple(self.retention), self.retention_default)

    def with_client_list(self) -> frozenset[str]:
        from finishup.domain.code_exclusions import ALWAYS_EXCLUDED

        return frozenset({*self.exclusions, *ALWAYS_EXCLUDED})


class ProfileUnavailable(Exception):
    """This service's configuration cannot be stated exactly in a profile; ``reason`` is closed."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _provider_token(provider_id: str) -> str:
    if not _PROVIDER_TOKEN.match(provider_id):
        # Never server prose, and never "no provider named": a provider the profile cannot name
        # exactly would make two different providers look the same to a consent.
        raise ProfileUnavailable("review_provider_unrepresentable")
    return provider_id


def review_offer(config: FinishUpConfig) -> ReviewEgress:
    """What this service's AI review may send to a model provider, from its own config.

    Names every provider its review may send to: the primary and, with a ``[semantic_fallback]``
    pairing, the fallback. Raises ``ProfileUnavailable`` for a provider it cannot name exactly.
    """

    from finishup.config.models import (
        PROFILE_CAPABILITIES,
        SemanticPolicy,
        fallback_external_endpoint,
        primary_external_endpoint,
    )

    if PROFILE_CAPABILITIES[config.profile].semantic is not SemanticPolicy.OPTIONAL_EXTERNAL:
        return ReviewEgress("none", None)
    primary = primary_external_endpoint(config)
    fallback = fallback_external_endpoint(config)
    return ReviewEgress(
        "server_policy",
        None if primary is None else _provider_token(primary.provider_id),
        None if fallback is None else _provider_token(fallback.provider_id),
    )


def _copy_offered(code_copy: CodeCopyOffer | None) -> CodeCopyOffer | None:
    return code_copy if code_copy is not None and l2_released() else None


def _subset(review: ReviewEgress, code_copy: CodeCopyOffer | None = None) -> dict[str, JsonValue]:
    offered = _copy_offered(code_copy)
    if offered is None:
        return consent_subset(
            levels=OFFERED_LEVELS, code_sync=None, retention=None, exclusions=None, review=review
        )
    return consent_subset(
        levels=COPY_LEVELS,
        code_sync=offered.code_sync(),
        retention=offered.profile_retention(),
        exclusions=offered.with_client_list(),
        review=review,
    )


def offer_digest(config: FinishUpConfig, code_copy: CodeCopyOffer | None = None) -> str:
    """The ``profile_digest`` of what this service offers under ``config`` (and ``code_copy``).

    Raises ``ProfileUnavailable`` when ``config`` cannot be stated exactly.
    """

    return profile_digest(_subset(review_offer(config), code_copy))


class ProfileRevisionStore:
    """The owner-only record of this server's profile revision (see the module text)."""

    __slots__ = ("_path",)

    def __init__(self, path: Path) -> None:
        self._path = path

    def _read(self) -> ServerProfileRevision | None:
        """The recorded revision; ``None`` when there is none or it cannot be read safely."""

        try:
            descriptor = os.open(self._path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            return None
        try:
            facts = os.fstat(descriptor)
            if (
                not stat.S_ISREG(facts.st_mode)
                or facts.st_uid != os.geteuid()
                or stat.S_IMODE(facts.st_mode) & 0o077
                or facts.st_size > _MAX_RECORD_BYTES
            ):
                return None
            encoded = os.read(descriptor, _MAX_RECORD_BYTES + 1)
        except OSError:
            return None
        finally:
            os.close(descriptor)
        try:
            if not encoded.endswith(b"\n"):
                return None
            value = strict_json_parse(encoded[:-1])
            if type(value) is not dict:
                return None
            source = cast(dict[str, JsonValue], value)
            if set(source) != {"schema", "issuer", "revision", "profile_digest"}:
                return None
            if source["schema"] != REVISION_SCHEMA:
                return None
            revision = ServerProfileRevision(
                cast(str, source["issuer"]),
                cast(int, source["revision"]),
                cast(str, source["profile_digest"]),
            )
        except (ValueError, ProfileError):
            return None
        if _encode(revision) != encoded:
            return None
        return revision

    def advance(self, digest: str) -> ServerProfileRevision:
        """The revision for ``digest``: the recorded one when it stands for it, else the next.

        Never raises for the record: one that cannot be read starts again under a new issuer,
        and one that cannot be written keeps the new revision in memory.
        """

        recorded = self._read()
        if recorded is not None and recorded.profile_digest == digest:
            return recorded
        if recorded is None:
            revision = ServerProfileRevision(secrets.token_hex(16), 1, digest)
        else:
            revision = ServerProfileRevision(recorded.issuer, recorded.revision + 1, digest)
        self._write(revision)
        return revision

    def _write(self, revision: ServerProfileRevision) -> bool:
        temporary = self._path.with_name(f".{self._path.name}.{secrets.token_hex(6)}.tmp")
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
            try:
                view = memoryview(_encode(revision))
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("short_write")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, self._path)
        except OSError:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            return False
        return True


def _encode(revision: ServerProfileRevision) -> bytes:
    document: dict[str, JsonValue] = {
        "schema": REVISION_SCHEMA,
        "issuer": revision.issuer,
        "revision": revision.revision,
        "profile_digest": revision.profile_digest,
    }
    return canonical_encode(document) + b"\n"


@dataclass(frozen=True, slots=True)
class ServerProfileSource:
    """What this running service offers, and the revision it issued at start.

    ``review`` and ``revision`` are ``None`` together when the configuration cannot be stated
    exactly (``ProfileUnavailable``): the service then offers no profile, and every hello held to
    a revision is refused (there is none it issues).
    """

    review: ReviewEgress | None
    revision: ServerProfileRevision | None
    code_copy: CodeCopyOffer | None = None

    @classmethod
    def load(
        cls, config: FinishUpConfig, state_dir: Path, code_copy: CodeCopyOffer | None = None
    ) -> ServerProfileSource:
        """Decide the offer from ``config`` (and ``code_copy``, honoured only while L2 is
        released) and issue its revision (once, at service start)."""

        offered = _copy_offered(code_copy)
        try:
            review = review_offer(config)
        except ProfileUnavailable:
            # No revision is issued or recorded for an offer that cannot be stated: the record
            # keeps the last one, and the next offer that can be stated advances past it.
            return cls(None, None, offered)
        digest = profile_digest(_subset(review, offered))
        revision = ProfileRevisionStore(state_dir / REVISION_FILE_NAME).advance(digest)
        return cls(review, revision, offered)

    @property
    def keeps_copies(self) -> bool:
        """Whether this service offers level L2 (a code-copy offer while L2 is released)."""

        return self.revision is not None and _copy_offered(self.code_copy) is not None

    def profile(self, status: ServiceStatus, manifest_digest: str) -> ServerProfile:
        """The profile this service answers a peer-authenticated owner session with.

        Raises ``ProfileUnavailable`` when the service offers none.
        """

        if self.review is None or self.revision is None:
            raise ProfileUnavailable("review_provider_unrepresentable")
        offered = _copy_offered(self.code_copy)
        return ServerProfile(
            release=status.service_version,
            schema_manifest_digest=manifest_digest,
            service_instance_id=status.service_instance_id,
            key=_OWNER_KEY,
            edges=_EDGES,
            levels=OFFERED_LEVELS if offered is None else COPY_LEVELS,
            code_sync=None if offered is None else offered.code_sync(),
            retention=None if offered is None else offered.profile_retention(),
            exclusions=None if offered is None else offered.with_client_list(),
            review=self.review,
            official=False,
            revision=self.revision,
        )

    def document(self, status: ServiceStatus, manifest_digest: str) -> dict[str, JsonValue]:
        """``profile`` as its canonical ``server-profile`` 1.0.0 JSON object."""

        return profile_to_json(self.profile(status, manifest_digest))
