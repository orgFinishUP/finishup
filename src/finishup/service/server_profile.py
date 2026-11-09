"""This server's own profile and the revision it issues (ADR-052, design v2 §2.2, §8.2).

A FinishUP service states what it offers a client elsewhere in a ``server-profile`` 1.0.0
document (``protocol.server_profile``), answered by the ``server_profile`` control operation and
by ``finishup service profile --json`` (the SSH discovery of layer 4). The server offers; the
client decides (design v2 §1).

**Where the offer comes from** (layer 3's decision D2):

* ``levels``: pinned by this release, not configurable: L1 is offered and required (a server
  elsewhere always keeps the tasks); L2, the server keeping a copy of the code, is never offered
  before the layer that builds it, so ``code_sync``, ``retention`` and ``exclusions`` are null.
* ``review``: derived from this service's own ``config.toml``, from the same settings that decide
  whether it can reach an AI provider at all, so the profile never understates it: a profile whose
  semantic capability is an external provider states ``server_policy`` (its owner's privacy policy
  decides what is sent) and names that provider by a closed token; any other states ``none``.
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
from finishup.protocol.consent_envelope import ReviewEgress
from finishup.protocol.server_profile import (
    ProfileError,
    ProfileKey,
    ProfileLevels,
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
    "OFFERED_LEVELS",
    "REVISION_FILE_NAME",
    "REVISION_SCHEMA",
    "ProfileRevisionStore",
    "ServerProfileSource",
    "offer_digest",
    "review_offer",
]

REVISION_FILE_NAME: Final = "server-profile-revision.json"
REVISION_SCHEMA: Final = "yoetz.server-profile-revision/1"
# Layer 3 offers L1 only and requires it; L2 arrives with the layer that builds the server copy.
OFFERED_LEVELS: Final = ProfileLevels(("L1",), "L1")
_EDGES: Final = ("ssh-control",)
_OWNER_KEY: Final = ProfileKey(None, "operator", "owner")
_PROVIDER_TOKEN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$", re.ASCII)
_MAX_RECORD_BYTES: Final = 1_024


def review_offer(config: FinishUpConfig) -> ReviewEgress:
    """What this service's AI review may send to a model provider, from its own config."""

    from finishup.config.models import (
        CODEX_SUBSCRIPTION_PROVIDER_ID,
        PROFILE_CAPABILITIES,
        SemanticPolicy,
    )

    if PROFILE_CAPABILITIES[config.profile].semantic is not SemanticPolicy.OPTIONAL_EXTERNAL:
        return ReviewEgress("none", None)
    provider: str | None = None
    if config.provider is not None:
        provider = config.provider.provider_id
    elif config.external_runtime is not None:
        provider = CODEX_SUBSCRIPTION_PROVIDER_ID
    if provider is not None and not _PROVIDER_TOKEN.match(provider):
        # Never server prose: a provider this release cannot name as a token is named by none.
        provider = None
    return ReviewEgress("server_policy", provider)


def _subset(review: ReviewEgress) -> dict[str, JsonValue]:
    return consent_subset(
        levels=OFFERED_LEVELS, code_sync=None, retention=None, exclusions=None, review=review
    )


def offer_digest(config: FinishUpConfig) -> str:
    """The ``profile_digest`` of what this service offers under ``config``."""

    return profile_digest(_subset(review_offer(config)))


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
    """What this running service offers, and the revision it issued at start."""

    review: ReviewEgress
    revision: ServerProfileRevision

    @classmethod
    def load(cls, config: FinishUpConfig, state_dir: Path) -> ServerProfileSource:
        """Decide the offer from ``config`` and issue its revision (once, at service start)."""

        review = review_offer(config)
        digest = profile_digest(_subset(review))
        revision = ProfileRevisionStore(state_dir / REVISION_FILE_NAME).advance(digest)
        return cls(review, revision)

    def profile(self, status: ServiceStatus, manifest_digest: str) -> ServerProfile:
        """The profile this service answers a peer-authenticated owner session with."""

        return ServerProfile(
            release=status.service_version,
            schema_manifest_digest=manifest_digest,
            service_instance_id=status.service_instance_id,
            key=_OWNER_KEY,
            edges=_EDGES,
            levels=OFFERED_LEVELS,
            code_sync=None,
            retention=None,
            exclusions=None,
            review=self.review,
            official=False,
            revision=self.revision,
        )

    def document(self, status: ServiceStatus, manifest_digest: str) -> dict[str, JsonValue]:
        """``profile`` as its canonical ``server-profile`` 1.0.0 JSON object."""

        return profile_to_json(self.profile(status, manifest_digest))
