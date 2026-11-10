"""What never enters a server copy by its name (level L2; design v2 §4.2, U10; ADR-054).

``ALWAYS_EXCLUDED`` is the reviewed list of names and paths that are always left out of a
repository's server copy, whatever a server or an owner says: the ADR-031 credential names every
repository excerpt already withholds (``domain.repository_excerpt``) plus further key, keystore and
cloud credential conventions. A server's ``exclusions.always`` and the owner's per-repository list
add to it; nothing removes from it. The server states it in its profile's ``exclusions`` and the
client applies it, so both sides name the same list.

``excluded_by`` matches every pattern case-insensitively: a pattern without ``/`` matches the last
path component, a pattern ending in ``/`` matches a directory anywhere on the path, and a pattern
with an inner ``/`` matches the whole path from the repository's root (``*`` crosses ``/``). Names
are a heuristic, not a secret guarantee.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable
from typing import Final

from finishup.domain.repository_excerpt import credential_name_patterns

__all__ = ["ALWAYS_EXCLUDED", "excluded_by", "valid_pattern"]

_FURTHER_NAMES: Final = (
    ".aws/credentials",
    ".docker/config.json",
    ".dockercfg",
    "*.asc",
    "*.gpg",
    "*.kubeconfig",
    "*.ovpn",
    "*.p8",
    "*.ppk",
    "*.secret",
    "*.secrets",
    "id_*",
    "kubeconfig",
    "secrets.*",
)
ALWAYS_EXCLUDED: Final[tuple[str, ...]] = tuple(
    sorted({*credential_name_patterns(), *_FURTHER_NAMES})
)

_PATTERN: Final = re.compile(r"^[^\x00-\x1f]{1,512}$")


def valid_pattern(pattern: str) -> bool:
    """Whether ``pattern`` may be recorded as an exclusion: 1 to 512 characters, no control
    characters, and not only slashes or stars."""

    return (
        type(pattern) is str
        and bool(_PATTERN.match(pattern))
        and pattern.strip("/*") != ""
        and pattern != "/"
    )


def _matches(pattern: str, path: str) -> bool:
    pattern = pattern.lower()
    path = path.lower()
    if pattern.endswith("/"):
        directory = pattern.rstrip("/")
        components = path.split("/")[:-1]
        if "/" in directory:
            return any(
                fnmatch.fnmatchcase("/".join(components[: index + 1]), directory.lstrip("/"))
                for index in range(len(components))
            )
        return any(fnmatch.fnmatchcase(component, directory) for component in components)
    if "/" in pattern.strip("/"):
        return fnmatch.fnmatchcase(path, pattern.lstrip("/"))
    return fnmatch.fnmatchcase(path.rsplit("/", 1)[-1], pattern.strip("/"))


def excluded_by(path: str, patterns: Iterable[str]) -> str | None:
    """The first of ``patterns`` (in sorted order) that excludes repository path ``path``."""

    for pattern in sorted(set(patterns)):
        if _matches(pattern, path):
            return pattern
    return None
