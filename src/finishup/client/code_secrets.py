"""What never enters a server copy by its name, and the content scan for known secret formats.

Level L2 (design v2 §4.2, §8.1, U10, U19). Before a file enters the export of a repository's
server copy, two checks run on this computer:

* **Names.** ``ALWAYS_EXCLUDED`` is the reviewed list of names and paths that are always left
  out, whatever a server or an owner says: the ADR-031 credential names every repository excerpt
  already withholds (``domain.repository_excerpt``) plus further key, keystore and cloud
  credential conventions. A server's ``exclusions.always`` and the owner's per-repository list
  add to it; nothing removes from it. ``excluded_by`` matches every pattern case-insensitively:
  a pattern without ``/`` matches the last path component, a pattern ending in ``/`` matches a
  directory anywhere on the path, and a pattern with an inner ``/`` matches the whole path from
  the repository's root (``*`` crosses ``/``).
* **Content.** ``holds_known_secret`` scans the bytes with the diagnostic privacy scanner's
  high-confidence findings (private key blocks, the token formats it knows, passwords in URLs)
  and an L2-only list of further known formats. A hit holds the file out; its path (never its
  content) is named so the owner can allow that exact content
  (``finishup server code allow``). Heuristic matches (``password = …`` assignments) never hold a
  file: they would hold most configuration files.

Both are heuristics, not a secret guarantee: a secret in a format no pattern knows, or under a name
no pattern lists, is sent. The docs say so.
"""

from __future__ import annotations

import re
from typing import Final

from finishup.domain.code_exclusions import ALWAYS_EXCLUDED, excluded_by, valid_pattern

__all__ = [
    "ALWAYS_EXCLUDED",
    "SCANNER_VERSION",
    "excluded_by",
    "holds_known_secret",
    "valid_pattern",
]

# Bumped whenever the content scan changes, so a cached verdict of an older scan is not reused.
SCANNER_VERSION: Final = "1"


# Known secret formats the diagnostic scanner does not list; each is specific enough that a match
# in source code is almost always a real credential.
_FURTHER_FORMATS: Final = (
    re.compile(rb"(?<![A-Za-z0-9])(?:sk|rk)_live_[A-Za-z0-9]{16,256}"),
    re.compile(rb"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"),
    re.compile(rb"(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{20,256}"),
    re.compile(rb"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])"),
    re.compile(rb"(?<![A-Za-z0-9])pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,512}"),
    re.compile(rb"(?<![A-Za-z0-9])xapp-[0-9]-[A-Za-z0-9-]{20,256}"),
    re.compile(rb"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"),
    re.compile(rb"AccountKey=[A-Za-z0-9+/]{40,128}={0,2}"),
    re.compile(rb"(?<![A-Z0-9])ASIA[A-Z0-9]{16}(?![A-Z0-9])"),
)


def holds_known_secret(data: bytes) -> bool:
    """Whether ``data`` holds a secret in a known format (see the module text)."""

    from finishup.observability.privacy import ScanConfidence, scan_for_sensitive_content

    for pattern in _FURTHER_FORMATS:
        if pattern.search(data) is not None:
            return True
    return any(
        finding.confidence is ScanConfidence.HIGH for finding in scan_for_sensitive_content(data)
    )
