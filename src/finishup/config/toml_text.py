"""The one way FinishUP parses TOML text: every invalid document raises ``TOMLDecodeError``.

``tomllib.loads`` reports most invalid documents as ``tomllib.TOMLDecodeError``, but not all of
them: an integer longer than the interpreter's integer string conversion limit raises a plain
``ValueError``, and deeply nested inline arrays or tables raise ``RecursionError``. Both fit in a
few kilobytes, below every byte cap FinishUP applies, and both can sit in a file a cloned
repository controls (``<project>/.codex/config.toml``). Readers catch ``TOMLDecodeError`` to give
their closed invalid-TOML outcome, so this function raises exactly that for every document
``tomllib`` cannot load, without carrying the interpreter's message.
"""

from __future__ import annotations

import tomllib
from typing import Any

__all__ = ["TomlNotLoadable", "load_toml_text"]


class TomlNotLoadable(tomllib.TOMLDecodeError):
    """A TOML document ``tomllib`` could not load for a reason it does not report as a decode error.

    It has no position: ``lineno`` and ``colno`` are absent, as they are before Python 3.14.
    """

    def __init__(self) -> None:
        # ``TOMLDecodeError.__init__`` on 3.14 wants a document and a position this error does
        # not have; the plain ``ValueError`` initializer keeps one fixed message on every version.
        ValueError.__init__(self, "TOML document cannot be loaded")


def load_toml_text(text: str) -> dict[str, Any]:
    """``tomllib.loads(text)``, raising ``tomllib.TOMLDecodeError`` for every unloadable document."""

    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        raise
    except (ValueError, RecursionError):
        raise TomlNotLoadable() from None
