"""The deliberately small, side-effect-free FinishUP package boundary."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Wave F owns this module; retain the required type-only edge without materializing it early.
    from finishup.version import (  # pyright: ignore[reportMissingImports]
        VersionManifest,  # pyright: ignore[reportMissingImports, reportUnknownVariableType]
    )

    # Resolved lazily by ``__getattr__`` below; declared here for static checkers only.
    __version__: str

__all__ = ("__version__", "get_version_manifest")


def __getattr__(name: str) -> str:
    """Resolve ``__version__`` on first use so importing the package stays metadata-free.

    ``importlib.metadata`` costs more than the rest of the package import; hook processes that never
    read the version must not pay it. The value is cached in module globals, so later reads are plain
    attribute lookups and ``from finishup import __version__`` sees the same string as before.

    The installed metadata is therefore read at first use, not at package import. Long-lived
    processes (CLI app, service daemon, MCP server, TUI) import modules that read it while loading,
    so they still pin it at startup; a short-lived hook that first reads it later sees the
    distribution as installed at that moment.
    """

    if name != "__version__":
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib.metadata import PackageNotFoundError, version

    # Always the ``finishup`` distribution: a transitional ``yoetz`` distribution installed beside
    # it (ADR-048) carries its own metadata and must never stand in for this package's version.
    try:
        value = version("finishup")
    except PackageNotFoundError:
        value = "0.0.0+uninstalled"
    globals()["__version__"] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), "__version__"})


def get_version_manifest() -> VersionManifest:  # pyright: ignore[reportUnknownParameterType]
    """Build the installed runtime manifest without widening ordinary package import."""

    # The runtime import is intentionally lazy and becomes statically resolvable in Wave F.
    from finishup.version import (  # pyright: ignore[reportMissingImports]
        build_version_manifest,  # pyright: ignore[reportMissingImports, reportUnknownVariableType]
    )

    return build_version_manifest()  # pyright: ignore[reportUnknownVariableType]
