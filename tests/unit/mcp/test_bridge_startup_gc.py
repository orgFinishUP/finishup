"""The MCP bridge starts with cyclic collection off and serves with it on over a frozen heap."""

from __future__ import annotations

import gc
import sys
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any

import pytest

from finishup.cli import entry
from finishup.mcp import server


@pytest.fixture(autouse=True)
def restore_gc() -> Iterator[None]:
    was_enabled = gc.isenabled()
    try:
        yield
    finally:
        if was_enabled:
            gc.enable()
        else:  # pragma: no cover - pytest runs with collection on
            gc.disable()


def _run_entry(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> list[bool]:
    from finishup.adapters import release_runtime

    def enter(_arguments: list[str]) -> None:
        return None

    monkeypatch.setattr(release_runtime, "enter_release_runtime", enter)
    monkeypatch.setattr(entry.os, "name", "posix")
    monkeypatch.setattr(sys, "argv", ["finishup", *argv])
    seen: list[bool] = []
    monkeypatch.setattr(entry, "_run_full_cli", lambda: seen.append(gc.isenabled()))
    entry.main()
    return seen


def test_mcp_serve_loads_the_cli_with_cyclic_collection_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _run_entry(monkeypatch, ["mcp", "serve", "--host", "claude"]) == [False]


@pytest.mark.parametrize(
    "argv",
    [
        ["mcp", "serve", "--help"],
        ["mcp", "serve", "-h"],
        ["mcp", "status"],
        ["service", "run"],
        ["privacy", "show"],
    ],
    ids=["help", "short-help", "other-mcp", "service", "other"],
)
def test_other_commands_keep_cyclic_collection_on(
    argv: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _run_entry(monkeypatch, argv) == [True]


def _patch_bridge_startup(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    events: list[str] = []
    real_freeze: Callable[[], None] = gc.freeze

    def freeze() -> None:
        events.append(f"freeze:enabled={gc.isenabled()}")
        real_freeze()

    def run(_func: Callable[..., Any], *_args: object) -> None:
        events.append(f"serve:enabled={gc.isenabled()}")

    def ignore(*_args: object, **_kwargs: object) -> None:
        return None

    def runtime(*_args: object, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(route_profile="policy", host_profile="claude")

    monkeypatch.setattr(server, "configure_logging", ignore)
    monkeypatch.setattr(server, "build_bridge_runtime", runtime)
    monkeypatch.setattr(server, "record_startup_route_drift", ignore)
    monkeypatch.setattr(server.gc, "freeze", freeze)
    monkeypatch.setattr(server.anyio, "run", run)
    return events


def test_bridge_freezes_the_startup_heap_once_and_serves_with_collection_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _patch_bridge_startup(monkeypatch)
    gc.disable()
    try:
        server.main(host="claude")
    finally:
        gc.unfreeze()
    assert events == ["freeze:enabled=False", "serve:enabled=True"]


def test_in_process_bridge_with_collection_on_does_not_freeze(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _patch_bridge_startup(monkeypatch)
    server.main(host="claude")
    assert events == ["serve:enabled=True"]
