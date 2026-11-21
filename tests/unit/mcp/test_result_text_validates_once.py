"""The MCP result text checks its wire against the canonical profile once, not once per section."""

from __future__ import annotations

import contextlib
from collections.abc import Generator, Mapping, Sequence

import pytest

from finishup.mcp import server, summaries
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.models import PUBLISH_BLOCKER_NOTICE_TEXTS

_result_text = server._result_text  # pyright: ignore[reportPrivateUsage]

_HEAD = "sha256:" + "1" * 64
_TASK = "tsk_00000000-0000-4000-8000-000000000001"
_SESSION = "ses_00000000-0000-4000-8000-000000000002"
_WRITER = "wri_00000000-0000-4000-8000-000000000003"
_OBLIGATION = "obl_98500000-0000-4000-8000-000000000001"

_CANONICAL: dict[str, dict[str, object]] = {
    "start": {
        "ok": True,
        "outcome": "created",
        "task_id": _TASK,
        "session_id": _SESSION,
        "writer_id": _WRITER,
        "frontier": {"sequence": "1", "head_digest": _HEAD},
    },
    "publish": {
        "ok": True,
        "outcome": "recorded",
        "accepted_events": [{"event_id": "evt_x"}],
        "result_frontier": {"sequence": "4", "head_digest": _HEAD},
    },
    "publish_blocker": {
        "ok": True,
        "outcome": "dry_run",
        "evidential": False,
        "blocker_notices": [
            {
                "obligation_id": _OBLIGATION,
                "blocker_kind": "dependency_unavailable",
                "notice": "blocker_claimed",
                "text": PUBLISH_BLOCKER_NOTICE_TEXTS["blocker_claimed"],
            }
        ],
    },
    "error": {
        "ok": False,
        "error": {
            "code": "invalid_request",
            "safe_details": {"reason_code": "field_missing", "field": "task_id"},
        },
    },
    "awaiting": {
        "ok": True,
        "outcome": "recorded",
        "state": "awaiting_input",
        "continuation": {"kind": "unknown"},
    },
    "preparatory": {"ok": True, "outcome": "recorded", "preparatory_only": True},
}

# Bodies outside the canonical profile: every section must fail exactly as it did before.
_NON_CANONICAL: dict[str, dict[str, object]] = {
    "float": {"ok": True, "outcome": "created", "ratio": 1.5},
    "nested_float": {"ok": True, "outcome": "recorded", "totals": {"open": 0.5}},
    "non_string_key": {"ok": True, "outcome": "recorded", "detail": {1: "x"}},
}

_HOSTS: tuple[server.McpHostProfile, ...] = ("generic", "codex", "claude", "cursor")


def _render(
    wire: Mapping[str, object], host: server.McpHostProfile, monkeypatch: pytest.MonkeyPatch
) -> tuple[str, list[tuple[str, str, str]]]:
    recorded: list[tuple[str, str, str]] = []

    def record(
        failures: Sequence[tuple[str, BaseException]],
        *,
        request_id: str | None,
        operation: str | None,
    ) -> str:
        del request_id, operation
        recorded.extend((site, type(exc).__name__, str(exc)) for site, exc in failures)
        return "Text summary degraded."

    with monkeypatch.context() as patch:
        patch.setattr(server, "_record_summary_degradation", record)
        text = _result_text(wire, host_profile=host)
    return text, recorded


@contextlib.contextmanager
def _per_section_checks(_wire: Mapping[str, object]) -> Generator[None]:
    """The previous behavior: no prevalidation, every section checks the body itself."""

    yield


@pytest.mark.parametrize("host", _HOSTS)
@pytest.mark.parametrize("name", [*_CANONICAL, *_NON_CANONICAL])
def test_text_and_recorded_failures_match_per_section_checking(
    name: str, host: server.McpHostProfile, monkeypatch: pytest.MonkeyPatch
) -> None:
    wire = {**_CANONICAL, **_NON_CANONICAL}[name]
    fast = _render(wire, host, monkeypatch)
    monkeypatch.setattr(server, "prevalidated_wire", _per_section_checks)
    slow = _render(wire, host, monkeypatch)
    assert fast == slow
    if name in _NON_CANONICAL and host != "cursor":
        assert fast[1], "a non-canonical body still degrades every section that reads it"


def _count_wire_checks(
    wire: Mapping[str, object], monkeypatch: pytest.MonkeyPatch
) -> tuple[int, int]:
    """Canonical-profile checks of exactly ``wire`` with and without prevalidation."""

    calls = 0
    real = summaries.ensure_canonical_value

    def counted(value: object, *, depth: int = 0) -> None:
        nonlocal calls
        if value is wire:
            calls += 1
        real(value, depth=depth)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(summaries, "ensure_canonical_value", counted)
    _render(wire, "codex", monkeypatch)
    once = calls
    calls = 0
    monkeypatch.setattr(server, "prevalidated_wire", _per_section_checks)
    _render(wire, "codex", monkeypatch)
    return once, calls


@pytest.mark.parametrize("name", ["start", "publish", "publish_blocker", "error", "awaiting"])
def test_a_canonical_body_is_checked_once(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    once, per_section = _count_wire_checks(_CANONICAL[name], monkeypatch)
    assert once == 1
    assert per_section >= 5


def test_a_non_canonical_body_is_still_checked_by_every_section(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    once, per_section = _count_wire_checks(_NON_CANONICAL["float"], monkeypatch)
    assert once == per_section + 1


def test_only_the_prevalidated_object_skips_its_check() -> None:
    wire = _CANONICAL["start"]
    with summaries.prevalidated_wire(wire):
        assert summaries._mapping(wire) is wire  # pyright: ignore[reportPrivateUsage]
        with pytest.raises(ProtocolValueError):
            summaries._mapping({"ratio": 1.5})  # pyright: ignore[reportPrivateUsage]
        with pytest.raises(ProtocolValueError):
            summaries._mapping(dict(_NON_CANONICAL["float"]))  # pyright: ignore[reportPrivateUsage]
    assert summaries._PREVALIDATED_WIRE.get() is None  # pyright: ignore[reportPrivateUsage]


def test_the_mark_is_cleared_when_a_section_raises() -> None:
    wire = _CANONICAL["start"]
    with pytest.raises(RuntimeError), summaries.prevalidated_wire(wire):
        raise RuntimeError("section")
    assert summaries._PREVALIDATED_WIRE.get() is None  # pyright: ignore[reportPrivateUsage]


def test_rendering_never_mutates_the_body() -> None:
    import copy

    for wire in _CANONICAL.values():
        before = copy.deepcopy(wire)
        for host in _HOSTS:
            _result_text(wire, host_profile=host)
        assert wire == before
