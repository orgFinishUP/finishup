"""Every hook process imports ``finishup.cli.hooks``; it must not drag in pydantic.

Observation lanes reach this module for child identity and start-mapping recovery, so the
protocol models, the control port and the service client load only inside the mapped-session
status read. The hook-local recovery suffix stays byte-identical to the renderer's. Whole hook
runs are guarded in ``tests/subprocess/test_hook_import_light.py``.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from finishup.cli import hooks as hooks_module
from finishup.cli.render import render_hook_recovery_suffix
from finishup.protocol import recovery

_HEAVY = ("pydantic", "finishup.protocol.models", "finishup.service.client", "finishup.cli.render")

_IMPORT_PROBE = r"""
import json, sys
import finishup.cli.hooks
heavy = json.loads(sys.argv[1])
print(json.dumps(sorted(name for name in heavy if name in sys.modules)))
"""


def _reasons() -> list[str]:
    local = recovery._LOCAL_REASON_CONTINUATIONS  # pyright: ignore[reportPrivateUsage]
    return sorted(
        {
            *recovery.covered_reason_codes(),
            *local,
            "vault_locked",
            "not_a_registered_reason",
        }
    )


@pytest.mark.parametrize("reason", _reasons())
def test_hook_recovery_suffix_matches_the_renderer(reason: str) -> None:
    helper = hooks_module._hook_recovery_suffix  # pyright: ignore[reportPrivateUsage]
    assert helper(reason) == render_hook_recovery_suffix(reason)


def test_locked_context_text_is_unchanged() -> None:
    assert hooks_module._LOCKED_CONTEXT == (  # pyright: ignore[reportPrivateUsage]
        "FinishUP vault is locked for this mapped session; no live receipt can be promised."
        + render_hook_recovery_suffix("vault_locked")
    )


def test_connect_service_resolves_lazily_to_the_service_client() -> None:
    from finishup.service.client import connect_service

    assert hooks_module.connect_service is connect_service  # pyright: ignore[reportAttributeAccessIssue]
    with pytest.raises(AttributeError, match="has no attribute 'not_a_hooks_attribute'"):
        _ = hooks_module.not_a_hooks_attribute  # pyright: ignore[reportAttributeAccessIssue]


def test_importing_the_hooks_module_loads_no_protocol_models() -> None:
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and probe source
        [sys.executable, "-c", _IMPORT_PROBE, json.dumps(_HEAVY)],
        capture_output=True,
        check=True,
    )
    assert json.loads(completed.stdout) == []
