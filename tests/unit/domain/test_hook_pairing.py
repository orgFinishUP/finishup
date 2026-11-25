"""The hook-pairing contract lives in a light domain module and is re-exported unchanged."""

from __future__ import annotations

import subprocess
import sys

from finishup.adapters.integrations import observation_local
from finishup.cli import observe_hooks
from finishup.domain import finishup_tools, hook_pairing
from finishup.ports import integrations

_MOVED = (
    "HookCorrelationKind",
    "HookPairingMode",
    "observation_pairing_contract",
    "_DEFAULT_HOOK_PAIRING",
    "_LEGACY_HOST_PAIRING",
    "_HOOK_PAIRING_BY_PROFILE",
)


def test_ports_integrations_reexports_the_same_objects() -> None:
    for name in _MOVED:
        assert getattr(integrations, name) is getattr(hook_pairing, name), name
    for name in ("HookCorrelationKind", "HookPairingMode", "observation_pairing_contract"):
        assert name in integrations.__all__


def test_hook_ingress_binds_the_same_objects() -> None:
    assert observe_hooks.observation_pairing_contract is integrations.observation_pairing_contract
    assert observe_hooks.FINISHUP_SUPPORT_TOOL_NAMES is integrations.FINISHUP_SUPPORT_TOOL_NAMES
    assert observe_hooks.FINISHUP_WORKFLOW_TOOL_NAMES is integrations.FINISHUP_WORKFLOW_TOOL_NAMES
    assert observe_hooks.FINISHUP_WORKFLOW_TOOL_NAMES is finishup_tools.FINISHUP_WORKFLOW_TOOL_NAMES
    assert (
        observation_local.observation_pairing_contract is integrations.observation_pairing_contract
    )
    assert (
        observation_local.FINISHUP_WORKFLOW_TOOL_NAMES is integrations.FINISHUP_WORKFLOW_TOOL_NAMES
    )


def test_every_reviewed_cell_and_fallback_is_unchanged() -> None:
    contract = hook_pairing.observation_pairing_contract
    assert contract("claude", "claude-code-cli-local-project-2.1.241") == (
        "post_only",
        "tool_call_id",
    )
    assert contract("cursor", "cursor-ide-3.17.8") == ("post_only", "generation_id")
    assert contract("claude", None) == ("post_only", "tool_call_id")
    assert contract("cursor", None) == ("post_only", "generation_id")
    assert contract("codex", None) == ("paired", "tool_call_id")
    assert contract("claude", "untested") == ("paired", "tool_call_id")
    assert contract(1, None) == ("paired", "tool_call_id")  # type: ignore[arg-type]
    assert contract("claude", 1) == ("post_only", "tool_call_id")  # type: ignore[arg-type]


def test_observe_hooks_do_not_import_the_integrations_port() -> None:
    code = (
        "import sys\n"
        "import finishup.cli.observe_hooks\n"
        "import finishup.adapters.integrations.observation_local\n"
        "print('finishup.ports.integrations' in sys.modules)\n"
    )
    source = (
        "import sys\n"
        "import finishup.domain.hook_pairing\n"
        "print(sorted(m for m in sys.modules if m.startswith('finishup')))\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
    )
    assert completed.stdout == "False\n"
    light = subprocess.run(
        [sys.executable, "-c", source], capture_output=True, text=True, check=True
    )
    assert light.stdout == "['finishup', 'finishup.domain', 'finishup.domain.hook_pairing']\n"
