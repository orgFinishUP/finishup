"""The reviewed hook-pairing contract for each host/profile cell.

Kept apart from ``finishup.ports.integrations`` (which re-exports these same objects) so hook
ingress can apply the contract without importing the integrations port.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final, Literal

__all__ = ["HookCorrelationKind", "HookPairingMode", "observation_pairing_contract"]

HookPairingMode = Literal["paired", "post_only"]
HookCorrelationKind = Literal["tool_call_id", "generation_id", "none"]

# Pairing is a host/profile fact, rather than a property of the shared hook
# transport. Keep the exact reviewed profile cells here so hook ingress can
# apply the contract without importing a renderer (and its filesystem/process
# dependencies). An omitted profile is the compatibility path for an already
# installed legacy Claude/Cursor carrier. A nonempty unknown profile is a
# future claim, so it stays paired until that exact cell is reviewed.
_DEFAULT_HOOK_PAIRING: Final[tuple[HookPairingMode, HookCorrelationKind]] = (
    "paired",
    "tool_call_id",
)
_LEGACY_HOST_PAIRING: Final[Mapping[str, tuple[HookPairingMode, HookCorrelationKind]]] = (
    MappingProxyType(
        {
            "claude": ("post_only", "tool_call_id"),
            "cursor": ("post_only", "generation_id"),
        }
    )
)
_HOOK_PAIRING_BY_PROFILE: Final[
    Mapping[tuple[str, str], tuple[HookPairingMode, HookCorrelationKind]]
] = MappingProxyType(
    {
        (
            "claude",
            "claude-code-cli-local-project-2.1.241",
        ): ("post_only", "tool_call_id"),
        ("cursor", "cursor-ide-3.17.8"): ("post_only", "generation_id"),
    }
)


def observation_pairing_contract(
    harness_id: str, capability_profile_id: str | None
) -> tuple[HookPairingMode, HookCorrelationKind]:
    """Return the reviewed pairing contract for one host/profile cell.

    The mapping is intentionally exact. A missing Claude/Cursor profile uses
    the installed legacy post-only contract without claiming a supported
    host/version cell. A nonempty unknown profile stays on the conservative
    paired contract until its exact hook shape is reviewed.
    """

    if type(harness_id) is not str:
        return _DEFAULT_HOOK_PAIRING
    if type(capability_profile_id) is str:
        exact = _HOOK_PAIRING_BY_PROFILE.get((harness_id, capability_profile_id))
        if exact is not None:
            return exact
        return _DEFAULT_HOOK_PAIRING
    return _LEGACY_HOST_PAIRING.get(harness_id, _DEFAULT_HOOK_PAIRING)
