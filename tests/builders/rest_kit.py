"""What the REST server conformance kit runs against (``tests/conformance/rest``, ADR-053)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from builders.tls_material import TlsMaterial

__all__ = ["ProvisionedServer", "RestTarget"]


@dataclass(frozen=True, slots=True)
class RestTarget:
    """One server under test: where it is, how to trust it, and its keys."""

    name: str
    url: str
    operator_key: str
    agent_key: str | None
    ca_file: str | None
    tls_pin: str | None


@dataclass
class ProvisionedServer:
    """This checkout's own server root, provisioned for the kit."""

    base: Path
    root: Path
    operator_key: str
    agent_key: str
    tls: TlsMaterial
    passphrase: str = field(repr=False, default="")
