"""The REST gateway: the default edge of a FinishUP server (ADR-053, design v2 U13, section 8.4).

A separate process of the service's own user, run by ``finishup service rest run`` (the default
``--edge gateway``) on the server host. It serves the REST v1 routes (``finishup.rest.app``) and
re-enters the service over its owner-only control socket as ordinary control connections
(``gateway.backend.ControlSocketBackend``). It holds no vault, no installation MAC and no storage
or policy authority: it may import SHARED modules and ``finishup.service.client`` only (the cut
line in ``tests/unit/architecture``). Importing this package is inert.
"""

from __future__ import annotations

__all__: tuple[str, ...] = ()
