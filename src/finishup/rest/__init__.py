"""The REST v1 edge of a FinishUP server (design v2 U9, sections 1.1 and 8.4; ADR-053).

One public network protocol, served by either edge a server owner picks: the separate gateway
process (``finishup.gateway``, the default) or the native listener inside the service
(``finishup.service.rest_native``). ``rest.contract`` is the wire contract both sides share (pure,
standard library and ``finishup.protocol``); ``rest.api_keys`` the server's key store;
``rest.backend`` the interface the routes call; ``rest.app`` the routes; ``rest.listener`` the TLS
listeners. A client imports ``rest.contract`` only (``client.rest_client``). Importing this package
is inert.
"""

from __future__ import annotations

__all__: tuple[str, ...] = ()
