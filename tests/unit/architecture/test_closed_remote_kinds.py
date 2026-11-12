"""Every remote kind is open in this release, each with its protections (ADR-052, ADR-053).

Shared authorization (generations, the gate, the repository hold, consent envelopes), the profile
consent and the helper landed before any new remote path (design v2 sections 8.3 and 9). Layer 4
opened ``ssh``, through the target's helper or directly; layer 5 opens ``https`` and
``local_port`` over REST v1 once the REST client, its mapping, the revision on every request and
the key's credential generation exist.
"""

from __future__ import annotations


def test_ssh_https_and_local_port_are_open_in_this_release() -> None:
    from finishup.client.authorization import OPEN_REMOTE_KINDS

    assert OPEN_REMOTE_KINDS == frozenset({"ssh", "https", "local_port"})


def test_every_open_kind_has_its_transport_its_profile_source_and_its_runtime() -> None:
    """A kind may be open only with a transport, a profile source and a runtime of its own."""

    from finishup.client import target_runtime
    from finishup.client.authorization import OPEN_REMOTE_KINDS
    from finishup.client.server_profile import PROFILE_SOURCES
    from finishup.service import client as service_client

    for kind in OPEN_REMOTE_KINDS:
        assert kind in PROFILE_SOURCES
        assert kind in target_runtime._RUNTIME_LOADERS  # pyright: ignore[reportPrivateUsage]
    # HTTPS and port servers are reached over REST v1 (the helper's upstream or a direct stream).
    rest_kinds = service_client._REST_KINDS  # pyright: ignore[reportPrivateUsage]
    assert rest_kinds == frozenset({"https", "local_port"})
