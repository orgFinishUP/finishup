"""Only SSH is open in this release (ADR-052; design v2 sections 8.3 and 9).

Shared authorization (generations, the gate, the repository hold, consent envelopes), the profile
consent and the helper landed before any new remote path. Layer 4 opens ``ssh``, through the
target's helper or directly, once those protections exist; layer 5 opens ``https`` and
``local_port`` with the REST client. Until then every connection to those stops at the gate's kind
step; a test that exercises one opens it in process only (``builders.server_targets.open_remote_kinds``).
"""

from __future__ import annotations


def test_only_ssh_is_open_in_this_release() -> None:
    from finishup.client.authorization import OPEN_REMOTE_KINDS

    assert OPEN_REMOTE_KINDS == frozenset({"ssh"})


def test_ssh_has_its_transport_its_profile_source_and_its_runtime() -> None:
    """A kind may be open only with a transport, a profile source and a runtime of its own."""

    from finishup.client import target_runtime
    from finishup.client.authorization import OPEN_REMOTE_KINDS
    from finishup.client.server_profile import PROFILE_SOURCES

    for kind in OPEN_REMOTE_KINDS:
        assert kind in PROFILE_SOURCES
        assert kind in target_runtime._RUNTIME_LOADERS  # pyright: ignore[reportPrivateUsage]
    assert {"https", "local_port"}.isdisjoint(PROFILE_SOURCES)
