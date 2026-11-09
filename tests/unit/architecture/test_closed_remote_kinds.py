"""No remote kind is open in this release (ADR-052; design v2 section 8.3).

Shared authorization (generations, the gate, the repository hold, consent envelopes) lands before
any new remote path. Layer 4 is the first that may open ``ssh``, layer 5 ``https`` and
``local_port``; until then every connection to a server elsewhere stops at the gate's kind step.
A test that exercises an admitted connection opens a kind in process only
(``builders.server_targets.open_remote_kinds``).
"""

from __future__ import annotations


def test_no_remote_kind_is_open_in_this_release() -> None:
    from finishup.client.authorization import OPEN_REMOTE_KINDS

    assert OPEN_REMOTE_KINDS == frozenset()
