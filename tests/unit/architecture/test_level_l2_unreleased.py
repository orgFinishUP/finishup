"""Level L2 (the server keeps a copy of the code) stays unavailable in this release.

Design v2 §8.3: L2 stays unavailable until sync consent, the round-5 hold, encrypted storage,
forget, provenance and receipts all exist, and the reads of the copy with them. Layer 6 builds
them bottom-up behind one switch, ``protocol.server_copy.L2_RELEASED``; the commit that sets it
must be the layer's last code commit and must change this test with the protections it names.
"""

from __future__ import annotations


def test_level_l2_is_not_released() -> None:
    from finishup.protocol.server_copy import L2_RELEASED

    assert L2_RELEASED is False
