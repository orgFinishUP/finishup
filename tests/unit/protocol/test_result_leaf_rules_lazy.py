"""The result-leaf registry is built on first use, once, with the same rules in the same order.

Every full-CLI command imports ``finishup.protocol.models`` but never classifies a result leaf, so
building the two thousand rules at import was wasted work. The guard is a count: importing the
module builds nothing, and concurrent first use builds exactly once.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from typing import Any

import pytest

from finishup.protocol import models

_PROBE = r"""
import json
import finishup.protocol.models as models
before = models._result_leaf_rules_built is None
rules = models._result_leaf_rules()
print(json.dumps([before, len(rules), rules is models._result_leaf_rules()]))
"""


def test_importing_the_models_builds_no_rule_until_first_use() -> None:
    result = subprocess.run(
        [sys.executable, "-c", _PROBE], capture_output=True, text=True, check=True
    )
    assert json.loads(result.stdout) == [True, 2122, True]


def test_the_lazy_registry_matches_a_fresh_build_rule_for_rule() -> None:
    lazy: tuple[Any, ...] = getattr(models, "_result_leaf_rules")()
    fresh: tuple[Any, ...] = getattr(models, "_build_result_leaf_rules")()
    assert lazy == fresh
    assert [repr(rule) for rule in lazy] == [repr(rule) for rule in fresh]


def test_concurrent_first_use_builds_once_and_shares_one_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_build = getattr(models, "_build_result_leaf_rules")
    builds: list[int] = []

    def counting_build() -> tuple[Any, ...]:
        builds.append(1)
        return real_build()

    monkeypatch.setattr(models, "_result_leaf_rules_built", None)
    monkeypatch.setattr(models, "_build_result_leaf_rules", counting_build)
    workers = 8
    barrier = threading.Barrier(workers)
    seen: list[object] = []

    def first_use() -> None:
        barrier.wait()
        seen.append(getattr(models, "_result_leaf_rules")())

    threads = [threading.Thread(target=first_use) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert builds == [1]
    assert len(seen) == workers
    assert all(rules is seen[0] for rules in seen)
