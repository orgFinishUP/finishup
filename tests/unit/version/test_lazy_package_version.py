"""``finishup.__version__`` is resolved on first read, never by importing the package.

Reading distribution metadata (``importlib.metadata`` plus ``email`` and ``zipfile``) used to cost
more than the rest of ``import finishup``. Hook processes that never report a version must not pay
it, while every reader keeps getting the exact string the eager lookup produced. The hook-process
guards live in ``tests/subprocess/test_startup_hooks_skip_metadata.py``, whose hermetic root lets
the hooks take their ordinary path.
"""

from __future__ import annotations

import json
import subprocess
import sys

_PROBE = r"""
import json, sys
import finishup
loaded_after_import = "importlib.metadata" in sys.modules
cached_before_read = "__version__" in vars(finishup)
value = finishup.__version__
from finishup import __version__ as imported
namespace = {}
exec("from finishup import *", namespace)
from importlib.metadata import PackageNotFoundError, version
try:
    eager = version("finishup")
except PackageNotFoundError:
    eager = "0.0.0+uninstalled"
try:
    finishup.not_a_finishup_attribute
except AttributeError as error:
    missing = str(error)
print(json.dumps({
    "loaded_after_import": loaded_after_import,
    "cached_before_read": cached_before_read,
    "value": value,
    "imported": imported,
    "star": namespace.get("__version__"),
    "eager": eager,
    "cached_after_read": vars(finishup).get("__version__"),
    "in_dir": "__version__" in dir(finishup),
    "missing": missing,
}))
"""

_UNINSTALLED_PROBE = r"""
import importlib.metadata as metadata
def refuse(name):
    raise metadata.PackageNotFoundError(name)
metadata.version = refuse
import finishup
print(finishup.__version__)
"""


def _run(code: str) -> str:
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and probe source
        [sys.executable, "-c", code],
        capture_output=True,
        check=False,
    )
    return completed.stdout.decode() + completed.stderr.decode()


def test_package_import_defers_metadata_and_reads_the_same_version() -> None:
    result = json.loads(_run(_PROBE))

    assert result["loaded_after_import"] is False
    assert result["cached_before_read"] is False
    assert result["value"] == result["eager"]
    assert result["imported"] == result["eager"]
    assert result["star"] == result["eager"]
    assert result["cached_after_read"] == result["eager"]
    assert result["in_dir"] is True
    assert result["missing"] == "module 'finishup' has no attribute 'not_a_finishup_attribute'"


def test_uninstalled_fallback_is_unchanged() -> None:
    assert _run(_UNINSTALLED_PROBE).strip() == "0.0.0+uninstalled"
