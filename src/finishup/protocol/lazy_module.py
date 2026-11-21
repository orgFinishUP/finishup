"""A module stand-in that imports the real module on its first attribute read.

A module that names a pydantic or protocol model only in annotations, in a type alias, or inside
functions that run when such a model already exists, binds that module's names through a
:class:`LazyModule` instead of importing it. Importing the holder then stays free of pydantic,
while every place that reads a name (an annotation that pydantic or ``typing`` evaluates, a type
alias's value, a runtime identity check) still gets the real object from the real module.

The stand-in caches the imported module, never the attributes it reads from it, so a read always
sees the module's current binding.
"""

from __future__ import annotations

from importlib import import_module
from types import ModuleType

__all__ = ["LazyModule"]


class LazyModule:
    """Read attributes of the module named ``name``, importing it on the first read."""

    __slots__ = ("_module", "_name")

    def __init__(self, name: str) -> None:
        self._name = name
        self._module: ModuleType | None = None

    def __getattr__(self, attribute: str) -> object:
        # Protocol probes (``__wrapped__``, ``__mro_entries__``, ...) never import the module.
        if attribute.startswith("__"):
            raise AttributeError(attribute)
        module = self._module
        if module is None:
            module = import_module(self._name)
            self._module = module
        return getattr(module, attribute)

    def __repr__(self) -> str:
        return f"<lazy module {self._name!r}>"
