"""Deferred pydantic schema builds that stay serialized and namespace-stable.

The shared FinishUP model configs set ``defer_build=True`` so a process pays for building a
model's validator and serializer only when it first uses that model. Pydantic's own lazy path
calls ``model_rebuild`` without a lock and resolves string annotations against the locals of
whichever frame first used the model. The base models route that call through
:func:`serialized_rebuild`, which holds one process-wide lock and resolves names exactly as an
import-time build did: from the class's own parent namespace and module globals, never a
caller's frame.

Two readers bypass that lazy path, so they call :func:`ensure_built` first, which finishes the
model's build under the lock. While pydantic builds a model it removes the model's placeholder
core schema, so for that moment ``Model.model_json_schema()`` in another thread would read the
parent class's schema; the base models' ``model_json_schema`` therefore waits for the build.
And a ``TypeAdapter`` over a model that is not built yet makes its own validator instead of
reusing the model's (its error title then names pydantic's wrapper, not the model), so every
``TypeAdapter`` in ``src/`` and ``scripts/`` wraps its type in :func:`ensure_built`, unless the
type is a module-level name that is not a model class; ``tests/unit/architecture`` enforces it.

Long-lived processes (the service, the MCP bridge, and the native REST edge before it listens)
call :func:`build_deferred_models` before they serve. It builds every model created so far in
creation order, which is the order an import-time build used, so nested models are complete
before the models that contain them and those processes validate with the same prebuilt
validators as before deferral.
"""

from __future__ import annotations

import threading
import weakref
from collections.abc import Callable
from typing import Final

from pydantic import BaseModel

_BUILD_LOCK: Final = threading.RLock()
_CREATED: Final[list[weakref.ref[type[BaseModel]]]] = []


def serialized_rebuild(rebuild: Callable[[], bool | None]) -> bool | None:
    """Run one ``model_rebuild`` while holding the process-wide build lock."""

    with _BUILD_LOCK:
        return rebuild()


def ensure_built[T](model: T) -> T:
    """Finish one deferred model's build, under the build lock, and return the model.

    A complete model returns at once without the lock: pydantic marks a model complete only
    after its core schema, validator and serializer are all in place. Any other type form (a
    union, an alias, a builtin) is returned unchanged, so a caller adapting a type it does not
    know statically can wrap it too.
    """

    candidate: object = model
    if (
        isinstance(candidate, type)
        and issubclass(candidate, BaseModel)
        and not candidate.__pydantic_complete__
    ):
        candidate.model_rebuild(raise_errors=False)
    return model


def record_deferred_model(model: type[BaseModel]) -> None:
    """Remember one deferred model, in creation order, for :func:`build_deferred_models`.

    This runs during class creation, often under an import lock, so it never takes the build
    lock: ``list.append`` is atomic, and a thread importing a module never waits on a build.
    """

    _CREATED.append(weakref.ref(model))


def build_deferred_models() -> None:
    """Build every recorded model that is not built yet, in creation order.

    A model that is already complete is skipped, so a second call (the native REST edge builds
    before it listens, then the service it runs builds again) only builds models created since.
    """

    with _BUILD_LOCK:
        models = [model for reference in list(_CREATED) if (model := reference()) is not None]
        for model in models:
            if not model.__pydantic_complete__:
                model.model_rebuild(raise_errors=False)
