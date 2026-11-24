"""Deferred protocol/config model builds: same behavior, built only on first use."""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import threading
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from pydantic import BaseModel

import finishup.protocol.deferred_build as deferred_build
from builders.server_targets import ambient_home
from finishup.config.models import StrictConfigModel
from finishup.protocol.models import PublicResultModel

REPO_ROOT = Path(__file__).resolve().parents[3]


def _run(script: str) -> str:
    completed = subprocess.run(  # noqa: S603 - no shell and a fixed interpreter
        [sys.executable, "-I", "-c", textwrap.dedent(script)],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout


_MODELS_HELPER = """
import importlib
from pydantic import BaseModel
for name in ("finishup.protocol.models", "finishup.config.models", "finishup.config.privacy"):
    importlib.import_module(name)
from finishup.protocol import deferred_build

def finishup_models():
    found, pending = [], [BaseModel]
    while pending:
        model = pending.pop()
        pending.extend(model.__subclasses__())
        if model.__module__.startswith("finishup."):
            found.append(model)
    return found

def recorded_models():
    return [model for ref in deferred_build._CREATED if (model := ref()) is not None]
"""


def test_importing_the_models_builds_no_validator() -> None:
    """The import pays for no FinishUP model build; each model builds on first use."""

    out = _run(
        _MODELS_HELPER
        + """
import finishup.cli.app
built = sorted(
    f"{model.__module__}.{model.__qualname__}"
    for model in finishup_models()
    if model.__pydantic_complete__ and model.__name__ != "PublicResultModel"
)
print(len(finishup_models()), len(recorded_models()), built)
"""
    )
    total, recorded, built = out.split(" ", 2)
    assert int(total) > 200
    assert recorded == total, "every FinishUP model is recorded for the long-lived eager build"
    assert built.strip() == "[]"


_IMPORT_TIME_BUILD = """
import sys
import pydantic
if sys.argv[1] == "import":
    # The retained slow path: the same configs without ``defer_build``, built at import.
    _config_dict = pydantic.ConfigDict
    def _without_defer(**options):
        options.pop("defer_build", None)
        return _config_dict(**options)
    pydantic.ConfigDict = _without_defer
"""


def test_import_time_eager_and_lazy_builds_are_equivalent() -> None:
    """Import-time, service/MCP eager, and CLI lazy first-use builds give identical behavior.

    The import-time build (the configs without ``defer_build``) is the retained reference. The
    eager build runs in creation order, as the import did; the lazy path builds each model
    independently on first use, in reverse order. All three must produce the same JSON schemas
    and the same validation result or errors for every wire vector under ``fixtures/``.
    """

    script = (
        _IMPORT_TIME_BUILD
        + _MODELS_HELPER
        + """
import hashlib, json, pathlib, sys
from pydantic import ValidationError
if sys.argv[1] == "import":
    pydantic.ConfigDict = _config_dict
    built = [model for model in recorded_models() if model.__pydantic_complete__]
    assert len(built) > 200, len(built)
if sys.argv[1] == "eager":
    deferred_build.build_deferred_models()
    assert all(model.__pydantic_complete__ for model in recorded_models())
models = sorted(recorded_models(), key=repr, reverse=True)
vectors = {}
def walk(value):
    if isinstance(value, dict):
        if "protocol_version" in value or "ok" in value:
            vectors.setdefault(json.dumps(value, sort_keys=True), value)
        for child in value.values():
            walk(child)
    elif isinstance(value, list):
        for child in value:
            walk(child)
for path in sorted(pathlib.Path("fixtures").rglob("*.json")):
    try:
        walk(json.loads(path.read_text(encoding="utf-8")))
    except ValueError:
        pass
digest = hashlib.sha256()
accepted = 0
for model in models:
    digest.update(repr(model).encode())
    for mode in ("validation", "serialization"):
        digest.update(json.dumps(model.model_json_schema(mode=mode), sort_keys=True).encode())
    for text in sorted(vectors):
        try:
            result = "ok " + model.model_validate(vectors[text]).model_dump_json()
            accepted += 1
        except ValidationError as exc:
            result = "error " + json.dumps(
                exc.errors(include_url=False, include_context=False), default=repr
            )
        except Exception as exc:
            result = f"raised {type(exc).__name__} {exc}"
        digest.update(result.encode())
print(len(models), len(vectors), accepted, digest.hexdigest())
"""
    )

    def run(mode: str) -> str:
        completed = subprocess.run(  # noqa: S603 - no shell and a fixed interpreter
            [sys.executable, "-I", "-c", textwrap.dedent(script), mode],
            check=False,
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        assert completed.returncode == 0, completed.stderr
        return completed.stdout

    reference = run("import")
    models, vectors, accepted, _ = reference.split()
    assert int(models) > 200
    assert int(vectors) > 100
    assert int(accepted) > 0
    assert run("eager") == reference
    assert run("lazy") == reference


def test_long_lived_processes_build_every_model_before_serving() -> None:
    """The service and the MCP bridge call the eager build before they serve."""

    import finishup.mcp.server as mcp_server
    import finishup.service.daemon as daemon

    assert mcp_server.build_deferred_models is deferred_build.build_deferred_models
    assert daemon.build_deferred_models is deferred_build.build_deferred_models
    for function, before in (
        (daemon.run_service, "_production_composition("),
        (mcp_server.main, "anyio.run("),
    ):
        source = Path(function.__code__.co_filename).read_text(encoding="utf-8")
        body = source[source.index(f"def {function.__name__}(") :]
        assert body.index("build_deferred_models()") < body.index(before)


def test_native_rest_edge_builds_every_model_before_it_listens() -> None:
    """The native edge builds the models before its port listens, as the import-time build did.

    The service it then runs finds them built, so the time between the port accepting
    connections and the control channel answering is not lengthened by the build.
    """

    import finishup.cli.rest_server as rest_server

    source = Path(rest_server.__file__).read_text(encoding="utf-8")
    body = source[source.index("def rest_run(") : source.index("def _run_gateway(")]
    build = body.index("build_deferred_models()")
    assert body.rindex('if edge == "native":', 0, build) < build < body.index("RestListener.bind(")


# ``finishup service rest run --edge native`` in a new process, stopped twice: where the port
# would start to listen (``RestListener.bind``), and where the service would start to run
# (``anyio.run``, by then holding every model its module imports create). Nothing listens and no
# service starts. Only models whose build is deferred are counted: any other model is built by
# the import that creates it, wherever that import runs.
_NATIVE_EDGE_IN_A_NEW_PROCESS = """
import json, sys

import anyio
import pydantic

import finishup.rest.listener as listener


def deferred_models():
    found, pending = {}, [pydantic.BaseModel]
    while pending:
        model = pending.pop()
        pending.extend(model.__subclasses__())
        if model.__module__.startswith("finishup.") and model.model_config.get("defer_build"):
            found[f"{model.__module__}.{model.__qualname__}"] = model.__pydantic_complete__
    return found


built_when_the_port_opens = set()


class Bound:
    scheme, port = "http", 0


def bind(*_arguments, **_options):
    built_when_the_port_opens.update(name for name, built in deferred_models().items() if built)
    return Bound()


def run(*_arguments, **_options):
    held = deferred_models()
    print(json.dumps({
        "models": len(held),
        "config_models": sum(name.startswith("finishup.config.") for name in held),
        "not_built_when_the_port_opened": sorted(set(held) - built_when_the_port_opens),
    }))


listener.RestListener.bind = bind
anyio.run = run
sys.argv = ["finishup", "service", "rest", "run", "--edge", "native"]
sys.argv += ["--listen", "127.0.0.1:0", "--behind-proxy"]
from finishup.cli.entry import main
main()
"""


def test_native_rest_edge_has_built_every_service_model_when_its_port_opens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every deferred model the native edge's service holds was built before the port opened.

    The eager build only builds models that exist when it runs. The command graph does not
    import the config models, and the service the edge runs imports them after the port is
    bound, so a pre-listen build that ran without them left them to the service's own build,
    while the port already accepted connections.
    """

    with ambient_home(monkeypatch):
        out = _run(_NATIVE_EDGE_IN_A_NEW_PROCESS)
    report = json.loads(out.strip().splitlines()[-1])
    assert report["models"] > 200
    assert report["config_models"] > 0
    assert report["not_built_when_the_port_opened"] == []


def test_a_second_eager_build_rebuilds_no_built_model(monkeypatch: pytest.MonkeyPatch) -> None:
    """Once every model is built, the eager build only takes its own lock: no model rebuilds."""

    deferred_build.build_deferred_models()
    assert all(model.__pydantic_complete__ for model in _recorded())
    lock = _CountingLock()
    monkeypatch.setattr(deferred_build, "_BUILD_LOCK", lock)
    deferred_build.build_deferred_models()
    assert lock.acquired == 1


def test_no_forward_referenced_field_is_tuple_typed() -> None:
    """No closed-model field whose annotation is a forward reference resolves to a tuple type.

    ``_ClosedModel`` turns a JSON array into a tuple by reading ``field.annotation`` when it
    validates. A forward reference stays unresolved until its model is built, and the eager
    build, the lazy first use and an import-time build resolve it at different moments, so a
    tuple-typed one would accept an array in one process and reject it in another.
    """

    out = _run(
        """
import importlib, pkgutil, typing
import finishup
from pydantic import BaseModel
for _, name, _ in pkgutil.walk_packages(finishup.__path__, "finishup."):
    if "__main__" not in name and ".resources" not in name:
        importlib.import_module(name)
from finishup.protocol import deferred_build, models

def closed_models():
    found, pending = [], [models._ClosedModel]
    while pending:
        model = pending.pop()
        pending.extend(model.__subclasses__())
        found.append(model)
    return found

def unresolved(annotation):
    if isinstance(annotation, (str, typing.ForwardRef)):
        return True
    origin = typing.get_origin(annotation)
    if origin is typing.Literal:
        return False
    arguments = typing.get_args(annotation)
    if origin is typing.Annotated:
        arguments = arguments[:1]
    return any(unresolved(argument) for argument in arguments)

forward = [
    (model, name)
    for model in closed_models()
    for name, field in model.model_fields.items()
    if unresolved(field.annotation)
]
deferred_build.build_deferred_models()
tuple_typed = [
    f"{model.__qualname__}.{name}"
    for model, name in forward
    if unresolved(model.model_fields[name].annotation)
    or models._annotation_accepts_tuple(model.model_fields[name].annotation)
]
print(len(closed_models()), len(forward), sorted(f"{m.__qualname__}.{n}" for m, n in forward))
print(tuple_typed)
"""
    )
    counts, tuple_typed = out.splitlines()
    closed, forward, _ = counts.split(" ", 2)
    assert int(closed) > 200
    assert int(forward) > 0, counts  # the scan sees the forward references it guards
    assert tuple_typed == "[]", counts


def _recorded() -> list[type[BaseModel]]:
    references = deferred_build._CREATED  # pyright: ignore[reportPrivateUsage]
    return [model for reference in references if (model := reference()) is not None]


def _deferred_module(tmp_path: Path, name: str, body: str) -> ModuleType:
    path = tmp_path / f"{name}.py"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    module = ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    try:
        exec(compile(path.read_text(encoding="utf-8"), str(path), "exec"), module.__dict__)  # noqa: S102
    except BaseException:
        del sys.modules[name]
        raise
    return module


@pytest.fixture
def shadow_module(tmp_path: Path) -> object:
    name = "finishup_deferred_build_probe"
    module = _deferred_module(
        tmp_path,
        name,
        """
        from __future__ import annotations

        from finishup.config.models import StrictConfigModel
        from finishup.protocol.models import _ClosedModel

        Alias = int


        class ClosedProbe(_ClosedModel):
            value: Alias


        class ConfigProbe(StrictConfigModel):
            value: Alias
        """,
    )
    yield module
    del sys.modules[name]


def test_first_use_resolves_names_like_an_import_time_build(shadow_module: object) -> None:
    """A caller's local variable never changes how a deferred model reads its annotations."""

    closed_probe: type[BaseModel] = getattr(shadow_module, "ClosedProbe")
    config_probe: type[BaseModel] = getattr(shadow_module, "ConfigProbe")
    assert not closed_probe.__pydantic_complete__
    assert not config_probe.__pydantic_complete__

    def first_use() -> tuple[BaseModel, BaseModel]:
        Alias = str  # noqa: N806 - the shadowing local the build must not see
        built = closed_probe.model_validate({"value": 1}), config_probe(value=1)
        assert Alias is str
        return built

    closed, config = first_use()
    assert getattr(closed, "value") == 1
    assert getattr(config, "value") == 1


class _CountingLock:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.acquired = 0

    def __enter__(self) -> None:
        self._lock.acquire()
        self.acquired += 1

    def __exit__(self, *_: object) -> None:
        self._lock.release()


def test_first_use_builds_once_under_the_process_lock(
    shadow_module: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pydantic's lazy build is routed through one lock and runs once per model."""

    lock = _CountingLock()
    monkeypatch.setattr(deferred_build, "_BUILD_LOCK", lock)
    probe: type[BaseModel] = getattr(shadow_module, "ClosedProbe")
    for value in (1, 2, 3):
        assert getattr(probe.model_validate({"value": value}), "value") == value
    assert json.loads(probe.model_validate({"value": 4}).model_dump_json()) == {"value": 4}
    assert probe.__pydantic_complete__
    assert lock.acquired == 1


def test_concurrent_first_use_validates_with_the_model_itself(shadow_module: object) -> None:
    """Threads racing on a model's first use all get that model's own validator."""

    probe: type[BaseModel] = getattr(shadow_module, "ClosedProbe")
    barrier = threading.Barrier(8)
    results: list[object] = []
    errors: list[BaseException] = []

    def worker(value: int) -> None:
        try:
            barrier.wait()
            results.append(probe.model_validate({"value": value}))
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(value,)) for value in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert sorted(getattr(item, "value") for item in results) == list(range(8))
    assert all(type(item) is probe for item in results)


def test_first_json_schema_waits_for_the_locked_build(
    shadow_module: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A JSON schema asked of an unbuilt model builds it under the lock before reading it."""

    lock = _CountingLock()
    monkeypatch.setattr(deferred_build, "_BUILD_LOCK", lock)
    probe: type[BaseModel] = getattr(shadow_module, "ClosedProbe")
    config_probe: type[BaseModel] = getattr(shadow_module, "ConfigProbe")
    for model in (probe, config_probe):
        assert not model.__pydantic_complete__
        schema = model.model_json_schema()
        assert model.__pydantic_complete__
        assert schema["title"] == model.__name__
        assert schema["properties"] == {"value": {"title": "Value", "type": "integer"}}
        assert model.model_json_schema() == schema
    assert lock.acquired == 2


class _ObservedLock:
    """The build lock, reporting when a thread has to wait for it."""

    def __init__(self, contended: threading.Event) -> None:
        self._lock = threading.RLock()
        self._contended = contended

    def __enter__(self) -> None:
        if not self._lock.acquire(blocking=False):
            self._contended.set()
            self._lock.acquire()

    def __exit__(self, *_: object) -> None:
        self._lock.release()


def test_json_schema_during_another_threads_build_waits_for_it(
    shadow_module: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """While one thread builds a model, another thread's JSON schema waits for that build.

    Pydantic drops the model's placeholder core schema while it builds, so an unguarded read
    in that moment returns the parent class's schema. The first build is held inside that
    moment until the second thread has either answered or blocked on the build lock.
    """

    from pydantic._internal import _model_construction

    from finishup.protocol import models

    probe: type[BaseModel] = getattr(shadow_module, "ClosedProbe")
    parent: type[BaseModel] = getattr(models, "_ClosedModel")
    parent.model_rebuild()  # a built parent schema is what an unguarded read would return
    assert parent.__pydantic_complete__
    assert not probe.__pydantic_complete__
    progress = threading.Event()
    in_build = threading.Event()
    monkeypatch.setattr(deferred_build, "_BUILD_LOCK", _ObservedLock(progress))
    complete = _model_construction.complete_model_class

    def held_build(*args: Any, **kwargs: Any) -> bool:
        if not in_build.is_set():
            in_build.set()
            assert progress.wait(timeout=60), "the second thread neither answered nor waited"
        return complete(*args, **kwargs)

    monkeypatch.setattr(_model_construction, "complete_model_class", held_build)
    schemas: list[dict[str, Any]] = []

    def second() -> None:
        schemas.append(probe.model_json_schema())
        progress.set()

    builder = threading.Thread(target=lambda: probe.model_validate({"value": 1}))
    builder.start()
    assert in_build.wait(timeout=60)
    reader = threading.Thread(target=second)
    reader.start()
    reader.join()
    builder.join()
    assert schemas == [probe.model_json_schema()]
    assert schemas[0]["title"] == "ClosedProbe"


def test_provider_adapters_reuse_their_models_validators() -> None:
    """Module-level adapters over deferred models validate with the model's own validator.

    Before deferral every model was built at import, so ``TypeAdapter(Model)`` reused the
    model's validator (its error titles name the model). A fresh process without the eager
    build must behave the same.
    """

    out = _run(
        """
from collections.abc import Mapping
from pydantic import BaseModel, TypeAdapter, ValidationError
import finishup.adapters.providers.openai_responses as module

adapters = []
for name, value in sorted(vars(module).items()):
    values = value.values() if isinstance(value, Mapping) else (value,)
    adapters.extend(item for item in values if isinstance(item, TypeAdapter))
checked = []
for adapter in adapters:
    model = adapter._type
    if not (isinstance(model, type) and issubclass(model, BaseModel)):
        continue
    try:
        adapter.validate_python({})
    except ValidationError as exc:
        assert exc.title == model.__name__, exc.title
    assert adapter.validator is model.__pydantic_validator__, model
    checked.append(model.__name__)
print(len(checked))
"""
    )
    assert int(out) == 8


def test_bases_are_recorded_for_the_eager_build() -> None:
    from finishup.protocol import models

    recorded = {reference() for reference in deferred_build._CREATED}  # pyright: ignore[reportPrivateUsage]
    assert {getattr(models, "_ClosedModel"), PublicResultModel, StrictConfigModel} <= recorded
