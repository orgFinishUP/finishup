"""Every ``TypeAdapter`` over a model class adapts a model ``ensure_built`` has finished.

Protocol and config models defer their pydantic build to first use. A ``TypeAdapter`` built over
a model that is not built yet makes its own validator instead of reusing the model's, outside
the build lock, and its ``ValidationError`` title names pydantic's wrapper (for example
``function-after[_validate_x(), XModel]``) where an import-time build named the model. So each
``TypeAdapter(...)`` under ``src/`` and ``scripts/`` wraps its type in ``ensure_built(...)``; the
only exception is a module-level name in ``src/`` that resolves to something other than a model
class (a union alias, for example), which this test resolves and checks.
"""

from __future__ import annotations

import ast
import importlib
from collections.abc import Callable, Iterator
from pathlib import Path

from pydantic import BaseModel

REPO_ROOT = Path(__file__).resolve().parents[3]
_SANCTIONED = "ensure_built"
_UNRESOLVED = object()


def _is_type_adapter(node: ast.expr) -> bool:
    if isinstance(node, ast.Subscript):
        node = node.value
    if isinstance(node, ast.Name):
        return node.id == "TypeAdapter"
    return isinstance(node, ast.Attribute) and node.attr == "TypeAdapter"


def _is_sanctioned(node: ast.expr) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
    return name == _SANCTIONED


def _adapted_type(call: ast.Call) -> ast.expr | None:
    if call.args:
        return call.args[0]
    for keyword in call.keywords:
        if keyword.arg == "type":
            return keyword.value
    return None


def violations(source: str, resolve: Callable[[str], object]) -> Iterator[str]:
    """Yield one ``line: reason`` per ``TypeAdapter`` not over a built model, in ``source``.

    ``resolve`` maps a module-level name to its value, or ``_UNRESOLVED`` when it cannot.
    """

    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.alias) and node.name == "TypeAdapter" and node.asname:
            yield f"{node.lineno}: TypeAdapter imported under another name"
        if not (isinstance(node, ast.Call) and _is_type_adapter(node.func)):
            continue
        adapted = _adapted_type(node)
        if adapted is None or _is_sanctioned(adapted):
            continue
        value = resolve(adapted.id) if isinstance(adapted, ast.Name) else _UNRESOLVED
        if value is _UNRESOLVED:
            yield f"{node.lineno}: TypeAdapter over a type this test cannot resolve"
        elif isinstance(value, type) and issubclass(value, BaseModel):
            yield f"{node.lineno}: TypeAdapter over the model {value.__name__}"


def _sources() -> Iterator[tuple[Path, str | None]]:
    for path in sorted((REPO_ROOT / "src" / "finishup").rglob("*.py")):
        relative = path.relative_to(REPO_ROOT / "src").with_suffix("")
        if "resources" in relative.parts:
            continue
        parts = relative.parts[:-1] if relative.name == "__init__" else relative.parts
        yield path, ".".join(parts)
    for path in sorted((REPO_ROOT / "scripts").rglob("*.py")):
        yield path, None


def _resolver(module_name: str | None) -> Callable[[str], object]:
    def resolve(name: str) -> object:
        if module_name is None:
            return _UNRESOLVED
        return getattr(importlib.import_module(module_name), name, _UNRESOLVED)

    return resolve


def test_every_type_adapter_adapts_a_built_model() -> None:
    found: list[str] = []
    checked = 0
    for path, module_name in _sources():
        source = path.read_text(encoding="utf-8")
        if "TypeAdapter" not in source:
            continue
        checked += 1
        relative = path.relative_to(REPO_ROOT)
        found.extend(f"{relative}:{item}" for item in violations(source, _resolver(module_name)))
    assert checked > 0
    assert found == [], (
        "wrap the adapted type in finishup.protocol.deferred_build.ensure_built(...):\n"
        + "\n".join(found)
    )


class _Model(BaseModel):
    value: int


def test_the_check_flags_an_unwrapped_model_and_unresolvable_types() -> None:
    names: dict[str, object] = {"_Model": _Model, "Alias": int | str}
    source = """
from pydantic import TypeAdapter
from pydantic import TypeAdapter as Renamed
import pydantic
A = TypeAdapter(_Model)
B = pydantic.TypeAdapter[_Model](_Model)
C = TypeAdapter(type=_Model)
D = TypeAdapter(list[_Model])
E = TypeAdapter(ensure_built(_Model))
F = TypeAdapter(deferred_build.ensure_built(_Model))
G = TypeAdapter(Alias)
"""
    found = sorted(
        violations(source, lambda name: names.get(name, _UNRESOLVED)),
        key=lambda item: int(item.split(":", 1)[0]),
    )
    assert found == [
        "3: TypeAdapter imported under another name",
        "5: TypeAdapter over the model _Model",
        "6: TypeAdapter over the model _Model",
        "7: TypeAdapter over the model _Model",
        "8: TypeAdapter over a type this test cannot resolve",
    ]
