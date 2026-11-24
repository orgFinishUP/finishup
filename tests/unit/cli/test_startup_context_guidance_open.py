"""The startup cue opens its guidance where ``importlib.resources`` would, without importing it.

Each layout below builds a real namespace package for ``finishup.resources`` and compares what
``_open_guidance`` yields (bytes or exact exception class) against the previous
``resources.files(...).joinpath(...).open("rb")`` read of the same package.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import subprocess
import sys
import zipfile
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path

import pytest

import finishup
from finishup.cli import startup_context

_BODY = b"# Title\n\nFor material work, read finishup://guidance/workflow.md now.\n\nrest\n"


def _reference_open() -> bytes:
    from importlib import resources

    node = resources.files("finishup.resources").joinpath("guidance/agent-instructions.md")
    with node.open("rb") as stream:
        return stream.read(1_024)


def _fast_open() -> bytes:
    with startup_context._open_guidance() as stream:  # pyright: ignore[reportPrivateUsage]
        return stream.read(1_024)


def _fast_open_without_importlib_resources() -> bytes:
    """The same open, failing loudly if it reached for ``importlib.resources``."""

    from importlib import resources

    original = resources.files

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("single filesystem portion must not use importlib.resources")

    resources.files = forbidden  # type: ignore[assignment]
    try:
        return _fast_open()
    finally:
        resources.files = original


def _outcome(read: Callable[[], bytes]) -> tuple[str, object]:
    try:
        return ("read", read())
    except OSError as exc:
        return ("raised", type(exc))


@pytest.fixture
def namespace_package(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[list[str]], None]]:
    def install(portions: list[str]) -> None:
        spec = importlib.machinery.PathFinder.find_spec("resources", portions)
        assert spec is not None
        module = importlib.util.module_from_spec(spec)
        assert module.__spec__ is not None
        assert type(module.__spec__.loader).__name__ == "NamespaceLoader"
        monkeypatch.setitem(sys.modules, "finishup.resources", module)
        monkeypatch.setattr(finishup, "resources", module, raising=False)

    yield install


def _portion(root: Path, name: str) -> Path:
    portion = root / name / "resources"
    portion.mkdir(parents=True)
    return portion


def _assert_same(install: Callable[[list[str]], None], portions: Sequence[Path | str]) -> None:
    install([str(portion.parent) if isinstance(portion, Path) else portion for portion in portions])
    assert _outcome(_fast_open) == _outcome(_reference_open)
    if len(portions) == 1 and isinstance(portions[0], Path):
        assert _outcome(_fast_open_without_importlib_resources) == _outcome(_reference_open)


def test_single_portion_reads_the_same_bytes(
    tmp_path: Path, namespace_package: Callable[[list[str]], None]
) -> None:
    portion = _portion(tmp_path, "a")
    (portion / "guidance").mkdir()
    (portion / "guidance" / "agent-instructions.md").write_bytes(_BODY)
    _assert_same(namespace_package, [portion])
    assert _outcome(_fast_open) == ("read", _BODY)


def test_missing_guidance_directory_fails_the_same_way(
    tmp_path: Path, namespace_package: Callable[[list[str]], None]
) -> None:
    portion = _portion(tmp_path, "a")
    (portion / "other").mkdir()
    _assert_same(namespace_package, [portion])
    assert _outcome(_fast_open) == ("raised", FileNotFoundError)


def test_differently_cased_guidance_directory_matches_importlib(
    tmp_path: Path, namespace_package: Callable[[list[str]], None]
) -> None:
    portion = _portion(tmp_path, "a")
    (portion / "Guidance").mkdir()
    (portion / "Guidance" / "agent-instructions.md").write_bytes(_BODY)
    _assert_same(namespace_package, [portion])


def test_unlisted_guidance_directory_still_opens_the_joined_path(
    tmp_path: Path,
    namespace_package: Callable[[list[str]], None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A listing without an exact ``guidance`` entry still opens ``<portion>/guidance/...``.

    This is what a case-insensitive filesystem does with a ``Guidance`` directory: importlib's
    traversal finds no exact name, falls back to joining the whole path onto the portion, and the
    OS resolves it. The listing is filtered here so the same holds on a case-sensitive host.
    """

    portion = _portion(tmp_path, "a")
    (portion / "guidance").mkdir()
    (portion / "guidance" / "agent-instructions.md").write_bytes(_BODY)
    original_iterdir = Path.iterdir

    def iterdir_hiding_guidance(self: Path) -> Iterator[Path]:
        return (child for child in original_iterdir(self) if child.name != "guidance")

    monkeypatch.setattr(Path, "iterdir", iterdir_hiding_guidance)
    original_listdir = startup_context.os.listdir

    def listdir_hiding_guidance(path: str) -> list[str]:
        return [name for name in original_listdir(path) if name != "guidance"]

    monkeypatch.setattr(startup_context.os, "listdir", listdir_hiding_guidance)
    namespace_package([str(portion.parent)])
    assert _outcome(_reference_open) == ("read", _BODY)
    assert _outcome(_fast_open) == ("read", _BODY)
    assert _outcome(_fast_open_without_importlib_resources) == ("read", _BODY)


def test_missing_guidance_file_fails_the_same_way(
    tmp_path: Path, namespace_package: Callable[[list[str]], None]
) -> None:
    portion = _portion(tmp_path, "a")
    (portion / "guidance").mkdir()
    _assert_same(namespace_package, [portion])
    assert _outcome(_fast_open) == ("raised", FileNotFoundError)


def test_guidance_as_a_file_fails_the_same_way(
    tmp_path: Path, namespace_package: Callable[[list[str]], None]
) -> None:
    portion = _portion(tmp_path, "a")
    (portion / "guidance").write_bytes(_BODY)
    _assert_same(namespace_package, [portion])
    assert _outcome(_fast_open) == ("raised", NotADirectoryError)


def test_guidance_file_as_a_directory_fails_the_same_way(
    tmp_path: Path, namespace_package: Callable[[list[str]], None]
) -> None:
    portion = _portion(tmp_path, "a")
    (portion / "guidance" / "agent-instructions.md").mkdir(parents=True)
    _assert_same(namespace_package, [portion])


@pytest.mark.parametrize("holder", [0, 1])
def test_several_portions_resolve_the_same_way(
    tmp_path: Path, namespace_package: Callable[[list[str]], None], holder: int
) -> None:
    portions = [_portion(tmp_path, "a"), _portion(tmp_path, "b")]
    for index, portion in enumerate(portions):
        (portion / "guidance").mkdir()
        if index == holder:
            (portion / "guidance" / "agent-instructions.md").write_bytes(_BODY)
    _assert_same(namespace_package, portions)
    assert _outcome(_fast_open) == ("read", _BODY)


def test_zipped_portion_resolves_the_same_way(
    tmp_path: Path, namespace_package: Callable[[list[str]], None]
) -> None:
    archive = tmp_path / "bundle.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        # Explicit directory entries: before Python 3.14 the zip importer finds a namespace
        # portion only through them.
        bundle.writestr("resources/", b"")
        bundle.writestr("resources/guidance/", b"")
        bundle.writestr("resources/guidance/agent-instructions.md", _BODY)
    _assert_same(namespace_package, [str(archive)])
    # importlib.resources reads a zipped namespace portion from Python 3.13 on and raises before
    # that; the cue gives the library's answer on each.
    if sys.version_info >= (3, 13):
        assert _outcome(_fast_open) == ("read", _BODY)
    else:
        assert _outcome(_fast_open) == ("raised", NotADirectoryError)


def test_installed_guidance_matches_importlib_resources() -> None:
    assert _outcome(_fast_open) == _outcome(_reference_open)
    assert _outcome(_fast_open)[0] == "read"


@pytest.mark.parametrize("host", ["claude", "cursor"])
def test_the_cue_does_not_import_importlib_resources(host: str) -> None:
    code = (
        "import io, sys\n"
        "from finishup.cli import startup_context\n"
        "out = io.BytesIO()\n"
        f"startup_context.handle_startup_context(host={host!r}, stdout=out)\n"
        "sys.stdout.write(out.getvalue().decode())\n"
        "print()\n"
        "print('importlib.resources' in sys.modules)\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    payload, imported = completed.stdout.rsplit("\n", 2)[:2]
    assert imported == "False"
    assert "finishup://guidance/workflow.md" in json.dumps(json.loads(payload))
