"""The exact bare version forms answer without the typer graph, byte for byte as the full CLI.

Each case runs the fast path and the retained full CLI (``finishup.cli.app.main``) against the same
stream and compares stdout, stderr, exit code and the streams left installed, so a change on either
side that makes them drift fails here.
"""

from __future__ import annotations

import errno
import io
import os
import re
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

import finishup
import finishup.cli.entry as entry

_INTERNAL_ERROR = re.compile(
    r"internal_error: the command could not be completed; correlation: err_[0-9a-f-]{36}\n"
)


class _Stdout(io.StringIO):
    """A text stdout whose writes or flushes can fail the way a real descriptor does."""

    def __init__(self, failure: BaseException | None = None, *, on_flush: bool = False) -> None:
        super().__init__()
        self.failure = failure
        self.on_flush = on_flush

    def write(self, s: str) -> int:
        if self.failure is not None and not self.on_flush:
            raise self.failure
        return super().write(s)

    def flush(self) -> None:
        if self.failure is not None and self.on_flush:
            raise self.failure
        super().flush()


@dataclass(frozen=True)
class _Outcome:
    code: int | str | None
    out: str
    err: str
    stdout_type: str
    stderr_type: str


def _run(
    monkeypatch: pytest.MonkeyPatch,
    arguments: list[str],
    stdout_factory: Callable[[], io.StringIO | None],
    runner: Callable[[], None],
) -> _Outcome:
    stdout = stdout_factory()
    stderr = io.StringIO()
    with monkeypatch.context() as scoped:
        scoped.setattr(sys, "argv", ["finishup", *arguments])
        scoped.setattr(sys, "stdout", stdout)
        scoped.setattr(sys, "stderr", stderr)
        code: int | str | None = 0
        try:
            runner()
        except SystemExit as exited:
            code = exited.code
        stdout_type = type(sys.stdout).__name__
        stderr_type = type(sys.stderr).__name__
    return _Outcome(
        code=0 if code is None else code,
        out="" if stdout is None else stdout.getvalue(),
        err=stderr.getvalue(),
        stdout_type=stdout_type,
        stderr_type=stderr_type,
    )


def _full_cli() -> None:
    from finishup.cli.app import main as app_main

    app_main()


def _no_full_cli() -> None:
    raise AssertionError("the exact version forms must not load the full CLI")


@pytest.fixture
def fast_main(monkeypatch: pytest.MonkeyPatch) -> Callable[[], None]:
    monkeypatch.setattr(entry.os, "name", "posix")
    monkeypatch.delenv("_FINISHUP_COMPLETE", raising=False)
    monkeypatch.setattr(entry, "_run_full_cli", _no_full_cli)
    return entry.main


_STDOUTS: dict[str, Callable[[], io.StringIO | None]] = {
    "ordinary": _Stdout,
    "closed": lambda: None,
    "storage_full_on_flush": lambda: _Stdout(OSError(errno.ENOSPC, "full"), on_flush=True),
    "storage_full_on_write": lambda: _Stdout(OSError(errno.ENOSPC, "full")),
    "broken_pipe": lambda: _Stdout(BrokenPipeError(errno.EPIPE, "pipe")),
    "interrupted": lambda: _Stdout(KeyboardInterrupt()),
    "unexpected": lambda: _Stdout(RuntimeError("private detail")),
}


@pytest.mark.parametrize("stdout_case", sorted(_STDOUTS))
@pytest.mark.parametrize("arguments", [["--version"], ["version"]])
def test_fast_path_matches_the_full_cli(
    monkeypatch: pytest.MonkeyPatch,
    fast_main: Callable[[], None],
    arguments: list[str],
    stdout_case: str,
) -> None:
    factory = _STDOUTS[stdout_case]
    fast = _run(monkeypatch, arguments, factory, fast_main)
    full = _run(monkeypatch, arguments, factory, _full_cli)

    normalize = re.compile(r"err_[0-9a-f-]{36}")
    assert normalize.sub("err_X", fast.err) == normalize.sub("err_X", full.err)
    assert (fast.code, fast.out, fast.stdout_type, fast.stderr_type) == (
        full.code,
        full.out,
        full.stdout_type,
        full.stderr_type,
    )


@pytest.mark.parametrize("arguments", [["--version"], ["version"]])
def test_fast_path_outcomes_are_the_documented_ones(
    monkeypatch: pytest.MonkeyPatch, fast_main: Callable[[], None], arguments: list[str]
) -> None:
    ordinary = _run(monkeypatch, arguments, _Stdout, fast_main)
    assert (ordinary.code, ordinary.out, ordinary.err) == (0, finishup.__version__ + "\n", "")
    closed = _run(monkeypatch, arguments, lambda: None, fast_main)
    assert (closed.code, closed.err) == (0, "")
    full = _run(monkeypatch, arguments, _STDOUTS["storage_full_on_flush"], fast_main)
    assert full.code == 70
    assert _INTERNAL_ERROR.fullmatch(full.err.lstrip("\n"))
    assert (
        "private detail" not in _run(monkeypatch, arguments, _STDOUTS["unexpected"], fast_main).err
    )
    pipe = _run(monkeypatch, arguments, _STDOUTS["broken_pipe"], fast_main)
    assert (pipe.code, pipe.err, pipe.stdout_type) == (1, "", "PacifyFlushWrapper")
    interrupted = _run(monkeypatch, arguments, _STDOUTS["interrupted"], fast_main)
    assert (interrupted.code, interrupted.err) == (130, "")


@pytest.mark.parametrize(
    "arguments",
    [
        ["version", "--json"],
        ["version", "--resources"],
        ["version", "extra"],
        ["--version", "status"],
        ["--version", "--version"],
        ["--home-project", "/srv/project", "--version"],
        ["--version", "--help"],
        ["version", "--help"],
        ["VERSION"],
        ["-V"],
        [],
    ],
)
def test_every_other_form_falls_through_to_the_full_cli(
    monkeypatch: pytest.MonkeyPatch, arguments: list[str]
) -> None:
    assert entry._version_fast_path(arguments) is None  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(sys, "argv", ["finishup", *arguments])
    monkeypatch.setattr(entry.os, "name", "posix")
    calls: list[str] = []
    monkeypatch.setattr(entry, "_run_full_cli", lambda: calls.append("cli"))
    entry.main()
    assert calls == ["cli"]


@pytest.mark.parametrize("value", ["bash_source", "zsh_complete", ""])
@pytest.mark.parametrize("arguments", [["--version"], ["version"]])
def test_a_shell_completion_request_falls_through_to_typer(
    monkeypatch: pytest.MonkeyPatch, arguments: list[str], value: str
) -> None:
    monkeypatch.setenv("_FINISHUP_COMPLETE", value)

    assert entry._version_fast_path(arguments) is None  # pyright: ignore[reportPrivateUsage]


def test_the_version_forms_never_import_the_typer_graph(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    probe = (
        "import sys\n"
        "import finishup.cli.entry as entry\n"
        "for arguments in (['--version'], ['version']):\n"
        "    sys.argv = ['finishup', *arguments]\n"
        "    try:\n"
        "        entry.main()\n"
        "    except SystemExit as exited:\n"
        "        assert exited.code == 0, exited.code\n"
        "loaded = sorted(\n"
        "    name for name in ('typer', 'click', 'pydantic', 'finishup.cli.app') if name in sys.modules\n"
        ")\n"
        "sys.stderr.write(repr(loaded))\n"
    )
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"_FINISHUP_COMPLETE", "YOETZ_ISOLATED_ROOT"}
    }
    environment["FINISHUP_ISOLATED_ROOT"] = str(root)
    completed = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
        timeout=60,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == (finishup.__version__ + "\n") * 2
    assert completed.stderr == "[]"
