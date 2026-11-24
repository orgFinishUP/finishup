"""Every TOML document ``tomllib`` cannot load is a ``TOMLDecodeError`` to FinishUP's readers.

``tomllib.loads`` raises a plain ``ValueError`` for an integer past the interpreter's integer
string conversion limit and ``RecursionError`` for deep inline nesting. Both documents are about
10 KB, inside every byte cap, and both must reach each reader's closed invalid-TOML outcome
instead of escaping as an internal error (issue #1484).
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from finishup.config.load import load_config
from finishup.config.models import ConfigError
from finishup.config.privacy_desired import load_privacy_desired_canonical
from finishup.config.toml_text import TomlNotLoadable, load_toml_text

# TOML 1.0: an integer that cannot be represented losslessly is an error; tomllib reports this
# one as ``ValueError`` from the integer string conversion limit.
HUGE_INTEGER = "x = " + "1" * 4301 + "\n"
# Deep inline nesting: tomllib reports this one as ``RecursionError``.
DEEP_ARRAY = "x = " + "[" * 5000 + "]" * 5000 + "\n"
UNLOADABLE = pytest.mark.parametrize("body", [HUGE_INTEGER, DEEP_ARRAY], ids=["huge_int", "deep"])


@UNLOADABLE
def test_unloadable_document_is_a_decode_error_without_its_message(body: str) -> None:
    with pytest.raises(tomllib.TOMLDecodeError) as caught:
        load_toml_text(body)
    assert type(caught.value) is TomlNotLoadable
    assert str(caught.value) == "TOML document cannot be loaded"
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__
    assert getattr(caught.value, "lineno", None) is None


def test_ordinary_decode_errors_and_documents_pass_through_unchanged() -> None:
    assert load_toml_text('a = 1\n[b]\nc = "d"\n') == {"a": 1, "b": {"c": "d"}}
    with pytest.raises(tomllib.TOMLDecodeError) as caught:
        load_toml_text("a = [")
    assert type(caught.value) is tomllib.TOMLDecodeError


@UNLOADABLE
def test_finishup_config_reports_config_toml_invalid(tmp_path: Path, body: str) -> None:
    path = tmp_path / "config.toml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(ConfigError) as caught:
        load_config({}, {}, path)
    assert caught.value.reason_code == "config_toml_invalid"
    assert (caught.value.line, caught.value.column) == (None, None)


@UNLOADABLE
def test_privacy_desired_state_reports_config_value_invalid(tmp_path: Path, body: str) -> None:
    path = tmp_path / "privacy.toml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(ConfigError) as caught:
        load_privacy_desired_canonical(path)
    assert caught.value.reason_code == "config_value_invalid"


def test_production_code_parses_toml_only_through_the_shared_reader() -> None:
    source = Path(__file__).resolve().parents[3] / "src" / "finishup"
    direct = sorted(
        str(path.relative_to(source))
        for path in source.rglob("*.py")
        if "tomllib.loads(" in path.read_text(encoding="utf-8")
        or "tomllib.load(" in path.read_text(encoding="utf-8")
    )
    assert direct == ["config/toml_text.py"]
