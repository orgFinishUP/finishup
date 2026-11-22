"""A config the loader accepts stays rewritable when a string holds a control character.

TOML basic strings cannot carry a raw control character, but the loader accepts one spelled
as a ``\\uXXXX`` escape. The writer must spell it back the same way so its round-trip check
(#520) holds, and every writer failure stays a bounded ``ConfigError``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from finishup.cli.provider_binding import apply_provider_endpoint_choice
from finishup.config.load import load_config
from finishup.config.models import ConfigError
from finishup.config.write import render_config_toml, write_config_toml

_CONTROL_CHARACTERS = ("\x00", "\x01", "\x08", "\x0b", "\x0c", "\x1b", "\x1f", "\x7f")


def _escaped(character: str) -> str:
    return f"\\u{ord(character):04X}"


@pytest.mark.parametrize("character", _CONTROL_CHARACTERS)
def test_rendered_config_round_trips_a_loaded_control_character(
    tmp_path: Path, character: str
) -> None:
    source = tmp_path / "config.toml"
    source.write_text(f'[storage]\ndata_dir = "/srv/a{_escaped(character)}b"\n', encoding="utf-8")
    loaded = load_config({}, {}, source)
    assert str(loaded.storage.data_dir) == f"/srv/a{character}b"

    rendered = render_config_toml(loaded)

    assert character not in rendered
    target = tmp_path / "rewritten.toml"
    write_config_toml(loaded, target)
    assert target.read_text(encoding="utf-8") == rendered
    assert str(load_config({}, {}, target).storage.data_dir) == f"/srv/a{character}b"


def test_provider_binding_rewrites_a_config_holding_an_escaped_control_character(
    tmp_path: Path,
) -> None:
    target = tmp_path / "config.toml"
    target.write_text('[storage]\ndata_dir = "/srv/a\\u007Fb"\n', encoding="utf-8")

    apply_provider_endpoint_choice("official_openai", model="gpt-5", path=target)

    assert str(load_config({}, {}, target).storage.data_dir) == "/srv/a\x7fb"


def test_ordinary_escapes_render_unchanged(tmp_path: Path) -> None:
    source = tmp_path / "config.toml"
    source.write_text('[storage]\ndata_dir = "/srv/a\\"q\\\\b\\tc"\n', encoding="utf-8")

    rendered = render_config_toml(load_config({}, {}, source))

    assert 'data_dir = "/srv/a\\"q\\\\b\\tc"' in rendered


def test_an_unloadable_render_is_a_bounded_config_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import finishup.config.write as write_module

    source = tmp_path / "config.toml"
    source.write_text('[storage]\ndata_dir = "/srv/secret-path"\n', encoding="utf-8")
    loaded = load_config({}, {}, source)

    def unloadable_escape(value: str) -> str:
        return value + "\x7f"

    monkeypatch.setattr(write_module, "_escape_basic", unloadable_escape)

    with pytest.raises(ConfigError) as caught:
        render_config_toml(loaded)

    assert caught.value.reason_code == "config_value_invalid"
    assert "secret-path" not in str(caught.value)


@pytest.mark.parametrize(
    "module_name", ["finishup.config.write", "finishup.config.privacy_desired"]
)
def test_every_basic_string_escape_parses_back_to_its_value(module_name: str) -> None:
    import importlib
    import tomllib

    escape = importlib.import_module(module_name)._escape_basic
    value = "".join(chr(code) for code in range(0x80)) + "é "

    assert tomllib.loads(f'v = "{escape(value)}"\n')["v"] == value
