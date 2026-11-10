"""The ``[server]`` table and its ``[server.code_copy]`` offer, config 1.4.0 (ADR-054).

A server's owner makes a level-L2 code-copy offer from ``config.toml`` and from nowhere else. A
file without the table, a bare ``[server]`` table and ``enabled = false`` offer nothing; unknown
keys are refused as everywhere else (``unknown_config_key``); invalid values are refused with the
loader's closed ``config_value_invalid``, naming the key and never the value; and a rewrite keeps
both every file without the table byte for byte and every offer an owner wrote.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import cast

import pytest

from finishup.config.load import load_config, validate_config_mapping
from finishup.config.models import (
    ConfigError,
    FinishUpConfig,
    ObservationConfig,
    ServerCodeCopyConfig,
    ServerConfig,
)
from finishup.config.write import render_config_toml, write_config_toml
from finishup.domain.code_exclusions import ALWAYS_EXCLUDED
from finishup.protocol.canonical import JsonValue
from finishup.protocol.consent_envelope import Retention
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance

_OFFER = """\
[server.code_copy]
enabled = true
max_repo_bytes = 2097152
max_file_bytes = 131072
retention = ["until_forgotten", "days:14", "task_close"]
retention_default = "days:14"
exclusions = ["*.sqlite", "fixtures/private/"]
"""


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    return path


def _refused(text: str) -> ConfigError:
    with pytest.raises(ConfigError) as caught:
        validate_config_mapping(tomllib.loads(text))
    return caught.value


@pytest.mark.parametrize(
    "text",
    [
        "",
        "[server]\n",
        "[server.code_copy]\n",
        _OFFER.replace("enabled = true", "enabled = false"),
    ],
)
def test_no_table_a_bare_server_table_or_a_disabled_one_offers_nothing(
    tmp_path: Path, text: str
) -> None:
    config = load_config({}, {}, _write(tmp_path, text))
    table = config.server.code_copy
    assert table is None or table.enabled is False


def test_an_enabled_table_loads_its_arrays_from_toml(tmp_path: Path) -> None:
    table = load_config({}, {}, _write(tmp_path, _OFFER)).server.code_copy

    assert table is not None and table.enabled
    assert (table.max_repo_bytes, table.max_file_bytes) == (2_097_152, 131_072)
    assert table.retention == ("until_forgotten", "days:14", "task_close")
    assert table.retention_options() == (
        Retention("until_forgotten", None),
        Retention("days", 14),
        Retention("task_close", None),
    )
    assert table.retention_choice() == Retention("days", 14)
    assert table.exclusions == ("*.sqlite", "fixtures/private/")


def test_an_enabled_table_with_only_enabled_takes_every_default(tmp_path: Path) -> None:
    table = load_config(
        {}, {}, _write(tmp_path, "[server.code_copy]\nenabled = true\n")
    ).server.code_copy
    assert table == ServerCodeCopyConfig(enabled=True)


@pytest.mark.parametrize(
    ("text", "key"),
    [
        ("[server]\nrest_edge = true\n", "rest_edge"),
        ("[server.code_copy]\nenabled = true\nmax_bytes = 1\n", "max_bytes"),
        ("[server.code_copy]\nretention_days = 30\n", "retention_days"),
        ("[server.code_copy.limits]\nrepo = 1\n", "limits"),
    ],
)
def test_unknown_keys_in_either_table_are_refused_like_every_other_table(
    text: str, key: str
) -> None:
    refused = _refused(text)
    assert (refused.reason_code, refused.safe_name) == ("unknown_config_key", key)


def test_no_environment_variable_or_override_reaches_the_offer(tmp_path: Path) -> None:
    path = _write(tmp_path, "")
    with pytest.raises(ConfigError) as environment:
        load_config({}, {"FINISHUP_SERVER_CODE_COPY_ENABLED": "true"}, path)
    assert environment.value.reason_code == "unknown_config_env_var"
    with pytest.raises(ConfigError) as override:
        load_config({"server.code_copy.enabled": "true"}, {}, path)
    assert override.value.reason_code == "unknown_config_override"


_SECRET_LOOKING = "sk_live_must_not_appear"


@pytest.mark.parametrize(
    ("body", "key"),
    [
        ('enabled = "yes"', None),
        ("max_repo_bytes = true", None),
        ("max_repo_bytes = 0", None),
        ("max_repo_bytes = 1099511627777", None),
        ("max_file_bytes = -1", None),
        ("max_repo_bytes = 1000\nmax_file_bytes = 1001", "max_file_bytes"),
        ("retention = []", None),
        ('retention = "days:30"', None),
        ("retention = [30]", None),
        (f'retention = ["{_SECRET_LOOKING}"]', "retention"),
        ('retention = ["days:0"]\nretention_default = "days:0"', "retention"),
        ('retention = ["days:030"]\nretention_default = "days:030"', "retention"),
        ('retention = ["days:36501"]\nretention_default = "days:36501"', "retention"),
        ('retention = ["days:-1"]\nretention_default = "days:-1"', "retention"),
        ('retention = ["days: 7"]\nretention_default = "days: 7"', "retention"),
        ('retention = ["TASK_CLOSE"]\nretention_default = "TASK_CLOSE"', "retention"),
        ('retention = ["days:7", "days:7"]\nretention_default = "days:7"', "retention"),
        ('retention = ["days:7"]\nretention_default = "days:8"', "retention_default"),
        (f'retention_default = "{_SECRET_LOOKING}"', "retention_default"),
        ('retention = ["days:7"]', "retention_default"),
        ("exclusions = [1]", None),
        ('exclusions = "*.sqlite"', None),
        ('exclusions = [""]', "exclusions"),
        ('exclusions = ["*"]', "exclusions"),
        ('exclusions = ["**/"]', "exclusions"),
        ('exclusions = ["/"]', "exclusions"),
        ('exclusions = ["a\\u0001b"]', "exclusions"),
        ('exclusions = ["a\\u007fb"]', "exclusions"),
        ('exclusions = ["a\\tb"]', "exclusions"),
        (f'exclusions = ["{"x" * 513}"]', "exclusions"),
        ('exclusions = ["*.sqlite", "*.sqlite"]', "exclusions"),
        (f'exclusions = ["{_SECRET_LOOKING}", "{_SECRET_LOOKING}"]', "exclusions"),
    ],
)
def test_invalid_values_are_refused_with_the_loaders_closed_reason_never_the_value(
    body: str, key: str | None
) -> None:
    refused = _refused(f"[server.code_copy]\n{body}\n")
    assert (refused.reason_code, refused.safe_name) == ("config_value_invalid", key)
    assert _SECRET_LOOKING not in f"{refused!s}{refused!r}{refused.safe_name}"


def test_the_offers_bounds_are_the_profiles() -> None:
    """At most 16 retention options; at most 256 patterns in the profile's ``exclusions.always``
    (the offer's with ``ALWAYS_EXCLUDED``) and half a profile's bytes."""

    sixteen = [f"days:{days}" for days in range(1, 17)]
    accepted = ServerCodeCopyConfig(
        max_repo_bytes=1 << 40,
        max_file_bytes=1 << 40,
        retention=(*sixteen[:15], "days:36500"),
        retention_default="days:36500",
    )
    assert accepted.retention_choice() == Retention("days", 36_500)
    with pytest.raises(ConfigError):
        ServerCodeCopyConfig(retention=(*sixteen, "task_close"), retention_default="task_close")

    room = 256 - len(ALWAYS_EXCLUDED)
    patterns = tuple(f"generated-{index}.bin" for index in range(room))
    assert len(ServerCodeCopyConfig(exclusions=patterns).exclusions) == room
    # A pattern the client already excludes adds nothing to the profile, so it leaves room.
    assert ServerCodeCopyConfig(exclusions=(*patterns, ALWAYS_EXCLUDED[0])).exclusions
    with pytest.raises(ConfigError) as too_many:
        ServerCodeCopyConfig(exclusions=(*patterns, "one-more.bin"))
    assert too_many.value.safe_name == "exclusions"

    # 62 patterns of 512 characters with the client's list come to 32,377 canonical bytes; a 63rd
    # passes 32,768.
    long = tuple(f"{index:03d}-" + "x" * 508 for index in range(62))
    assert len(ServerCodeCopyConfig(exclusions=long).exclusions) == 62
    with pytest.raises(ConfigError) as too_large:
        ServerCodeCopyConfig(exclusions=(*long, "062-" + "x" * 508))
    assert too_large.value.safe_name == "exclusions"


def test_the_table_round_trips_and_validates_against_config_1_4_0_only(tmp_path: Path) -> None:
    config = validate_config_mapping(tomllib.loads(_OFFER))

    rendered = render_config_toml(config)
    assert rendered.endswith(
        "[server.code_copy]\n"
        "enabled = true\n"
        "max_repo_bytes = 2097152\n"
        "max_file_bytes = 131072\n"
        'retention = ["until_forgotten", "days:14", "task_close"]\n'
        'retention_default = "days:14"\n'
        'exclusions = ["*.sqlite", "fixtures/private/"]\n'
    )
    assert FinishUpConfig.model_validate(tomllib.loads(rendered), strict=True) == config
    assert load_config({}, {}, write_config_toml(config, path=tmp_path / "c.toml")) == config
    document = cast(JsonValue, tomllib.loads(rendered))
    validate_schema_instance("yoetz-config", "1.4.0", document)
    # v0.3.0's config 1.3.0 is frozen: it has no [server] table.
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("yoetz-config", "1.3.0", document)
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance(
            "yoetz-config",
            "1.4.0",
            cast(JsonValue, tomllib.loads("[server]\nrest_edge = true\n")),
        )


def test_patterns_that_need_escaping_round_trip_exactly() -> None:
    table = ServerCodeCopyConfig(
        enabled=True, exclusions=('quoted"name', "back\\slash", "naïve/", "空白.txt")
    )
    config = FinishUpConfig(server=ServerConfig(code_copy=table))
    assert validate_config_mapping(tomllib.loads(render_config_toml(config))) == config


@pytest.mark.parametrize(
    "config",
    [
        FinishUpConfig(),
        FinishUpConfig(server=ServerConfig()),
        FinishUpConfig(observation=ObservationConfig(enabled=False)),
    ],
)
def test_a_config_without_the_table_renders_no_server_table(config: FinishUpConfig) -> None:
    """Every existing config file keeps its bytes: nothing about ``[server]`` is written."""

    rendered = render_config_toml(config)
    assert "server" not in rendered
    assert rendered == render_config_toml(config.model_copy(update={"server": ServerConfig()}))
    validate_schema_instance("yoetz-config", "1.3.0", cast(JsonValue, tomllib.loads(rendered)))
    validate_schema_instance("yoetz-config", "1.4.0", cast(JsonValue, tomllib.loads(rendered)))


def test_an_unrelated_rewrite_keeps_the_owners_offer(tmp_path: Path) -> None:
    disabled = _OFFER.replace("enabled = true", "enabled = false")
    for text in (_OFFER, disabled, "[server.code_copy]\n"):
        path = _write(tmp_path, text)
        loaded = load_config({}, {}, path)
        changed = loaded.model_copy(update={"observation": ObservationConfig(enabled=False)})
        reloaded = load_config({}, {}, write_config_toml(changed, path=path))
        assert reloaded.server == loaded.server
        assert reloaded.server.code_copy is not None
