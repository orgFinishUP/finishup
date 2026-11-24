"""Domain PrivacyPolicy ↔ wire privacy-policy compatibility codec."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from builders.privacy_policies import local_only_policy, minimal_external_policy
from finishup.adapters.privacy.catalog import (
    decode_privacy_policy_canonical,
    encode_privacy_policy_json,
)
from finishup.domain.privacy import ReviewSelectionPolicy
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance


def test_encode_local_only_matches_wire_schema() -> None:
    wire = encode_privacy_policy_json(local_only_policy())
    validate_schema_instance("privacy-policy", "1.1.0", wire)
    assert wire["schema_version"] == "1.1.0"
    assert "agent_context_categories" not in wire
    ceilings = wire["local_sink_category_ceilings"]
    assert type(ceilings) is dict
    assert set(cast(dict[str, JsonValue], ceilings)) == {
        "local_model",
        "agent_context",
        "trusted_human_control",
    }
    channels = wire["channel_policies"]
    assert type(channels) is list
    assert [cast(dict[str, JsonValue], item)["channel"] for item in channels] == [
        "capability_testing",
        "crash_diagnostics",
        "llm_inference",
        "product_telemetry",
        "update_checks",
    ]


def test_wire_round_trip_preserves_domain_policy() -> None:
    original = minimal_external_policy()
    wire = encode_privacy_policy_json(original)
    # The current Assisted preset names the task_statement section, a 1.2.0-only field.
    assert wire["schema_version"] == "1.2.0"
    validate_schema_instance("privacy-policy", "1.2.0", wire)
    decoded = decode_privacy_policy_canonical(canonical_encode(wire))
    assert decoded == original


def test_domain_desired_state_shape_still_decodes(tmp_path: Path) -> None:
    from finishup.config.privacy_desired import (
        load_privacy_desired_canonical,
        write_privacy_desired_toml,
    )

    original = local_only_policy()
    path = write_privacy_desired_toml(original, tmp_path / "desired.toml")
    decoded = decode_privacy_policy_canonical(load_privacy_desired_canonical(path))
    assert decoded == original


def test_wire_decode_rejects_a_missing_never_send_deny_list() -> None:
    """``never_send`` is a const deny list; absence must not decode as a valid policy."""

    wire = dict(encode_privacy_policy_json(local_only_policy()))
    del wire["never_send"]
    with pytest.raises(ValueError, match="privacy_policy_row_corrupt"):
        decode_privacy_policy_canonical(canonical_encode(cast(JsonValue, wire)))


def test_wire_decode_rejects_a_weakened_never_send_deny_list() -> None:
    wire = dict(encode_privacy_policy_json(local_only_policy()))
    never_send = cast(list[JsonValue], wire["never_send"])
    wire["never_send"] = never_send[1:]
    with pytest.raises(ValueError, match="privacy_policy_row_corrupt"):
        decode_privacy_policy_canonical(canonical_encode(cast(JsonValue, wire)))


def test_wire_decode_rejects_an_unsupported_schema_version() -> None:
    wire = dict(encode_privacy_policy_json(local_only_policy()))
    wire["schema_version"] = "2.0.0"
    with pytest.raises(ValueError, match="privacy_policy_row_corrupt"):
        decode_privacy_policy_canonical(canonical_encode(cast(JsonValue, wire)))


def test_released_wire_policy_still_decodes() -> None:
    # A released 1.0.0 document carries the preset of its time, without task_statement.
    policy = minimal_external_policy()
    original = replace(
        policy,
        review_selection=ReviewSelectionPolicy.for_profile(
            policy.review_context_profile, preset_version="1.1.0"
        ),
    )
    wire = encode_privacy_policy_json(original)
    wire["schema_version"] = "1.0.0"
    validate_schema_instance("privacy-policy", "1.0.0", wire)
    assert decode_privacy_policy_canonical(canonical_encode(wire)) == original


def _with_llm_ceilings(max_bytes: int, max_tokens: int):  # noqa: ANN202
    from finishup.domain.privacy import EgressChannel

    base = minimal_external_policy()
    return replace(
        base,
        channel_policies=tuple(
            replace(channel, max_bytes=max_bytes, max_tokens=max_tokens)
            if channel.channel is EgressChannel.LLM_INFERENCE
            else channel
            for channel in base.channel_policies
        ),
    )


def test_a_channel_ceiling_above_262144_bytes_is_written_only_as_1_3_0() -> None:
    """#1118: the sized reviewer exchange bound (524,288 bytes) needs privacy-policy 1.3.0; a
    policy within 262,144 bytes keeps its older version and bytes."""

    within = encode_privacy_policy_json(_with_llm_ceilings(262_144, 65_536))
    assert within["schema_version"] == "1.2.0"
    validate_schema_instance("privacy-policy", "1.2.0", within)

    raised = _with_llm_ceilings(524_288, 131_072)
    wire = encode_privacy_policy_json(raised)
    assert wire["schema_version"] == "1.3.0"
    validate_schema_instance("privacy-policy", "1.3.0", wire)
    assert decode_privacy_policy_canonical(canonical_encode(wire)) == raised
    # 1.2.0 stays byte-identical, so it still refuses the wider ceiling.
    relabelled: dict[str, JsonValue] = {**wire, "schema_version": "1.2.0"}
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("privacy-policy", "1.2.0", relabelled)
    # A mis-stamped older document is refused, not read as a wider approval.
    with pytest.raises(ValueError, match="privacy_policy_row_corrupt"):
        decode_privacy_policy_canonical(canonical_encode(relabelled))
    over = cast(dict[str, JsonValue], json.loads(canonical_encode(wire)))
    llm = cast(list[dict[str, JsonValue]], over["channel_policies"])[2]
    llm["max_bytes"] = "524289"
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("privacy-policy", "1.3.0", cast(JsonValue, over))


@pytest.mark.parametrize(
    "digit_zero", [0xFF10, 0x0660, 0x0966], ids=["fullwidth", "arabic", "deva"]
)
@pytest.mark.parametrize(
    "field", ["version", "max_bytes", "max_tokens", "authorization_ttl_seconds"]
)
def test_wire_decode_refuses_a_counter_spelled_in_non_ascii_digits(
    tmp_path: Path, digit_zero: int, field: str
) -> None:
    """The frozen schema's decimal counters are ASCII ``[0-9]``; a Unicode-digit spelling of the
    same number is outside the wire grammar and must not decode, even from a desired-state file."""
    from finishup.config.privacy_desired import (
        PRIVACY_DESIRED_SCHEMA,
        load_privacy_desired_canonical,
    )

    wire = encode_privacy_policy_json(minimal_external_policy())
    if field == "version":
        target: dict[str, JsonValue] = wire
    else:
        channels = cast(list[dict[str, JsonValue]], wire["channel_policies"])
        target = next(item for item in channels if item["channel"] == "llm_inference")
    target[field] = "".join(chr(digit_zero + int(ch)) for ch in cast(str, target[field]))
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("privacy-policy", cast(str, wire["schema_version"]), wire)
    with pytest.raises(ValueError, match="_row_corrupt"):
        decode_privacy_policy_canonical(canonical_encode(wire))

    desired = tmp_path / "desired.toml"
    desired.write_text(
        f'schema = "{PRIVACY_DESIRED_SCHEMA}"\n\n[privacy.desired]\npolicy_json = '
        + json.dumps(json.dumps(wire, ensure_ascii=False), ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="_row_corrupt"):
        decode_privacy_policy_canonical(load_privacy_desired_canonical(desired))
