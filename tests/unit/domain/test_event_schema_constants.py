"""Per-record schema predicates compare against prebuilt schemas, never construct one per call."""

from __future__ import annotations

import pytest

from builders.observed_runs import ObservedLedger
from builders.replay import replay_records
from finishup.domain import events
from finishup.domain.events import (
    CONTENT_FORGOTTEN_EVENT_SCHEMA_VERSION,
    AcceptedEvent,
    ContentForgottenPayload,
    EventSchema,
    LedgerRecord,
    is_content_forgotten_record,
    is_observation_authored,
)
from finishup.domain.evidence_provenance import EvidenceProvenance
from finishup.kernel.forgotten_content import latest_content_forgotten
from finishup.protocol.coverage import PublicationChannel

_VECTORS = (
    "all-event-families",
    "multi-writer",
    "supersession-redaction",
    "unknown-schema",
    "projection-rebuild",
)

# Each prebuilt module constant and the exact schema its call sites used to build inline.
_PREBUILT = (
    ("_CLAIM_V1_1_SCHEMA", "claim_recorded", events.CLAIM_SCHEMA_VERSION),
    ("_OBLIGATION_V1_1_SCHEMA", "obligation_published", events.OBLIGATION_SCHEMA_VERSION),
    (
        "_DECISION_REVIEW_MODE_SCHEMA",
        "decision_recorded",
        events.DECISION_REVIEW_MODE_SCHEMA_VERSION,
    ),
    ("_RESULT_VERIFICATION_SCHEMA", "result_recorded", events.RESULT_VERIFICATION_SCHEMA_VERSION),
    ("_RESPONSE_V1_1_SCHEMA", "response_recorded", events.RESPONSE_EVENT_SCHEMA_VERSION),
    ("_REDACTION_SCHEMA", "redaction_recorded", events.SCHEMA_VERSION),
    ("_EVIDENCE_V1_0_SCHEMA", "evidence_recorded", events.SCHEMA_VERSION),
    (
        "_LINEAGE_SESSION_OPENED_SCHEMA",
        "session_opened",
        events.LINEAGE_SESSION_EVENT_SCHEMA_VERSION,
    ),
    ("_CONTENT_FORGOTTEN_SCHEMA", "content_forgotten", CONTENT_FORGOTTEN_EVENT_SCHEMA_VERSION),
)


@pytest.mark.parametrize(("attribute", "name", "version"), _PREBUILT)
def test_prebuilt_schema_equals_the_one_built_inline(
    attribute: str, name: str, version: str
) -> None:
    prebuilt = getattr(events, attribute)
    inline = EventSchema(name, version)
    assert type(prebuilt) is EventSchema
    assert prebuilt == inline
    assert hash(prebuilt) == hash(inline)


def test_prebuilt_task_statement_plan_schemas_equal_the_inline_set() -> None:
    assert getattr(events, "_TASK_STATEMENT_PLAN_SCHEMAS") == frozenset(
        {
            EventSchema("plan_published", events.TASK_STATEMENT_PLAN_SCHEMA_VERSION),
            EventSchema("plan_revised", events.TASK_STATEMENT_PLAN_SCHEMA_VERSION),
        }
    )


def _count_schema_builds(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    built = [0]
    original = EventSchema.__post_init__

    def counting(self: EventSchema) -> None:
        built[0] += 1
        original(self)

    monkeypatch.setattr(EventSchema, "__post_init__", counting)
    return built


def _forgotten_records() -> list[LedgerRecord]:
    """A ledger holding the event the scan looks for, as the engine and as an agent wrote it."""
    ledger = ObservedLedger()
    schema = EventSchema("content_forgotten", CONTENT_FORGOTTEN_EVENT_SCHEMA_VERSION)
    payload = ContentForgottenPayload(
        forget_id="0123456789abcdef0123456789abcdef",
        reason="owner",
        source="server_copy",
        objects_erased=3,
        provenance=EvidenceProvenance({"server_copy_read": 4, "outside_read": 1}, 2),
    )
    append = ledger._append  # pyright: ignore[reportPrivateUsage]
    append(schema, payload, observed=True, channel=PublicationChannel.ENGINE_DERIVED)
    append(schema, payload, observed=False)
    append(schema, payload, observed=True, channel=PublicationChannel.ENGINE_DERIVED)
    return ledger.records


def _records(name: str) -> list[LedgerRecord]:
    return _forgotten_records() if name == "content-forgotten" else list(replay_records(name))


@pytest.mark.parametrize("name", (*_VECTORS, "content-forgotten"))
def test_content_forgotten_scan_matches_the_inline_predicate_and_builds_no_schema(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    records = _records(name)
    inline = EventSchema("content_forgotten", CONTENT_FORGOTTEN_EVENT_SCHEMA_VERSION)
    legacy = [
        type(record) is AcceptedEvent
        and record.schema == inline
        and (record.payload is None or type(record.payload) is events.ContentForgottenPayload)
        and is_observation_authored(record)
        for record in records
    ]
    if name == "content-forgotten":
        # The engine-written events match and the agent-written one does not.
        assert legacy == [True, False, True]
    expected_latest = latest_content_forgotten(records)
    built = _count_schema_builds(monkeypatch)
    assert [is_content_forgotten_record(record) for record in records] == legacy
    assert latest_content_forgotten(records) == expected_latest
    assert built[0] == 0


# Each additively versioned schema the locator compares against a prebuilt constant, its near
# misses, and the key kind it has always projected under.
_LOCATOR_KINDS = (
    (("claim_recorded", "1.1.0"), "claim"),
    (("obligation_published", "1.1.0"), "obligation"),
    (("decision_recorded", "1.1.0"), "event"),
    (("plan_published", "1.1.0"), "plan"),
    (("plan_revised", "1.1.0"), "plan"),
    (("result_recorded", "1.1.0"), "result"),
    (("response_recorded", "1.1.0"), "finding"),
    (("action_recorded", "1.1.0"), "none"),
    (("assignment_recorded", "1.1.0"), "none"),
    (("claim_recorded", "1.0.0"), "claim"),
)


@pytest.mark.parametrize(("schema", "kind"), _LOCATOR_KINDS)
def test_locator_key_kind_of_each_prebuilt_comparison_is_unchanged(
    monkeypatch: pytest.MonkeyPatch, schema: tuple[str, str], kind: str
) -> None:
    built_schema = EventSchema(*schema)
    built = _count_schema_builds(monkeypatch)
    assert getattr(events, "_locator_key_kind")(built_schema) == kind
    assert built[0] == 0


@pytest.mark.parametrize("name", _VECTORS)
def test_locator_key_kind_builds_no_schema_per_record(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    records = replay_records(name)
    key_kind = getattr(events, "_locator_key_kind")
    expected = [key_kind(record.schema) for record in records]
    built = _count_schema_builds(monkeypatch)
    assert [key_kind(record.schema) for record in records] == expected
    assert built[0] == 0
