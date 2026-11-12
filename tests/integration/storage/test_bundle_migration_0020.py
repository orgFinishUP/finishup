"""Bundle migration 0020 (ADR-054, owner ruling U20): ``events`` admits ``content_forgotten``.

0020 rebuilds ``events`` exactly as 0014 and 0019 did, widening only the ``summary_code`` CHECK.
Row and dependent-table preservation through every rebuild, and a row of the new family, are
exercised by ``test_migration_0001``'s 0014 chain test; this pins the shape, and that a v19 bundle
(the v0.3.0 storage) still refuses the family until it is migrated.
"""

from __future__ import annotations

import re

import apsw
import pytest

from finishup.adapters.sqlite.migrations import BUNDLE_MIGRATIONS, run_migrations


def _events_shape(db: apsw.Connection) -> tuple[object, ...]:
    columns = tuple(db.execute("PRAGMA table_info(events)").fetchall())
    indexes = tuple(
        sorted(
            (row[0], row[1])
            for row in db.execute(
                "SELECT name, sql FROM sqlite_schema WHERE type = 'index' AND tbl_name = 'events' "
                "AND sql IS NOT NULL"
            )
        )
    )
    return columns, indexes


def _summary_codes(db: apsw.Connection) -> set[str]:
    row = db.execute(
        "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'events'"
    ).fetchone()
    assert row is not None
    sql = str(row[0])
    block = sql[sql.index("summary_code IN (") : sql.index("))", sql.index("summary_code IN ("))]
    return set(re.findall(r"'([a-z_]+)'", block))


def _schema_nineteen() -> apsw.Connection:
    db = apsw.Connection(":memory:")
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA trusted_schema = OFF")
    with db:
        db.execute(BUNDLE_MIGRATIONS[0].ddl.decode("utf-8"))
        db.execute(
            "INSERT INTO bundle_meta(key, value) VALUES "
            "('task_id', 'task_test'), ('owner_generation', '1'), "
            "('storage_schema_version', '1'), ('protocol_version', '0.1'), "
            "('import_schema_version', '1')"
        )
        db.execute("INSERT INTO counters(name, next_value) VALUES ('ingestion_sequence', 1)")
    run_migrations(db, BUNDLE_MIGRATIONS[:19], maintenance=None)  # type: ignore[arg-type]
    assert db.pragma("user_version") == 19
    return db


def _insert_event(db: apsw.Connection, summary_code: str) -> None:
    db.execute("PRAGMA foreign_keys = OFF")  # isolate the CHECK; writers are not under test
    db.execute(
        "INSERT INTO objects(object_id, kind, plaintext_size, commitment, envelope_digest, "
        "encryption_format, key_slot, state, durable_at) VALUES ('object-1', 'event_payload', 1, "
        "'commitment-1', 'envelope-1', 'v1', 'slot', 'present', '2026-01-01')"
    )
    db.execute(
        "INSERT INTO events("
        "ingestion_seq, event_id, task_id, session_id, schema_name, schema_version, "
        "projection_status, summary_code, author_id, author_type, author_assurance, "
        "writer_id, writer_seq, operation_id, previous_ledger_digest, "
        "previous_writer_digest, entry_digest, canonical_entry, payload_object_id, "
        "payload_commitment, publication_channel, redaction_state, occurred_at, accepted_at"
        ") VALUES (1, 'event-1', 'task_test', 'session', ?, '1.0.0', 'projected', ?, 'author', "
        "'harness', 'harness_observed', 'writer', 1, 'operation-1', 'genesis', 'genesis', "
        "'entry-1', X'02', 'object-1', 'commitment-1', 'engine_derived', 'present', "
        "'2026-01-01', '2026-01-01')",
        (summary_code, summary_code),
    )


def test_0020_widens_only_the_summary_check() -> None:
    db = _schema_nineteen()
    try:
        before_shape, before_codes = _events_shape(db), _summary_codes(db)
        assert "content_forgotten" not in before_codes
        report = run_migrations(db, BUNDLE_MIGRATIONS, maintenance=None)  # type: ignore[arg-type]
        assert (report.from_version, report.to_version, report.applied_versions) == (
            19,
            20,
            ("0020",),
        )
        assert _events_shape(db) == before_shape
        assert _summary_codes(db) == before_codes | {"content_forgotten"}
        assert db.execute("PRAGMA foreign_key_check").fetchone() is None
        assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        _insert_event(db, "content_forgotten")
        assert db.execute("SELECT summary_code FROM events").fetchall() == [("content_forgotten",)]
    finally:
        db.close(force=True)


def test_a_v19_bundle_refuses_the_family_until_migrated() -> None:
    db = _schema_nineteen()
    try:
        with pytest.raises(apsw.ConstraintError):
            _insert_event(db, "content_forgotten")
        assert db.execute("SELECT COUNT(*) FROM events").fetchone() == (0,)
    finally:
        db.close(force=True)
