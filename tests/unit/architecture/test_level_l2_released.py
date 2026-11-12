"""Level L2 (the server keeps a copy of the code) is released, and every protection it rests on is.

Design v2 §8.3: "L2 stays unavailable until sync consent, the hold, encrypted storage, forget,
provenance and receipts all exist." Layer 6 built them behind one switch,
``protocol.server_copy.L2_RELEASED``, and set it in its last code commit. This test names each
protection by the code that enforces it and the tests that hold it, so none of them can be removed
or renamed away while L2 stays released: withdrawing one must withdraw the release with it.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path
from typing import Final

import pytest

_TESTS: Final = Path(__file__).resolve().parents[2]

# protection -> (the enforcing names, as "module:attribute[.attribute]"), (test file, test names)
_PROTECTIONS: Final[dict[str, tuple[tuple[str, ...], tuple[tuple[str, tuple[str, ...]], ...]]]] = {
    # The owner's consent at L2, and the revision it names, before the helper builds anything.
    "sync_consent": (
        (
            "finishup.client.code_sync:CodeSyncResponder",
            "finishup.client.remote_binding:remote_workspace_binding",
            "finishup.protocol.consent_envelope:retention_from_token",
        ),
        (
            (
                "unit/client/test_code_sync.py",
                (
                    "test_no_agent_but_one_given_a_responder_ever_declares_the_sync",
                    "test_a_target_consented_at_l1_is_never_synced",
                    "test_every_refusal_comes_before_any_export",
                ),
            ),
        ),
    ),
    # The repository hold and zero network refuse before a bundle is built or a file is read.
    "hold_before_bundle": (
        ("finishup.client.code_export:export_snapshot",),
        (
            ("unit/client/test_code_sync.py", ("test_every_refusal_comes_before_any_export",)),
            (
                "unit/client/test_code_export.py",
                (
                    "test_the_gate_runs_before_anything_is_read_or_written",
                    "test_a_known_secret_is_held_out_until_the_owner_allows_that_exact_content",
                    "test_the_audit_refuses_a_bundle_with_anything_not_admitted",
                ),
            ),
        ),
    ),
    # Copies encrypted at rest under the vault's authority; locked vault reads nothing.
    "encrypted_storage": (
        (
            "finishup.service.code_store:CodeStore",
            "finishup.service.code_copy:VaultCopyKeyring",
            "finishup.service.code_checkout:CopyCheckouts",
        ),
        (
            (
                "unit/service/test_code_store.py",
                (
                    "test_a_snapshot_is_admitted_read_back_and_kept_encrypted",
                    "test_a_locked_vault_admits_and_reads_nothing",
                    "test_one_principal_never_reaches_another_s_copy",
                    "test_hostile_or_broken_uploads_are_refused",
                ),
            ),
            (
                "unit/service/test_code_copy_reads.py",
                ("test_the_checkout_is_owner_only_never_follows_a_link_and_forget_removes_it",),
            ),
        ),
    ),
    # Forget (tombstone first, fenced uploads, expiry) and the erasure of derived excerpts (U20).
    "forget": (
        (
            "finishup.service.code_store:CodeStore.forget",
            "finishup.service.code_copy:CodeCopies.attach_erasure",
            "finishup.application.content_forgetting:forget_task_content",
            "finishup.cli.server_code:forget_every_copy",
        ),
        (
            (
                "unit/service/test_code_store.py",
                (
                    "test_forget_deletes_the_copy_and_its_key_exactly_once",
                    "test_forget_fences_an_upload_already_in_flight",
                    "test_expiry_follows_the_retention_chosen",
                ),
            ),
            (
                "unit/service/test_code_copy_reads.py",
                (
                    "test_task_close_retention_expires_once_no_pinned_task_is_open",
                    "test_a_pending_erasure_is_cleared_only_once_its_task_says_so",
                ),
            ),
            (
                "integration/service/test_content_forgetting.py",
                ("test_forget_records_the_marker_erases_content_and_masks_every_view",),
            ),
            (
                "unit/kernel/test_forgotten_content.py",
                ("test_forget_masks_every_recorded_snippet_and_projects_the_marker",),
            ),
            (
                "unit/service/test_copy_evidence_wiring.py",
                ("test_the_erasure_is_done_only_when_nothing_is_left_to_retry",),
            ),
        ),
    ),
    # Reads from the copy are pinned, counted and named; never the level-L1 sentence for them.
    "provenance": (
        (
            "finishup.domain.evidence_provenance:EvidenceProvenance",
            "finishup.service.code_copy:CodeCopies.provenance",
            "finishup.service.workspace_routing:RoutedChangeCapture",
        ),
        (
            (
                "unit/service/test_code_copy_reads.py",
                (
                    "test_a_task_base_and_its_capture_are_read_from_the_copy_as_the_client_reads_them",
                    "test_an_offline_client_s_reads_come_from_the_copy_as_last_synced_and_checks_fail",
                    "test_a_refused_sync_never_reads_the_copy",
                    "test_an_approved_check_of_another_subject_than_the_pinned_snapshot_is_never_a_pass",
                    "test_reviewer_reads_beneath_the_root_come_from_the_pinned_snapshot_and_are_counted",
                ),
            ),
            (
                "unit/service/test_copy_evidence_wiring.py",
                ("test_a_forgotten_copy_is_read_from_the_task_ledger",),
            ),
        ),
    ),
    # Every receipt rendering states the provenance and the content-forgotten marker.
    "receipts": (
        (
            "finishup.domain.receipts:server_copy_receipt_block",
            "finishup.client.attribution:evidence_provenance_section",
        ),
        (
            (
                "unit/domain/test_receipt_server_copy_block.py",
                (
                    "test_a_copy_read_names_every_source_and_the_snapshot_in_fixed_lines",
                    "test_a_stale_read_says_the_client_was_offline_and_a_forgotten_copy_says_so",
                    "test_the_longest_section_fits_the_closing_section_bound",
                ),
            ),
            (
                "unit/protocol/test_receipt_evidence_provenance.py",
                ("test_every_receipt_format_admits_a_level_l2_account",),
            ),
            (
                "integration/application/test_receipt_evidence_provenance.py",
                (
                    "test_a_level_l2_account_ends_the_receipt_and_rides_every_format",
                    "test_a_replay_asks_again_and_the_stored_receipt_never_changes",
                ),
            ),
        ),
    ),
}


def test_level_l2_is_released() -> None:
    from finishup.protocol.server_copy import L2_RELEASED, l2_released

    assert L2_RELEASED is True
    assert l2_released() is True


def test_the_release_names_every_protection_of_design_v2_section_8_3() -> None:
    assert set(_PROTECTIONS) == {
        "sync_consent",
        "hold_before_bundle",
        "encrypted_storage",
        "forget",
        "provenance",
        "receipts",
    }


def _resolve(name: str) -> object:
    module_name, _sep, attributes = name.partition(":")
    found: object = importlib.import_module(module_name)
    for attribute in attributes.split("."):
        found = getattr(found, attribute)
    return found


def _test_names(path: Path) -> frozenset[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return frozenset(
        node.name
        for node in tree.body
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        and node.name.startswith("test_")
    )


@pytest.mark.parametrize("protection", sorted(_PROTECTIONS))
def test_each_protection_is_enforced_and_held_by_its_tests(protection: str) -> None:
    names, tests = _PROTECTIONS[protection]
    for name in names:
        assert callable(_resolve(name)), name
    for relative, wanted in tests:
        path = _TESTS / relative
        assert path.is_file(), relative
        missing = set(wanted) - _test_names(path)
        assert not missing, (relative, sorted(missing))


def test_nothing_in_a_process_can_withdraw_or_fake_the_release() -> None:
    import finishup.protocol.server_copy as server_copy

    assert not hasattr(server_copy, "enable_unreleased_l2")
    assert not hasattr(server_copy, "_ENABLED_IN_THIS_PROCESS")
