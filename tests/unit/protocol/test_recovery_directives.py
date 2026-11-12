"""Registry, ratchet, and projection tests for typed recovery directives (issue #739)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import cast

import pytest

from finishup.cli.render import render_human_error
from finishup.mcp import resources
from finishup.mcp.resources import MAX_GUIDANCE_PAGE_SIZE
from finishup.mcp.summaries import (
    _MAX_SUMMARY_BYTES,  # pyright: ignore[reportPrivateUsage]
    summary_for_public_error,
)
from finishup.protocol.errors import (
    ADMITTED_CLAIM_REVISION_INVARIANTS,
    PROTOCOL_REASON_CODES,
    REASON_CODE_CONTINUATIONS,
    SAFE_DETAIL_KEYS,
    PublicErrorCode,
    PublicOperationError,
    normalize_safe_details,
)
from finishup.protocol.models import PublicErrorModel
from finishup.protocol.recovery import (
    CLAIM_REVISION_CORRECTIONS,
    CONTINUATION_TOKENS,
    LOCAL_REASON_CONTINUATION_PREFIXES,
    RECOVERY_DIRECTIVES,
    continuation_for_local_reason,
    continuation_for_reason,
    correction_for_invariant,
    covered_reason_codes,
    directive_for,
    local_reason_has_disposition,
    timeout_operation_kind,
)

_GUIDANCE_ROOT = Path(__file__).resolve().parents[3] / "guidance"
_CORRELATION_ID = "err_3f2a1b4c-5d6e-4f70-8a91-b2c3d4e5f607"


def _read_canonical_resource(logical_name: str) -> bytes:
    return (_GUIDANCE_ROOT.parent / logical_name).read_bytes()


def _heading_slugs(path: Path) -> set[str]:
    """Return GitHub-style anchor slugs for every heading in a guidance document."""

    slugs: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^#{1,6} +(.*?)\s*$", line)
        if match is None:
            continue
        text = re.sub(r"[^a-z0-9 \-]", "", match.group(1).lower())
        slugs.add(re.sub(r" +", "-", text.strip()))
    return slugs


def _error(**safe_details: object) -> dict[str, object]:
    return {
        "error": {
            "code": "SERVICE_UNAVAILABLE",
            "message": "A message the text channel must never copy.",
            "retryable": True,
            "correlation_id": _CORRELATION_ID,
            "safe_details": dict(safe_details),
        }
    }


class TestRatchet:
    def test_local_reasons_cannot_shadow_operation_dependent_protocol_reasons(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import finishup.protocol.recovery as recovery

        monkeypatch.setattr(
            recovery,
            "_LOCAL_REASON_CONTINUATIONS",
            {"request_timeout": "read_timeout_new_identity"},
        )
        with pytest.raises(
            RuntimeError, match="recovery_local_reason_collides_with_protocol_reason"
        ):
            recovery._check_registry()  # pyright: ignore[reportPrivateUsage]

    def test_every_reason_code_has_a_disposition(self) -> None:
        """A reason code with neither a directive nor an exemption is the regression to catch."""

        assert PROTOCOL_REASON_CODES - covered_reason_codes() == set()

    def test_no_disposition_names_an_unregistered_reason_code(self) -> None:
        assert covered_reason_codes() - PROTOCOL_REASON_CODES == set()

    def test_continuation_tokens_are_admitted_by_the_protocol_normalizer(self) -> None:
        """A registered token nothing can put on the wire would be a dead registry entry."""

        for token in CONTINUATION_TOKENS:
            gated = normalize_safe_details({"continuation": token})
            assert gated.get("continuation") == token


class TestRegistryBounds:
    def test_every_guidance_pointer_is_registered_and_one_bounded_page(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Typed recovery never points at an orphan or oversized guidance section."""

        monkeypatch.setattr(
            resources,
            "read_verified_resource",
            _read_canonical_resource,
        )
        resources._topic_resource.cache_clear()  # pyright: ignore[reportPrivateUsage]
        pointers = {
            entry.guidance_uri for entry in RECOVERY_DIRECTIVES.values() if entry.guidance_uri
        }
        assert pointers
        for uri in pointers:
            resource = resources.resource_for_uri(uri)
            payload = resources.read_resource(uri)
            assert resource.uri == uri
            assert payload.startswith(b"#")
            assert 0 < len(payload) <= MAX_GUIDANCE_PAGE_SIZE
            page = resources.read_resource_page(uri, page_size=MAX_GUIDANCE_PAGE_SIZE)
            assert page.page_count == 1
            assert page.complete
            assert page.continuation is None

    @pytest.mark.parametrize("token", sorted(CONTINUATION_TOKENS))
    def test_guidance_pointer_resolves_to_a_real_document_and_anchor(self, token: str) -> None:
        """A pointer that leads nowhere teaches an agent to ignore every pointer."""

        entry = RECOVERY_DIRECTIVES[token]
        if entry.guidance_uri is None:
            pytest.skip("directive carries no guidance pointer")
        name, _, anchor = entry.guidance_uri.removeprefix("finishup://guidance/").partition("#")
        document = _GUIDANCE_ROOT / name
        assert document.is_file()
        if anchor:
            assert anchor in _heading_slugs(document)

    @pytest.mark.parametrize("token", sorted(CONTINUATION_TOKENS))
    def test_directive_is_an_instruction_not_a_prediction(self, token: str) -> None:
        """Coverage-bounded language: an error may direct, but may not promise an outcome."""

        entry = RECOVERY_DIRECTIVES[token]
        text = f"{entry.directive} {entry.nudge or ''}".lower()
        for promise in ("will fix", "will resolve", "this fixes", "guaranteed", "should work"):
            assert promise not in text


class TestReasonResolution:
    def test_read_write_and_start_timeouts_resolve_to_different_continuations(self) -> None:
        """The distinction #669 reported as lost is the whole point of the operation kind.

        ``start`` is its own kind: a lost first start returns neither session nor writer id, so
        the generic write recovery (read ``status view=operation``) is an instruction it cannot
        follow, and the shipped guidance excepts it with an exact same-request_id replay.
        """

        assert continuation_for_reason("request_timeout", operation_kind="read") == (
            "read_timeout_new_identity"
        )
        assert continuation_for_reason("request_timeout", operation_kind="write") == (
            "write_timeout_same_identity"
        )
        assert continuation_for_reason("request_timeout", operation_kind="start") == (
            "start_timeout_same_identity"
        )

    def test_operation_names_classify_into_the_three_timeout_kinds(self) -> None:
        assert timeout_operation_kind("start") == "start"
        for write in ("publish_work", "check", "respond", "receipt"):
            assert timeout_operation_kind(write) == "write"
        assert timeout_operation_kind("status") == "read"
        assert timeout_operation_kind(None) is None

    def test_start_timeout_directive_never_prescribes_the_operation_view(self) -> None:
        """The write directive requires ids a lost start never returned."""

        start = RECOVERY_DIRECTIVES["start_timeout_same_identity"]
        assert "view=operation" not in start.directive
        assert "same request_id" in start.directive
        assert "view=operation" in RECOVERY_DIRECTIVES["write_timeout_same_identity"].directive

    def test_unknown_operation_kind_carries_no_timeout_continuation(self) -> None:
        """Silence beats asserting a commit claim the caller could not establish."""

        assert continuation_for_reason("request_timeout") is None

    def test_local_and_protocol_reason_vocabularies_stay_disjoint(self) -> None:
        assert continuation_for_local_reason("service_already_running") == "service_holder_busy"
        assert continuation_for_reason("service_already_running") is None
        assert continuation_for_local_reason("unsorted_set_field") is None

    def test_no_cap_capacity_refusal_is_a_local_request_correction(self) -> None:
        """#828: an unsupported no-cap request names a finite choice, never a protocol reason."""

        assert (
            continuation_for_local_reason("capacity_no_cap_unsupported")
            == "capacity_request_correction"
        )
        assert continuation_for_reason("capacity_no_cap_unsupported") is None

    def test_unregistered_and_non_string_input_is_refused(self) -> None:
        assert directive_for(None) is None
        assert directive_for("not_a_registered_token") is None
        assert continuation_for_reason(object()) is None


class TestAttachmentAtConstruction:
    """The reason map is applied where every public error is built, not at each raising site.

    The first version of the registry mapped reasons to tokens but attached nothing: production
    use was one MCP timeout branch, so an ``unsorted_set_field`` rejection reached the model with
    the registered directive absent. Attachment now happens in ``PublicOperationError`` itself.
    """

    @pytest.mark.parametrize("reason", sorted(REASON_CODE_CONTINUATIONS))
    def test_every_mapped_reason_attaches_its_token_when_the_error_is_built(
        self, reason: str
    ) -> None:
        error = PublicOperationError(
            PublicErrorCode.EVENT_INVALID, "message", False, safe_details={"reason_code": reason}
        )
        assert error.safe_details.get("continuation") == REASON_CODE_CONTINUATIONS[reason]
        assert list(error.safe_details) == sorted(error.safe_details)

    def test_a_producer_chosen_continuation_is_never_overridden(self) -> None:
        error = PublicOperationError(
            PublicErrorCode.SERVICE_UNAVAILABLE,
            "message",
            True,
            safe_details={
                "reason_code": "frontier_changed",
                "continuation": "session_rebind_required",
            },
        )
        assert error.safe_details["continuation"] == "session_rebind_required"

    def test_an_unmapped_reason_attaches_nothing(self) -> None:
        error = PublicOperationError(
            PublicErrorCode.INTERNAL_ERROR,
            "message",
            False,
            safe_details={"reason_code": "internal_error"},
        )
        assert "continuation" not in error.safe_details

    def test_the_frontier_directive_agrees_with_the_shipped_replay_semantics(self) -> None:
        """publish_work stores a frontier conflict as a retryable failure under the same request_id."""

        directive = RECOVERY_DIRECTIVES["frontier_refresh_required"].directive
        assert "same request_id" in directive
        assert "new request_id" not in directive.lower()


class TestNativeTextProjection:
    def test_vault_continuation_reaches_the_model(self) -> None:
        """Issue #740: the #512 continuation and its frozen commands were dropped entirely."""

        summary = summary_for_public_error(
            {
                "error": {
                    "code": "VAULT_LOCKED",
                    "message": "A message the text channel must never copy.",
                    "retryable": False,
                    "correlation_id": _CORRELATION_ID,
                    "safe_details": {
                        "continuation": "vault_initialization_required",
                        "prepare_command": "finishup consent prepare vault_initialize",
                        "review_command": "finishup consent review",
                    },
                }
            }
        )
        assert "vault_initialization_required" in summary
        assert "finishup consent prepare vault_initialize" in summary
        assert "finishup consent review" in summary

    def test_projection_never_copies_the_public_error_message(self) -> None:
        summary = summary_for_public_error(
            _error(reason_code="request_timeout", continuation="read_timeout_new_identity")
        )
        assert "must never copy" not in summary

    def test_unregistered_continuation_token_renders_nothing(self) -> None:
        """A token the normalizer refuses must not reach the text channel as a bare string."""

        summary = summary_for_public_error(_error(continuation="not_a_registered_token"))
        assert "not_a_registered_token" not in summary
        assert summary.startswith("Error SERVICE_UNAVAILABLE;")

    @pytest.mark.parametrize("token", sorted(CONTINUATION_TOKENS))
    def test_every_directive_fits_the_summary_ceiling(self, token: str) -> None:
        """A directive that overflows would drop the projection back to bare identity."""

        summary = summary_for_public_error(
            _error(
                continuation=token,
                prepare_command="finishup consent prepare vault_initialize",
                review_command="finishup consent review",
                authorize_command="finishup consent authorize",
            )
        )
        assert len(summary.encode("ascii")) <= _MAX_SUMMARY_BYTES
        assert token in summary

    def test_error_identity_survives_a_budget_too_tight_for_advice(self) -> None:
        """Priority order: identity is never the part sacrificed to fit a directive."""

        summary = summary_for_public_error(
            _error(
                continuation="write_timeout_same_identity",
                reason_code="request_timeout",
                field="/" + "a" * 250,
            )
        )
        assert summary.startswith("Error SERVICE_UNAVAILABLE; retryable: yes;")
        assert _CORRELATION_ID in summary
        assert len(summary.encode("ascii")) <= _MAX_SUMMARY_BYTES


class TestCliProjection:
    @pytest.mark.parametrize(
        "reason", ("check_resume_capacity_exceeded", "check_result_capacity_exceeded")
    )
    def test_local_checkpoint_capacity_reaches_cli_and_mcp(self, reason: str) -> None:
        error = PublicOperationError(
            PublicErrorCode.LIMIT_EXCEEDED,
            "The local check checkpoint exceeds its capacity.",
            False,
            correlation_id=_CORRELATION_ID,
            safe_details={"reason_code": reason, "count": 5_000_000, "limit": 4_194_304},
        )
        wire = error.as_public_dict()
        model = PublicErrorModel.model_validate(wire)
        rendered = render_human_error(model)
        summary = summary_for_public_error({"error": wire})
        directive = RECOVERY_DIRECTIVES["check_capacity_handoff"].directive
        for text in (rendered, summary):
            assert "LIMIT_EXCEEDED" in text
            assert "check_capacity_handoff" in text
            assert directive in text
        assert reason in summary

    def test_cli_renders_the_same_directive(self) -> None:
        model = PublicErrorModel.model_validate(
            {
                "code": "SERVICE_UNAVAILABLE",
                "message": "The operation timed out and may still have committed.",
                "retryable": True,
                "correlation_id": _CORRELATION_ID,
                "safe_details": {
                    "reason_code": "request_timeout",
                    "continuation": "write_timeout_same_identity",
                },
            }
        )
        rendered = render_human_error(model)
        assert rendered.splitlines()[0].startswith("SERVICE_UNAVAILABLE:")
        assert "Continuation: write_timeout_same_identity" in rendered
        assert RECOVERY_DIRECTIVES["write_timeout_same_identity"].directive in rendered

    def test_cli_error_without_a_continuation_is_unchanged(self) -> None:
        model = PublicErrorModel.model_validate(
            {
                "code": "INTERNAL_ERROR",
                "message": "An internal error occurred.",
                "retryable": False,
                "correlation_id": _CORRELATION_ID,
            }
        )
        assert render_human_error(model) == "INTERNAL_ERROR: An internal error occurred."


class TestSafeDetailBounds:
    """The allowlist size and the schema's per-instance cap are different limits.

    ``public-error-1.0.0`` sets ``maxProperties: 32`` on a ``safe_details`` *instance* and admits
    property names by pattern, never by an enumerated list. The code-side allowlist may therefore
    exceed 32 -- adding ``invariant`` took it to 33 -- as long as no producer emits more than 32
    properties on one error. These tests lock that distinction, because mistaking one limit for
    the other is what nearly forced an unnecessary ``public-error-1.1.0``.
    """

    def test_allowlist_may_exceed_the_per_instance_cap(self) -> None:
        assert len(SAFE_DETAIL_KEYS) > 32
        assert tuple(SAFE_DETAIL_KEYS) == tuple(sorted(SAFE_DETAIL_KEYS))

    def test_real_producers_stay_inside_the_per_instance_cap(self) -> None:
        """Every error a producer actually builds must still validate against the schema."""

        from finishup.domain.events import (
            ClaimRevisionMismatch,
            public_error_for_claim_revision_mismatch,
        )

        error = public_error_for_claim_revision_mismatch(
            ClaimRevisionMismatch("obligation_refs", "scope_overlap_required"), event_index=0
        ).bind_correlation_id(_CORRELATION_ID)
        public = error.as_public_dict()
        details = cast(dict[str, object], public["safe_details"])
        assert len(details) <= 32
        PublicErrorModel.model_validate(public)


class TestClaimRevisionCorrections:
    def test_every_admitted_invariant_has_a_correction(self) -> None:
        assert frozenset(CLAIM_REVISION_CORRECTIONS) == ADMITTED_CLAIM_REVISION_INVARIANTS

    def test_invariant_rides_as_a_typed_detail_not_only_in_the_message(self) -> None:
        """ADR-030: the fact the MCP projector used to recover by regex is now structural."""

        from finishup.domain.events import (
            ClaimRevisionMismatch,
            public_error_for_claim_revision_mismatch,
        )

        error = public_error_for_claim_revision_mismatch(
            ClaimRevisionMismatch("claim_id", "claim_id_must_be_fresh"), event_index=3
        )
        assert error.safe_details.get("invariant") == "claim_id_must_be_fresh"

    def test_unregistered_invariant_is_stripped_by_the_normalizer(self) -> None:
        assert normalize_safe_details({"invariant": "never_registered"}) == {}
        assert correction_for_invariant("never_registered") is None
        assert correction_for_invariant(None) is None


@pytest.mark.parametrize(
    ("reason", "token"),
    [
        ("attach_handle_reused", "lineage_attach_review"),
        ("coordination_source_policy_denied", "coordination_policy_review"),
        ("coordination_generation_superseded", "coordination_superseded_recheck"),
        ("lineage_event_operation_pending", "lineage_operation_recovery"),
        ("lineage_operation_quarantined", "lineage_terminal_review"),
        ("lineage_catalog_migration_required", "lineage_service_review"),
        ("lineage_manifest_stale", "lineage_state_refresh"),
        # The parent reconciles its own session; the child-attach directive never fits it (#837).
        ("lineage_parent_session_invalid", "lineage_state_refresh"),
        ("lineage_parent_work_terminal", "lineage_successor_task"),
        ("lineage_resume_work_terminal", "lineage_successor_task"),
        ("cursor_project_mcp_preview_required", "cursor_project_preview_review"),
        ("stored_result_shape_invalid", "lineage_integrity_review"),
    ],
)
def test_lineage_reasons_attach_a_directive_without_weakening_the_ratchet(
    reason: str, token: str
) -> None:
    error = PublicOperationError(
        PublicErrorCode.SESSION_CONFLICT,
        "The operation was refused.",
        False,
        safe_details={"reason_code": reason},
    )
    assert error.safe_details["continuation"] == token
    projected = summary_for_public_error(_error(**dict(error.safe_details)))
    assert token in projected
    assert RECOVERY_DIRECTIVES[token].directive in projected


class TestLocalReasonRatchet:
    """The second ratchet (issue #741): the CLI's own reason vocabulary.

    #743 shipped the renderer and registered fourteen local reasons. The other forty carried a
    ``REMEDIATION_MESSAGES`` sentence and no typed directive, so the same condition that got a
    directive over MCP got none in a shell. These tests hold the closed set closed.
    """

    def test_every_remediation_and_refusal_reason_resolves_to_a_directive(self) -> None:
        from finishup.cli.exits import CEREMONY_REFUSAL_MESSAGES, REMEDIATION_MESSAGES

        for reason in sorted(set(REMEDIATION_MESSAGES) | set(CEREMONY_REFUSAL_MESSAGES)):
            assert local_reason_has_disposition(reason), reason

    def test_every_reason_the_cli_can_print_resolves_to_a_directive(self) -> None:
        """Lifecycle and instance public-code tables reach an operator too."""

        from finishup.cli.exits import LOCAL_REASONS

        for reason in sorted(LOCAL_REASONS):
            assert local_reason_has_disposition(reason), reason

    def test_one_reason_is_answered_only_through_the_protocol_vocabulary(self) -> None:
        """``service_draining`` is a protocol reason code the CLI also raises.

        Its disposition was recorded on the protocol side as owned by a later sub-issue of #739,
        so it must resolve there and stay out of the local map, which the disjointness gate
        enforces. ADR-051's ``target_root_is_remote`` is the same shape: ``service run`` raises it
        locally, and its directive is the protocol one every surface resolves.
        """

        from finishup.cli.exits import LOCAL_REASONS

        through_protocol = {
            reason
            for reason in LOCAL_REASONS
            if continuation_for_local_reason(reason) is None
            and local_reason_has_disposition(reason)
        }
        assert through_protocol == {"service_draining", "target_root_is_remote"}

    def test_a_new_local_reason_without_a_directive_fails_at_import(self) -> None:
        import finishup.cli.exits as exits

        original = exits.LOCAL_REASONS
        exits.LOCAL_REASONS = frozenset(original | {"a_reason_nobody_dispositioned"})
        try:
            with pytest.raises(RuntimeError, match="local_reason_without_recovery_disposition"):
                exits._check_local_reason_coverage()  # pyright: ignore[reportPrivateUsage]
        finally:
            exits.LOCAL_REASONS = original

    def test_the_vault_result_family_resolves_through_its_prefix(self) -> None:
        """The one generated family: enumerating it would be a lie about a closed set."""

        assert LOCAL_REASON_CONTINUATION_PREFIXES == (("vault_result_", "ceremony_result_invalid"),)
        for reason in ("vault_result_throttle_record_exists", "vault_result_keyring_unavailable"):
            assert continuation_for_local_reason(reason) == "ceremony_result_invalid"
        assert continuation_for_local_reason("vault_result_") is None
        assert continuation_for_local_reason("vault_result") is None

    def test_local_tokens_are_never_attached_by_a_protocol_reason(self) -> None:
        """The two vocabularies stay disjoint at the value end as well as the key end."""

        local_only = {
            "capacity_request_correction",
            "ceremony_refusal_terminal",
            "ceremony_result_invalid",
            "config_correction_required",
            "consent_outcome_unconfirmed",
            "consent_relay_correction",
            "instance_identity_repair",
            "instance_request_correction",
            "local_service_unavailable",
            "local_state_repair",
            "pending_decision_in_flight",
            "pending_decision_refresh",
            "provider_setup_required",
            "vault_unlock_required",
        }
        assert local_only <= CONTINUATION_TOKENS
        assert local_only & set(REASON_CODE_CONTINUATIONS.values()) == set()

    def test_non_string_input_is_refused(self) -> None:
        assert local_reason_has_disposition(None) is False
        assert local_reason_has_disposition("not_a_reason_at_all") is False


class TestWorkspaceBindingAndServerTargetReasons:
    """ADR-051: every binding, server-target and remote-connection reason carries a directive."""

    _EXPECTED: dict[str, str] = {
        "workspace_binding_conflict": "workspace_binding_correction",
        "workspace_ref_not_portable": "workspace_handle_required",
        "requires_server_host": "server_host_command_required",
        "target_root_is_remote": "remote_target_no_local_service",
        "target_reauthorization_required": "server_reauthorization_required",
        "selection_overridden": "server_selection_overridden",
        "remote_unreachable": "remote_server_test",
        "remote_auth_failed": "remote_credential_repair",
        "remote_identity_changed": "remote_identity_verify",
        "remote_service_not_running": "remote_service_start_required",
        "remote_incompatible": "remote_release_mismatch",
        "zero_network_remote_selected": "zero_network_local_server_required",
        "remote_kind_unavailable": "server_on_this_computer_required",
        "repository_egress_held": "repository_send_decision_required",
        "repository_egress_kept": "repository_kept_on_this_computer",
        "server_authorization_changed": "server_connection_renew",
    }

    @pytest.mark.parametrize("reason", sorted(_EXPECTED))
    def test_each_reason_is_registered_and_resolves_to_its_fixed_directive(
        self, reason: str
    ) -> None:
        token = self._EXPECTED[reason]
        assert reason in PROTOCOL_REASON_CODES
        assert continuation_for_reason(reason) == token
        assert REASON_CODE_CONTINUATIONS[reason] == token
        entry = directive_for(token)
        assert entry is not None
        # Fixed repository text: no placeholder a caller value could fill, no host or path slot.
        assert "{" not in entry.directive and "<" not in entry.directive
        assert entry.directive.isascii()
        # A CLI that raises the reason locally resolves it through the protocol side.
        assert continuation_for_local_reason(reason) is None
        assert local_reason_has_disposition(reason)
        error = PublicOperationError(
            PublicErrorCode.SERVICE_UNAVAILABLE,
            "The selected FinishUP server could not serve this request.",
            True,
            correlation_id=_CORRELATION_ID,
            safe_details={"reason_code": reason},
        )
        assert error.safe_details == {"reason_code": reason, "continuation": token}

    def test_the_workspace_agent_reasons_are_receipt_gaps_with_no_directive(self) -> None:
        """ADR-051: an agent that refused or gave no answer is a check-time change gap with its
        own fixed receipt sentence, never a public error, so it carries no directive; the two
        tokens that once stood for one are gone from every registry (refusal-guide review)."""

        for reason in ("workspace_agent_refused", "workspace_agent_unavailable"):
            assert reason in PROTOCOL_REASON_CODES
            assert reason not in REASON_CODE_CONTINUATIONS
            assert continuation_for_reason(reason) is None
            assert local_reason_has_disposition(reason)
        for token in ("workspace_agent_reconnect", "workspace_agent_refusal_review"):
            assert directive_for(token) is None
            assert token not in CONTINUATION_TOKENS

    def test_the_handle_directive_names_a_start_an_agent_can_send(self) -> None:
        # An agent cannot know the connection's handle; it can send the pair, and the FinishUP
        # MCP bridge and CLI put the handle in place of the path. The directive must not speak
        # only of a path the start may never have sent.
        entry = directive_for("workspace_handle_required")
        assert entry is not None
        assert "external_ref" in entry.directive
        assert "canonical absolute workspace_ref" in entry.directive
        assert "naming an absolute" not in entry.directive
        assert entry.nudge is not None and "in place of" in entry.nudge

    def test_remote_connection_phases_are_their_own_reason_codes(self) -> None:
        from finishup.protocol.errors import REMOTE_CONNECTION_PHASES

        # ``remote_kind_unavailable`` refuses a command (``server add``, ``use``, ``login``), never
        # a connection: a connection from a remote root keeps ``target_root_is_remote``.
        assert "remote_kind_unavailable" not in REMOTE_CONNECTION_PHASES
        assert REMOTE_CONNECTION_PHASES == frozenset(
            reason
            for reason in self._EXPECTED
            if reason.startswith("remote_") and reason != "remote_kind_unavailable"
        ) | {
            "target_reauthorization_required",
            "target_root_is_remote",
            "zero_network_remote_selected",
            "repository_egress_held",
            "repository_egress_kept",
            "server_authorization_changed",
            "server_profile_changed",
            "server_level_unavailable",
        }
        assert REMOTE_CONNECTION_PHASES <= PROTOCOL_REASON_CODES
        for phase in REMOTE_CONNECTION_PHASES:
            assert re.fullmatch(r"[a-z][a-z0-9_]{0,63}", phase)
            assert continuation_for_reason(phase) is not None

    @pytest.mark.parametrize(
        ("phase", "token"),
        [
            ("server_profile_changed", "remote_reconsent"),
            ("server_level_unavailable", "server_level_decision_required"),
        ],
    )
    def test_a_changed_profile_or_level_asks_the_owner_and_never_agrees_for_them(
        self, phase: str, token: str
    ) -> None:
        """ADR-052 (O5): only the owner agrees again, on their own terminal, with 'finishup
        server use'; the agent never does it for them. A level above the consent is refused
        before anything is sent; a changed profile may also be the server's own refusal of what
        it was sent, so it says only that the server did no work for it (review of layer 3:
        B2)."""

        assert continuation_for_reason(phase) == token
        entry = directive_for(token)
        assert entry is not None and entry.nudge is not None
        if phase == "server_profile_changed":
            assert "before that server did any work for it" in entry.directive
            assert "nothing" not in entry.directive
        else:
            assert "before anything was sent" in entry.directive
        assert "finishup server use" in entry.nudge
        assert "Never agree for them" in entry.nudge
        assert "stays there" not in entry.directive

    @pytest.mark.parametrize(
        "token",
        ["remote_server_test", "remote_credential_repair", "remote_service_start_required"],
    )
    def test_a_remote_failure_that_may_follow_a_sent_call_never_claims_nothing_was_recorded(
        self, token: str
    ) -> None:
        # A connection can end, a key be revoked or the remote service stop while a call is in
        # flight, after the server may already have recorded it; the directive says to repeat it
        # under its original identity rules (the same request_id for a write), never that it is
        # safe to treat as unsent.
        entry = directive_for(token)
        assert entry is not None
        assert "nothing was recorded" not in entry.directive
        assert "sent nothing" not in entry.directive
        assert entry.directive.endswith("under its original identity rules.")

    def test_the_zero_network_refusal_says_why_and_the_one_way_out(self) -> None:
        # Maintainer decision of 2026-11-07: this computer's zero-network policy and a server
        # elsewhere are never in force together; the refusal names why, that nothing was sent,
        # and the one command that fixes it, and never tells an agent to do it for the owner.
        entry = directive_for("zero_network_local_server_required")
        assert entry is not None
        assert "make no network connections" in entry.directive
        assert "nothing was sent" in entry.directive
        assert "'finishup server use local'" in entry.directive
        assert entry.nudge is not None and "Never select a FinishUP server" in entry.nudge

    def test_the_closed_remote_kinds_say_what_this_release_connects_to(self) -> None:
        # Every kind is open from layer 5: the refusal of an address this release names none of
        # says which servers are reached, that nothing was added, selected or sent, and the
        # owner's way back, and never tells an agent to choose a server itself.
        entry = directive_for("server_on_this_computer_required")
        assert entry is not None
        assert "connects to servers on this computer, over SSH and over HTTPS" in entry.directive
        assert "nothing was added, selected or sent" in entry.directive
        assert "'finishup server use local'" in entry.directive
        assert entry.nudge == "Never select or add a FinishUP server for the owner."

    def test_a_held_repository_asks_once_and_a_kept_one_never_asks_again(self) -> None:
        # Maintainer decision of 2026-11-07, round 4: a repository whose privacy policy here
        # allows no network use is held from a server elsewhere; the agent asks the user once,
        # only the user allows it, and a decline is remembered with 'keep', which an agent may
        # run. A kept repository is never asked about again. Both refuse a request before
        # anything from the repository was sent, and say only that (never "nothing was sent",
        # which could read as a hold over what that server received before; design v2 8.10).
        held = directive_for("repository_send_decision_required")
        assert held is not None and held.nudge is not None
        assert "allows no network use" in held.directive
        assert "this request was refused before anything from it was sent" in held.directive
        assert "Ask the user once" in held.directive
        assert "'finishup server repositories add'" in held.directive
        assert held.nudge.startswith("Then repeat it.")
        assert "'finishup server repositories keep'" in held.nudge
        assert "do not ask again" in held.nudge and "Never run 'add'" in held.nudge
        kept = directive_for("repository_kept_on_this_computer")
        assert kept is not None and kept.nudge is not None
        assert "kept on this computer" in kept.directive
        assert "this request was refused before anything from it was sent" in kept.directive
        assert "do not ask about it again" in kept.directive
        for entry in (held, kept):
            assert "nothing from it was sent" not in entry.directive
        assert "Ask" not in kept.directive
        assert "'finishup server repositories add'" in kept.nudge
        for entry in (held, kept):
            assert entry.guidance_uri is not None

    def test_a_changed_authorization_says_sending_stopped_and_the_outcome_is_unknown(self) -> None:
        # ADR-052: an open connection to a server elsewhere ends when what it was authorized
        # under changes; it already sent something, so the words say FinishUP stopped sending and
        # that what the server received stays there, never that nothing was sent (design v2 8.10).
        # A request already sent is never resent (ADR-051: no replay across targets), so its
        # outcome is unknown, and only later requests follow the selection (O1).
        entry = directive_for("server_connection_renew")
        assert entry is not None and entry.nudge is not None
        assert "authorized under changed" in entry.directive
        assert "stopped sending over it" in entry.directive
        assert "what that server received stays there" in entry.directive
        assert "may be recorded there; FinishUP never resends it" in entry.directive
        assert "nothing" not in entry.directive
        assert "same identity" not in entry.directive
        assert entry.nudge.startswith("Later requests use the current selection")
        assert "outcome is unknown" in entry.nudge
        assert "Never change servers or keys." in entry.nudge
        assert entry.guidance_uri is not None

    def test_the_new_tokens_are_protocol_tokens_not_local_ones(self) -> None:
        tokens = set(self._EXPECTED.values())
        assert tokens <= CONTINUATION_TOKENS
        assert len(tokens) == len(self._EXPECTED)
        assert tokens <= set(REASON_CODE_CONTINUATIONS.values())

    def test_a_selected_remote_root_points_to_this_computer_and_a_new_session(self) -> None:
        # The way back from a selection is 'finishup server use local'; an open agent session's
        # MCP bridge keeps the root it started with, so the owner starts a new one. A stale
        # disclosure of an SSH server (open since layer 4) is confirmed again by the owner with
        # 'finishup server use NAME' on their own terminal; an HTTPS or port one only later.
        for token in ("remote_target_no_local_service", "server_reauthorization_required"):
            entry = directive_for(token)
            assert entry is not None
            assert "Ask the owner to run 'finishup server use local'" in entry.directive
            assert entry.directive.endswith("then start a new session.")
            assert "with its name" not in entry.directive
        remote = directive_for("remote_target_no_local_service")
        assert remote is not None and "server use NAME" not in remote.directive
        stale = directive_for("server_reauthorization_required")
        assert stale is not None
        assert "older disclosure" in stale.directive
        assert "'finishup server use NAME' on their own terminal," in stale.directive

    def test_a_remote_root_an_override_names_points_to_the_override(self) -> None:
        # With an isolation variable or a pinned launcher naming the root, 'finishup server use
        # local' answers selection_overridden: the way back is to clear that override. The token
        # is attached by the client that knows its root's source, never through a reason code.
        from finishup.client.targets import REMOTE_ROOT_OVERRIDE_CONTINUATION

        assert REMOTE_ROOT_OVERRIDE_CONTINUATION == "remote_root_override_clear"
        assert REMOTE_ROOT_OVERRIDE_CONTINUATION in CONTINUATION_TOKENS
        assert REMOTE_ROOT_OVERRIDE_CONTINUATION not in set(REASON_CODE_CONTINUATIONS.values())
        entry = directive_for(REMOTE_ROOT_OVERRIDE_CONTINUATION)
        assert entry is not None
        assert entry.directive.startswith("FINISHUP_ISOLATED_ROOT or a pinned launcher names")
        assert "nothing was sent or started" in entry.directive
        assert "unset it or use an unpinned launcher" in entry.directive
        assert entry.directive.endswith("then start a new agent session.")
        assert "Ask the owner to run 'finishup server use local'" not in entry.directive
        assert entry.nudge is not None
        assert "YOETZ_ISOLATED_ROOT" in entry.nudge
        assert "'finishup server use local' cannot override" in entry.nudge

    @pytest.mark.parametrize(
        "phase",
        [
            "target_root_is_remote",
            "target_reauthorization_required",
            "zero_network_remote_selected",
        ],
    )
    def test_a_remote_root_refusal_resolves_by_what_named_the_root(
        self, phase: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import finishup.config.paths as paths
        from finishup.client.targets import remote_root_continuation
        from finishup.config.paths import ISOLATED_ROOT_ENV_NAMES

        for name in ISOLATED_ROOT_ENV_NAMES:
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setattr(paths, "read_runtime_pin", lambda: None)
        # The saved selection (or nothing explicit): the phase's own registry continuation.
        assert remote_root_continuation(phase) == REASON_CODE_CONTINUATIONS[phase]
        # A pinned launcher, then an isolation variable under either spelling.
        monkeypatch.setattr(paths, "read_runtime_pin", lambda: object())
        assert remote_root_continuation(phase) == "remote_root_override_clear"
        monkeypatch.setattr(paths, "read_runtime_pin", lambda: None)
        for name in ISOLATED_ROOT_ENV_NAMES:
            monkeypatch.setenv(name, "/srv/finishup-root")
            assert remote_root_continuation(phase) == "remote_root_override_clear"
            monkeypatch.delenv(name)

    def test_any_other_reason_resolves_as_the_registry_does_whatever_named_the_root(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from finishup.client.targets import remote_root_continuation
        from finishup.config.paths import ISOLATED_ROOT_ENV_NAMES

        monkeypatch.setenv(ISOLATED_ROOT_ENV_NAMES[0], "/srv/finishup-root")
        for reason in ("remote_unreachable", "selection_overridden", "request_timeout"):
            assert remote_root_continuation(reason) == continuation_for_reason(reason)
