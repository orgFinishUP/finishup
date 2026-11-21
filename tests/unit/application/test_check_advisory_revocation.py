"""Revocation fences and the result bound for current project advisory notes."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, Mock

import pytest

import finishup.application.check as check
from builders.projection_workflow import run_projection_workflow
from finishup.domain.coordination import CoordinationError, CoordinationErrorCode
from finishup.ports.ledger import CheckCommitResult

_PROJECT = "prj_00000000-0000-4000-8000-000000000001"
_REQUESTER = "tsk_00000000-0000-4000-8000-000000000001"
_COUNTERPART = "tsk_00000000-0000-4000-8000-000000000002"


@pytest.mark.anyio
@pytest.mark.parametrize("authority_change", ("revoke", "new_generation_same_members"))
async def test_advisory_notes_suppress_after_duplicate_reads_are_revoked(
    monkeypatch: pytest.MonkeyPatch,
    authority_change: str,
) -> None:
    class Catalog:
        generation = 1

        async def project_state(self, project: str) -> object:
            assert project == _PROJECT
            return SimpleNamespace(membership_generation=self.generation)

        async def list_task_project_ids(self, task_id: str) -> tuple[str, ...]:
            assert task_id == _REQUESTER
            return (_PROJECT,)

    class ProjectApplication:
        def __init__(self) -> None:
            self.catalog = Catalog()
            self.live_reads = 0
            self.revoked = False

        async def live_admitted_member_task_ids(
            self, task_id: str, *, project: str, expected_generation: int
        ) -> tuple[str, ...]:
            assert task_id == _REQUESTER
            assert project == _PROJECT
            self.live_reads += 1
            if expected_generation != self.catalog.generation:
                raise ValueError("coordination_generation_revoked")
            return () if self.revoked else (_COUNTERPART,)

    project_application = ProjectApplication()
    app = SimpleNamespace(project_application=project_application)

    async def duplicate_after_revoke(*_args: object, **_kwargs: object) -> tuple[str, ...]:
        # Model the awaited context/ledger reads in the real duplicate helper: authority is
        # revoked after the pre-duplicate fence but before the note is projected.
        if authority_change == "revoke":
            project_application.revoked = True
        else:
            # A newly granted generation can contain identical members. Their equality must
            # not authorize duplicate finding facts read under the earlier generation.
            project_application.catalog.generation += 1
        return (_REQUESTER, _COUNTERPART)

    monkeypatch.setattr(check, "_duplicate_project_advisory_task_ids", duplicate_after_revoke)

    notes_reader = cast(
        Callable[[object, str, tuple[object, ...]], Awaitable[tuple[object, ...]]],
        getattr(check, "_current_project_advisory_notes"),
    )
    notes = await notes_reader(app, _REQUESTER, ())

    assert notes == ()
    assert project_application.live_reads == 3


@pytest.mark.anyio
@pytest.mark.parametrize(
    "reason",
    (
        CoordinationErrorCode.CONSENT_REQUIRED,
        CoordinationErrorCode.GRANT_REVOKED,
        CoordinationErrorCode.GENERATION_MISMATCH,
    ),
)
async def test_expected_authority_refusal_skips_fallback_without_internal_diagnostic(
    monkeypatch: pytest.MonkeyPatch, reason: CoordinationErrorCode
) -> None:
    admitted_project = "prj_00000000-0000-4000-8000-000000000002"

    async def live_members(
        task_id: str, *, project: str, expected_generation: int
    ) -> tuple[str, ...]:
        assert task_id == _REQUESTER
        assert expected_generation == 1
        if project == _PROJECT:
            raise CoordinationError(reason)
        assert project == admitted_project
        return (_COUNTERPART,)

    fallback = AsyncMock(side_effect=AssertionError("authority refusal must not use fallback"))
    app = SimpleNamespace(
        project_application=SimpleNamespace(
            catalog=SimpleNamespace(
                list_task_project_ids=AsyncMock(return_value=(_PROJECT, admitted_project)),
                project_state=AsyncMock(return_value=SimpleNamespace(membership_generation=1)),
            ),
            live_admitted_member_task_ids=live_members,
            coordination_advice_for=fallback,
        )
    )
    diagnostics = Mock()
    monkeypatch.setattr(check, "record_unexpected_exception_without_raising", diagnostics)
    monkeypatch.setattr(check, "_duplicate_project_advisory_task_ids", AsyncMock(return_value=()))
    notes_reader = cast(
        Callable[[object, str, tuple[object, ...]], Awaitable[tuple[object, ...]]],
        getattr(check, "_current_project_advisory_notes"),
    )

    notes = await notes_reader(app, _REQUESTER, ())

    assert len(notes) == 1
    assert getattr(notes[0], "project_id") == admitted_project
    fallback.assert_not_awaited()
    diagnostics.assert_not_called()


@pytest.mark.anyio
@pytest.mark.parametrize("invalid_contract", (False, True))
async def test_unexpected_advisory_failure_still_records_diagnostic(
    monkeypatch: pytest.MonkeyPatch, invalid_contract: bool
) -> None:
    failure = (
        CoordinationError(CoordinationErrorCode.INVALID)
        if invalid_contract
        else RuntimeError("synthetic projection failure")
    )
    app = SimpleNamespace(
        project_application=SimpleNamespace(
            catalog=SimpleNamespace(
                list_task_project_ids=AsyncMock(return_value=(_PROJECT,)),
                project_state=AsyncMock(return_value=SimpleNamespace(membership_generation=1)),
            ),
            live_admitted_member_task_ids=AsyncMock(side_effect=failure),
        )
    )
    diagnostics = Mock()
    monkeypatch.setattr(check, "record_unexpected_exception_without_raising", diagnostics)
    notes_reader = cast(
        Callable[[object, str, tuple[object, ...]], Awaitable[tuple[object, ...]]],
        getattr(check, "_current_project_advisory_notes"),
    )

    assert await notes_reader(app, _REQUESTER, ()) == ()
    diagnostics.assert_called_once_with(
        failure, component="check", operation="project_advisory_read"
    )


def _many_project_app(projects: tuple[str, ...]) -> SimpleNamespace:
    async def live_members(
        task_id: str, *, project: str, expected_generation: int
    ) -> tuple[str, ...]:
        assert task_id == _REQUESTER
        assert project in projects
        assert expected_generation == 1
        return (_COUNTERPART,)

    return SimpleNamespace(
        project_application=SimpleNamespace(
            catalog=SimpleNamespace(
                list_task_project_ids=AsyncMock(return_value=projects),
                project_state=AsyncMock(return_value=SimpleNamespace(membership_generation=1)),
            ),
            live_admitted_member_task_ids=live_members,
        )
    )


@pytest.mark.anyio
async def test_project_advisory_notes_stop_at_the_result_bound_inside_a_project(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The first project yields one note and every later project two, so the bound of 64 falls
    # between a project's member note and its duplicate note.
    projects = tuple(f"prj_00000000-0000-4000-8000-{index:012d}" for index in range(1, 40))

    async def duplicates(
        _app: object, _task: str, project_id: str, *_args: object, **_kwargs: object
    ) -> tuple[str, ...]:
        return () if project_id == projects[0] else (_REQUESTER, _COUNTERPART)

    monkeypatch.setattr(check, "_duplicate_project_advisory_task_ids", duplicates)
    notes_reader = cast(
        Callable[[object, str, tuple[object, ...]], Awaitable[tuple[object, ...]]],
        getattr(check, "_current_project_advisory_notes"),
    )

    notes = await notes_reader(_many_project_app(projects), _REQUESTER, ())

    assert len(notes) == 64
    # The cut is deterministic in project order: the 33rd project keeps its member note only.
    assert getattr(notes[-1], "kind") == "live_member_present"
    assert getattr(notes[-1], "project_id") == projects[32]
    assert {getattr(note, "project_id") for note in notes} == set(projects[:33])


@pytest.mark.anyio
async def test_attaching_bounded_project_advice_to_a_committed_check_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow = await run_projection_workflow("disabled")
    committed = workflow.case("check").internal
    assert isinstance(committed, CheckCommitResult)
    projects = tuple(f"prj_00000000-0000-4000-8000-{index:012d}" for index in range(1, 40))

    async def duplicates(
        _app: object, _task: str, project_id: str, *_args: object, **_kwargs: object
    ) -> tuple[str, ...]:
        return () if project_id == projects[0] else (_REQUESTER, _COUNTERPART)

    monkeypatch.setattr(check, "_duplicate_project_advisory_task_ids", duplicates)
    attach = cast(
        Callable[[object, str, CheckCommitResult], Awaitable[CheckCommitResult]],
        getattr(check, "_attach_current_project_advisory_notes"),
    )

    attached = await attach(_many_project_app(projects), _REQUESTER, committed)

    assert len(attached.advisory_notes) == 64
    assert attached.findings == committed.findings


@pytest.mark.anyio
async def test_unattachable_project_advice_leaves_the_committed_check_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow = await run_projection_workflow("disabled")
    committed = workflow.case("check").internal
    assert isinstance(committed, CheckCommitResult)
    note = check.CheckAdvisoryNote("live_member_present", _PROJECT, (_COUNTERPART,), 1)
    # A projection that breaks the result's own invariants (here, a repeated note) is advice that
    # cannot be shown; it must never fail the already committed check.
    monkeypatch.setattr(
        check, "_current_project_advisory_notes", AsyncMock(return_value=(note, note))
    )
    diagnostics = Mock()
    monkeypatch.setattr(check, "record_unexpected_exception_without_raising", diagnostics)
    attach = cast(
        Callable[[object, str, CheckCommitResult], Awaitable[CheckCommitResult]],
        getattr(check, "_attach_current_project_advisory_notes"),
    )

    attached = await attach(SimpleNamespace(), _REQUESTER, committed)

    assert attached is committed
    diagnostics.assert_called_once()
    assert diagnostics.call_args.kwargs == {
        "component": "check",
        "operation": "project_advisory_attach",
    }
