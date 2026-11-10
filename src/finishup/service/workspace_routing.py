"""Route every service workspace read to the local adapter or to the client's workspace agent.

A task whose session opened on this machine names its workspace by an absolute path, and every
read below goes to the existing local adapter exactly as before. A claim-bound task (ADR-051)
names its workspace by the ``client:<16 hex>`` handle its connection's claim produced: then
every read goes to the client's workspace agent through ``WorkspaceAgentHub`` and the catalog
codecs (``finishup.ports.workspace_agent``), and no local adapter is ever handed that task's
workspace. The service never resolves a handle to a path on its own disk.

The adapters here are synchronous because the ports they stand in for are: their callers run
them in worker threads (``asyncio.to_thread``), and a blocking call reaches the hub's event loop
from there (``WorkspaceAgentHub.call_blocking``). What the agent returns is the client's
attestation (``CLIENT_ATTESTED``): the hub records each answer it delivers under that label,
and a claim-bound task's human receipts say so in a fixed line.

Failures keep their meaning. An agent answer that is one of change capture's own closed reasons
raises the same ``ChangeCaptureUnavailable`` a local read would; an agent that does not answer
raises ``WorkspaceAgentUnavailable``, which every caller records as a gap, never as a pass.

**Level L2 (ADR-054, design v2 §4.1).** When this service keeps a copy of a claim-bound task's
repository, the reads inside the repository root are served from the copy instead, through the
same local adapters run against a materialized checkout of the snapshot the task is pinned to
(``service.code_copy.CodeCopies``, ``service.code_checkout``): the task base, change capture and
its metadata, the requested-path, line-count and undeclared-reference probes, the reviewer's
listings, file reads and declared tests beneath the root, and an opened workspace's changed paths
and inspection. Reads outside the root, the check policy, the subject state and approved checks
stay with the client's agent (approved checks run on the user's computer, U7). A git read at an
evidence boundary syncs first; a client that is offline then reads the copy as last synced
(``stale_copy_read``), and a refused sync never falls back to the copy. Every read of a task
pinned to a copy is counted for the task by where it was answered (``evidence_task_scope``).
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol, cast

from finishup.adapters.approved_checks import (
    ApprovedCheckCommand,
    ApprovedCheckOutcome,
    ApprovedCheckRunner,
    ApprovedCheckStatus,
)
from finishup.adapters.task_input_read import ReadDeadline
from finishup.adapters.task_input_read import list_beneath as _local_list_beneath
from finishup.adapters.task_input_read import read_text_beneath as _local_read_text_beneath
from finishup.application.observation_check_policy import (
    CHECK_POLICY_PATH,
    LEGACY_CHECK_POLICY_PATH,
    ObservationCheckPolicy,
    ObservationCheckPolicyAbsent,
    ObservationCheckPolicyAmbiguous,
    parse_observation_check_policy,
)
from finishup.application.observation_workspace import (
    LocalObservationWorkspace,
    ObservationWorkspaceAccess,
)
from finishup.application.reviewer_loop import LOCAL_READ_SECONDS, ReadStop
from finishup.domain.receipts import CLIENT_ATTESTED
from finishup.ports.approved_checks import ApprovedCheckApproval, ApprovedCheckResult
from finishup.ports.change_capture import (
    CHANGE_CAPTURE_UNAVAILABLE_REASONS,
    MAX_TASK_INPUT_FILES,
    ChangeCapturePort,
    ChangeCaptureUnavailable,
    ChangeLineCounts,
    CheckChangeCapture,
    CheckChangeMetadata,
    OutsideSnapshotRead,
    RequestedPathProbe,
    TaskChangeBase,
    TaskInputFile,
    current_evidence_task,
)
from finishup.ports.subject_state import (
    LocalWorkspaceHandle,
    SubjectStateCaptureCommand,
    SubjectStateCapturePort,
    SubjectStateCaptureResult,
)
from finishup.ports.workspace_agent import (
    MAX_WORKSPACE_DEADLINE_MS,
    ApprovedCheckRun,
    CaptureArguments,
    CaptureMetadataArguments,
    CheckPolicyRead,
    ClassifyUndeclaredReferencesArguments,
    CountChangeLinesArguments,
    InspectArguments,
    ListBeneathArguments,
    ListChangedPathsArguments,
    LstatCandidatesArguments,
    LstatFacts,
    OpenWorkspaceArguments,
    OutsideInputsRead,
    OutsideSnapshotsRead,
    ProbeRequestedPathsArguments,
    ReadDeclaredTestArguments,
    ReadOutsideInputsArguments,
    ReadTextBeneathArguments,
    RunApprovedCheckArguments,
    SnapshotOutsideInputsArguments,
    SubjectStateCaptureArguments,
    WorkspaceAgentUnavailable,
    WorkspaceOnlyArguments,
    WorkspaceOperation,
    resolve_client_location,
    workspace_handle_valid,
)
from finishup.ports.workspace_inspect import (
    WorkspaceInspectCommand,
    WorkspaceInspectPort,
    WorkspaceInspectResult,
)
from finishup.protocol.errors import ProtocolValueError
from finishup.service.workspace_hub import WorkspaceAgentHub

if TYPE_CHECKING:
    from finishup.domain.evidence_provenance import EvidenceToken
    from finishup.service.code_copy import CodeCopies, CopyView

__all__ = [
    "CLIENT_ATTESTED",
    "ClientWorkspaceReads",
    "RoutedApprovedCheckRunner",
    "RoutedChangeCapture",
    "RoutedObservationWorkspace",
    "WorkspaceFileReads",
    "WorkspaceRouting",
    "client_bound",
]

# Bounds on one agent answer, by family. Each exceeds the local adapter's own read bound so the
# agent's own fences, not this wait, decide a slow read; the round trip adds the rest.
_GIT_SECONDS: Final = 60.0
_READ_SECONDS: Final = 15.0
_SNAPSHOT_GRACE_SECONDS: Final = 5.0
# A reviewer's read (and its ignored-path probe) stops at the reviewer's own per-read budget, so
# a slow agent ends the review ``deadline`` as a slow local read does. Within it, the agent's
# answer gets no more time than the read's own stop (``ReadStop``) leaves when the read starts;
# the wait for an agent connection keeps the hub's own bound.
_REVIEWER_READ_SECONDS: Final = LOCAL_READ_SECONDS + 1.0
# Less time than this before a read's stop is no time at all: nothing is sent.
_MIN_READ_SECONDS: Final = 0.001
# Paths one ignored-path probe carries (the change capture's own requested-path bound).
_PROBE_BATCH: Final = 64
# The agent's answers that its read ran out of the time it was given: its own read stop, or the
# client's bound on the call. Either is the read's stop, as a slow local read raises it.
_AGENT_READ_DEADLINES: Final = frozenset({"read_deadline", "deadline_exceeded"})


def _reviewer_read_deadline(exc: WorkspaceAgentUnavailable) -> bool:
    """Whether a reviewer read ran out of its time (``ReadDeadline``), wherever it was cut.

    The agent may say so itself, or the hub may stop waiting for an answer that did not come
    within the time the read was given (``deadline_exceeded``): an agent whose worker has no
    timer of its own answers only once its Git or file read returns, and a slow link delivers
    even a timely answer late. Either way the read's stop has passed, as for a slow local read.
    """

    if exc.reason == "deadline_exceeded":
        return True
    return exc.reason == "agent_unavailable" and exc.agent_reason in _AGENT_READ_DEADLINES


def _until_stop(expired: Callable[[], bool], bound: float) -> float:
    """``bound``, but no longer than the read's own stop leaves; ``ReadDeadline`` once it passed.

    The reviewer loop's ``ReadStop`` knows the time left, so the agent is given exactly what a
    local read would still run for; any other ``expired`` is only asked whether it has passed.
    """

    left = expired.seconds_left() if isinstance(expired, ReadStop) else bound
    if left < _MIN_READ_SECONDS or expired():
        raise ReadDeadline("reviewer_read_deadline")
    return min(bound, left)


def _never() -> bool:
    return False


def _fenced(read: object) -> int:
    """The outside reads the client's agent fenced from a held repository (ADR-052 O7)."""

    count = getattr(read, "fenced", 0)
    return count if type(count) is int and count > 0 else 0


def _record_copy(operation: str) -> None:
    from finishup.observability.logging import record_bounded_event_without_raising

    record_bounded_event_without_raising(
        component="service.code_copy", operation=operation, reason=operation
    )


def client_bound(workspace: object) -> bool:
    """Whether ``workspace`` names a claim-bound task's workspace (its ``client:`` handle)."""

    return workspace_handle_valid(workspace)


def _call(
    hub: WorkspaceAgentHub | None,
    handle: str,
    operation: WorkspaceOperation,
    arguments: object,
    timeout_seconds: float,
) -> Any:  # noqa: ANN401 - the operation's own result type
    if hub is None:
        raise WorkspaceAgentUnavailable("hub_unavailable")
    # A long approved check plus its grace never asks for more than one call may wait; the agent
    # then ends the run early enough for its result, a timeout included, to arrive in time.
    bounded = min(timeout_seconds, MAX_WORKSPACE_DEADLINE_MS / 1000)
    return hub.call_blocking(handle, operation, arguments, timeout_seconds=bounded)


def _capture_call(
    hub: WorkspaceAgentHub | None,
    handle: str,
    operation: WorkspaceOperation,
    arguments: object,
) -> Any:  # noqa: ANN401 - the operation's own result type
    """A git-family call; an agent's own capture reason raises the local typed failure."""

    try:
        return _call(hub, handle, operation, arguments, _GIT_SECONDS)
    except WorkspaceAgentUnavailable as exc:
        reason = exc.agent_reason
        if reason is not None and reason in CHANGE_CAPTURE_UNAVAILABLE_REASONS:
            raise ChangeCaptureUnavailable(reason) from None
        raise


class RoutedChangeCapture:
    """``ChangeCapturePort`` plus its optional check-time extensions, routed per workspace.

    ``local`` is the service's own Git adapter; it serves every absolute workspace exactly as
    before and never sees a handle. ``lstat_probe`` stands in for the metadata-only ``lstat`` of
    outside-input candidates (``outside_inputs_not_admitted``): None keeps the local probe.
    """

    __slots__ = ("_hub", "_local")

    def __init__(self, local: ChangeCapturePort, hub: WorkspaceAgentHub | None) -> None:
        self._local = local
        self._hub = hub

    def __repr__(self) -> str:
        return "RoutedChangeCapture(<redacted>)"

    def _copies(self) -> CodeCopies | None:
        # A hub without the attribute (a stand-in) keeps no copies.
        return cast("CodeCopies | None", getattr(self._hub, "code_copies", None))

    def _from_copy(
        self,
        workspace: str,
        purpose: Literal["base", "check"],
        base: TaskChangeBase | None,
        read: Callable[[str, TaskChangeBase | None], Any],
    ) -> tuple[bool, Any]:
        """Level L2 (ADR-054): sync before an evidence-consuming git read, then serve it from
        the copy when the copy serves this task (``CodeCopies.git_view``); ``(False, None)``
        sends it to the client's agent. A checkout that cannot be made also does."""

        copies = self._copies()
        if copies is None:
            return False, None
        task = current_evidence_task()
        view, effective = copies.git_view(workspace, purpose=purpose, base=base, task_id=task)
        if view is None:
            return False, None
        commits = (
            ()
            if effective is None or effective.commit == view.manifest.base
            else (effective.commit,)
        )
        try:
            with copies.checkout(view, commits=commits) as folder:
                result = read(os.fspath(folder), effective)
        except ChangeCaptureUnavailable:
            copies.count(workspace, task, view.token)
            raise
        except Exception:  # noqa: BLE001 - a checkout that cannot be made: the client answers
            _record_copy("code_copy_read_failed")
            return False, None
        copies.count(workspace, task, view.token)
        return True, result

    def _client_count(self, workspace: str) -> None:
        copies = self._copies()
        if copies is not None:
            copies.count(workspace, current_evidence_task(), "client_attested_read")

    def _pinned(self, workspace: str, read: Callable[[str], Any]) -> tuple[bool, Any]:
        """A probe that follows a capture: served from the snapshot the task is pinned to when
        the copy serves the task (no sync), else ``(False, None)``."""

        copies = self._copies()
        if copies is None:
            return False, None
        task = current_evidence_task()
        view = copies.reader_view(workspace, task)
        if view is None:
            return False, None
        try:
            with copies.checkout(view) as folder:
                result = read(os.fspath(folder))
        except ChangeCaptureUnavailable:
            copies.count(workspace, task, view.token)
            raise
        except Exception:  # noqa: BLE001 - a checkout that cannot be made: the client answers
            _record_copy("code_copy_read_failed")
            return False, None
        copies.count(workspace, task, view.token)
        return True, result

    def read_task_base(self, workspace: str) -> TaskChangeBase:
        if not client_bound(workspace):
            return self._local.read_task_base(workspace)
        served, result = self._from_copy(
            workspace, "base", None, lambda folder, _base: self._local.read_task_base(folder)
        )
        if served:
            return cast(TaskChangeBase, result)
        found = _capture_call(
            self._hub,
            workspace,
            WorkspaceOperation.READ_TASK_BASE,
            WorkspaceOnlyArguments(workspace),
        )
        self._client_count(workspace)
        return cast(TaskChangeBase, found)

    def capture(
        self,
        workspace: str,
        base: TaskChangeBase | None,
        *,
        priority_paths: tuple[str, ...] = (),
        input_paths: tuple[str, ...] = (),
        space_cut_paths: frozenset[str] = frozenset(),
    ) -> CheckChangeCapture:
        # The exact call shape the caller made: a port without these options keeps working.
        options: dict[str, object] = {}
        if priority_paths:
            options["priority_paths"] = priority_paths
        if input_paths:
            options["input_paths"] = input_paths
        if space_cut_paths:
            options["space_cut_paths"] = space_cut_paths
        if not client_bound(workspace):
            return self._local.capture(workspace, base, **options)  # pyright: ignore[reportArgumentType]
        served, result = self._from_copy(
            workspace,
            "check",
            base,
            lambda folder, effective: self._local.capture(folder, effective, **options),  # pyright: ignore[reportArgumentType]
        )
        if served:
            return cast(CheckChangeCapture, result)
        found = _capture_call(
            self._hub,
            workspace,
            WorkspaceOperation.CAPTURE,
            CaptureArguments(workspace, base, priority_paths, input_paths, space_cut_paths),
        )
        self._client_count(workspace)
        return cast(CheckChangeCapture, found)

    def capture_metadata(self, workspace: str, base: TaskChangeBase | None) -> CheckChangeMetadata:
        if not client_bound(workspace):
            return self._local.capture_metadata(workspace, base)
        served, result = self._from_copy(
            workspace,
            "check",
            base,
            lambda folder, effective: self._local.capture_metadata(folder, effective),
        )
        if served:
            return cast(CheckChangeMetadata, result)
        found = _capture_call(
            self._hub,
            workspace,
            WorkspaceOperation.CAPTURE_METADATA,
            CaptureMetadataArguments(workspace, base),
        )
        self._client_count(workspace)
        return cast(CheckChangeMetadata, found)

    def probe_requested_paths(
        self, workspace: str, values: tuple[str, ...]
    ) -> tuple[RequestedPathProbe, ...]:
        if not client_bound(workspace):
            return self._local_extension("probe_requested_paths")(workspace, values)
        local = self._local_extension("probe_requested_paths")
        served, result = self._pinned(workspace, lambda folder: local(folder, values))
        if served:
            return cast(tuple[RequestedPathProbe, ...], result)
        found = _capture_call(
            self._hub,
            workspace,
            WorkspaceOperation.PROBE_REQUESTED_PATHS,
            ProbeRequestedPathsArguments(workspace, tuple(values)),
        )
        self._client_count(workspace)
        return cast(tuple[RequestedPathProbe, ...], found)

    def count_change_lines(
        self, workspace: str, base_commit: str, base_paths: tuple[str, ...]
    ) -> ChangeLineCounts:
        if not client_bound(workspace):
            return self._local_extension("count_change_lines")(workspace, base_commit, base_paths)
        local = self._local_extension("count_change_lines")
        served, result = self._pinned(
            workspace, lambda folder: local(folder, base_commit, base_paths)
        )
        if served:
            return cast(ChangeLineCounts, result)
        found = _capture_call(
            self._hub,
            workspace,
            WorkspaceOperation.COUNT_CHANGE_LINES,
            CountChangeLinesArguments(workspace, base_commit, tuple(base_paths)),
        )
        self._client_count(workspace)
        return cast(ChangeLineCounts, found)

    def classify_undeclared_references(
        self,
        workspace: str,
        deliverables: tuple[str, ...],
        candidates: tuple[str, ...],
        declared: tuple[str, ...] = (),
    ) -> tuple[tuple[int, int, str], ...]:
        if not client_bound(workspace):
            return self._local_extension("classify_undeclared_references")(
                workspace, deliverables, candidates, declared
            )
        local = self._local_extension("classify_undeclared_references")
        served, result = self._pinned(
            workspace, lambda folder: local(folder, deliverables, candidates, declared)
        )
        if served:
            return cast(tuple[tuple[int, int, str], ...], result)
        found = _capture_call(
            self._hub,
            workspace,
            WorkspaceOperation.CLASSIFY_UNDECLARED_REFERENCES,
            ClassifyUndeclaredReferencesArguments(
                workspace, tuple(deliverables), tuple(candidates), tuple(declared)
            ),
        )
        self._client_count(workspace)
        return cast(tuple[tuple[int, int, str], ...], found)

    def lstat_probe(self, workspace: str) -> Callable[[str], os.stat_result | None] | None:
        """The candidate ``lstat`` for a claim-bound workspace; None keeps the local one."""

        if not client_bound(workspace):
            return None
        hub = self._hub

        def probe(path: str) -> os.stat_result | None:
            if not path.startswith("/"):
                return None
            (found,) = cast(
                tuple[LstatFacts | None, ...],
                _call(
                    hub,
                    workspace,
                    WorkspaceOperation.LSTAT_CANDIDATES,
                    LstatCandidatesArguments((path,)),
                    _READ_SECONDS,
                ),
            )
            return None if found is None else found.to_stat_result()

        return probe

    def _local_extension(self, name: str) -> Callable[..., Any]:
        method = getattr(self._local, name, None)
        if not callable(method):
            # Exactly what the caller's own ``getattr`` on the local adapter would have met.
            raise AttributeError(name)
        return cast(Callable[..., Any], method)


class WorkspaceFileReads(Protocol):
    """The reviewer's and the check's reads beneath roots, as ``adapters.task_input_read``."""

    def list_beneath(
        self,
        root: str,
        relative: str,
        *,
        excluded: tuple[str, ...],
        expired: Callable[[], bool],
        inspect: int = 128,
    ) -> tuple[tuple[tuple[str, bool], ...], bool] | None: ...

    def read_text_beneath(
        self, root: str, relative: str, *, excluded: tuple[str, ...], expired: Callable[[], bool]
    ) -> tuple[bytes, int] | None: ...

    def read_declared_test(
        self, location: str, *, excluded: tuple[str, ...], expired: Callable[[], bool] = ...
    ) -> bytes | None: ...

    def read_outside_inputs(
        self,
        roots: tuple[str, ...],
        values: tuple[str, ...],
        *,
        limit: int = MAX_TASK_INPUT_FILES,
        excluded: tuple[str, ...] = (),
        space_cut: frozenset[str] = frozenset(),
    ) -> tuple[TaskInputFile, ...]: ...

    def snapshot_outside_inputs(
        self,
        roots: tuple[str, ...],
        values: tuple[str, ...],
        *,
        limit: int,
        max_bytes: int,
        seconds: float,
        excluded: tuple[str, ...] = (),
    ) -> tuple[OutsideSnapshotRead, ...]: ...


class ClientWorkspaceReads:
    """Every read of one claim-bound task, answered by the client's workspace agent.

    Roots and locations are absolute paths the task's content or the owner's policy named, or
    the task's handle standing for the claimed root; the agent resolves and confines them. A
    reviewer read the agent refused reads as nothing, exactly as a local read that found
    nothing. One that ran out of its time, on the client or while this service waited for the
    client's answer, raises ``ReadDeadline``, as a slow local read does, so the review ends
    ``deadline`` whatever the transport. Any other unanswered read (no agent, a busy or
    failed one, an answer too large to carry) raises ``WorkspaceAgentUnavailable``, and the
    review ends with that recorded reason: what the agent never read is never shown as absent.
    """

    __slots__ = ("_handle", "_hub")

    def __init__(self, hub: WorkspaceAgentHub | None, handle: str) -> None:
        if not workspace_handle_valid(handle):
            raise ValueError("workspace_handle_invalid")
        self._hub = hub
        self._handle = handle

    def __repr__(self) -> str:
        return "ClientWorkspaceReads(<redacted>)"

    # --- level L2: reads beneath the root from the copy (ADR-054) ----------------------------

    def _copies(self) -> CodeCopies | None:
        return cast("CodeCopies | None", getattr(self._hub, "code_copies", None))

    def _inside(self, value: str) -> bool:
        """Whether ``value`` names the claimed root or a location beneath it (by its handle)."""

        return value == self._handle or value.startswith(self._handle + "/")

    def _count(self, token: EvidenceToken, *, fenced: int = 0) -> None:
        copies = self._copies()
        if copies is not None:
            copies.count(self._handle, current_evidence_task(), token, fenced=fenced)

    def _copy_view(self, value: str) -> tuple[CodeCopies, CopyView] | None:
        """The copy and the task's pinned snapshot a read beneath the root is served from."""

        copies = self._copies()
        if copies is None or not self._inside(value):
            return None
        view = copies.reader_view(self._handle, current_evidence_task())
        return None if view is None else (copies, view)

    def _copy_excluded(self, excluded: Sequence[str], folder: str) -> tuple[str, ...]:
        """The read's exclusions in the checkout: this root's locations resolved there; an
        absolute one that holds the checkout (this service's own directories) is dropped, since
        the checkout is the root the read is confined to."""

        kept: list[str] = []
        for value in excluded:
            if value.startswith("/"):
                if not (folder + "/").startswith(value.rstrip("/") + "/"):
                    kept.append(value)
                continue
            if self._inside(value):
                resolved = resolve_client_location(value, self._handle, folder)
                if resolved is not None:
                    kept.append(resolved)
        return tuple(kept)

    def _from_copy(self, value: str, read: Callable[[str], Any]) -> tuple[bool, Any]:
        found = self._copy_view(value)
        if found is None:
            return False, None
        copies, view = found
        try:
            with copies.checkout(view) as folder:
                result = read(os.fspath(folder))
        except ReadDeadline:
            copies.count(self._handle, current_evidence_task(), view.token)
            raise
        except Exception:  # noqa: BLE001 - a checkout that cannot be made: the client answers
            _record_copy("code_copy_read_failed")
            return False, None
        copies.count(self._handle, current_evidence_task(), view.token)
        return True, result

    def _client_token(self, value: str) -> EvidenceToken:
        return "client_attested_read" if self._inside(value) else "outside_read"

    def _read(
        self, operation: WorkspaceOperation, arguments: object, seconds: float = _READ_SECONDS
    ) -> Any:  # noqa: ANN401
        try:
            return _call(self._hub, self._handle, operation, arguments, seconds)
        except WorkspaceAgentUnavailable as exc:
            if _reviewer_read_deadline(exc):
                raise ReadDeadline("reviewer_read_deadline") from None
            if exc.refused:
                return None
            raise

    def refused_paths(
        self, paths: tuple[str, ...], expired: Callable[[], bool] = _never
    ) -> frozenset[str]:
        """The workspace-relative ``paths`` a reviewer may not read: Git-ignored, or unanswerable.

        The reviewer's ignored-path rule for this workspace, asked of the agent in batches of
        ``probe_requested_paths`` within the reviewer's own read budget and the read's stop
        (``expired``, checked before every batch), rather than once per listed entry. As the
        per-path rule: an empty path (the root) is never refused, and a path
        Git cannot answer for (the agent refused the probe, or answered with one of change
        capture's own reasons) is refused. A probe that ran out of its time raises
        ``ReadDeadline``; an agent that is gone, busy or failed raises
        ``WorkspaceAgentUnavailable``, so the review ends on it rather than on a listing that
        silently left out every entry of the batch.
        """

        wanted = tuple(dict.fromkeys(path for path in paths if path))
        if self._copy_view(self._handle) is not None:
            # Level L2: every file of the copy is one Git showed the client (ignored files were
            # never sent), so nothing it holds is refused; what it lacks reads as nothing.
            return frozenset()
        refused: set[str] = set()
        for start in range(0, len(wanted), _PROBE_BATCH):
            batch = wanted[start : start + _PROBE_BATCH]
            seconds = _until_stop(expired, _REVIEWER_READ_SECONDS)
            try:
                found = cast(
                    tuple[RequestedPathProbe, ...],
                    _call(
                        self._hub,
                        self._handle,
                        WorkspaceOperation.PROBE_REQUESTED_PATHS,
                        ProbeRequestedPathsArguments(self._handle, batch),
                        seconds,
                    ),
                )
            except WorkspaceAgentUnavailable as exc:
                if _reviewer_read_deadline(exc):
                    raise ReadDeadline("reviewer_read_deadline") from None
                if exc.refused or (
                    exc.reason == "agent_unavailable"
                    and exc.agent_reason in CHANGE_CAPTURE_UNAVAILABLE_REASONS
                ):
                    refused.update(batch)  # Git cannot say: refused, as locally
                    continue
                raise
            except Exception:  # noqa: BLE001 - an unanswerable ignore state refuses the read
                refused.update(batch)
                continue
            if type(found) is not tuple or len(found) != len(batch):
                refused.update(batch)  # not an answer for these paths: refused, never guessed
                continue
            refused.update(path for path, probe in zip(batch, found) if probe.ignored is not False)
        return frozenset(refused)

    def list_beneath(
        self,
        root: str,
        relative: str,
        *,
        excluded: tuple[str, ...],
        expired: Callable[[], bool],
        inspect: int = 128,
    ) -> tuple[tuple[tuple[str, bool], ...], bool] | None:
        served, result = self._from_copy(
            root,
            lambda folder: _local_list_beneath(
                cast(str, resolve_client_location(root, self._handle, folder)),
                relative,
                excluded=self._copy_excluded(excluded, folder),
                expired=expired,
                inspect=inspect,
            ),
        )
        if not served:
            result = self._read(
                WorkspaceOperation.LIST_BENEATH,
                ListBeneathArguments(root, relative, tuple(excluded), inspect),
                _until_stop(expired, _REVIEWER_READ_SECONDS),
            )
            self._count(self._client_token(root))
        return cast(tuple[tuple[tuple[str, bool], ...], bool] | None, result)

    def read_text_beneath(
        self, root: str, relative: str, *, excluded: tuple[str, ...], expired: Callable[[], bool]
    ) -> tuple[bytes, int] | None:
        served, result = self._from_copy(
            root,
            lambda folder: _local_read_text_beneath(
                cast(str, resolve_client_location(root, self._handle, folder)),
                relative,
                excluded=self._copy_excluded(excluded, folder),
                expired=expired,
            ),
        )
        if not served:
            result = self._read(
                WorkspaceOperation.READ_TEXT_BENEATH,
                ReadTextBeneathArguments(root, relative, tuple(excluded)),
                _until_stop(expired, _REVIEWER_READ_SECONDS),
            )
            self._count(self._client_token(root))
        return cast(tuple[bytes, int] | None, result)

    def _copy_declared_test(self, location: str, excluded: tuple[str, ...]) -> tuple[bool, Any]:
        """A declared test beneath the root, read from the copy as the local read returns it:
        UTF-8 text of at most 1 MiB with no NUL byte, else nothing."""

        def read(folder: str) -> bytes | None:
            resolved = resolve_client_location(location, self._handle, folder)
            if resolved is None or resolved == folder:
                return None
            relative = resolved[len(folder) + 1 :]
            found = _local_read_text_beneath(
                folder, relative, excluded=self._copy_excluded(excluded, folder), expired=_never
            )
            if found is None:
                return None
            data, size = found
            if not data or size != len(data) or b"\0" in data:
                return None
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                return None
            return data

        return self._from_copy(location, read)

    def read_declared_test(
        self,
        location: str,
        *,
        excluded: tuple[str, ...],
        expired: Callable[[], bool] = _never,
    ) -> bytes | None:
        served, result = self._copy_declared_test(location, excluded)
        if served:
            return cast(bytes | None, result)
        try:
            found = cast(
                bytes | None,
                self._read(
                    WorkspaceOperation.READ_DECLARED_TEST,
                    ReadDeclaredTestArguments(location, tuple(excluded)),
                    _until_stop(expired, _READ_SECONDS),
                ),
            )
        except ReadDeadline:
            # As the local read: a declared test not read within its stop is not visible.
            return None
        self._count(self._client_token(location))
        return found

    def declared_test(self, location: str, *, excluded: tuple[str, ...]) -> bytes | None:
        """``read_declared_test`` that lets the agent's refusal through.

        A refusal is ``WorkspaceAgentUnavailable`` (``agent_refused``, with the agent's closed
        reason), so the caller can tell a test the owner did not let this server read
        (``root_not_admitted``, ADR-051 decision 5) from one that could not be read.
        """

        served, result = self._copy_declared_test(location, excluded)
        if served:
            return cast(bytes | None, result)
        found = cast(
            bytes | None,
            _call(
                self._hub,
                self._handle,
                WorkspaceOperation.READ_DECLARED_TEST,
                ReadDeclaredTestArguments(location, tuple(excluded)),
                _READ_SECONDS,
            ),
        )
        self._count(self._client_token(location))
        return found

    def outside_inputs(
        self,
        roots: tuple[str, ...],
        values: tuple[str, ...],
        *,
        limit: int = MAX_TASK_INPUT_FILES,
        excluded: tuple[str, ...] = (),
        space_cut: frozenset[str] = frozenset(),
    ) -> OutsideInputsRead:
        """The agent's whole answer: the inputs it read, and the indices of ``values`` it left
        unread because its owner did not list them for this server (ADR-051 decision 5)."""

        found = cast(
            OutsideInputsRead,
            _call(
                self._hub,
                self._handle,
                WorkspaceOperation.READ_OUTSIDE_INPUTS,
                ReadOutsideInputsArguments(
                    tuple(roots), tuple(values), limit, tuple(excluded), frozenset(space_cut)
                ),
                _READ_SECONDS,
            ),
        )
        # Outside the root: the client's agent answers, under its outside-read policy, and says
        # how many it fenced from a held repository (ADR-052 O7).
        self._count("outside_read", fenced=_fenced(found))
        return found

    def read_outside_inputs(
        self,
        roots: tuple[str, ...],
        values: tuple[str, ...],
        *,
        limit: int = MAX_TASK_INPUT_FILES,
        excluded: tuple[str, ...] = (),
        space_cut: frozenset[str] = frozenset(),
    ) -> tuple[TaskInputFile, ...]:
        return self.outside_inputs(
            roots, values, limit=limit, excluded=excluded, space_cut=space_cut
        ).inputs

    def outside_snapshots(
        self,
        roots: tuple[str, ...],
        values: tuple[str, ...],
        *,
        limit: int,
        max_bytes: int,
        seconds: float,
        excluded: tuple[str, ...] = (),
    ) -> OutsideSnapshotsRead:
        """The agent's whole snapshot answer, ``unlisted`` included (``outside_inputs``)."""

        budget_ms = max(0, int(seconds * 1000))
        found = cast(
            OutsideSnapshotsRead,
            _call(
                self._hub,
                self._handle,
                WorkspaceOperation.SNAPSHOT_OUTSIDE_INPUTS,
                SnapshotOutsideInputsArguments(
                    tuple(roots), tuple(values), limit, max_bytes, budget_ms, tuple(excluded)
                ),
                seconds + _SNAPSHOT_GRACE_SECONDS,
            ),
        )
        self._count("outside_read", fenced=_fenced(found))
        return found

    def snapshot_outside_inputs(
        self,
        roots: tuple[str, ...],
        values: tuple[str, ...],
        *,
        limit: int,
        max_bytes: int,
        seconds: float,
        excluded: tuple[str, ...] = (),
    ) -> tuple[OutsideSnapshotRead, ...]:
        """Rows only: a value the owner did not list is not kept, as one that could not be read
        is not (a later check reports it, ``outside_reads_not_listed``)."""

        return self.outside_snapshots(
            roots, values, limit=limit, max_bytes=max_bytes, seconds=seconds, excluded=excluded
        ).reads


@dataclass(frozen=True, slots=True)
class WorkspaceRouting:
    """The ready application's one routing point: the capture port and the per-task readers.

    ``hub`` is None only in an application composed without a daemon; a claim-bound read then
    fails as ``hub_unavailable`` and is recorded as a gap, never served from this disk. A local
    task's reads stay with each caller's own trusted readers (``reads_for`` answers None).
    """

    hub: WorkspaceAgentHub | None
    change_capture: RoutedChangeCapture

    @classmethod
    def compose(
        cls, hub: WorkspaceAgentHub | None, local_capture: ChangeCapturePort
    ) -> WorkspaceRouting:
        return cls(hub, RoutedChangeCapture(local_capture, hub))

    def reads_for(self, workspace: str | None) -> ClientWorkspaceReads | None:
        """The agent's readers for a claim-bound task's ``workspace``; None for a local one."""

        if workspace is not None and client_bound(workspace):
            return ClientWorkspaceReads(self.hub, workspace)
        return None

    def reads_excluding(self, excluded: Sequence[str]) -> ClientWorkspaceReads | None:
        """``reads_for`` the workspace a read names first among its exclusions (the readers'
        convention: the task's workspace, then this service's own directories)."""

        return self.reads_for(excluded[0] if excluded else None)


# --- observation verification (T11) and approved checks (T12) ------------------------------

_OBSERVATION_SECONDS: Final = 60.0
_CHECK_GRACE_SECONDS: Final = 30.0


class _ClientOpenedWorkspace:
    """Held inside a ``LocalWorkspaceHandle``: a claim-bound workspace its agent opened.

    ``workspace`` is the claim handle (the route to the agent), ``opened`` the agent's own
    opaque handle for the workspace it opened. Neither is a path on this machine. Several
    connections of one client may serve the same claim, and an agent may restart: an agent that
    does not know ``opened`` answers ``handle_unknown``, and ``_opened_call`` then opens the
    workspace again on the agent now serving the claim and keeps its new handle here.
    """

    __slots__ = ("opened", "workspace")

    workspace: str
    opened: str

    def __init__(self, workspace: str, opened: str) -> None:
        self.workspace = workspace
        self.opened = opened

    def __repr__(self) -> str:
        return "_ClientOpenedWorkspace(<redacted>)"


def _client_opened(handle: LocalWorkspaceHandle) -> _ClientOpenedWorkspace | None:
    descriptor = handle._validated_descriptor()  # pyright: ignore[reportPrivateUsage]
    return descriptor if type(descriptor) is _ClientOpenedWorkspace else None


def _observation_call(
    hub: WorkspaceAgentHub | None,
    handle: str,
    operation: WorkspaceOperation,
    arguments: object,
    timeout_seconds: float = _OBSERVATION_SECONDS,
) -> Any:  # noqa: ANN401 - the operation's own result type
    return _call(hub, handle, operation, arguments, timeout_seconds)


def _open_on_agent(hub: WorkspaceAgentHub | None, workspace: str) -> str:
    return cast(
        str,
        _observation_call(
            hub,
            workspace,
            WorkspaceOperation.OPEN_WORKSPACE,
            OpenWorkspaceArguments(workspace, admitted_home_project=True),
            _READ_SECONDS,
        ),
    )


def _opened_call(
    hub: WorkspaceAgentHub | None,
    client: _ClientOpenedWorkspace,
    operation: WorkspaceOperation,
    arguments: Callable[[str], object],
    timeout_seconds: float = _OBSERVATION_SECONDS,
) -> Any:  # noqa: ANN401 - the operation's own result type
    """One call naming the agent-opened workspace; reopened once if the agent forgot it.

    The agent answering may not be the one that opened the workspace (another connection of the
    same client now serves the claim, or the agent restarted). It says ``handle_unknown``, and
    the workspace is opened again on it, exactly as first opened, before the call is retried
    once. Every other outcome is the call's own.
    """

    try:
        return _observation_call(
            hub, client.workspace, operation, arguments(client.opened), timeout_seconds
        )
    except WorkspaceAgentUnavailable as exc:
        if exc.agent_reason != "handle_unknown":
            raise
    client.opened = _open_on_agent(hub, client.workspace)
    return _observation_call(
        hub, client.workspace, operation, arguments(client.opened), timeout_seconds
    )


def _opened_from_copy(
    hub: WorkspaceAgentHub | None, client: _ClientOpenedWorkspace, read: Callable[[str], Any]
) -> tuple[bool, Any]:
    """Level L2: an opened workspace's changed paths and inspection, from the snapshot the task
    is pinned to when the copy serves the task; ``(False, None)`` asks the client's agent."""

    copies = cast("CodeCopies | None", getattr(hub, "code_copies", None))
    if copies is None:
        return False, None
    task = current_evidence_task()
    view = copies.reader_view(client.workspace, task)
    if view is None:
        return False, None
    try:
        with copies.checkout(view) as folder:
            result = read(os.fspath(folder))
    except Exception:  # noqa: BLE001 - a checkout that cannot be made: the client answers
        _record_copy("code_copy_read_failed")
        return False, None
    copies.count(client.workspace, task, view.token)
    return True, result


def _count_client(hub: WorkspaceAgentHub | None, workspace: str) -> None:
    copies = cast("CodeCopies | None", getattr(hub, "code_copies", None))
    if copies is not None:
        copies.count(workspace, current_evidence_task(), "client_attested_read")


class _RoutedSubjectState:
    """``SubjectStateCapturePort``: a client-opened workspace is hashed by its agent."""

    __slots__ = ("_hub", "_local")

    def __init__(self, hub: WorkspaceAgentHub | None, local: SubjectStateCapturePort) -> None:
        self._hub = hub
        self._local = local

    def capture(self, command: SubjectStateCaptureCommand) -> SubjectStateCaptureResult:
        client = _client_opened(command.workspace)
        if client is None:
            return self._local.capture(command)
        return cast(
            SubjectStateCaptureResult,
            _opened_call(
                self._hub,
                client,
                WorkspaceOperation.SUBJECT_STATE_CAPTURE,
                lambda opened: SubjectStateCaptureArguments(opened, command.expected_format),
            ),
        )


class _RoutedInspect:
    """``WorkspaceInspectPort``: a client-opened workspace is inspected by its agent."""

    __slots__ = ("_hub", "_local")

    def __init__(self, hub: WorkspaceAgentHub | None, local: WorkspaceInspectPort) -> None:
        self._hub = hub
        self._local = local

    def inspect(self, command: WorkspaceInspectCommand) -> WorkspaceInspectResult:
        client = _client_opened(command.workspace)
        if client is None:
            return self._local.inspect(command)
        local = self._local
        served, result = _opened_from_copy(
            self._hub,
            client,
            lambda folder: local.inspect(
                replace(command, workspace=LocalObservationWorkspace().open(folder))
            ),
        )
        if served:
            return cast(WorkspaceInspectResult, result)
        found = cast(
            WorkspaceInspectResult,
            _opened_call(
                self._hub,
                client,
                WorkspaceOperation.INSPECT,
                lambda opened: InspectArguments(opened, command.relative_paths),
            ),
        )
        _count_client(self._hub, client.workspace)
        return found


class RoutedApprovedCheckRunner(ApprovedCheckRunner):
    """An approved check of a client-opened workspace runs on the client, by its agent.

    The service still decides first, exactly as its own runner does and before anything is
    sent: an approval this policy does not hold, a stale subject state or a network request is
    refused here. The agent then runs the argv only when its own copy of the owner-approved
    policy holds the same approval; its redacted output reaches this runner's output sink.

    Level L2 (ADR-054, design v2 §8.6): a check of a task whose evidence the server reads from
    its copy is pinned to the copy too. The copy is synced first, so the task's pin names the
    snapshot of the tree the check runs on; a check whose subject state differs from that
    snapshot's subject-state commitment ran against another subject than the server read, and
    its result is ``stale`` / ``subject_state_mismatch`` (recorded as ``code_snapshot_mismatch``),
    never a pass. A client that is offline cannot run it: ``workspace_agent_unavailable``.
    """

    def __init__(
        self, approvals: Mapping[str, ApprovedCheckApproval], hub: WorkspaceAgentHub | None
    ) -> None:
        super().__init__(approvals)
        self._hub = hub
        self._task: str | None = None

    def bind_evidence_task(self, task_id: str | None) -> None:
        """The task whose evidence this runner's checks are (``evidence_task_scope`` otherwise)."""

        self._task = task_id

    def _copy_pin(self, workspace: str) -> tuple[CodeCopies, str] | None:
        """Sync a copy task's copy before its check; the copies and the task, or None."""

        copies = cast("CodeCopies | None", getattr(self._hub, "code_copies", None))
        task = current_evidence_task() or self._task
        if copies is None or task is None:
            return None
        pinned = copies.pinned_manifest(workspace, task)
        if pinned is None:
            return None
        original = None if set(pinned.original_base) == {"0"} else pinned.original_base
        copies.sync_blocking(workspace, purpose="check", base_commit=original, task_id=task)
        return copies, task

    def _against_copy(
        self, workspace: str, pin: tuple[CodeCopies, str] | None, result: ApprovedCheckResult
    ) -> ApprovedCheckResult:
        if pin is None:
            return result
        copies, task = pin
        copies.count(workspace, task, "client_check")
        if result.status in {ApprovedCheckStatus.REJECTED, ApprovedCheckStatus.STALE}:
            return result
        manifest = copies.pinned_manifest(workspace, task)
        if manifest is not None and manifest.subject_state == result.subject_state_digest:
            return result
        _record_copy("code_snapshot_mismatch")
        return self._result(
            ApprovedCheckStatus.STALE,
            ApprovedCheckOutcome.SUBJECT_STATE_MISMATCH,
            None,
            None,
            0,
            result.subject_state_digest,
            result.approval_commitment,
            result.duration_ms,
        )

    def run(self, command: ApprovedCheckCommand) -> ApprovedCheckResult:
        if type(command) is not ApprovedCheckCommand:
            return super().run(command)
        client = _client_opened(command.workspace)
        approval = command.approval
        registered = self._approvals.get(approval.approval_commitment)
        if (
            client is None
            or registered is None
            or registered != approval
            or (
                command.expected_subject_state_digest is not None
                and command.expected_subject_state_digest != command.subject_state_digest
            )
            or approval.allow_network
        ):
            # Every one of these is decided before a workspace is touched.
            return super().run(command)
        pin = self._copy_pin(client.workspace)
        run = cast(
            ApprovedCheckRun,
            _opened_call(
                self._hub,
                client,
                WorkspaceOperation.RUN_APPROVED_CHECK,
                lambda opened: RunApprovedCheckArguments(
                    opened,
                    approval,
                    command.subject_state_digest,
                    command.expected_subject_state_digest,
                ),
                approval.timeout_seconds + _CHECK_GRACE_SECONDS,
            ),
        )
        sink = self._output_sink
        if run.output is not None and sink is not None:
            sink(run.output, run.output_redacted)
        return self._against_copy(client.workspace, pin, run.result)


class RoutedObservationWorkspace:
    """``ObservationWorkspaceAccess``: a ``client:`` locator is read by its client's agent.

    Any other locator reads this machine through ``local``, unchanged. The service never
    resolves a handle to a path: the agent opens its own claimed root and returns an opaque
    handle for it, which only that agent can use.
    """

    __slots__ = ("_hub", "_local")

    def __init__(
        self, hub: WorkspaceAgentHub | None, local: ObservationWorkspaceAccess | None = None
    ) -> None:
        self._hub = hub
        self._local: ObservationWorkspaceAccess = (
            LocalObservationWorkspace() if local is None else local
        )

    def __repr__(self) -> str:
        return "RoutedObservationWorkspace(<redacted>)"

    def open(self, locator: str) -> LocalWorkspaceHandle:
        if not client_bound(locator):
            return self._local.open(locator)
        return LocalWorkspaceHandle._from_validated_descriptor(  # pyright: ignore[reportPrivateUsage]
            _ClientOpenedWorkspace(locator, _open_on_agent(self._hub, locator))
        )

    def load_policy(self, locator: str) -> tuple[ObservationCheckPolicy, bytes]:
        if not client_bound(locator):
            return self._local.load_policy(locator)
        try:
            read = cast(
                CheckPolicyRead,
                _observation_call(
                    self._hub,
                    locator,
                    WorkspaceOperation.LOAD_CHECK_POLICY,
                    WorkspaceOnlyArguments(locator),
                    _READ_SECONDS,
                ),
            )
        except WorkspaceAgentUnavailable as exc:
            # The agent's policy answers keep the local loader's exact typed outcomes.
            if exc.agent_reason == "policy_absent":
                raise ObservationCheckPolicyAbsent() from None
            if exc.agent_reason == "policy_ambiguous":
                raise ObservationCheckPolicyAmbiguous() from None
            if exc.agent_reason == "policy_invalid":
                raise ProtocolValueError("invalid_approved_check_policy") from None
            raise
        source = CHECK_POLICY_PATH if read.location == "current" else LEGACY_CHECK_POLICY_PATH
        return replace(parse_observation_check_policy(read.raw), source_path=source), read.raw

    def subject_state(self) -> SubjectStateCapturePort:
        return _RoutedSubjectState(self._hub, self._local.subject_state())

    def list_changed(self, workspace: LocalWorkspaceHandle) -> tuple[str, ...]:
        client = _client_opened(workspace)
        if client is None:
            return self._local.list_changed(workspace)
        local = self._local
        served, result = _opened_from_copy(
            self._hub, client, lambda folder: local.list_changed(local.open(folder))
        )
        if served:
            return cast(tuple[str, ...], result)
        found = cast(
            tuple[str, ...],
            _opened_call(
                self._hub,
                client,
                WorkspaceOperation.LIST_CHANGED_PATHS,
                ListChangedPathsArguments,
            ),
        )
        _count_client(self._hub, client.workspace)
        return found

    def inspect_port(self) -> WorkspaceInspectPort:
        return _RoutedInspect(self._hub, self._local.inspect_port())

    def runner(self, approvals: Mapping[str, ApprovedCheckApproval]) -> ApprovedCheckRunner:
        return RoutedApprovedCheckRunner(approvals, self._hub)
