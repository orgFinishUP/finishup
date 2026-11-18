"""Ask this computer's everyday FinishUP what one repository's own privacy policy says.

ADR-051 decision 8, maintainer decision of 2026-11-07, round 4. A repository whose own grant on
this computer composes to no network egress is held from a server elsewhere
(``client.repository_hold``); what this computer's everyday FinishUP last said about each
repository is its report (``client.everyday_policy``). This module makes and records those
reports:

* ``read_everyday_repository`` asks the running everyday service, over one connection bound to
  the repository's worktree, for the machine-scope policy (recorded as the zero-network marker)
  and for the repository's setup view (``privacy_get_setup`` 2.0.0, whose ``grant_state`` and
  ``composed_policy`` say what its own grant allows). It never starts or supersedes a service: a
  stopped or locked service fails the connection at once, and the read is bounded by its budget.
  While the machine row forbids all network use the repository's own grant cannot be told apart,
  so its entry is forgotten (it becomes unknown, and is read again later) and the zero-network
  refusal governs. A computer whose everyday FinishUP was never set up has no policy: both
  records are removed.
* ``remember_repository_setup`` records a setup view this computer's service already gave a
  client command on its everyday root (the privacy ceremonies, ``provider status``): nothing is
  asked twice.
* ``report_needs_refresh`` says when a session start should ask: no entry for the repository,
  one older than ``REPORT_REFRESH_SECONDS``, or one older than the last machine report.

Every read and record here is dormant until this computer records a server elsewhere (a remote
target, selected or not; ADR-052, the owner's answer O3): before then nothing is asked or written,
and there is no report from before then. Unknown is never held: an isolation variable or pin, a
read that fails, a setup view that cannot be classified, or a timeout records nothing. The everyday installation is read under
``selection_override(None)``, context-local, so a process whose own selection names a server
elsewhere still asks this computer's own FinishUP, and nothing outside the read sees it.

This module imports only the standard library and lean SHARED modules, so a hook may import it;
the workspace-root adapter, the service client and the machine-scope request load only when a
read runs. Plain ``asyncio``: no CLI framework.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import posixpath
from collections.abc import Awaitable, Callable, Coroutine, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final, Literal, Protocol, cast

from finishup.client.everyday_policy import (
    CLI_LOCK_WAIT_SECONDS,
    ReportedPolicy,
    everyday_scope,
    forget_repository_reports,
    read_marker,
    read_repository_reports,
    record_reported_policy,
    record_repository_report,
    remove_marker,
    remove_repository_reports,
    repository_report,
)
from finishup.client.repository_hold import repository_key

if TYPE_CHECKING:
    from finishup.domain.values import JsonObject
    from finishup.ports.control import ControlClientKind, WorkspaceLocator

__all__ = [
    "CLI_READ_SECONDS",
    "HOOK_READ_SECONDS",
    "REPORT_REFRESH_SECONDS",
    "EverydayReads",
    "MachineState",
    "RepositoryState",
    "classify_setup",
    "everyday_installation_exists",
    "read_everyday_repository",
    "refresh_at_session_start",
    "remember_repository_setup",
    "report_needs_refresh",
    "repository_key_for",
    "session_start_hold_phase",
]

type MachineState = Literal["zero_network", "network_permitted", "no_policy", "unreadable"]
type RepositoryState = Literal["no_network", "network_permitted", "no_policy", "unreadable"]

# The live read's budget in a hook pass and in a CLI command.
HOOK_READ_SECONDS: Final = 0.5
CLI_READ_SECONDS: Final = 3.0
# A session start asks again for a report older than this, even when nothing else changed.
REPORT_REFRESH_SECONDS: Final = 24 * 60 * 60
# Written once, when the everyday installation's vault is initialized.
_INSTALLATION_MARKER: Final = "installation-state.json"
_SETUP_REQUEST: Final[Mapping[str, str]] = {"schema_version": "2.0.0"}


class _PrivacyClient(Protocol):
    async def privacy_get_effective(self, request: JsonObject) -> object: ...

    async def privacy_get_setup(self, request: JsonObject) -> object: ...

    async def close(self) -> None: ...


type Connect = Callable[..., Awaitable[_PrivacyClient]]


@dataclass(frozen=True, slots=True)
class EverydayReads:
    """What one live read learned: this computer's machine-scope state and the repository's."""

    machine: MachineState
    repository: RepositoryState


_UNREADABLE: Final = EverydayReads("unreadable", "unreadable")


def everyday_installation_exists() -> bool:
    """Whether this computer's everyday FinishUP was set up (its vault initialized).

    Call it under ``selection_override(None)``. Anything that keeps the answer from being known
    fails closed: it counts as set up.
    """

    from finishup.config.load import load_config
    from finishup.config.models import ConfigError
    from finishup.config.paths import PathSafetyError, bundle_root

    try:
        config = load_config({}, os.environ, None)
        (bundle_root(_data_dir=config.storage.data_dir) / _INSTALLATION_MARKER).lstat()
    except FileNotFoundError:
        return False
    except (ConfigError, OSError, PathSafetyError):
        return True
    return True


def _machine_request() -> JsonObject:
    from finishup.cli.provider_status import machine_scope_request

    return machine_scope_request()


async def _connect(kind: ControlClientKind, *, workspace_locator: WorkspaceLocator) -> object:
    from finishup.service.client import connect_service

    return await connect_service(kind, workspace_locator=workspace_locator)


def classify_setup(setup: object) -> Literal["no_network", "network_permitted"] | None:
    """What a ``privacy_get_setup`` 2.0.0 view says of the repository's own grant, or None.

    ``no_network``: the repository has its own grant (``granted``) and the policy it composes to
    allows no network egress. ``network_permitted``: a repository with no grant (``missing``,
    which inherits this computer's row and is never held) or one whose grant permits it. Only
    meaningful while the machine row permits network use: otherwise a forbidding composition
    cannot be told apart from the machine's own.
    """

    if not isinstance(setup, Mapping):
        return None
    fields = cast(Mapping[str, object], setup)
    state = fields.get("grant_state")
    policy = fields.get("composed_policy")
    if fields.get("schema_version") != "2.0.0" or not isinstance(policy, Mapping):
        return None
    permitted = cast(Mapping[str, object], policy).get("network_egress_permitted")
    if type(permitted) is not bool or state not in {"granted", "missing"}:
        return None
    if state == "granted" and not permitted:
        return "no_network"
    return "network_permitted"


def _machine_permits(effective: object) -> bool | None:
    if not isinstance(effective, Mapping):
        return None
    policy = cast(Mapping[str, object], effective).get("policy")
    if not isinstance(policy, Mapping):
        return None
    permitted = cast(Mapping[str, object], policy).get("network_egress_permitted")
    return permitted if type(permitted) is bool else None


def _worktree(locator: str) -> str | None:
    if type(locator) is not str or not locator.startswith("/"):
        return None
    worktree = posixpath.normpath(locator)
    return None if worktree == "/" else worktree


async def repository_key_for(worktree: str) -> str | None:
    """The report key of the repository at ``worktree``; None when it cannot be resolved."""

    from finishup.adapters.workspace_root import RepositoryIdentityError, canonical_workspace_root
    from finishup.ports.control import WorkspaceLocator

    try:
        return repository_key(await canonical_workspace_root(WorkspaceLocator(worktree)))
    except (RepositoryIdentityError, OSError, ValueError):
        return None


async def read_everyday_repository(
    locator: str,
    *,
    budget_seconds: float = CLI_READ_SECONDS,
    lock_wait_seconds: float = CLI_LOCK_WAIT_SECONDS,
    connect: Connect | None = None,
    installation_exists: Callable[[], bool] | None = None,
    machine_request: Callable[[], JsonObject] | None = None,
    now: datetime | None = None,
    key: str | None = None,
) -> EverydayReads:
    """Ask this computer's everyday FinishUP about the repository whose worktree is ``locator``.

    ``locator`` is the worktree's top (absolute, normal); ``key`` its report key when the caller
    already derived it. Records what it learns and returns it; never raises (see the module
    text). Runs on the caller's event loop: call it in a fresh ``contextvars`` context, so its
    ``selection_override(None)`` stays its own. Dormant until a server elsewhere is recorded
    (``_hold_active``, O3): before then nothing is asked or recorded, on any surface, and the
    answer is ``unreadable``.
    """

    from finishup.config.paths import PathSafetyError, selection_override
    from finishup.ports.control import ControlClientKind, WorkspaceLocator

    worktree = _worktree(locator)
    if worktree is None or not everyday_scope() or not _hold_active():
        return _UNREADABLE
    try:
        with selection_override(None):
            if not (installation_exists or everyday_installation_exists)():
                remove_marker()
                remove_repository_reports()
                return EverydayReads("no_policy", "no_policy")
            try:
                request = (machine_request or _machine_request)()
            except Exception:  # noqa: BLE001 - MachineScopeError and friends: not readable now
                return _UNREADABLE
            if key is None:
                key = await repository_key_for(worktree)
            if key is None:
                return _UNREADABLE
            dial = connect or cast(Connect, _connect)
            async with asyncio.timeout(max(0.0, budget_seconds)):
                client = await dial(
                    ControlClientKind.CLI, workspace_locator=WorkspaceLocator(worktree)
                )
                try:
                    effective = await client.privacy_get_effective(request)
                    from finishup.domain.values import JsonObject

                    setup = await client.privacy_get_setup(JsonObject(dict(_SETUP_REQUEST)))
                finally:
                    with contextlib.suppress(Exception):
                        await client.close()
    except (TimeoutError, OSError, ValueError, PathSafetyError):
        return _UNREADABLE
    except Exception:  # noqa: BLE001 - ControlError, decode failures: unknown is not held
        return _UNREADABLE
    permitted = _machine_permits(effective)
    if permitted is None:
        return _UNREADABLE
    record_reported_policy(zero_network=not permitted, now=now)
    if not permitted:
        # The repository's own grant cannot be told apart while this computer forbids all
        # network use: what was said of it no longer holds, and the zero-network refusal governs.
        forget_repository_reports([key], lock_wait_seconds=lock_wait_seconds)
        return EverydayReads("zero_network", "unreadable")
    state = classify_setup(setup)
    if state is None:
        return EverydayReads("network_permitted", "unreadable")
    record_repository_report(
        key,
        worktree,
        no_network=state == "no_network",
        now=now,
        lock_wait_seconds=lock_wait_seconds,
    )
    return EverydayReads("network_permitted", state)


async def remember_repository_setup(
    locator: str | os.PathLike[str],
    setup: object,
    *,
    now: datetime | None = None,
    lock_wait_seconds: float = CLI_LOCK_WAIT_SECONDS,
) -> bool:
    """Record a setup view this computer's everyday FinishUP just gave for ``locator``'s repository.

    Only for a process on the everyday root (no isolation variable or pin, no server selected
    for it), and only once a server elsewhere is recorded (``_hold_active``): a server elsewhere,
    or a named local one, answers for its own policy. A repository
    with no grant, or one whose grant permits network use, is recorded as such. One whose grant
    composes to no network egress is recorded only while the last machine report says this
    computer permits network use; while it says zero-network the entry is forgotten; with no
    machine report it is left as it is. Returns whether the record changed; never raises.
    """

    from finishup.adapters.workspace_binding import canonical_workspace_locator
    from finishup.config.paths import PathSafetyError, active_root

    try:
        if not everyday_scope() or active_root() is not None or not _hold_active():
            return False
        worktree = canonical_workspace_locator(os.fspath(locator))
    except (PathSafetyError, OSError, ValueError):
        return False
    if worktree is None:
        return False
    state = classify_setup(setup)
    if state is None:
        return False
    key = await repository_key_for(worktree)
    if key is None:
        return False
    if state == "no_network":
        marker = read_marker()
        if not isinstance(marker, ReportedPolicy):
            return False
        if marker.zero_network:
            return forget_repository_reports([key], lock_wait_seconds=lock_wait_seconds)
    return record_repository_report(
        key,
        worktree,
        no_network=state == "no_network",
        now=now,
        lock_wait_seconds=lock_wait_seconds,
    )


def _hold_active() -> bool:
    """Whether the hold's reads and records are switched on: once a server elsewhere is recorded.

    ADR-052 (the owner's answer O3): with no remote target on this computer, nothing here asks a
    service or writes a report, so a session start, a privacy ceremony and ``provider status``
    behave byte for byte as before the hold existed. The first remote target switches them on;
    there is no report from before then. File reads only; a registry that cannot be read switches
    them on (``targets.remote_target_recorded``).
    """

    from finishup.client.targets import remote_target_recorded

    return remote_target_recorded()


def _parsed(stamp: str) -> datetime | None:
    try:
        return datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def report_needs_refresh(key: str, *, now: datetime | None = None) -> bool:
    """Whether a session start should ask this computer's FinishUP about repository ``key``.

    True with no entry for it, with one older than ``REPORT_REFRESH_SECONDS``, or with one older
    than this computer's last machine report (the machine row may have changed since, and with it
    what the repository's composition meant). File reads only.
    """

    report = repository_report(key)
    if report is None:
        return True
    reported = _parsed(report.reported_at)
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if reported is None or current - reported > timedelta(seconds=REPORT_REFRESH_SECONDS):
        return True
    marker = read_marker()
    return isinstance(marker, ReportedPolicy) and marker.reported_at > report.reported_at


# --- at session start (every host's SessionStart hook pass) --------------------------------------


def _root_kind() -> Literal["everyday", "remote", "other"]:
    """Which root this process uses: this computer's everyday one, a server elsewhere, or other.

    ``other`` covers an isolation variable or pin, a named local server and a root or record that
    cannot be read: nothing is asked or recorded for it here.
    """

    from finishup.client.targets import TargetError, active_target_record
    from finishup.config.paths import PathSafetyError, active_root

    if not everyday_scope():
        return "other"
    try:
        if active_root() is None:
            return "everyday"
        record = active_target_record()
    except (TargetError, PathSafetyError, OSError):
        return "other"
    return "remote" if record is not None and record.is_remote else "other"


async def _session_start_refresh(worktree: str, budget_seconds: float) -> bool:
    from finishup.client.everyday_policy import HOOK_LOCK_WAIT_SECONDS, note_repository_worktree

    loop = asyncio.get_running_loop()
    expires = loop.time() + budget_seconds
    try:
        # The whole pass is bounded, the repository's one Git read included.
        async with asyncio.timeout_at(expires):
            key = await repository_key_for(worktree)
    except TimeoutError:
        return False
    if key is None:
        return False
    if not report_needs_refresh(key):
        report = repository_report(key)
        if report is not None and report.no_network and worktree not in report.worktrees:
            # A linked worktree of a repository already reported: record it, so its folders are
            # fenced and shown as well.
            note_repository_worktree(key, worktree, lock_wait_seconds=HOOK_LOCK_WAIT_SECONDS)
        return False
    remaining = expires - loop.time()
    if remaining <= 0:
        return False
    reads = await _live_read(
        worktree,
        budget_seconds=remaining,
        lock_wait_seconds=HOOK_LOCK_WAIT_SECONDS,
        key=key,
    )
    return reads.repository in {"no_network", "network_permitted"}


# The live read a session start makes; the test suite replaces it so no test reaches a service.
_live_read = read_everyday_repository


def refresh_at_session_start(
    worktree: str | None,
    *,
    budget_seconds: float,
    run_async: Callable[[Callable[[], Awaitable[object]]], object] | None = None,
) -> bool:
    """At a session start, ask this computer's FinishUP about the session's repository if needed.

    Dormant until a server elsewhere is recorded (``_hold_active``); then it runs on this
    computer's everyday root (while its service is usually running, so a report exists before the
    owner switches to the server elsewhere) and while a server elsewhere is selected (before any attach, status or drain connection, so a repository just found to allow
    no network use is held in the same pass). Only when the report has no entry for the
    repository, or a stale one (``report_needs_refresh``); otherwise it at most records the
    session's worktree for an entry that allows no network use. Bounded by ``budget_seconds``
    (``HOOK_READ_SECONDS`` at most); a stopped service fails at once. Runs in a fresh
    ``contextvars`` context on its own event loop (``run_async``, ``asyncio.run`` by default).
    Returns whether a report was recorded; never raises.
    """

    import contextvars

    def run(make: Callable[[], Awaitable[object]]) -> object:
        return asyncio.run(cast("Coroutine[object, object, object]", make()))

    if worktree is None or budget_seconds <= 0 or not _hold_active():
        return False
    if _root_kind() == "other":
        return False
    budget = min(HOOK_READ_SECONDS, budget_seconds)
    try:
        result = contextvars.Context().run(
            run_async or run, lambda: _session_start_refresh(worktree, budget)
        )
    except Exception:  # noqa: BLE001 - a session start never fails on this read
        return False
    return result is True


async def _hold_phase(worktree: str, budget_seconds: float) -> str | None:
    from finishup.client.authorization import preflight_refusal
    from finishup.client.repository_hold import decide
    from finishup.client.targets import active_target_record, target_root

    if preflight_refusal() is not None:
        # An earlier step of the gate refuses this root (ADR-052; in this release, every remote
        # kind is closed): the hold is not what stops a connection, so it is not named.
        return None
    reports = read_repository_reports()
    if isinstance(reports, str) or not any(report.no_network for report in reports):
        # Nothing this computer reported is held: no Git read is needed to know it.
        return None
    try:
        async with asyncio.timeout(budget_seconds):
            key = await repository_key_for(worktree)
    except TimeoutError:
        return None
    record = active_target_record()
    if key is None or record is None or not record.is_remote:
        return None
    return decide(target_root(record.target_id), record.target_id, key).phase


def session_start_hold_phase(
    worktree: str | None,
    *,
    budget_seconds: float,
    run_async: Callable[[Callable[[], Awaitable[object]]], object] | None = None,
) -> str | None:
    """At a session start with no observation consent: whether the session's repository is held
    from the selected server elsewhere, or kept on this computer; the phase, or None.

    Record-only, like the connection seam's own decision (``repository_hold.decide``): no service
    is asked. Only while a server elsewhere is selected that the gate's earlier steps admit
    (``authorization.preflight_refusal``: none is in this release) and this computer reported a
    repository that allows no network use; then the repository's one Git read, bounded by
    ``budget_seconds`` (``HOOK_READ_SECONDS`` at most), in a fresh ``contextvars`` context on its
    own event loop (``run_async``, ``asyncio.run`` by default). Never raises.
    """

    import contextvars

    def run(make: Callable[[], Awaitable[object]]) -> object:
        return asyncio.run(cast("Coroutine[object, object, object]", make()))

    if worktree is None or budget_seconds <= 0 or _root_kind() != "remote":
        return None
    budget = min(HOOK_READ_SECONDS, budget_seconds)
    try:
        phase = contextvars.Context().run(run_async or run, lambda: _hold_phase(worktree, budget))
    except Exception:  # noqa: BLE001 - a session start never fails on this read
        return None
    return phase if isinstance(phase, str) else None
