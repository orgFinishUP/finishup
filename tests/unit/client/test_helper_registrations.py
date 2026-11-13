"""The helper's workspace registration API (ADR-052, design v2 section 8.5).

A client process registers the workspaces a server elsewhere's helper is to serve; a registration
is owner-only, leased, bound to what the connection was admitted under (the target, credential,
consent, profile revision and repository hold) and to its own worktree by its claim, and is served
only while all of that still holds.
"""

from __future__ import annotations

import asyncio
import fcntl
import json
import os
import subprocess
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from builders.server_profiles import profile_document, refreshed
from builders.server_targets import ambient_home, open_remote_kinds
from finishup.adapters.workspace_root import canonical_workspace_root
from finishup.client import targets
from finishup.client.authorization import (
    ConnectionAuthorization,
    Grant,
    bump_credential_generation,
)
from finishup.client.everyday_policy import record_reported_policy, record_repository_report
from finishup.client.helper_registrations import (
    MAX_REGISTRATIONS,
    Registration,
    RegistrationError,
    new_registrant,
    register,
    registrations_dir,
    release,
    release_registrant,
    renew,
    served_workspaces,
)
from finishup.client.remote_binding import binding_for_active_root
from finishup.client.repository_hold import repository_key
from finishup.config.paths import reset_selection_memo
from finishup.ports.control import WorkspaceClaim, WorkspaceLocator
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.consent_envelope import ReviewEgress

_GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": os.defpath,
}
_AT = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)


@dataclass
class _Admitted:
    record: targets.ServerTarget
    authorization: ConnectionAuthorization
    claim: WorkspaceClaim
    worktree: str


def _repository(base: Path, name: str) -> str:
    folder = base / name
    folder.mkdir(mode=0o700)
    subprocess.run(
        ("git", "init", "--quiet"),
        cwd=folder,
        check=True,
        capture_output=True,
        env={**_GIT_ENV, "HOME": os.fspath(folder)},
    )
    return os.fspath(folder.resolve())


def _admit(worktree: str) -> tuple[ConnectionAuthorization, WorkspaceClaim]:
    binding = asyncio.run(
        binding_for_active_root(WorkspaceLocator(worktree), serve_workspace=False)
    )
    assert binding is not None and isinstance(binding.authorization, ConnectionAuthorization)
    return binding.authorization, binding.claim


@pytest.fixture
def admitted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[_Admitted]:
    with ambient_home(monkeypatch):
        open_remote_kinds(monkeypatch, "https")
        with targets.registry_lock():
            record, _root = targets.new_remote_target(
                "lab", "https", base_url="https://lab.example"
            )
            targets.write_selection(record)
        reset_selection_memo()
        worktree = _repository(tmp_path, "private-project")
        authorization, claim = _admit(worktree)
        yield _Admitted(record, authorization, claim, worktree)


def _register(admitted: _Admitted, *, registrant: str | None = None) -> Registration:
    return register(
        admitted.authorization,
        admitted.claim,
        admitted.worktree,
        registrant=registrant or new_registrant(),
        source="mcp_bridge",
        now=_AT,
    )


def _served(admitted: _Admitted, *, now: datetime = _AT) -> tuple[list[Registration], list[str]]:
    dropped: list[str] = []
    stored = targets.read_target(targets.target_root(admitted.record.target_id))
    assert stored is not None
    served = asyncio.run(served_workspaces(stored, now=now, drop=dropped.append))
    return [item.registration for item in served], dropped


def test_a_registration_is_an_owner_only_record_the_helper_serves(admitted: _Admitted) -> None:
    registration = _register(admitted)

    (path,) = registrations_dir(admitted.record.target_id).iterdir()
    assert path.stat().st_mode & 0o077 == 0
    document = json.loads(path.read_bytes())
    assert document["schema"] == "yoetz.helper-registration/1"
    assert document["server_profile"]["revision"] == 1
    assert document["expires_at"] == "2026-11-09T12:15:00.000Z"
    served, dropped = _served(admitted)
    assert served == [registration] and dropped == []


def test_registering_under_a_refusing_authorization_writes_nothing(admitted: _Admitted) -> None:
    record_reported_policy(zero_network=True)

    with pytest.raises(RegistrationError) as refused:
        _register(admitted)

    assert (refused.value.reason, refused.value.phase) == (
        "registration_refused",
        "zero_network_remote_selected",
    )
    assert not registrations_dir(admitted.record.target_id).exists()


def test_renewing_extends_the_lease_and_a_changed_authorization_releases_it(
    admitted: _Admitted,
) -> None:
    registration = _register(admitted)

    renewed = renew(registration, admitted.authorization, now=_AT + timedelta(minutes=10))
    assert isinstance(renewed, Registration)
    assert renewed.expires_at == "2026-11-09T12:25:00.000Z"

    targets.clear_selection()
    reset_selection_memo()
    assert renew(renewed, admitted.authorization) == "server_authorization_changed"
    assert list(registrations_dir(admitted.record.target_id).iterdir()) == []


def test_an_expired_registration_is_dropped_and_removed(admitted: _Admitted) -> None:
    _register(admitted)

    served, dropped = _served(admitted, now=_AT + timedelta(minutes=16))

    assert served == [] and dropped == ["expired"]
    assert list(registrations_dir(admitted.record.target_id).iterdir()) == []


@pytest.mark.parametrize("change", ["credential", "consent", "hold"])
def test_a_registration_is_not_served_once_what_it_was_made_under_changed(
    admitted: _Admitted, change: str
) -> None:
    _register(admitted)
    root = targets.target_root(admitted.record.target_id)
    if change == "credential":
        assert bump_credential_generation(root)
        expected = "credential_changed"
    elif change == "consent":
        stored = targets.read_target(root)
        assert stored is not None
        # The same offer under a new revision: the consent now names another one.
        refreshed(stored, profile_document(revision=2))
        expected = "consent_changed"
    else:
        key = repository_key(
            asyncio.run(canonical_workspace_root(WorkspaceLocator(admitted.worktree)))
        )
        record_repository_report(key, admitted.worktree, no_network=True)
        expected = "repository_egress_held"

    served, dropped = _served(admitted)

    assert served == [] and dropped == [expected]


def test_a_widened_profile_is_not_served(admitted: _Admitted) -> None:
    _register(admitted)
    stored = targets.read_target(targets.target_root(admitted.record.target_id))
    assert stored is not None
    refreshed(stored, profile_document(review=ReviewEgress("server_policy", "openai"), revision=2))

    served, dropped = _served(admitted)

    assert served == [] and dropped == ["server_profile_changed"]


def test_a_record_naming_another_folder_than_its_claim_is_never_served(
    admitted: _Admitted, tmp_path: Path
) -> None:
    registration = _register(admitted)
    other = _repository(tmp_path, "other-project")
    path = next(registrations_dir(admitted.record.target_id).iterdir())
    body = registration.body()
    body["worktree"] = other
    path.write_bytes(canonical_encode(body) + b"\n")

    served, dropped = _served(admitted)

    assert served == [] and dropped == ["claim_mismatch"]
    assert not path.exists()


@pytest.mark.parametrize("damage", ["loose_mode", "not_canonical", "symlink"])
def test_a_record_that_cannot_be_read_safely_is_dropped(admitted: _Admitted, damage: str) -> None:
    _register(admitted)
    path = next(registrations_dir(admitted.record.target_id).iterdir())
    if damage == "loose_mode":
        path.chmod(0o644)
    elif damage == "not_canonical":
        path.write_bytes(json.dumps(json.loads(path.read_bytes()), indent=1).encode() + b"\n")
    else:
        target = path.with_name("elsewhere")
        target.write_bytes(path.read_bytes())
        target.chmod(0o600)
        path.unlink()
        path.symlink_to(target)

    served, dropped = _served(admitted)

    assert served == [] and dropped == ["unreadable"]


def test_at_most_the_limit_of_registrations_per_target(admitted: _Admitted) -> None:
    for _index in range(MAX_REGISTRATIONS):
        _register(admitted)

    with pytest.raises(RegistrationError) as limited:
        _register(admitted)
    assert limited.value.reason == "registration_limit"


def test_releasing_a_registrant_removes_only_its_own(admitted: _Admitted) -> None:
    mine, theirs = new_registrant(), new_registrant()
    _register(admitted, registrant=mine)
    kept = _register(admitted, registrant=theirs)

    assert release_registrant(admitted.record.target_id, mine) == 1

    served, _dropped = _served(admitted)
    assert served == [kept]
    assert release(admitted.record.target_id, admitted.claim, theirs)
    assert not release(admitted.record.target_id, admitted.claim, theirs)


# --- review of layer 3: C1, C2 and C4 ------------------------------------------------------------


def test_a_registration_follows_the_selection_unless_its_connection_was_pinned(
    admitted: _Admitted,
) -> None:
    """C1: a connection that followed the selection registers ``selection_bound``; once the
    selection names another server (or none) the helper no longer serves it. A connection pinned
    to its root on purpose (an isolation variable, a pin, a named probe) keeps being served."""

    from dataclasses import replace

    from finishup.client.authorization import read_generation

    bound = _register(admitted)
    root = targets.target_root(admitted.record.target_id)
    grant = replace(admitted.authorization.grant, selection_bound=False)
    pinned_authorization = ConnectionAuthorization(
        grant, read_generation(root, selection_bound=False)
    )
    pinned = register(
        pinned_authorization,
        admitted.claim,
        admitted.worktree,
        registrant=new_registrant(),
        source="cli",
        now=_AT,
    )
    with targets.registry_lock():
        other, _other_root = targets.new_remote_target(
            "elsewhere", "https", base_url="https://elsewhere.example"
        )
        targets.write_selection(other)
    reset_selection_memo()

    served, dropped = _served(admitted)
    assert served == [pinned] and dropped == ["selection_changed"]
    with targets.registry_lock():
        targets.clear_selection()
    served, dropped = _served(admitted)
    assert served == [pinned] and dropped == ["selection_changed"]
    documents = {
        json.loads(path.read_bytes())["registrant"]: json.loads(path.read_bytes())
        for path in registrations_dir(admitted.record.target_id).iterdir()
    }
    assert documents[bound.registrant]["selection_bound"] is True
    assert documents[pinned.registrant]["selection_bound"] is False


class _ConcurrentOwnerAction:
    """An admission whose check is followed at once by an owner action from another process
    (``server logout`` or ``server remove``), which takes the registry lock as those commands do:
    when the registration holds the lock it waits (``waited``), and the test runs it after the
    registration has let go, exactly where it would run. No timing is involved."""

    def __init__(self, inner: ConnectionAuthorization, action: Callable[[], object]) -> None:
        self.inner = inner
        self.action = action
        self.waited = False

    @property
    def grant(self) -> Grant:
        return self.inner.grant

    def refusal(self) -> str | None:
        phase = self.inner.refusal()
        descriptor = os.open(
            targets.servers_dir() / ".registry.lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600
        )
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                self.waited = True
                return phase
            self.action()
        finally:
            os.close(descriptor)
        return phase


def _register_during(admitted: _Admitted, action: Callable[[], object]) -> _ConcurrentOwnerAction:
    concurrent = _ConcurrentOwnerAction(admitted.authorization, action)
    try:
        register(
            cast(ConnectionAuthorization, concurrent),
            admitted.claim,
            admitted.worktree,
            registrant=new_registrant(),
            source="mcp_bridge",
            now=_AT,
        )
    except RegistrationError:
        pass
    if concurrent.waited:
        with targets.registry_lock():
            action()
    return concurrent


def test_a_logout_during_registration_never_lends_it_the_new_credential_generation(
    admitted: _Admitted,
) -> None:
    """C2: the credential generation is read under the registry lock with the admission, so a
    logout is wholly before (refused) or wholly after it (recorded under the old generation and
    dropped by the helper); never an old connection stamped with the new generation."""

    root = targets.target_root(admitted.record.target_id)

    concurrent = _register_during(admitted, lambda: bump_credential_generation(root))

    served, dropped = _served(admitted)
    assert served == [] and dropped == ["credential_changed"]
    assert concurrent.waited


def test_a_target_removed_during_registration_is_never_made_again(admitted: _Admitted) -> None:
    """C2: the target's existence is checked under the same lock as the write, which never
    creates the target's folder again."""

    root = targets.target_root(admitted.record.target_id)

    def remove() -> None:
        stored = targets.read_target(root)
        assert stored is not None
        targets.remove_target_root(stored)

    concurrent = _register_during(admitted, remove)

    assert not root.exists()
    assert concurrent.waited
    with pytest.raises(RegistrationError) as refused:
        _register(admitted)
    assert (refused.value.reason, refused.value.phase) == (
        "registration_refused",
        "server_authorization_changed",
    )
    assert not root.exists()


def test_pruning_keeps_a_lease_its_registrant_renewed_after_it_was_judged(
    admitted: _Admitted,
) -> None:
    """C4: a record judged expired is removed only if it is still the one judged; the registrant
    renewing it in between (here, as the helper reports the drop) keeps its fresh lease."""

    registration = _register(admitted)
    later = _AT + timedelta(minutes=16)
    renewed: list[Registration] = []

    def renew_meanwhile(reason: str) -> None:
        assert reason == "expired"
        fresh = renew(registration, admitted.authorization, now=later)
        assert isinstance(fresh, Registration)
        renewed.append(fresh)

    stored = targets.read_target(targets.target_root(admitted.record.target_id))
    assert stored is not None
    served = asyncio.run(served_workspaces(stored, now=later, drop=renew_meanwhile))

    assert served == () and len(renewed) == 1
    (path,) = registrations_dir(admitted.record.target_id).iterdir()
    assert json.loads(path.read_bytes())["expires_at"] == renewed[0].expires_at
    again, dropped = _served(admitted, now=later)
    assert again == renewed and dropped == []
