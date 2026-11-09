"""One authorization gate and generation for every connection to a server elsewhere (ADR-052).

The gate refuses in one order; a generation names every record an admission read, so a change
the owner makes ends the connection, while a rewrite with the same content does not. Remote kinds
are closed in this release: tests that admit a connection open one in process
(``open_remote_kinds``), and the architecture tripwire keeps the release's own set empty.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from builders.server_targets import ambient_home, open_remote_kinds
from finishup.client import authorization, targets
from finishup.client.authorization import (
    CHANGED,
    ConnectionAuthorization,
    authorize_active_root,
    bump_credential_generation,
    credential_generation_path,
    gate,
    preflight_refusal,
    read_generation,
)
from finishup.client.everyday_policy import (
    record_reported_policy,
    record_repository_report,
    remove_marker,
)
from finishup.client.repository_hold import add_kept, add_override
from finishup.client.targets import ServerTarget, TargetError
from finishup.config.paths import reset_selection_memo

_KEY = "sha256:" + "a" * 64


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


def _remote(name: str = "web", *, select: bool = True) -> ServerTarget:
    with targets.registry_lock():
        record, _root = targets.new_remote_target(name, "https", base_url=f"https://{name}.example")
        if select:
            targets.write_selection(record)
    reset_selection_memo()
    return record


def _admitted(
    monkeypatch: pytest.MonkeyPatch, *, key: str | None = None
) -> ConnectionAuthorization:
    open_remote_kinds(monkeypatch, "https")
    admitted = authorize_active_root()
    assert admitted is not None
    return admitted if key is None else admitted.for_repository(key)


def _rewrite(path: Path) -> None:
    """Rename a byte-identical copy into place, as every FinishUP writer does."""

    data = path.read_bytes()
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(data)
    temporary.chmod(0o600)
    os.replace(temporary, path)


# --- local roots are never checked (O2) -----------------------------------------------------


def test_a_local_root_gets_no_authorization_and_no_generation(home: Path) -> None:
    assert authorize_active_root() is None
    assert preflight_refusal() is None
    with targets.registry_lock():
        record, _root = targets.new_local_target("work")
    targets.write_selection(record)
    reset_selection_memo()
    assert authorize_active_root() is None
    assert preflight_refusal() is None
    # The same process with a server elsewhere selected is gated.
    _remote()
    assert preflight_refusal() == "target_root_is_remote"


# --- the gate's one order --------------------------------------------------------------------


def test_the_gate_refuses_in_one_order(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    record = _remote()
    record_reported_policy(zero_network=False)
    record_repository_report(_KEY, "/srv/app", no_network=True)
    old = replace(record, disclosure_version=1)
    record_reported_policy(zero_network=True)

    def reason(candidate: ServerTarget, key: str | None = _KEY) -> str | None:
        try:
            gate(candidate, repository_key=key)
        except TargetError as error:
            return error.reason
        return None

    # Zero-network first, then the disclosure, then the closed kind, then the hold.
    assert reason(old) == "zero_network_remote_selected"
    remove_marker()
    assert reason(old) == "target_reauthorization_required"
    assert reason(record) == "target_root_is_remote"
    open_remote_kinds(monkeypatch, "https")
    assert reason(record) == "repository_egress_held"
    assert reason(record, key=None) is None
    with targets.registry_lock():
        add_kept(
            targets.target_root(record.target_id),
            record.target_id,
            _KEY,
            "/srv/app",
            _no_network_since(),
        )
    assert reason(record) == "repository_egress_kept"


def _no_network_since() -> str:
    from finishup.client.everyday_policy import repository_report

    report = repository_report(_KEY)
    assert report is not None and report.no_network_since is not None
    return report.no_network_since


def test_preflight_names_every_remote_root_as_the_first_layer_did(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """In this release the record-only gate and layer 1's refusal agree on every remote root."""

    record = _remote()
    assert preflight_refusal() == targets.active_remote_refusal() == "target_root_is_remote"
    record_reported_policy(zero_network=True)
    assert preflight_refusal() == targets.active_remote_refusal() == "zero_network_remote_selected"
    remove_marker()
    with targets.registry_lock():
        targets.write_target(
            targets.target_root(record.target_id), replace(record, disclosure_version=1)
        )
    assert (
        preflight_refusal() == targets.active_remote_refusal() == "target_reauthorization_required"
    )
    (targets.target_root(record.target_id) / "target.json").write_bytes(b"damaged")
    assert preflight_refusal() == targets.active_remote_refusal() == "target_root_is_remote"


def test_preflight_admits_an_open_kind_and_reads_no_service(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import finishup.service.client as client_module

    def no_service(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("the preflight never reaches a service")

    monkeypatch.setattr(client_module, "connect_control", no_service)
    monkeypatch.setattr(client_module, "_spawn_service_process", no_service)
    _remote()
    assert preflight_refusal() == "target_root_is_remote"
    open_remote_kinds(monkeypatch, "https")
    assert preflight_refusal() is None


# --- the generation ---------------------------------------------------------------------------


def test_each_component_changes_with_its_writer_and_a_hand_edit(home: Path) -> None:
    record = _remote()
    root = targets.target_root(record.target_id)

    def now() -> authorization.AuthorizationGeneration:
        return read_generation(root, selection_bound=True)

    seen = [now()]

    def changed() -> None:
        current = now()
        assert current != seen[-1]
        seen.append(current)

    targets.write_selection(record)
    changed()
    _rewrite(targets.selection_path())
    changed()
    with targets.registry_lock():
        targets.write_target(root, targets.reauthorized(record))
    changed()
    _rewrite(root / "target.json")
    changed()
    assert bump_credential_generation(root)
    changed()
    record_reported_policy(zero_network=False)
    changed()
    record_repository_report(_KEY, "/srv/app", no_network=True)
    changed()
    with targets.registry_lock():
        add_override(root, record.target_id, _KEY, "/srv/app", _no_network_since())
    changed()
    remove_marker()
    changed()
    # Nothing changed: the same stamps.
    assert now() == seen[-1]
    # A process whose root a variable or pin names never reads the selection.
    assert read_generation(root, selection_bound=False).selection == "pinned"


def test_the_credential_generation_is_an_owner_only_canonical_record(home: Path) -> None:
    record = _remote()
    root = targets.target_root(record.target_id)
    assert bump_credential_generation(root)
    path = credential_generation_path(root)
    data = path.read_bytes()
    assert data.startswith(b'{"generation":"') and data.endswith(
        b'","schema":"yoetz.credential-generation/1"}\n'
    )
    assert path.stat().st_mode & 0o777 == 0o600
    first = data
    assert bump_credential_generation(root)
    assert path.read_bytes() != first
    # A folder that is gone is never created by a bump.
    assert bump_credential_generation(home / "nowhere") is False
    assert not (home / "nowhere").exists()


def test_a_rewrite_with_the_same_content_keeps_the_connection(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = _remote()
    admitted = _admitted(monkeypatch)
    root = targets.target_root(record.target_id)
    _rewrite(targets.selection_path())
    _rewrite(root / "target.json")
    record_reported_policy(zero_network=False)
    with targets.registry_lock():
        targets.write_target(root, targets.reauthorized(record))
    assert admitted.refusal() is None
    assert admitted.refusal() is None


@pytest.mark.parametrize(
    "change",
    [
        "selection_moved",
        "selection_cleared",
        "target_replaced",
        "target_removed",
        "credential_bumped",
    ],
)
def test_a_changed_selection_target_or_key_ends_the_connection(
    home: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    record = _remote()
    admitted = _admitted(monkeypatch)
    root = targets.target_root(record.target_id)
    assert admitted.refusal() is None
    if change == "selection_moved":
        targets.write_selection(_remote("other", select=False))
    elif change == "selection_cleared":
        targets.clear_selection()
    elif change == "target_replaced":
        with targets.registry_lock():
            targets.write_target(root, replace(record, base_url="https://elsewhere.example"))
    elif change == "target_removed":
        with targets.registry_lock():
            targets.remove_target_root(record)
    else:
        assert bump_credential_generation(root)
    assert admitted.refusal() == CHANGED
    # Final for this connection, whatever happens next.
    if change == "selection_moved":
        targets.write_selection(record)
    assert admitted.refusal() == CHANGED


def test_a_later_zero_network_report_or_hold_ends_the_connection_with_its_own_phase(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _remote()
    zero = _admitted(monkeypatch)
    held = _admitted(monkeypatch, key=_KEY)
    assert zero.refusal() is None and held.refusal() is None
    record_reported_policy(zero_network=False)
    record_repository_report(_KEY, "/srv/app", no_network=True)
    assert zero.refusal() is None
    assert held.refusal() == "repository_egress_held"
    record_reported_policy(zero_network=True)
    assert zero.refusal() == "zero_network_remote_selected"


def test_a_check_that_cannot_be_made_keeps_the_last_decision(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _remote()
    admitted = _admitted(monkeypatch)

    def broken(_root: Path, *, selection_bound: bool) -> object:
        del selection_bound
        raise OSError("unreadable")

    monkeypatch.setattr(authorization, "read_generation", broken)
    assert admitted.refusal() is None


def test_the_admission_reads_the_generation_before_the_gate(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A change made while the gate runs is seen at the first check, never lost."""

    record = _remote()
    open_remote_kinds(monkeypatch, "https")
    root = targets.target_root(record.target_id)
    real = authorization.gate

    def gate_while_the_owner_logs_out(
        candidate: ServerTarget, *, repository_key: str | None = None
    ) -> None:
        assert bump_credential_generation(root)
        real(candidate, repository_key=repository_key)

    monkeypatch.setattr(authorization, "gate", gate_while_the_owner_logs_out)
    admitted = authorize_active_root()
    assert admitted is not None
    monkeypatch.setattr(authorization, "gate", real)
    assert admitted.refusal() == CHANGED


def test_refusals_from_the_gate_carry_a_closed_phase(home: Path) -> None:
    _remote()
    with pytest.raises(TargetError) as refused:
        authorize_active_root()
    assert refused.value.reason == "target_root_is_remote"
