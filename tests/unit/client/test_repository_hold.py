"""A repository whose privacy policy here allows no network use is held from a server elsewhere.

ADR-051 decision 8, maintainer decision of 2026-11-07, round 4. ``decide`` reads only this
computer's report record and the target's own record of the owner's choices; unknown is never
held, a no-network report is held unless the owner allowed it (``sent_anyway``) or kept it on this
computer (``kept``) in the same no-network stretch, and a choice record that cannot be read
allows nothing.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import finishup.client.repository_hold as repository_hold
from builders.server_targets import ambient_home
from finishup.adapters.workspace_root import CanonicalWorkspaceRoot, canonical_workspace_root
from finishup.client import targets
from finishup.client.everyday_policy import record_repository_report, repository_report
from finishup.client.repository_hold import (
    HoldDecision,
    RepositoryRecordError,
    SendHold,
    add_kept,
    add_override,
    clear_overrides,
    decide,
    held_worktrees,
    overrides_path,
    read_overrides,
    remove_override,
    repository_key,
    require_sendable,
)
from finishup.client.targets import ServerTarget, TargetError
from finishup.config.paths import reset_selection_memo
from finishup.ports.control import WorkspaceLocator

_AT = datetime(2026, 11, 7, 9, 30, tzinfo=UTC)
_STAMP = "2026-11-07T09:30:00.000Z"
_KEY = "sha256:" + "a" * 64
_OTHER = "sha256:" + "b" * 64


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


def _git(*arguments: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=FinishUP Test",
            "-c",
            "user.email=test@finishup.invalid",
            *arguments,
        ],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"},
    )


def _repository(path: Path) -> Path:
    path.mkdir()
    _git("-C", os.fspath(path), "init")
    (path / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    _git("-C", os.fspath(path), "add", "tracked.txt")
    _git("-C", os.fspath(path), "commit", "-m", "initial")
    return path


def _remote(kind: targets.TargetKind = "ssh") -> ServerTarget:
    with targets.registry_lock():
        if kind == "ssh":
            record, _root = targets.new_remote_target(
                "lab", "ssh", user="owner", host="lab.example", port=2222
            )
        elif kind == "local_port":
            record, _root = targets.new_remote_target(
                "port", "local_port", base_url="https://127.0.0.1:8443"
            )
        else:
            record, _root = targets.new_remote_target(
                "web", "https", base_url="https://finishup.example"
            )
    return record


def _root(record: ServerTarget) -> Path:
    return targets.target_root(record.target_id)


# --- the key ------------------------------------------------------------------------------------


@pytest.mark.anyio
async def test_one_key_per_repository_for_every_subfolder_and_linked_worktree(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "repository")
    (repository / "sub").mkdir()
    linked = tmp_path / "linked"
    _git("-C", os.fspath(repository), "worktree", "add", os.fspath(linked), "-b", "other")
    other = _repository(tmp_path / "other")

    async def key(path: Path) -> str:
        return repository_key(await canonical_workspace_root(WorkspaceLocator(os.fspath(path))))

    top = await key(repository)
    assert await key(repository / "sub") == top
    assert await key(linked) == top
    assert await key(other) != top
    # The documented derivation, under the record's own domain.
    root = CanonicalWorkspaceRoot("directory", tmp_path)
    assert (
        repository_key(root)
        == "sha256:"
        + hashlib.sha256(
            b"yoetz/everyday-repository/v1\x00directory\x00" + os.fsencode(tmp_path)
        ).hexdigest()
    )


# --- deciding -----------------------------------------------------------------------------------


def test_with_no_report_nothing_is_held(home: Path) -> None:
    record = _remote()
    assert decide(_root(record), record.target_id, _KEY) == HoldDecision("not_reported")


def test_a_repository_whose_policy_allows_network_use_is_not_held(home: Path) -> None:
    record = _remote()
    record_repository_report(_KEY, "/srv/app", no_network=False, now=_AT)
    assert decide(_root(record), record.target_id, _KEY) == HoldDecision(
        "not_held", reported_at=_STAMP
    )


def test_a_no_network_repository_is_held_until_the_owner_decides(home: Path) -> None:
    record = _remote()
    root = _root(record)
    record_repository_report(_KEY, "/srv/app", no_network=True, now=_AT)
    held = decide(root, record.target_id, _KEY)
    assert held == HoldDecision("held", "not_allowed", _STAMP)
    assert held.phase == "repository_egress_held"

    with targets.registry_lock():
        assert add_override(root, record.target_id, _KEY, "/srv/app", _STAMP, now=_AT) is True
    sent = decide(root, record.target_id, _KEY)
    assert sent == HoldDecision("sent_anyway", reported_at=_STAMP, decided_at=_STAMP)
    assert sent.phase is None

    # Keeping it on this computer replaces the allow; it only tightens.
    with targets.registry_lock():
        assert add_kept(root, record.target_id, _KEY, "/srv/app", _STAMP, now=_AT) is True
    kept = decide(root, record.target_id, _KEY)
    assert kept == HoldDecision("kept", reported_at=_STAMP, decided_at=_STAMP)
    assert kept.phase == "repository_egress_kept"
    (choice,) = read_overrides(root, record.target_id)
    assert choice.choice == "keep"


def test_a_choice_from_another_no_network_stretch_asks_again(home: Path) -> None:
    record = _remote()
    root = _root(record)
    record_repository_report(_KEY, "/srv/app", no_network=True, now=_AT)
    with targets.registry_lock():
        add_override(root, record.target_id, _KEY, "/srv/app", _STAMP, now=_AT)
    # The policy here allowed network use, then forbade it again: a new stretch.
    record_repository_report(_KEY, "/srv/app", no_network=False, now=_AT + timedelta(minutes=1))
    record_repository_report(_KEY, "/srv/app", no_network=True, now=_AT + timedelta(minutes=2))
    assert decide(root, record.target_id, _KEY) == HoldDecision(
        "held", "grant_changed", "2026-11-07T09:32:00.000Z"
    )
    with targets.registry_lock():
        add_kept(root, record.target_id, _KEY, "/srv/app", _STAMP, now=_AT)
    assert decide(root, record.target_id, _KEY).cause == "grant_changed"


def test_an_allow_under_an_older_disclosure_no_longer_applies(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = _remote()
    root = _root(record)
    record_repository_report(_KEY, "/srv/app", no_network=True, now=_AT)
    with targets.registry_lock():
        add_override(root, record.target_id, _KEY, "/srv/app", _STAMP, now=_AT)
    monkeypatch.setattr(repository_hold, "REPOSITORY_SEND_DISCLOSURE_VERSION", 2)
    assert decide(root, record.target_id, _KEY) == HoldDecision("held", "not_allowed", _STAMP)


@pytest.mark.parametrize("how", ["not_json", "group_readable", "symlink", "other_target"])
def test_a_choice_record_that_cannot_be_read_allows_nothing(home: Path, how: str) -> None:
    record = _remote()
    root = _root(record)
    record_repository_report(_KEY, "/srv/app", no_network=True, now=_AT)
    with targets.registry_lock():
        add_override(root, record.target_id, _KEY, "/srv/app", _STAMP, now=_AT)
    path = overrides_path(root)
    valid = path.read_bytes()
    if how == "not_json":
        path.write_bytes(b"{oops\n")
    elif how == "group_readable":
        path.chmod(0o640)
    elif how == "symlink":
        elsewhere = path.with_name("elsewhere.json")
        elsewhere.write_bytes(valid)
        elsewhere.chmod(0o600)
        path.unlink()
        path.symlink_to(elsewhere)
    else:
        path.write_bytes(valid.replace(record.target_id.encode(), b"t_00000000"))
    assert decide(root, record.target_id, _KEY) == HoldDecision("held", "not_allowed", _STAMP)
    with pytest.raises(RepositoryRecordError) as refused:
        read_overrides(root, record.target_id)
    assert refused.value.reason in {"repositories_record_invalid", "repositories_record_unsafe"}
    # Adding is refused, never replaces it; clearing repairs it, and everything is held.
    with targets.registry_lock(), pytest.raises(RepositoryRecordError):
        add_override(root, record.target_id, _KEY, "/srv/app", _STAMP, now=_AT)
    with targets.registry_lock():
        assert clear_overrides(root, record.target_id) == "repaired"
    assert read_overrides(root, record.target_id) == ()
    assert not path.is_symlink()
    assert decide(root, record.target_id, _KEY).state == "held"


def test_an_isolation_root_holds_nothing(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    record = _remote()
    record_repository_report(_KEY, "/srv/app", no_network=True, now=_AT)
    isolated = home / "isolated"
    isolated.mkdir(mode=0o700)
    monkeypatch.setenv("FINISHUP_ISOLATED_ROOT", os.fspath(isolated))
    reset_selection_memo()
    assert decide(_root(record), record.target_id, _KEY) == HoldDecision("not_held")
    assert held_worktrees(_root(record), record.target_id) == ()


def test_the_send_hold_reads_the_records_again_after_each_rewrite(home: Path) -> None:
    record = _remote()
    root = _root(record)
    hold = SendHold(root, record.target_id, _KEY)
    assert hold.held() is False and hold.phase() is None
    record_repository_report(_KEY, "/srv/app", no_network=True, now=_AT)
    assert hold.held() is True and hold.phase() == "repository_egress_held"
    with targets.registry_lock():
        add_override(root, record.target_id, _KEY, "/srv/app", _STAMP, now=_AT)
    assert hold.held() is False
    with targets.registry_lock():
        add_kept(root, record.target_id, _KEY, "/srv/app", _STAMP, now=_AT)
    assert hold.phase() == "repository_egress_kept"
    with targets.registry_lock():
        assert [item.key for item in remove_override(root, record.target_id, key=_KEY)] == [_KEY]
    assert hold.phase() == "repository_egress_held"
    record_repository_report(_KEY, "/srv/app", no_network=False, now=_AT)
    assert hold.held() is False


def test_held_worktrees_name_held_and_kept_repositories_only(home: Path) -> None:
    record = _remote()
    root = _root(record)
    third = "sha256:" + "c" * 64
    record_repository_report(_KEY, "/srv/held", no_network=True, now=_AT)
    record_repository_report(_OTHER, "/srv/sent", no_network=True, now=_AT)
    record_repository_report(third, "/srv/kept", no_network=True, now=_AT)
    record_repository_report("sha256:" + "d" * 64, "/srv/open", no_network=False, now=_AT)
    with targets.registry_lock():
        add_override(root, record.target_id, _OTHER, "/srv/sent", _STAMP, now=_AT)
        add_kept(root, record.target_id, third, "/srv/kept", _STAMP, now=_AT)
    assert sorted(held_worktrees(root, record.target_id)) == ["/srv/held", "/srv/kept"]


# --- the choices record -------------------------------------------------------------------------


def test_the_choice_record_is_canonical_owner_only_and_bound_to_its_target(home: Path) -> None:
    record = _remote()
    root = _root(record)
    with targets.registry_lock():
        add_override(root, record.target_id, _OTHER, "/srv/b", _STAMP, now=_AT)
        add_kept(root, record.target_id, _KEY, "/srv/a", _STAMP, now=_AT)
    path = overrides_path(root)
    assert path == root / "config" / "repositories.json"
    assert (path.stat().st_mode & 0o777) == 0o600
    assert json.loads(path.read_bytes()) == {
        "repositories": [
            {
                "choice": "keep",
                "decided_at": _STAMP,
                "key": _KEY,
                "no_network_since": _STAMP,
                "worktree": "/srv/a",
            },
            {
                "choice": "send",
                "decided_at": _STAMP,
                "disclosure_version": 1,
                "key": _OTHER,
                "no_network_since": _STAMP,
                "worktree": "/srv/b",
            },
        ],
        "schema": "yoetz.server-repositories/1",
        "target_id": record.target_id,
    }
    assert path.read_bytes().endswith(b"}\n") and b" " not in path.read_bytes()
    # The same choice again changes nothing.
    with targets.registry_lock():
        assert add_kept(root, record.target_id, _KEY, "/srv/a", _STAMP, now=_AT) is False


def test_the_choice_record_holds_at_most_64_repositories(home: Path) -> None:
    record = _remote()
    root = _root(record)
    with targets.registry_lock():
        for number in range(repository_hold.MAX_ALLOWED_REPOSITORIES):
            add_kept(root, record.target_id, f"sha256:{number:064x}", f"/srv/r{number}", _STAMP)
        with pytest.raises(RepositoryRecordError) as full:
            add_override(root, record.target_id, _KEY, "/srv/new", _STAMP)
        # Replacing a repository's own choice is never refused for the bound.
        assert add_override(root, record.target_id, f"sha256:{0:064x}", "/srv/r0", _STAMP)
    assert full.value.reason == "repository_limit"


@pytest.mark.parametrize(
    "worktree", ["relative", "/srv/a\u0001b", "/srv/../etc", "/", "/" + "x" * 1_025]
)
def test_a_worktree_the_record_cannot_keep_is_refused(home: Path, worktree: str) -> None:
    record = _remote()
    with targets.registry_lock(), pytest.raises(RepositoryRecordError) as refused:
        add_override(_root(record), record.target_id, _KEY, worktree, _STAMP)
    assert refused.value.reason == "repository_invalid"
    assert not overrides_path(_root(record)).exists()


def test_removing_by_key_by_recorded_path_and_clearing(home: Path) -> None:
    record = _remote()
    root = _root(record)
    with targets.registry_lock():
        add_override(root, record.target_id, _KEY, "/srv/a", _STAMP, now=_AT)
        add_kept(root, record.target_id, _OTHER, "/srv/moved", _STAMP, now=_AT)
        # A moved or deleted repository is removed by its recorded path, in normal form.
        (gone,) = remove_override(root, record.target_id, worktree="/srv/x/../moved")
        assert gone.key == _OTHER
        assert remove_override(root, record.target_id, key=_OTHER) == ()
        assert clear_overrides(root, record.target_id) == "cleared"
        assert clear_overrides(root, record.target_id) == "absent"
    assert read_overrides(root, record.target_id) == ()


# --- the seam's check -------------------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("kind", ["ssh", "https", "local_port"])
async def test_require_sendable_refuses_held_and_kept_alike_for_every_remote_kind(
    home: Path, tmp_path: Path, kind: targets.TargetKind
) -> None:
    record = _remote(kind)
    repository = _repository(tmp_path / "repository")
    root = await canonical_workspace_root(WorkspaceLocator(os.fspath(repository)))
    key = repository_key(root)

    hold = require_sendable(record, root)
    assert hold == SendHold(_root(record), record.target_id, key)

    record_repository_report(key, os.fspath(repository), no_network=True, now=_AT)
    with pytest.raises(TargetError) as held:
        require_sendable(record, root)
    assert held.value.reason == "repository_egress_held"
    report = repository_report(key)
    assert report is not None and report.no_network_since == _STAMP
    with targets.registry_lock():
        add_kept(_root(record), record.target_id, key, os.fspath(repository), _STAMP)
    with pytest.raises(TargetError) as kept:
        require_sendable(record, root)
    assert kept.value.reason == "repository_egress_kept"
    with targets.registry_lock():
        add_override(_root(record), record.target_id, key, os.fspath(repository), _STAMP)
    assert require_sendable(record, root) is not None


@pytest.mark.anyio
async def test_a_local_target_or_none_is_never_held(home: Path, tmp_path: Path) -> None:
    repository = _repository(tmp_path / "repository")
    root = await canonical_workspace_root(WorkspaceLocator(os.fspath(repository)))
    record_repository_report(repository_key(root), None, no_network=True, now=_AT)
    with targets.registry_lock():
        local, _local_root = targets.new_local_target("work")
    assert require_sendable(local, root) is None
    assert require_sendable(None, root) is None


@pytest.mark.parametrize(
    "module",
    [
        "finishup.client.everyday_policy",
        "finishup.client.repository_hold",
        "finishup.client.everyday_repository",
    ],
)
def test_the_hold_modules_import_only_hook_safe_modules(module: str) -> None:
    """A hook may import them: no CLI framework, wire models, service client or network client
    loads until a read actually runs (the hook import diet, ``tests/packaging``)."""

    import sys

    src = Path(__file__).resolve().parents[3] / "src"
    probe = (
        f"import json, sys; sys.path.insert(0, {os.fspath(src)!r})\n"
        f"import {module}\n"
        "print(json.dumps(sorted(sys.modules)))\n"
    )
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and source
        [sys.executable, "-I", "-c", probe],
        capture_output=True,
        check=True,
        timeout=60,
    )
    loaded = set(json.loads(completed.stdout))
    forbidden = {
        "pydantic",
        "typer",
        "anyio",
        "httpx",
        "keyring",
        "finishup.protocol.models",
        "finishup.service.client",
        "finishup.cli.app",
        "finishup.cli.render",
        "finishup.client.connector",
        "finishup.client.credentials",
        "finishup.client.target_runtime",
    }
    assert not loaded & forbidden
