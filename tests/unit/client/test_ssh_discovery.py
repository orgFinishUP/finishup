"""SSH discovery: the launcher, the endpoint, the profile and the host key (RE-7, RE-11; ADR-052).

A stand-in ``ssh`` (a small script driven by files in a state folder) plays OpenSSH and the server:
whether it knows the host key, what the owner answers when OpenSSH asks, and what the server's
launcher prints. The real OpenSSH runs in ``tests/capability/test_openssh_helper.py``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from builders.server_profiles import profile_document
from builders.server_targets import ambient_home
from finishup.client import targets
from finishup.client.ssh_discovery import (
    HostKeyQuestion,
    SshProfileSource,
    discover,
    fetch_profile,
    host_key_question,
)
from finishup.client.target_runtime import TargetRuntimeError
from finishup.protocol.schemas import schema_manifest_digest

_KEY_BLOB = b"the server's host key"
_FINGERPRINT = base64.b64encode(hashlib.sha256(_KEY_BLOB).digest()).rstrip(b"=").decode()
_IDENTITY = "sha256:" + hashlib.sha256(_KEY_BLOB).hexdigest()

_FAKE_SSH = r"""
import json, os, sys
from pathlib import Path

state = Path(os.environ["FAKE_SSH_STATE"])
argv = sys.argv[1:]
with (state / "calls").open("a") as log:
    log.write(json.dumps(argv) + "\n")
command = argv[-1]
known = (state / "known").read_text()
ask = "StrictHostKeyChecking=ask" in argv
if known == "changed":
    sys.stderr.write("@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\n")
    sys.stderr.write("Host key verification failed.\n")
    sys.exit(255)
if known == "unknown":
    if not ask:
        sys.stderr.write("No ED25519 host key is known for [h]:22 and you have requested strict checking.\n")
        sys.stderr.write("Host key verification failed.\n")
        sys.exit(255)
    if (state / "answer").read_text() != "yes":
        sys.stderr.write("Host key verification failed.\n")
        sys.exit(255)
    (state / "known").write_text("known")
key = (state / "fingerprint").read_text()
sys.stderr.write("debug1: Server host key: ssh-ed25519 SHA256:" + key + "\n")
if (state / "auth").read_text() == "refused":
    sys.stderr.write("owner@h: Permission denied (publickey).\n")
    sys.exit(255)
if "for candidate in" in command:
    launcher = (state / "launcher").read_text()
    if not launcher:
        sys.exit(3)
    print(launcher)
    sys.exit(0)
if "service endpoint --json" in command:
    print(json.dumps({
        "schema": "yoetz.service-endpoint/1",
        "endpoint": "/srv/fu/run/control.sock",
        "launcher": ["/srv/bin/finishup"],
        "release": "0.3.0",
        "schema_manifest_digest": (state / "manifest").read_text(),
        "runtime_dir_session_bound": False,
        "linger": "unknown",
    }))
    sys.exit(0)
if "service profile --json" in command:
    sys.stdout.write((state / "profile").read_text() + "\n")
    sys.exit(0)
sys.exit(127)
"""


class FakeServer:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.ssh = str(directory / "ssh")
        (directory / "ssh").write_text(f"#!{sys.executable}\n{_FAKE_SSH}", encoding="utf-8")
        (directory / "ssh").chmod(0o700)
        self.set(
            known="known",
            answer="no",
            fingerprint=_FINGERPRINT,
            auth="ok",
            launcher="/srv/bin/finishup",
            manifest=schema_manifest_digest(),
            profile=json.dumps(profile_document()),
        )
        (directory / "calls").write_text("")

    def set(self, **files: str) -> None:
        for name, text in files.items():
            (self.directory / name).write_text(text, encoding="utf-8")

    def calls(self) -> list[list[str]]:
        lines = (self.directory / "calls").read_text().splitlines()
        return [json.loads(line) for line in lines]

    def asked(self) -> list[bool]:
        return ["StrictHostKeyChecking=ask" in call for call in self.calls()]


@pytest.fixture
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeServer]:
    state = tmp_path / "ssh-state"
    state.mkdir()
    monkeypatch.setenv("FAKE_SSH_STATE", str(state))
    yield FakeServer(state)


def _discover(server: FakeServer, *, question: HostKeyQuestion | None = None, **options: object):  # noqa: ANN202
    arguments: dict[str, object] = {
        "user": "owner",
        "host": "h",
        "port": 22,
        "remote_root": None,
        "remote_launcher": None,
        "question": question,
        "ssh": server.ssh,
    }
    arguments.update(options)
    return discover(**arguments)  # type: ignore[arg-type]


def test_a_known_server_is_discovered_without_a_question(server: FakeServer) -> None:
    told: list[str] = []
    found = _discover(server, question=HostKeyQuestion(lambda: told.append("asked")))
    assert found.endpoint == "/srv/fu/run/control.sock"
    assert found.launcher == "/srv/bin/finishup"
    assert found.session_bound is False
    assert found.profile.identity_type == "ssh_host_key"
    assert found.profile.identity == _IDENTITY
    assert json.loads(found.profile.document) == profile_document()
    assert told == [] and not any(server.asked())
    # Every probe is strict, never multiplexed, and verbose (the host key is read from it).
    for call in server.calls():
        assert {"-v", "ControlPath=none", "BatchMode=yes", "StrictHostKeyChecking=yes"} <= set(call)


def test_the_launcher_given_is_used_and_the_remote_root_pins_every_command(
    server: FakeServer,
) -> None:
    _discover(server, remote_launcher="/opt/fu/bin/finishup", remote_root="/srv/fu")
    commands = [call[-1] for call in server.calls()]
    assert commands == [
        "env FINISHUP_ISOLATED_ROOT=/srv/fu /opt/fu/bin/finishup service endpoint --json",
        "env FINISHUP_ISOLATED_ROOT=/srv/fu /opt/fu/bin/finishup service profile --json",
    ]


def test_no_launcher_at_the_fixed_paths_is_named(server: FakeServer) -> None:
    server.set(launcher="")
    with pytest.raises(TargetRuntimeError) as raised:
        _discover(server)
    assert raised.value.reason == "remote_launcher_not_found"
    # The fixed candidate script ran; no bare 'finishup' was ever run on the remote PATH.
    assert len(server.calls()) == 1 and "$HOME/.local/bin/finishup" in server.calls()[0][-1]


def test_another_release_is_incompatible(server: FakeServer) -> None:
    server.set(manifest="sha256:" + "0" * 64)
    with pytest.raises(TargetRuntimeError) as raised:
        _discover(server)
    assert (raised.value.reason, raised.value.phase) == (
        "service_unavailable",
        "remote_incompatible",
    )


def test_an_unknown_host_key_is_asked_once_on_the_console_and_then_recorded(
    server: FakeServer,
) -> None:
    server.set(known="unknown", answer="yes")
    told: list[str] = []
    found = _discover(server, question=HostKeyQuestion(lambda: told.append("asked")))
    assert told == ["asked"]
    # The first strict attempt found the key unknown; the next one let OpenSSH ask; every later
    # probe asks nothing (the key is known now).
    assert server.asked() == [False, True, False, False]
    assert found.profile.identity == _IDENTITY


def test_a_declined_host_key_adds_nothing_and_is_named(server: FakeServer) -> None:
    server.set(known="unknown", answer="no")
    told: list[str] = []
    with pytest.raises(TargetRuntimeError) as raised:
        _discover(server, question=HostKeyQuestion(lambda: told.append("asked")))
    assert raised.value.reason == "remote_host_key_unconfirmed"
    assert told == ["asked"] and server.asked() == [False, True]


def test_an_unknown_host_key_with_no_console_is_never_asked(server: FakeServer) -> None:
    server.set(known="unknown", answer="yes")
    with pytest.raises(TargetRuntimeError) as raised:
        _discover(server, question=None)
    assert raised.value.reason == "trusted_console_required"
    assert server.asked() == [False]


def test_a_changed_host_key_is_refused_at_once_and_never_asked(server: FakeServer) -> None:
    """RE-7: nothing claims a question that never comes; a changed key is not asked about."""

    server.set(known="changed", answer="yes")
    told: list[str] = []
    with pytest.raises(TargetRuntimeError) as raised:
        _discover(server, question=HostKeyQuestion(lambda: told.append("asked")))
    assert raised.value.phase == "remote_identity_changed"
    assert told == [] and server.asked() == [False]


def test_a_refused_login_is_named(server: FakeServer) -> None:
    server.set(auth="refused")
    with pytest.raises(TargetRuntimeError) as raised:
        _discover(server)
    assert raised.value.phase == "remote_auth_failed"


def test_no_observed_host_key_fails_closed(server: FakeServer) -> None:
    server.set(fingerprint="not-a-fingerprint")
    with pytest.raises(TargetRuntimeError) as raised:
        _discover(server)
    assert raised.value.phase == "remote_identity_changed"


def test_the_profile_source_fetches_a_recorded_target_and_asks_only_inside_the_console_block(
    server: FakeServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.client import ssh_discovery

    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, _root = targets.new_remote_target(
                "lab",
                "ssh",
                user="owner",
                host="h",
                port=22,
                remote_root="/srv/fu",
                remote_launcher="/srv/bin/finishup",
            )
    monkeypatch.setattr(ssh_discovery, "resolve_ssh", lambda: server.ssh)
    profile = SshProfileSource().fetch(record)
    assert profile.identity == _IDENTITY
    assert server.calls()[-1][-1] == (
        "env FINISHUP_ISOLATED_ROOT=/srv/fu /srv/bin/finishup service profile --json"
    )
    server.set(known="unknown", answer="yes")
    with pytest.raises(TargetRuntimeError, match="trusted_console_required"):
        SshProfileSource().fetch(record)
    told: list[str] = []
    with host_key_question(HostKeyQuestion(lambda: told.append("asked"))):
        assert SshProfileSource().fetch(record).identity == _IDENTITY
    assert told == ["asked"]
    from dataclasses import replace

    with pytest.raises(TargetRuntimeError, match="remote_launcher_not_found"):
        fetch_profile(replace(record, remote_launcher=None), ssh=server.ssh)
