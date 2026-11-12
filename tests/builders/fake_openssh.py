"""A stand-in OpenSSH for SSH discovery tests (ADR-052): a script driven by files in a folder.

It plays OpenSSH and the server at once: whether OpenSSH knows the server's host key (``known``:
known, unknown or changed), what the owner answers when OpenSSH asks (``answer``), whether the
login is refused (``auth``), and what the server's launcher prints (``launcher``, ``manifest``,
``profile``). Every call's argv is logged. Point ``FAKE_SSH_STATE`` at the folder (the product
passes its environment to ``ssh`` children, FinishUP variables removed).
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from builders.server_profiles import profile_document
from finishup.protocol.schemas import schema_manifest_digest

__all__ = ["FINGERPRINT", "IDENTITY", "FakeServer", "fake_server"]

KEY_BLOB = b"the server's host key"
FINGERPRINT = base64.b64encode(hashlib.sha256(KEY_BLOB).digest()).rstrip(b"=").decode()
IDENTITY = "sha256:" + hashlib.sha256(KEY_BLOB).hexdigest()

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
            fingerprint=FINGERPRINT,
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


def fake_server(directory: Path, monkeypatch: object) -> FakeServer:
    """A ``FakeServer`` whose state lives in ``directory/ssh-state`` (made here), its folder
    exported as ``FAKE_SSH_STATE`` through ``monkeypatch`` (a ``pytest.MonkeyPatch``)."""

    state = directory / "ssh-state"
    state.mkdir()
    monkeypatch.setenv("FAKE_SSH_STATE", str(state))  # type: ignore[attr-defined]  # pyright: ignore[reportAttributeAccessIssue]
    return FakeServer(state)
