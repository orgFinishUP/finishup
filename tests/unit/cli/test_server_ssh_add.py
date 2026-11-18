"""``finishup server add NAME ssh://…`` and ``server use`` of an SSH server (ADR-052, layer 4).

SSH discovery runs against a stand-in OpenSSH (``builders.fake_openssh``) and a stand-in trusted
console: the order before anything is written (zero-network first, then discovery, then the
consent on the console), the host-key question asked only on the console and only for an unknown
key (RE-7, RE-11), a declined or changed key adding nothing, the record carrying the endpoint and
launcher the server's own launcher reported, and the held-repository line after a switch (FR-5).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from types import TracebackType
from typing import Self

import pytest
from typer.testing import CliRunner, Result

from builders.fake_openssh import IDENTITY, FakeServer, fake_server
from finishup.cli import app as cli
from finishup.cli import server as server_cli
from finishup.cli import trusted_console
from finishup.client import ssh_transport, targets
from finishup.client.server_profile import read_cached_profile
from finishup.config.paths import reset_selection_memo

_RUNNER = CliRunner()


class _Console:
    """A trusted console that answers from a script and records what it showed."""

    def __init__(self, answers: list[bytes]) -> None:
        self.answers = answers
        self.shown: list[str] = []
        self.opened = 0

    def __call__(self) -> Self:
        self.opened += 1
        return self

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        _kind: type[BaseException] | None,
        _value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        return None

    def write(self, text: str) -> None:
        self.shown.append(text)

    def read_choice(self, _prompt: str, allowed: tuple[bytes, ...]) -> bytes:
        if not self.answers:
            raise trusted_console.TrustedConsoleError("eof")
        answer = self.answers.pop(0)
        if answer in allowed:
            return answer
        raise trusted_console.TrustedConsoleError("input_invalid")

    @property
    def text(self) -> str:
        return "".join(self.shown)


class _NoConsole:
    def __call__(self) -> Self:
        raise trusted_console.TrustedConsoleError("trusted_console_required")


@pytest.fixture
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeServer]:
    from builders.server_targets import ambient_home

    with ambient_home(monkeypatch):
        fake = fake_server(tmp_path, monkeypatch)
        monkeypatch.setattr(ssh_transport, "resolve_ssh", lambda: fake.ssh)
        monkeypatch.setattr(server_cli, "_zero_network_in_force", lambda: False)
        yield fake


def _console(monkeypatch: pytest.MonkeyPatch, *answers: bytes) -> _Console:
    console = _Console(list(answers))
    monkeypatch.setattr(trusted_console, "TrustedForegroundConsole", console)
    return console


def _invoke(*arguments: str) -> Result:
    reset_selection_memo()
    return _RUNNER.invoke(cli.app, ["server", *arguments])


def test_add_discovers_the_server_and_records_what_its_launcher_reported(
    server: FakeServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    console = _console(monkeypatch, b"listed", b"lab")

    result = _invoke("add", "lab", "ssh://owner@lab.example:2222", "--remote-root", "/srv/fu")

    assert result.exit_code == 0, result.output
    (record,) = targets.list_targets()
    assert (record.kind, record.user, record.host, record.port) == (
        "ssh",
        "owner",
        "lab.example",
        2222,
    )
    # The endpoint and the launcher the server's own launcher reported, pinned to the root.
    assert record.remote_endpoint == "/srv/fu/run/control.sock"
    assert record.remote_launcher == "/srv/bin/finishup"
    assert record.remote_root == "/srv/fu"
    cached = read_cached_profile(targets.target_root(record.target_id))
    assert cached is not None and (cached.identity_type, cached.identity) == (
        "ssh_host_key",
        IDENTITY,
    )
    assert record.consent is not None and record.consent.level == "L1"
    # A known host key asks nothing; the disclosure and the typed name were on the console.
    assert server_cli._HOST_KEY_QUESTION not in console.text  # pyright: ignore[reportPrivateUsage]
    assert not any(server.asked())
    assert "Use it with 'finishup server use lab'." in result.stdout
    # An SSH server is listed as one this release reaches (an HTTPS one would not be).
    listed = _invoke("list")
    (row,) = [line for line in listed.stdout.splitlines() if record.target_id in line]
    assert row.endswith("ssh://owner@lab.example:2222/srv/fu") or "not available" not in row
    assert "not available" not in row
    # The address, the name and the paths travel to OpenSSH and the owner's display only.
    assert all("lab.example" not in line for line in result.stderr.splitlines())


def test_an_unknown_host_key_is_asked_about_once_on_the_console(
    server: FakeServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    server.set(known="unknown", answer="yes")
    console = _console(monkeypatch, b"listed", b"lab")

    result = _invoke("add", "lab", "ssh://owner@lab.example")

    assert result.exit_code == 0, result.output
    assert console.text.count(server_cli._HOST_KEY_QUESTION) == 1  # pyright: ignore[reportPrivateUsage]
    assert server.asked() == [False, True, False, False]


def test_a_declined_host_key_adds_nothing_and_names_the_way_on(
    server: FakeServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    server.set(known="unknown", answer="no")
    console = _console(monkeypatch, b"listed", b"lab")

    result = _invoke("add", "lab", "ssh://owner@lab.example")

    assert result.exit_code != 0
    assert result.stderr.startswith("remote_host_key_unconfirmed:")
    assert "answer yes to OpenSSH's question" in result.stderr
    assert targets.list_targets() == ()
    # Only the host key was asked about; no disclosure or typed name followed.
    assert console.answers == [b"listed", b"lab"]


def test_a_changed_host_key_is_refused_without_a_question(
    server: FakeServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RE-7: nothing claims a question that never comes."""

    server.set(known="changed", answer="yes")
    console = _console(monkeypatch, b"listed", b"lab")

    result = _invoke("add", "lab", "ssh://owner@lab.example")

    assert result.exit_code != 0
    assert result.stderr.startswith("remote_identity_changed:")
    assert server_cli._HOST_KEY_QUESTION not in console.text  # pyright: ignore[reportPrivateUsage]
    assert console.opened == 0 and targets.list_targets() == ()


def test_an_unknown_host_key_without_the_trusted_console_is_never_asked(
    server: FakeServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    server.set(known="unknown", answer="yes")
    monkeypatch.setattr(trusted_console, "TrustedForegroundConsole", _NoConsole())

    result = _invoke("add", "lab", "ssh://owner@lab.example")

    assert result.exit_code != 0
    assert result.stderr.startswith("trusted_console_required:")
    assert server.asked() == [False]
    assert targets.list_targets() == ()


def test_zero_network_refuses_before_anything_reaches_the_server(
    server: FakeServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SRV-3: this computer's zero-network state is asked before discovery."""

    monkeypatch.setattr(server_cli, "_zero_network_in_force", lambda: True)
    console = _console(monkeypatch, b"listed", b"lab")

    result = _invoke("add", "lab", "ssh://owner@lab.example")

    assert result.exit_code != 0
    assert result.stderr.startswith("zero_network_in_force:")
    assert server.calls() == [] and console.opened == 0
    assert targets.list_targets() == ()


def test_a_folder_openssh_cannot_use_as_written_refuses_before_the_server_is_asked(
    server: FakeServer, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """B2: this computer's FinishUP folder holds '%' (OpenSSH would expand it): refused first."""

    state = tmp_path / "st%h"
    state.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    console = _console(monkeypatch, b"listed", b"lab")

    result = _invoke("add", "lab", "ssh://owner@lab.example")

    assert result.exit_code != 0
    assert result.stderr.startswith("ssh_path_unusable:")
    assert server.calls() == [] and console.opened == 0
    assert targets.list_targets() == ()


def test_an_endpoint_openssh_cannot_forward_is_refused_before_anything_is_recorded(
    server: FakeServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """B2: the endpoint the server reports is checked before the consent and the record."""

    script = server.directory / "ssh"
    script.write_text(
        script.read_text().replace('"/srv/fu/run/control.sock"', '"/srv/f:u/run/control.sock"')
    )
    console = _console(monkeypatch, b"listed", b"lab")

    result = _invoke("add", "lab", "ssh://owner@lab.example")

    assert result.exit_code != 0
    assert result.stderr.startswith("ssh_path_unusable:")
    assert console.opened == 0 and targets.list_targets() == ()


def test_an_endpoint_with_spaces_is_recorded_as_reported(
    server: FakeServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """B2: a server whose FinishUP lives under "Application Support" (macOS) is added."""

    # As under a macOS home's "Library/Application Support" (no account's path is named here).
    endpoint = "/srv/Library/Application Support/finishup/run/control.sock"
    script = server.directory / "ssh"
    script.write_text(script.read_text().replace('"/srv/fu/run/control.sock"', f'"{endpoint}"'))
    _console(monkeypatch, b"listed", b"lab")

    result = _invoke("add", "lab", "ssh://owner@lab.example")

    assert result.exit_code == 0, result.output
    (record,) = targets.list_targets()
    assert record.remote_endpoint == endpoint


def test_a_server_whose_endpoint_is_session_bound_is_named(
    server: FakeServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = server.directory / "ssh"
    script.write_text(
        script.read_text().replace(
            '"runtime_dir_session_bound": False', '"runtime_dir_session_bound": True'
        )
    )
    _console(monkeypatch, b"listed", b"lab")

    result = _invoke("add", "lab", "ssh://owner@lab.example")

    assert result.exit_code == 0, result.output
    assert "disappears at its last logout" in result.stdout


def test_use_asks_again_over_ssh_and_says_what_is_held_for_it(
    server: FakeServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    _console(monkeypatch, b"listed", b"lab")
    assert _invoke("add", "lab", "ssh://owner@lab.example").exit_code == 0
    calls = len(server.calls())
    console = _console(monkeypatch, b"lab")

    def held(_record: object) -> object:
        class _Groups:
            held = ("/srv/a", "/srv/b")

        return _Groups()

    monkeypatch.setattr(server_cli, "repository_here", lambda: None)
    monkeypatch.setattr(server_cli, "repository_groups", held)

    result = _invoke("use", "lab")

    assert result.exit_code == 0, result.output
    # The profile was fetched again over SSH (strict: the key is known) and agreed to again.
    assert [call[-1] for call in server.calls()[calls:]] == [
        "/srv/bin/finishup service profile --json"
    ]
    assert "Type the target name" not in result.stdout and console.opened == 1
    assert (
        "2 repositories whose privacy policy on this computer allows no network use are held "
        "for lab" in result.stdout
    )
    record = targets.find_target("lab")
    assert targets.read_selected_target_id() == record.target_id


def test_a_closed_kind_is_still_refused_before_anything(
    server: FakeServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Every remote kind is open from layer 5: HTTPS is closed in this process as the example.
    monkeypatch.setattr("finishup.client.authorization.OPEN_REMOTE_KINDS", frozenset({"ssh"}))
    console = _console(monkeypatch, b"listed", b"lab")

    result = _invoke("add", "lab", "https://lab.example")

    assert result.exit_code == 2
    assert result.stderr.startswith("remote_kind_unavailable:")
    assert server.calls() == [] and console.opened == 0
