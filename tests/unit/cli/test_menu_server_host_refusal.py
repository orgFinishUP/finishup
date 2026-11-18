"""The menu refuses a server-host action while its root is a server elsewhere (ADR-051, layer 1).

Every menu action stands for a CLI command (``menu._ACTION_COMMANDS``), and the one scope table
(``cli.command_scope``) says which of them administer the server host: the provider setup, the
harness skill, the setup posture, unlocking and initializing the vault. The CLI refuses those
commands while this process's root is a server elsewhere; the menu called their helpers
directly, so Provider -> API setup asked its questions and wrote the provider binding. Each one
now names the remote root's refusal (its phase and the directive of its way back) on stderr
before any prompt, ceremony, service call or write. Every other action, and every action on a
server on this computer, runs as before.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

import finishup.client.everyday_policy as everyday_policy
from builders.server_targets import ambient_home
from finishup.cli import app as cli
from finishup.cli import menu
from finishup.cli.command_scope import command_scope, iter_command_paths
from finishup.client import targets
from finishup.config.paths import ISOLATED_ROOT_ENV_NAMES, active_root, reset_selection_memo
from finishup.protocol.recovery import directive_for

_AT = datetime(2026, 11, 7, 9, 30, tzinfo=UTC)
_HEAD = (
    "this action runs on the FinishUP server host, and the server this process uses is "
    "elsewhere and refused before anything is sent, so nothing was asked or changed"
)
_SUBMENUS = {
    "harness": menu._harness_menu,  # pyright: ignore[reportPrivateUsage]
    "provider": menu._provider_menu,  # pyright: ignore[reportPrivateUsage]
    "privacy": menu._privacy_menu,  # pyright: ignore[reportPrivateUsage]
    "service": menu._service_menu,  # pyright: ignore[reportPrivateUsage]
}
_ACTIONS = menu._ACTION_COMMANDS  # pyright: ignore[reportPrivateUsage]
_SERVER_HOST_ACTIONS = sorted(
    (submenu, choice)
    for submenu, choices in _ACTIONS.items()
    for choice, command in choices.items()
    if command_scope(command) == "server_host"
)


@dataclass(frozen=True, slots=True)
class _Refused:
    phase: str
    continuation: str


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        user_home = root / "home"
        user_home.mkdir(mode=0o700)
        monkeypatch.setenv("HOME", str(user_home))
        yield root


@pytest.fixture(params=["selection", "zero_network", "stale_disclosure", "isolation"])
def refused(
    home: Path, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> _Refused:
    """A remote root: a selection another build left (authorized under the current disclosure,
    with this computer's last report of zero-network, or under an older disclosure), or an
    isolation variable naming a remote target's root."""

    with targets.registry_lock():
        record, root = targets.new_remote_target("lab", "https", base_url="https://lab.example")
        if request.param != "isolation":
            targets.write_selection(record)
    if request.param == "isolation":
        monkeypatch.setenv(ISOLATED_ROOT_ENV_NAMES[0], str(root))
    reset_selection_memo()
    assert active_root() == root
    if request.param == "zero_network":
        everyday_policy.record_reported_policy(zero_network=True, now=_AT)
        return _Refused("zero_network_remote_selected", "zero_network_local_server_required")
    if request.param == "stale_disclosure":
        monkeypatch.setattr(targets, "DISCLOSURE_VERSION", targets.DISCLOSURE_VERSION + 1)
        return _Refused("target_reauthorization_required", "server_reauthorization_required")
    if request.param == "isolation":
        return _Refused("target_root_is_remote", "remote_root_override_clear")
    return _Refused("target_root_is_remote", "remote_target_no_local_service")


@pytest.fixture
def reached(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every prompt, ceremony, service call and write a menu action could make, recorded and
    failed: a refused action reaches none of them."""

    import finishup.cli.codex_subscription as codex_subscription
    import finishup.cli.privacy_setup as privacy_setup
    import finishup.cli.provider_binding as provider_binding
    import finishup.cli.unlock as unlock
    import finishup.config.write as config_write
    import finishup.service.client as service_client

    calls: list[str] = []

    def never(name: str) -> object:
        def call(*_args: object, **_kwargs: object) -> object:
            calls.append(name)
            raise AssertionError(f"a refused menu action reached {name}")

        return call

    for target, name in (
        ("typer.prompt", "typer.prompt"),
        ("typer.confirm", "typer.confirm"),
        ("getpass.getpass", "getpass"),
    ):
        monkeypatch.setattr(target, never(name))
    for module, names in (
        (provider_binding, ("prompt_provider_endpoint_binding", "write_provider_binding")),
        (config_write, ("write_provider_binding",)),
        (
            codex_subscription,
            (
                "prompt_codex_subscription_setup",
                "codex_subscription_status",
                "codex_subscription_disconnect",
                "codex_subscription_rollback",
                "codex_subscription_repair_plan",
                "codex_subscription_repair",
                "codex_evaluator_runtime_status",
            ),
        ),
        (
            unlock,
            (
                "initialize_passphrase_vault",
                "unlock_vault",
                "retry_keyring",
                "set_provider_credential",
                "rotate_provider_credential",
            ),
        ),
        (privacy_setup, ("get_privacy_setup_snapshot",)),
        (cli, ("build_service_client",)),
        (service_client, ("connect_control", "_spawn_service_process")),
    ):
        for name in names:
            monkeypatch.setattr(module, name, never(name))
    return calls


def _tree(root: Path) -> set[tuple[str, int]]:
    found: set[tuple[str, int]] = set()
    for folder, directories, files in os.walk(root):
        for name in (*directories, *files):
            path = Path(folder) / name
            found.add((str(path.relative_to(root)), path.lstat().st_size))
    return found


def _answer(monkeypatch: pytest.MonkeyPatch, choice: str | None) -> list[tuple[str, ...]]:
    """``menu._ask`` answers ``choice`` once (``None``: it must not be asked); the choices it was
    offered are returned."""

    offered: list[tuple[str, ...]] = []

    def ask(choices: tuple[str, ...]) -> str:
        offered.append(choices)
        if choice is None:
            raise AssertionError("the submenu was refused before its first question")
        return choice

    monkeypatch.setattr(menu, "_ask", ask)
    return offered


def test_every_menu_action_names_a_real_cli_command_and_every_choice_is_classified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The table is the menu's own: each action names a command the CLI registers, and each
    submenu offers exactly the actions the table classifies (plus going back)."""

    registered = {path for path, _info in iter_command_paths(cli.app)}
    for choices in _ACTIONS.values():
        assert set(choices.values()) <= registered
    for submenu, run in _SUBMENUS.items():
        offered = _answer(monkeypatch, menu._BACK)  # pyright: ignore[reportPrivateUsage]
        run()
        assert offered == [(*_ACTIONS[submenu], menu._BACK)]  # pyright: ignore[reportPrivateUsage]
    # The provider submenu is all server-host, so it is refused at its entry.
    assert all(command_scope(command) == "server_host" for command in _ACTIONS["provider"].values())
    assert _SERVER_HOST_ACTIONS == sorted(
        [("harness", choice) for choice in ("4", "5", "6", "7")]
        + [("provider", choice) for choice in _ACTIONS["provider"]]
        + [("privacy", "2"), ("service", "2"), ("service", "3")]
    )


@pytest.mark.parametrize(("submenu", "choice"), _SERVER_HOST_ACTIONS)
def test_a_server_host_action_is_refused_before_it_asks_or_writes(
    home: Path,
    refused: _Refused,
    reached: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    submenu: str,
    choice: str,
) -> None:
    offered = _answer(monkeypatch, None if submenu == "provider" else choice)
    before = _tree(home)

    _SUBMENUS[submenu]()

    captured = capsys.readouterr()
    directive = directive_for(refused.continuation)
    assert directive is not None
    assert captured.err.startswith(
        f"{refused.phase}: {_HEAD}\n"
        f"Continuation: {refused.continuation}\n"
        f"Next: {directive.directive}\n"
    )
    assert reached == []
    assert len(offered) == (0 if submenu == "provider" else 1)
    if submenu == "provider":
        assert captured.out == ""
    assert "lab.example" not in captured.out + captured.err
    assert _tree(home) == before


def test_an_action_that_does_not_administer_the_server_host_is_not_refused_here(
    refused: _Refused, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Harness registration is this computer's own (``client_only``): it runs as before."""

    ran: list[str] = []
    _answer(monkeypatch, "1")
    monkeypatch.setattr(menu, "_harness_registration", ran.append)

    menu._harness_menu()  # pyright: ignore[reportPrivateUsage]

    assert ran == ["status"]
    assert refused.phase not in capsys.readouterr().err


def test_a_server_on_this_computer_runs_the_action(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The everyday server and a named local one are the server host: nothing is refused."""

    import finishup.cli.provider_binding as provider_binding

    ran: list[str] = []
    monkeypatch.setattr(
        provider_binding, "prompt_provider_endpoint_binding", lambda: ran.append("api") or None
    )
    _answer(monkeypatch, "1")
    menu._provider_menu()  # pyright: ignore[reportPrivateUsage]
    with targets.registry_lock():
        record, _root = targets.new_local_target("work")
        targets.write_selection(record)
    reset_selection_memo()
    menu._provider_menu()  # pyright: ignore[reportPrivateUsage]

    assert ran == ["api", "api"]
