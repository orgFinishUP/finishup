"""``finishup server``: every way in has its way out, refusals are bounded, and hosts never move.

ADR-051 (design sections 5 and 6): ``add``/``remove``, ``use NAME``/``use local`` and
``connect``/``disconnect`` are reverse pairs; ``status --json`` is the generated
``server-target-status`` 1.0.0 contract. The remote kinds (``ssh``, ``https``, ``local_port``) are
closed in this release: ``add`` refuses them with ``remote_kind_unavailable`` before any prompt,
policy check, probe or write; ``use`` refuses a remote record (one another build wrote) and leaves
the selection unchanged; ``login`` refuses before reading anything, while ``logout`` stays the
offline way to delete a key such a record has; ``list`` and ``status`` show a remote record as not
available. Names and hosts appear only in owner displays; an isolation root or pin refuses
selection changes; a selection is never stamped into a host registration, and ``upgrade`` still
runs with one.
"""

from __future__ import annotations

import contextlib
import json
import re
import shutil
from collections.abc import Callable, Generator, Iterator
from dataclasses import replace
from pathlib import Path
from typing import Final, cast

import pytest
from typer.testing import CliRunner, Result

from builders.server_targets import StandInRuntime, ambient_home, remote_runtime
from finishup.cli import app as cli
from finishup.cli import server as server_cli
from finishup.cli import trusted_console
from finishup.client import targets
from finishup.client.credentials import SERVER_CREDENTIAL_SERVICE
from finishup.client.target_runtime import ProbeResult
from finishup.config.paths import ISOLATED_ROOT_ENV_NAMES, active_root, reset_selection_memo
from finishup.protocol.canonical import JsonValue
from finishup.protocol.schemas import validate_schema_instance

_RUNNER = CliRunner()
_KEY = "fuk_0123456789ab_" + "A" * 43


class _MemoryKeyring:
    """An allowlisted-looking platform store held in memory."""

    def __init__(self) -> None:
        self.entries: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.entries.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.entries[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        del self.entries[(service, username)]


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        # Every remote kind is open from layer 5 (``test_server_https_add`` covers HTTPS and
        # ports): these tests keep them closed in process, with no runtime, as the closed kinds'
        # example (a test that needs one registers a stand-in).
        monkeypatch.setattr("finishup.client.authorization.OPEN_REMOTE_KINDS", frozenset({"ssh"}))
        from finishup.client import target_runtime

        loaders = dict(target_runtime._RUNTIME_LOADERS)  # pyright: ignore[reportPrivateUsage]
        for kind in ("https", "local_port"):
            loaders.pop(kind, None)
        monkeypatch.setattr(target_runtime, "_RUNTIME_LOADERS", loaders)
        yield root


@pytest.fixture
def no_platform_store(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("finishup.client.credentials._platform_backend", lambda: None)


def _another_builds_target(
    name: str,
    kind: str = "https",
    *,
    select: bool = False,
    key: bool = False,
) -> tuple[targets.ServerTarget, Path]:
    """A remote record as another build (or a hand edit) left it: this release adds none.

    ``key`` stores an API key for it the way that build's ``login`` did (in the platform store
    when one is loaded, else an owner-only file) and records where.
    """

    from finishup.client.credentials import KeyringOrFileCredential

    with targets.registry_lock():
        if kind == "ssh":
            record, root = targets.new_remote_target(
                name, "ssh", user="owner", host=f"{name}.example", port=22
            )
        else:
            base = "https://127.0.0.1:9443" if kind == "local_port" else f"https://{name}.example"
            record, root = targets.new_remote_target(
                name, cast(targets.TargetKind, kind), base_url=base
            )
        if key:
            location = KeyringOrFileCredential(record.target_id, root, recorded=None).store(_KEY)
            record = replace(record, credential=location)
            targets.write_target(root, record)
        if select:
            targets.write_selection(record)
    reset_selection_memo()
    return record, root


def _invoke(*arguments: str) -> Result:
    reset_selection_memo()
    return _RUNNER.invoke(cli.app, ["server", *arguments])


def _plain(text: str) -> str:
    """Help text without terminal styling: CI forces colour, so options and names carry escapes."""

    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)


def _status_json(*arguments: str) -> dict[str, JsonValue]:
    result = _invoke("status", *arguments, "--json")
    assert result.exit_code == 0, result.output
    document = cast(dict[str, JsonValue], json.loads(result.stdout))
    validate_schema_instance("server-target-status", "1.0.0", cast(JsonValue, document))
    return document


def _not_running(_self: object, _root: Path | None) -> object:
    from finishup.client.target_runtime import ProbeResult

    return ProbeResult("not_running", reason="service_unavailable")


@pytest.fixture
def quiet_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """Probe without a service: the local runtime reports ``not_running`` without connecting."""

    monkeypatch.setattr("finishup.client.target_runtime.LocalTargetRuntime.probe", _not_running)


@pytest.mark.parametrize(
    "arguments",
    [(), *(((command.name or ""),) for command in server_cli.server_app.registered_commands)],
    ids=lambda arguments: "-".join(arguments) or "server",
)
def test_every_server_command_renders_its_help(home: Path, arguments: tuple[str, ...]) -> None:
    # Help renders as Rich markup: a bracketed address part such as ``[/base]`` once parsed as a
    # closing tag and turned ``server add --help`` into internal_error.
    result = _invoke(*arguments, "--help")
    assert result.exit_code == 0, result.output
    assert result.exception is None
    assert "internal_error" not in result.output


def test_the_help_offers_servers_on_this_computer_over_ssh_and_over_https(home: Path) -> None:
    """SSH (layer 4), HTTPS and port servers (layer 5) are open in this release: ``login`` and
    ``logout`` (API keys) are shown in ``server --help``, as are ``set``, ``folders`` and
    ``repositories``; ``add --help`` names the ``ssh://`` and ``https://`` addresses and their
    options. Every command shows its own help."""

    listing = _invoke("--help")
    assert listing.exit_code == 0, listing.output
    # The registry, not the rendered panel: help is box-drawn or plain depending on the terminal.
    shown = {
        command.name
        for command in server_cli.server_app.registered_commands
        if command.name is not None and not command.hidden
    } | {
        group.name
        for group in server_cli.server_app.registered_groups
        if group.name is not None and not group.hidden
    }
    assert shown == {
        "add",
        "list",
        "use",
        "status",
        "test",
        "remove",
        "connect",
        "disconnect",
        "set",
        "login",
        "logout",
        "folders",
        "repositories",
        "code",
    }
    words = set(re.findall(r"[a-z]+", _plain(listing.stdout)))
    assert {"add", "list", "use", "status", "test", "remove", "connect", "disconnect"} <= words
    assert {"login", "logout"} <= words

    add = _invoke("add", "--help")
    assert add.exit_code == 0, add.output
    add_help = _plain(add.stdout)
    assert "--local" in add_help
    for ssh in ("ssh://", "--remote-root", "--remote-launcher", "--outside-reads"):
        assert ssh in add_help
    for https in ("https://", "--port", "--ca-file", "--tls-pin", "--key-file"):
        assert https in add_help
    for hidden in (("login", "--help"), ("logout", "--help"), ("folders", "--help")):
        shown = _invoke(*hidden)
        assert shown.exit_code == 0, (hidden, shown.output)


def test_add_use_and_their_reverses_for_a_named_local_server(home: Path, quiet_probe: None) -> None:
    added = _invoke("add", "work", "--local")
    assert added.exit_code == 0, added.output
    (record,) = targets.list_targets()
    root = targets.target_root(record.target_id)
    assert (root / "state" / "instance-identity.json").is_file()

    listed = _invoke("list")
    assert listed.exit_code == 0
    assert listed.stdout.splitlines()[0].startswith("* local")
    assert "work" in listed.stdout and record.target_id in listed.stdout

    used = _invoke("use", "work")
    assert used.exit_code == 0, used.output
    assert "Restart open agent sessions" in used.stdout
    reset_selection_memo()
    assert active_root() == root
    status = _status_json()
    assert status["source"] == "selection"
    target = cast(dict[str, JsonValue], status["target"])
    assert (target["name"], target["target_id"], target["kind"]) == (
        "work",
        record.target_id,
        "local",
    )
    assert cast(dict[str, JsonValue], status["probe"])["outcome"] == "not_running"

    refused = _invoke("remove", "work")
    assert refused.exit_code == 2
    assert refused.stderr.startswith("target_selected:")

    back = _invoke("use", "local")
    assert back.exit_code == 0
    reset_selection_memo()
    assert active_root() is None
    assert _status_json()["source"] == "ambient"

    removed = _invoke("remove", "work")
    assert removed.exit_code == 0, removed.output
    assert not root.exists()
    assert targets.list_targets() == ()


def test_a_process_still_using_a_removed_target_never_recreates_its_folder(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SRV-1: an MCP bridge remembers the target it started with. After ``use local`` and
    ``remove`` elsewhere, its next on-demand connection refuses with the selection's own
    path-safety token instead of reading the missing folder as a local root, spawning a service
    there and recreating the folder, which then broke every ``finishup server`` command."""

    import asyncio

    from finishup.config.paths import PathSafetyError, selection_override
    from finishup.ports.control import ControlClientKind
    from finishup.service import client as service_client

    def stopped(_self: object, _target: Path | None) -> None:
        return None

    monkeypatch.setattr("finishup.client.target_runtime.LocalTargetRuntime.stop", stopped)
    assert _invoke("add", "devbox", "--local").exit_code == 0
    assert _invoke("use", "devbox").exit_code == 0
    reset_selection_memo()
    bridge = active_root()  # what the bridge resolved when it started
    assert bridge is not None
    assert _invoke("use", "local").exit_code == 0
    assert _invoke("remove", "devbox").exit_code == 0
    assert not bridge.exists()

    async def bridge_connects() -> None:
        await service_client.connect_service_on_demand(
            ControlClientKind.MCP_BRIDGE, timeout_seconds=2.0
        )

    # Back in the bridge: what it resolves still names the folder (the remembered answer is
    # locked in test_target_selection; an override takes the same check).
    with selection_override(bridge):
        with pytest.raises(PathSafetyError):
            service_client._open_service_stderr_log()  # pyright: ignore[reportPrivateUsage]
        with pytest.raises(Exception) as refused:  # noqa: PT011 - the refusal type is private
            asyncio.run(bridge_connects())
    assert service_client.path_refusal_reason(refused.value) == "isolation_root_invalid"
    assert not bridge.exists()
    listed = _invoke("list")
    assert listed.exit_code == 0, listed.output
    assert _invoke("add", "lab", "--local").exit_code == 0


def test_a_leftover_folder_is_reported_and_removed_by_its_id(home: Path) -> None:
    """A registry folder with no record (an add or remove that was interrupted) never keeps the
    registry from being read: ``list`` names it, and ``remove ID`` is its supported repair."""

    assert _invoke("add", "work", "--local").exit_code == 0
    leftover = targets.servers_dir() / "t_0badf00d"
    leftover.mkdir(mode=0o700)
    (leftover / "log").mkdir(mode=0o700)

    listed = _invoke("list")
    assert listed.exit_code == 0, listed.output
    assert "work" in listed.stdout
    assert (
        "Folder t_0badf00d holds no server target record: adding or removing a server was "
        "interrupted, and FinishUP does not use it. Delete it with 'finishup server remove "
        "t_0badf00d'."
    ) in listed.stdout
    (record,) = targets.list_targets()
    target = _invoke("remove", record.target_id)  # a target's folder goes by its name only
    assert target.exit_code == 2 and target.stderr.startswith("target_unknown:")
    assert targets.target_root(record.target_id).is_dir()
    assert _invoke("remove", "t_00000001").stderr.startswith("target_unknown:")

    removed = _invoke("remove", "t_0badf00d")
    assert removed.exit_code == 0, removed.output
    assert removed.stdout == "Removed the leftover server folder t_0badf00d.\n"
    assert not leftover.exists()
    assert "no server target record" not in _invoke("list").stdout


def test_remove_select_local_switches_back_first(home: Path) -> None:
    assert _invoke("add", "work", "--local").exit_code == 0
    assert _invoke("use", "work").exit_code == 0
    removed = _invoke("remove", "work", "--select-local")
    assert removed.exit_code == 0, removed.output
    reset_selection_memo()
    assert active_root() is None
    assert not targets.selection_path().exists()


def test_status_of_the_everyday_server_and_a_named_one(home: Path, quiet_probe: None) -> None:
    assert _invoke("add", "work", "--local").exit_code == 0
    everyday = _status_json()
    target = cast(dict[str, JsonValue], everyday["target"])
    assert (target["name"], target["target_id"], target["credential"]) == (
        "local",
        None,
        "not_applicable",
    )
    named = _status_json("work")
    assert cast(dict[str, JsonValue], named["target"])["name"] == "work"
    assert named["source"] == "ambient"  # status NAME never changes the selection


# SSH servers are open (layer 4; ``tests/unit/cli/test_server_ssh_add.py``); these stay closed.
_REMOTE_ADDRESSES: Final = (
    pytest.param(("https://fu.example",), id="https"),
    pytest.param(("https://fu.example", "--tls-pin", "sha256:" + "a" * 64), id="https-pin"),
    pytest.param(("https://127.0.0.1:9443",), id="loopback-address"),
    pytest.param(("--port", "9443"), id="port"),
    pytest.param(("https://fu.example", "--outside-reads", "local"), id="outside-reads"),
    # Nothing is parsed to tell the kind: an address that is no address is refused the same.
    pytest.param(("http://fu.example",), id="plain-http"),
    pytest.param(("not an address",), id="not-an-address"),
)


@pytest.mark.parametrize("arguments", _REMOTE_ADDRESSES)
def test_remote_add_is_refused_for_every_kind_before_anything_is_asked_or_written(
    home: Path, monkeypatch: pytest.MonkeyPatch, arguments: tuple[str, ...]
) -> None:
    """HTTPS and port servers are closed in this release: ``server add`` refuses one with
    ``remote_kind_unavailable`` before any trusted-console prompt, zero-network check, probe, dial,
    key prompt or write, says what this release connects to, and adds nothing."""

    from finishup.cli import zero_network_selection

    def never(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("nothing is asked, checked, probed or written for a remote kind")

    monkeypatch.setattr(trusted_console, "TrustedForegroundConsole", never)
    monkeypatch.setattr(zero_network_selection, "everyday_network_state", never)
    monkeypatch.setattr("finishup.service.client.connect_service", never)
    monkeypatch.setattr(server_cli, "runtime_for", never)
    monkeypatch.setattr(targets, "new_remote_target", never)
    monkeypatch.setattr("subprocess.run", never)

    result = _invoke("add", "lab", *arguments)

    assert result.exit_code == 2, result.output
    assert result.stdout == ""
    assert result.stderr == (
        f"remote_kind_unavailable: {server_cli.REMOTE_KIND_UNAVAILABLE}; nothing was added\n"
    )
    assert "over SSH" in result.stderr
    for owner_text in ("lab.example", "fu.example", "owner", "9443", "/srv/fu"):
        assert owner_text not in result.output
    assert targets.list_targets() == ()
    assert not targets.servers_dir().exists() or not any(targets.servers_dir().iterdir())
    assert not targets.selection_path().exists()


@pytest.mark.parametrize(
    "option",
    [
        ("--outside-reads", "local"),
        ("--remote-root", "/srv/fu"),
        ("--remote-launcher", "/opt/fu/bin/finishup"),
        ("--tls-pin", "sha256:" + "a" * 64),
    ],
)
def test_a_server_on_this_computer_takes_no_remote_option(
    home: Path, option: tuple[str, str]
) -> None:
    result = _invoke("add", "work", "--local", *option)
    assert result.exit_code == 2
    assert result.stderr == (
        "usage: --remote-root, --remote-launcher, --ca-file, --tls-pin and --outside-reads are "
        "for a server on another machine, a port or the web; a server on this computer takes "
        "none of them\n"
    )
    assert targets.list_targets() == ()


def test_the_disclosure_names_hook_observations_and_the_content_they_carry(home: Path) -> None:
    """ADR-051 decisions 6 and 12: over a claim-bound connection the hooks send captured content
    (prompts, messages, tool inputs and outputs) as a local service would receive it, so the
    disclosure says so in every mode; and a target confirmed under the disclosure that did not
    say so must be confirmed again before use. (No command shows it in this release: the remote
    kinds that need it are closed; the client attestation keys on its version.)"""

    shown = " ".join(" ".join(server_cli.DISCLOSURE_LINES).split())
    for words in (
        "Hook observations of projects where you gave observation consent are sent too.",
        "once you turn on content capture for a project",
        "your prompts, its messages, and tool inputs and outputs",
        "can name file paths on this computer and hold the contents of files it read, even "
        "outside your project or the folders you list for that server.",
        "Your project folder is named by a keyed label, not its path.",
        # ADR-051 decision 8 (2026-11-07, round 4): amended in place, it narrows what is sent.
        "A project whose privacy policy on this computer allows no network use is held: nothing "
        "from it is sent until you allow it with 'finishup server repositories add'.",
    ):
        assert words in shown
    # The old promise that no path leaves is gone: captured content can name one.
    assert "No file path" not in shown
    assert targets.DISCLOSURE_VERSION >= 2
    record, _root = _another_builds_target("gw")
    assert not record.needs_reauthorization
    assert replace(record, disclosure_version=1).needs_reauthorization


def test_a_named_local_server_has_no_outside_read_mode(home: Path) -> None:
    result = _invoke("add", "work", "--local")
    assert result.exit_code == 0, result.output
    assert "mode" not in result.stdout.replace("finishup setup", "")


def test_the_golden_status_vector_carries_a_remote_targets_outside_reads() -> None:
    """``server-target-status`` 1.0.0 (unreleased, amended in place): a remote target's mode,
    where it came from, and its listed folders (ADR-051 decision 5)."""

    from pydantic import ValidationError

    from finishup.protocol.canonical import canonical_encode
    from finishup.protocol.schemas import SchemaInstanceInvalid
    from finishup.protocol.server_target_status import ServerTargetStatusContract

    raw = (
        Path(__file__).parents[3] / "fixtures/service/server-target-status.case.json"
    ).read_bytes()
    payload = cast(dict[str, JsonValue], json.loads(raw))
    assert canonical_encode(cast(JsonValue, payload)) == raw
    validate_schema_instance("server-target-status", "1.0.0", cast(JsonValue, payload))
    ServerTargetStatusContract.model_validate(payload)
    target = cast(dict[str, JsonValue], payload["target"])
    # The vector shows a state the code produces: ``current`` is whether the confirmed
    # disclosure is this release's (``TargetRecord.needs_reauthorization``).
    from finishup.client.targets import DISCLOSURE_VERSION

    authorization = cast(dict[str, JsonValue], target["authorization"])
    assert authorization["current"] is (authorization["disclosure_version"] == DISCLOSURE_VERSION)
    assert target["outside_reads"] == {
        "folders": ["/srv/team-specs"],
        "mode": "listed",
        "mode_source": "owner",
    }
    wrongs: tuple[dict[str, JsonValue], ...] = (
        {"mode": "open", "mode_source": "owner", "folders": []},
        {"mode": "local", "mode_source": "selection", "folders": []},
        # D2b: no default per kind any more.
        {"mode": "local", "mode_source": "kind_default", "folders": []},
        {"mode": "local", "mode_source": "owner", "folders": ["relative"]},
        {"mode": "local", "mode_source": "owner"},
    )
    for wrong in wrongs:
        broken: dict[str, JsonValue] = {**payload, "target": {**target, "outside_reads": wrong}}
        with pytest.raises(SchemaInstanceInvalid):
            validate_schema_instance("server-target-status", "1.0.0", cast(JsonValue, broken))
        with pytest.raises(ValidationError):
            ServerTargetStatusContract.model_validate(broken)
    # A target that is not remote carries none, and the field is never left out.
    local = {**payload, "target": {**target, "kind": "local", "outside_reads": None}}
    validate_schema_instance("server-target-status", "1.0.0", cast(JsonValue, local))
    absent = {**payload, "target": {k: v for k, v in target.items() if k != "outside_reads"}}
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("server-target-status", "1.0.0", cast(JsonValue, absent))
    not_chosen: dict[str, JsonValue] = {
        "mode": "listed",
        "mode_source": "not_chosen",
        "folders": [],
    }
    validate_schema_instance(
        "server-target-status",
        "1.0.0",
        cast(JsonValue, {**payload, "target": {**target, "outside_reads": not_chosen}}),
    )


def test_the_golden_status_vector_carries_a_remote_targets_repositories() -> None:
    """``server-target-status`` 1.0.0 (unreleased, amended in place, ADR-051 decision 8): what a
    remote target holds, what the owner kept here or allowed, and this folder's state."""

    from pydantic import ValidationError

    from finishup.protocol.schemas import SchemaInstanceInvalid
    from finishup.protocol.server_target_status import ServerTargetStatusContract

    raw = (
        Path(__file__).parents[3] / "fixtures/service/server-target-status.case.json"
    ).read_bytes()
    payload = cast(dict[str, JsonValue], json.loads(raw))
    target = cast(dict[str, JsonValue], payload["target"])
    repositories = cast(dict[str, JsonValue], target["repositories"])
    assert repositories == {
        "allowed": [
            {
                "allowed_at": "2026-11-07T09:35:00.000Z",
                "state": "applies",
                "worktree": "/srv/dev/site",
            }
        ],
        "held": [
            {
                "cause": "not_allowed",
                "reported_at": "2026-11-07T09:30:00.000Z",
                "worktree": "/srv/dev/ledger",
            }
        ],
        "here": {
            "cause": "not_allowed",
            "policy_read": "last_reported",
            "reported_at": "2026-11-07T09:30:00.000Z",
            "state": "held",
        },
        "kept": [
            {
                "kept_at": "2026-11-07T09:40:00.000Z",
                "state": "applies",
                "worktree": "/srv/dev/notes",
            }
        ],
        "record": "readable",
        "reports": "readable",
    }
    here = cast(dict[str, JsonValue], repositories["here"])
    rights: tuple[dict[str, JsonValue], ...] = (
        {**repositories, "here": None},
        {**repositories, "here": {**here, "policy_read": "live", "reported_at": None}},
        {**repositories, "here": {**here, "state": "kept", "cause": None}},
        {**repositories, "here": {**here, "state": "held", "cause": "grant_changed"}},
        {
            **repositories,
            "here": {
                "state": "not_reported",
                "cause": None,
                "policy_read": None,
                "reported_at": None,
            },
        },
        {
            **repositories,
            "held": [
                {"worktree": None, "reported_at": here["reported_at"], "cause": "grant_changed"}
            ],
        },
        {
            **repositories,
            "reports": "unreadable",
            "record": "unreadable",
            "held": [],
            "kept": [],
            "allowed": [],
        },
    )
    for right in rights:
        document = {**payload, "target": {**target, "repositories": right}}
        validate_schema_instance("server-target-status", "1.0.0", cast(JsonValue, document))
        ServerTargetStatusContract.model_validate(document)
    wrongs: tuple[dict[str, JsonValue], ...] = (
        # A cause only on a held repository, and always on one.
        {**repositories, "here": {**here, "state": "not_held"}},
        {**repositories, "here": {**here, "cause": None}},
        # Last reported always says when; live and not reported never do.
        {**repositories, "here": {**here, "reported_at": None}},
        {**repositories, "here": {**here, "policy_read": "live"}},
        {**repositories, "here": {**here, "state": "not_reported", "cause": None}},
        {**repositories, "here": {**here, "state": "remembered"}},
        # Paths are absolute, without control characters, at most 1024 characters.
        {
            **repositories,
            "held": [
                {
                    "worktree": "relative/path",
                    "reported_at": here["reported_at"],
                    "cause": "not_allowed",
                }
            ],
        },
        {
            **repositories,
            "kept": [
                {"worktree": "/srv/a\u0001b", "kept_at": here["reported_at"], "state": "applies"}
            ],
        },
        {
            **repositories,
            "allowed": [
                {
                    "worktree": "/" + "x" * 1_024,
                    "allowed_at": here["reported_at"],
                    "state": "applies",
                }
            ],
        },
        {
            **repositories,
            "allowed": [
                {"worktree": "/srv/site", "allowed_at": here["reported_at"], "state": "maybe"}
            ],
        },
        {**repositories, "record": "damaged"},
        {k: v for k, v in repositories.items() if k != "kept"},
    )
    for wrong in wrongs:
        broken: dict[str, JsonValue] = {**payload, "target": {**target, "repositories": wrong}}
        with pytest.raises(SchemaInstanceInvalid):
            validate_schema_instance("server-target-status", "1.0.0", cast(JsonValue, broken))
        with pytest.raises(ValidationError):
            ServerTargetStatusContract.model_validate(broken)
    # A target that is not remote carries none, and the field is never left out.
    local = {
        **payload,
        "target": {**target, "kind": "local", "outside_reads": None, "repositories": None},
    }
    validate_schema_instance("server-target-status", "1.0.0", cast(JsonValue, local))
    absent = {**payload, "target": {k: v for k, v in target.items() if k != "repositories"}}
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("server-target-status", "1.0.0", cast(JsonValue, absent))


def test_server_status_json_carries_the_zero_network_item_the_check_reports(
    home: Path, quiet_probe: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``zero_network_selection`` is the item the zero-network selection check reports: null when
    it reports nothing, its item's fact otherwise, validated against the contract."""

    import finishup.cli.zero_network_selection as zero_network

    assert _status_json()["zero_network_selection"] is None
    item = zero_network.ZeroNetworkSelection(zero_network.REMOTE_SELECTED, "t_1a2b3c4d", "https")
    monkeypatch.setattr(zero_network, "find_zero_network_selection", lambda: item)
    assert _status_json()["zero_network_selection"] == {
        "reason": "zero_network_remote_selected",
        "target_id": "t_1a2b3c4d",
        "kind": "https",
        "detail": None,
        "policy_read": "live",
        "last_reported_at": None,
    }
    # This computer's service could not be asked: what it last reported decides, and says when.
    reported = zero_network.ZeroNetworkSelection(
        zero_network.REMOTE_SELECTED,
        "t_1a2b3c4d",
        "https",
        policy_read="last_reported",
        last_reported_at="2026-11-07T09:30:00.000Z",
    )
    monkeypatch.setattr(zero_network, "find_zero_network_selection", lambda: reported)
    assert _status_json()["zero_network_selection"] == {
        "reason": "zero_network_remote_selected",
        "target_id": "t_1a2b3c4d",
        "kind": "https",
        "detail": None,
        "policy_read": "last_reported",
        "last_reported_at": "2026-11-07T09:30:00.000Z",
    }


def test_the_status_document_carries_the_zero_network_item_by_id_and_token_only() -> None:
    """ADR-051 decision 8: ``zero_network_selection`` is null, or the zero-network item's fact
    (generated id and closed tokens); the field is never left out."""

    from pydantic import ValidationError

    from finishup.protocol.schemas import SchemaInstanceInvalid
    from finishup.protocol.server_target_status import ServerTargetStatusContract

    raw = (
        Path(__file__).parents[3] / "fixtures/service/server-target-status.case.json"
    ).read_bytes()
    payload = cast(dict[str, JsonValue], json.loads(raw))
    assert payload["zero_network_selection"] is None
    rights: tuple[dict[str, JsonValue], ...] = (
        {
            "reason": "zero_network_remote_selected",
            "target_id": "t_1a2b3c4d",
            "kind": "ssh",
            "detail": None,
            "policy_read": "live",
            "last_reported_at": None,
        },
        {
            "reason": "zero_network_selection_unreadable",
            "target_id": None,
            "kind": None,
            "detail": "selection_invalid",
            "policy_read": "live",
            "last_reported_at": None,
        },
        {
            "reason": "zero_network_remote_selected",
            "target_id": "t_1a2b3c4d",
            "kind": "ssh",
            "detail": None,
            "policy_read": "last_reported",
            "last_reported_at": "2026-11-07T09:30:00.000Z",
        },
    )
    for right in rights:
        document = {**payload, "zero_network_selection": right}
        validate_schema_instance("server-target-status", "1.0.0", cast(JsonValue, document))
        ServerTargetStatusContract.model_validate(document)
    wrongs: tuple[dict[str, JsonValue], ...] = (
        {**rights[0], "reason": "zero_network_in_force"},
        {**rights[0], "kind": "local"},
        {**rights[0], "target_id": "devbox"},
        {**rights[1], "detail": "/srv/shared/.config"},
        {k: v for k, v in rights[0].items() if k != "detail"},
        {k: v for k, v in rights[0].items() if k != "policy_read"},
        {**rights[0], "policy_read": "remembered"},
        # The time is there exactly when the state was last reported, in its fixed shape.
        {**rights[0], "last_reported_at": "2026-11-07T09:30:00.000Z"},
        {**rights[2], "last_reported_at": None},
        {**rights[2], "last_reported_at": "yesterday"},
    )
    for wrong in wrongs:
        broken = {**payload, "zero_network_selection": wrong}
        with pytest.raises(SchemaInstanceInvalid):
            validate_schema_instance("server-target-status", "1.0.0", cast(JsonValue, broken))
        with pytest.raises(ValidationError):
            ServerTargetStatusContract.model_validate(broken)
    absent = {k: v for k, v in payload.items() if k != "zero_network_selection"}
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("server-target-status", "1.0.0", cast(JsonValue, absent))


def test_a_probe_not_sent_carries_when_this_computer_reported_zero_network() -> None:
    """RE-4: ``probe.last_reported_at`` is set exactly for ``not_probed``, in its fixed shape."""

    from pydantic import ValidationError

    from finishup.protocol.schemas import SchemaInstanceInvalid
    from finishup.protocol.server_target_status import ServerTargetStatusContract

    raw = (
        Path(__file__).parents[3] / "fixtures/service/server-target-status.case.json"
    ).read_bytes()
    payload = cast(dict[str, JsonValue], json.loads(raw))
    probe = cast(dict[str, JsonValue], payload["probe"])
    assert probe["last_reported_at"] is None
    not_sent: dict[str, JsonValue] = {
        "outcome": "not_probed",
        "reason": "zero_network_in_force",
        "phase": None,
        "service_version": None,
        "service_instance_id": None,
        "service_state": None,
        "vault_mode": None,
        "round_trip_p95_ms": None,
        "samples": 0,
        "last_reported_at": "2026-11-07T09:30:00.000Z",
    }
    document = {**payload, "probe": not_sent}
    validate_schema_instance("server-target-status", "1.0.0", cast(JsonValue, document))
    ServerTargetStatusContract.model_validate(document)
    wrongs: tuple[dict[str, JsonValue], ...] = (
        {**not_sent, "last_reported_at": None},
        {**not_sent, "last_reported_at": "yesterday"},
        {**probe, "last_reported_at": "2026-11-07T09:30:00.000Z"},
        {k: v for k, v in probe.items() if k != "last_reported_at"},
    )
    for wrong in wrongs:
        broken = {**payload, "probe": wrong}
        with pytest.raises(SchemaInstanceInvalid):
            validate_schema_instance("server-target-status", "1.0.0", cast(JsonValue, broken))
        with pytest.raises(ValidationError):
            ServerTargetStatusContract.model_validate(broken)


_MACHINE_SCOPE: Final = {"schema_version": "1.0.0", "scope": {"kind": "machine"}}


class _PolicyClient:
    """A control client whose ``privacy_get_effective`` answers like the wire: a ``JsonObject``.

    Like the service, it answers only a machine-scope request on a connection that names no
    repository; ``privacy_get_setup`` needs a repository and is refused there.
    """

    def __init__(self, reply: object) -> None:
        self.reply = reply
        self.closed = False
        self.requests: list[object] = []

    async def privacy_get_setup(self, _request: object) -> object:
        from finishup.ports.control import ControlError

        raise ControlError("invalid_request")

    async def privacy_get_effective(self, request: object) -> object:
        self.requests.append(request)
        if isinstance(self.reply, BaseException):
            raise self.reply
        return self.reply

    async def close(self) -> None:
        self.closed = True


def _everyday_installation(home: Path) -> None:
    """The marker the everyday vault's initialization writes, in the ambient data folder."""

    bundle = home / "data" / "finishup"
    bundle.mkdir(mode=0o700, parents=True, exist_ok=True)
    (bundle / "installation-state.json").write_bytes(b"{}\n")


def _serve_policy(monkeypatch: pytest.MonkeyPatch, reply: object) -> list[_PolicyClient]:
    from finishup.domain.values import JsonObject
    from finishup.ports.control import ControlError

    clients: list[_PolicyClient] = []

    async def connect(_kind: object, *, workspace_locator: object = None) -> _PolicyClient:
        assert workspace_locator is None
        if isinstance(reply, ControlError) and reply.reason == "service_unavailable":
            raise reply
        client = _PolicyClient(reply)
        clients.append(client)
        return client

    monkeypatch.setattr("finishup.service.client.connect_service", connect)
    monkeypatch.setattr(
        "finishup.cli.provider_status.machine_scope_request",
        lambda: JsonObject(_MACHINE_SCOPE),
    )
    return clients


def _policy(egress: bool) -> object:
    from finishup.domain.values import JsonObject

    return JsonObject({"policy": {"network_egress_permitted": egress, "schema_version": "1.0.0"}})


def test_the_everyday_policy_is_asked_of_the_everyday_server_while_a_target_is_selected(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The read runs in a fresh context, which the caller's context-local override does not
    reach (SRV-7): it must still connect to this computer's server, never the selected one."""

    from finishup.cli import zero_network_selection

    _everyday_installation(home)
    _another_builds_target("alpha", select=True)
    assert active_root() is not None
    from finishup.ports.control import ControlClientKind
    from finishup.service import client as service_client

    clients = _serve_policy(monkeypatch, _policy(True))
    connect = service_client.connect_service
    roots: list[Path | None] = []

    async def recording(kind: ControlClientKind, *, workspace_locator: None = None) -> object:
        roots.append(active_root())
        return await connect(kind, workspace_locator=workspace_locator)

    monkeypatch.setattr(service_client, "connect_service", recording)
    assert zero_network_selection.everyday_network_state() == "network_permitted"
    assert roots == [None] and len(clients) == 1
    (client,) = clients
    assert client.closed
    # A computer-wide question: the installation's machine scope, never a repository's setup.
    assert client.requests == [_MACHINE_SCOPE]


def test_an_installation_whose_identity_cannot_be_read_has_an_unreadable_policy(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.cli import zero_network_selection
    from finishup.cli.provider_status import MachineScopeError

    _everyday_installation(home)
    clients = _serve_policy(monkeypatch, _policy(True))

    def unreadable() -> object:
        raise MachineScopeError("installation_marker_invalid")

    monkeypatch.setattr("finishup.cli.provider_status.machine_scope_request", unreadable)
    assert zero_network_selection.everyday_network_state() == "unreadable"
    assert clients == []


@pytest.mark.parametrize("before", ["everyday", "named_local"])
@pytest.mark.parametrize("kind", ["https", "local_port"])
def test_use_refuses_a_remote_record_and_leaves_the_selection(
    home: Path, monkeypatch: pytest.MonkeyPatch, before: str, kind: str
) -> None:
    """A remote record another build wrote: ``server use`` refuses it with
    ``remote_kind_unavailable`` before any prompt or policy read, and the selection (nothing, or
    a server on this computer) stays exactly as it was."""

    from finishup.cli import zero_network_selection

    def never(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("nothing is asked or read for a remote kind")

    monkeypatch.setattr(trusted_console, "TrustedForegroundConsole", never)
    monkeypatch.setattr(zero_network_selection, "everyday_network_state", never)
    monkeypatch.setattr(server_cli, "runtime_for", never)
    if before == "named_local":
        assert _invoke("add", "work", "--local").exit_code == 0
        assert _invoke("use", "work").exit_code == 0
    selected = targets.read_selected_target_id()
    selection_bytes = targets.selection_path().read_bytes() if selected is not None else None
    record, root = _another_builds_target("lab", kind)
    stored = (root / targets.SERVER_TARGET_FILE_NAME).read_bytes()

    result = _invoke("use", "lab")

    assert result.exit_code == 2, result.output
    assert result.stdout == ""
    assert result.stderr == (
        f"remote_kind_unavailable: {server_cli.REMOTE_KIND_UNAVAILABLE}; the selected server "
        "is unchanged\n"
    )
    assert "lab.example" not in result.output
    assert targets.read_selected_target_id() == selected
    if selection_bytes is not None:
        assert targets.selection_path().read_bytes() == selection_bytes
    # Nothing about the record changed either: no renewed authorization.
    assert (root / targets.SERVER_TARGET_FILE_NAME).read_bytes() == stored
    assert record.target_id not in (
        targets.selection_path().read_text() if targets.selection_path().exists() else ""
    )


def test_use_refuses_a_record_that_turned_remote_before_the_selection_is_written(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``use`` reads the record once to refuse a remote kind early and again under the registry
    lock. A named local record another process rewrote as a remote kind between those reads is
    refused under the lock with ``remote_kind_unavailable``, and no selection is written."""

    from contextlib import contextmanager

    assert _invoke("add", "work", "--local").exit_code == 0
    local = targets.find_target("work")
    root = targets.target_root(local.target_id)
    remote = targets.ServerTarget(
        local.target_id,
        local.name,
        "https",
        local.created_at,
        base_url="https://work.example",
        claim_salt="A" * 43 + "=",
        authorized_at=local.created_at,
        disclosure_version=targets.DISCLOSURE_VERSION,
    )
    real_lock = targets.registry_lock

    @contextmanager
    def turned_remote() -> Generator[None]:
        # Another process rewrites the record after ``use`` read it, before the lock is held.
        targets.write_target(root, remote)
        with real_lock():
            yield

    monkeypatch.setattr(server_cli, "registry_lock", turned_remote)

    result = _invoke("use", "work")

    assert result.exit_code == 2, result.output
    assert result.stdout == ""
    assert result.stderr.startswith("remote_kind_unavailable: ")
    assert result.stderr.endswith("; the selected server is unchanged\n")
    assert "work.example" not in result.output
    assert not targets.selection_path().exists()
    assert targets.read_selected_target_id() is None


def test_list_and_status_show_a_remote_record_as_not_available(
    home: Path, quiet_probe: None
) -> None:
    record, _root = _another_builds_target("lab", "https")

    listed = _invoke("list")
    assert listed.exit_code == 0, listed.output
    lines = listed.stdout.splitlines()
    assert lines[0].startswith("* local") and "(not available" not in lines[0]
    (row,) = [line for line in lines if record.target_id in line]
    assert row.endswith("https://lab.example (not available in this release)")

    # What 'server status lab' prints on a terminal (it prints the JSON document otherwise).
    shown = server_cli.status_lines(
        server_cli.build_status_document("lab"), in_use=server_cli.target_in_use("lab")
    )
    assert list(shown[:2]) == [
        f"Server: lab ({record.target_id}, https); not the server in use",
        f"Not available: {server_cli.REMOTE_KIND_UNAVAILABLE}.",
    ]
    status = _status_json("lab")
    target = cast(dict[str, JsonValue], status["target"])
    assert target["location"] == "https://lab.example"
    probe = cast(dict[str, JsonValue], status["probe"])
    # No remote runtime is registered: a closed token, never a local fallback, nothing sent.
    assert (probe["outcome"], probe["reason"], probe["phase"]) == (
        "unavailable",
        "remote_unreachable",
        "runtime_unavailable",
    )
    assert "claim_salt" not in json.dumps(status)
    # A server on this computer is never marked.
    everyday = server_cli.status_lines(server_cli.build_status_document(None))
    assert not any("Not available" in line for line in everyday)


@pytest.mark.parametrize(
    ("arguments", "reason"),
    [
        (("add", "lab"), "usage"),
        (("add", "lab", "--local", "--port", "9443"), "usage"),
        (("add", "lab", "http://fu.example"), "remote_kind_unavailable"),
        (("add", "lab", "https://user@fu.example"), "remote_kind_unavailable"),
        (("add", "Bad_Name", "https://user@fu.example"), "remote_kind_unavailable"),
        (("add", "local", "--local"), "target_name_reserved"),
        (("add", "Bad_Name", "--local"), "target_name_invalid"),
        (("add", "lab", "--local", "--remote-root", "/srv"), "usage"),
        (
            ("add", "lab", "ssh://lab.example", "--tls-pin", "sha256:" + "a" * 64),
            "target_tls_invalid",
        ),
        (("add", "lab", "ssh://lab.example", "--remote-root", "srv"), "target_path_invalid"),
        (("use", "nowhere"), "target_unknown"),
        (("remove", "nowhere"), "target_unknown"),
        (("login", "nowhere"), "remote_kind_unavailable"),
        (("logout", "nowhere"), "target_unknown"),
    ],
)
def test_refusals_are_closed_tokens_without_owner_text(
    home: Path, arguments: tuple[str, ...], reason: str
) -> None:
    result = _invoke(*arguments)
    assert result.exit_code == 2, result.output
    assert result.stderr.startswith(f"{reason}:")
    for owner_text in ("nowhere", "Bad_Name", "fu.example", "https://user@"):
        assert owner_text not in result.stderr


def test_a_name_already_taken_is_refused(home: Path) -> None:
    assert _invoke("add", "lab", "--local").exit_code == 0
    result = _invoke("add", "lab", "--local")
    assert result.exit_code == 2
    assert result.stderr.startswith("target_name_taken:")
    # A remote kind is refused as closed before its name is even looked at.
    remote = _invoke("add", "lab", "https://fu.example")
    assert remote.exit_code == 2
    assert remote.stderr.startswith("remote_kind_unavailable:")
    assert [record.name for record in targets.list_targets()] == ["lab"]


@pytest.mark.parametrize("kind", ["https", "local_port", "ssh"])
def test_login_is_refused_before_anything_is_read_and_logout_deletes_a_key_offline(
    home: Path, no_platform_store: None, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """``login`` is closed with the remote kinds: refused with ``remote_kind_unavailable`` before
    the target, the key file or a prompt is read, and nothing is stored or sent. ``logout`` is the
    reverse path that stays: it deletes a key another build stored, on this computer only."""

    from finishup.client import credentials

    def never(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("login reads, asks and sends nothing")

    monkeypatch.setattr(trusted_console, "TrustedForegroundConsole", never)
    monkeypatch.setattr(credentials, "read_key_file", never)
    monkeypatch.setattr("finishup.service.client.connect_service", never)
    monkeypatch.setattr(server_cli, "runtime_for", never)
    record, root = _another_builds_target("fu", kind, key=kind != "ssh")
    key_file = home / "key"
    key_file.write_text("not read\n", encoding="ascii")
    key_file.chmod(0o644)  # a shared key file would be refused if it were read at all

    for arguments in (("login", "fu"), ("login", "fu", "--key-file", str(key_file))):
        login = _invoke(*arguments)
        assert login.exit_code == 2, login.output
        assert login.stdout == ""
        assert login.stderr == (
            f"remote_kind_unavailable: {server_cli.REMOTE_KIND_UNAVAILABLE}; no key was read "
            "or stored\n"
        )
    assert (root / targets.SERVER_TARGET_FILE_NAME).is_file()
    stored = root / "config" / "credential" / record.target_id
    if kind == "ssh":
        # An SSH server authenticates with OpenSSH keys: no API key to delete.
        assert not stored.exists()
        assert _invoke("logout", "fu").stderr.startswith("credential_not_applicable:")
        return
    assert stored.read_text(encoding="ascii") == _KEY
    assert targets.find_target("fu").credential == "file"

    # Layer 5: logout stops the target's helper (A-CRED-STALE); a stand-in runtime records it.
    from builders.server_targets import StandInRuntime

    stand_in = StandInRuntime()

    def runtime_for(_kind: str) -> StandInRuntime:
        return stand_in

    monkeypatch.setattr(server_cli, "runtime_for", runtime_for)
    logout = _invoke("logout", "fu")
    assert logout.exit_code == 0, logout.output
    assert logout.stdout == f"Deleted the API key for {record.target_id}.\n"
    assert not stored.exists()
    assert targets.find_target("fu").credential is None
    assert _KEY not in logout.output
    again = _invoke("logout", "fu")
    assert again.exit_code == 0 and "No API key was stored" in again.stdout


_SWITCHED_BACK: Final = (
    "Using this computer's everyday FinishUP server.\n"
    "New hooks and CLI calls use it now. Restart open agent sessions: a running FinishUP MCP "
    "bridge keeps a server on this computer it started with, and ends a connection to a server "
    "elsewhere to follow the new selection.\n"
)


@pytest.mark.parametrize("stuck_stop", [None, 1, 2])
def test_remove_clears_the_selection_first_and_stops_again_right_before_the_folder_goes(
    home: Path, monkeypatch: pytest.MonkeyPatch, stuck_stop: int | None
) -> None:
    """SRV-2: ``remove`` stopped the connection while the selection still named the target, then
    deleted the key, so a fresh hook could start the connection again and the folder was deleted
    under it. Now the selection goes first, and the connection is stopped once more after the key
    is deleted, right before the folder goes; one that then does not stop keeps the folder.

    A remove refused at either stop says what it already did: the switch to this computer's
    server stays and is printed, and a key deleted before the second stop is recorded as gone
    (``server status`` never reports a key that no longer exists) and named in the refusal."""

    from finishup.client.authorization import credential_generation_path
    from finishup.client.target_runtime import TargetRuntimeError

    keyring = _MemoryKeyring()
    monkeypatch.setattr("finishup.client.credentials._platform_backend", lambda: keyring)
    seen: list[tuple[str | None, bool, bool]] = []

    class _Runtime:
        def stop(self, target: Path | None) -> None:
            assert target is not None
            seen.append((targets.read_selected_target_id(), bool(keyring.entries), target.is_dir()))
            if len(seen) == stuck_stop:
                raise TargetRuntimeError("service_unavailable", phase="stop_timeout")

    def runtime_for(_kind: str) -> _Runtime:
        return _Runtime()

    monkeypatch.setattr(server_cli, "runtime_for", runtime_for)
    record, root = _another_builds_target("fu", select=True, key=True)
    assert record.credential == "keyring"

    result = _invoke("remove", "fu", "--select-local")

    assert seen == [(None, True, True), (None, False, True)][: stuck_stop or 2]
    assert targets.read_selected_target_id() is None
    if stuck_stop is None:
        assert result.exit_code == 0, result.output
        assert not root.exists() and targets.list_targets() == ()
        assert result.stdout == f"Removed server target fu ({record.target_id}).\n{_SWITCHED_BACK}"
        return
    assert result.exit_code == 20
    assert result.stdout == _SWITCHED_BACK
    assert root.is_dir()
    (kept,) = targets.list_targets()
    if stuck_stop == 1:
        assert result.stderr == (
            "target_still_connected: the connection this client runs for that target did not "
            "stop in time, so nothing was removed; run the same command again\n"
        )
        assert (kept.credential, len(keyring.entries)) == ("keyring", 1)
        # Nothing was done to the key, so no connection made under it is ended (ADR-052, O8).
        assert not credential_generation_path(root).exists()
    else:
        assert result.stderr == (
            "target_still_connected: the connection this client runs for that target started "
            "again and did not stop in time, so its folder was kept, but its API key was already "
            "deleted; run the same command again, or 'finishup server login' to keep using that "
            "server\n"
        )
        # ``server status`` reports the record's credential: "none", not a key that is gone.
        assert (kept.credential, len(keyring.entries)) == (None, 0)
        # The key went, so every connection made under it ends (ADR-052, O8).
        assert credential_generation_path(root).exists()


@pytest.mark.parametrize("record_left", [True, False])
def test_a_folder_changed_while_it_is_removed_is_refused_with_the_way_to_finish(
    home: Path, monkeypatch: pytest.MonkeyPatch, record_left: bool
) -> None:
    """A-REMOVE-RACE: an OSError from deleting the folder (something wrote into it meanwhile)
    surfaced as a bare internal_error after the selection was switched and the key deleted. Now
    the refusal says the folder was only partly removed, that the key is gone, and how to finish:
    the same command while the record is left, else the leftover's id that 'list' names."""

    import errno

    keyring = _MemoryKeyring()
    monkeypatch.setattr("finishup.client.credentials._platform_backend", lambda: keyring)
    record, root = _another_builds_target("fu", select=True, key=True)
    real_remove = targets.remove_target_root

    def partly(target: targets.ServerTarget) -> None:
        if not record_left:
            (root / targets.SERVER_TARGET_FILE_NAME).unlink()
        raise OSError(errno.ENOTEMPTY, "Directory not empty")

    monkeypatch.setattr(targets, "remove_target_root", partly)

    result = _invoke("remove", "fu", "--select-local")

    assert result.exit_code == 20
    assert result.stdout == _SWITCHED_BACK
    assert result.stderr == (
        "target_partly_removed: the target's folder changed while it was being deleted, so only "
        "part of it was removed, and its API key was already deleted; run the same command "
        "again, or, if 'finishup server list' names a leftover folder instead, 'finishup server "
        "remove' with that folder's id\n"
    )
    assert "fu.example" not in result.output
    assert targets.read_selected_target_id() is None and keyring.entries == {}
    monkeypatch.setattr(targets, "remove_target_root", real_remove)
    if record_left:
        (kept,) = targets.list_targets()
        assert kept.credential is None  # never reported as a key that is gone
        assert _invoke("remove", "fu").exit_code == 0
    else:
        assert targets.list_targets() == ()
        assert record.target_id in _invoke("list").stdout
        assert _invoke("remove", record.target_id).exit_code == 0
    assert not root.exists()


def test_leaving_a_remote_record_without_a_runtime_says_nothing_of_a_connection(
    home: Path, quiet_probe: None
) -> None:
    """A remote record another build selected: ``use local`` is the way back, and with no
    runtime for its kind in this release this client ran nothing for it, so no connection is
    said to have closed."""

    record, _root = _another_builds_target("lab", "https", select=True)

    back = _invoke("use", "local")

    assert back.exit_code == 0, back.output
    assert targets.read_selected_target_id() is None
    assert back.stdout == _SWITCHED_BACK
    assert back.stderr == ""
    assert record.target_id not in back.output


def test_switching_away_from_a_remote_target_stops_what_this_client_runs_for_it(
    home: Path, quiet_probe: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-051 decision 8: the way out of a remote selection stops its traffic. Where a runtime
    is registered for the kind (none is in this release), ``use local``, or ``use`` of a server
    on this computer, stops the left target's runtime as ``server disconnect`` does; leaving a
    server on this computer, or one never left, stops nothing."""

    from finishup.client.target_runtime import LocalTargetRuntime

    runtime = remote_runtime(monkeypatch)
    local_stops: list[Path | None] = []

    def stop(_self: object, target: Path | None) -> None:
        local_stops.append(target)

    monkeypatch.setattr(LocalTargetRuntime, "stop", stop)
    assert _invoke("add", "work", "--local").exit_code == 0
    lab, lab_root = _another_builds_target("lab", "ssh", select=True)

    back = _invoke("use", "local")
    assert back.exit_code == 0, back.output
    assert runtime.calls == [("stop", lab_root)]
    assert targets.read_selected_target_id() is None
    assert (
        f"Closed this computer's connection to the server {lab.target_id} (ssh): it no longer "
        "answers that server's requests for your files."
    ) in back.stdout
    assert "Restart open agent sessions" in back.stdout
    assert back.stderr == ""
    assert "lab.example" not in back.output and "owner" not in back.output

    with targets.registry_lock():
        targets.write_selection(lab)
    assert _invoke("use", "work").exit_code == 0
    assert runtime.calls == [("stop", lab_root), ("stop", lab_root)]
    plain = _invoke("use", "local")
    assert plain.exit_code == 0
    assert len(runtime.calls) == 2 and local_stops == []
    assert "connection to the server" not in plain.output


def test_a_switch_whose_left_connection_did_not_stop_still_switches_and_says_how_to_finish(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The way back always switches; a connection that did not stop in time is said on stderr
    with the command that stops it, by the target's generated id, never its name or address."""

    from finishup.client.target_runtime import TargetRuntimeError

    runtime = remote_runtime(monkeypatch)
    runtime.stop_error = TargetRuntimeError("service_unavailable", phase="stop_timeout")
    record, _root = _another_builds_target("lab", "ssh", select=True)

    back = _invoke("use", "local")

    assert back.exit_code == 0, back.output
    assert targets.read_selected_target_id() is None
    assert "Using this computer's everyday FinishUP server." in back.stdout
    assert back.stderr == (
        f"The connection to the server {record.target_id} (ssh) did not close in time, so it may "
        "still answer that server's requests for your files. Run 'finishup server disconnect' "
        "with that server's name ('finishup server list' shows it).\n"
    )
    assert "lab.example" not in back.output


def test_remove_deletes_a_key_from_the_platform_store(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    keyring = _MemoryKeyring()
    monkeypatch.setattr("finishup.client.credentials._platform_backend", lambda: keyring)
    record, _root = _another_builds_target("fu", key=True)
    assert keyring.entries == {(SERVER_CREDENTIAL_SERVICE, record.target_id): _KEY}
    assert targets.list_targets()[0].credential == "keyring"
    assert _invoke("remove", "fu").exit_code == 0
    assert keyring.entries == {}


def test_logout_is_an_owner_action_that_bumps_the_credential_generation(
    home: Path, no_platform_store: None
) -> None:
    """ADR-052 (O8): every connection made under a key ends once the owner logs out."""

    from finishup.client.authorization import credential_generation_path

    record, root = _another_builds_target("fu", key=True)
    path = credential_generation_path(root)
    assert not path.exists()
    assert _invoke("logout", "fu").exit_code == 0
    first = path.read_bytes()
    assert b"yoetz.credential-generation/1" in first
    assert _invoke("logout", "fu").exit_code == 0
    assert path.read_bytes() != first
    # An SSH target holds no key: logout refuses and bumps nothing.
    _ssh, ssh_root = _another_builds_target("lab", "ssh")
    assert _invoke("logout", "lab").exit_code != 0
    assert not credential_generation_path(ssh_root).exists()
    del record


def test_removing_the_last_server_elsewhere_deletes_the_repository_reports(
    home: Path, no_platform_store: None
) -> None:
    """ADR-052 (O3): the reports exist only while a server elsewhere is recorded, so removing the
    last one is their way out; removing one of two, or a named local server, keeps them."""

    from finishup.client.everyday_policy import record_repository_report, reports_path

    _another_builds_target("one")
    _another_builds_target("two", "ssh")
    with targets.registry_lock():
        targets.new_local_target("work")
    assert record_repository_report("sha256:" + "a" * 64, "/srv/app", no_network=True)
    assert reports_path().exists()

    first = _invoke("remove", "one")
    assert first.exit_code == 0, first.output
    assert reports_path().exists()
    assert "no longer keeps" not in first.output

    last = _invoke("remove", "two")
    assert last.exit_code == 0, last.output
    assert not reports_path().exists()
    assert "No server elsewhere is left" in last.output


class _LockedKeyring:
    """A platform store that is present but cannot be used now (a keychain locked over SSH)."""

    def get_password(self, service: str, username: str) -> str | None:
        raise RuntimeError("locked", service, username)

    def set_password(self, service: str, username: str, password: str) -> None:
        del password
        raise RuntimeError("locked", service, username)

    def delete_password(self, service: str, username: str) -> None:
        raise RuntimeError("locked", service, username)


def test_a_locked_platform_store_never_blocks_removing_a_target_or_logging_out(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SRV-4: a store a key is not recorded in never blocks the way out; a key that stays in the
    store it is recorded in is named (by generated id) and the target is still removed."""

    keyring: object = _MemoryKeyring()
    monkeypatch.setattr("finishup.client.credentials._platform_backend", lambda: keyring)
    _another_builds_target("lab", "ssh")
    kept, _root = _another_builds_target("kept", key=True)
    assert kept.credential == "keyring"
    keyring = None  # no platform store: the next key goes to a file
    fu, _root = _another_builds_target("fu", key=True)
    assert fu.credential == "file"
    keyring = _LockedKeyring()

    logout = _invoke("logout", "fu")
    assert logout.exit_code == 0, logout.output
    assert not (targets.target_root(fu.target_id) / "config" / "credential" / fu.target_id).exists()
    lab = targets.find_target("lab")
    removed = _invoke("remove", "lab")
    assert removed.exit_code == 0, removed.output
    assert removed.stderr == ""
    assert not targets.target_root(lab.target_id).exists()

    left = _invoke("remove", "kept")
    assert left.exit_code == 0, left.output
    assert not targets.target_root(kept.target_id).exists()
    assert left.stderr == (
        "Its API key stays in the platform credential store, which could not be used now (it may "
        "be locked, or this session cannot reach it): unlock it, then delete the entry "
        f"'{SERVER_CREDENTIAL_SERVICE}' for {kept.target_id} with your system's credential tool.\n"
    )
    assert "kept.example" not in left.output


def test_a_key_in_a_platform_store_that_cannot_be_loaded_now_is_kept_and_named(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SRV-4: a key recorded in the platform store, on a machine where no platform store can be
    loaded now (a Linux desktop reached over SSH, with no D-Bus session), was skipped: ``logout``
    said no key was stored and recorded none, and ``remove`` said nothing about the key it left.
    Now ``logout`` refuses and keeps the record, and ``remove`` names the entry it left."""

    keyring = _MemoryKeyring()
    store: object = keyring
    monkeypatch.setattr("finishup.client.credentials._platform_backend", lambda: store)
    fu, _root = _another_builds_target("fu", key=True)
    assert fu.credential == "keyring"
    store = None  # no platform store can be loaded in this session

    logout = _invoke("logout", "fu")
    assert logout.exit_code == 20
    assert logout.stdout == ""
    assert logout.stderr == (
        "credential_store_unavailable: the API key is in the platform credential store, which "
        "could not be used now (it may be locked, or this session cannot reach it), so it was "
        "kept; unlock it, then run the same command again\n"
    )
    assert targets.find_target("fu").credential == "keyring"
    assert len(keyring.entries) == 1

    removed = _invoke("remove", "fu")
    assert removed.exit_code == 0, removed.output
    assert not targets.target_root(fu.target_id).exists()
    assert removed.stderr == (
        "Its API key stays in the platform credential store, which could not be used now (it may "
        "be locked, or this session cannot reach it): unlock it, then delete the entry "
        f"'{SERVER_CREDENTIAL_SERVICE}' for {fu.target_id} with your system's credential tool.\n"
    )
    assert len(keyring.entries) == 1


def test_connect_and_disconnect_dispatch_to_a_registered_remote_runtime(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The seam a later layer fills: a runtime registered for a remote kind is what ``connect``
    and ``disconnect`` call, with that target's root."""

    runtime = remote_runtime(monkeypatch)
    _record, root = _another_builds_target("lab", "ssh")
    assert _invoke("connect", "lab").exit_code == 0
    assert _invoke("disconnect", "lab").exit_code == 0
    assert runtime.calls == [("ensure_ready", root), ("stop", root)]


@pytest.mark.parametrize("kind", ["ssh", "https"])
def test_a_stopped_remote_service_is_named_alike_for_every_kind(
    home: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """An SSH server has no gateway: the line for a server whose FinishUP service does not run
    names the service and the one fix, the same for every kind of server."""

    from finishup.client.target_runtime import TargetRuntimeError

    runtime = remote_runtime(monkeypatch)
    runtime.ready_error = TargetRuntimeError("remote_service_not_running")
    _another_builds_target("lab", kind)
    result = _invoke("connect", "lab")
    assert result.exit_code != 0
    assert result.stderr == (
        "remote_service_not_running: the server answered but its FinishUP service is not "
        "running; start it there with 'finishup service start'\n"
    )


def test_a_remote_kind_without_a_runtime_is_a_typed_refusal(home: Path) -> None:
    _another_builds_target("lab", "https")
    for command in ("connect", "disconnect", "test"):
        result = _invoke(command, "lab")
        assert result.exit_code == 20
        assert result.stderr.startswith("runtime_unavailable:")
        assert "remote_unreachable, phase runtime_unavailable" in result.stderr
        # Nothing was asked of that server, so it is never said not to have answered.
        assert "did not answer" not in result.output


def test_connect_and_disconnect_dispatch_to_the_local_runtime(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, Path | None]] = []

    def ensure_ready(_self: object, root: Path | None) -> None:
        calls.append(("ensure_ready", root))

    def stop(_self: object, root: Path | None) -> None:
        calls.append(("stop", root))

    monkeypatch.setattr(
        "finishup.client.target_runtime.LocalTargetRuntime.ensure_ready", ensure_ready
    )
    monkeypatch.setattr("finishup.client.target_runtime.LocalTargetRuntime.stop", stop)
    assert _invoke("add", "work", "--local").exit_code == 0
    (record,) = targets.list_targets()
    root = targets.target_root(record.target_id)
    assert _invoke("connect", "work").exit_code == 0
    assert _invoke("disconnect", "work").exit_code == 0
    assert _invoke("connect").exit_code == 0  # the everyday server, with nothing selected
    assert calls == [("ensure_ready", root), ("stop", root), ("ensure_ready", None)]


def test_the_everyday_server_starts_while_another_is_selected(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``connect local`` starts the everyday server: its spawn reads no selection (ADR-051)."""

    calls: list[Path | None] = []

    def ensure_ready(_self: object, root: Path | None) -> None:
        calls.append(root)

    monkeypatch.setattr(
        "finishup.client.target_runtime.LocalTargetRuntime.ensure_ready", ensure_ready
    )
    assert _invoke("add", "work", "--local").exit_code == 0
    assert _invoke("use", "work").exit_code == 0
    result = _invoke("connect", "local")
    assert result.exit_code == 0, result.output
    assert calls == [None]
    assert "this computer's everyday server" in result.stdout


def _dangling_selection(home: Path) -> None:
    """Select a named local server, then delete its folder behind the selection's back."""

    assert _invoke("add", "work", "--local").exit_code == 0
    assert _invoke("use", "work").exit_code == 0
    shutil.rmtree(targets.target_root(targets.find_target("work").target_id))


def _malformed_selection(home: Path) -> None:
    path = targets.selection_path()
    path.parent.mkdir(mode=0o700, exist_ok=True)
    path.write_bytes(b"{not json")
    path.chmod(0o600)


def _symlinked_selection(home: Path) -> None:
    elsewhere = home / "elsewhere.json"
    elsewhere.write_bytes(b'{"schema":"yoetz.server-selection/1","target_id":"t_0a1b2c3d"}\n')
    elsewhere.chmod(0o600)
    targets.selection_path().parent.mkdir(mode=0o700, exist_ok=True)
    targets.selection_path().symlink_to(elsewhere)


@pytest.mark.parametrize(
    "break_selection", [_dangling_selection, _malformed_selection, _symlinked_selection]
)
def test_use_local_is_the_way_back_from_a_broken_selection(
    home: Path, quiet_probe: None, break_selection: Callable[[Path], None]
) -> None:
    """A damaged or dangling selection fails closed, and the remedy it names actually works."""

    break_selection(home)
    for arguments in (("list",), ("status", "--json"), ("use", "work")):
        refused = _invoke(*arguments)
        assert refused.exit_code == 20, (arguments, refused.output)
        assert refused.stderr.startswith("selection_invalid:")
        assert "'finishup server use local' clears it" in refused.stderr

    back = _invoke("use", "local")
    assert back.exit_code == 0, back.output
    assert not targets.selection_path().is_symlink()
    assert not targets.selection_path().exists()
    if break_selection is _symlinked_selection:
        assert (home / "elsewhere.json").is_file()  # the link is removed, never what it names
    reset_selection_memo()
    assert active_root() is None
    listed = _invoke("list")
    assert listed.exit_code == 0, listed.output
    assert listed.stdout.splitlines()[0].startswith("* local")


def test_remove_select_local_clears_a_selection_that_cannot_be_read(home: Path) -> None:
    assert _invoke("add", "work", "--local").exit_code == 0
    _malformed_selection(home)
    refused = _invoke("remove", "work")
    assert refused.exit_code == 20
    assert refused.stderr.startswith("selection_invalid:")
    assert targets.list_targets() != ()

    removed = _invoke("remove", "work", "--select-local")
    assert removed.exit_code == 0, removed.output
    assert not targets.selection_path().exists()
    assert targets.list_targets() == ()
    reset_selection_memo()
    assert active_root() is None


def test_another_target_can_be_removed_while_the_selection_dangles(home: Path) -> None:
    assert _invoke("add", "spare", "--local").exit_code == 0
    _dangling_selection(home)
    removed = _invoke("remove", "spare")
    assert removed.exit_code == 0, removed.output
    assert targets.selection_path().exists()  # not this target's; 'use local' clears it


def test_an_isolation_root_still_refuses_the_way_back(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _malformed_selection(home)
    explicit = home / "explicit"
    explicit.mkdir(mode=0o700)
    monkeypatch.setenv(ISOLATED_ROOT_ENV_NAMES[0], str(explicit))
    result = _invoke("use", "local")
    assert result.exit_code == 2
    assert result.stderr.startswith("selection_overridden:")
    assert targets.selection_path().exists()


def test_an_isolation_root_overrides_the_selection(
    home: Path, monkeypatch: pytest.MonkeyPatch, quiet_probe: None
) -> None:
    assert _invoke("add", "work", "--local").exit_code == 0
    assert _invoke("use", "work").exit_code == 0
    explicit = home / "explicit"
    explicit.mkdir(mode=0o700)
    monkeypatch.setenv(ISOLATED_ROOT_ENV_NAMES[0], str(explicit))

    for arguments in (("use", "local"), ("add", "lab", "--local"), ("remove", "work")):
        result = _invoke(*arguments)
        assert result.exit_code == 2
        assert result.stderr.startswith("selection_overridden:")
    status = _status_json()
    assert status["source"] == "environment"
    assert status["selection_overridden"] is True
    assert cast(dict[str, JsonValue], status["target"])["target_id"] is None


def test_a_target_removed_during_a_slow_logout_stays_removed(
    home: Path, no_platform_store: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SRV-12: a target removed after ``logout`` read it is not recreated with only its record.

    Since the layer-5 review (C2) the key is deleted inside logout's registry-locked step, so a
    removal can no longer land between the delete and the record's write; it lands before the
    lock is taken (here: as logout asks for it), and logout then finds no record to update.
    """

    record, root = _another_builds_target("team", key=True)
    real_lock = targets.registry_lock

    @contextlib.contextmanager
    def removed_first() -> Generator[None]:
        with real_lock():
            targets.remove_target_root(record)
        with real_lock():
            yield

    monkeypatch.setattr(server_cli, "registry_lock", removed_first)
    assert _invoke("logout", "team").exit_code == 0
    assert not root.exists()


def test_a_stale_disclosure_is_refused_by_connect_and_shown_by_status(
    home: Path, quiet_probe: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``connect`` sends nothing to a target confirmed under an older disclosure; seeing,
    stopping and removing it stay possible, and ``use`` is refused as for every remote kind."""

    _another_builds_target("lab", "https")
    # A later release shows a newer disclosure than the one the owner confirmed.
    monkeypatch.setattr(targets, "DISCLOSURE_VERSION", targets.DISCLOSURE_VERSION + 1)

    refused = _invoke("connect", "lab")
    assert refused.exit_code == 2
    assert refused.stderr.startswith("target_reauthorization_required:")
    assert "lab.example" not in refused.stderr
    # An SSH server is confirmed again with 'server use NAME' on the owner's terminal; an HTTPS
    # one (refused below while closed) points to a server on this computer.
    assert "'finishup server use NAME' on your own terminal (an SSH or HTTPS server)" in (
        refused.stderr
    )
    assert "'finishup server use local'" in refused.stderr
    status = _status_json("lab")
    authorization = cast(
        dict[str, JsonValue], cast(dict[str, JsonValue], status["target"])["authorization"]
    )
    assert authorization["current"] is False
    assert _invoke("disconnect", "lab").stderr.startswith("runtime_unavailable:")
    assert _invoke("use", "lab").stderr.startswith("remote_kind_unavailable:")
    assert _invoke("remove", "lab").exit_code == 0
    assert targets.list_targets() == ()


# -- registrations and upgrade with a selection ---------------------------------------------


def _registration_bytes(launcher: Path) -> dict[str, bytes]:
    from finishup.adapters.integrations.claude_code_integration import render_claude_code_plugin
    from finishup.adapters.integrations.codex_mcp import isolated_root_environment
    from finishup.adapters.integrations.cursor_integration import render_cursor_plugin
    from finishup.ports.plugin_artifacts import PluginFormatProfile
    from finishup.protocol.canonical import canonical_encode

    claude = render_claude_code_plugin(finishup_launcher=launcher)
    cursor = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE, finishup_launcher=launcher
    )
    members = {f"claude/{name}": data for name, data in claude.members.items()}
    members.update({f"cursor/{name}": data for name, data in cursor.members.items()})
    members["codex/env"] = canonical_encode(cast(JsonValue, isolated_root_environment()))
    return members


def test_a_selection_is_never_stamped_into_a_host_registration(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launcher = home / "finishup"
    launcher.write_text("#!/bin/sh\n", encoding="utf-8")
    launcher.chmod(0o700)
    before = _registration_bytes(launcher)

    assert _invoke("add", "work", "--local").exit_code == 0
    assert _invoke("use", "work").exit_code == 0
    reset_selection_memo()
    assert active_root() is not None
    after = _registration_bytes(launcher)
    assert after == before
    (record,) = targets.list_targets()
    assert not any(record.target_id.encode() in data for data in after.values())

    # The same renderers do stamp an explicit isolation root, so the comparison can see one.
    explicit = home / "explicit"
    explicit.mkdir(mode=0o700)
    monkeypatch.setenv(ISOLATED_ROOT_ENV_NAMES[0], str(explicit))
    stamped = _registration_bytes(launcher)
    assert stamped != before
    assert any(str(explicit).encode() in data for data in stamped.values())


def test_upgrade_is_not_refused_while_a_target_is_selected(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.adapters import package_upgrade

    assert _invoke("add", "work", "--local").exit_code == 0
    assert _invoke("use", "work").exit_code == 0
    reset_selection_memo()
    monkeypatch.setattr(package_upgrade, "installation_prefix", lambda: home / "source")

    def run(argv: tuple[str, ...], **_kwargs: object) -> object:
        from types import SimpleNamespace

        assert argv == ("uv", "tool", "dir")
        return SimpleNamespace(returncode=0, stdout=str(home / "tools").encode())

    monkeypatch.setattr(package_upgrade.subprocess, "run", run)
    # Past the isolation guard: the ordinary uv-tool check decides, never the selection.
    assert package_upgrade.execute_package_upgrade() == "refused_non_uv_tool_runtime"


# -- service start (the reverse of service stop) ---------------------------------------------


def test_service_start_is_an_on_demand_start_plus_status(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.ports.control import ControlClientKind, ServiceState, ServiceStatus

    status = ServiceStatus(
        protocol_version="1.0",
        service_version="0.3.0",
        service_instance_id="svc_00000000-0000-4000-8000-000000000001",
        service_generation="1",
        state=ServiceState.LOCKED,
        state_reason="vault_uninitialized",
        vault_mode="uninitialized",
        capabilities=(),
        session_monitor="unavailable",
    )
    calls: list[tuple[ControlClientKind, object]] = []

    class _Client:
        async def service_status(self) -> ServiceStatus:
            return status

        async def close(self) -> None:
            return None

    async def on_demand(kind: ControlClientKind, *, workspace_locator: object = None) -> _Client:
        calls.append((kind, workspace_locator))
        return _Client()

    monkeypatch.setattr("finishup.service.client.connect_service_on_demand", on_demand)
    result = _RUNNER.invoke(cli.app, ["service", "start", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["service_instance_id"] == status.service_instance_id
    assert calls == [(ControlClientKind.CLI, None)]


def test_service_profile_is_shown_and_prints_what_this_server_offers(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-052: ``finishup service profile`` (shown since SSH discovery runs it, layer 4) starts
    this root's service on demand, as ``service start`` does, and prints its verified profile."""

    from finishup.cli.app import service_app
    from finishup.ports.control import ControlClientKind
    from finishup.protocol.server_profile import profile_from_json, profile_to_json

    document = json.loads(
        (Path(__file__).parents[3] / "fixtures/service/server-profile.case.json").read_bytes()
    )["valid"][0]["document"]
    profile = profile_from_json(document)
    calls: list[tuple[ControlClientKind, object]] = []

    class _Client:
        async def server_profile(self) -> object:
            return profile

        async def close(self) -> None:
            return None

    async def on_demand(kind: ControlClientKind, *, workspace_locator: object = None) -> _Client:
        calls.append((kind, workspace_locator))
        return _Client()

    monkeypatch.setattr("finishup.service.client.connect_service_on_demand", on_demand)
    result = _RUNNER.invoke(cli.app, ["service", "profile", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == profile_to_json(profile)
    assert calls == [(ControlClientKind.CLI, None)]
    text = _RUNNER.invoke(cli.app, ["service", "profile"])
    assert text.exit_code == 0, text.output
    assert "profile_revision: " in text.stdout
    hidden = {
        command.name: command.hidden
        for command in service_app.registered_commands
        if command.name in {"profile", "endpoint", "status"}
    }
    assert hidden == {"profile": False, "endpoint": False, "status": False}


def test_ambiguous_everyday_folders_are_a_bounded_refusal(home: Path) -> None:
    for app_name in ("finishup", "yoetz"):
        folder = home / "config" / app_name
        folder.mkdir(mode=0o700)
        (folder / "config.toml").write_text("", encoding="utf-8")
    for arguments in (("list",), ("add", "work", "--local")):
        result = _invoke(*arguments)
        assert result.exit_code == 20, result.output
        assert result.stderr.startswith("installation_root_ambiguous:")
        assert "Traceback" not in result.output


def _ready_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    from finishup.client.target_runtime import ProbeResult

    def ready(_self: object, _root: Path | None) -> ProbeResult:
        return ProbeResult(
            "ready", service_state="ready", service_version="0.3.0", round_trip_p95_ms=5, samples=5
        )

    def timed(_self: object, _root: Path | None, count: int) -> tuple[int, ...]:
        return (40,) * count

    remote_runtime(monkeypatch).probe_result = ready(None, None)
    monkeypatch.setattr("finishup.client.target_runtime.LocalTargetRuntime.probe", ready)
    monkeypatch.setattr(
        "finishup.client.target_runtime.LocalTargetRuntime.time_new_connections", timed
    )


@pytest.mark.parametrize("selected", ["lab", None])
def test_chosen_by_is_shown_only_for_the_server_in_use(
    home: Path, monkeypatch: pytest.MonkeyPatch, selected: str | None
) -> None:
    """RE-5: what chose the server this process uses is not said of another target.

    ``server status NAME``, ``server test NAME`` and the terminal interface's ``/server`` status
    show ``chosen by`` for the server in use only; a target named that is not in use says so.
    """

    with targets.registry_lock():
        lab, _root = targets.new_remote_target(
            "lab", "ssh", host="lab.example", port=22, remote_launcher="/opt/fu/bin/finishup"
        )
        web, _root = targets.new_remote_target(
            "web", "https", base_url="https://web.example:8443", tls_pin="sha256:" + "a" * 64
        )
        if selected is not None:
            targets.write_selection(lab)
    reset_selection_memo()
    _ready_probe(monkeypatch)
    in_use = {"lab": selected == "lab", "web": False, "local": selected is None}
    source = "selection" if selected is not None else "ambient"
    for name, used in in_use.items():
        tested = _invoke("test", name)
        assert tested.exit_code == 0, tested.output
        heading = tested.stdout.splitlines()[0]
        shown = server_cli.status_lines(
            server_cli.build_status_document(name, zero_network=lambda: None),
            in_use=server_cli.target_in_use(name),
        )
        for line in (heading, shown[0]):
            assert line.startswith(f"Server: {name} (")
            if used:
                assert line.endswith(f"; chosen by: {source}")
            else:
                assert line.endswith("; not the server in use")
                assert "chosen by" not in line
    del web
    # Without a name the lines describe this process's own server, which is in use.
    assert server_cli.target_in_use(None) is True


@pytest.mark.parametrize(
    ("kind", "fix"),
    [
        ("ssh", "load the SSH key it accepts (ssh-add)"),
        ("https", "run 'finishup server login lab' with an API key it accepts"),
    ],
)
def test_server_status_and_test_say_a_refused_key_was_an_answer(
    home: Path, monkeypatch: pytest.MonkeyPatch, kind: str, fix: str
) -> None:
    """RE-6: a server that refused this client's key answered: never "did not answer"."""

    from finishup.client.target_runtime import ProbeResult

    with targets.registry_lock():
        if kind == "ssh":
            targets.new_remote_target(
                "lab", "ssh", host="lab.example", port=22, remote_launcher="/opt/fu/bin/finishup"
            )
        else:
            targets.new_remote_target(
                "lab", "https", base_url="https://lab.example:8443", tls_pin="sha256:" + "a" * 64
            )

    remote_runtime(monkeypatch).probe_result = ProbeResult(
        "unavailable", reason="remote_auth_failed"
    )
    tested = _invoke("test", "lab")
    assert tested.exit_code != 0
    assert "State: answered, key refused (remote_auth_failed)" in tested.stdout
    assert "The server answered and refused this client's key; " in tested.stdout
    assert fix in tested.stdout
    assert "The target answered and refused this client's key." in tested.stderr
    for text in (tested.stdout, tested.stderr):
        assert "did not answer" not in text
        assert "could not be reached" not in text
    shown = server_cli.status_lines(server_cli.build_status_document("lab"), in_use=False)
    assert "State: answered, key refused (remote_auth_failed)" in shown
    document = _status_json("lab")
    probe = cast(dict[str, JsonValue], document["probe"])
    assert (probe["outcome"], probe["reason"]) == ("unavailable", "remote_auth_failed")


def _ready_lab(monkeypatch: pytest.MonkeyPatch, *, round_trip_ms: int) -> StandInRuntime:
    from finishup.client.target_runtime import ProbeResult

    with targets.registry_lock():
        targets.new_remote_target(
            "lab", "ssh", host="lab.example", port=22, remote_launcher="/opt/fu/bin/finishup"
        )
    runtime = remote_runtime(monkeypatch)
    runtime.probe_result = ProbeResult(
        "ready",
        service_state="ready",
        service_version="0.3.0",
        round_trip_p95_ms=round_trip_ms,
        samples=10,
    )
    return runtime


def test_server_test_warns_when_a_new_connection_misses_the_startup_gate(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Design v2 section 8.9: a warm status round trip of 120 ms said "within the hook budgets"
    while the startup gate's own connection and status took 673 ms; what is compared with the
    gate's bound is now what the gate times, a new process's connection and status."""

    runtime = _ready_lab(monkeypatch, round_trip_ms=120)
    runtime.new_connection_times = (540, 610, 702, 580, 560)
    tested = _invoke("test", "lab")
    assert tested.exit_code == 0, tested.output
    assert "Round trip p95: 120 ms over 10 status calls" in tested.stdout
    assert (
        "New connection and status: 702 ms at the slowest of 5 new processes "
        "(the required startup gate allows 650 ms)."
    ) in tested.stdout
    assert (
        "Warning: 702 ms is above the 650 ms the required startup gate allows for a connection "
        "and a status; agent tools would likely be denied."
    ) in tested.stdout
    assert "Within" not in tested.stdout
    roots = [root for call, root in runtime.calls if call == "time_new_connections"]
    lab = targets.find_target("lab")
    assert lab is not None
    assert roots == [targets.target_root(lab.target_id)]


def test_server_test_says_a_new_connection_fits_the_gate_with_what_it_did_not_time(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _ready_lab(monkeypatch, round_trip_ms=320)
    runtime.new_connection_times = (450, 470, 650, 430, 440)  # the bound itself still fits
    tested = _invoke("test", "lab")
    assert tested.exit_code == 0, tested.output
    assert "650 ms at the slowest of 5 new processes" in tested.stdout
    assert (
        "Within the startup gate's 650 ms for a new connection and status; a task's status asks "
        "the server for more than this one."
    ) in tested.stdout
    assert "Warning" not in tested.stdout  # the warm round trip alone (320 ms) decides nothing


def test_server_test_names_a_new_connection_that_did_not_answer(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.client.target_runtime import TargetRuntimeError

    runtime = _ready_lab(monkeypatch, round_trip_ms=40)
    runtime.new_connection_error = TargetRuntimeError("service_unavailable", phase="timeout")
    tested = _invoke("test", "lab")
    assert tested.exit_code == 20
    assert (
        "A new connection did not answer a status call (service_unavailable, phase timeout)."
        in tested.stderr
    )
    assert "Within" not in tested.stdout
