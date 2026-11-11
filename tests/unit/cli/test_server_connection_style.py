"""``finishup server set NAME --style`` and how ``server status`` shows the connection (ADR-052).

The relay style is the default; the direct style is an advanced option, and only a style the
server's own profile offers may be chosen (design v2 section 1.2). Changing it stops what this
client runs for the target first (its helper and its OpenSSH master), and is not an authorization
change: nothing is asked and no generation moves.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from builders.server_profiles import consent_to, profile_document, refreshed
from builders.server_targets import ambient_home, open_remote_kinds, remote_runtime
from finishup.cli import server as server_cli
from finishup.client import targets
from finishup.client.authorization import read_generation
from finishup.client.helper_status import (
    new_status,
    now_stamp,
    read_connection_style,
    write_helper_status,
)
from finishup.client.targets import ServerTarget

_RUNNER = CliRunner()


def _invoke(*arguments: str) -> Result:
    return _RUNNER.invoke(server_cli.server_app, list(arguments))


@pytest.fixture
def lab(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[ServerTarget, Path]]:
    with ambient_home(monkeypatch):
        open_remote_kinds(monkeypatch, "ssh")
        with targets.registry_lock():
            _record, root = targets.new_remote_target(
                "lab",
                "ssh",
                user="owner",
                host="lab.example",
                port=22,
                remote_root="/srv/fu",
                remote_launcher="/srv/bin/finishup",
            )
        record = targets.read_target(root)
        assert record is not None
        yield record, root


def test_the_style_changes_only_to_one_the_profile_offers_and_back(
    lab: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    record, root = lab
    runtime = remote_runtime(monkeypatch)
    before = read_generation(root, selection_bound=False)
    result = _invoke("set", "lab", "--style", "direct")
    assert result.exit_code == 0, result.output
    assert "direct style" in result.stdout
    assert read_connection_style(root) == "direct"
    # What this client ran for the target stopped first; nothing about the authorization moved.
    assert runtime.stops == [root]
    assert read_generation(root, selection_bound=False) == before
    back = _invoke("set", "lab", "--style", "relay")
    assert back.exit_code == 0, back.output
    assert read_connection_style(root) == "relay"
    del record


def test_an_isolation_root_refuses_the_style_change_before_anything_is_stopped(
    lab: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """C1: a pinned or isolated process never stops and restyles the ambient registry's target."""

    from finishup.config.paths import ISOLATED_ROOT_ENV_NAMES

    _record, root = lab
    runtime = remote_runtime(monkeypatch)
    explicit = root.parents[3] / "explicit"
    explicit.mkdir(mode=0o700)
    monkeypatch.setenv(ISOLATED_ROOT_ENV_NAMES[0], str(explicit))
    result = _invoke("set", "lab", "--style", "direct")
    assert result.exit_code != 0
    assert result.stderr.startswith("selection_overridden:")
    assert read_connection_style(root) == "relay" and runtime.calls == []


@pytest.mark.parametrize(
    ("arguments", "reason"),
    [
        (("set", "lab", "--style", "tunnel"), "style_invalid"),
        (("set", "nobody", "--style", "direct"), "target_unknown"),
    ],
)
def test_a_style_that_cannot_be_chosen_changes_nothing(
    lab: tuple[ServerTarget, Path],
    monkeypatch: pytest.MonkeyPatch,
    arguments: tuple[str, ...],
    reason: str,
) -> None:
    _record, root = lab
    runtime = remote_runtime(monkeypatch)
    result = _invoke(*arguments)
    assert result.exit_code != 0
    assert result.stderr.startswith(f"{reason}:")
    assert read_connection_style(root) == "relay" and runtime.calls == []


def test_a_profile_that_offers_no_such_style_refuses_it(
    lab: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    record, root = lab
    runtime = remote_runtime(monkeypatch)
    document = profile_document()
    document["edges"] = ["rest-1"]
    refreshed(record, document)
    result = _invoke("set", "lab", "--style", "direct")
    assert result.exit_code != 0
    assert result.stderr.startswith("style_unavailable:")
    assert read_connection_style(root) == "relay" and runtime.calls == []


def test_a_server_on_this_computer_has_no_style(monkeypatch: pytest.MonkeyPatch) -> None:
    with ambient_home(monkeypatch):
        with targets.registry_lock():
            targets.new_local_target("bench")
        result = _invoke("set", "bench", "--style", "direct")
    assert result.exit_code != 0
    assert result.stderr.startswith("style_not_applicable:")


def test_a_style_change_is_refused_while_the_helper_does_not_stop(
    lab: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.client.target_runtime import TargetRuntimeError

    _record, root = lab
    runtime = remote_runtime(monkeypatch)
    runtime.stop_error = TargetRuntimeError("target_still_connected")
    result = _invoke("set", "lab", "--style", "direct")
    assert result.exit_code != 0
    assert result.stderr.startswith("target_still_connected:")
    assert read_connection_style(root) == "relay"


def test_status_shows_the_style_the_styles_offered_and_the_helper(
    lab: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    record, root = lab
    remote_runtime(monkeypatch)
    write_helper_status(
        root, new_status(None, "unavailable", "remote_auth_failed", started_at=now_stamp())
    )
    result = _invoke("status", "lab", "--json")
    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert document["target"]["connection"] == {
        "style": "relay",
        "styles_offered": ["relay", "direct"],
        "helper": {
            "running": False,
            "phase": "unavailable",
            "reason": "remote_auth_failed",
            "generation": 1,
        },
    }
    text = "\n".join(server_cli.status_lines(document))
    assert "Connection: relay (" in text
    assert "Helper: not running; last unavailable, remote_auth_failed." in text
    del record


def test_status_of_a_target_that_is_not_ssh_has_no_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with ambient_home(monkeypatch):
        open_remote_kinds(monkeypatch, "https")
        remote_runtime(monkeypatch)
        with targets.registry_lock():
            record, _root = targets.new_remote_target(
                "web", "https", base_url="https://finishup.example"
            )
        consent_to(record)
        result = _invoke("status", "web", "--json")
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["target"]["connection"] is None


def test_connect_after_the_profile_widened_names_the_owners_way_to_agree_again(
    lab: tuple[ServerTarget, Path],
) -> None:
    """C4: ``server connect`` renders the registered ``remote_reconsent`` directive and names
    the trusted-console re-consent command, instead of a bare refusal."""

    from finishup.protocol.recovery import directive_for
    from finishup.protocol.server_profile import ReviewEgress

    record, _root = lab
    refreshed(record, profile_document(review=ReviewEgress("server_policy", "openai"), revision=2))

    result = _invoke("connect", "lab")

    assert result.exit_code != 0
    first, *rest = result.stderr.splitlines()
    assert first.startswith("server_profile_changed: ")
    assert "'finishup server use NAME'" in first and "own terminal" in first
    directive = directive_for("remote_reconsent")
    assert directive is not None
    assert rest[:2] == ["Continuation: remote_reconsent", f"Next: {directive.directive}"]
    assert directive.nudge is not None and directive.nudge in rest
    assert "lab.example" not in result.stderr


def test_connect_refused_on_a_revision_not_fetched_yet_asks_to_repeat_not_to_agree_again(
    lab: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """F2: the server refused a hello naming a revision this computer has not fetched while the
    owner's consent still admits the profile held here. What changed is not known yet and may be
    a narrowing FinishUP adjusts to by itself, so ``server connect`` asks for the same command
    again (``remote_profile_checking``), not for the owner to agree again."""

    from finishup.client.target_runtime import TargetRuntimeError
    from finishup.protocol.recovery import directive_for

    record, _root = lab
    consent_to(record)
    runtime = remote_runtime(monkeypatch)
    runtime.ready_error = TargetRuntimeError("service_unavailable", phase="server_profile_changed")

    result = _invoke("connect", "lab")

    assert result.exit_code != 0
    first, *rest = result.stderr.splitlines()
    assert first.startswith("server_profile_changed: ")
    assert "refused before that server did any work for it" in first
    assert "run the same command again" in first
    directive = directive_for("remote_profile_checking")
    assert directive is not None
    assert rest[:2] == ["Continuation: remote_profile_checking", f"Next: {directive.directive}"]
    assert "lab.example" not in result.stderr
