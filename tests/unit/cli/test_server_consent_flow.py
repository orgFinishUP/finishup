"""``server add`` and ``server use`` for a server elsewhere: the owner's consent to its profile.

ADR-052, design v2 section 2.3. No remote kind is open in this release and no transport fetches a
profile, so these flows are reached only here, with a kind opened in process and a stand-in
profile source. In order, before anything is written: the address and its options (remote paths
absolute, SRV-11), the name, this computer's zero-network state (SRV-3), the server's profile, and
the envelope of using it at level L1; then, on the trusted console only, the disclosure in this
release's own words, the outside-read question at ``add`` and the typed name; then the record,
its consent and the mode, changed field by field as stored (SRV-12).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from types import TracebackType
from typing import Any, Self

import pytest
from typer.testing import CliRunner, Result

from builders.server_profiles import HOST_KEY, consent_to, fetched, profile_document
from builders.server_targets import ambient_home, open_remote_kinds
from finishup.cli import app as cli
from finishup.cli import server as server_cli
from finishup.cli import trusted_console
from finishup.client import server_profile, targets
from finishup.client.server_profile import FetchedProfile
from finishup.client.ssh_discovery import SshDiscovery
from finishup.client.targets import ServerTarget
from finishup.config.paths import reset_selection_memo
from finishup.protocol.consent_envelope import ReviewEgress
from finishup.protocol.server_profile import ProfileLevels

_RUNNER = CliRunner()
_ADDRESSES = {
    "ssh": ("ssh://owner@lab.example",),
    "https": ("https://lab.example",),
    "local_port": ("--port", "8443"),
}


class _Console:
    """A trusted console that answers from a script (``"eof"`` and the like raise)."""

    def __init__(self, answers: list[bytes | str]) -> None:
        self.answers = answers
        self.shown: list[str] = []
        self.asked: list[tuple[bytes, ...]] = []
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
        self.asked.append(allowed)
        if not self.answers:
            raise trusted_console.TrustedConsoleError("eof")
        answer = self.answers.pop(0)
        if isinstance(answer, str):
            raise trusted_console.TrustedConsoleError(answer)
        if answer in allowed:
            return answer
        raise trusted_console.TrustedConsoleError("input_invalid")

    @property
    def text(self) -> str:
        return "".join(self.shown)


class _Source:
    """A stand-in transport: hands over ``document`` as the server's profile."""

    def __init__(self) -> None:
        self.document: dict[str, Any] = profile_document()
        self.fetched: list[str] = []

    def fetch(self, record: ServerTarget) -> FetchedProfile:
        self.fetched.append(record.kind)
        return fetched(record, self.document)


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


@pytest.fixture
def opened(home: Path, monkeypatch: pytest.MonkeyPatch) -> _Source:
    """Every remote kind open, with a stand-in profile source (no zero-network decision)."""

    del home
    open_remote_kinds(monkeypatch, "ssh", "https", "local_port", consent=False)
    stand_in = _Source()
    for kind in ("ssh", "https", "local_port"):
        monkeypatch.setitem(server_profile.PROFILE_SOURCES, kind, lambda: stand_in)

    def discover(
        user: str | None,
        host: str,
        port: int,
        remote_root: str | None,
        remote_launcher: str | None,
    ) -> SshDiscovery:
        # SSH discovery at 'server add' (``client.ssh_discovery``, tested on its own and against
        # a real OpenSSH): the endpoint and launcher the server reported, and the stand-in profile.
        del user, host, port
        stand_in.fetched.append("ssh")
        return SshDiscovery(
            f"{(remote_root or '/srv/fu').rstrip('/')}/run/control.sock",
            remote_launcher or "/usr/local/bin/finishup",
            False,
            FetchedProfile(json.dumps(stand_in.document).encode(), "ssh_host_key", HOST_KEY),
        )

    monkeypatch.setattr(server_cli, "_discover_ssh", discover)

    def discover_rest(record: ServerTarget, key_file: Path | None) -> tuple[FetchedProfile, str]:
        # HTTPS discovery and the key at 'server add' (layer 5, ``client.rest_discovery``,
        # tested on its own and against the real routes): the stand-in profile and a key.
        del key_file
        return stand_in.fetch(record), "fuk_0123456789ab_" + "A" * 43

    monkeypatch.setattr(server_cli, "_discover_rest", discover_rest)
    # No platform credential store: the key goes to the owner-only file (injected, since
    # keyring's process-wide cache may hold whatever an earlier test loaded).
    monkeypatch.setattr("finishup.client.credentials._platform_backend", lambda: None)
    return stand_in


@pytest.fixture
def source(opened: _Source, monkeypatch: pytest.MonkeyPatch) -> _Source:
    """``opened``, on a computer whose own FinishUP allows network use."""

    monkeypatch.setattr(server_cli, "_zero_network_in_force", lambda: False)
    return opened


def _console(monkeypatch: pytest.MonkeyPatch, *answers: bytes | str) -> _Console:
    console = _Console(list(answers))
    monkeypatch.setattr(trusted_console, "TrustedForegroundConsole", console)
    return console


def _invoke(*arguments: str) -> Result:
    reset_selection_memo()
    return _RUNNER.invoke(cli.app, ["server", *arguments])


def _only() -> ServerTarget:
    (record,) = targets.list_targets()
    return record


@pytest.mark.parametrize("kind", ["ssh", "https", "local_port"])
def test_add_records_the_consent_the_owner_typed_for(
    source: _Source, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    console = _console(monkeypatch, b"listed", b"lab")

    result = _invoke("add", "lab", *_ADDRESSES[kind])

    assert result.exit_code == 0, result.output
    assert source.fetched == [kind]
    record = _only()
    assert record.kind == kind and record.consent is not None
    assert record.consent.level == "L1" and record.consent.revision == 1
    root = targets.target_root(record.target_id)
    assert (root / "config" / "consent-envelope.json").is_file()
    assert (root / "state" / "server-profile.json").is_file()
    assert "disclosure 3" in console.text
    assert "Level of use: that server keeps your tasks" in console.text
    assert "sends nothing it reads to an AI-powered review provider" in console.text
    assert console.asked == [(b"local", b"listed"), (b"lab",)]
    assert "mode listed, from you" in result.stdout or "mode listed" in result.stdout


def test_a_relative_remote_path_is_refused_before_any_fetch_or_console(
    source: _Source, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SRV-11: a relative --remote-root never reaches the server or the owner's consent."""

    console = _console(monkeypatch, b"listed", b"lab")

    result = _invoke("add", "lab", "ssh://owner@lab.example", "--remote-root", "srv/finishup")

    assert result.exit_code == 2
    assert result.stderr.startswith("target_path_invalid:")
    assert source.fetched == [] and console.opened == 0
    assert targets.list_targets() == ()


@pytest.mark.parametrize(
    ("document", "reason"),
    [
        (
            profile_document(levels=ProfileLevels(("L1", "L2"), "L2")),
            "server_level_unavailable",
        ),
        ({**profile_document(), "profile_digest": "sha256:" + "0" * 64}, "server_profile_changed"),
    ],
    ids=["requires_a_copy", "unreadable"],
)
def test_a_profile_this_release_cannot_agree_to_is_refused_before_the_console(
    source: _Source, monkeypatch: pytest.MonkeyPatch, document: dict[str, Any], reason: str
) -> None:
    source.document = document
    console = _console(monkeypatch, b"listed", b"lab")

    result = _invoke("add", "lab", "ssh://owner@lab.example")

    assert result.exit_code == 2
    assert result.stderr.startswith(f"{reason}:")
    assert console.opened == 0
    assert targets.list_targets() == ()
    assert list(targets.servers_dir().glob("t_*")) == []


@pytest.mark.parametrize("selected", [True, False])
def test_an_unreadable_policy_names_a_way_that_works_while_another_server_is_selected(
    opened: _Source, monkeypatch: pytest.MonkeyPatch, selected: bool
) -> None:
    """SRV-3: with a server selected, 'service start' and 'service unlock' never reach this
    computer's own FinishUP, so the refusal names 'server connect local' instead."""

    monkeypatch.setattr(
        "finishup.cli.zero_network_selection.everyday_network_state", lambda: "unreadable"
    )
    monkeypatch.setattr("finishup.client.everyday_policy.last_reported_zero_network", lambda: None)
    if selected:
        with targets.registry_lock():
            alpha, _root = targets.new_local_target("alpha")
        targets.write_selection(alpha)

    result = _invoke("add", "beta", "ssh://owner@lab.example")

    assert result.exit_code == 20
    assert result.stderr.startswith("network_policy_unreadable:")
    assert ("'finishup server connect local'" in result.stderr) is selected
    assert ("'finishup service start'" in result.stderr) is not selected
    assert opened.fetched == []


def test_the_flag_answers_the_question_and_local_shows_what_it_lets_the_server_read(
    source: _Source, monkeypatch: pytest.MonkeyPatch
) -> None:
    del source
    console = _console(monkeypatch, b"lab")

    result = _invoke("add", "lab", "ssh://owner@lab.example", "--outside-reads", "local")

    assert result.exit_code == 0, result.output
    assert console.asked == [(b"lab",)]
    assert "(mode local, from --outside-reads)" in console.text
    assert "as a FinishUP service on this computer answers them" in console.text


@pytest.mark.parametrize("answers", [(b"listed", b"nope"), ("trusted_console_required",)])
def test_declining_or_no_console_records_nothing(
    source: _Source, monkeypatch: pytest.MonkeyPatch, answers: tuple[bytes | str, ...]
) -> None:
    del source
    _console(monkeypatch, *answers)

    result = _invoke("add", "lab", "ssh://owner@lab.example")

    assert result.exit_code == 2
    assert result.stderr.split(":")[0] in {"authorization_declined", "trusted_console_required"}
    assert targets.list_targets() == ()
    assert list(targets.servers_dir().glob("t_*")) == []


def test_the_disclosure_names_a_provider_only_in_this_releases_words(
    source: _Source, monkeypatch: pytest.MonkeyPatch
) -> None:
    source.document = profile_document(review=ReviewEgress("server_policy", "acme-ai"))
    console = _console(monkeypatch, b"listed", b"lab")

    result = _invoke("add", "lab", "ssh://owner@lab.example")

    assert result.exit_code == 0, result.output
    assert "a provider this release does not name" in console.text
    assert "acme-ai" not in console.text


def test_the_disclosure_names_every_provider_a_paired_review_may_send_to(
    source: _Source, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A server whose review falls back to a second provider names both (review of layer 3:
    A1), and the consent records both."""

    source.document = profile_document(
        review=ReviewEgress("server_policy", "fireworks", "openai-codex")
    )
    console = _console(monkeypatch, b"listed", b"lab")

    result = _invoke("add", "lab", "ssh://owner@lab.example")

    assert result.exit_code == 0, result.output
    text = " ".join(console.text.split())
    assert "(Fireworks) and, when that one fails, to another (OpenAI Codex)" in text
    consented = json.loads(
        (targets.target_root(_only().target_id) / "config" / "consent-envelope.json").read_bytes()
    )
    assert consented["review"] == {
        "ai_review": "server_policy",
        "provider_disclosure": "fireworks",
        "fallback_disclosure": "openai-codex",
    }


def _remote(source: _Source) -> ServerTarget:
    del source
    with targets.registry_lock():
        record, _root = targets.new_remote_target("lab", "https", base_url="https://lab.example")
    return consent_to(record)


def test_use_asks_again_and_changes_only_the_consent_of_the_record_as_stored(
    source: _Source, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SRV-12: what another command recorded during the confirmation (a key, say) is kept."""

    record = _remote(source)
    source.document = profile_document(revision=2)

    def authorize(name: str, kind: str, lines: tuple[str, ...]) -> None:
        assert (name, kind) == ("lab", "https")
        assert any("Level of use" in line for line in lines)
        with targets.registry_lock():
            stored = targets.read_target(targets.target_root(record.target_id))
            assert stored is not None
            from dataclasses import replace

            targets.write_target(
                targets.target_root(record.target_id), replace(stored, credential="file")
            )

    switch = server_cli.use_target("lab", authorize=authorize)

    stored = targets.read_target(targets.target_root(record.target_id))
    assert stored is not None and switch.record is not None
    assert stored.credential == "file"
    assert stored.consent is not None and stored.consent.revision == 2
    assert targets.read_selected_target_id() == record.target_id


def test_a_target_removed_during_the_confirmation_stays_removed(
    source: _Source, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = _remote(source)
    root = targets.target_root(record.target_id)

    def authorize(_name: str, _kind: str, _lines: tuple[str, ...]) -> None:
        with targets.registry_lock():
            targets.remove_target_root(record)

    with pytest.raises(server_cli.ServerCommandRefused) as refused:
        server_cli.use_target("lab", authorize=authorize)

    assert refused.value.reason == "target_unknown"
    assert not root.exists()
    assert targets.read_selected_target_id() is None


def test_use_of_a_closed_kind_is_refused_before_anything(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del home
    # Every remote kind is open from layer 5: HTTPS is closed in this process as the example.
    monkeypatch.setattr("finishup.client.authorization.OPEN_REMOTE_KINDS", frozenset({"ssh"}))
    with targets.registry_lock():
        targets.new_remote_target("lab", "https", base_url="https://lab.example")

    result = _invoke("use", "lab")

    assert result.stderr.startswith("remote_kind_unavailable:")
    assert targets.read_selected_target_id() is None
    document = json.loads((targets.target_root(_only().target_id) / "target.json").read_bytes())
    assert document["schema"] == "yoetz.server-target/1"


# --- what server status says of the consent (server_profile_narrowed) ---------------------------


def _status(name: str = "lab") -> tuple[dict[str, Any], str]:
    from finishup.protocol.schemas import validate_schema_instance

    result = _invoke("status", name, "--json")
    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    validate_schema_instance("server-target-status", "1.0.0", document)
    # The owner display (a terminal shows it; a pipe gets the JSON).
    return document["target"], "\n".join(server_cli.status_lines(document))


def test_status_shows_the_consent_a_narrowing_adjusted_and_a_change_that_asks_again(
    source: _Source,
) -> None:
    from builders.server_profiles import refreshed

    record = _remote(source)
    target, text = _status()
    assert target["consent"] == {
        "level": "L1",
        "profile_revision": 1,
        "state": "current",
        "adjusted_at": None,
        "coverage_reduced": [],
    }
    assert "Consent: level L1 under that server's profile revision 1." in text
    assert "server_profile_narrowed" not in text

    # Agreed under review egress, then the server stopped sending to a provider: narrowed.
    record = consent_to(record, profile_document(review=ReviewEgress("server_policy", "openai")))
    refreshed(record, profile_document(revision=2))
    target, text = _status()
    consent = target["consent"]
    assert (consent["state"], consent["profile_revision"], consent["coverage_reduced"]) == (
        "current",
        2,
        ["review"],
    )
    assert consent["adjusted_at"] is not None
    assert "server_profile_narrowed:" in text and "(no longer covered: review)" in text

    # Then it widens again: nothing is sent until the owner agrees again.
    stored = targets.read_target(targets.target_root(record.target_id))
    assert stored is not None
    refreshed(stored, profile_document(review=ReviewEgress("server_policy", "openai"), revision=3))
    target, text = _status()
    assert target["consent"]["state"] == "changed"
    assert "server_profile_changed:" in text and "'finishup server use lab'" in text


def test_status_names_a_level_the_owner_did_not_agree_to(source: _Source) -> None:
    from builders.server_profiles import refreshed

    record = _remote(source)
    refreshed(record, profile_document(levels=ProfileLevels(("L1", "L2"), "L2"), revision=2))

    target, text = _status()

    assert target["consent"]["state"] == "level_unavailable"
    assert "server_level_unavailable:" in text


def test_status_of_a_target_with_no_consent_or_a_local_one_shows_none(home: Path) -> None:
    del home
    with targets.registry_lock():
        targets.new_remote_target("lab", "https", base_url="https://lab.example")
        targets.new_local_target("work")

    remote, text = _status("lab")
    local, _text = _status("work")

    assert remote["consent"] is None and local["consent"] is None
    assert "Consent:" not in text
