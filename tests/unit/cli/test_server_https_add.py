"""``finishup server add NAME https://…`` / ``--port``, ``login``, ``logout`` and the official
preset (ADR-053, design v2 sections 2.1 to 2.4 and 8.8).

The REST routes (``rest.app``) with a scripted backend answer over ``httpx``'s ASGI transport; the
trusted console is a script. In order and before anything is written: discovery without a key
(another contract adds nothing and asks for no key), then the key (an owner-only key file, or typed
hidden on the console), then the profile with it (a refused key adds nothing), then the consent;
then the record, its consent, the key kept and a credential generation. ``login`` checks the key
with the server before keeping it (refused, mismatched or incompatible: nothing kept; unanswered:
kept, not verified yet), bumps the generation and stops the helper; a new identity asks for the
consent again. ``logout`` deletes the key, bumps the generation and stops the helper. ``server add
official`` fills the pinned URL, or refuses while none is pinned.
"""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Self

import httpx
import pytest
from typer.testing import CliRunner, Result

from builders.rest_backend import ScriptedRestBackend
from builders.server_profiles import profile_document
from builders.server_targets import StandInRuntime, ambient_home, open_remote_kinds, remote_runtime
from finishup.cli import app as cli
from finishup.cli import server as server_cli
from finishup.cli import trusted_console
from finishup.client import server_folders, targets
from finishup.client.authorization import credential_generation_path
from finishup.client.credentials import KeyringOrFileCredential
from finishup.client.rest_client import RestTransport
from finishup.client.server_profile import read_cached_profile
from finishup.client.targets import ServerTarget
from finishup.config.paths import reset_selection_memo
from finishup.rest.api_keys import ApiKeyStore
from finishup.rest.app import RestApp
from finishup.rest.contract import Discovery, discovery_document

_RUNNER = CliRunner()
_PIN = "sha256:" + "e" * 64


class _Console:
    """A trusted console that answers from a script and records what it showed."""

    def __init__(self, answers: list[bytes]) -> None:
        self.answers = answers
        self.shown: list[str] = []
        self.secrets_asked = 0

    def __call__(self) -> Self:
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

    def read_secret(self, _prompt: str, _maximum: int) -> bytearray:
        self.secrets_asked += 1
        if not self.answers:
            raise trusted_console.TrustedConsoleError("eof")
        return bytearray(self.answers.pop(0))

    @property
    def text(self) -> str:
        return "".join(self.shown)


@dataclass
class _Server:
    backend: ScriptedRestBackend
    keys: ApiKeyStore
    key: str
    base: Path
    discovery: bytes | None = None
    reachable: bool = True
    # When set, ``GET /v1/server`` answers ``200`` with these bytes (a broken or foreign server).
    profile_body: bytes | None = None

    def key_file(self, key: str | None = None, name: str = "laptop.key") -> Path:
        path = self.base / name
        path.write_text((key or self.key) + "\n")
        path.chmod(0o600)
        return path


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Server]:
    # No platform credential store: the key goes to the owner-only file (injected, since
    # keyring's process-wide cache may hold whatever an earlier test loaded).
    monkeypatch.setattr("finishup.client.credentials._platform_backend", lambda: None)
    base = Path.home() / f".yz-https-add-{os.getpid()}-{id(object())}"
    base.mkdir(mode=0o700)
    try:
        with ambient_home(monkeypatch):
            open_remote_kinds(monkeypatch, "https", "local_port", consent=False, rest=True)
            monkeypatch.setattr(server_cli, "_zero_network_in_force", lambda: False)
            keys = ApiKeyStore(base / "rest")
            _record, key = keys.create("laptop", "agent")
            document = profile_document()
            document["edges"] = ["rest-1"]
            backend = ScriptedRestBackend(profile_document=document)
            app = RestApp(backend, keys)
            served = _Server(backend, keys, key, base)
            inner = app.asgi()

            async def gate(scope: Any, receive: Any, send: Any) -> None:
                if not served.reachable:
                    raise httpx.ConnectError("unreachable")
                # A server behind a path prefix (a proxy, an official origin's prefix) serves
                # every route, the discovery document included, beneath its base URL.
                path = str(scope.get("path", ""))
                for marker in ("/.well-known/", "/v1/"):
                    if marker in path:
                        scope = {**scope, "path": path[path.index(marker) :]}
                        break
                if served.discovery is not None and scope.get("path") == "/.well-known/finishup":
                    await send({"type": "http.response.start", "status": 200, "headers": []})
                    await send({"type": "http.response.body", "body": served.discovery})
                    return
                if served.profile_body is not None and scope.get("path") == "/v1/server":
                    await send({"type": "http.response.start", "status": 200, "headers": []})
                    await send({"type": "http.response.body", "body": served.profile_body})
                    return
                await inner(scope, receive, send)

            original = RestTransport.for_target.__func__  # type: ignore[attr-defined]

            def for_target(
                cls: type[RestTransport],
                target: ServerTarget,
                *,
                key: str | None,
                transport: Any = None,
                consented: bool = False,
            ) -> RestTransport:
                del transport
                return original(
                    cls,
                    target,
                    key=key,
                    transport=httpx.ASGITransport(app=gate),
                    consented=consented,
                )

            monkeypatch.setattr(RestTransport, "for_target", classmethod(for_target))
            yield served
    finally:
        shutil.rmtree(base, ignore_errors=True)


def _console(monkeypatch: pytest.MonkeyPatch, *answers: bytes) -> _Console:
    console = _Console(list(answers))
    monkeypatch.setattr(trusted_console, "TrustedForegroundConsole", console)
    return console


def _invoke(*arguments: str) -> Result:
    reset_selection_memo()
    return _RUNNER.invoke(cli.app, ["server", *arguments])


def _added(name: str = "web") -> tuple[ServerTarget, Path]:
    (record,) = [item for item in targets.list_targets() if item.name == name]
    return record, targets.target_root(record.target_id)


def test_add_https_discovers_reads_the_key_and_keeps_it_with_the_consent(
    server: _Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    console = _console(monkeypatch, b"listed", b"web")
    ca = server.base / "ca.pem"
    ca.write_bytes(b"-----BEGIN CERTIFICATE-----\nnot really\n-----END CERTIFICATE-----\n")
    result = _invoke(
        "add",
        "web",
        "https://web.example/finishup",
        "--ca-file",
        str(ca),
        "--key-file",
        str(server.key_file()),
    )
    assert result.exit_code == 0, result.output
    record, root = _added()
    assert (record.kind, record.base_url, record.credential) == (
        "https",
        "https://web.example/finishup",
        "file",
    )
    assert record.consent is not None and record.consent.level == "L1"
    cached = read_cached_profile(root)
    assert cached is not None and cached.identity_type == "tls_ca_file"
    assert cached.profile.key.scope == "agent" and cached.profile.edges == ("rest-1",)
    assert credential_generation_path(root).exists()
    stored = KeyringOrFileCredential(record.target_id, root, recorded="file").read()
    assert stored == server.key
    assert server.key not in result.output and server.key not in console.text
    assert len(server.backend.sessions) == 0  # nothing but discovery and the profile was asked


def test_add_port_takes_a_pin_and_the_key_typed_on_the_console(
    server: _Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    console = _console(monkeypatch, server.key.encode(), b"listed", b"bench")
    result = _invoke("add", "bench", "--port", "8443", "--tls-pin", _PIN)
    assert result.exit_code == 0, result.output
    record, root = _added("bench")
    assert (record.kind, record.base_url, record.tls_pin) == (
        "local_port",
        "https://127.0.0.1:8443",
        _PIN,
    )
    cached = read_cached_profile(root)
    assert cached is not None and (cached.identity_type, cached.identity) == ("tls_pin", _PIN)
    assert console.secrets_asked == 1
    assert server.key not in console.text


def test_a_server_of_another_contract_adds_nothing_and_no_key_is_asked(
    server: _Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    server.discovery = discovery_document(
        Discovery(rest_majors=("1",), api_manifests=("sha256:" + "0" * 64,))
    )
    console = _console(monkeypatch, server.key.encode(), b"listed", b"web")
    result = _invoke("add", "web", "https://web.example")
    assert result.exit_code != 0
    assert result.stderr.startswith("remote_incompatible:")
    assert console.secrets_asked == 0
    assert targets.list_targets() == ()


def test_a_key_the_server_refuses_adds_nothing(
    server: _Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    _console(monkeypatch, b"listed", b"web")
    wrong = server.key_file("fuk_000000000000_" + "A" * 43)
    result = _invoke("add", "web", "https://web.example", "--key-file", str(wrong))
    assert result.exit_code != 0
    assert result.stderr.startswith("remote_auth_failed:")
    assert targets.list_targets() == ()


def test_the_official_preset_refuses_while_no_official_service_is_pinned(
    server: _Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    del server
    console = _console(monkeypatch)
    result = _invoke("add", "official")
    assert result.exit_code == 2
    assert result.stderr.startswith("official_endpoint_unavailable:")
    assert console.shown == [] and targets.list_targets() == ()


def test_the_official_preset_fills_the_pinned_url_and_still_asks_the_consent(
    server: _Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        server_folders,
        "OFFICIAL_ENDPOINT_ORIGINS",
        (server_folders.OfficialOrigin("fu.example", 443, "/api"),),
    )
    console = _console(monkeypatch, b"official")
    result = _invoke("add", "official", "--key-file", str(server.key_file()))
    assert result.exit_code == 0, result.output
    record, _root = _added("official")
    assert record.base_url == "https://fu.example/api"
    # Official skips the outside-read question, never the consent's typed name: the one answer
    # given was the typed name.
    assert console.answers == []


class _RefusingStore:
    """A platform credential store that is there but cannot take a key now (a keychain that is
    locked, or missing under a private HOME); it records what it was asked."""

    def __init__(self) -> None:
        self.asked: list[str] = []

    def get_password(self, service: str, username: str) -> str | None:
        self.asked.append("get")
        raise RuntimeError("refused", service, username)

    def set_password(self, service: str, username: str, password: str) -> None:
        del password
        self.asked.append("set")
        raise RuntimeError("refused", service, username)

    def delete_password(self, service: str, username: str) -> None:
        self.asked.append("delete")
        raise RuntimeError("refused", service, username)


def test_add_and_login_keep_the_key_in_the_owner_only_file_when_the_store_cannot_take_it(
    server: _Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On a Mac whose keychain could not take the key, ``server add`` failed with
    ``credential_store_unavailable``; the key belongs in the owner-only file instead, and the
    record says so, so every reader finds it there."""

    store = _RefusingStore()
    monkeypatch.setattr("finishup.client.credentials._platform_backend", lambda: store)
    remote_runtime(monkeypatch)
    _console(monkeypatch, b"listed", b"web")
    added = _invoke("add", "web", "https://web.example", "--key-file", str(server.key_file()))
    assert added.exit_code == 0, added.output
    record, root = _added()
    assert record.credential == "file"
    assert KeyringOrFileCredential(record.target_id, root, recorded="file").read() == server.key
    _rotated, newer = server.keys.create("laptop-2", "agent")
    login = _invoke("login", "web", "--key-file", str(server.key_file(newer, "new.key")))
    assert login.exit_code == 0, login.output
    assert f"({record.target_id}) in an owner-only file; the server accepted it" in login.stdout
    record, root = _added()
    assert record.credential == "file"
    assert KeyringOrFileCredential(record.target_id, root, recorded="file").read() == newer
    assert store.asked == ["set", "set"]


class _MissingKeychain(_RefusingStore):
    """keyring's macOS backend, by identity, on a Mac whose keychain is missing or locked."""

    __module__ = "keyring.backends.macOS"
    __qualname__ = "Keyring"


def test_add_and_login_never_ask_a_keychain_that_is_missing_or_locked(
    server: _Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Under a private HOME, storing the key made macOS show "A keychain cannot be found to
    store ..." and wait. The keychain's state is read first, without asking anyone; a missing
    or locked one is never asked to store, and the owner-only file keeps the key."""

    from finishup.client import credentials

    keychain = _MissingKeychain()
    monkeypatch.setattr(credentials, "_platform_backend", lambda: keychain)
    monkeypatch.setattr(credentials, "_macos_keychain_ready", lambda: False)
    remote_runtime(monkeypatch)
    _console(monkeypatch, b"listed", b"web")
    added = _invoke("add", "web", "https://web.example", "--key-file", str(server.key_file()))
    assert added.exit_code == 0, added.output
    _rotated, newer = server.keys.create("laptop-2", "agent")
    login = _invoke("login", "web", "--key-file", str(server.key_file(newer, "new.key")))
    assert login.exit_code == 0, login.output
    assert "in an owner-only file; the server accepted it" in login.stdout
    record, root = _added()
    assert record.credential == "file"
    assert KeyringOrFileCredential(record.target_id, root, recorded="file").read() == newer
    assert keychain.asked == []


def test_login_keeps_nothing_the_server_refuses_and_an_unverified_key_when_it_is_down(
    server: _Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime: StandInRuntime = remote_runtime(monkeypatch)
    _console(monkeypatch, b"listed", b"web")
    assert (
        _invoke("add", "web", "https://web.example", "--key-file", str(server.key_file())).exit_code
        == 0
    )
    record, root = _added()
    generation = credential_generation_path(root).read_bytes()
    refused = _invoke(
        "login", "web", "--key-file", str(server.key_file("fuk_000000000000_" + "A" * 43, "x.key"))
    )
    assert refused.exit_code != 0
    assert "nothing was stored" in refused.stderr
    assert KeyringOrFileCredential(record.target_id, root, recorded="file").read() == server.key
    assert credential_generation_path(root).read_bytes() == generation
    assert runtime.stops == []
    server.reachable = False
    later = "fuk_0123456789ab_" + "B" * 43
    down = _invoke("login", "web", "--key-file", str(server.key_file(later, "later.key")))
    assert down.exit_code == 0, down.output
    assert "not verified yet" in down.stdout
    assert KeyringOrFileCredential(record.target_id, root, recorded="file").read() == later
    assert credential_generation_path(root).read_bytes() != generation
    assert runtime.stops == [root]


def test_login_with_a_new_key_asks_for_the_consent_again_and_logout_ends_it(
    server: _Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = remote_runtime(monkeypatch)
    _console(monkeypatch, b"listed", b"web")
    assert (
        _invoke("add", "web", "https://web.example", "--key-file", str(server.key_file())).exit_code
        == 0
    )
    record, root = _added()
    _rotated, newer = server.keys.create("laptop-2", "agent")
    accepted = _invoke("login", "web", "--key-file", str(server.key_file(newer, "new.key")))
    assert accepted.exit_code == 0, accepted.output
    assert "the server accepted it" in accepted.stdout
    assert "finishup server use web" in accepted.stdout
    generation = credential_generation_path(root).read_bytes()
    out = _invoke("logout", "web")
    assert out.exit_code == 0, out.output
    assert targets.read_target(root) is not None
    assert targets.read_target(root).credential is None  # type: ignore[union-attr]
    assert credential_generation_path(root).read_bytes() != generation
    assert runtime.stops == [root, root]
    del record


def test_status_names_the_https_connection(
    server: _Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    remote_runtime(monkeypatch)
    _console(monkeypatch, b"listed", b"web")
    assert (
        _invoke("add", "web", "https://web.example", "--key-file", str(server.key_file())).exit_code
        == 0
    )
    status = _invoke("status", "web", "--json")
    assert status.exit_code == 0, status.output
    connection = json.loads(status.stdout)["target"]["connection"]
    assert connection["style"] == "relay" and connection["styles_offered"] == ["relay", "direct"]


# --- layer-5 review fixes ------------------------------------------------------------------------


def _registry_locked() -> bool:
    """Whether another holder has the registry lock now (a second open's non-blocking flock)."""

    import fcntl

    path = targets.servers_dir() / targets._REGISTRY_LOCK_NAME  # pyright: ignore[reportPrivateUsage]
    descriptor = os.open(path, os.O_RDWR)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    finally:
        os.close(descriptor)
    return False


def test_an_unverified_login_refuses_work_until_the_keys_own_profile_is_checked(
    server: _Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """C1: a key stored while the server did not answer leaves no profile cached from the
    previous key, so the consent step refuses until this key's profile is fetched and compared."""

    from finishup.client.rest_discovery import fetch_profile
    from finishup.client.server_profile import consent_verdict, refresh_profile

    remote_runtime(monkeypatch)
    _console(monkeypatch, b"listed", b"web")
    assert (
        _invoke("add", "web", "https://web.example", "--key-file", str(server.key_file())).exit_code
        == 0
    )
    record, root = _added()
    assert consent_verdict(record).phase is None
    _other, other_principal = server.keys.create("someone-else", "agent")
    server.reachable = False
    down = _invoke("login", "web", "--key-file", str(server.key_file(other_principal, "o.key")))
    assert down.exit_code == 0, down.output
    assert "sends nothing to that server until the key is checked" in down.stdout
    assert read_cached_profile(root) is None
    stored = targets.read_target(root)
    assert stored is not None and consent_verdict(stored).phase == "server_profile_changed"
    # The server is back: the profile this key answers is another identity than the consented
    # one, so it stays refused until the owner agrees again.
    server.reachable = True
    with targets.registry_lock():
        verdict = refresh_profile(stored, fetch_profile(stored, consented=True))
    assert verdict.phase == "server_profile_changed"
    # The same key as consented, stored while the server was down: its own profile, once
    # fetched and compared, admits again.
    server.reachable = False
    again = _invoke("login", "web", "--key-file", str(server.key_file()))
    assert again.exit_code == 0, again.output
    assert read_cached_profile(root) is None
    server.reachable = True
    stored = targets.read_target(root)
    assert stored is not None
    with targets.registry_lock():
        verdict = refresh_profile(stored, fetch_profile(stored, consented=True))
    assert verdict.phase is None


def test_login_and_logout_change_the_key_only_under_the_registry_lock(
    server: _Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """C2: the key is stored and deleted inside the registry-locked step that writes the record,
    the generation and the profile, so concurrent logins and logouts are serialized."""

    remote_runtime(monkeypatch)
    _console(monkeypatch, b"listed", b"web")
    assert (
        _invoke("add", "web", "https://web.example", "--key-file", str(server.key_file())).exit_code
        == 0
    )
    held: list[tuple[str, bool]] = []
    original_store = KeyringOrFileCredential.store
    original_delete = KeyringOrFileCredential.delete

    def store(self: KeyringOrFileCredential, key: str) -> Any:
        held.append(("store", _registry_locked()))
        return original_store(self, key)

    def delete(self: KeyringOrFileCredential) -> Any:
        held.append(("delete", _registry_locked()))
        return original_delete(self)

    monkeypatch.setattr(KeyringOrFileCredential, "store", store)
    monkeypatch.setattr(KeyringOrFileCredential, "delete", delete)
    assert _invoke("login", "web", "--key-file", str(server.key_file())).exit_code == 0
    assert _invoke("logout", "web").exit_code == 0
    assert held == [("store", True), ("delete", True)]


@pytest.mark.parametrize("body", [b"{}", None], ids=["empty_document", "another_key"])
def test_a_profile_this_release_cannot_use_stores_nothing_and_stops_nothing(
    server: _Server, monkeypatch: pytest.MonkeyPatch, body: bytes | None
) -> None:
    """C3 and B7: ``200`` with an invalid profile, or one naming another key than the one sent,
    is ``remote_incompatible`` before anything changes: the working key, the generation and the
    helper stay as they were."""

    runtime: StandInRuntime = remote_runtime(monkeypatch)
    _console(monkeypatch, b"listed", b"web")
    assert (
        _invoke("add", "web", "https://web.example", "--key-file", str(server.key_file())).exit_code
        == 0
    )
    record, root = _added()
    generation = credential_generation_path(root).read_bytes()
    cached = read_cached_profile(root)
    _newer_record, newer = server.keys.create("laptop-2", "agent")
    if body is None:
        document = profile_document()
        document["edges"] = ["rest-1"]
        document["key"] = {"id": "0" * 12, "scope": "agent", "principal": "p_" + "1" * 16}
        body = json.dumps(document).encode()
    server.profile_body = body
    refused = _invoke("login", "web", "--key-file", str(server.key_file(newer, "n.key")))
    assert refused.exit_code != 0
    assert refused.stderr.startswith("remote_incompatible:")
    assert "nothing was stored" in refused.stderr
    assert KeyringOrFileCredential(record.target_id, root, recorded="file").read() == server.key
    assert credential_generation_path(root).read_bytes() == generation
    assert read_cached_profile(root) == cached
    assert runtime.stops == []


# --- layer-5 review fixes, second round ----------------------------------------------------------


def test_a_new_key_is_stored_only_after_the_previous_keys_profile_and_generation_are_gone(
    server: _Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """C1: when the key store runs, the profile answered to the previous key is already forgotten
    and the credential generation already moved: no reader can pair the new key with the
    previous consent, even for an instant."""

    from finishup.client.server_profile import consent_verdict

    remote_runtime(monkeypatch)
    _console(monkeypatch, b"listed", b"web")
    assert (
        _invoke("add", "web", "https://web.example", "--key-file", str(server.key_file())).exit_code
        == 0
    )
    record, root = _added()
    generation = credential_generation_path(root).read_bytes()
    seen: list[tuple[bool, bool, str | None]] = []
    original_store = KeyringOrFileCredential.store

    def store(self: KeyringOrFileCredential, key: str) -> Any:
        stored = targets.read_target(root)
        assert stored is not None
        seen.append(
            (
                read_cached_profile(root) is None,
                credential_generation_path(root).read_bytes() != generation,
                consent_verdict(stored).phase,
            )
        )
        return original_store(self, key)

    monkeypatch.setattr(KeyringOrFileCredential, "store", store)
    _rotated, newer = server.keys.create("laptop-2", "agent")
    accepted = _invoke("login", "web", "--key-file", str(server.key_file(newer, "new.key")))
    assert accepted.exit_code == 0, accepted.output
    assert seen == [(True, True, "server_profile_changed")]
    del record


@pytest.mark.parametrize("failing", ["write_target", "refresh_profile"])
def test_a_login_that_fails_after_its_key_is_stored_leaves_nothing_sendable(
    server: _Server, monkeypatch: pytest.MonkeyPatch, failing: str
) -> None:
    """C1: the record write (or the profile's) failing once the new key is stored never leaves
    that key with the previous consent: the profile stays forgotten, the generation moved, the
    helper stopped, and the gate every connection passes first refuses until a key is checked."""

    from finishup.client import authorization, server_profile
    from finishup.client.targets import TargetError

    runtime: StandInRuntime = remote_runtime(monkeypatch)
    _console(monkeypatch, b"listed", b"web")
    assert (
        _invoke("add", "web", "https://web.example", "--key-file", str(server.key_file())).exit_code
        == 0
    )
    record, root = _added()
    generation = credential_generation_path(root).read_bytes()
    authorization.gate(record)  # admitted under the consent before the login

    def fail(*_args: object, **_kwargs: object) -> Any:
        raise TargetError("target_root_unsafe")

    module = server_cli if failing == "write_target" else server_profile
    monkeypatch.setattr(module, failing, fail)
    _rotated, newer = server.keys.create("laptop-2", "agent")
    failed = _invoke("login", "web", "--key-file", str(server.key_file(newer, "new.key")))
    assert failed.exit_code != 0
    assert failed.stderr.startswith("target_root_unsafe:")
    assert "sends nothing to that server until a key is checked" in failed.stderr
    assert KeyringOrFileCredential(record.target_id, root, recorded="file").read() == newer
    assert read_cached_profile(root) is None
    assert credential_generation_path(root).read_bytes() != generation
    assert runtime.stops == [root]
    stored = targets.read_target(root)
    assert stored is not None
    with pytest.raises(TargetError) as refused:
        authorization.gate(stored)
    assert refused.value.reason == "server_profile_changed"


def test_a_login_refused_before_anything_changed_still_says_nothing_was_stored(
    server: _Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """C1: a refusal before the previous key's profile was forgotten changes nothing."""

    runtime: StandInRuntime = remote_runtime(monkeypatch)
    _console(monkeypatch, b"listed", b"web")
    assert (
        _invoke("add", "web", "https://web.example", "--key-file", str(server.key_file())).exit_code
        == 0
    )
    record, root = _added()
    cached = read_cached_profile(root)
    generation = credential_generation_path(root).read_bytes()

    def fail(_root: Path) -> None:
        raise server_cli.TargetError("target_root_unsafe")

    from finishup.client import server_profile

    monkeypatch.setattr(server_profile, "forget_cached_profile", fail)
    _rotated, newer = server.keys.create("laptop-2", "agent")
    failed = _invoke("login", "web", "--key-file", str(server.key_file(newer, "new.key")))
    assert failed.exit_code != 0
    assert "sends nothing" not in failed.stderr
    assert KeyringOrFileCredential(record.target_id, root, recorded="file").read() == server.key
    assert read_cached_profile(root) == cached
    assert credential_generation_path(root).read_bytes() == generation
    assert runtime.stops == []


def test_server_use_never_records_a_consent_to_a_profile_another_key_answered(
    server: _Server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """C2: a login that lands while the owner is asked (after the profile was fetched with the
    previous key) means that profile answered another key: nothing is recorded or selected."""

    remote_runtime(monkeypatch)
    _console(monkeypatch, b"listed", b"web", b"web")
    assert (
        _invoke("add", "web", "https://web.example", "--key-file", str(server.key_file())).exit_code
        == 0
    )
    record, root = _added()
    before = targets.read_target(root)
    original = server_cli._fetch_profile  # pyright: ignore[reportPrivateUsage]

    def fetched_then_login(target: ServerTarget) -> Any:
        fetched = original(target)
        from finishup.client.authorization import bump_credential_generation

        assert bump_credential_generation(root)  # 'server login' elsewhere, meanwhile
        return fetched

    monkeypatch.setattr(server_cli, "_fetch_profile", fetched_then_login)
    refused = _invoke("use", "web")
    assert refused.exit_code != 0
    assert "changed while you were asked" in refused.stderr
    assert targets.read_target(root) == before
    assert targets.read_selected_target_id() != record.target_id
