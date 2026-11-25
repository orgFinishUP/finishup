from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

import pytest

from finishup.adapters.integrations.cursor_integration import (
    CursorPluginTarget,
    apply_cursor_plugin,
    preview_cursor_plugin,
    render_cursor_plugin,
    status_cursor_plugin,
)
from finishup.adapters.integrations.cursor_mcp_runtime import (
    CursorMcpProcessSnapshot,
    FixedCursorMcpProcesses,
    classify_cursor_semantic_ceiling,
    classify_serve_argv,
    classify_serve_suffix,
    observe_cursor_mcp_runtime,
)
from finishup.domain.values import request_id
from finishup.ports.plugin_artifacts import (
    ArtifactAuthority,
    McpOwnership,
    PluginArtifactAction,
    PluginFormatProfile,
    PluginProofFacet,
)
from finishup.protocol.canonical import canonical_encode
from finishup.version import read_verified_resource
from synthetic_paths import MACOS_HOME

_REQUEST = request_id("req_10000000-0000-4000-8000-000000000021")
_REVIEW_ID = "a" * 64


class _AcceptingReview:
    def consume_artifact_review(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        return None

    def consume_setup_authority(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        return None


def test_serve_suffix_classifies_exact_policy_and_strict_argv() -> None:
    assert classify_serve_suffix(("/opt/finishup/bin/finishup", "mcp", "serve")) == "policy"
    assert classify_serve_suffix(("finishup", "mcp", "serve", "--host", "cursor")) == "policy"
    assert (
        classify_serve_suffix(
            (
                "finishup",
                "mcp",
                "serve",
                "--host",
                "cursor",
                "--project-root",
                "/srv/projects/example",
            )
        )
        == "policy"
    )
    assert classify_serve_suffix(("finishup", "mcp", "serve", "--semantic", "off")) == "strict"
    assert (
        classify_serve_suffix(("finishup", "mcp", "serve", "--host", "cursor", "--semantic", "off"))
        == "strict"
    )
    assert (
        classify_serve_suffix(
            (
                "finishup",
                "mcp",
                "serve",
                "--host",
                "cursor",
                "--project-root",
                "/srv/projects/example",
                "--semantic",
                "off",
            )
        )
        == "strict"
    )
    assert (
        classify_serve_suffix(
            ("finishup", "mcp", "serve", "--host", "cursor", "--project-root", "relative")
        )
        == "foreign"
    )
    assert (
        classify_serve_suffix(
            ("finishup", "mcp", "serve", "--host", "cursor", "--project-root", "/")
        )
        == "foreign"
    )
    assert (
        classify_serve_suffix(
            ("finishup", "mcp", "serve", "--host", "cursor", "--project-root", "/srv/../project")
        )
        == "foreign"
    )
    assert classify_serve_suffix(("/secret/finishup", "mcp", "serve", "--extra")) == "foreign"
    assert classify_serve_suffix(("/secret/not-finishup", "mcp", "serve")) is None
    assert classify_serve_suffix(("python", "worker.py", "mcp", "serve")) is None
    assert classify_serve_suffix(("unrelated",)) is None


def test_cursor_helper_comm_accepts_macos_paths_without_retaining_them() -> None:
    import finishup.adapters.integrations.cursor_mcp_runtime as module

    assert module._cursor_helper_comm(  # pyright: ignore[reportPrivateUsage]
        "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper (Plugin)"
    )
    assert module._cursor_helper_comm("cursor")  # pyright: ignore[reportPrivateUsage]
    assert not module._cursor_helper_comm(  # pyright: ignore[reportPrivateUsage]
        "/Applications/Other.app/Contents/MacOS/Other"
    )


def test_installed_policy_plus_live_strict_helper_requires_full_restart() -> None:
    runtime = observe_cursor_mcp_runtime(
        installed_route="policy",
        processes=FixedCursorMcpProcesses(
            (
                CursorMcpProcessSnapshot("cursor_helper", "strict"),
                CursorMcpProcessSnapshot("cursor_helper", "policy"),
            )
        ),
    )
    assert runtime.activation == "full_restart_required"
    assert runtime.live_route_profile is None
    assert runtime.strict_process_count == 1
    assert runtime.policy_process_count == 1
    assert (
        classify_cursor_semantic_ceiling(
            semantic_status="blocked_by_policy",
            semantic_reason="route_semantic_ceiling",
            installed_route="policy",
            runtime=runtime,
        )
        == "activation_mismatch"
    )


def test_installed_and_live_strict_is_a_genuine_ceiling() -> None:
    runtime = observe_cursor_mcp_runtime(
        installed_route="strict",
        processes=FixedCursorMcpProcesses((CursorMcpProcessSnapshot("cursor_helper", "strict"),)),
    )
    assert runtime.activation == "matched"
    assert runtime.live_route_profile == "strict"
    assert (
        classify_cursor_semantic_ceiling(
            semantic_status="blocked_by_policy",
            semantic_reason="route_semantic_ceiling",
            installed_route="strict",
            runtime=runtime,
        )
        == "genuine_route_ceiling"
    )


def test_non_helper_processes_do_not_prove_cursor_activation() -> None:
    runtime = observe_cursor_mcp_runtime(
        installed_route="policy",
        processes=FixedCursorMcpProcesses((CursorMcpProcessSnapshot("other", "strict"),)),
    )
    assert runtime.activation == "unobserved"
    assert runtime.strict_process_count == 1
    assert runtime.live_route_profile is None


def test_truncated_process_inventory_never_reports_a_route_match() -> None:
    runtime = observe_cursor_mcp_runtime(
        installed_route="policy",
        processes=FixedCursorMcpProcesses(
            tuple(CursorMcpProcessSnapshot("cursor_helper", "policy") for _ in range(65))
        ),
    )

    assert runtime.observed is True
    assert runtime.activation == "unobserved"
    assert runtime.live_route_profile is None


def test_status_binds_installed_policy_to_stale_strict_runtime(tmp_path: Path) -> None:
    target = CursorPluginTarget(str(tmp_path / ".cursor"))
    artifact = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
        mcp_ownership=McpOwnership.PLUGIN_MANAGED,
        route_profile="policy",
    )
    preview = preview_cursor_plugin(
        _REQUEST,
        target,
        PluginArtifactAction.INSTALL,
        artifact,
    )
    apply_cursor_plugin(
        preview.request_id,
        target,
        PluginArtifactAction.INSTALL,
        artifact,
        accepted_preview_digest=preview.preview_digest,
        authority=ArtifactAuthority("review_only", preview.preview_digest, _REVIEW_ID),
        review=_AcceptingReview(),
    )
    status = status_cursor_plugin(
        target,
        artifact,
        processes=FixedCursorMcpProcesses((CursorMcpProcessSnapshot("cursor_helper", "strict"),)),
    )
    assert status.mcp_observation.route_profile == "policy"
    assert status.mcp_observation.ownership_state.value == "plugin"
    assert status.runtime.activation == "full_restart_required"
    assert status.runtime.live_route_profile == "strict"
    proof = {item.facet: item.status for item in status.proof}
    assert proof[PluginProofFacet.INSTALLED_BYTES] == "proven"
    assert proof[PluginProofFacet.HOST_ACTIVATION] == "not_observed"
    encoded = canonical_encode(
        {
            "activation": status.runtime.activation,
            "route": status.mcp_observation.route_profile,
        }
    )
    assert b"full_restart_required" in encoded
    assert b"/secret/" not in encoded
    assert "reload_window_does_not_replace_mcp_runtime" in preview.warnings


def test_runtime_status_never_echoes_foreign_argv() -> None:
    runtime = observe_cursor_mcp_runtime(
        installed_route="policy",
        processes=FixedCursorMcpProcesses((CursorMcpProcessSnapshot("cursor_helper", None),)),
    )
    payload = json.dumps(
        {
            "activation": runtime.activation,
            "foreign_process_count": runtime.foreign_process_count,
            "live_route_profile": runtime.live_route_profile,
        }
    )
    assert runtime.foreign_process_count == 1
    assert runtime.activation == "full_restart_required"
    assert "secret" not in payload
    assert runtime.live_route_profile is None


def test_dogfood_fixture_names_the_activation_mismatch_case() -> None:
    fixture = json.loads(
        read_verified_resource("fixtures/agent-plugins/cursor-stale-shared-mcp-runtime.case.json")
    )
    runtime = observe_cursor_mcp_runtime(
        installed_route=fixture["installed_route_profile"],
        processes=FixedCursorMcpProcesses(
            (CursorMcpProcessSnapshot("cursor_helper", fixture["live_runtime_route_profile"]),)
        ),
    )
    assert runtime.activation == fixture["expected_activation"]
    assert (
        classify_cursor_semantic_ceiling(
            semantic_status="blocked_by_policy",
            semantic_reason="route_semantic_ceiling",
            installed_route=fixture["installed_route_profile"],
            runtime=runtime,
        )
        == fixture["expected_ceiling_class"]
    )


def test_serve_argv_compares_the_tokens_before_serve_with_the_bound_launcher() -> None:
    """Issue #468: a live helper child must be attributable to the exact bound executable."""

    from finishup.adapters.integrations.cursor_mcp_runtime import classify_serve_argv

    console = ("/opt/current/bin/finishup",)
    module = ("/opt/current/bin/python3.14", "-m", "finishup")
    serve = ("mcp", "serve", "--host", "cursor")

    assert classify_serve_argv((*console, *serve), console) == ("policy", "matched")
    # A shebang console script shows the interpreter first; the script token still matches.
    assert classify_serve_argv(("/opt/current/bin/python3.14", *console, *serve), console) == (
        "policy",
        "matched",
    )
    assert classify_serve_argv((*module, *serve, "--semantic", "off"), module) == (
        "strict",
        "matched",
    )
    # Another explicit executable answered the spawn: an ambient or neighbouring channel.
    assert classify_serve_argv(("/opt/older/bin/finishup", *serve), console) == (
        "policy",
        "different",
    )
    assert classify_serve_argv(("/usr/bin/python3", "-m", "finishup", *serve), module) == (
        "policy",
        "different",
    )
    # A bare name cannot be attributed either way.
    assert classify_serve_argv(("finishup", *serve), console) == ("policy", "unresolved")
    # Without an expected launcher nothing is compared.
    assert classify_serve_argv((*console, *serve), None) == ("policy", None)
    assert classify_serve_argv(("unrelated",), console) == (None, None)


def test_helper_child_on_a_different_executable_requires_full_restart() -> None:
    installed_policy_other_executable = FixedCursorMcpProcesses(
        (CursorMcpProcessSnapshot("cursor_helper", "policy", "different"),)
    )
    observation = observe_cursor_mcp_runtime(
        installed_route="policy", processes=installed_policy_other_executable
    )
    assert observation.activation == "full_restart_required"
    assert observation.executable_activation == "executable_mismatch"
    assert observation.live_route_profile == "policy"

    matched = observe_cursor_mcp_runtime(
        installed_route="policy",
        processes=FixedCursorMcpProcesses(
            (CursorMcpProcessSnapshot("cursor_helper", "policy", "matched"),)
        ),
    )
    assert matched.activation == "matched"
    assert matched.executable_activation == "matched"

    unresolved = observe_cursor_mcp_runtime(
        installed_route="policy",
        processes=FixedCursorMcpProcesses(
            (CursorMcpProcessSnapshot("cursor_helper", "policy", "unresolved"),)
        ),
    )
    assert unresolved.activation == "matched"
    assert unresolved.executable_activation == "unproven"

    # A non-helper process on another executable is counted but never drives activation.
    bystander = observe_cursor_mcp_runtime(
        installed_route="policy",
        processes=FixedCursorMcpProcesses(
            (
                CursorMcpProcessSnapshot("cursor_helper", "policy", "matched"),
                CursorMcpProcessSnapshot("other", "policy", "different"),
            )
        ),
    )
    assert bystander.activation == "matched"
    assert bystander.executable_activation == "matched"
    assert bystander.policy_process_count == 2


def test_macos_ps_text_matches_a_launcher_path_that_contains_whitespace() -> None:
    """``ps`` joins argv with spaces; a bound path with whitespace must still match exactly."""

    from finishup.adapters.integrations.cursor_mcp_runtime import launcher_precedes_serve_in_text

    spaced = ("/opt/FinishUP Tools/bin/finishup",)
    module = ("/opt/FinishUP Tools/venv/bin/python3.14", "-m", "finishup")

    assert launcher_precedes_serve_in_text(
        "/opt/FinishUP Tools/bin/finishup mcp serve --host cursor", spaced
    )
    # Shebang expansion puts the interpreter first; the script token still sits before serve.
    assert launcher_precedes_serve_in_text(
        "/opt/FinishUP Tools/bin/python3.14 /opt/FinishUP Tools/bin/finishup mcp serve --host cursor",
        spaced,
    )
    assert launcher_precedes_serve_in_text(
        "/opt/FinishUP Tools/venv/bin/python3.14 -m finishup mcp serve", module
    )
    # A longer path that merely ends with the same suffix is another executable.
    assert not launcher_precedes_serve_in_text(
        "/opt/other/opt/FinishUP Tools/bin/finishup mcp serve --host cursor", spaced
    )
    assert not launcher_precedes_serve_in_text("/opt/older/bin/finishup mcp serve", spaced)
    assert not launcher_precedes_serve_in_text("", spaced)

    # The split-token path alone would call the spaced launcher ``different``; the text check
    # is what the macOS scanner consults before reporting an executable mismatch.
    from finishup.adapters.integrations.cursor_mcp_runtime import classify_serve_argv

    text = "/opt/FinishUP Tools/bin/finishup mcp serve --host cursor"
    assert classify_serve_argv(tuple(text.split()), spaced) == ("policy", "different")


def test_darwin_scanner_uses_the_text_match_for_whitespace_launchers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess

    import finishup.adapters.integrations.cursor_mcp_runtime as module

    spaced = ("/opt/FinishUP Tools/bin/finishup",)
    comm_table = b"10 1 Cursor\n11 10 mcp-process\n12 11 /opt/FinishUP\n"
    arg_table = (
        b"10 1 /Applications/Cursor.app/Contents/MacOS/Cursor\n"
        b"11 10 mcp-process\n"
        b"12 11 /opt/FinishUP Tools/bin/finishup mcp serve --host cursor\n"
    )

    class _Completed:
        def __init__(self, stdout: bytes) -> None:
            self.returncode = 0
            self.stdout = stdout

    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: object) -> _Completed:
        del kwargs
        calls.append(argv)
        return _Completed(comm_table if "comm=" in argv else arg_table)

    monkeypatch.setattr(subprocess, "run", fake_run)
    snapshot = module._darwin_snapshots(spaced)  # pyright: ignore[reportPrivateUsage]
    assert snapshot == (CursorMcpProcessSnapshot("cursor_helper", "policy", "matched"),)
    assert len(calls) == 2


@pytest.mark.parametrize("filler_rows", [0, 509, 700, 4_000])
def test_darwin_scanner_reads_the_whole_process_table(
    monkeypatch: pytest.MonkeyPatch, filler_rows: int
) -> None:
    # ``ps`` lists by PID and Cursor usually starts late, so its helper child can sit past any
    # fixed row count; macOS must see it just as the Linux /proc walk does.
    import subprocess

    import finishup.adapters.integrations.cursor_mcp_runtime as module

    launcher = "/opt/finishup/bin/finishup"
    pids = range(100, 100 + filler_rows)
    comm_table = b"".join(f"{pid} 1 /usr/libexec/d{pid}\n".encode() for pid in pids)
    arg_table = b"".join(f"{pid} 1 /usr/libexec/d{pid} --flag\n".encode() for pid in pids)
    comm_table += b"9000 1 Cursor\n9001 9000 mcp-process\n9002 9001 finishup\n"
    arg_table += (
        b"9000 1 /Applications/Cursor.app/Contents/MacOS/Cursor\n"
        b"9001 9000 mcp-process\n" + f"9002 9001 {launcher} mcp serve --host cursor\n".encode()
    )

    class _Completed:
        def __init__(self, stdout: bytes) -> None:
            self.returncode = 0
            self.stdout = stdout

    def fake_run(argv: list[str], **kwargs: object) -> _Completed:
        del kwargs
        return _Completed(comm_table if "comm=" in argv else arg_table)

    monkeypatch.setattr(subprocess, "run", fake_run)
    snapshot = module._darwin_snapshots((launcher,))  # pyright: ignore[reportPrivateUsage]
    assert snapshot == (CursorMcpProcessSnapshot("cursor_helper", "policy", "matched"),)
    observation = observe_cursor_mcp_runtime(
        installed_route="policy", processes=FixedCursorMcpProcesses(snapshot)
    )
    assert observation.activation == "matched"
    assert observation.executable_activation == "matched"


@pytest.mark.parametrize(
    ("root", "tail", "route"),
    [
        (f"{MACOS_HOME}/dev/Documents/My Project", (), "policy"),
        (f"{MACOS_HOME}/dev/Documents/My Project", ("--semantic", "off"), "strict"),
        (f"{MACOS_HOME}/dev/Library/Mobile Documents/com~apple~CloudDocs/a b  c", (), "policy"),
        (f"{MACOS_HOME}/dev/" + "deep dir/" * 40 + "app", ("--semantic", "off"), "strict"),
    ],
)
@pytest.mark.parametrize(
    "launcher", [("/opt/finishup/bin/finishup",), ("/opt/FinishUP Tools/bin/finishup",)]
)
def test_darwin_scanner_classifies_a_project_root_that_contains_whitespace(
    monkeypatch: pytest.MonkeyPatch,
    root: str,
    tail: tuple[str, ...],
    route: str,
    launcher: tuple[str, ...],
) -> None:
    # Cursor expands ``--project-root ${workspaceFolder}`` to the workspace path, which on macOS
    # often contains spaces (``~/Documents/My Project``, iCloud ``Mobile Documents``). ``ps``
    # joins argv with spaces, so the scanner must classify the same child Linux classifies.
    import subprocess

    import finishup.adapters.integrations.cursor_mcp_runtime as module

    argv = (*launcher, "mcp", "serve", "--host", "cursor", "--project-root", root, *tail)
    assert classify_serve_argv(argv, launcher) == (route, "matched")

    comm_table = b"10 1 Cursor\n11 10 mcp-process\n12 11 /opt/finishup\n"
    arg_table = (
        b"10 1 /Applications/Cursor.app/Contents/MacOS/Cursor\n"
        b"11 10 mcp-process\n" + b"12 11 " + " ".join(argv).encode() + b"\n"
    )

    class _Completed:
        def __init__(self, stdout: bytes) -> None:
            self.returncode = 0
            self.stdout = stdout

    def fake_run(argv: list[str], **kwargs: object) -> _Completed:
        del kwargs
        return _Completed(comm_table if "comm=" in argv else arg_table)

    monkeypatch.setattr(subprocess, "run", fake_run)
    snapshot = module._darwin_snapshots(launcher)  # pyright: ignore[reportPrivateUsage]
    assert snapshot == (CursorMcpProcessSnapshot("cursor_helper", route, "matched"),)  # pyright: ignore[reportArgumentType]
    observation = observe_cursor_mcp_runtime(
        installed_route=route,  # pyright: ignore[reportArgumentType]
        processes=FixedCursorMcpProcesses(snapshot),
    )
    assert observation.activation == "matched"
    assert observation.live_route_profile == route
    assert observation.executable_activation == "matched"


def test_macos_ps_text_classifies_only_the_exact_project_registration() -> None:
    from finishup.adapters.integrations.cursor_mcp_runtime import classify_project_serve_text

    bound = ("/opt/finishup/bin/finishup",)
    root = f"{MACOS_HOME}/a/My Project"
    text = f"/opt/finishup/bin/finishup mcp serve --host cursor --project-root {root}"
    assert classify_project_serve_text(text, bound) == ("policy", "matched")
    assert classify_project_serve_text(text + " --semantic off", bound) == ("strict", "matched")
    assert classify_project_serve_text(text, None) == ("policy", None)
    other = text.replace("/opt/finishup/", "/opt/older/")
    assert classify_project_serve_text(other, bound) == ("policy", "different")
    # Not a FinishUP launcher before ``mcp serve``, a relative or traversing root, an unknown
    # trailing flag, or no project root at all: not this registration.
    assert classify_project_serve_text(text.replace("bin/finishup", "bin/other"), bound) is None
    assert classify_project_serve_text(text.replace(root, "My Project"), bound) is None
    traversing = text.replace(root, f"{MACOS_HOME}/../My Project")
    assert classify_project_serve_text(traversing, bound) is None
    assert classify_project_serve_text("/opt/finishup/bin/finishup mcp serve", bound) is None
    assert classify_project_serve_text("", bound) is None
    for trailing in (
        " --evil x",
        " --evil",
        " --semantic on",
        " --semantic offline",
        " --semantic off/y",
        " --project-binding mcp-roots",
        " --semantic off --evil x",
        " --evil x --semantic off",
        " --semantic off --semantic off",
    ):
        assert classify_project_serve_text(text + trailing, bound) is None, trailing


def _macos_scan_of_one_cursor_child(
    monkeypatch: pytest.MonkeyPatch, launcher: tuple[str, ...], argv: tuple[str, ...]
) -> tuple[CursorMcpProcessSnapshot, ...] | None:
    """Run the macOS scanner over a faked ``ps`` table: ``argv`` as a Cursor helper's child."""

    import subprocess

    import finishup.adapters.integrations.cursor_mcp_runtime as module

    comm_table = b"10 1 Cursor\n11 10 mcp-process\n12 11 /opt/finishup\n"
    arg_table = (
        b"10 1 /Applications/Cursor.app/Contents/MacOS/Cursor\n"
        b"11 10 mcp-process\n" + b"12 11 " + " ".join(argv).encode() + b"\n"
    )

    class _Completed:
        def __init__(self, stdout: bytes) -> None:
            self.returncode = 0
            self.stdout = stdout

    def fake_run(argv: list[str], **kwargs: object) -> _Completed:
        del kwargs
        return _Completed(comm_table if "comm=" in argv else arg_table)

    monkeypatch.setattr(subprocess, "run", fake_run)
    return module._darwin_snapshots(launcher)  # pyright: ignore[reportPrivateUsage]


_BOUND: tuple[str, ...] = ("/opt/finishup/bin/finishup",)
_PROJECT_SERVE: tuple[str, ...] = (*_BOUND, "mcp", "serve", "--host", "cursor", "--project-root")


@pytest.mark.parametrize("name", ["Project - Copy", "Notes -- 2026", "old --> new", "Project -v2"])
@pytest.mark.parametrize("tail", [(), ("--semantic", "off")])
def test_darwin_scanner_keeps_a_root_whose_words_start_no_long_option(
    monkeypatch: pytest.MonkeyPatch, name: str, tail: tuple[str, ...]
) -> None:
    route = "strict" if tail else "policy"
    argv = (*_PROJECT_SERVE, f"{MACOS_HOME}/a/{name}", *tail)
    assert classify_serve_argv(argv, _BOUND) == (route, "matched")
    snapshot = _macos_scan_of_one_cursor_child(monkeypatch, _BOUND, argv)
    assert snapshot == (CursorMcpProcessSnapshot("cursor_helper", route, "matched"),)


@pytest.mark.parametrize(
    "name",
    [
        "My Project --draft",
        "My Project --2026",
        "My Project --\u00e9t\u00e9",
        "x --semantic off/y",
        "x --semantic offline/y",
        "x --project-binding registered-project/y",
    ],
)
@pytest.mark.parametrize("tail", [(), ("--semantic", "off")])
def test_darwin_scanner_counts_a_root_that_holds_long_option_text_as_foreign(
    monkeypatch: pytest.MonkeyPatch, name: str, tail: tuple[str, ...]
) -> None:
    # ``ps`` text cannot tell a directory named ``My Project --draft`` from the root
    # ``My Project`` followed by an unknown ``--draft`` argument, nor ``x --semantic off/y`` from
    # the root ``x`` followed by ``--semantic off/y``. The argv classifier calls the second
    # reading foreign, so the text form refuses both: macOS counts this child as foreign, as main
    # did, while the NUL-split argv on Linux and WSL 2 still classifies it.
    argv = (*_PROJECT_SERVE, f"{MACOS_HOME}/a/{name}", *tail)
    assert classify_serve_argv(argv, _BOUND) == ("strict" if tail else "policy", "matched")
    snapshot = _macos_scan_of_one_cursor_child(monkeypatch, _BOUND, argv)
    assert snapshot == (CursorMcpProcessSnapshot("cursor_helper", None, "matched"),)


@pytest.mark.parametrize("words", [("-v",), ("extra",), ("--",), ("--", "x"), ("--_x",)])
@pytest.mark.parametrize("tail", [(), ("--semantic", "off")])
def test_darwin_scanner_reads_trailing_words_that_start_no_long_option_as_the_root(
    monkeypatch: pytest.MonkeyPatch, words: tuple[str, ...], tail: tuple[str, ...]
) -> None:
    # The known limit of the text form, recorded in the Cursor runbook. Trailing words that
    # start no long option cannot be told from a workspace path with spaces
    # (``My Project -v``), so macOS reads them as part of the root and classifies the child,
    # where the NUL-split argv on Linux and WSL 2, and main, call it foreign. ``mcp serve``
    # takes no positional argument and no short option.
    route = "strict" if tail else "policy"
    argv = (*_PROJECT_SERVE, f"{MACOS_HOME}/a/proj", *words, *tail)
    assert classify_serve_argv(argv, _BOUND) == ("foreign", "matched")
    snapshot = _macos_scan_of_one_cursor_child(monkeypatch, _BOUND, argv)
    assert snapshot == (CursorMcpProcessSnapshot("cursor_helper", route, "matched"),)


def test_darwin_scanner_reads_a_root_that_ends_in_the_strict_tail_as_the_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The other half of that limit: a workspace directory literally named ``x --semantic off``
    # renders the same text as the root ``x`` on the strict route, and macOS reads the route.
    # Main read it the same way from the whitespace-split tokens.
    argv = (*_PROJECT_SERVE, f"{MACOS_HOME}/a/x --semantic off")
    assert classify_serve_argv(argv, _BOUND) == ("policy", "matched")
    snapshot = _macos_scan_of_one_cursor_child(monkeypatch, _BOUND, argv)
    assert snapshot == (CursorMcpProcessSnapshot("cursor_helper", "strict", "matched"),)


@pytest.mark.parametrize("route", ["policy", "strict"])
@pytest.mark.parametrize("binding", ["mcp-roots", "registered-project"])
@pytest.mark.parametrize("root", [f"{MACOS_HOME}/a/proj", f"{MACOS_HOME}/a/My Project"])
@pytest.mark.parametrize(
    "launcher",
    [
        ("/opt/finishup/bin/finishup",),
        ("/opt/FinishUP Tools/bin/finishup",),
        ("/opt/current/bin/python3.14", "-m", "finishup"),
    ],
)
def test_every_rendered_project_registration_is_classified_in_both_forms(
    monkeypatch: pytest.MonkeyPatch,
    route: Literal["policy", "strict"],
    binding: Literal["mcp-roots", "registered-project"],
    root: str,
    launcher: tuple[str, ...],
) -> None:
    # The command comes from the renderer behind ``project-mcp install`` and ``setup run``:
    # ``--host cursor-cli`` selects the ``registered-project`` binding (issue #786), which is
    # rendered between the root and ``--semantic off``. A live child of FinishUP's own
    # registration is never foreign, from the NUL-split argv or from macOS ``ps`` text.
    from finishup.adapters.integrations import cursor_project_mcp

    entry = cursor_project_mcp._expected(  # pyright: ignore[reportPrivateUsage]
        launcher, None, route, project_root=Path(root), project_binding=binding
    )
    args = entry["args"]
    assert isinstance(args, list)
    argv = (str(entry["command"]), *(str(item) for item in args))
    assert ("--project-binding" in argv) is (binding == "registered-project")
    assert classify_serve_argv(argv, launcher) == (route, "matched")

    snapshot = _macos_scan_of_one_cursor_child(monkeypatch, launcher, argv)
    assert snapshot == (CursorMcpProcessSnapshot("cursor_helper", route, "matched"),)
    assert snapshot is not None
    observation = observe_cursor_mcp_runtime(
        installed_route=route, processes=FixedCursorMcpProcesses(snapshot)
    )
    assert observation.activation == "matched"
    assert observation.live_route_profile == route
    assert observation.foreign_process_count == 0


def test_agent_cli_binding_is_accepted_only_where_the_renderer_puts_it() -> None:
    from finishup.adapters.integrations.cursor_mcp_runtime import classify_project_serve_text

    serve = _PROJECT_SERVE[:-1]
    root = f"{MACOS_HOME}/a/My Project"
    binding = ("--project-binding", "registered-project")
    strict = ("--semantic", "off")

    rendered = (*serve, "--project-root", root, *binding)
    assert classify_serve_argv(rendered, _BOUND) == ("policy", "matched")
    assert classify_serve_argv((*rendered, *strict), _BOUND) == ("strict", "matched")
    assert classify_project_serve_text(" ".join(rendered), _BOUND) == ("policy", "matched")
    assert classify_project_serve_text(" ".join((*rendered, *strict)), _BOUND) == (
        "strict",
        "matched",
    )

    # The renderer never emits the binding without an absolute root, after the route, twice,
    # without a value, or with another value (the default ``mcp-roots`` spelled out, a longer
    # word that starts the same): none of these is that registration.
    for argv in (
        (*serve, *binding),
        (*serve, *binding, *strict),
        (*serve, "--project-root", "relative", *binding),
        (*serve, "--project-root", root, *strict, *binding),
        (*serve, "--project-root", root, *binding, *binding),
        (*serve, "--project-root", root, "--project-binding", "mcp-roots"),
        (*serve, "--project-root", root, "--project-binding"),
        (*serve, "--project-root", root, "--project-binding", "registered-projects"),
    ):
        assert classify_serve_argv(argv, _BOUND) == ("foreign", "matched"), argv
        assert classify_project_serve_text(" ".join(argv), _BOUND) is None, argv


_FOREIGN_TAILS: tuple[tuple[str, ...], ...] = (
    ("--evil", "x"),
    ("--evil",),
    ("--\u00c9vil", "x"),
    ("--semantic", "on"),
    ("--semantic", "offline"),
    ("--semantic", "off2"),
    ("--semantic", "off/y"),
    ("--semantic", "off/y", "--semantic", "off"),
    ("--project-binding", "mcp-roots"),
    ("--project-binding", "mcp-roots", "--semantic", "off"),
    ("--project-binding", "registered-projects"),
    ("--project-binding", "registered-project/y"),
    ("--project-binding", "registered-project/y", "--semantic", "off"),
    ("--project-binding", "registered-project", "--semantic", "on"),
    ("--project-binding", "registered-project", "--semantic", "offline"),
    ("--project-binding", "registered-project", "--evil", "x"),
    ("--project-binding", "registered-project", "--project-binding", "registered-project"),
    ("--semantic", "off", "--project-binding", "registered-project"),
    ("--semantic", "off", "--semantic", "off"),
    ("--semantic", "off", "--evil", "x"),
    ("--evil", "x", "--semantic", "off"),
)


@pytest.mark.parametrize("tail", _FOREIGN_TAILS)
@pytest.mark.parametrize("root", [f"{MACOS_HOME}/a/proj", f"{MACOS_HOME}/a/My Project"])
def test_darwin_scanner_reads_trailing_arguments_as_the_argv_classifier_does(
    monkeypatch: pytest.MonkeyPatch, root: str, tail: tuple[str, ...]
) -> None:
    # The ``ps`` text form exists only to recover a root that contains spaces. Long options after
    # the root that the argv classifier (Linux, WSL 2) calls foreign must read as foreign on
    # macOS too, whether or not the root has a space.
    argv = (*_PROJECT_SERVE, root, *tail)
    assert classify_serve_argv(argv, _BOUND) == ("foreign", "matched")
    snapshot = _macos_scan_of_one_cursor_child(monkeypatch, _BOUND, argv)
    assert snapshot == (CursorMcpProcessSnapshot("cursor_helper", None, "matched"),)
    assert snapshot is not None
    observation = observe_cursor_mcp_runtime(
        installed_route="strict", processes=FixedCursorMcpProcesses(snapshot)
    )
    assert observation.activation == "full_restart_required"
    assert observation.live_route_profile is None
    assert observation.foreign_process_count == 1
    assert observation.strict_process_count == 0
    assert observation.policy_process_count == 0


def test_darwin_scanner_skips_a_process_row_too_long_to_classify(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A row past the bound is not classified from a cut-off prefix (which could drop a trailing
    # ``--semantic off`` and misread the route); it is skipped, as Linux skips a long cmdline.
    import subprocess

    import finishup.adapters.integrations.cursor_mcp_runtime as module

    launcher = "/opt/finishup/bin/finishup"
    root = f"{MACOS_HOME}/dev/" + "d/" * 3_000 + "app"
    comm_table = b"10 1 Cursor\n11 10 mcp-process\n12 11 finishup\n"
    arg_table = (
        b"10 1 /Applications/Cursor.app/Contents/MacOS/Cursor\n"
        b"11 10 mcp-process\n"
        + f"12 11 {launcher} mcp serve --host cursor --project-root {root} --semantic off\n".encode()
    )

    class _Completed:
        def __init__(self, stdout: bytes) -> None:
            self.returncode = 0
            self.stdout = stdout

    def fake_run(argv: list[str], **kwargs: object) -> _Completed:
        del kwargs
        return _Completed(comm_table if "comm=" in argv else arg_table)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert module._darwin_snapshots((launcher,)) == ()  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    "launcher",
    ["yoetz", "/opt/yoetz/bin/yoetz", "C:\\tools\\yoetz.exe", "finishup", "/opt/x/finishup.exe"],
)
def test_either_launcher_spelling_is_a_finishup_child(launcher: str) -> None:
    # A helper keeps the ``yoetz mcp serve`` child an older registration spawned (ADR-048).
    assert classify_serve_suffix((launcher, "mcp", "serve", "--host", "cursor")) == "policy"


def test_other_launcher_names_are_not_finishup_children() -> None:
    assert classify_serve_suffix(("/opt/yoetz-tools/bin/yoetzd", "mcp", "serve")) is None
