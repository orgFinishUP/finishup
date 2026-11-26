"""OS-written metadata files are recognised by name and never collide with a managed member."""

from __future__ import annotations

import pytest

from finishup.adapters.integrations.claude_code_integration import render_claude_code_plugin
from finishup.adapters.integrations.codex_plugin import (
    plugin_tree_matches_marker,
    render_plugin_install_tree,
)
from finishup.adapters.integrations.codex_skill import load_packaged_skill_members
from finishup.adapters.integrations.cursor_integration import render_cursor_plugin
from finishup.adapters.integrations.os_metadata import is_os_metadata_file
from finishup.adapters.integrations.portable_plugin import render_portable_plugin_tree
from finishup.ports.plugin_artifacts import PluginFormatProfile


@pytest.mark.parametrize(
    "path",
    [
        ".DS_Store",
        "skills/finishup/.DS_Store",
        "._SKILL.md",
        "._.mcp.json",
        "._.codex-plugin",
        "skills/finishup/._SKILL.md",
    ],
)
def test_finder_and_appledouble_files_are_os_metadata(path: str) -> None:
    assert is_os_metadata_file(path) is True


@pytest.mark.parametrize(
    "path",
    [
        "SKILL.md",
        "DS_Store",
        ".DS_Store.txt",
        ".ds_store",
        "notes._md",
        "._",
        "._notes/draft.md",
        ".DS_Store/notes.md",
        ".yoetz-plugin-install.json",
        ".yoetz-install.json",
        ".mcp.json",
    ],
)
def test_other_names_are_owner_content(path: str) -> None:
    assert is_os_metadata_file(path) is False


def test_no_rendered_managed_member_is_mistaken_for_os_metadata() -> None:
    """Skipping these names can never hide a file FinishUP itself writes."""

    trees = [
        render_plugin_install_tree(),
        render_plugin_install_tree(codex_version="0.148.0-alpha.6"),
        render_portable_plugin_tree(),
        dict(load_packaged_skill_members()),
        dict(render_claude_code_plugin().members),
        dict(render_cursor_plugin(PluginFormatProfile.AGENT_PLUGINS_1).members),
        dict(render_cursor_plugin(PluginFormatProfile.CURSOR_PLUGIN_NATIVE).members),
    ]

    for tree in trees:
        assert tree
        assert not [path for path in tree if is_os_metadata_file(path)]


def test_a_marker_consistent_tree_with_os_metadata_still_matches_its_marker() -> None:
    tree = render_plugin_install_tree()
    with_metadata = {
        **tree,
        ".DS_Store": b"\x00\x00\x00\x01Bud1",
        "skills/finishup/._SKILL.md": b"\x00\x05\x16\x07",
    }
    assert plugin_tree_matches_marker(with_metadata) is True
    assert plugin_tree_matches_marker({**with_metadata, "notes.md": b"owner\n"}) is False
    assert plugin_tree_matches_marker({**with_metadata, "._": b"owner\n"}) is False
