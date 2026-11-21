"""tools/list builds its Tool objects once per runtime and advertises the same bytes every time."""

from __future__ import annotations

import asyncio
import dataclasses
from typing import cast

import pytest
from mcp import types

from finishup.mcp import server
from finishup.mcp.descriptors import ToolDescriptor
from finishup.protocol.canonical import JsonValue, canonical_encode


def _uncached_tools(descriptors: tuple[ToolDescriptor, ...]) -> list[types.Tool]:
    """The pre-cache list_tools body, kept verbatim as the differential reference."""

    return [
        types.Tool(
            name=descriptor.name,
            title=descriptor.title,
            description=descriptor.description,
            inputSchema=cast(
                dict[str, object],
                server._mutable_json(descriptor.advertised_input_schema),  # pyright: ignore[reportPrivateUsage]
            ),
            outputSchema=cast(
                dict[str, object],
                server._mutable_json(descriptor.output_schema),  # pyright: ignore[reportPrivateUsage]
            ),
            annotations=types.ToolAnnotations(
                title=descriptor.title,
                readOnlyHint=descriptor.annotations.read_only,
                destructiveHint=descriptor.annotations.destructive,
                idempotentHint=descriptor.annotations.idempotent,
                openWorldHint=descriptor.annotations.open_world,
            ),
        )
        for descriptor in descriptors
    ]


def _wire(tools: list[types.Tool]) -> bytes:
    result = types.ListToolsResult(tools=tools)
    return canonical_encode(
        cast(JsonValue, result.model_dump(by_alias=True, mode="json", exclude_none=True))
    )


@pytest.mark.parametrize("route_profile", ["policy", "strict"])
@pytest.mark.parametrize("host_profile", ["generic", "codex", "claude", "cursor"])
def test_cached_tool_list_matches_the_uncached_build_byte_for_byte(
    route_profile: server.McpRouteProfile, host_profile: server.McpHostProfile
) -> None:
    runtime = server.build_bridge_runtime(route_profile, host_profile=host_profile)
    expected = _wire(_uncached_tools(runtime.descriptors))
    first = asyncio.run(server.list_tools(runtime))
    second = asyncio.run(server.list_tools(runtime))
    assert _wire(first) == expected
    assert _wire(second) == expected
    assert first is not second
    assert [tool.name for tool in first] == [d.name for d in runtime.descriptors]


def test_repeat_tool_list_does_not_rebuild_schemas(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = server.build_bridge_runtime("policy", host_profile="claude")
    calls = 0
    real = server._mutable_json  # pyright: ignore[reportPrivateUsage]

    def counted(value: object) -> object:
        nonlocal calls
        calls += 1
        return real(value)

    monkeypatch.setattr(server, "_mutable_json", counted)
    asyncio.run(server.list_tools(runtime))
    assert calls > 0
    calls = 0
    for _ in range(3):
        asyncio.run(server.list_tools(runtime))
    assert calls == 0


def test_replaced_runtime_never_reuses_another_runtimes_tool_list() -> None:
    runtime = server.build_bridge_runtime("policy")
    asyncio.run(server.list_tools(runtime))
    narrowed = dataclasses.replace(runtime, descriptors=runtime.descriptors[:2])
    tools = asyncio.run(server.list_tools(narrowed))
    assert _wire(tools) == _wire(_uncached_tools(runtime.descriptors[:2]))
    assert len(asyncio.run(server.list_tools(runtime))) == len(runtime.descriptors)
