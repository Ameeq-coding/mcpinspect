"""STDIO transport implementation (anyio subprocess)."""

from __future__ import annotations

from typing import Any

from mcpinspect.transport.base import MCPTransport


class StdioTransport(MCPTransport):
    """Connect to an MCP server over STDIO (subprocess)."""

    def __init__(self, command: str) -> None:
        self.command = command

    async def connect(self) -> None:  # noqa: D102
        raise NotImplementedError("StdioTransport.connect not implemented")

    async def disconnect(self) -> None:  # noqa: D102
        raise NotImplementedError("StdioTransport.disconnect not implemented")

    async def call(self, method: str, params: dict[str, Any] | None = None) -> Any:  # noqa: D102
        raise NotImplementedError("StdioTransport.call not implemented")

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:  # noqa: D102
        raise NotImplementedError("StdioTransport.call_tool not implemented")
