"""HTTP + SSE transport implementation (httpx + anyio)."""

from __future__ import annotations

from typing import Any

from mcpinspect.transport.base import MCPTransport


class HttpSseTransport(MCPTransport):
    """Connect to an MCP server over HTTP with Server-Sent Events."""

    def __init__(self, url: str) -> None:
        self.url = url

    async def connect(self) -> None:  # noqa: D102
        raise NotImplementedError("HttpSseTransport.connect not implemented")

    async def disconnect(self) -> None:  # noqa: D102
        raise NotImplementedError("HttpSseTransport.disconnect not implemented")

    async def call(self, method: str, params: dict[str, Any] | None = None) -> Any:  # noqa: D102
        raise NotImplementedError("HttpSseTransport.call not implemented")

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:  # noqa: D102
        raise NotImplementedError("HttpSseTransport.call_tool not implemented")
