"""High-level MCP client that wraps a transport."""

from __future__ import annotations

from typing import Any

from mcpinspect.protocol.models import ServerManifest, ToolResponse
from mcpinspect.transport.base import MCPTransport


class MCPClient:
    """Fetch manifests and call tools through an MCPTransport."""

    def __init__(self, transport: MCPTransport) -> None:
        self.transport = transport

    async def fetch_manifest(self) -> ServerManifest:
        """Retrieve the full server manifest (tools, resources, prompts)."""
        raise NotImplementedError("MCPClient.fetch_manifest not implemented")

    async def call_tool(self, name: str, args: dict[str, Any] | None = None) -> ToolResponse:
        """Call a single tool and return its response."""
        raise NotImplementedError("MCPClient.call_tool not implemented")
