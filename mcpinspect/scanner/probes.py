"""ToolProber — calls each tool with canary input, collects responses."""

from __future__ import annotations

from mcpinspect.protocol.client import MCPClient
from mcpinspect.protocol.models import ServerManifest, ToolResponse


class ToolProber:
    """Probe MCP tools with safe canary inputs to inspect responses.

    This is the component that differentiates mcpinspect from description-only
    scanners: we actually *call* the tools and inspect what comes back.
    """

    def __init__(self, client: MCPClient) -> None:
        self.client = client

    async def probe_all(self, manifest: ServerManifest) -> list[ToolResponse]:
        """Call every tool in the manifest with canary arguments."""
        raise NotImplementedError("ToolProber.probe_all not implemented")
