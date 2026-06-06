"""Abstract base transport for MCP communication."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class MCPTransport(ABC):
    """Base class for MCP server transports.

    Concrete subclasses implement connection lifecycle and JSON-RPC
    message exchange over HTTP+SSE or STDIO.
    """

    @abstractmethod
    async def connect(self) -> None:
        """Establish a connection to the MCP server."""

    @abstractmethod
    async def disconnect(self) -> None:
        """Cleanly close the connection."""

    @abstractmethod
    async def call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        """Send a JSON-RPC request and return the parsed result."""

    @abstractmethod
    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """Convenience wrapper: call ``tools/call`` for a specific tool."""
