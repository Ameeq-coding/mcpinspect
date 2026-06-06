"""Abstract base transport for MCP communication."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from mcpinspect import __version__


class TransportError(Exception):
    """Raised when a transport-level operation fails."""

    def __init__(self, message: str, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


# JSON-RPC error codes we care about
METHOD_NOT_FOUND = -32601


class MCPTransport(ABC):
    """Base class for MCP server transports.

    Concrete subclasses implement connection lifecycle and JSON-RPC
    message exchange over HTTP+SSE or STDIO.
    """

    transport_type: str = "unknown"

    def __init__(self) -> None:
        self._connected: bool = False
        self._request_id: int = 0
        self._response_log: list[tuple[str, dict[str, Any], bytes, float]] = []
        self._server_info: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_connected(self) -> bool:
        """Whether the transport has an active connection."""
        return self._connected

    @property
    def response_log(self) -> list[tuple[str, dict[str, Any], bytes, float]]:
        """Captured (tool_name, args, raw_bytes, latency_ms) for every call_tool."""
        return list(self._response_log)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _build_request(
        self, method: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Build a JSON-RPC 2.0 request envelope."""
        req: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": method,
        }
        if params is not None:
            req["params"] = params
        return req

    def _build_notification(
        self, method: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Build a JSON-RPC 2.0 notification (no id)."""
        note: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            note["params"] = params
        return note

    @staticmethod
    def _init_params() -> dict[str, Any]:
        """Parameters for the MCP ``initialize`` handshake."""
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcpinspect", "version": __version__},
        }

    @staticmethod
    def _parse_result(data: dict[str, Any]) -> dict[str, Any]:
        """Extract result from a JSON-RPC response, raising on error."""
        if "error" in data:
            err = data["error"]
            raise TransportError(
                f"JSON-RPC error {err.get('code', '?')}: {err.get('message', 'unknown')}",
                code=err.get("code"),
            )
        return data.get("result", {})

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    async def connect(self) -> None:
        """Establish a connection and perform the MCP initialize handshake."""

    @abstractmethod
    async def disconnect(self) -> None:
        """Cleanly close the connection."""

    @abstractmethod
    async def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send a JSON-RPC request and return the parsed result dict."""

    @abstractmethod
    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Call ``tools/call`` for a specific tool; log raw response."""
