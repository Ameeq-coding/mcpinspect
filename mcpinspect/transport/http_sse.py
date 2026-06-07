"""HTTP + SSE transport implementation.

Supports both MCP Streamable HTTP (POST → JSON) and legacy SSE transports.
Uses httpx for HTTP and manual SSE parsing for streaming responses.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any
from urllib.parse import urljoin

import httpx

from mcpinspect.transport.base import MCPTransport, TransportError

logger = logging.getLogger(__name__)


class HttpSseTransport(MCPTransport):
    """Connect to an MCP server over HTTP (Streamable HTTP / SSE)."""

    transport_type = "http_sse"

    def __init__(self, url: str, headers: dict[str, str] | None = None) -> None:
        super().__init__()
        self.url: str = url.rstrip("/")
        self.insecure: bool = url.startswith("http://")
        self._client: httpx.AsyncClient | None = None
        self._post_url: str = self.url
        self._session_id: str | None = None
        self._custom_headers = headers or {}

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Connect and perform the MCP initialize handshake.

        Strategy:
        1. Try Streamable HTTP (POST directly) — the current standard.
        2. If that gets 405/404, attempt SSE endpoint discovery then POST.
        """
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0),
            follow_redirects=True,
        )

        # --- attempt streamable HTTP first --------------------------------
        try:
            await self._initialize_handshake()
            return
        except TransportError:
            raise
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code not in (404, 405):
                raise TransportError(
                    f"HTTP {exc.response.status_code} during initialize: {exc}"
                )
        except httpx.ConnectError as exc:
            raise TransportError(f"Cannot connect to {self.url}: {exc}")

        # --- fall back to SSE endpoint discovery --------------------------
        try:
            await self._discover_sse_endpoint()
            await self._initialize_handshake()
        except Exception as exc:
            raise TransportError(f"Failed to connect to {self.url}: {exc}")

    async def disconnect(self) -> None:
        """Close the HTTP client."""
        self._connected = False
        if self._client:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # JSON-RPC calls
    # ------------------------------------------------------------------

    async def call(
        self, method: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """POST a JSON-RPC request; retry once on connection reset."""
        if not self._client:
            raise TransportError("Not connected")

        request = self._build_request(method, params)
        headers = self._request_headers()

        try:
            raw = await self._post_jsonrpc(request, headers)
        except (httpx.RemoteProtocolError, httpx.ReadError, ConnectionResetError):
            logger.debug("Connection reset on %s — retrying once", method)
            raw = await self._post_jsonrpc(request, headers)

        return self._parse_result(raw)

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Call ``tools/call``, log raw response bytes and latency."""
        args = arguments or {}
        t0 = time.monotonic()

        result = await self.call("tools/call", {"name": name, "arguments": args})

        latency_ms = (time.monotonic() - t0) * 1000
        raw_bytes = json.dumps(result, ensure_ascii=False).encode("utf-8")
        self._response_log.append((name, args, raw_bytes, latency_ms))

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _request_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        headers.update(self._custom_headers)
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        return headers

    async def _post_jsonrpc(
        self, request: dict[str, Any], headers: dict[str, str]
    ) -> dict[str, Any]:
        """POST a JSON-RPC envelope and return the parsed response."""
        assert self._client is not None

        response = await self._client.post(
            self._post_url, json=request, headers=headers
        )
        response.raise_for_status()

        # Capture session id from server
        sid = response.headers.get("mcp-session-id")
        if sid:
            self._session_id = sid

        content_type = response.headers.get("content-type", "")

        if "text/event-stream" in content_type:
            return self._extract_sse_result(response.text, request["id"])

        from typing import cast
        return cast(dict[str, Any], response.json())

    async def _initialize_handshake(self) -> dict[str, Any]:
        """Send ``initialize`` + ``notifications/initialized``."""
        result = await self.call("initialize", self._init_params())
        self._server_info = result.get("serverInfo", {})

        # Send the initialized notification (fire-and-forget POST, no id)
        notification = self._build_notification("notifications/initialized")
        assert self._client is not None
        try:
            await self._client.post(
                self._post_url,
                json=notification,
                headers=self._request_headers(),
            )
        except httpx.HTTPError:
            logger.debug("Server ignored initialized notification (non-fatal)")

        self._connected = True
        logger.info(
            "Connected to %s (server: %s)",
            self.url,
            self._server_info.get("name", "unknown"),
        )
        return result

    async def _discover_sse_endpoint(self) -> None:
        """Legacy SSE discovery: GET the server URL, read the ``endpoint`` event."""
        assert self._client is not None

        sse_timeout = httpx.Timeout(connect=10.0, read=15.0, write=10.0, pool=10.0)
        async with self._client.stream(
            "GET",
            self.url,
            headers={"Accept": "text/event-stream"},
            timeout=sse_timeout,
        ) as response:
            response.raise_for_status()
            event_type = ""
            async for line in response.aiter_lines():
                stripped = line.strip()
                if not stripped:
                    event_type = ""
                    continue
                if stripped.startswith("event:"):
                    event_type = stripped[6:].strip()
                elif stripped.startswith("data:") and event_type == "endpoint":
                    endpoint = stripped[5:].strip()
                    if endpoint.startswith(("http://", "https://")):
                        self._post_url = endpoint
                    else:
                        self._post_url = urljoin(self.url + "/", endpoint)
                    logger.info("SSE discovered POST endpoint: %s", self._post_url)
                    return

        raise TransportError("SSE stream closed without sending an endpoint event")

    @staticmethod
    def _extract_sse_result(text: str, request_id: int) -> dict[str, Any]:
        """Parse SSE text body and find the JSON-RPC response for *request_id*."""
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("data:"):
                payload = stripped[5:].strip()
                if not payload:
                    continue
                try:
                    msg = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                if isinstance(msg, dict) and msg.get("id") == request_id:
                    return msg
        raise TransportError(
            f"SSE response did not contain a message for request id {request_id}"
        )
