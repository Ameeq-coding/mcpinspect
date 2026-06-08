"""End-to-end integration test: spin up a mock MCP server, scan it."""

from __future__ import annotations

import json
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from typing import Any

import pytest

from mcpinspect.transport import get_transport
from mcpinspect.transport.http_sse import HttpSseTransport
from mcpinspect.transport.stdio import StdioTransport
from mcpinspect.transport.base import TransportError
from mcpinspect.protocol.client import MCPClient
from mcpinspect.protocol.models import (
    MCPTool,
    ToolResponse,
    ServerManifest,
)


# ======================================================================
# Minimal MCP JSON-RPC server (stdlib, no dependencies)
# ======================================================================

class _MCPHandler(BaseHTTPRequestHandler):
    """Tiny MCP Streamable HTTP server for testing."""

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        request = json.loads(body)

        method = request.get("method", "")
        req_id = request.get("id")

        # Route
        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {"name": "test-server", "version": "0.0.1"},
            }
        elif method == "notifications/initialized":
            # Notification — no response needed, but respond 200 anyway
            self._respond(200, b"")
            return
        elif method == "tools/list":
            result = {
                "tools": [
                    {
                        "name": "get_weather",
                        "description": "Get current weather for a location.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "city": {"type": "string", "description": "City name"},
                            },
                            "required": ["city"],
                        },
                    },
                    {
                        "name": "run_query",
                        "description": "Run a database query.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "sql": {"type": "string"},
                            },
                        },
                    },
                ]
            }
        elif method == "resources/list":
            result = {
                "resources": [
                    {
                        "uri": "file:///docs/readme.md",
                        "name": "readme",
                        "description": "Project readme",
                    }
                ]
            }
        elif method == "resources/read":
            result = {
                "contents": [
                    {"uri": "file:///docs/readme.md", "text": "# Hello World\nThis is a test."}
                ]
            }
        elif method == "prompts/list":
            result = {
                "prompts": [
                    {"name": "summarize", "description": "Summarize input text"}
                ]
            }
        elif method == "prompts/get":
            result = {
                "messages": [
                    {"role": "user", "content": {"type": "text", "text": "Please summarize: {{input}}"}}
                ]
            }
        elif method == "tools/call":
            params = request.get("params", {})
            tool_name = params.get("name", "")
            if tool_name == "get_weather":
                result = {
                    "content": [
                        {"type": "text", "text": "Sunny, 22°C in London"},
                    ],
                    "isError": False,
                }
            else:
                result = {
                    "content": [{"type": "text", "text": "Unknown tool"}],
                    "isError": True,
                }
        else:
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }
            self._respond_json(response)
            return

        response = {"jsonrpc": "2.0", "id": req_id, "result": result}
        self._respond_json(response)

    def _respond_json(self, data: dict[str, Any]) -> None:
        body = json.dumps(data).encode()
        self._respond(200, body, "application/json")

    def _respond(self, code: int, body: bytes, content_type: str = "text/plain") -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Silence request logs


@pytest.fixture()
def mock_mcp_server():
    """Start a mock MCP server on a random port and return its URL."""
    server = HTTPServer(("127.0.0.1", 0), _MCPHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


# ======================================================================
# Tests
# ======================================================================

class TestTransportFactory:
    """Transport factory routing tests."""

    def test_http_url(self) -> None:
        t = get_transport("https://example.com/mcp")
        assert isinstance(t, HttpSseTransport)
        assert t.transport_type == "http_sse"
        assert t.insecure is False

    def test_http_insecure(self) -> None:
        t = get_transport("http://localhost:8080")
        assert isinstance(t, HttpSseTransport)
        assert t.insecure is True

    def test_stdio_scheme(self) -> None:
        t = get_transport("stdio://python -m server --port 9000")
        assert isinstance(t, StdioTransport)
        assert t.command == ["python", "-m", "server", "--port", "9000"]

    def test_bare_path(self) -> None:
        t = get_transport("/usr/bin/my-server")
        assert isinstance(t, StdioTransport)
        assert t.command == ["/usr/bin/my-server"]


class TestModels:
    """Protocol model tests."""

    def test_tool_description_hash(self) -> None:
        tool = MCPTool(name="t", description="hello")
        assert len(tool.description_hash) == 64

    def test_tool_response_raw_text(self) -> None:
        resp = ToolResponse(
            tool_name="t",
            content=[
                {"type": "text", "text": "A"},
                {"type": "image", "data": "..."},
                {"type": "text", "text": "B"},
            ],
        )
        assert resp.raw_text == "A\nB"

    def test_manifest_defaults(self) -> None:
        m = ServerManifest(target="http://x", transport_type="http_sse")
        assert m.scan_timestamp is not None
        assert m.fetch_duration_ms == 0.0
        assert m.insecure_transport is False


class TestHttpTransportE2E:
    """End-to-end tests with the mock MCP server."""

    @pytest.mark.anyio
    async def test_connect_and_fetch_manifest(self, mock_mcp_server: str) -> None:
        transport = get_transport(mock_mcp_server)
        assert isinstance(transport, HttpSseTransport)

        await transport.connect()
        assert transport.is_connected
        assert transport._server_info["name"] == "test-server"

        client = MCPClient(transport)
        manifest = await client.fetch_manifest()

        # Tools
        assert len(manifest.tools) == 2
        assert manifest.tools[0].name == "get_weather"
        assert manifest.tools[1].name == "run_query"
        assert len(manifest.tools[0].description_hash) == 64

        # Resources
        assert len(manifest.resources) == 1
        assert manifest.resources[0].uri == "file:///docs/readme.md"
        assert manifest.resources[0].raw_content is not None
        assert "Hello World" in manifest.resources[0].raw_content

        # Prompts
        assert len(manifest.prompts) == 1
        assert manifest.prompts[0].name == "summarize"
        assert manifest.prompts[0].template is not None

        # Metadata
        assert manifest.transport_type == "http_sse"
        assert manifest.insecure_transport is True  # http:// not https://
        assert manifest.fetch_duration_ms > 0

        await transport.disconnect()
        assert not transport.is_connected

    @pytest.mark.anyio
    async def test_call_tool(self, mock_mcp_server: str) -> None:
        transport = get_transport(mock_mcp_server)
        await transport.connect()
        client = MCPClient(transport)

        manifest = await client.fetch_manifest()
        weather_tool = manifest.tools[0]

        response = await client.call_tool(weather_tool, {"city": "London"})

        assert response.tool_name == "get_weather"
        assert response.arguments_sent == {"city": "London"}
        assert "22°C" in response.raw_text
        assert response.error is None
        assert response.latency_ms > 0

        # Verify response log on transport
        assert len(transport.response_log) == 1
        name, args, raw_bytes, latency = transport.response_log[0]
        assert name == "get_weather"
        assert args == {"city": "London"}
        assert latency > 0

        await transport.disconnect()

    @pytest.mark.anyio
    async def test_call_tool_error_captured(self, mock_mcp_server: str) -> None:
        """Tool errors should be captured, not raised."""
        transport = get_transport(mock_mcp_server)
        await transport.connect()
        client = MCPClient(transport)

        tool = MCPTool(name="nonexistent", description="does not exist")
        response = await client.call_tool(tool, {})

        # Should NOT raise — error is in the response
        assert response.tool_name == "nonexistent"
        # Response contains isError=True from server
        assert response.error is None or isinstance(response.error, str)

        await transport.disconnect()

    @pytest.mark.anyio
    async def test_connection_failure(self) -> None:
        """Connecting to a dead server should raise TransportError."""
        transport = get_transport("http://127.0.0.1:1")  # port 1 = guaranteed fail
        with pytest.raises(TransportError):
            await transport.connect()
