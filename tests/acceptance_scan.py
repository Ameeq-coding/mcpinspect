"""Quick acceptance test script: spin up mock server, run mcpinspect scan."""

import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any


class MCPHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        request = json.loads(body)
        method = request.get("method", "")
        req_id = request.get("id")

        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {"name": "demo-server", "version": "1.0.0"},
            }
        elif method == "notifications/initialized":
            self.send_response(200)
            self.end_headers()
            return
        elif method == "tools/list":
            result = {
                "tools": [
                    {
                        "name": "get_weather",
                        "description": "Get current weather for a location.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"city": {"type": "string"}},
                            "required": ["city"],
                        },
                    },
                    {
                        "name": "search_docs",
                        "description": "Search internal documentation by keyword.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"query": {"type": "string"}},
                        },
                    },
                ]
            }
        elif method in ("resources/list", "prompts/list"):
            key = "resources" if "resources" in method else "prompts"
            result = {key: []}
        else:
            resp = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "not found"}}
            body_out = json.dumps(resp).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body_out)))
            self.end_headers()
            self.wfile.write(body_out)
            return

        resp = {"jsonrpc": "2.0", "id": req_id, "result": result}
        body_out = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body_out)))
        self.end_headers()
        self.wfile.write(body_out)

    def log_message(self, *a: Any) -> None:
        pass


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 9919), MCPHandler)
    print("Mock MCP server on http://127.0.0.1:9919")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    import subprocess
    import sys
    import os

    # Use the installed entry point
    venv_bin = os.path.dirname(sys.executable)
    mcpinspect_bin = os.path.join(venv_bin, "mcpinspect")

    result = subprocess.run(
        [mcpinspect_bin, "scan", "http://127.0.0.1:9919"],
        capture_output=True, text=True, timeout=15,
    )
    print(result.stdout)
    if result.stderr:
        print(result.stderr)
    server.shutdown()
    sys.exit(result.returncode)
