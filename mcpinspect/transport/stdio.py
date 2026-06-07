"""STDIO transport implementation.

Spawns an MCP server as a subprocess and communicates via
newline-delimited JSON-RPC over stdin/stdout.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import anyio
import anyio.abc

from mcpinspect.transport.base import MCPTransport, TransportError

logger = logging.getLogger(__name__)


class StdioTransport(MCPTransport):
    """Connect to an MCP server over STDIO (subprocess)."""

    transport_type = "stdio"

    def __init__(self, command: list[str]) -> None:
        super().__init__()
        self.command: list[str] = command
        self._process: anyio.abc.Process | None = None
        self._read_buffer: bytes = b""

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Spawn the subprocess and perform the MCP initialize handshake."""
        try:
            self._process = await anyio.open_process(
                self.command,
                stdin=anyio.abc.Process.PIPE if hasattr(anyio.abc.Process, "PIPE") else True,
                stdout=anyio.abc.Process.PIPE if hasattr(anyio.abc.Process, "PIPE") else True,
                stderr=anyio.abc.Process.PIPE if hasattr(anyio.abc.Process, "PIPE") else True,
            )
        except (OSError, FileNotFoundError) as exc:
            raise TransportError(
                f"Failed to spawn {self.command!r}: {exc}"
            )

        # Initialize handshake
        try:
            result = await self.call("initialize", self._init_params())
        except Exception as exc:
            await self._kill_process()
            raise TransportError(
                f"Initialize handshake failed: {exc}"
            )

        self._server_info = result.get("serverInfo", {})

        # Verify protocol version
        proto = result.get("protocolVersion", "")
        if proto and proto < "2024-11-05":
            logger.warning(
                "Server reports old protocol version %s — some features may not work",
                proto,
            )

        # Send initialized notification
        notification = self._build_notification("notifications/initialized")
        await self._write_message(notification)

        self._connected = True
        logger.info(
            "Connected via stdio to %s (server: %s)",
            " ".join(self.command),
            self._server_info.get("name", "unknown"),
        )

    async def disconnect(self) -> None:
        """Hard-kill the subprocess — never leave orphans."""
        self._connected = False
        await self._kill_process()

    # ------------------------------------------------------------------
    # JSON-RPC calls
    # ------------------------------------------------------------------

    async def call(
        self, method: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Write a JSON-RPC request line, read the response line."""
        self._ensure_alive()
        request = self._build_request(method, params)
        req_id = request["id"]

        await self._write_message(request)
        response = await self._read_response(req_id)
        return self._parse_result(response)

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Call ``tools/call``; log raw response bytes and latency."""
        args = arguments or {}
        t0 = time.monotonic()

        result = await self.call("tools/call", {"name": name, "arguments": args})

        latency_ms = (time.monotonic() - t0) * 1000
        raw_bytes = json.dumps(result, ensure_ascii=False).encode("utf-8")
        self._response_log.append((name, args, raw_bytes, latency_ms))

        return result

    # ------------------------------------------------------------------
    # Internal I/O
    # ------------------------------------------------------------------

    async def _write_message(self, msg: dict[str, Any]) -> None:
        """Write a single JSON-RPC message as a newline-delimited line."""
        assert self._process is not None and self._process.stdin is not None
        line = json.dumps(msg, ensure_ascii=False) + "\n"
        try:
            await self._process.stdin.send(line.encode("utf-8"))
        except (anyio.ClosedResourceError, BrokenPipeError) as exc:
            stderr_text = await self._drain_stderr()
            raise TransportError(
                f"Failed to write to server stdin: {exc}\nstderr: {stderr_text}"
            )

    async def _read_response(self, expected_id: int) -> dict[str, Any]:
        """Read lines until we get the JSON-RPC response matching *expected_id*.

        Server may emit notifications between request and response — skip them.
        """
        deadline = time.monotonic() + 30.0  # 30s read timeout
        while time.monotonic() < deadline:
            line = await self._read_line()
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("Non-JSON line from server, skipping: %s", line[:200])
                continue

            # Skip notifications (no "id" field)
            if "id" not in msg:
                continue

            if msg["id"] == expected_id:
                from typing import cast
                return cast(dict[str, Any], msg)

            logger.warning(
                "Unexpected response id %s (wanted %s), skipping",
                msg.get("id"),
                expected_id,
            )

        raise TransportError(
            f"Timed out waiting for response to request {expected_id}"
        )

    async def _read_line(self) -> str:
        """Read a single newline-delimited line from stdout."""
        assert self._process is not None and self._process.stdout is not None

        while b"\n" not in self._read_buffer:
            try:
                chunk = await self._process.stdout.receive(65536)
            except (anyio.ClosedResourceError, anyio.EndOfStream):
                stderr_text = await self._drain_stderr()
                raise TransportError(
                    f"Server process closed stdout unexpectedly\nstderr: {stderr_text}"
                )
            if not chunk:
                stderr_text = await self._drain_stderr()
                raise TransportError(
                    f"Server process exited\nstderr: {stderr_text}"
                )
            self._read_buffer += chunk

        line_bytes, self._read_buffer = self._read_buffer.split(b"\n", 1)
        return line_bytes.decode("utf-8")

    async def _drain_stderr(self) -> str:
        """Read whatever is available on stderr (non-blocking best effort)."""
        if not self._process or not self._process.stderr:
            return ""
        chunks: list[bytes] = []
        try:
            with anyio.fail_after(1.0):
                while True:
                    chunk = await self._process.stderr.receive(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
        except (TimeoutError, anyio.ClosedResourceError, anyio.EndOfStream):
            pass
        return b"".join(chunks).decode("utf-8", errors="replace")

    async def _kill_process(self) -> None:
        """Terminate then kill the subprocess."""
        if not self._process:
            return
        try:
            self._process.terminate()
            with anyio.fail_after(3.0):
                await self._process.wait()
        except (TimeoutError, ProcessLookupError):
            try:
                self._process.kill()
            except ProcessLookupError:
                pass
        finally:
            self._process = None
            self._read_buffer = b""

    def _ensure_alive(self) -> None:
        """Raise if the process is not running."""
        if not self._process:
            raise TransportError("Not connected — no subprocess running")
        if self._process.returncode is not None:
            raise TransportError(
                f"Server process exited with code {self._process.returncode}"
            )
