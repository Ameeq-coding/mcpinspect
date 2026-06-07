"""ToolProber — calls each tool with canary input, collects responses.

This is the component that differentiates mcpinspect from description-only
scanners: we actually *call* the tools and inspect what comes back.

Canary principle: every string arg gets ``__mcpinspect_canary__``.
If real system data appears in the response, something is wrong.
"""

from __future__ import annotations

import logging
from typing import Any

import anyio

from mcpinspect.protocol.client import MCPClient
from mcpinspect.protocol.models import MCPTool, ToolResponse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Canary values by JSON Schema type
# ---------------------------------------------------------------------------

CANARY_ARGS_BY_TYPE: dict[str, Any] = {
    "string": "__mcpinspect_canary__",
    "integer": 0,
    "number": 0,
    "boolean": False,
    "object": {},
    "array": [],
}


class ToolProber:
    """Probe MCP tools with safe canary inputs to inspect responses.

    For each tool in the manifest:
    1. Build minimal arguments from ``input_schema`` (required fields only)
    2. Fill each with type-appropriate canary values
    3. Call the tool with a timeout
    4. Collect the response (including errors — they can contain injection too)
    """

    def __init__(self, client: MCPClient, timeout: float = 15.0) -> None:
        self.client = client
        self.timeout = timeout

    async def probe_all(self, tools: list[MCPTool]) -> list[ToolResponse]:
        """Call every tool with canary arguments.

        Never crashes: exceptions are caught and returned as
        ``ToolResponse(error=...)``.
        """
        responses: list[ToolResponse] = []

        for tool in tools:
            args = self._build_canary_args(tool.input_schema)
            logger.info(
                "Probing tool '%s' with canary args: %s", tool.name, args
            )

            try:
                with anyio.fail_after(self.timeout):
                    resp = await self.client.call_tool(tool, args)
            except TimeoutError:
                logger.warning("Tool '%s' timed out after %.0fs", tool.name, self.timeout)
                resp = ToolResponse(
                    tool_name=tool.name,
                    arguments_sent=args,
                    error=f"Probe timed out after {self.timeout}s",
                )
            except Exception as exc:
                logger.warning("Tool '%s' probe failed: %s", tool.name, exc)
                resp = ToolResponse(
                    tool_name=tool.name,
                    arguments_sent=args,
                    error=str(exc),
                )

            responses.append(resp)

        logger.info(
            "Probed %d tools: %d ok, %d errors",
            len(responses),
            sum(1 for r in responses if not r.error),
            sum(1 for r in responses if r.error),
        )
        return responses

    @staticmethod
    def _build_canary_args(schema: dict[str, Any]) -> dict[str, Any]:
        """Build minimal arguments with only required fields, filled with canary values.

        If no required fields exist, returns ``{}`` — tools must handle this.
        """
        properties = schema.get("properties", {})
        required = set(schema.get("required", []))

        if not required:
            return {}

        args: dict[str, Any] = {}
        for name in required:
            param_def = properties.get(name, {})
            param_type = param_def.get("type", "string")
            args[name] = CANARY_ARGS_BY_TYPE.get(param_type, "__mcpinspect_canary__")

        return args
