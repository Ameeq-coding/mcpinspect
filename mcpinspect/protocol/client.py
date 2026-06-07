"""High-level MCP client that wraps a transport.

Handles manifest fetching (with cursor pagination), resource reading,
prompt fetching, and tool calling — all with robust error handling so
a partial manifest is always returned rather than crashing.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

from mcpinspect.protocol.models import (
    MCPPrompt,
    MCPResource,
    MCPTool,
    ServerManifest,
    ToolResponse,
)
from mcpinspect.transport.base import MCPTransport, TransportError, METHOD_NOT_FOUND

logger = logging.getLogger(__name__)


class MCPClient:
    """Fetch manifests and call tools through an MCPTransport."""

    def __init__(self, transport: MCPTransport) -> None:
        self.transport = transport

    # ------------------------------------------------------------------
    # Manifest fetching
    # ------------------------------------------------------------------

    async def fetch_manifest(self) -> ServerManifest:
        """Retrieve the full server manifest.

        Steps:
        1. ``tools/list`` with cursor pagination until done
        2. ``resources/list`` with pagination (skip if method-not-found)
        3. ``prompts/list`` with pagination (skip if unsupported)
        4. For each resource, attempt ``resources/read`` for raw_content
        5. For each prompt, attempt ``prompts/get`` for template

        Every sub-call is individually wrapped — a partial manifest is
        always better than a crash.
        """
        t0 = time.monotonic()
        ts = datetime.now(timezone.utc)

        tools = await self._list_tools()
        resources = await self._list_resources()
        prompts = await self._list_prompts()

        # Enrich resources with content
        for res in resources:
            await self._read_resource(res)

        # Enrich prompts with templates
        for prompt in prompts:
            await self._get_prompt(prompt)

        fetch_ms = (time.monotonic() - t0) * 1000

        # Detect insecure transport
        insecure = getattr(self.transport, "insecure", False)

        return ServerManifest(
            target=self._target_label(),
            transport_type=self.transport.transport_type,
            tools=tools,
            resources=resources,
            prompts=prompts,
            server_info=self.transport._server_info,
            insecure_transport=insecure,
            scan_timestamp=ts,
            fetch_duration_ms=round(fetch_ms, 2),
        )

    # ------------------------------------------------------------------
    # Tool calling
    # ------------------------------------------------------------------

    async def call_tool(
        self, tool: MCPTool, arguments: dict[str, Any] | None = None
    ) -> ToolResponse:
        """Call a single tool, returning a ToolResponse.

        Never raises — errors are captured in the ToolResponse.error field.
        """
        args = arguments or {}
        t0 = time.monotonic()
        try:
            result = await self.transport.call_tool(tool.name, args)
            latency_ms = (time.monotonic() - t0) * 1000
            content = result.get("content", [])
            is_err = result.get("isError", False)

            return ToolResponse(
                tool_name=tool.name,
                arguments_sent=args,
                content=content,
                latency_ms=round(latency_ms, 2),
                error=str(result.get("error", "")) if is_err else None,
            )
        except Exception as exc:
            latency_ms = (time.monotonic() - t0) * 1000
            logger.warning("Tool call %s failed: %s", tool.name, exc)
            return ToolResponse(
                tool_name=tool.name,
                arguments_sent=args,
                latency_ms=round(latency_ms, 2),
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Paginated listing helpers
    # ------------------------------------------------------------------

    async def _list_tools(self) -> list[MCPTool]:
        """Fetch all tools with cursor pagination."""
        return await self._paginated_list(
            "tools/list", "tools", MCPTool
        )

    async def _list_resources(self) -> list[MCPResource]:
        """Fetch all resources, returning [] if unsupported."""
        return await self._paginated_list(
            "resources/list", "resources", MCPResource
        )

    async def _list_prompts(self) -> list[MCPPrompt]:
        """Fetch all prompts, returning [] if unsupported."""
        return await self._paginated_list(
            "prompts/list", "prompts", MCPPrompt
        )

    async def _paginated_list(
        self,
        method: str,
        key: str,
        model_cls: type,
        max_pages: int = 50,
    ) -> list[Any]:
        """Generic paginated listing for any MCP list method."""
        items: list[Any] = []
        cursor: str | None = None

        for _ in range(max_pages):
            params: dict[str, Any] = {}
            if cursor:
                params["cursor"] = cursor

            try:
                result = await self.transport.call(method, params or None)
            except TransportError as exc:
                if exc.code == METHOD_NOT_FOUND:
                    logger.debug("%s not supported by server (method-not-found)", method)
                    return []
                logger.warning("Error calling %s: %s", method, exc)
                break

            raw_items = result.get(key, [])
            for raw in raw_items:
                try:
                    items.append(model_cls(**raw))
                except Exception as exc:
                    logger.warning("Failed to parse %s item: %s", key, exc)

            next_cursor = result.get("nextCursor")
            if not next_cursor:
                break
            cursor = next_cursor

        logger.info("Fetched %d %s", len(items), key)
        return items

    # ------------------------------------------------------------------
    # Resource / prompt enrichment
    # ------------------------------------------------------------------

    async def _read_resource(self, resource: MCPResource) -> None:
        """Attempt ``resources/read`` to fill in raw_content."""
        try:
            result = await self.transport.call(
                "resources/read", {"uri": resource.uri}
            )
            contents = result.get("contents", [])
            if contents:
                # Join all text content items
                text_parts = [
                    c.get("text", "") for c in contents if "text" in c
                ]
                if text_parts:
                    resource.raw_content = "\n".join(text_parts)
        except TransportError as exc:
            if exc.code == METHOD_NOT_FOUND:
                return
            logger.debug("resources/read failed for %s: %s", resource.uri, exc)
        except Exception as exc:
            logger.debug("resources/read failed for %s: %s", resource.uri, exc)

    async def _get_prompt(self, prompt: MCPPrompt) -> None:
        """Attempt ``prompts/get`` to fill in the template."""
        try:
            result = await self.transport.call(
                "prompts/get", {"name": prompt.name}
            )
            messages = result.get("messages", [])
            if messages:
                text_parts = []
                for msg in messages:
                    content = msg.get("content", {})
                    if isinstance(content, dict) and content.get("type") == "text":
                        text_parts.append(content.get("text", ""))
                    elif isinstance(content, str):
                        text_parts.append(content)
                if text_parts:
                    prompt.template = "\n".join(text_parts)
        except TransportError as exc:
            if exc.code == METHOD_NOT_FOUND:
                return
            logger.debug("prompts/get failed for %s: %s", prompt.name, exc)
        except Exception as exc:
            logger.debug("prompts/get failed for %s: %s", prompt.name, exc)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _target_label(self) -> str:
        """Derive a human-readable target label."""
        transport = self.transport
        if hasattr(transport, "url"):
            return str(getattr(transport, "url"))
        if hasattr(transport, "command"):
            return " ".join(getattr(transport, "command"))
        return "unknown"
