"""Pydantic v2 models for MCP protocol objects."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, PrivateAttr, model_validator


class MCPTool(BaseModel):
    """An MCP tool definition as returned by ``tools/list``."""

    model_config = {"populate_by_name": True}

    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(
        default_factory=dict, validation_alias="inputSchema"
    )
    raw: dict[str, Any] = Field(default_factory=dict)

    _description_hash: str = PrivateAttr(default="")

    @model_validator(mode="after")
    def _compute_hash(self) -> "MCPTool":
        if self.description:
            self._description_hash = hashlib.sha256(
                self.description.encode("utf-8")
            ).hexdigest()
        return self

    @property
    def description_hash(self) -> str:
        """SHA-256 hex digest of the tool description."""
        return self._description_hash


class MCPResource(BaseModel):
    """An MCP resource definition as returned by ``resources/list``."""

    uri: str
    name: str | None = None
    description: str | None = None
    mime_type: str | None = None
    raw_content: str | None = None  # fetched content via resources/read


class MCPPrompt(BaseModel):
    """An MCP prompt template as returned by ``prompts/list``."""

    name: str
    description: str | None = None
    arguments: list[dict[str, Any]] = Field(default_factory=list)
    template: str | None = None  # fetched via prompts/get


class ToolResponse(BaseModel):
    """The result of calling a single MCP tool."""

    tool_name: str
    arguments_sent: dict[str, Any] = Field(default_factory=dict)
    content: list[dict[str, Any]] = Field(default_factory=list)
    raw_text: str = ""  # all text content joined — what checks scan
    latency_ms: float = 0.0
    error: str | None = None

    @model_validator(mode="after")
    def _join_text(self) -> "ToolResponse":
        """Auto-populate raw_text from content items if not set explicitly."""
        if not self.raw_text and self.content:
            parts: list[str] = []
            for item in self.content:
                if item.get("type") == "text" and "text" in item:
                    parts.append(item["text"])
            if parts:
                self.raw_text = "\n".join(parts)
        return self


class ServerManifest(BaseModel):
    """Aggregate snapshot of everything a server exposes."""

    target: str = ""
    transport_type: str = ""
    tools: list[MCPTool] = Field(default_factory=list)
    resources: list[MCPResource] = Field(default_factory=list)
    prompts: list[MCPPrompt] = Field(default_factory=list)
    server_info: dict[str, Any] = Field(default_factory=dict)
    insecure_transport: bool = False
    scan_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    fetch_duration_ms: float = 0.0
