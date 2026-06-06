"""Pydantic models for MCP protocol objects."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class MCPTool(BaseModel):
    """An MCP tool definition as returned by ``tools/list``."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)


class MCPResource(BaseModel):
    """An MCP resource definition as returned by ``resources/list``."""

    uri: str
    name: str = ""
    description: str = ""
    mime_type: str = ""


class MCPPrompt(BaseModel):
    """An MCP prompt template as returned by ``prompts/list``."""

    name: str
    description: str = ""
    arguments: list[dict[str, Any]] = Field(default_factory=list)


class ToolResponse(BaseModel):
    """The result of calling a single MCP tool."""

    tool_name: str
    content: list[dict[str, Any]] = Field(default_factory=list)
    is_error: bool = False


class ServerManifest(BaseModel):
    """Aggregate snapshot of everything a server exposes."""

    tools: list[MCPTool] = Field(default_factory=list)
    resources: list[MCPResource] = Field(default_factory=list)
    prompts: list[MCPPrompt] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
