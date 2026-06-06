"""Parse MCP config files (mcp.json, claude_desktop_config, cursor configs)."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def parse_config(path: Path) -> dict[str, Any]:
    """Parse an MCP configuration file and return structured data.

    Supports:
    - mcp.json
    - claude_desktop_config.json
    - cursor MCP configs
    """
    raise NotImplementedError("parse_config: not implemented")
