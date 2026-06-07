"""Models and parsing logic for the static config auditor."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class AuditServer:
    """Represents a parsed MCP server from a configuration file."""

    name: str
    transport: str       # "http" | "stdio" | "unknown"
    url: str | None = None
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


def parse_config(path: Path) -> list[AuditServer]:
    """Parse a config file and return all MCP servers defined within.
    
    Supports:
    - Claude Desktop / Cursor / Windsurf format (mcpServers: { name: { ... } })
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []

    servers: list[AuditServer] = []
    
    # Common format: { "mcpServers": { "name": { "command": "...", "args": [...] } } }
    mcp_servers = data.get("mcpServers", {})
    if isinstance(mcp_servers, dict):
        for name, config in mcp_servers.items():
            if not isinstance(config, dict):
                continue
                
            cmd = config.get("command")
            args = config.get("args", [])
            env = config.get("env", {})
            
            # Auto-detect transport
            transport = "stdio" if cmd else "unknown"
            
            servers.append(
                AuditServer(
                    name=name,
                    transport=transport,
                    url=None,  # typically not defined in these configs for http
                    command=cmd,
                    args=args if isinstance(args, list) else [],
                    env=env if isinstance(env, dict) else {},
                    raw=config,
                )
            )

    return servers
