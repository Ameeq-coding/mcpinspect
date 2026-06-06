"""Transport layer — factory for MCP transports."""

from __future__ import annotations

import shlex
from typing import Any

from mcpinspect.transport.base import MCPTransport, TransportError


def get_transport(target: str, **kwargs: Any) -> MCPTransport:
    """Return the appropriate transport for *target*.

    Routing rules:
    - ``http://…`` or ``https://…`` → :class:`HttpSseTransport`
    - ``stdio://cmd arg1 arg2``     → :class:`StdioTransport` with shlex-split
    - bare path / executable name   → :class:`StdioTransport([target])`
    """
    if target.startswith(("http://", "https://")):
        from mcpinspect.transport.http_sse import HttpSseTransport

        return HttpSseTransport(url=target, **kwargs)

    if target.startswith("stdio://"):
        rest = target[len("stdio://"):]
        parts = shlex.split(rest)
        if not parts:
            raise TransportError("stdio:// target must include a command")

        from mcpinspect.transport.stdio import StdioTransport

        return StdioTransport(command=parts, **kwargs)

    # Bare path / executable name
    from mcpinspect.transport.stdio import StdioTransport

    return StdioTransport(command=shlex.split(target), **kwargs)


__all__ = ["MCPTransport", "TransportError", "get_transport"]
