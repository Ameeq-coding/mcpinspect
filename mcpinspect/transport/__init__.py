"""Transport layer — factory for MCP transports."""

from __future__ import annotations

from mcpinspect.transport.base import MCPTransport


def get_transport(target: str) -> MCPTransport:
    """Return the appropriate transport for *target*.

    - If *target* starts with ``http://`` or ``https://``, use HTTP+SSE.
    - Otherwise treat it as a STDIO command.
    """
    if target.startswith(("http://", "https://")):
        from mcpinspect.transport.http_sse import HttpSseTransport

        return HttpSseTransport(url=target)

    from mcpinspect.transport.stdio import StdioTransport

    return StdioTransport(command=target)


__all__ = ["MCPTransport", "get_transport"]
