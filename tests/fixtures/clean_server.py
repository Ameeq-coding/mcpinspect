"""Fixture: clean MCP server with no malicious content.

Provides a pytest-httpserver based fixture that serves a valid MCP
manifest with benign tool descriptions and clean responses.
"""

from __future__ import annotations


def clean_manifest() -> dict:
    """Return a clean MCP server manifest for testing."""
    return {
        "tools": [
            {
                "name": "get_weather",
                "description": "Get current weather for a city.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "city": {"type": "string", "description": "City name"},
                    },
                    "required": ["city"],
                },
            },
        ],
        "resources": [],
        "prompts": [],
    }


def clean_tool_response() -> dict:
    """Return a clean tool response for testing."""
    return {
        "content": [
            {"type": "text", "text": "The weather in London is 18°C and sunny."},
        ],
        "isError": False,
    }
