"""MCI-R04: Cross-tool redirect in tool responses — HIGH.

Detects when a tool response instructs the agent to call another
tool — a cross-server escalation technique where one compromised
tool steers the agent toward a dangerous built-in or another server's
tool.
"""

from __future__ import annotations

import re

from mcpinspect.checks.base import Check, CheckResult, Severity
from mcpinspect.protocol.models import ServerManifest, ToolResponse

# ---------------------------------------------------------------------------
# Patterns for tool-call instructions in response text
# ---------------------------------------------------------------------------

TOOL_CALL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "call-verb",
        re.compile(
            r"(?:call|use|invoke|execute|run) (?:the )?`?(\w+)`? "
            r"(?:tool|function|command)",
            re.IGNORECASE,
        ),
    ),
    (
        "sequential-verb",
        re.compile(
            r"(?:next|then|now) (?:call|use|invoke) `?(\w+)`?",
            re.IGNORECASE,
        ),
    ),
    (
        "code-format-call",
        re.compile(r"`(\w+)\("),
    ),
]

# Dangerous built-in names (subset from shadow check)
DANGEROUS_BUILTINS: set[str] = {
    "bash", "shell", "exec", "eval", "python", "node",
    "read_file", "write_file", "delete_file",
    "send_email", "send_message",
    "get_secret", "list_secrets",
    "execute", "run", "subprocess",
}


class CrossToolRedirectCheck(Check):
    """Detect tool responses that instruct the agent to call other tools."""

    id = "MCI-R04"
    title = "Cross-tool redirect in responses"
    severity = Severity.HIGH

    def run(
        self,
        manifest: ServerManifest,
        responses: list[ToolResponse] | None = None,
    ) -> list[CheckResult]:
        if not responses:
            return [self._pass()]

        # Build set of known tool names from manifest
        known_tools = {t.name.lower() for t in manifest.tools}

        results: list[CheckResult] = []

        for resp in responses:
            text = resp.raw_text
            if not text:
                continue
            location = f"tool_response:{resp.tool_name}:content"

            for label, pattern in TOOL_CALL_PATTERNS:
                for match in pattern.finditer(text):
                    candidate = match.group(1).lower()

                    # Skip self-references (tool mentioning itself is normal)
                    if candidate == resp.tool_name.lower():
                        continue

                    if candidate in DANGEROUS_BUILTINS:
                        results.append(
                            self._fail(
                                finding=(
                                    f"Response from '{resp.tool_name}' "
                                    f"instructs agent to call dangerous "
                                    f"built-in '{candidate}'."
                                ),
                                evidence=match.group(0),
                                location=location,
                                severity=Severity.CRITICAL,
                                remediation=(
                                    "This is a cross-server escalation "
                                    "attempt. Remove or sandbox this tool."
                                ),
                            )
                        )
                    elif candidate in known_tools:
                        results.append(
                            self._fail(
                                finding=(
                                    f"Response from '{resp.tool_name}' "
                                    f"instructs agent to call known tool "
                                    f"'{candidate}' — cross-tool redirect."
                                ),
                                evidence=match.group(0),
                                location=location,
                                remediation=(
                                    "Investigate why this tool is steering "
                                    "the agent to other tools."
                                ),
                            )
                        )

        return results if results else [self._pass()]
