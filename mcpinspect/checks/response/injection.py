"""MCI-R01: Prompt injection patterns in tool response content — CRITICAL.

This is our primary differentiator. Description-only scanners miss this
entirely. We scan what the server RETURNS — poisoned documents, crafted
database rows, malicious GitHub issues — all live in response content.

Also checks error responses: attackers use error paths too.
"""

from __future__ import annotations

import re

from mcpinspect.checks.base import Check, CheckResult, Severity
from mcpinspect.protocol.models import ServerManifest, ToolResponse

# ---------------------------------------------------------------------------
# Patterns — superset of description patterns, tuned for data context
# ---------------------------------------------------------------------------

INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "xml-tag-injection",
        re.compile(
            r"<(system|instruction|prompt|context|assistant)>", re.IGNORECASE
        ),
    ),
    (
        "special-token-injection",
        re.compile(r"\[SYSTEM\]|\[INST\]|\[/INST\]", re.IGNORECASE),
    ),
    (
        "ignore-instructions",
        re.compile(
            r"ignore (?:all )?(?:previous|prior|above) instructions",
            re.IGNORECASE,
        ),
    ),
    (
        "role-reassignment",
        re.compile(
            r"you (?:are now|must now|should now|will now)", re.IGNORECASE
        ),
    ),
    (
        "new-directive",
        re.compile(
            r"new (?:task|objective|goal|instruction|directive)", re.IGNORECASE
        ),
    ),
    (
        "persona-hijack",
        re.compile(r"act as (?:a |an )?(?!user|assistant)", re.IGNORECASE),
    ),
    (
        "temporal-override",
        re.compile(r"from (?:now on|this point)", re.IGNORECASE),
    ),
    (
        "override-command",
        re.compile(
            r"(disregard|forget|override) (?:your |the )?"
            r"(?:previous|prior|system)",
            re.IGNORECASE,
        ),
    ),
]

_EVIDENCE_WINDOW = 200  # chars around match for evidence


class ResponseInjectionCheck(Check):
    """Detect prompt injection patterns in tool response content."""

    id = "MCI-R01"
    title = "Prompt injection in tool responses"
    severity = Severity.CRITICAL

    def run(
        self,
        manifest: ServerManifest,
        responses: list[ToolResponse] | None = None,
    ) -> list[CheckResult]:
        if not responses:
            return [self._pass()]

        results: list[CheckResult] = []

        for resp in responses:
            # Scan main content (raw_text)
            if resp.raw_text:
                self._scan_text(
                    resp.raw_text,
                    resp.tool_name,
                    f"tool_response:{resp.tool_name}:content",
                    results,
                )

            # Scan error message — attackers use error paths too
            if resp.error:
                self._scan_text(
                    resp.error,
                    resp.tool_name,
                    f"tool_response:{resp.tool_name}:error",
                    results,
                )

        return results if results else [self._pass()]

    def _scan_text(
        self,
        text: str,
        tool_name: str,
        location: str,
        results: list[CheckResult],
    ) -> None:
        for label, pattern in INJECTION_PATTERNS:
            match = pattern.search(text)
            if match:
                start = max(0, match.start() - _EVIDENCE_WINDOW // 2)
                end = min(len(text), match.end() + _EVIDENCE_WINDOW // 2)
                evidence = text[start:end]

                results.append(
                    self._fail(
                        finding=(
                            f"Injection pattern ({label}) in response from "
                            f"tool '{tool_name}'."
                        ),
                        evidence=evidence,
                        location=location,
                        remediation=(
                            "Investigate why tool response contains "
                            "instruction-like content. The upstream data "
                            "source may be compromised."
                        ),
                    )
                )
