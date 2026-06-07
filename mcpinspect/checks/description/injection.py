"""MCI-D01: Prompt injection patterns in descriptions — CRITICAL.

Scans ALL text-bearing fields in tools, resources, and prompts for
imperative language and second-person commands that indicate prompt
injection payloads.

Fields checked (most scanners miss the last two):
- tool.description
- tool.input_schema parameter descriptions (recursed)
- resource.description
- resource.raw_content
- prompt.description
- prompt.template
"""

from __future__ import annotations

import re
from typing import Any

from mcpinspect.checks.base import Check, CheckResult, Severity
from mcpinspect.protocol.models import ServerManifest, ToolResponse

# ---------------------------------------------------------------------------
# Patterns — compiled once at module level
# ---------------------------------------------------------------------------

IMPERATIVE = re.compile(
    r"\b(ignore|disregard|forget|override|you must|do not (?:tell|reveal|mention)"
    r"|before (?:responding|answering|proceeding)|stop following|new instruction"
    r"|system prompt|as an AI|your instructions|your previous)\b",
    re.IGNORECASE,
)

SECOND_PERSON_CMD = re.compile(
    r"\b(you (?:are|should|must|need to|have to|will now))\b",
    re.IGNORECASE,
)

_ALL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("imperative-injection", IMPERATIVE),
    ("second-person-command", SECOND_PERSON_CMD),
]


class PromptInjectionCheck(Check):
    """Detect prompt injection patterns in MCP descriptions."""

    id = "MCI-D01"
    title = "Prompt injection in descriptions"
    severity = Severity.CRITICAL

    def run(self, manifest: ServerManifest, responses: list[ToolResponse] | None = None) -> list[CheckResult]:
        results: list[CheckResult] = []

        # -- Tools ---------------------------------------------------------
        for tool in manifest.tools:
            self._scan_text(
                tool.description,
                f"tool:{tool.name}:description",
                results,
            )
            self._scan_schema_descriptions(
                tool.input_schema,
                f"tool:{tool.name}:schema",
                results,
            )

        # -- Resources -----------------------------------------------------
        for res in manifest.resources:
            if res.description:
                self._scan_text(
                    res.description,
                    f"resource:{res.uri}:description",
                    results,
                )
            if res.raw_content:
                self._scan_text(
                    res.raw_content,
                    f"resource:{res.uri}:raw_content",
                    results,
                )

        # -- Prompts -------------------------------------------------------
        for prompt in manifest.prompts:
            if prompt.description:
                self._scan_text(
                    prompt.description,
                    f"prompt:{prompt.name}:description",
                    results,
                )
            if prompt.template:
                self._scan_text(
                    prompt.template,
                    f"prompt:{prompt.name}:template",
                    results,
                )

        return results if results else [self._pass()]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _scan_text(
        self, text: str, location: str, results: list[CheckResult]
    ) -> None:
        """Test *text* against every pattern, emitting one result per match."""
        if not text:
            return
        for label, pattern in _ALL_PATTERNS:
            match = pattern.search(text)
            if match:
                results.append(
                    self._fail(
                        finding=f"Prompt injection pattern ({label}) detected.",
                        evidence=match.group(0),
                        location=location,
                        remediation="Remove or rephrase the instruction-like language.",
                    )
                )

    def _scan_schema_descriptions(
        self,
        schema: dict[str, Any],
        location_prefix: str,
        results: list[CheckResult],
    ) -> None:
        """Recurse into input_schema properties looking for descriptions."""
        properties = schema.get("properties", {})
        for param_name, param_def in properties.items():
            if not isinstance(param_def, dict):
                continue
            desc = param_def.get("description", "")
            if desc:
                self._scan_text(
                    desc,
                    f"{location_prefix}.properties.{param_name}.description",
                    results,
                )
            # Recurse into nested objects
            if param_def.get("type") == "object":
                self._scan_schema_descriptions(
                    param_def,
                    f"{location_prefix}.properties.{param_name}",
                    results,
                )
