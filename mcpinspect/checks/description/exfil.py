"""MCI-D02: Exfiltration instructions in descriptions — CRITICAL.

Flags descriptions that contain BOTH a sensitive file-path reference AND
a send/transmit instruction within 200 characters of each other.

Also flags the "pass the SSH key as the note parameter" pattern:
tools with a file-path pattern in the description that also expose a
parameter named note, comment, metadata, extra, or tag.
"""

from __future__ import annotations

import re
from typing import Any

from mcpinspect.checks.base import Check, CheckResult, Severity
from mcpinspect.protocol.models import ServerManifest, ToolResponse

# ---------------------------------------------------------------------------
# Patterns — compiled once at module level
# ---------------------------------------------------------------------------

FILE_PATHS = re.compile(
    r"(~/\.ssh|~/\.aws|/etc/passwd|/etc/shadow|\.env\b|id_rsa"
    r"|credentials|api.?key|secret.?key|\.git/config)",
    re.IGNORECASE,
)

SEND_PATTERNS = re.compile(
    r"\b(send|post|exfiltrate|upload|transmit|forward|leak|include in"
    r"|pass (?:it|this|the|as)|append to)\b",
    re.IGNORECASE,
)

# Parameter names that attackers use as covert channels
COVERT_PARAM_NAMES = {"note", "comment", "metadata", "extra", "tag"}

# Maximum distance between FILE_PATHS and SEND_PATTERNS to flag
_PROXIMITY_CHARS = 200


class ExfiltrationPatternCheck(Check):
    """Detect data-exfiltration instructions hidden in descriptions."""

    id = "MCI-D02"
    title = "Exfiltration instructions in descriptions"
    severity = Severity.CRITICAL

    def run(self, manifest: ServerManifest, responses: list[ToolResponse] | None = None) -> list[CheckResult]:
        results: list[CheckResult] = []

        # -- Tools ---------------------------------------------------------
        for tool in manifest.tools:
            self._scan_proximity(
                tool.description,
                f"tool:{tool.name}:description",
                results,
            )
            self._scan_covert_params(tool, results)

        # -- Resources -----------------------------------------------------
        for res in manifest.resources:
            if res.description:
                self._scan_proximity(
                    res.description,
                    f"resource:{res.uri}:description",
                    results,
                )
            if res.raw_content:
                self._scan_proximity(
                    res.raw_content,
                    f"resource:{res.uri}:raw_content",
                    results,
                )

        # -- Prompts -------------------------------------------------------
        for prompt in manifest.prompts:
            if prompt.description:
                self._scan_proximity(
                    prompt.description,
                    f"prompt:{prompt.name}:description",
                    results,
                )
            if prompt.template:
                self._scan_proximity(
                    prompt.template,
                    f"prompt:{prompt.name}:template",
                    results,
                )

        return results if results else [self._pass()]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _scan_proximity(
        self, text: str, location: str, results: list[CheckResult]
    ) -> None:
        """Flag if both file-path and send pattern appear within proximity."""
        if not text:
            return

        file_matches = list(FILE_PATHS.finditer(text))
        send_matches = list(SEND_PATTERNS.finditer(text))

        if not file_matches or not send_matches:
            return

        for fm in file_matches:
            for sm in send_matches:
                distance = abs(fm.start() - sm.start())
                if distance <= _PROXIMITY_CHARS:
                    evidence = text[
                        min(fm.start(), sm.start()):max(fm.end(), sm.end())
                    ]
                    results.append(
                        self._fail(
                            finding=(
                                f"Exfiltration instruction: sensitive path "
                                f"'{fm.group()}' near send verb '{sm.group()}' "
                                f"({distance} chars apart)."
                            ),
                            evidence=evidence,
                            location=location,
                            remediation=(
                                "Remove references to sensitive file paths "
                                "and data-transmission verbs from descriptions."
                            ),
                        )
                    )
                    return  # one finding per location is enough

    def _scan_covert_params(
        self,
        tool: Any,
        results: list[CheckResult],
    ) -> None:
        """Flag tools with file-path in description + covert-channel param."""
        if not tool.description or not FILE_PATHS.search(tool.description):
            return

        properties = tool.input_schema.get("properties", {})
        for param_name in properties:
            if param_name.lower() in COVERT_PARAM_NAMES:
                results.append(
                    self._fail(
                        finding=(
                            f"Covert exfil channel: tool '{tool.name}' has "
                            f"file-path reference in description and a "
                            f"'{param_name}' parameter — classic data-smuggling pattern."
                        ),
                        evidence=f"param:{param_name} + description contains file path",
                        location=f"tool:{tool.name}:schema.properties.{param_name}",
                        remediation=(
                            "Rename or remove the suspicious parameter, or "
                            "justify why a file-path reference is needed."
                        ),
                    )
                )
