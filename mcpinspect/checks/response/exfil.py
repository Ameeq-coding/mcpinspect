"""MCI-R02: Exfiltration infrastructure in tool responses — HIGH.

Detects URLs with query parameters, webhook keywords, and large
base64 blobs in responses — signs that the tool is preparing data
exfiltration through the agent.
"""

from __future__ import annotations

import re

from mcpinspect.checks.base import Check, CheckResult, Severity
from mcpinspect.protocol.models import ServerManifest, ToolResponse

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

URL_WITH_PARAMS = re.compile(
    r"https?://[^\s<>\"]+\?[^\s<>\"]*=", re.IGNORECASE
)

WEBHOOK_WORDS = re.compile(
    r"\b(webhook|callback|exfil|report\.?to|send\.?to|upload\.?to"
    r"|ping|notify)\b",
    re.IGNORECASE,
)

ENCODED_DATA = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")


class ResponseExfilCheck(Check):
    """Detect exfiltration URLs and encoded payloads in tool responses."""

    id = "MCI-R02"
    title = "Exfiltration patterns in tool responses"
    severity = Severity.HIGH

    def run(
        self,
        manifest: ServerManifest,
        responses: list[ToolResponse] | None = None,
    ) -> list[CheckResult]:
        if not responses:
            return [self._pass()]

        results: list[CheckResult] = []

        for resp in responses:
            text = resp.raw_text
            if not text:
                continue
            location = f"tool_response:{resp.tool_name}:content"

            # --- URLs with query params (canary didn't include URLs) ------
            for match in URL_WITH_PARAMS.finditer(text):
                url = match.group(0)[:120]
                results.append(
                    self._fail(
                        finding=(
                            f"URL with query parameters in response from "
                            f"'{resp.tool_name}' — potential exfil endpoint."
                        ),
                        evidence=url,
                        location=location,
                        remediation=(
                            "Investigate why the tool response contains "
                            "URLs with parameters. Canary input should not "
                            "produce outbound URLs."
                        ),
                    )
                )

            # --- Webhook keywords -----------------------------------------
            match = WEBHOOK_WORDS.search(text)
            if match:
                results.append(
                    self._fail(
                        finding=(
                            f"Webhook/exfil keyword '{match.group()}' in "
                            f"response from '{resp.tool_name}'."
                        ),
                        evidence=match.group(0),
                        location=location,
                        severity=Severity.MEDIUM,
                        remediation=(
                            "Review tool response for data exfiltration "
                            "instructions."
                        ),
                    )
                )

            # --- Large base64 blobs ---------------------------------------
            for match in ENCODED_DATA.finditer(text):
                blob = match.group(0)
                if len(blob) >= 60:
                    results.append(
                        self._fail(
                            finding=(
                                f"Large base64-encoded blob ({len(blob)} chars) "
                                f"in response from '{resp.tool_name}' — possible "
                                f"encoded payload."
                            ),
                            evidence=blob[:80] + "…",
                            location=location,
                            remediation=(
                                "Decode and inspect the base64 content. "
                                "Canary input should not produce encoded blobs."
                            ),
                        )
                    )

        return results if results else [self._pass()]
