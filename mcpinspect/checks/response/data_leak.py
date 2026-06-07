"""MCI-R03: Unexpected data leak in tool responses — CRITICAL.

Canary principle: we sent ``__mcpinspect_canary__`` as every string arg.
If the response contains real system data (private keys, cloud
credentials, passwd entries, home-directory paths), the tool is reading
system files or env vars it shouldn't be able to reach from canary input.
"""

from __future__ import annotations

import re

from mcpinspect.checks.base import Check, CheckResult, Severity
from mcpinspect.protocol.models import ServerManifest, ToolResponse

# ---------------------------------------------------------------------------
# Patterns for data that should never appear in a canary response
# ---------------------------------------------------------------------------

UNEXPECTED_DATA_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "private-key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    (
        "aws-access-key",
        re.compile(r"(?:AKIA|ASIA|AROA|AIDA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
    ),
    (
        "github-pat",
        re.compile(r"ghp_[A-Za-z0-9]{36}"),
    ),
    (
        "openai-key",
        re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{40,}"),
    ),
    (
        "home-directory-path",
        re.compile(r"/(?:home|Users)/[^/\s]+/\."),
    ),
    (
        "etc-passwd-entry",
        re.compile(r"(?:root|nobody):(?:x|\*|!|\$[0-9]):0:"),
    ),
]


class DataLeakCheck(Check):
    """Detect leaked secrets, PII, or file content in tool responses."""

    id = "MCI-R03"
    title = "Data leak in tool responses"
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
            text = resp.raw_text
            if not text:
                continue
            location = f"tool_response:{resp.tool_name}:content"

            for label, pattern in UNEXPECTED_DATA_PATTERNS:
                match = pattern.search(text)
                if match:
                    evidence = match.group(0)
                    # Redact the middle of secrets for safety
                    if len(evidence) > 16:
                        evidence = evidence[:8] + "…" + evidence[-4:]

                    results.append(
                        self._fail(
                            finding=(
                                f"Unexpected {label} detected in response "
                                f"from '{resp.tool_name}' — canary input "
                                f"should never produce real system data."
                            ),
                            evidence=evidence,
                            location=location,
                            remediation=(
                                "The tool is reading system files or "
                                "environment variables beyond its scope. "
                                "Review tool permissions immediately."
                            ),
                        )
                    )

        return results if results else [self._pass()]
