"""ACI-02: Hardcoded secrets in env configuration."""

from __future__ import annotations

from mcpinspect.checks.base import Check, CheckResult, Severity
from mcpinspect.protocol.models import ServerManifest, ToolResponse


class SecretsCheck(Check):
    """Detect hardcoded secrets in MCP configuration env blocks."""

    id = "ACI-02"
    title = "Hardcoded secrets in env"
    severity = Severity.CRITICAL

    def run(self, manifest: ServerManifest, responses: list[ToolResponse] | None = None) -> list[CheckResult]:
        raise NotImplementedError(f"{self.id}: not implemented")
