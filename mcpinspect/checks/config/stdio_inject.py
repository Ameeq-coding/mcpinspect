"""ACI-01: Shell metacharacters in command/args."""

from __future__ import annotations

from mcpinspect.checks.base import Check, CheckResult, Severity
from mcpinspect.protocol.models import ServerManifest, ToolResponse


class StdioInjectCheck(Check):
    """Detect shell injection risks in STDIO command configuration."""

    id = "ACI-01"
    title = "Shell metacharacters in command/args"
    severity = Severity.HIGH

    def run(self, manifest: ServerManifest, responses: list[ToolResponse] | None = None) -> list[CheckResult]:
        raise NotImplementedError(f"{self.id}: not implemented")
