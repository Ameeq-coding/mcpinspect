"""ACI-03: --allow-all / over-privileged flags."""

from __future__ import annotations

from mcpinspect.checks.base import Check, CheckResult, Severity
from mcpinspect.protocol.models import ServerManifest, ToolResponse


class PrivilegeCheck(Check):
    """Detect over-privileged flags in MCP server configuration."""

    id = "ACI-03"
    title = "Over-privileged flags (--allow-all etc.)"
    severity = Severity.HIGH

    def run(self, manifest: ServerManifest, responses: list[ToolResponse] | None = None) -> list[CheckResult]:
        raise NotImplementedError(f"{self.id}: not implemented")
