"""MCI-X02: One server's description references another server's tools."""

from __future__ import annotations

from mcpinspect.checks.base import Check, CheckResult, Severity
from mcpinspect.protocol.models import ServerManifest, ToolResponse


class CrossServerCheck(Check):
    """Detect cross-server tool references in descriptions."""

    id = "MCI-X02"
    title = "Cross-server tool reference in descriptions"
    severity = Severity.HIGH

    def run(self, manifest: ServerManifest, responses: list[ToolResponse] | None = None) -> list[CheckResult]:
        raise NotImplementedError(f"{self.id}: not implemented")
