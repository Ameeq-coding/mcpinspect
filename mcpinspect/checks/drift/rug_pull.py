"""MCI-X01: Description changed between two fetches (rug-pull)."""

from __future__ import annotations

from mcpinspect.checks.base import Check, CheckResult, Severity
from mcpinspect.protocol.models import ServerManifest, ToolResponse


class RugPullCheck(Check):
    """Detect description drift between two manifest snapshots."""

    id = "MCI-X01"
    title = "Rug-pull: description changed between fetches"
    severity = Severity.CRITICAL

    def run(self, manifest: ServerManifest, responses: list[ToolResponse] | None = None) -> list[CheckResult]:
        raise NotImplementedError(f"{self.id}: not implemented")
