"""MCI-D05: Schema fields used as instruction channels."""

from __future__ import annotations

from typing import Any

from mcpinspect.checks.base import Check, CheckResult
from mcpinspect.protocol.models import ServerManifest, ToolResponse


class SchemaAbuseCheck(Check):
    """Detect schema fields being repurposed to carry injection payloads."""

    check_id = "MCI-D05"
    title = "Schema fields as instruction channels"

    def run(
        self,
        manifest: ServerManifest | None = None,
        responses: list[ToolResponse] | None = None,
        baseline: ServerManifest | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[CheckResult]:
        raise NotImplementedError(f"{self.check_id}: not implemented")
