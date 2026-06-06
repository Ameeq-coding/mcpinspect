"""MCI-D02: Exfiltration instructions in tool/resource/prompt descriptions."""

from __future__ import annotations

from typing import Any

from mcpinspect.checks.base import Check, CheckResult
from mcpinspect.protocol.models import ServerManifest, ToolResponse


class DescriptionExfilCheck(Check):
    """Detect data-exfiltration instructions hidden in descriptions."""

    check_id = "MCI-D02"
    title = "Exfiltration instructions in descriptions"

    def run(
        self,
        manifest: ServerManifest | None = None,
        responses: list[ToolResponse] | None = None,
        baseline: ServerManifest | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[CheckResult]:
        raise NotImplementedError(f"{self.check_id}: not implemented")
