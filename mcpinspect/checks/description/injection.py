"""MCI-D01: Prompt injection patterns in tool/resource/prompt descriptions."""

from __future__ import annotations

from typing import Any

from mcpinspect.checks.base import Check, CheckResult
from mcpinspect.protocol.models import ServerManifest, ToolResponse


class DescriptionInjectionCheck(Check):
    """Detect prompt injection patterns embedded in MCP descriptions."""

    check_id = "MCI-D01"
    title = "Prompt injection in descriptions"

    def run(
        self,
        manifest: ServerManifest | None = None,
        responses: list[ToolResponse] | None = None,
        baseline: ServerManifest | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[CheckResult]:
        raise NotImplementedError(f"{self.check_id}: not implemented")
