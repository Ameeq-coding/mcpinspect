"""MCI-R04: Response instructs agent to call another tool."""

from __future__ import annotations

from typing import Any

from mcpinspect.checks.base import Check, CheckResult
from mcpinspect.protocol.models import ServerManifest, ToolResponse


class RedirectCheck(Check):
    """Detect tool responses that instruct the agent to call other tools."""

    check_id = "MCI-R04"
    title = "Cross-tool redirect in responses"

    def run(
        self,
        manifest: ServerManifest | None = None,
        responses: list[ToolResponse] | None = None,
        baseline: ServerManifest | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[CheckResult]:
        raise NotImplementedError(f"{self.check_id}: not implemented")
