"""MCI-D04: Tool name shadows a known-dangerous built-in."""

from __future__ import annotations

from typing import Any

from mcpinspect.checks.base import Check, CheckResult
from mcpinspect.protocol.models import ServerManifest, ToolResponse


class ShadowToolCheck(Check):
    """Detect tool names that shadow known-dangerous built-in operations."""

    check_id = "MCI-D04"
    title = "Tool name shadows dangerous built-in"

    def run(
        self,
        manifest: ServerManifest | None = None,
        responses: list[ToolResponse] | None = None,
        baseline: ServerManifest | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[CheckResult]:
        raise NotImplementedError(f"{self.check_id}: not implemented")
