"""MCI-R02: URLs with encoded data / webhook patterns in responses."""

from __future__ import annotations

from typing import Any

from mcpinspect.checks.base import Check, CheckResult
from mcpinspect.protocol.models import ServerManifest, ToolResponse


class ResponseExfilCheck(Check):
    """Detect exfiltration URLs and webhook patterns in tool responses."""

    check_id = "MCI-R02"
    title = "Exfiltration patterns in tool responses"

    def run(
        self,
        manifest: ServerManifest | None = None,
        responses: list[ToolResponse] | None = None,
        baseline: ServerManifest | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[CheckResult]:
        raise NotImplementedError(f"{self.check_id}: not implemented")
