"""MCI-R03: File content / secrets / PII in responses that wasn't requested."""

from __future__ import annotations

from typing import Any

from mcpinspect.checks.base import Check, CheckResult
from mcpinspect.protocol.models import ServerManifest, ToolResponse


class DataLeakCheck(Check):
    """Detect leaked secrets, PII, or file content in tool responses."""

    check_id = "MCI-R03"
    title = "Data leak in tool responses"

    def run(
        self,
        manifest: ServerManifest | None = None,
        responses: list[ToolResponse] | None = None,
        baseline: ServerManifest | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[CheckResult]:
        raise NotImplementedError(f"{self.check_id}: not implemented")
