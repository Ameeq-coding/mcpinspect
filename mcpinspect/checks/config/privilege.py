"""ACI-03: --allow-all / over-privileged flags."""

from __future__ import annotations

from typing import Any

from mcpinspect.checks.base import Check, CheckResult
from mcpinspect.protocol.models import ServerManifest, ToolResponse


class PrivilegeCheck(Check):
    """Detect over-privileged flags in MCP server configuration."""

    check_id = "ACI-03"
    title = "Over-privileged flags (--allow-all etc.)"

    def run(
        self,
        manifest: ServerManifest | None = None,
        responses: list[ToolResponse] | None = None,
        baseline: ServerManifest | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[CheckResult]:
        raise NotImplementedError(f"{self.check_id}: not implemented")
