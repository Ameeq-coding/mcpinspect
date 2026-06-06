"""ACI-01: Shell metacharacters in command/args."""

from __future__ import annotations

from typing import Any

from mcpinspect.checks.base import Check, CheckResult
from mcpinspect.protocol.models import ServerManifest, ToolResponse


class StdioInjectCheck(Check):
    """Detect shell injection risks in STDIO command configuration."""

    check_id = "ACI-01"
    title = "Shell metacharacters in command/args"

    def run(
        self,
        manifest: ServerManifest | None = None,
        responses: list[ToolResponse] | None = None,
        baseline: ServerManifest | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[CheckResult]:
        raise NotImplementedError(f"{self.check_id}: not implemented")
