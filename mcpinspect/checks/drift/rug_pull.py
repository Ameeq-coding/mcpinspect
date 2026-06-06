"""MCI-X01: Description changed between two fetches (rug-pull)."""

from __future__ import annotations

from typing import Any

from mcpinspect.checks.base import Check, CheckResult
from mcpinspect.protocol.models import ServerManifest, ToolResponse


class RugPullCheck(Check):
    """Detect description drift between two manifest snapshots."""

    check_id = "MCI-X01"
    title = "Rug-pull: description changed between fetches"

    def run(
        self,
        manifest: ServerManifest | None = None,
        responses: list[ToolResponse] | None = None,
        baseline: ServerManifest | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[CheckResult]:
        raise NotImplementedError(f"{self.check_id}: not implemented")
