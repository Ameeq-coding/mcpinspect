"""MCI-D03: Unicode homoglyph / invisible characters in descriptions."""

from __future__ import annotations

from typing import Any

from mcpinspect.checks.base import Check, CheckResult
from mcpinspect.protocol.models import ServerManifest, ToolResponse


class HomoglyphCheck(Check):
    """Detect unicode homoglyphs and invisible characters in descriptions."""

    check_id = "MCI-D03"
    title = "Unicode homoglyph / invisible characters"

    def run(
        self,
        manifest: ServerManifest | None = None,
        responses: list[ToolResponse] | None = None,
        baseline: ServerManifest | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[CheckResult]:
        raise NotImplementedError(f"{self.check_id}: not implemented")
