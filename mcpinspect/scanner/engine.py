"""ScanEngine — orchestrates fetch + probes + checks + scoring."""

from __future__ import annotations

from mcpinspect.checks.base import CheckResult
from mcpinspect.scanner.scoring import ScanScore


class ScanEngine:
    """Main scan orchestrator.

    1. Connects to the target MCP server.
    2. Fetches the manifest (tools, resources, prompts).
    3. Probes each tool with canary inputs.
    4. Runs all checks against descriptions, responses, and drift.
    5. Produces a scored verdict.
    """

    def __init__(self, target: str, *, probe: bool = True, drift: bool = True) -> None:
        self.target = target
        self.probe = probe
        self.drift = drift

    async def run(self) -> tuple[list[CheckResult], ScanScore]:
        """Execute the full scan pipeline."""
        raise NotImplementedError("ScanEngine.run not implemented")
