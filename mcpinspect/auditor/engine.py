"""AuditEngine — static config analysis, no network required."""

from __future__ import annotations

from pathlib import Path

from mcpinspect.checks.base import CheckResult
from mcpinspect.scanner.scoring import ScanScore


class AuditEngine:
    """Static analysis engine for MCP config files.

    Parses the config and runs config-category checks (ACI-01 through ACI-03)
    without ever touching the network.
    """

    def __init__(self, config_path: Path) -> None:
        self.config_path = config_path

    def run(self) -> tuple[list[CheckResult], ScanScore]:
        """Parse the config and run all config checks."""
        raise NotImplementedError("AuditEngine.run not implemented")
