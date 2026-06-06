"""Rich-based terminal output formatter."""

from __future__ import annotations

from mcpinspect.checks.base import CheckResult
from mcpinspect.scanner.scoring import ScanScore


def render_terminal(results: list[CheckResult], score: ScanScore) -> None:
    """Print scan results to the terminal using Rich."""
    raise NotImplementedError("render_terminal: not implemented")
