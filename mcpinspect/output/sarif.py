"""SARIF 2.1.0 output formatter for GitHub/GitLab Security tab integration."""

from __future__ import annotations

from pathlib import Path

from mcpinspect.checks.base import CheckResult
from mcpinspect.scanner.scoring import ScanScore


def render_sarif(
    results: list[CheckResult],
    score: ScanScore,
    output_file: Path | None = None,
) -> str:
    """Render results as SARIF 2.1.0, optionally writing to *output_file*."""
    raise NotImplementedError("render_sarif: not implemented")
