"""Machine-readable JSON output formatter."""

from __future__ import annotations

from pathlib import Path

from mcpinspect.checks.base import CheckResult
from mcpinspect.scanner.scoring import ScanScore


def render_json(
    results: list[CheckResult],
    score: ScanScore,
    output_file: Path | None = None,
) -> str:
    """Render results as JSON, optionally writing to *output_file*."""
    raise NotImplementedError("render_json: not implemented")
