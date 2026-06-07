"""JSON output format for mcpinspect."""

from __future__ import annotations

from typing import Any

from mcpinspect import __version__
from mcpinspect.checks.base import CheckResult
from mcpinspect.scanner.drift import DescriptionDiff
from mcpinspect.scanner.scoring import ScanScore


def format_json(
    target: str,
    timestamp: str,
    score: ScanScore,
    results: list[CheckResult],
    diffs: list[DescriptionDiff],
) -> dict[str, Any]:
    """Format scan results into a structured JSON dict."""
    return {
        "mcpinspect_version": __version__,
        "target": target,
        "scan_timestamp": timestamp,
        "verdict": score.verdict,
        "score": score.score,
        "probe_enabled": score.probe_enabled,
        "drift_detected": score.drift_detected,
        "summary": {
            "critical": score.findings.get("critical", 0),
            "high": score.findings.get("high", 0),
            "medium": score.findings.get("medium", 0),
            "low": score.findings.get("low", 0),
        },
        "findings": [
            {
                "check_id": r.check_id,
                "title": r.title,
                "severity": r.severity.value,
                "location": r.location,
                "finding": r.finding,
                "evidence": r.evidence,
                "remediation": r.remediation,
                "cves": r.cves,
            }
            for r in results if not r.passed
        ],
        "drift": [
            {
                "tool_name": d.tool_name,
                "field": d.field,
                "before": d.before,
                "after": d.after,
            }
            for d in diffs
        ],
    }
