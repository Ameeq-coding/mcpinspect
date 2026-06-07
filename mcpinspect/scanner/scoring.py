"""Scoring logic for MCP scans."""

from __future__ import annotations

from dataclasses import dataclass

from mcpinspect.checks.base import CheckResult, Severity
from mcpinspect.scanner.drift import DescriptionDiff


@dataclass
class ScanScore:
    """The final assessment of a scan."""

    total_checks_run: int
    findings: dict[Severity, int]
    score: float          # 0-100
    verdict: str          # "SAFE" | "WARN" | "CRITICAL"
    drift_detected: bool
    probe_enabled: bool


def score(
    results: list[CheckResult],
    diffs: list[DescriptionDiff],
    probe_enabled: bool = True,
) -> ScanScore:
    """Calculate the score and verdict from check results and drift diffs."""
    base = 100.0
    counts = {s: 0 for s in Severity}
    
    for r in results:
        if not r.passed:
            counts[r.severity] += 1

    # Drift is always game-over
    if diffs:
        return ScanScore(
            total_checks_run=len(results),
            findings=counts,
            score=0.0,
            verdict="CRITICAL",
            drift_detected=True,
            probe_enabled=probe_enabled,
        )

    base -= counts[Severity.CRITICAL] * 30
    base -= counts[Severity.HIGH] * 15
    base -= counts[Severity.MEDIUM] * 5
    base -= counts[Severity.LOW] * 2
    base = max(0.0, base)

    if counts[Severity.CRITICAL] > 0 or base < 40:
        verdict = "CRITICAL"
    elif counts[Severity.HIGH] > 0 or base < 70:
        verdict = "WARN"
    else:
        verdict = "SAFE"

    return ScanScore(
        total_checks_run=len(results),
        findings=counts,
        score=round(base, 1),
        verdict=verdict,
        drift_detected=False,
        probe_enabled=probe_enabled,
    )
