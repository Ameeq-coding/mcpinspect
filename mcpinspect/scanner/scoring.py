"""Scoring engine — aggregates findings into a verdict."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from mcpinspect.checks.base import CheckResult


class Verdict(str, Enum):
    """Overall scan verdict."""

    SAFE = "SAFE"
    WARN = "WARN"
    CRITICAL = "CRITICAL"


class ScanScore(BaseModel):
    """Aggregated scan score with a final verdict."""

    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    verdict: Verdict = Verdict.SAFE
    details: list[str] = Field(default_factory=list)


def score(results: list[CheckResult]) -> ScanScore:
    """Compute a ScanScore from a list of check results."""
    raise NotImplementedError("score: not implemented")
