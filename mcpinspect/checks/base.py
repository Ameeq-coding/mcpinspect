"""Check base classes, severity enum, and result dataclass."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum

from mcpinspect.protocol.models import ServerManifest, ToolResponse


class Severity(str, Enum):
    """Finding severity levels (ordered highest → lowest)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class CheckResult:
    """A single finding produced by a check.

    One result per violation per location — never aggregate.
    The security analyst needs to know exactly where each one is.
    """

    check_id: str
    title: str
    severity: Severity
    passed: bool
    finding: str        # one sentence, human-readable
    evidence: str       # the exact text that triggered this
    location: str       # e.g. "tool:get_weather:description"
    cves: list[str] = field(default_factory=list)
    remediation: str = ""  # one sentence: what to do


class Check(ABC):
    """Abstract base for all security checks.

    Subclasses set ``id``, ``title``, ``severity`` as class attributes
    and implement ``run()`` to return a list of findings.

    Description checks use *manifest*; response checks use *responses*.
    """

    id: str = ""
    title: str = ""
    severity: Severity = Severity.MEDIUM

    @abstractmethod
    def run(
        self,
        manifest: ServerManifest,
        responses: list[ToolResponse] | None = None,
    ) -> list[CheckResult]:
        """Execute the check and return findings."""

    # ------------------------------------------------------------------
    # Convenience helpers for subclasses
    # ------------------------------------------------------------------

    def _pass(self) -> CheckResult:
        """Return a single passing result (no violations found)."""
        return CheckResult(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            passed=True,
            finding="No issues found.",
            evidence="",
            location="",
        )

    def _fail(
        self,
        finding: str,
        evidence: str,
        location: str,
        *,
        severity: Severity | None = None,
        remediation: str = "",
        cves: list[str] | None = None,
    ) -> CheckResult:
        """Return a failing result for a specific location."""
        return CheckResult(
            check_id=self.id,
            title=self.title,
            severity=severity or self.severity,
            passed=False,
            finding=finding,
            evidence=evidence,
            location=location,
            remediation=remediation,
            cves=cves or [],
        )
