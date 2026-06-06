"""DriftDetector — two-pass manifest comparison for rug-pull detection."""

from __future__ import annotations

from mcpinspect.checks.base import CheckResult
from mcpinspect.protocol.models import ServerManifest


class DriftDetector:
    """Compare two manifest fetches to detect post-deployment changes.

    A rug-pull attack works by serving clean descriptions during review
    and swapping in malicious descriptions after deployment. Two fetches
    separated by time can detect this.
    """

    def compare(self, baseline: ServerManifest, current: ServerManifest) -> list[CheckResult]:
        """Return findings for any descriptions that changed between fetches."""
        raise NotImplementedError("DriftDetector.compare not implemented")
