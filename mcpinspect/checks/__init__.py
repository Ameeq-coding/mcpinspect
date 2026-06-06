"""Security checks — registry and runner for all check categories."""

from __future__ import annotations

from mcpinspect.checks.base import Check, CheckResult, Severity
from mcpinspect.checks.description import DESCRIPTION_CHECKS
from mcpinspect.checks.response import RESPONSE_CHECKS
from mcpinspect.checks.drift import DRIFT_CHECKS
from mcpinspect.checks.config import CONFIG_CHECKS
from mcpinspect.protocol.models import ServerManifest, ToolResponse

ALL_CHECKS: list[Check] = [
    *DESCRIPTION_CHECKS,
    *RESPONSE_CHECKS,
    *DRIFT_CHECKS,
    *CONFIG_CHECKS,
]


def run_all(
    manifest: ServerManifest | None = None,
    responses: list[ToolResponse] | None = None,
    baseline: ServerManifest | None = None,
    config: dict[str, object] | None = None,
) -> list[CheckResult]:
    """Execute every registered check and collect results."""
    raise NotImplementedError("run_all: not implemented")


__all__ = [
    "ALL_CHECKS",
    "Check",
    "CheckResult",
    "Severity",
    "run_all",
]
