"""Security checks — registry and runner for all check categories."""

from __future__ import annotations

import logging

from mcpinspect.checks.base import Check, CheckResult, Severity
from mcpinspect.checks.description import DESCRIPTION_CHECKS
from mcpinspect.checks.response import RESPONSE_CHECKS
from mcpinspect.protocol.models import ServerManifest, ToolResponse

logger = logging.getLogger(__name__)

ALL_CHECKS: list[Check] = [
    *DESCRIPTION_CHECKS,
    *RESPONSE_CHECKS,
]


def run_all(
    manifest: ServerManifest,
    responses: list[ToolResponse] | None = None,
    checks: list[Check] | None = None,
) -> list[CheckResult]:
    """Execute checks against *manifest* (and optional *responses*).

    Unimplemented stubs are silently skipped.
    """
    results: list[CheckResult] = []
    for check in checks or ALL_CHECKS:
        try:
            results.extend(check.run(manifest, responses=responses))
        except NotImplementedError:
            logger.debug("Skipping unimplemented check %s", check.id)
        except Exception as exc:
            logger.warning("Check %s crashed: %s", check.id, exc)
    return results


__all__ = [
    "ALL_CHECKS",
    "DESCRIPTION_CHECKS",
    "RESPONSE_CHECKS",
    "Check",
    "CheckResult",
    "Severity",
    "run_all",
]
