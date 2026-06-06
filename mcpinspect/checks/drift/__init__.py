"""Drift checks — compare manifests over time."""

from mcpinspect.checks.drift.rug_pull import RugPullCheck
from mcpinspect.checks.drift.cross_server import CrossServerCheck

DRIFT_CHECKS = [
    RugPullCheck(),
    CrossServerCheck(),
]

__all__ = ["DRIFT_CHECKS", "RugPullCheck", "CrossServerCheck"]
