"""Check base classes, severity enum, and result model."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from mcpinspect.protocol.models import ServerManifest, ToolResponse


class Severity(str, Enum):
    """Finding severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CheckResult(BaseModel):
    """A single finding produced by a check."""

    check_id: str
    title: str
    severity: Severity
    description: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    location: str = ""


class Check(ABC):
    """Abstract base for all security checks."""

    #: Unique identifier, e.g. ``MCI-D01``
    check_id: str = ""
    #: Human-readable title
    title: str = ""

    @abstractmethod
    def run(
        self,
        manifest: ServerManifest | None = None,
        responses: list[ToolResponse] | None = None,
        baseline: ServerManifest | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[CheckResult]:
        """Execute the check and return findings."""
