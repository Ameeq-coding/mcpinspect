"""Response checks — analyse what tools actually return."""

from mcpinspect.checks.response.injection import ResponseInjectionCheck
from mcpinspect.checks.response.exfil import ResponseExfilCheck
from mcpinspect.checks.response.data_leak import DataLeakCheck
from mcpinspect.checks.response.redirect import RedirectCheck

RESPONSE_CHECKS = [
    ResponseInjectionCheck(),
    ResponseExfilCheck(),
    DataLeakCheck(),
    RedirectCheck(),
]

__all__ = [
    "RESPONSE_CHECKS",
    "ResponseInjectionCheck",
    "ResponseExfilCheck",
    "DataLeakCheck",
    "RedirectCheck",
]
