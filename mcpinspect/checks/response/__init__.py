"""Response checks — analyse what tools actually return.

This is mcpinspect's primary differentiator: no other open-source
scanner inspects tool response content.
"""

from mcpinspect.checks.base import Check
from mcpinspect.checks.response.injection import ResponseInjectionCheck
from mcpinspect.checks.response.exfil import ResponseExfilCheck
from mcpinspect.checks.response.data_leak import DataLeakCheck
from mcpinspect.checks.response.redirect import CrossToolRedirectCheck

RESPONSE_CHECKS: list[Check] = [
    ResponseInjectionCheck(),
    ResponseExfilCheck(),
    DataLeakCheck(),
    CrossToolRedirectCheck(),
]

__all__ = [
    "RESPONSE_CHECKS",
    "ResponseInjectionCheck",
    "ResponseExfilCheck",
    "DataLeakCheck",
    "CrossToolRedirectCheck",
]
