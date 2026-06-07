"""Description checks — analyse tool/resource/prompt descriptions.

These check what the server CLAIMS — not what it does.
"""

from mcpinspect.checks.base import Check
from mcpinspect.checks.description.injection import PromptInjectionCheck
from mcpinspect.checks.description.exfil import ExfiltrationPatternCheck
from mcpinspect.checks.description.homoglyph import HomoglyphCheck
from mcpinspect.checks.description.shadow import ShadowToolCheck
from mcpinspect.checks.description.schema_abuse import SchemaAbuseCheck

DESCRIPTION_CHECKS: list[Check] = [
    PromptInjectionCheck(),
    ExfiltrationPatternCheck(),
    HomoglyphCheck(),
    ShadowToolCheck(),
    SchemaAbuseCheck(),
]

__all__ = [
    "DESCRIPTION_CHECKS",
    "PromptInjectionCheck",
    "ExfiltrationPatternCheck",
    "HomoglyphCheck",
    "ShadowToolCheck",
    "SchemaAbuseCheck",
]
