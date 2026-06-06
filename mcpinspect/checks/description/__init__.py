"""Description checks — analyse tool/resource/prompt descriptions."""

from mcpinspect.checks.description.injection import DescriptionInjectionCheck
from mcpinspect.checks.description.exfil import DescriptionExfilCheck
from mcpinspect.checks.description.homoglyph import HomoglyphCheck
from mcpinspect.checks.description.shadow import ShadowToolCheck
from mcpinspect.checks.description.schema_abuse import SchemaAbuseCheck

DESCRIPTION_CHECKS = [
    DescriptionInjectionCheck(),
    DescriptionExfilCheck(),
    HomoglyphCheck(),
    ShadowToolCheck(),
    SchemaAbuseCheck(),
]

__all__ = [
    "DESCRIPTION_CHECKS",
    "DescriptionInjectionCheck",
    "DescriptionExfilCheck",
    "HomoglyphCheck",
    "ShadowToolCheck",
    "SchemaAbuseCheck",
]
