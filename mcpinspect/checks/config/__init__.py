"""Config checks — static analysis of MCP config files (no network)."""

from mcpinspect.checks.config.stdio_inject import StdioInjectCheck
from mcpinspect.checks.config.secrets import SecretsCheck
from mcpinspect.checks.config.privilege import PrivilegeCheck

CONFIG_CHECKS = [
    StdioInjectCheck(),
    SecretsCheck(),
    PrivilegeCheck(),
]

__all__ = ["CONFIG_CHECKS", "StdioInjectCheck", "SecretsCheck", "PrivilegeCheck"]
