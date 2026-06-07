"""ACI-01: Shell metacharacters in command/args."""

import re

from mcpinspect.auditor.parser import AuditServer
from mcpinspect.checks.base import CheckResult, Severity

SHELL_META = re.compile(r'[;&|`$<>]|\$\(|\|\|')


def check_stdio_inject(server: AuditServer, config_path: str) -> list[CheckResult]:
    """Scan every string in command + args for shell metacharacters."""
    results = []
    
    if server.transport != "stdio":
        return results

    cmd_parts = []
    if server.command:
        cmd_parts.append(server.command)
    cmd_parts.extend(server.args)

    for i, part in enumerate(cmd_parts):
        if SHELL_META.search(part):
            results.append(
                CheckResult(
                    check_id="ACI-01",
                    title="Shell metacharacters in command/args",
                    severity=Severity.CRITICAL,
                    passed=False,
                    finding=f"Shell metacharacter detected in command arg for '{server.name}'.",
                    evidence=part,
                    location=f"config:{config_path}:server:{server.name}:arg_{i}",
                    remediation="Remove shell metacharacters; use list form subprocess args.",
                )
            )

    return results
