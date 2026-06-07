"""ACI-03: Over-privileged flags in MCP config."""

from mcpinspect.auditor.parser import AuditServer
from mcpinspect.checks.base import CheckResult, Severity

DANGEROUS_FLAGS = {
    '--allow-all', '--no-sandbox', '--privileged', '--allow-read=/', 
    '--allow-write=/', '--allow-net', '--allow-env', '--allow-run'
}

def check_privilege(server: AuditServer, config_path: str) -> list[CheckResult]:
    """Scan args list for any match in DANGEROUS_FLAGS."""
    results = []
    
    for i, arg in enumerate(server.args):
        # some args might be like --allow-read=/home/user, so checking exact match and prefixes
        if arg in DANGEROUS_FLAGS or any(arg.startswith(f) and '=' in f for f in DANGEROUS_FLAGS if '=' in f):
            results.append(
                CheckResult(
                    check_id="ACI-03",
                    title="Over-privileged flags",
                    severity=Severity.MEDIUM,
                    passed=False,
                    finding=f"Over-privileged flag '{arg}' detected for '{server.name}'.",
                    evidence=arg,
                    location=f"config:{config_path}:server:{server.name}:arg_{i}",
                    remediation="Restrict permissions to minimum required paths.",
                )
            )

    return results
