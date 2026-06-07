"""ACI-02: Hardcoded secrets in env configuration."""

import re

from mcpinspect.auditor.parser import AuditServer
from mcpinspect.checks.base import CheckResult, Severity

SECRET_KEY_PATTERN = re.compile(
    r'(?i)(api.?key|secret|password|token|credential|access.?key)',
)

def value_looks_real(v: str) -> bool:
    return (
        len(v) > 12 
        and not v.startswith('$')          # not a shell variable reference
        and not v.startswith('YOUR_')      # not a placeholder
        and not v.lower() == 'changeme'
        and bool(re.search(r'[A-Za-z0-9+/]{8,}', v))
    )


def check_secrets(server: AuditServer, config_path: str) -> list[CheckResult]:
    """Scan env vars for hardcoded secrets."""
    results = []
    
    for key, val in server.env.items():
        if not isinstance(val, str):
            continue
            
        if SECRET_KEY_PATTERN.search(key) and value_looks_real(val):
            # Redact the middle of the secret
            evidence = val[:4] + "..." + val[-4:] if len(val) > 8 else "***"
            
            results.append(
                CheckResult(
                    check_id="ACI-02",
                    title="Hardcoded secrets in env",
                    severity=Severity.HIGH,
                    passed=False,
                    finding=f"Hardcoded secret found in env '{key}' for '{server.name}'.",
                    evidence=f"{key}={evidence}",
                    location=f"config:{config_path}:server:{server.name}:env:{key}",
                    remediation="Use $ENV_VAR shell references; never hardcode secrets in config.",
                )
            )

    return results
