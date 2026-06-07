"""The audit engine for static config files."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mcpinspect.auditor.checks.privilege import check_privilege
from mcpinspect.auditor.checks.secrets import check_secrets
from mcpinspect.auditor.checks.stdio_inject import check_stdio_inject
from mcpinspect.auditor.parser import parse_config
from mcpinspect.checks.base import CheckResult, Severity


@dataclass
class AuditReport:
    total_servers: int
    findings: dict[str, list[CheckResult]]
    verdict: str


def get_default_paths() -> list[Path]:
    """Return common paths for MCP config files."""
    home = Path.home()
    paths = [
        home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        home / ".cursor" / "mcp.json",
        home / ".codeium" / "windsurf" / "mcp_config.json",
        Path.cwd() / ".vscode" / "mcp.json",
    ]
    return [p for p in paths if p.exists() and p.is_file()]


async def audit(path: Path | None, discover: bool) -> AuditReport:
    """Audit config files for vulnerabilities."""
    paths_to_check: list[Path] = []
    
    if path:
        if path.is_dir():
            paths_to_check.extend(path.glob("**/*.json"))
        else:
            paths_to_check.append(path)
            
    if discover:
        for default_path in get_default_paths():
            if default_path not in paths_to_check:
                paths_to_check.append(default_path)

    all_servers = []
    server_paths = {}

    for p in paths_to_check:
        servers = parse_config(p)
        for s in servers:
            all_servers.append(s)
            server_paths[s.name] = str(p)

    findings_by_server: dict[str, list[CheckResult]] = {}
    total_critical = 0
    total_high = 0

    for server in all_servers:
        server_findings = []
        config_path = server_paths[server.name]

        # Run checks
        server_findings.extend(check_stdio_inject(server, config_path))
        server_findings.extend(check_secrets(server, config_path))
        server_findings.extend(check_privilege(server, config_path))

        if server_findings:
            findings_by_server[server.name] = server_findings
            for f in server_findings:
                if f.severity == Severity.CRITICAL:
                    total_critical += 1
                elif f.severity == Severity.HIGH:
                    total_high += 1

    if total_critical > 0:
        verdict = "CRITICAL"
    elif total_high > 0:
        verdict = "WARN"
    else:
        verdict = "SAFE"

    return AuditReport(
        total_servers=len(all_servers),
        findings=findings_by_server,
        verdict=verdict,
    )
