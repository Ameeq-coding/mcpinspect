"""Tests for the config auditor and checks."""

from pathlib import Path

from mcpinspect.auditor.checks.privilege import check_privilege
from mcpinspect.auditor.checks.secrets import check_secrets
from mcpinspect.auditor.checks.stdio_inject import check_stdio_inject
from mcpinspect.auditor.parser import AuditServer, parse_config


def test_parser(tmp_path: Path):
    config = tmp_path / "mcp.json"
    config.write_text(
        '{"mcpServers": {"test": {"command": "npx", "args": ["--allow-all"], "env": {"API_KEY": "1234567890abcdef"}}}}'
    )
    
    servers = parse_config(config)
    assert len(servers) == 1
    server = servers[0]
    
    assert server.name == "test"
    assert server.transport == "stdio"
    assert server.command == "npx"
    assert server.args == ["--allow-all"]
    assert server.env == {"API_KEY": "1234567890abcdef"}


def test_stdio_inject():
    server = AuditServer(name="test", transport="stdio", command="bash", args=["-c", "ls && rm -rf /"])
    results = check_stdio_inject(server, "config.json")
    
    assert len(results) == 1
    assert "&&" in results[0].evidence or "&" in results[0].evidence


def test_secrets():
    server = AuditServer(name="test", transport="stdio", command="node", env={"API_KEY": "sk-proj-1234567890abcdef1234567890abcdef1234567890abcdef", "SECRET_TOKEN": "$ENV_VAR"})
    results = check_secrets(server, "config.json")
    
    assert len(results) == 1
    assert "API_KEY" in results[0].evidence


def test_privilege():
    server = AuditServer(name="test", transport="stdio", command="npx", args=["--allow-all", "--allow-read=/tmp"])
    results = check_privilege(server, "config.json")
    
    assert len(results) == 2
    assert any("--allow-all" in r.evidence for r in results)
    assert any("--allow-read=/tmp" in r.evidence for r in results)
