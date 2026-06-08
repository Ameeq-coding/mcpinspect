"""Tests for CLI."""

from typer.testing import CliRunner
from mcpinspect.cli import app
from unittest.mock import patch, MagicMock

runner = CliRunner()

def test_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.stdout
    assert "audit" in result.stdout
    assert "diff" in result.stdout

def test_scan_help():
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "probe" in result.stdout
    assert "sarif" in result.stdout

@patch("mcpinspect.cli.ScanEngine")
def test_scan_command_safe(mock_engine_cls):
    # Setup mock
    mock_engine = MagicMock()
    mock_engine_cls.return_value = mock_engine
    
    # We must mock async run
    async def mock_run():
        from mcpinspect.scanner.scoring import ScanScore
        return [], [], ScanScore(1, {}, 100.0, "SAFE", False, True)
        
    mock_engine.run.return_value = mock_run()
    
    result = runner.invoke(app, ["scan", "http://test"])
    assert result.exit_code == 0

@patch("mcpinspect.cli.ScanEngine")
def test_scan_command_critical(mock_engine_cls):
    mock_engine = MagicMock()
    mock_engine_cls.return_value = mock_engine
    
    async def mock_run():
        from mcpinspect.scanner.scoring import ScanScore
        return [], [], ScanScore(1, {}, 50.0, "CRITICAL", False, True)
        
    mock_engine.run.return_value = mock_run()
    
    result = runner.invoke(app, ["scan", "http://test", "--format", "json"])
    assert result.exit_code == 2

@patch("mcpinspect.cli._audit_async")
def test_audit_command(mock_audit):
    async def mock_run(*args, **kwargs):
        from mcpinspect.auditor.engine import AuditReport
        from mcpinspect.scanner.scoring import ScanScore
        return AuditReport(servers=[], results=[]), ScanScore(1, {}, 100.0, "SAFE", False, True)
    
    mock_audit.return_value = mock_run()
    
    result = runner.invoke(app, ["audit", "--discover"])
    assert result.exit_code == 0
