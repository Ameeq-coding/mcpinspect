"""Tests for output formats."""

from mcpinspect.checks.base import CheckResult, Severity
from mcpinspect.scanner.scoring import ScanScore
from mcpinspect.scanner.drift import DescriptionDiff
from mcpinspect.output.json_out import format_json
from mcpinspect.output.sarif import format_sarif
from mcpinspect.output.terminal import print_terminal_report


def test_format_json():
    score = ScanScore(total_checks_run=1, findings={}, score=50.0, verdict="CRITICAL", drift_detected=True, probe_enabled=True)
    results = [CheckResult(check_id="MCI-D01", title="Title", severity=Severity.CRITICAL, passed=False, finding="f", evidence="e", location="l")]
    diffs = [DescriptionDiff("tool", "desc", "a", "b", Severity.CRITICAL)]
    
    data = format_json("http://test", "2023-01-01T00:00:00Z", score, results, diffs)
    
    assert data["target"] == "http://test"
    assert data["verdict"] == "CRITICAL"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["check_id"] == "MCI-D01"
    assert len(data["drift"]) == 1


def test_format_sarif():
    results = [CheckResult(check_id="MCI-D01", title="Title", severity=Severity.CRITICAL, passed=False, finding="f", evidence="e", location="l")]
    diffs = [DescriptionDiff("tool", "desc", "a", "b", Severity.CRITICAL)]
    
    data = format_sarif("http://test", results, diffs)
    
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    run = data["runs"][0]
    assert len(run["results"]) == 2  # 1 check + 1 drift
    
    
def test_terminal_report():
    score = ScanScore(total_checks_run=1, findings={}, score=50.0, verdict="CRITICAL", drift_detected=True, probe_enabled=True)
    results = [
        CheckResult(check_id="MCI-D01", title="Title", severity=Severity.CRITICAL, passed=False, finding="f", evidence="e", location="l"),
        CheckResult(check_id="MCI-R02", title="Safe", severity=Severity.HIGH, passed=True, finding="", evidence="", location=""),
    ]
    diffs = [DescriptionDiff("tool", "desc", "a", "b", Severity.CRITICAL)]
    
    # Just ensure it doesn't crash
    print_terminal_report("http://test", "2023-01-01T00:00:00Z", score, results, diffs, 1.5)
