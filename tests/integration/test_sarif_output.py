"""Integration test for SARIF output."""

import json
from pathlib import Path

import pytest
from pytest_httpserver import HTTPServer

from mcpinspect.cli import _scan_async
from mcpinspect.scanner.engine import ScanConfig


@pytest.mark.anyio
async def test_sarif_schema_valid(malicious_server: HTTPServer, tmp_path: Path):
    target = malicious_server.url_for("/sse")
    out_file = tmp_path / "results.sarif"
    
    config = ScanConfig(
        target=target,
        probe=True,
        drift_check=False,
        output_format="sarif"
    )
    
    # Run scan with SARIF output formatting via CLI function
    with pytest.raises(Exception) as excinfo:
        await _scan_async(config, output_file=out_file)
        
    # malicious_server should yield CRITICAL verdict (exit code 2)
    assert excinfo.value.exit_code == 2
    
    # Validate SARIF schema properties
    assert out_file.exists()
    sarif_data = json.loads(out_file.read_text())
    
    assert sarif_data["version"] == "2.1.0"
    assert "runs" in sarif_data
    assert len(sarif_data["runs"]) == 1
    
    run = sarif_data["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcpinspect"
    
    results = run["results"]
    assert len(results) > 0
    
    # Check that CRITICAL findings map to level=="error"
    has_error = False
    for result in results:
        assert "ruleId" in result
        if result["level"] == "error":
            has_error = True
            
    assert has_error
