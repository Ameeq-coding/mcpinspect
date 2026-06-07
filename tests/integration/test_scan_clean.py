"""Integration test for clean server scanning."""

import pytest
from pytest_httpserver import HTTPServer

from mcpinspect.scanner.engine import ScanConfig, ScanEngine


@pytest.mark.anyio
async def test_full_scan_clean_server(clean_server: HTTPServer):
    target = clean_server.url_for("/sse")
    config = ScanConfig(target=target, probe=True, drift_check=True, drift_interval=0.1)
    engine = ScanEngine(config)
    
    results, diffs, score = await engine.run()
    
    # Expect: verdict SAFE, exit code 0, zero findings
    assert score.verdict == "SAFE"
    failed_results = [r for r in results if not r.passed]
    assert len(failed_results) == 0
    assert len(diffs) == 0
