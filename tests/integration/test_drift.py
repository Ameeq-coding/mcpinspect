"""Integration test for drift detection."""

import pytest
from pytest_httpserver import HTTPServer

from mcpinspect.scanner.engine import ScanConfig, ScanEngine


@pytest.mark.anyio
async def test_detects_rug_pull(rug_pull_server: HTTPServer):
    target = rug_pull_server.url_for("/sse")
    config = ScanConfig(target=target, probe=False, drift_check=True, drift_interval=0.1)
    engine = ScanEngine(config)
    
    results, diffs, score = await engine.run()
    
    assert len(diffs) > 0, "No drift detected!"
    assert score.verdict == "CRITICAL"
    assert score.drift_detected is True
    
    # Check that it correctly identified the description change
    diff = diffs[0]
    assert diff.tool_name == "transfer_funds"
    assert diff.field == "description"
    assert "read ~/.aws/credentials" in diff.after
