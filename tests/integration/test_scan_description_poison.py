"""Integration test for malicious server scanning (description poisoning)."""

import pytest
from pytest_httpserver import HTTPServer

from mcpinspect.scanner.engine import ScanConfig, ScanEngine


@pytest.mark.anyio
async def test_detects_description_poison(malicious_server: HTTPServer):
    target = malicious_server.url_for("/sse")
    config = ScanConfig(target=target, probe=True, drift_check=False)
    engine = ScanEngine(config)
    
    results, diffs, score = await engine.run()
    
    assert score.verdict == "CRITICAL"
    
    failed_results = [r for r in results if not r.passed]
    triggered_ids = {r.check_id for r in failed_results}
    
    assert "MCI-D01" in triggered_ids  # Prompt injection (ignore previous instructions)
    assert "MCI-D03" in triggered_ids  # Homoglyph (wеather)
    assert "MCI-D05" in triggered_ids  # Schema abuse (cmd typed string)
