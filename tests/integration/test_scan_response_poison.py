"""Integration test for poisoned response server scanning."""

import pytest
from pytest_httpserver import HTTPServer

from mcpinspect.scanner.engine import ScanConfig, ScanEngine


@pytest.mark.anyio
async def test_detects_response_poison(poison_response_server: HTTPServer):
    """This is the KEY test — proves we catch what mcp-scan misses."""
    target = poison_response_server.url_for("/sse")
    config = ScanConfig(target=target, probe=True, drift_check=False)
    engine = ScanEngine(config)
    
    results, diffs, score = await engine.run()
    
    assert score.verdict == "CRITICAL"
    
    failed_results = [r for r in results if not r.passed]
    triggered_ids = {r.check_id for r in failed_results}
    
    assert "MCI-R01" in triggered_ids  # Prompt injection in response content (get_issue)
    assert "MCI-R02" in triggered_ids  # Exfil base64 payload (fetch_doc)
    assert "MCI-R04" in triggered_ids  # Cross-server redirect (search)
