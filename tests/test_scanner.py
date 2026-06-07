"""Tests for drift detection and scoring logic."""

import pytest
from mcpinspect.checks.base import CheckResult, Severity
from mcpinspect.protocol.models import MCPTool, ServerManifest
from mcpinspect.scanner.drift import DescriptionDiff, DriftDetector
from mcpinspect.scanner.scoring import score


class MockClient:
    def __init__(self, manifests):
        self.manifests = manifests
        self.calls = 0

    async def fetch_manifest(self):
        m = self.manifests[self.calls]
        self.calls += 1
        return m


@pytest.mark.anyio
async def test_drift_detector_clean():
    m1 = ServerManifest(
        target="test",
        transport_type="test",
        tools=[MCPTool(name="t1", description="desc1")],
    )
    client = MockClient([m1, m1])
    detector = DriftDetector(client, interval_seconds=0.0)
    diffs = await detector.detect(m1)
    assert not diffs


@pytest.mark.anyio
async def test_drift_detector_rug_pull():
    m1 = ServerManifest(
        target="test",
        transport_type="test",
        tools=[MCPTool(name="t1", description="safe")],
    )
    m2 = ServerManifest(
        target="test",
        transport_type="test",
        tools=[MCPTool(name="t1", description="malicious")],
    )
    client = MockClient([m1, m2])
    detector = DriftDetector(client, interval_seconds=0.0)
    diffs = await detector.detect(m1)
    
    assert len(diffs) == 1
    assert diffs[0].tool_name == "t1"
    assert diffs[0].field == "description"
    assert diffs[0].before == "safe"
    assert diffs[0].after == "malicious"
    assert diffs[0].severity == Severity.CRITICAL


@pytest.mark.anyio
async def test_drift_detector_existence():
    m1 = ServerManifest(
        target="test",
        transport_type="test",
        tools=[MCPTool(name="t1", description="safe")],
    )
    m2 = ServerManifest(
        target="test",
        transport_type="test",
        tools=[MCPTool(name="t1", description="safe"), MCPTool(name="t2", description="bad")],
    )
    client = MockClient([m1, m2])
    detector = DriftDetector(client, interval_seconds=0.0)
    diffs = await detector.detect()
    
    assert len(diffs) == 1
    assert diffs[0].tool_name == "t2"
    assert diffs[0].field == "existence"
    assert diffs[0].severity == Severity.CRITICAL


def test_score_clean():
    s = score([], [])
    assert s.score == 100.0
    assert s.verdict == "SAFE"


def test_score_drift_is_critical():
    diffs = [DescriptionDiff("t", "desc", "a", "b", Severity.CRITICAL)]
    s = score([], diffs)
    assert s.score == 0.0
    assert s.verdict == "CRITICAL"
    assert s.drift_detected is True


def test_score_deductions():
    results = [
        CheckResult("c", "t", Severity.HIGH, False, "f", "e", "l"),
        CheckResult("c", "t", Severity.MEDIUM, False, "f", "e", "l"),
    ]
    s = score(results, [])
    assert s.score == 80.0
    assert s.verdict == "WARN"
    assert s.findings[Severity.HIGH] == 1
    assert s.findings[Severity.MEDIUM] == 1


def test_score_critical_finding():
    results = [
        CheckResult("c", "t", Severity.CRITICAL, False, "f", "e", "l"),
    ]
    s = score(results, [])
    assert s.score == 70.0
    assert s.verdict == "CRITICAL"
