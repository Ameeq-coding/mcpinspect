"""The main ScanEngine that orchestrates a full scan."""

from __future__ import annotations

from dataclasses import dataclass, field

from mcpinspect.checks import DESCRIPTION_CHECKS, RESPONSE_CHECKS
from mcpinspect.checks.base import CheckResult
from mcpinspect.protocol.client import MCPClient
from mcpinspect.protocol.models import ToolResponse
from mcpinspect.scanner.drift import DescriptionDiff, DriftDetector
from mcpinspect.scanner.probes import ToolProber
from mcpinspect.scanner.scoring import ScanScore, score
from mcpinspect.transport import get_transport


@dataclass
class ScanConfig:
    """Configuration for a scan."""

    target: str
    probe: bool = True
    drift_check: bool = True
    drift_interval: float = 20.0
    timeout: float = 30.0
    output_format: str = "terminal"
    headers: dict[str, str] = field(default_factory=dict)


class ScanEngine:
    """Orchestrates an end-to-end security scan of an MCP server."""

    def __init__(self, config: ScanConfig):
        self.config = config

    async def run(self) -> tuple[list[CheckResult], list[DescriptionDiff], ScanScore]:
        """Run the full scan pipeline."""
        kwargs = {}
        if self.config.target.startswith("http"):
            if self.config.headers:
                kwargs["headers"] = self.config.headers

        transport = get_transport(self.config.target, **kwargs)
        
        # Override the default connect timeout if possible, though currently
        # HttpSseTransport has it hardcoded, but we can manage timeout at the probe level.
        
        await transport.connect()
        client = MCPClient(transport)

        try:
            # 1. Fetch manifest
            manifest = await client.fetch_manifest()

            # 2. Probe tools (if enabled)
            responses: list[ToolResponse] = []
            if self.config.probe:
                prober = ToolProber(client, timeout=self.config.timeout)
                responses = await prober.probe_all(manifest.tools)

            # 3. Run all checks
            results: list[CheckResult] = []
            for check in DESCRIPTION_CHECKS:
                results.extend(check.run(manifest))
                
            if responses:
                for check in RESPONSE_CHECKS:
                    # check.run for response checks expects manifest and responses
                    results.extend(check.run(manifest, responses=responses))

            # 4. Drift detection (if enabled)
            diffs: list[DescriptionDiff] = []
            if self.config.drift_check:
                detector = DriftDetector(client, interval_seconds=self.config.drift_interval)
                diffs = await detector.detect(manifest)

            # 5. Score
            scan_score = score(results, diffs, probe_enabled=self.config.probe)

            return results, diffs, scan_score

        finally:
            await transport.disconnect()
