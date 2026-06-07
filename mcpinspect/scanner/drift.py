"""Rug-pull drift detection: compares manifests over time."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import anyio

from mcpinspect.checks.base import Severity
from mcpinspect.protocol.client import MCPClient


@dataclass
class DescriptionDiff:
    """A difference detected between two manifest snapshots."""

    tool_name: str
    field: str           # e.g., "description", "existence"
    before: str
    after: str
    severity: Severity   # Drift is generally always CRITICAL


class DriftDetector:
    """Detects description drift / rug-pulls.

    Fetches the manifest twice, pausing for a specified interval
    in between. By comparing the hashes of tool descriptions, this catches:
    1. Classic rug-pulls (description changed post-approval).
    2. Dynamic poisoning (server detects scanner, serves clean content
       on the first call, then malicious on subsequent calls).
    """

    def __init__(self, client: MCPClient, interval_seconds: float = 30.0):
        self.client = client
        self.interval = interval_seconds

    async def detect(self) -> list[DescriptionDiff]:
        """Fetch twice and return any differences."""
        manifest_1 = await self.client.fetch_manifest()
        
        if self.interval > 0:
            await anyio.sleep(self.interval)
            
        manifest_2 = await self.client.fetch_manifest()

        diffs: list[DescriptionDiff] = []
        tools_1 = {t.name: t for t in manifest_1.tools}
        tools_2 = {t.name: t for t in manifest_2.tools}

        # Check for tools that were added in the second fetch
        for name in tools_2.keys() - tools_1.keys():
            diffs.append(
                DescriptionDiff(
                    tool_name=name,
                    field="existence",
                    before="[not present]",
                    after=tools_2[name].description or "[no description]",
                    severity=Severity.CRITICAL,
                )
            )

        # Check for modified descriptions in tools that exist in both
        for name in tools_1.keys() & tools_2.keys():
            t1, t2 = tools_1[name], tools_2[name]
            
            # Use the pre-computed hash or compute on the fly
            hash1 = hashlib.sha256(t1.description.encode("utf-8")).hexdigest()
            hash2 = hashlib.sha256(t2.description.encode("utf-8")).hexdigest()

            if hash1 != hash2:
                diffs.append(
                    DescriptionDiff(
                        tool_name=name,
                        field="description",
                        before=t1.description,
                        after=t2.description,
                        severity=Severity.CRITICAL,
                    )
                )

        return diffs
