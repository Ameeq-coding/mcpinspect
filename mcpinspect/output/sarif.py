"""SARIF 2.1.0 output format for mcpinspect."""

from __future__ import annotations

from typing import Any

from mcpinspect import __version__
from mcpinspect.checks.base import CheckResult
from mcpinspect.scanner.drift import DescriptionDiff


def severity_to_sarif_level(severity: str) -> str:
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
    }
    return mapping.get(severity.lower(), "none")


def format_sarif(
    target: str,
    results: list[CheckResult],
    diffs: list[DescriptionDiff],
) -> dict[str, Any]:
    """Format scan results into a SARIF 2.1.0 document."""
    failed_results = [r for r in results if not r.passed]
    
    rules = []
    seen_rules = set()

    # Create rules from failed checks
    for r in failed_results:
        if r.check_id not in seen_rules:
            rules.append({
                "id": r.check_id,
                "shortDescription": {"text": r.title},
                "fullDescription": {"text": r.remediation},
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(r.severity.value)
                }
            })
            seen_rules.add(r.check_id)
            
    # Add a special rule for drift
    if diffs:
        rules.append({
            "id": "MCI-X01",
            "shortDescription": {"text": "Manifest Drift Detected"},
            "fullDescription": {"text": "Tool descriptions changed since last fetch."},
            "defaultConfiguration": {"level": "error"},
        })

    sarif_results = []
    for r in failed_results:
        sarif_results.append({
            "ruleId": r.check_id,
            "level": severity_to_sarif_level(r.severity.value),
            "message": {
                "text": f"{r.finding}\nEvidence: {r.evidence}"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": target
                    },
                    "region": {
                        "snippet": {
                            "text": r.location
                        }
                    }
                }
            }]
        })
        
    for d in diffs:
        sarif_results.append({
            "ruleId": "MCI-X01",
            "level": "error",
            "message": {
                "text": f"Drift detected in '{d.tool_name}' ({d.field}).\nBefore: {d.before}\nAfter: {d.after}"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": target
                    },
                    "region": {
                        "snippet": {
                            "text": f"tool:{d.tool_name}:{d.field}"
                        }
                    }
                }
            }]
        })

    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "mcpinspect",
                    "version": __version__,
                    "rules": rules,
                }
            },
            "results": sarif_results,
        }]
    }
