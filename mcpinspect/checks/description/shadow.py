"""MCI-D04: Tool name shadows a known-dangerous built-in — HIGH.

Flags tool names within edit distance 2 of a known-dangerous operation,
unless the description contains expected semantics for that name
(i.e., a tool legitimately called "execute" that describes SQL execution).

Uses a minimal Wagner-Fischer edit distance implementation — no
external libraries.
"""

from __future__ import annotations

from mcpinspect.checks.base import Check, CheckResult, Severity
from mcpinspect.protocol.models import ServerManifest, ToolResponse

# ---------------------------------------------------------------------------
# Dangerous built-in names that attackers shadow
# ---------------------------------------------------------------------------

DANGEROUS_NAMES: set[str] = {
    "bash", "shell", "exec", "eval", "python", "node", "ruby", "perl",
    "read_file", "write_file", "delete_file", "send_email", "send_message",
    "get_secret", "list_secrets", "execute", "run", "subprocess",
}

# Semantic keywords that justify a tool having a dangerous-sounding name
_EXPECTED_SEMANTICS: dict[str, set[str]] = {
    "bash":         {"terminal", "shell", "bash", "cli", "command line"},
    "shell":        {"terminal", "shell", "bash", "cli", "command line"},
    "exec":         {"execute", "run", "query", "sql"},
    "eval":         {"evaluate", "expression", "calculate", "formula"},
    "python":       {"python", "script", "interpreter"},
    "node":         {"node", "javascript", "runtime"},
    "ruby":         {"ruby", "script"},
    "perl":         {"perl", "script"},
    "read_file":    {"file", "read", "content", "open"},
    "write_file":   {"file", "write", "save", "create"},
    "delete_file":  {"file", "delete", "remove", "trash"},
    "send_email":   {"email", "mail", "smtp"},
    "send_message": {"message", "send", "chat", "notify"},
    "get_secret":   {"secret", "vault", "credential", "key"},
    "list_secrets": {"secret", "vault", "credential", "list"},
    "execute":      {"execute", "run", "query", "sql", "task"},
    "run":          {"run", "execute", "start", "launch", "task"},
    "subprocess":   {"subprocess", "process", "spawn"},
}


def _edit_distance(a: str, b: str) -> int:
    """Wagner-Fischer edit distance (no external deps)."""
    m, n = len(a), len(b)
    # Optimise: if length difference > threshold, skip
    if abs(m - n) > 2:
        return abs(m - n)

    prev = list(range(n + 1))
    curr = [0] * (n + 1)

    for i in range(1, m + 1):
        curr[0] = i
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr[j] = min(
                prev[j] + 1,       # deletion
                curr[j - 1] + 1,    # insertion
                prev[j - 1] + cost, # substitution
            )
        prev, curr = curr, prev

    return prev[n]


class ShadowToolCheck(Check):
    """Detect tool names that shadow known-dangerous operations."""

    id = "MCI-D04"
    title = "Tool name shadows dangerous built-in"
    severity = Severity.HIGH

    def run(self, manifest: ServerManifest, responses: list[ToolResponse] | None = None) -> list[CheckResult]:
        results: list[CheckResult] = []

        for tool in manifest.tools:
            name_lower = tool.name.lower().strip()
            # Normalise: replace hyphens/dots with underscores for matching
            name_norm = name_lower.replace("-", "_").replace(".", "_")

            for dangerous in DANGEROUS_NAMES:
                dist = _edit_distance(name_norm, dangerous)
                if dist > 2:
                    continue

                # Check if the description contains expected semantics
                if self._has_expected_semantics(tool.description, dangerous):
                    continue

                qualifier = "exact match" if dist == 0 else f"edit distance {dist}"
                results.append(
                    self._fail(
                        finding=(
                            f"Tool '{tool.name}' shadows dangerous name "
                            f"'{dangerous}' ({qualifier}) without expected "
                            f"semantic justification."
                        ),
                        evidence=f"tool.name='{tool.name}' ≈ '{dangerous}'",
                        location=f"tool:{tool.name}:name",
                        remediation=(
                            f"Rename the tool to avoid confusion with "
                            f"'{dangerous}', or add a clear description."
                        ),
                    )
                )

        return results if results else [self._pass()]

    @staticmethod
    def _has_expected_semantics(description: str, dangerous_name: str) -> bool:
        """Check if the description justifies having this name."""
        if not description:
            return False
        desc_lower = description.lower()
        expected = _EXPECTED_SEMANTICS.get(dangerous_name, set())
        return any(kw in desc_lower for kw in expected)
