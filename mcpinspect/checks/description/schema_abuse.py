"""MCI-D05: Schema fields used as instruction channels — HIGH.

Checks for abuse of ``input_schema`` parameter descriptions:
1. Full sentences (ending with `.`, `!`, `?`) in type documentation
2. Second-person pronouns directing the LLM agent
3. Parameters typed ``string`` but named like code execution inputs
"""

from __future__ import annotations

import re
from typing import Any

from mcpinspect.checks.base import Check, CheckResult, Severity
from mcpinspect.protocol.models import ServerManifest, ToolResponse

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Sentence-ending punctuation (in what should be terse type docs)
FULL_SENTENCE = re.compile(r"[.!?]\s*$")

# Second-person language directing the LLM
SECOND_PERSON = re.compile(
    r"\b(you|your|you're|you'll|yourself)\b", re.IGNORECASE
)

# Suspicious string-typed parameter names (code/command execution channels)
SUSPICIOUS_PARAM_NAMES: set[str] = {
    "cmd", "command", "shell", "exec", "eval", "script", "code",
}


class SchemaAbuseCheck(Check):
    """Detect schema fields being repurposed as instruction channels."""

    id = "MCI-D05"
    title = "Schema fields as instruction channels"
    severity = Severity.HIGH

    def run(self, manifest: ServerManifest, responses: list[ToolResponse] | None = None) -> list[CheckResult]:
        results: list[CheckResult] = []

        for tool in manifest.tools:
            self._check_properties(tool.name, tool.input_schema, results)

        return results if results else [self._pass()]

    def _check_properties(
        self,
        tool_name: str,
        schema: dict[str, Any],
        results: list[CheckResult],
    ) -> None:
        """Iterate over top-level and nested properties."""
        properties = schema.get("properties", {})
        for param_name, param_def in properties.items():
            if not isinstance(param_def, dict):
                continue

            location = (
                f"tool:{tool_name}:schema.properties.{param_name}.description"
            )
            desc = param_def.get("description", "")
            param_type = param_def.get("type", "")

            # --- Check 1: full sentences in type documentation ------------
            if desc and FULL_SENTENCE.search(desc) and len(desc) > 40:
                results.append(
                    self._fail(
                        finding=(
                            f"Parameter '{param_name}' description contains "
                            f"full sentences — possible instruction channel."
                        ),
                        evidence=desc[:150],
                        location=location,
                        severity=Severity.MEDIUM,
                        remediation=(
                            "Keep parameter descriptions terse and factual. "
                            "Move instructions to tool description."
                        ),
                    )
                )

            # --- Check 2: second-person pronouns -------------------------
            if desc and SECOND_PERSON.search(desc):
                match = SECOND_PERSON.search(desc)
                assert match is not None
                results.append(
                    self._fail(
                        finding=(
                            f"Parameter '{param_name}' description uses "
                            f"second-person language — may direct agent behaviour."
                        ),
                        evidence=match.group(0),
                        location=location,
                        remediation=(
                            "Remove second-person pronouns from parameter "
                            "descriptions."
                        ),
                    )
                )

            # --- Check 3: suspicious name + string type ------------------
            if (
                param_name.lower() in SUSPICIOUS_PARAM_NAMES
                and param_type == "string"
            ):
                results.append(
                    self._fail(
                        finding=(
                            f"String parameter named '{param_name}' — "
                            f"potential code/command execution channel."
                        ),
                        evidence=f"type=string, name={param_name}",
                        location=f"tool:{tool_name}:schema.properties.{param_name}",
                        remediation=(
                            "Rename the parameter or constrain the type "
                            "with an enum/pattern."
                        ),
                    )
                )

            # Recurse into nested objects
            if param_def.get("type") == "object":
                self._check_properties(tool_name, param_def, results)
