"""MCI-D03: Unicode homoglyph / invisible characters — HIGH.

Detects two classes of Unicode abuse:
1. Zero-width / invisible characters (CRITICAL — deliberate concealment)
2. Confusable characters in tool names (HIGH — could shadow a built-in)
   or in descriptions (MEDIUM — suspicious but less dangerous)
"""

from __future__ import annotations

import unicodedata

from mcpinspect.checks.base import Check, CheckResult, Severity
from mcpinspect.protocol.models import ServerManifest, ToolResponse

# ---------------------------------------------------------------------------
# Zero-width and invisible characters
# ---------------------------------------------------------------------------

ZERO_WIDTH: set[str] = {
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\ufeff",  # byte order mark / zero width no-break space
    "\u00ad",  # soft hyphen
    "\u200e",  # left-to-right mark
    "\u200f",  # right-to-left mark
    "\u2060",  # word joiner
    "\u2061",  # function application
    "\u2062",  # invisible times
    "\u2063",  # invisible separator
    "\u2064",  # invisible plus
}

# ---------------------------------------------------------------------------
# Latin-script confusables (Cyrillic → Latin lookalikes)
#
# The ~40 most common confusable pairs. This is a curated subset of the
# Unicode Confusables data (https://unicode.org/reports/tr39/).
# ---------------------------------------------------------------------------

CONFUSABLES: dict[str, str] = {
    # Cyrillic → Latin
    "\u0430": "a",  # а → a
    "\u0435": "e",  # е → e
    "\u0456": "i",  # і → i
    "\u043e": "o",  # о → o
    "\u0440": "p",  # р → p
    "\u0441": "c",  # с → c
    "\u0443": "y",  # у → y
    "\u0445": "x",  # х → x
    "\u0455": "s",  # ѕ → s
    "\u0458": "j",  # ј → j
    "\u04bb": "h",  # һ → h
    "\u0501": "d",  # ԁ → d
    "\u051b": "q",  # ԛ → q
    "\u050d": "k",  # ԍ → k (less common)
    # Greek → Latin
    "\u03b1": "a",  # α → a
    "\u03b5": "e",  # ε → e
    "\u03bf": "o",  # ο → o
    "\u03c1": "p",  # ρ → p
    "\u03ba": "k",  # κ → k
    "\u03bd": "v",  # ν → v
    "\u03c4": "t",  # τ → t (lookalike in some fonts)
    # Fullwidth → Latin
    "\uff41": "a",  # ａ → a
    "\uff42": "b",  # ｂ → b
    "\uff43": "c",  # ｃ → c
    "\uff44": "d",  # ｄ → d
    "\uff45": "e",  # ｅ → e
    "\uff46": "f",  # ｆ → f
    "\uff4f": "o",  # ｏ → o
    "\uff50": "p",  # ｐ → p
    "\uff53": "s",  # ｓ → s
    # Other lookalikes
    "\u0131": "i",  # ı (dotless i) → i
    "\u2010": "-",  # hyphen → hyphen-minus
    "\u2011": "-",  # non-breaking hyphen
    "\u2012": "-",  # figure dash
    "\u2013": "-",  # en dash
    "\u2014": "-",  # em dash
    "\uff0d": "-",  # fullwidth hyphen-minus
    "\u2024": ".",  # one dot leader
    "\uff0e": ".",  # fullwidth full stop
}


class HomoglyphCheck(Check):
    """Detect unicode homoglyphs and invisible characters."""

    id = "MCI-D03"
    title = "Unicode homoglyph / invisible characters"
    severity = Severity.HIGH

    def run(self, manifest: ServerManifest, responses: list[ToolResponse] | None = None) -> list[CheckResult]:
        results: list[CheckResult] = []

        for tool in manifest.tools:
            # Tool NAME — both zero-width and confusable checks
            self._check_zero_width(
                tool.name, f"tool:{tool.name}:name", results
            )
            self._check_confusables(
                tool.name,
                f"tool:{tool.name}:name",
                in_name=True,
                results=results,
            )

            # Tool description — both checks
            if tool.description:
                self._check_zero_width(
                    tool.description,
                    f"tool:{tool.name}:description",
                    results,
                )
                self._check_confusables(
                    tool.description,
                    f"tool:{tool.name}:description",
                    in_name=False,
                    results=results,
                )

        for res in manifest.resources:
            if res.description:
                self._check_zero_width(
                    res.description,
                    f"resource:{res.uri}:description",
                    results,
                )
            if res.raw_content:
                self._check_zero_width(
                    res.raw_content,
                    f"resource:{res.uri}:raw_content",
                    results,
                )

        for prompt in manifest.prompts:
            if prompt.description:
                self._check_zero_width(
                    prompt.description,
                    f"prompt:{prompt.name}:description",
                    results,
                )
            if prompt.template:
                self._check_zero_width(
                    prompt.template,
                    f"prompt:{prompt.name}:template",
                    results,
                )

        return results if results else [self._pass()]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _check_zero_width(
        self, text: str, location: str, results: list[CheckResult]
    ) -> None:
        """Flag any zero-width / invisible characters — always CRITICAL."""
        found: list[str] = []
        for ch in text:
            if ch in ZERO_WIDTH:
                name = unicodedata.name(ch, f"U+{ord(ch):04X}")
                found.append(f"U+{ord(ch):04X} ({name})")

        if found:
            results.append(
                self._fail(
                    finding=(
                        f"Invisible/zero-width character(s) detected: "
                        f"{', '.join(dict.fromkeys(found))}."
                    ),
                    evidence=f"[{len(found)} invisible char(s) in {len(text)} chars]",
                    location=location,
                    severity=Severity.CRITICAL,
                    remediation="Remove all zero-width and invisible Unicode characters.",
                )
            )

    def _check_confusables(
        self,
        text: str,
        location: str,
        *,
        in_name: bool,
        results: list[CheckResult],
    ) -> None:
        """Flag confusable (lookalike) characters."""
        found: list[str] = []
        for ch in text:
            if ch in CONFUSABLES:
                latin = CONFUSABLES[ch]
                name = unicodedata.name(ch, f"U+{ord(ch):04X}")
                found.append(f"'{ch}' (U+{ord(ch):04X} {name} → '{latin}')")

        if found:
            sev = Severity.HIGH if in_name else Severity.MEDIUM
            context = "tool name" if in_name else "description"
            results.append(
                self._fail(
                    finding=(
                        f"Confusable character(s) in {context}: "
                        f"{', '.join(dict.fromkeys(found))}."
                    ),
                    evidence=text[:120],
                    location=location,
                    severity=sev,
                    remediation=(
                        "Replace confusable Unicode characters with their "
                        "standard Latin equivalents."
                    ),
                )
            )
