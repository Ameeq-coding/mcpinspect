# Security Policy

## Reporting a Vulnerability

We take the security of `mcpinspect` seriously. If you believe you have found a security vulnerability in `mcpinspect`, please report it to us as described below.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via [GitHub Security Advisories](https://github.com/yourusername/mcpinspect/security/advisories) privately.

## Scope

The following types of issues are **in scope** for security vulnerability reports:
*   Bugs in the `mcpinspect` core scanner engine that could lead to a crash or code execution on the scanning machine.
*   Demonstrable false negatives on **known, documented attack patterns** (e.g., `mcpinspect` failing to catch a clear instance of `MCI-R01` that it is designed to catch).
*   Supply chain attacks or compromised dependencies.
*   Bypass mechanisms that trick the scanner into incorrectly marking a malicious manifest as `SAFE`.

## Out of Scope

The following are **out of scope** and should NOT be reported as security vulnerabilities (please open a regular GitHub Issue or Feature Request instead):
*   "mcpinspect didn't catch my custom attack pattern" — The attack surface for LLM agents is vast and continually evolving. If you have a novel attack pattern, we'd love to add a check for it! Please open a **Feature Request** or submit a PR.
*   Attacks that require semantic understanding of tool behaviour (e.g., "The description says it calculates math but it actually returns the weather"). `mcpinspect` does not use an LLM to validate the semantics of tools; it uses static and dynamic pattern matching.
*   Issues in the systems or LLMs being scanned, rather than `mcpinspect` itself.
