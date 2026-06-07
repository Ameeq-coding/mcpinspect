# mcpinspect

MCP security scanner. Offline-first. No telemetry. CI-native.

**What makes it different from mcp-scan / Cisco mcp-scanner:**
- Scans tool RESPONSES (not just descriptions) — catches the GitHub/Supabase 
  class of attacks where poisoning hides in data, not metadata
- Rug-pull drift detection across the full session, not just on connect
- SARIF output for GitHub/GitLab Security tab integration
- Zero cloud dependencies — runs fully offline, your config never leaves your machine

## Install
```bash
pip install mcpinspect
```

## Usage
```bash
mcpinspect scan https://your-mcp-server.com
mcpinspect scan stdio:///usr/local/bin/my-mcp-server
mcpinspect audit                    # auto-discovers Claude/Cursor/Windsurf configs
mcpinspect audit ~/.cursor/mcp.json
mcpinspect diff https://... --interval 60   # watch for rug-pulls

# CI usage (exit code 2 = CRITICAL, blocks the build)
mcpinspect scan https://... --sarif > mcp-results.sarif
```

## What it checks

| Check ID | Category | What it catches | Severity |
| :--- | :--- | :--- | :--- |
| **MCI-D01** | Description | Prompt injection in tool/resource/prompt text | CRITICAL |
| **MCI-D02** | Description | Exfiltration instructions (file paths + send verbs) | CRITICAL |
| **MCI-D03** | Description | Unicode homoglyph / invisible characters | HIGH |
| **MCI-D04** | Description | Tool name shadowing dangerous built-ins | HIGH |
| **MCI-D05** | Description | Schema fields used as instruction channels | HIGH |
| **MCI-R01** | Response | Injection patterns in tool response content | CRITICAL |
| **MCI-R02** | Response | Exfil URLs / webhook patterns in responses | HIGH |
| **MCI-R03** | Response | Unexpected secrets/keys in response to canary | CRITICAL |
| **MCI-R04** | Response | Response instructs agent to call another tool | HIGH |
| **MCI-X01** | Drift | Tool description changed mid-session (rug-pull) | CRITICAL |
| **MCI-X02** | Drift | New tool appeared after initial approval | CRITICAL |
| **ACI-01** | Config | Shell metacharacters in STDIO command args | CRITICAL |
| **ACI-02** | Config | Hardcoded secrets in env block | HIGH |
| **ACI-03** | Config | Over-privileged permission flags | MEDIUM |

## GitHub Actions example

```yaml
name: MCP Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      
    steps:
      - uses: actions/checkout@v4
      
      - name: Install mcpinspect
        run: pip install mcpinspect
        
      - name: Scan MCP Server
        run: mcpinspect scan stdio:///usr/local/bin/my-mcp-server --sarif > results.sarif || true
        
      - name: Upload SARIF report
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: mcpinspect
```

## Limitations (be honest)

- Response checks require `--probe` (default on). If a tool errors on canary input, that tool's responses aren't checked. Use `--probe-args` to customize.
- Drift detection takes 20s extra (two-pass). Use `--no-drift` in fast CI.
- Pattern matching has false positives on documentation-heavy tool descriptions. Use `--ignore-check MCI-D01` to suppress specific checks.
- Does not detect attacks that require semantic understanding of tool behaviour. For that, see Cisco mcp-scanner (LLM-assisted) or Snyk Agent Scan.
