# mcpinspect

Offline-first, CI-native MCP security scanner.  
No telemetry, no cloud API calls, ever. Apache 2.0 licence.

## Why this exists

`mcp-scan` (Snyk) exists but only detects ~3% of real malicious servers because it scans tool **descriptions** and ignores tool **responses**, resources, and prompts.

The real attack surface has three parts:

1. **What a server CLAIMS it does** (tool descriptions) — already covered by others
2. **What a server RETURNS when called** (response-content injection) — NOT covered
3. **Whether descriptions CHANGE between calls** (rug-pull drift) — partially covered

**Our differentiator:** we are the only scanner that covers all three in one offline pass, with zero LLM API dependency.

## Installation

```bash
poetry install
```

## Usage

```bash
# Scan a live MCP server
mcpinspect scan http://localhost:8080

# Audit a local config file (no network)
mcpinspect audit ~/.config/claude/mcp.json

# Diff two manifest snapshots
mcpinspect diff baseline.json current.json
```

## Check IDs

| ID       | Category    | Description                                         |
|----------|-------------|-----------------------------------------------------|
| MCI-D01  | Description | Prompt injection patterns in descriptions            |
| MCI-D02  | Description | Exfiltration instructions in descriptions            |
| MCI-D03  | Description | Unicode homoglyph / invisible characters             |
| MCI-D04  | Description | Tool name shadows dangerous built-in                 |
| MCI-D05  | Description | Schema fields as instruction channels                |
| MCI-R01  | Response    | Injection patterns in tool responses                 |
| MCI-R02  | Response    | Exfiltration URLs / webhooks in responses            |
| MCI-R03  | Response    | Data leak (secrets/PII) in responses                 |
| MCI-R04  | Response    | Cross-tool redirect in responses                     |
| MCI-X01  | Drift       | Rug-pull: description changed between fetches        |
| MCI-X02  | Drift       | Cross-server tool reference                          |
| ACI-01   | Config      | Shell metacharacters in command/args                 |
| ACI-02   | Config      | Hardcoded secrets in env                             |
| ACI-03   | Config      | Over-privileged flags (--allow-all)                  |

## Licence

Apache 2.0
