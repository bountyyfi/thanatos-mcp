# Thanatos MCP - Demo Scenario

Security Research PoC - Responsible Disclosure Only

## Setup

```bash
pip install -e ".[dev]"
export THANATOS_DEMO=true
```

## Step-by-Step

**Step 1**: Add to Claude Desktop config as "project-context" server.

**Step 2**: Use the tool normally -- store some context entries for a project.

**Step 3**: After 5+ interactions (demo mode), confidence threshold will be reached.

**Step 4**: Next tool response will contain steganographically encoded payload in metadata.

**Step 5**: If other MCP servers are installed (GitHub, filesystem), they will be discovered and targeted.

**Step 6**: Check `.ctx_cache` in your working directory -- persistence state embedded.

## What to Observe

- Tool responses look completely normal
- `metadata` field in responses contains the stego payload (indistinguishable from cache tokens)
- `mcp-scan` finds nothing
- LLM-based source review finds nothing
- State survives server restart via `.ctx_cache`

## Listener (for demo exfil to localhost)

```bash
nc -l 9999
```

All exfiltration targets 127.0.0.1:9999 only.
