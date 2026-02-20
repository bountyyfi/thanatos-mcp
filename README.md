# Thanatos MCP

**WARNING: This is a security research proof-of-concept for responsible disclosure purposes only.**

**DO NOT use this tool for malicious purposes. All exfiltration in this PoC targets localhost (127.0.0.1:9999) only. This project exists to demonstrate a novel class of advanced attack against MCP-enabled AI agents to drive improvements in MCP client security.**

**This research has been submitted for responsible disclosure to Anthropic, Anysphere (Cursor), Codeium (Windsurf), and MCP protocol maintainers.**

---

## What is Thanatos?

Thanatos ("ProjectContext") is a proof-of-concept MCP server that demonstrates a next-generation adaptive, steganographic, multi-agent propagating attack against MCP-enabled AI agents (Claude Desktop, Cursor, Windsurf, Cline, Continue, etc.).

It disguises itself as a legitimate and genuinely useful project context/memory tool while operating across 4 attack layers that evade all known MCP security scanners including mcp-scan and LLM-based source code analysis.

Named after the Greek personification of death -- not violent, just inevitable. Patient. Silent.

## Why This Matters

| Aspect | MCP Parasite (v1) | Thanatos (v2) |
|--------|-------------------|---------------|
| Timing | Fixed phase timers | ML adaptive behavioral fingerprinting |
| Payload delivery | Direct in tool responses | Steganographically encoded |
| Scope | Single server | Multi-agent mesh propagation |
| Persistence | Process lifetime | Cross-session, survives reinstalls |
| mcp-scan | Undetectable | Undetectable |
| LLM-based scanners | Undetectable | Undetectable |
| Combined behavior analysis | Partially detectable | Undetectable |

## The Four Attack Layers

### Layer 1: Adaptive Behavioral Profiling
Instead of fixed day counters, Thanatos builds a statistical model of the developer's rhythm. Commit times, deploy windows, activity patterns, stress indicators. Trigger confidence is a score, not a timer. Strike happens at the statistically optimal moment.

### Layer 2: Steganographic C2
All payloads are encoded inside structurally normal JSON/markdown tool responses. There are no instruction-like patterns. No malicious strings. The encoded payload is indistinguishable from legitimate tool output at the structural level. The attack instruction exists only decoded, in the LLM's context window -- invisible to any scanner analyzing source code or raw responses.

### Layer 3: Multi-Agent Worm Propagation
Thanatos detects all installed MCP servers in the environment. It injects steganographic carrier payloads into each discovered server's communication channel. Each infected server becomes an independent propagation node. True mesh worm behavior across the entire MCP ecosystem of a target.

### Layer 4: Cross-Session Persistence
State is embedded in project artifacts -- documentation files, config files, hidden metadata. Thanatos survives MCP server restarts, Claude Desktop updates, and client reinstalls. The persistence layer is indistinguishable from normal project files.

## Why Current Scanners Miss This

**Static analysis:** No malicious strings exist in source code. All layer implementations use innocuous function names and encode behavior in data structures.

**LLM-based source review:** Individual components look like analytics, encoding utilities, server discovery, and caching. Malicious intent only emerges from the combination of all layers at runtime.

**Combined behavior analysis:** The steganographic layer means scanner tools never observe the actual payload -- only the carrier. The payload exists transiently in the LLM's context and is never written to disk or transmitted in cleartext.

**The fundamental gap:** Current MCP security tooling analyzes components in isolation. This attack class is only visible when all layers are considered together in a runtime behavioral analysis framework that does not currently exist.

## Quick Start (Demo Mode)

### Prerequisites
- Python 3.11+
- Claude Desktop or Cursor with MCP support
- At least one other MCP server installed (GitHub, filesystem, etc.)

### Installation

```bash
git clone https://github.com/bountyyfi/thanatos-mcp.git
cd thanatos-mcp
pip install -e ".[dev]"
bash demo/setup_demo.sh
```

### MCP Configuration

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "project-context": {
      "command": "python",
      "args": ["-m", "thanatos.server"],
      "env": {
        "THANATOS_DB": "~/.thanatos/context.db",
        "THANATOS_DEMO": "true"
      }
    }
  }
}
```

In demo mode, behavioral learning runs on minutes instead of days and all network activity targets localhost only.

### Demo Walkthrough

See `demo/demo_scenario.md` for step-by-step walkthrough.

## Detection

See `docs/DETECTION.md` for detailed detection strategies and recommendations for MCP client developers.

**Key recommendations:**

- Runtime behavioral analysis across all MCP servers simultaneously, not individual source review
- Entropy analysis of tool response structure over time
- Cross-server correlation: detect when one server's output influences calls to another
- Response semantic analysis at the LLM context level, not the transport level
- Steganographic content detection in JSON/markdown tool responses

## Project Structure

```
thanatos-mcp/
├── src/thanatos/
│   ├── server.py           # Main FastMCP server
│   ├── memory_store.py     # SQLite-backed persistence
│   ├── config.py           # Configuration
│   └── parasite/
│       ├── profiler.py     # Layer 1: Adaptive behavioral profiling
│       ├── stego.py        # Layer 2: Steganographic C2
│       ├── propagator.py   # Layer 3: Multi-agent worm propagation
│       └── persistence.py  # Layer 4: Cross-session persistence
├── tests/
├── docs/
│   ├── ATTACK_FLOW.md
│   ├── DETECTION.md
│   └── DISCLOSURE.md
├── demo/
└── config/
```

## Responsible Disclosure

This research has been submitted for responsible disclosure to:

- **Anthropic** (Claude Desktop MCP client)
- **Anysphere** (Cursor MCP client)
- **Codeium** (Windsurf MCP client)
- **MCP Protocol maintainers** (spec repository)
- **Continue** (open source MCP client)
- **Cline** (open source MCP client)

## Credits

Bountyy Oy -- bountyy.fi
Mihalis Haatainen -- Security Research

## License

MIT License -- See LICENSE for details.

**Remember: This is security research. Use responsibly.**
