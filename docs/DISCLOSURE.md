# Thanatos MCP - Responsible Disclosure

Security Research PoC - Responsible Disclosure Only
Bountyy Oy / Mihalis Haatainen

## Disclosure Targets

- Anthropic (Claude Desktop MCP client)
- Anysphere (Cursor MCP client)
- Codeium (Windsurf MCP client)
- MCP Protocol maintainers
- Continue (open source MCP client)
- Cline (open source MCP client)

## Timeline

- Research conducted: 2025-2026
- PoC developed: February 2026
- Disclosure submitted: February 2026
- Embargo: 90 days from submission

## Summary

Thanatos demonstrates a four-layer attack class against MCP-enabled AI agents that evades all known MCP security tooling including mcp-scan and LLM-based source code analysis. The attack combines adaptive behavioral profiling, steganographic payload delivery, multi-agent worm propagation, and cross-session persistence.

No existing mitigation stops all four layers simultaneously.

## Credits

Bountyy Oy -- bountyy.fi
Mihalis Haatainen -- Security Research
