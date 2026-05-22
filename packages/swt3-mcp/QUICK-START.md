# Witness Your AI in 60 Seconds

Listed on the official MCP Registry as `io.tenova/swt3-witness`.

## Prerequisites

- Claude Code, Cursor, Windsurf, or any MCP-compatible host
- Node.js 18+

## Step 1: Add the MCP Server

Add to your MCP configuration (no install required -- npx handles it):

```json
{
  "mcpServers": {
    "swt3-witness": {
      "command": "npx",
      "args": ["@tenova/swt3-mcp"]
    }
  }
}
```

**Claude Code:** `~/.claude/claude_desktop_config.json`
**Cursor:** Settings > MCP Servers
**Windsurf:** `.windsurf/mcp.json`

## Step 2: Try It (Demo Mode)

No API key needed. The server starts in demo mode automatically:

```
> Use the witness_inference tool to witness a test inference

Result: SWT3 anchor minted locally
  procedure: AI-INF.1
  fingerprint: 7a3f9b2c1d4e
  trust_level: 1 (basic)
```

Every tool call is now witnessed. Try `list_procedures` to see all 44 available procedures.

## Step 3: Connect to Axiom (Persistent Ledger)

Create a free account at `https://sovereign.tenova.io/signup`, then set your environment:

```bash
export SWT3_API_KEY=axm_live_your_key_here
export SWT3_TENANT_ID=your_tenant_id
```

Or use a `.swt3.yaml` config:

```yaml
api_key_env: SWT3_API_KEY
tenant_id_env: SWT3_TENANT_ID
clearing_level: 1
```

Restart the MCP server. Anchors now persist to the Axiom ledger.

## Step 4: Verify Your First Anchor

Open `https://sovereign.tenova.io/verify` and paste any fingerprint from the demo output. One click. Tamper-proof verification.

## What Just Happened?

Every tool call your AI agent made was cryptographically witnessed (SHA-256 fingerprint), Merkle-accumulated into a session proof, and trust-evaluated against configurable policy. No code changes to your agent. No latency added to inference. Full regulatory evidence trail for EU AI Act, NIST AI RMF, and CMMC.

## Next Steps

- `check_posture` -- see your compliance coverage
- `verify_anchor` -- verify any anchor from the conversation
- [Full MCP Tools Reference](https://www.npmjs.com/package/@tenova/swt3-mcp)
- [SDK Docs](https://sovereign.tenova.io/docs/)
- [Policy-as-Code (.swt3.yaml)](https://www.npmjs.com/package/@tenova/swt3-ai)
