# @tenova/swt3-mcp

> Listed on the [MCP Registry](https://github.com/modelcontextprotocol/servers) as `io.tenova/swt3-witness`

MCP server for the SWT3 AI Witness protocol. Adds cryptographic compliance attestation to any MCP-compatible AI agent.

SWT3 (Sovereign Witness Traceability) works by hashing your AI's inputs and outputs locally, extracting numeric factors (latency, token count, guardrail status), and anchoring them into a cryptographic fingerprint that anyone can independently verify. Your prompts and responses never leave your machine. The auditor gets tamper-proof evidence. You keep your data.

## Why This Exists

In 2026, MCP configuration injection in Flowise led to arbitrary code execution across thousands of AI workflow instances. A compromised third-party AI tool (Context.ai) pivoted into Vercel's internal systems. Microsoft disclosed RCE vulnerabilities in Semantic Kernel. 65% of firms reported AI agent incidents. Only 14.4% of agents go live with full compliance approval.

Every tool call your agent makes should be witnessed. This server records those calls, evaluates them against declared policy, and produces a cryptographic evidence chain that proves what happened. The audit trail is immutable. If a tool call doesn't match policy, the witness records the violation -- creating proof of what was attempted and what rule applied.

## Trust Mesh -- Secure Agent-to-Agent Communication

Witnessing your own agent is step one. The next question is: can you trust the agent on the other side? Before two agents exchange data, invoke each other's tools, or share context, each side verifies the other's compliance posture. No anchor, no handshake.

**You run Agent A. Your partner runs Agent B. Here's what happens:**

```
Your Agent (A)                    Partner's Agent (B)
     |                                  |
     |--- presentCredential() --------->|
     |                                  |-- verifyTrust(credential)
     |                                  |-- signed? yes
     |                                  |-- procedures witnessed? 12 of 12
     |                                  |-- trust level? 2 (verified)
     |<---------- GRANTED --------------|
     |                                  |
     |    (data exchange begins)        |
     |                                  |
     |<-- presentCredential() ----------|
     |-- verifyTrust(credential)        |
     |-- signed? yes                    |
     |-- trusted tenant? yes            |
     |------------ GRANTED ------------>|
     |                                  |
     |    (bidirectional trust)         |
```

**What each side needs:**

1. Both agents install the SDK (`pip install swt3-ai` or `npm install @tenova/swt3-ai`)
2. Both configure `.swt3.yaml` with signing keys and trust boundaries
3. Both add each other's tenant to `trusted_tenants`
4. Exchange signing keys out-of-band (env vars, secrets manager, KMS)
5. Call `presentCredential()` / `verifyTrust()` before any data exchange

That's it. When you adopt the SWT3 witness layer, your partners and vendors must adopt it too in order to interact with your agents. Compliance becomes the connection protocol. Every agent in the mesh strengthens the network.

```yaml
# Your .swt3.yaml
trust_mesh:
  mode: strict
  min_trust_level: 2
  require_signature: true
  trusted_tenants: ["PARTNER_B_TENANT"]

# Partner's .swt3.yaml
trust_mesh:
  mode: strict
  min_trust_level: 2
  require_signature: true
  trusted_tenants: ["YOUR_TENANT"]
```

**Trust levels:**

| Level | Name | What It Means |
|-------|------|---------------|
| 1 | Basic | Valid credential, no signature verified |
| 2 | Verified | Credential + HMAC signature confirmed |
| 3 | Attested | Verified + hardware attestation + guardrails |
| 4 | Sovereign | Attested + clearing level 2+ |

Unsigned agents are capped at level 1. You decide the minimum level your agents accept. All verification is local. Zero cloud overhead. No data leaves until both sides clear the gate.

## Policy-as-Code (swt3.yaml)

Define your entire witnessing policy in a YAML file. No constructor parameters, no environment variable sprawl:

```bash
# Generate a config from a built-in profile
npx @tenova/swt3-mcp  # reads .swt3.yaml automatically
```

```yaml
# .swt3.yaml
endpoint: https://sovereign.tenova.io
tenant_id: YOUR_TENANT
api_key_env: SWT3_API_KEY
clearing_level: 2
signing_key_env: SWT3_SIGNING_KEY
agent_id: my-agent

trust_mesh:
  mode: strict
  min_trust_level: 2
  require_signature: true

mcp_policy:
  require_witness: true
  blocked_tools: ["shell_exec", "rm_rf"]
```

Layer configs with `extends:` for environment-specific overrides. Three built-in profiles ship with the SDK: `eu-ai-act-high-risk`, `nist-ai-rmf`, and `minimal`.

Validate your config:

```bash
npx swt3 doctor       # 8 checks: YAML, env vars, profile, trust mesh
```

## Zero-config start

```bash
npx @tenova/swt3-mcp
```

That's it. No account, no API key, no configuration. The server starts in demo mode and mints local witness anchors immediately.

Ask your agent to witness an inference and you'll see:

```
Verdict: PASS
Anchor: SWT3-DEMO-LOCAL-AI-AIINF1-PASS-1779146826-ed28dc4c2698
Procedure: AI-INF.1
Model: gpt-4o
Clearing Level: 1
Fingerprint: ed28dc4c2698
```

That fingerprint is a SHA-256 hash of the tenant, procedure, factors, and timestamp. Anyone can recompute it independently. If it matches, the anchor is real. If a single bit changed, the hash breaks.

When you're ready to persist anchors to the SWT3 ledger, use the `signup` tool from within your agent conversation -- no need to leave your editor.

## Setup

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "swt3": {
      "command": "npx",
      "args": ["@tenova/swt3-mcp"]
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "swt3": {
      "command": "npx",
      "args": ["@tenova/swt3-mcp"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add swt3 -- npx @tenova/swt3-mcp
```

## How it works

```
1. Add server to your MCP config         (one line)
2. Start using AI tools as normal         (zero code changes)
3. Ask your agent to witness inferences   (anchors minted locally)
4. Use the signup tool when ready          (free account, never leave your editor)
5. Anchors persist to the SWT3 ledger     (cryptographic compliance trail)
```

## Three modes

| Mode | Config needed | What happens |
|------|--------------|--------------|
| **Demo** | Nothing | Local-only anchors, instant start |
| **API key only** | `SWT3_API_KEY` | Tenant auto-resolved, anchors persisted |
| **Full config** | `SWT3_API_KEY` + `SWT3_TENANT_ID` | Explicit tenant, anchors persisted |

## Regulatory Coverage

Every anchor maps to specific regulatory obligations:

- **EU AI Act**: Articles 9, 10, 12, 13, 14, 53, 72
- **NIST AI RMF**: GOVERN, MAP, MEASURE, MANAGE functions
- **OWASP Agentic Top 10**: Tool abuse, prompt injection, chain exploitation
- **CMMC**: Level 2 evidence automation for defense contractors
- **NIST 800-53**: SI-7 (integrity), AU-2/AU-3 (audit), AC controls
- **SR 11-7**: Model risk management for financial services
- **ISO 42001**: Annex A AI management controls

## Tools (18)

**Witnessing:**
`witness_inference` -- mint a cryptographic anchor for any AI inference. Prompt and response are hashed locally, never sent to the server. Returns verdict (PASS/FAIL), anchor token, and verification URL.

**Verification:**
`verify_anchor` -- verify the cryptographic integrity of an existing anchor.

**Trust Mesh:**
`verify_agent_trust` -- verify another agent's compliance credential.
`present_trust_credential` -- present your agent's credential for verification.

**Audit Sessions:**
`start_audit_session` -- begin a scoped audit session with a session ID.
`end_audit_session` -- close the session and get a summary with Merkle root.

**Agent Chains:**
`start_chain` -- initialize a multi-agent chain with a cycle ID.
`chain_handoff` -- record a handoff between agents in the chain.
`report_violation` -- report a policy violation with severity and category.

**Model Governance:**
`witness_model_integrity` -- witness model weight hashes for tamper detection.
`witness_adapter_stack` -- witness LoRA/adapter configurations.

**Skill Attestation:**
`attest_skill_manifest` -- witness which skills and plugins are loaded.
`attest_memory_context` -- witness which memory sources the agent accesses.

**Authorization:**
`witness_authorization` -- witness pre-inference authorization decisions.

**Discovery:**
`list_procedures` -- browse the UCT procedure registry (204+ controls).
`suggest_procedures` -- get recommended procedures based on your use case.
`check_posture` -- check current tenant compliance posture.
`signup` -- create a free account without leaving your editor.

## Environment variables (optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `SWT3_API_KEY` | demo mode | API key (starts with `axm_`) |
| `SWT3_TENANT_ID` | auto-resolved | Tenant ID (resolved from API key if omitted) |
| `SWT3_ENDPOINT` | `https://sovereign.tenova.io` | Witness endpoint |
| `SWT3_CLEARING_LEVEL` | `1` | Data clearing (0=analytics, 1=standard, 2=sensitive, 3=classified) |
| `SWT3_AGENT_ID` | | Agent identity for AI-ID.1 |
| `SWT3_SIGNING_KEY` | | HMAC-SHA256 signing key (register server-side for validation) |

## Clearing levels

| Level | What leaves the wire |
|-------|---------------------|
| 0 | All metadata |
| 1 | Hashes + model ID + context |
| 2 | Hashes + model ID only |
| 3 | Factors only, model ID hashed |

Raw prompt and response text never leaves your machine at any clearing level.

## Resources

- `swt3://registry/procedures` -- Full UCT procedure catalog
- `swt3://health` -- Service health status

## License

Apache 2.0. Patent pending.

Built by [TeNova](https://tenova.io). Questions: engineering@tenovaai.com
