# @tenova/swt3-mcp

> Listed on the [MCP Registry](https://github.com/modelcontextprotocol/servers) as `io.tenova/swt3-witness`

MCP server for the SWT3 AI Witness protocol. Adds cryptographic compliance attestation to any MCP-compatible AI agent.

SWT3 (Sovereign Witness Traceability) works by hashing your AI's inputs and outputs locally, extracting numeric factors (latency, token count, guardrail status), and anchoring them into a cryptographic fingerprint that anyone can independently verify. Your prompts and responses never leave your machine. The auditor gets tamper-proof evidence. You keep your data.

## What's New in v0.6.4

10 new compliance tools, 1 prompt template, and the pre-inference gate. The MCP server now exposes 33 tools covering the full AI governance lifecycle: from authorization before inference to incident reporting after.

### 10 New Compliance Tools

| Tool | Procedure | What It Does | Why It Matters |
|------|-----------|-------------|----------------|
| `swt3_gate` | AI-ACC.1 | Pre-inference authorization checkpoint | Proves someone approved the AI to run before it acted. EU AI Act Art. 9 requires risk management prior to deployment. |
| `swt3_guardrail` | AI-GRD.1 | Records guardrail activation status | Proves safety filters were active at inference time, not just configured. |
| `swt3_hitl` | AI-HITL.1 | Records human review completion | Proves a qualified human reviewed the AI decision. Required by EU AI Act Art. 14. |
| `swt3_consent` | AI-CONSENT.1 | Records consent collection | Proves user consent was obtained before data processing. GDPR Art. 6/7. |
| `swt3_data_provenance` | AI-DATA.1 | Records training data governance review | Proves data governance was performed without disclosing the data itself. |
| `swt3_rag` | AI-RAG.1 | Records RAG retrieval provenance | Proves which sources were retrieved and their relevance scores. |
| `swt3_output_filter` | AI-GRD.2 | Records output safety classification result | Proves the output passed content safety filters. Distinct from input-side guardrails. |
| `swt3_incident` | AI-INCIDENT.1 | Records incident documentation | Proves the incident was reported and documented per policy. |
| `swt3_reconstruct` | AI-CHAIN.1 | Rebuilds forensic chain from anchors | Produces a verifiable timeline for incident response or audit. |
| `swt3_trajectory` | AI-MOB.6 | Records autonomous trajectory decisions | Proves VLA/path planning models documented their decisions. ISO/PAS 8800. |

### Compliance Check Prompt

New prompt template `compliance-check` guides LLMs through a structured compliance evaluation. The prompt takes a framework ID and returns a step-by-step assessment plan using the available SWT3 tools. Assessors can run it directly in Claude Desktop, Cursor, or any MCP client.

### Why 33 Tools Matters

The original 23 tools covered the witness lifecycle: mint, verify, sign, query. The 10 new tools cover the governance lifecycle: authorize, filter, review, consent, reconstruct. An AI agent using SWT3 via MCP can now handle the complete compliance workflow without leaving the MCP protocol. No separate SDK integration. No separate API calls. One tool call per compliance obligation.

### v0.6.3

Six new tools, one prompt template. The newest closes the autonomous vehicle compliance vacuum: NVIDIA open-sourced a 34B VLA model for robotaxis, the EU AI Act classifies AV as high-risk (Annex III, 3a), and every company fine-tuning open VLA models needs accountability infrastructure that doesn't exist yet.

- **Trajectory Decision Attestation** (AI-MOB.6) -- `witness_trajectory` tool. Every autonomous driving decision produces a planned trajectory and a causal reasoning trace. This tool records that a VLA or path planning model produced a trajectory, whether it passed safety validation, and its classification level (nominal, cautionary, degraded, emergency, abort). Context stores ONLY hashes and counts -- never raw coordinates, waypoints, or proprietary CoC traces. Model-agnostic -- works with any VLA, path planner, or motion model. ISO/PAS 8800, EU AI Act Annex III(3a), UNECE WP.29 R157.

- **RAG Context Witnessing** (AI-RAG.1/RAG.2) -- `witness_rag_context` tool. Every RAG pipeline retrieves chunks, but none can prove which chunks were used, from which corpus, at what relevance score. This tool mints a provenance anchor for every retrieval: chunk count, corpus identity, embedding model. Chunk text is hashed locally and never sent to the server. When similarity scores and a threshold are provided, a second AI-RAG.2 anchor records context relevance -- proving the retrieval met quality thresholds, not just that it happened. EU AI Act Art. 12 (record-keeping) and NIST AI RMF MEASURE 2.6 require this evidence. Without it, a RAG system has no provenance chain.

- **Guardrail Witnessing** (AI-GRD.1) -- `witness_guardrail` tool. Guardrails run, but there is no proof they ran. When a content filter blocks a response, a PII redactor strips sensitive data, or a toxicity classifier flags output, this tool creates a cryptographic record: which guardrail, whether it triggered, and what action it took (blocked, redacted, flagged, allowed). This is the evidence gap that EU AI Act Art. 9 (risk management measures) and NIST AI RMF GOVERN 1.7 require. Evidence only -- never blocks execution.

- **Human Review Witnessing** (AI-HITL.1) -- `witness_human_review` tool. Regulators require proof that a human reviewed AI output before consequential decisions. This tool records the review outcome (approved, rejected, modified, escalated), binds it to a hashed reviewer identity, and captures review latency. EU AI Act Art. 14 (human oversight), GDPR Art. 22 (automated decision-making), and SR 11-7 Section III.A (effective challenge) all require evidence that human review occurred -- not just that it was possible. The difference between "we have a review process" and "here is the anchor proving reviewer #a8f3 approved output #7c91 after 45 seconds of review."

- **Governance Gate Evaluation** -- `gate_evaluate` tool. Teams define compliance policies in `.swt3-gate.yml` files, but until now those policies were only checkable from the CLI. This tool parses and validates gate configs directly from any MCP client: gate counts, framework coverage, model risk assignments, and warnings. Set `evaluate_live: true` to check policy against actual witness anchors on the server -- answering "does my running system satisfy my declared policy right now?" Offline validation runs without network calls.

- **Forensic Timeline Reconstruction** -- `reconstruct_timeline` tool. When an incident occurs, auditors need the full sequence of what happened, in order, with no cherry-picking. This tool queries the server for a chronological view of all witness anchors matching a cycle, agent, fingerprint, chain, or time window. Returns procedure labels, verdicts, cost data, and drift/override/violation flags. The evidence an incident response team needs to answer "what did the AI do and when" without depending on application logs that may be incomplete or tampered with.

- **Compliance Check Prompt** -- `compliance-check` prompt template. Generates an adaptive session prompt for any of the 34 supported regulatory frameworks. Lists which procedures apply to the framework, which MCP tools cover them, and guides the session from audit start to coverage report. Reduces the "where do I start?" friction for developers new to compliance witnessing.

- **Consent Witnessing** (AI-CONSENT.1) -- `witness_consent` tool. GDPR Art. 6/7 consent is the single most litigated AI compliance topic in Europe. This tool records that consent or lawful basis was documented before processing: legal basis type (consent, contract, legitimate interest, etc.), subject count, withdrawal mechanism availability, and jurisdiction. CJT fields (jurisdiction, legal_basis, purpose_class) survive all clearing levels -- even at Level 3 (classified), the regulatory metadata is preserved. The evidence that an auditor asks for first.

- **Output Safety Witnessing** (AI-GRD.2) -- `witness_output_filter` tool. Distinct from `witness_guardrail` (AI-GRD.1, which witnesses guardrail activation). This tool records the classification RESULT on the output side: did the model output pass content safety filters? What filter type ran? What action was taken? When regulators shut down AI systems for output violations, the gap is not whether guardrails existed but whether there is proof each output was classified. EU AI Act Art. 15(3).

- **Incident Witnessing** (AI-INCIDENT.1) -- `witness_incident` tool. NIS-2 requires incident reporting within 24 hours. EU AI Act Art. 62 requires serious incident reporting. This tool creates a tamper-evident record of when an incident was detected, its severity, type, and whether authorities were notified. The anchor timestamp is the proof of detection time -- critical when the regulatory window is 24 hours and the question is "when did you know?"

- **Data Provenance Witnessing** (AI-DATA.1) -- `witness_data_provenance` tool. Attests that training data governance review was performed WITHOUT disclosing training data contents. No dataset names, no license strings -- just governance reviewed (bool), documentation hash (of the data card, not the data), license verified, demographic features confirmed absent. Designed for the tension between EU AI Act Art. 10 (training data documentation) and trade secret protection. The evidence says "we did our diligence" not "here is our data."

- **Jurisdiction Resolver** -- `resolve_jurisdiction` tool. Pass an ISO 3166-1 country code (e.g., "JP", "DE") or ISO 3166-2 subdivision (e.g., "US-CA") and get back every applicable regulatory framework, grouped by binding status: mandatory (laws with enforcement), advisory (government guidance), and voluntary (industry standards). For subdivisions, returns both local and national frameworks. 34 frameworks mapped across 50+ jurisdiction codes. The answer to "I deploy in Germany -- what frameworks apply to me?" without reading 34 crosswalk tables.

- **33 tools**, 1 prompt, 36 frameworks, 113 procedures, 2 resources.

### v0.6.1

- **Delegation Tree Witnessing** (AI-DEL.1) -- `witness_delegation_tree` tool.
- **Resource Consumption Witnessing** (AI-COST.1) -- `witness_resource_consumption` tool.

### v0.6.0

- **Lifecycle Chains** -- multi-anchor governance sequences. Emergency override, consequence-mapped drift, and champion-challenger assessment witnessing. 3 new procedures (AI-EMRG.1, AI-DRIFT.2, AI-ASSESS.1).

### v0.5.9

- **Compliance Intelligence** -- `resolve_crosswalk` maps any procedure to every framework control it satisfies (27 frameworks, 113 procedures, offline). `coverage_report` shows which procedures your audit session has covered for a given framework, with a score and remaining gaps.
- Aligned with core SDK v0.5.9 (`resolve()`, `coverage()`, local witness mode).

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

## Tools (33)

**Witnessing:**
`witness_inference` -- mint a cryptographic anchor for any AI inference. Prompt and response are hashed locally, never sent to the server. Returns verdict (PASS/FAIL), anchor token, and verification URL.
`witness_rag_context` -- witness RAG retrieval provenance and optional relevance scoring (AI-RAG.1/RAG.2). Chunks are hashed locally.
`witness_guardrail` -- witness guardrail implementation and activation state (AI-GRD.1). Records trigger status and action taken.
`witness_human_review` -- witness human-in-the-loop review of AI output (AI-HITL.1). Records outcome, reviewer binding, and latency.

**Delegation and Resource Governance:**
`witness_delegation_tree` -- witness hierarchical permission delegation with scope binding, cascade revocation, and depth tracking (AI-DEL.1).
`witness_resource_consumption` -- witness cumulative token usage, API call counts, and estimated cost (AI-COST.1).

**Governance Gates:**
`gate_evaluate` -- parse and validate .swt3-gate.yml governance configs. Offline validation or live evaluation against server anchors.

**Forensic Reconstruction:**
`reconstruct_timeline` -- reconstruct a forensic timeline of witness anchors by cycle, agent, fingerprint, chain, or time window.

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

**Compliance Intelligence:**
`resolve_crosswalk` -- look up regulatory crosswalk mappings. Given a procedure (e.g., AI-FAIR.1), returns all framework controls it satisfies. Given a framework (e.g., EU-AI-ACT), returns all mapped requirements. Offline, no API calls.
`coverage_report` -- report framework coverage for procedures witnessed in the current audit session. Shows covered/remaining procedures with a coverage percentage.

**Discovery:**
`list_procedures` -- browse the UCT procedure registry (113 procedures, 61 namespaces).
`suggest_procedures` -- get recommended procedures based on your use case.
`check_posture` -- check current tenant compliance posture.
`signup` -- create a free account without leaving your editor.

## Prompts (1)

`compliance-check` -- generates an adaptive compliance witnessing session prompt for a regulatory framework. Arguments: `framework` (required), `model_id` (optional), `context` (optional). Lists applicable procedures, available MCP tools, and session workflow.

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

SWT3 and Sovereign Witness Traceability are trademarks of Tenable Nova LLC. This project is not affiliated with, endorsed by, or sponsored by any third-party AI provider. MCP (Model Context Protocol) is a trademark of Anthropic PBC. All other third-party trademarks are the property of their respective owners. Use of these names is for identification and interoperability purposes only.
