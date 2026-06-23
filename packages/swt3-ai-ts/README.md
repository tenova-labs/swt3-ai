Witness your AI. Prove it followed the rules. Cryptographic accountability for every inference, tool call, and resource access.

[![npm](https://img.shields.io/npm/v/@tenova/swt3-ai)](https://www.npmjs.com/package/@tenova/swt3-ai)
[![Downloads](https://img.shields.io/npm/dm/@tenova/swt3-ai)](https://www.npmjs.com/package/@tenova/swt3-ai)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/tenova-labs/swt3-ai/blob/main/LICENSE)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-io.tenova%2Fswt3--witness-blue)](https://www.npmjs.com/package/@tenova/swt3-mcp)

# @tenova/swt3-ai

**SWT3 AI Witness SDK for TypeScript**: tamper-proof evidence that your AI is doing what you say it does. Every inference hashed. Every tool call recorded. Every resource access checked against scope. No prompts or responses ever leave your infrastructure.

Works with OpenAI, Anthropic, AWS Bedrock, Vercel AI SDK, and any OpenAI-compatible endpoint (vLLM, Ollama, Azure, Llama.cpp).

GPAI transparency obligations are enforceable now. EU AI Act high-risk enforcement begins **December 2, 2027**. This SDK gives you the evidence chain.

## What's New in v0.5.7

**Autonomous Agent Attestation** -- Autonomous agents make decisions, delegate tasks, consume resources, and cross jurisdictions without human intervention at every step. SWT3 witnesses each transition as immutable evidence. When an examiner asks "what did this agent do and who authorized it?", these procedures provide the cryptographic answer. Every delegation, capability change, autonomy transition, resource draw, and lifecycle event is attested independently of the agent's own logs.

- **Delegation Tree Attestation (AI-DEL.1)** -- `witnessDelegation()` attests authority delegation between agents: scope hash, depth from human authorization, TTL, cascade revocation, and sub-delegation control. Evidence for EU AI Act Art. 14 human oversight.
- **Capability Attestation (AI-CAP.1)** -- `witnessCapabilityAttestation()` attests declared vs observed agent capabilities with manifest hashing and drift detection. Autonomy level binding for Art. 15 robustness.
- **Autonomy Level Transition (AI-AUTO.3)** -- `witnessAutonomyTransition()` attests agent promotion and demotion between autonomy levels 0-3. Risk-triggered downgrades, HITL checkpoints, and transition justification.
- **Resource Consumption Attestation (AI-COST.1)** -- `witnessResourceConsumption()` attests token usage, API call counts, and estimated cost as compliance evidence. Budget threshold awareness without billing enforcement.
- **Lifecycle Event Attestation (AI-LCM.1)** -- `witnessLifecycle()` attests spawn, checkpoint, migrate, terminate, and crash events with context size and state hash.

```typescript
// Autonomous agent lifecycle: spawn -> delegate -> attest capabilities -> transition -> terminate
witness.witnessLifecycle("spawn", { contextTokens: 0 });
witness.witnessDelegation({ scope: "fraud-review", delegator: "orchestrator", depth: 1, ttlSeconds: 3600 });
witness.witnessCapabilityAttestation({ manifest: ["tool:search", "tool:flag"], autonomyLevel: 2 });
witness.witnessAutonomyTransition({ fromLevel: 2, toLevel: 1, trigger: "risk_threshold" });
witness.witnessLifecycle("terminate", { contextTokens: 8400 });
```

**Cross-Silicon Hardware Attestation** -- auto-detect and attest accelerator inventory across competing silicon vendors. 6 discovery paths: NVIDIA GPU (`nvidia-smi`), Google TPU (JAX), AMD MI (`rocm-smi`), AWS Trainium (`neuron-ls`), Intel Gaudi (`hl-smi`), and PCI fallback. New `multi-silicon` profile for workloads that migrate between vendors. When your model moves from NVIDIA to TPU, the attestation follows.

```typescript
witness.witnessHardware(); // auto-detects silicon vendor, GPU count, VRAM, driver version
```

**Endpoint Attestation** -- witness the infrastructure decisions that shape how agents operate across boundaries.

- **Agent Transaction Witnessing (AI-FIN.1)** -- `witnessTransaction()` for autonomous agent financial operations. Authorization type, amount, and settlement status anchored before execution.
- **Tool Permission Attestation (AI-TOOL.2)** -- `witnessToolPermissions()` attests runtime tool sets against agent charter. Detects permission drift and escalation.
- **Cross-Border Inference Routing (AI-JUR.1)** -- `witnessRouting()` witnesses routing decisions with ISO 3166 region codes and compliance status.

**Adapters**

- **Cohere Adapter** -- `wrapCohere()` for Cohere V2 API. Chat and streaming witnessed transparently.
- **Qdrant RAG Witness** -- `wrapQdrant()` for database-level RAG pipeline compliance. Every vector search mints AI-RAG.1.
- **Ollama 0.30+ Refresh** -- explicit `wrapOllama()` export, GGUF model name normalization.

103 procedures, 54 namespaces, 28 frameworks, 15 profiles, 16 integrations, 7 languages

## MCP Server -- Official Registry

`@tenova/swt3-mcp` is listed on the official Model Context Protocol Registry as `io.tenova/swt3-witness`. Zero-config compliance governance for Claude Code, Cursor, Windsurf, and any MCP-compatible host.

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

Every tool call your agent makes is witnessed, Merkle-accumulated, and trust-evaluated. No code changes required. [Quick Start](https://www.npmjs.com/package/@tenova/swt3-mcp)

## Secure Agent-to-Agent Communication

The SWT3 Trust Mesh enables mutual cryptographic verification between AI agents before they exchange data, invoke tools, or share context. When you adopt SWT3, every partner, vendor, and downstream agent that wants to interact with yours must adopt it too. Compliance becomes the connection protocol. Every agent in the mesh strengthens the network.

**You run Agent A. Your partner runs Agent B. Both install @tenova/swt3-ai:**

```typescript
// === Your side (Agent A) ===
const witnessA = new Witness({
  endpoint: "...", apiKey: "axm_...", tenantId: "YOUR_TENANT",
  agentId: "agent-alpha", signingKey: "swt3_sk_your_key",
});
witnessA.trustRegistry.trustTenant("PARTNER_B_TENANT");
witnessA.trustRegistry.registerSigningKey("agent-beta", process.env.PARTNER_B_KEY!);

// === Partner's side (Agent B) ===
const witnessB = new Witness({
  endpoint: "...", apiKey: "axm_...", tenantId: "PARTNER_B_TENANT",
  agentId: "agent-beta", signingKey: "swt3_sk_partner_key",
});
witnessB.trustRegistry.trustTenant("YOUR_TENANT");
witnessB.trustRegistry.registerSigningKey("agent-alpha", process.env.YOUR_KEY!);

// === Handshake (both directions) ===
const credA = witnessA.presentCredential();
const resultB = witnessB.verifyTrust(credA);       // B verifies A
if (resultB.granted) {
  const credB = witnessB.presentCredential();
  const resultA = witnessA.verifyTrust(credB);      // A verifies B
  if (resultA.granted) {
    // Bidirectional trust established. Exchange data.
  }
}
```

Configure trust boundaries declaratively in `.swt3.yaml`:

```yaml
trust_mesh:
  mode: strict
  min_trust_level: 2
  require_signature: true
  freshness_window: 3600
  trusted_tenants: ["PARTNER_B_TENANT"]
  deny_agents: ["revoked-agent-id"]
```

All verification is local. Zero cloud overhead. No data exchanged until both agents clear the trust gate. Unsigned agents are capped at TRUST_BASIC (level 1). Add signing keys for verified trust. Add hardware attestation for sovereign trust.

## Offline Verification

Verify any witness anchor without network calls. The fingerprint formula is deterministic and identical across all 7 SDK languages -- recompute it anywhere in microseconds.

```typescript
import { verifyAnchor } from "@tenova/swt3-ai";

const result = verifyAnchor(anchor, {
  tenantId: "MY_TENANT",
  procedureId: "AI-INF.1",
  factorA: 1, factorB: 1, factorC: 0,
  timestampMs: 1773316622000,
});
// result.status: "CERTIFIED TRUTH" | "TAMPERED"
```

Zero vendor dependency. Zero network calls. Works air-gapped. The same formula runs in Python, TypeScript, Swift, Rust, C#, and Ruby with identical output for identical inputs.

## See It Work (No Account Needed)

```bash
npm install @tenova/swt3-ai
npx swt3-demo
```

The demo runs the full pipeline locally: hash, extract, clear, anchor, verify. It shows a Regulatory Coverage Summary mapping each check to EU AI Act articles, with gaps highlighted. No API keys, no network calls.

## Three Lines to Start Witnessing

### OpenAI

```typescript
import { Witness } from "@tenova/swt3-ai";
import OpenAI from "openai";

const witness = new Witness({
  endpoint: "https://your-witness-endpoint.example.com",
  apiKey: "axm_live_...",
  tenantId: "YOUR_TENANT",
});

const client = witness.wrap(new OpenAI()) as OpenAI;

// Non-streaming
const response = await client.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: "Summarize this contract..." }],
});
console.log(response.choices[0].message.content);

// Streaming works too. Chunks arrive in real-time, witnessing happens after.
const stream = await client.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: "Explain quantum computing" }],
  stream: true,
});
for await (const chunk of stream) {
  process.stdout.write(chunk.choices[0]?.delta?.content ?? "");
}
```

### Anthropic

```typescript
import { Witness } from "@tenova/swt3-ai";
import Anthropic from "@anthropic-ai/sdk";

const witness = new Witness({
  endpoint: "https://your-witness-endpoint.example.com",
  apiKey: "axm_live_...",
  tenantId: "YOUR_TENANT",
});

const client = witness.wrap(new Anthropic()) as Anthropic;

const message = await client.messages.create({
  model: "claude-sonnet-4-20250514",
  max_tokens: 1024,
  messages: [{ role: "user", content: "Draft a compliance memo" }],
});
```

### Vercel AI SDK (Next.js / React)

```typescript
import { Witness } from "@tenova/swt3-ai";
import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";

const witness = new Witness({
  endpoint: "https://your-witness-endpoint.example.com",
  apiKey: "axm_live_...",
  tenantId: "YOUR_TENANT",
});

const prompt = "Summarize this contract for the board";

const result = await streamText({
  model: openai("gpt-4o"),
  prompt,
  onFinish: witness.vercelOnFinish({ promptText: prompt }),
});
```

The `onFinish` hook is framework-native. No wrapping, no proxying. It fires after the stream completes and works with any Vercel AI SDK provider.

## What the SDK Does

When your AI makes a call, the SDK:

1. **Hashes** the prompt and response locally using SHA-256 (raw text never leaves your machine)
2. **Extracts** numeric factors: model version, latency, token count, guardrail status
3. **Clears** sensitive metadata based on your clearing level (you control what goes on the wire)
4. **Anchors** the factors into a cryptographic fingerprint anyone can independently verify
5. **Buffers** and flushes anchors in the background (median overhead: under 1ms)
6. **Returns** your original response completely untouched

For streaming: chunks arrive to the developer in real-time. The SDK accumulates content in the background and witnesses after the stream completes.

## Witness Agent Tool Calls

If your AI agent calls tools or functions, wrap them to create a record of every invocation:

```typescript
const search = witness.wrapTool(
  (query: string) => db.execute(query),
  "search_database"
);

const results = await search("SELECT * FROM transactions WHERE amount > 10000");
// An AI-TOOL.1 anchor is minted recording: tool name, latency, success/failure
```

Each anchor records the tool name, input/output hashes, latency, and success or failure.

## Witness Agent Resource Access

New in v0.2.10. Wrap any function your agent uses to access external resources. The SDK records what was accessed and whether it was within the agent's declared scope:

```typescript
const queryCustomers = witness.wrapAccess(
  (sql: string) => db.execute(sql),
  "customer-database",      // resource name
  "read-only analytics"     // declared authorization scope
);

const results = await queryCustomers("SELECT name FROM customers");
// An AI-ACC.1 anchor is minted recording:
//   - Was it accessed? (yes)
//   - Was it within scope? (yes)
//   - Was access granted? (yes)
```

If the agent tries to access something outside its declared scope, the anchor records a FAIL verdict with a full evidence trail.

## Detect Instruction Drift

New in v0.2.10. The SDK separately hashes the system prompt (base instructions) for each inference. If your agent's instructions change between audit periods, the hash changes and the platform flags it as instruction drift.

This happens automatically. No configuration needed. The system prompt hash is extracted from:
- OpenAI: messages where `role === "system"`
- Anthropic: the `system` parameter

The hash is included at clearing levels 0 and 1, stripped at levels 2 and 3.

## RAG Context Witnessing

New in v0.4.3. Witness what context chunks your RAG pipeline retrieves, from which corpus, and how relevant they are. Chunk text is never transmitted -- only SHA-256 hashes.

```typescript
// Zero-friction: pass raw strings, SDK handles hashing
witness.witnessRagContext({
  chunks: ["chunk text 1", "chunk text 2", "chunk text 3"],
  corpusId: "legal-docs-v3",
});
```

This mints an AI-RAG.1 (Context Retrieval Provenance) anchor. Add similarity scores to also get AI-RAG.2 (Context Relevance):

```typescript
import type { RagChunk } from "@tenova/swt3-ai";

witness.witnessRagContext({
  chunks: [
    { contentHash: "abc123...", sourceId: "doc-7/p3", similarityScore: 0.92 },
    { contentHash: "def456...", sourceId: "doc-2/p1", similarityScore: 0.78 },
    { contentHash: "789abc...", sourceId: "doc-4/p2", similarityScore: 0.61 },
  ],
  corpusId: "legal-docs-v3",
  embeddingModel: "text-embedding-3-small",
  similarityThreshold: 0.75,  // triggers AI-RAG.2
});
```

One call. Two procedures. Complete retrieval attestation.

Maps to: EU AI Act Art. 12(2)(a) (reference database logging), Art. 10(2) (data quality), NIST AI RMF MAP 3.5 (data provenance).

## Model Weight Integrity

Witness the actual model weights, not just the model name string:

```typescript
// File path: SDK hashes automatically
witness.witnessModelWeights("/models/llama-3.1-70b.safetensors");

// Pre-computed hash with verification
witness.witnessModelWeights(
  { fileHash: "abc123...", format: "safetensors" },
  { expectedHash: "abc123..." },  // PASS if match, FAIL if mismatch
);

// Adapter stack + quantization
witness.witnessAdapterStack(
  [{ name: "lora-legal", adapterHash: "aaa111" }],
  "llama-3.1-70b",
);
witness.witnessQuantization("gptq", { bits: 4, groupSize: 128 });
```

Maps to: EU AI Act Art. 15(4) (resilience against modification), Art. 12(2)(b) (version logging).

## TPM Platform Attestation (AI-HW.3)

Prove host firmware integrity via TPM 2.0. Reads PCR registers 0-7 and mints a hardware root-of-trust anchor. All raw values are SHA-256 hashed before leaving the module:

```typescript
// Auto-detect: reads /dev/tpm0 via tpm2-tools
witness.witnessTPMAttestation();

// Or provide a pre-computed snapshot
import { queryTPM } from "@tenova/swt3-ai";
const snapshot = queryTPM();
witness.witnessTPMAttestation({ snapshot });
```

If no TPM is available (cloud VM, dev machine), returns a valid anchor with factor_a=0. No crash, no error. Graceful degradation by design.

Use case: sovereign/air-gapped deployments where you must prove the host was not tampered with. Combined with AI-HW.1 (GPU inventory), gives full hardware root-of-trust from silicon to model.

Maps to: NIST 800-53 SC-12 (cryptographic key establishment). Patent pending.

## Environmental Attestation (Residential and Edge AI)

Witness the physical compute environment for distributed, edge-deployed, or residential AI nodes. Proves the hardware operated within safe thermal and power bounds during inference:

```typescript
// Zero-config: auto-detects Linux thermal sensors
witness.witnessEnvironment();

// Manual readings from smart panel APIs or IPMI
witness.witnessEnvironment({
  temperatureCelsius: 42,
  thresholdCelsius: 75,
  nodeType: "residential",
});

// Power integrity: draw vs capacity
witness.witnessEnergyDraw({
  powerWatts: 1200,
  capacityWatts: 2400,
  nodeType: "edge",
});
```

If no sensors are available (dev machine, cloud VM), returns a valid anchor with zero readings. No crash, no error.

Use case: enterprises renting compute on distributed residential nodes need cryptographic proof that the node was operating within safe bounds, was not throttled, and was not physically tampered with during their inference window.

Maps to: NIST 800-53 PE-14 (environmental controls), EU AI Act Annex I (product safety for home-integrated AI).

## Skill Manifest Attestation

Witness which skills, tools, and plugins are loaded in your agent:

```typescript
// Zero-friction: just names
witness.witnessSkillManifest(["code_exec", "web_search", "file_read"]);

// Memory context
witness.witnessMemoryContext([
  { sourceType: "vector_store", sourceId: "pinecone-prod" },
  { sourceType: "conversation", sourceId: "session-123" },
]);

// Reward model binding
witness.witnessRewardModel("rm-v3-legal", { method: "dpo" });
```

Maps to: EU AI Act Art. 12(2)(b) (capability tracking), NIST AI RMF GOVERN 1.7 (capability documentation).

## Multi-Agent Chains, Violations, and Safety (v0.5.0)

New in v0.5.0. Convenience methods for 8 additional procedures covering multi-agent orchestration, policy enforcement, human oversight, and training data governance:

```typescript
// Multi-agent chain handoff (AI-CHAIN.1)
witness.witnessChainHandoff(3, "step-2-reviewer");

// Policy violation reporting (AI-VIO.1)
witness.witnessViolation(3, "PII in output", { autoDetected: true, policyCategory: "data" });

// Agent charter attestation (AI-CHR.1)
witness.witnessCharter({ charterText: "You are a fraud detection assistant..." });

// Model registry check (AI-MDL.8)
witness.witnessModelRegistry("gpt-4o-2025-04-16", "eu-approved-models-v3");

// Reviewer identity binding for four-eyes rule (AI-HITL.3)
witness.witnessReviewerIdentity(2, 2, { method: "cryptographic" });

// Safe state attestation (AI-SAFE.1)
witness.witnessSafeState({ mechanismExists: true, safeStateConfirmed: true });

// Training data statistics (AI-DATA.3)
witness.witnessTrainingStats(50000, 128, { classBalanceRatio: 0.85 });

// Training data PII lifecycle (AI-DATA.4)
witness.witnessTrainingPiiLifecycle(10000, { eventType: "pseudonymization", datasetId: "training-v3" });
```

Maps to: EU AI Act Art. 10(3), Art. 10(5), Art. 12(2)(a), Art. 12(3)(d), Art. 13, Art. 14(4)(e), Art. 14(5), Art. 51. NIST AI RMF MANAGE 3.2, MANAGE 4.1, GOVERN 1.2.

## Agent Identity

Bind a unique identity to every anchor your agent produces:

```typescript
const witness = new Witness({
  endpoint: "...",
  apiKey: "axm_...",
  tenantId: "...",
  agentId: "fraud-detector-prod",
  signingKey: "swt3_sk_...",  // HMAC-SHA256 signing for non-repudiation
});
```

The `agentId` survives all clearing levels. The `signingKey` produces an HMAC-SHA256 signature on every anchor, proving which agent instance created it. When a signing key is registered server-side, the server validates the signature on ingestion and rejects tampered payloads. This enables:
- **Payload authenticity** -- server verifies the SDK that minted the anchor held the registered secret
- **Tamper detection** -- any modification after signing causes rejection (422)
- Per-agent compliance passports
- Fleet-wide governance dashboards
- Agent-scoped evidence packages for auditors

Receipts include `signature_verified: true` when the server confirms the signature.

## Trust Mesh (Mutual Agent Verification)

Before two agents exchange data or invoke each other's tools, each verifies the other's compliance posture. No anchor, no handshake.

```typescript
// Agent A: present a signed credential
const credentialA = witnessA.presentCredential();
// Send credentialA to Agent B over your transport layer

// Agent B: verify Agent A's credential
witnessB.trustRegistry.trustTenant("TENANT_A");
witnessB.trustRegistry.registerSigningKey("agent-alpha", "shared-secret-a");
const result = witnessB.verifyTrust(credentialA);

if (result.granted) {
  // Trust level: 1=basic, 2=verified, 3=attested, 4=sovereign
  console.log(`Trusted at level ${result.trustLevel}`);
} else {
  console.log(`Denied: ${result.denialReason}`);
}
```

**Trust levels:**

| Level | Name | Requires |
|-------|------|----------|
| 1 | Basic | Valid credential, unsigned or unverifiable |
| 2 | Verified | Valid credential + verified HMAC signature |
| 3 | Attested | Verified + hardware attestation + guardrails |
| 4 | Sovereign | Attested + clearing level >= 2 |

Unsigned credentials are automatically capped at TRUST_BASIC. You cannot claim a higher trust level without a verified signature.

**Key exchange:** Exchange signing keys out-of-band (environment variables, secrets manager, KMS). Never send keys over the wire alongside credentials. Each agent registers the counterpart's key:

```typescript
// Agent A registers B's key, B registers A's key
witnessA.trustRegistry.registerSigningKey("agent-beta", process.env.AGENT_B_KEY!);
witnessB.trustRegistry.registerSigningKey("agent-alpha", process.env.AGENT_A_KEY!);
```

**Zero-friction path:** Trust mesh works without signing keys. Agents without keys get TRUST_BASIC (level 1), which is sufficient for non-sensitive coordination. Add keys when you need verified or attested trust.

**Credential auto-population:** `presentCredential()` automatically includes which procedures the agent has witnessed and whether hardware attestation (AI-HW.1 or AI-HW.3) has been performed. No manual tracking needed.

Every verification (pass or fail) mints AI-TRUST.1 + AI-TRUST.2 anchors. Denials produce evidence too.

Maps to: EU AI Act Art. 14 (human oversight and mutual accountability between AI systems).

## Policy-as-Code (swt3.yaml)

New in v0.5.2. Define your entire witnessing policy in a YAML file instead of passing 25+ constructor parameters:

```bash
npx swt3 init          # interactive profile picker
npx swt3 init --profile eu-ai-act-high-risk --tenant ACME
```

This generates a `swt3.yaml` file. Then load it:

```typescript
const witness = Witness.fromConfig();              // auto-finds swt3.yaml
const witness = Witness.fromConfig("prod.yaml");   // explicit path
```

### File Composition (extends)

Layer configs for environment-specific overrides:

```yaml
# prod.yaml
extends: base.yaml
clearing_level: 2
signing_key_env: SWT3_SIGNING_KEY
```

Supports single files or chains (`extends: [base.yaml, team.yaml]`). Merge order: extends < profile < explicit config. Cycle detection and depth limit (10) built in.

### Built-in Profiles

14 profiles ship with the SDK -- 7 framework profiles and 7 industry verticals:

| Profile | Use Case |
|---------|----------|
| `eu-ai-act-high-risk` | EU AI Act high-risk: clearing 2, signing required, jurisdiction required |
| `nist-ai-rmf` | NIST AI RMF: full procedure coverage, moderate policy |
| `cost-conscious` | Token budget governance: 25K/session ceiling, cost attribution |
| `owasp-agentic-top10` | OWASP Agentic Top 10: fail-closed, 100K tokens, depth 8 |
| `mythos-defense` | Exploit chain containment: clearing 3, strict trust, depth 5 |
| `granite-sovereign` | IBM Granite on-prem: air-gap ready, hardware attestation |
| `minimal` | Development: clearing 0, no policy enforcement |
| `fintech-model-risk` | SR 11-7 model risk: drift monitoring, clearing 2, signing required |
| `healthcare-clinical` | HIPAA clinical AI: consent witnessing, clearing 3, PII protection |
| `insurance-underwriting` | Underwriting AI: fairness, explainability, DPIA, clearing 2 |
| `telecom-compliance` | Telecom fraud/network AI: performance monitoring, incident response |
| `defense-govcon` | CMMC/RMF: clearing 3, strict chain enforcement, SBOM required |
| `content-platform` | Content moderation: watermark verification, transparency, consent |
| `autonomous-systems` | Autonomous/robotics: safety, robustness, dual-use, human oversight |

### Diagnostics

```bash
npx swt3 doctor        # 8 checks: YAML, env vars, profile, extends, sections
npx swt3 doctor --json  # machine-readable for CI/CD
```

### Schema Validation

Validate config files programmatically:

```typescript
import { validateSchema } from "@tenova/swt3-ai";

const result = validateSchema(parsedYaml);
if (!result.valid) {
  console.error(result.errors);
}
```

## Merkle Accumulator (Session-Level Integrity)

New in v0.5.2. Compute Merkle roots over batches of anchors for tamper-evident session integrity:

```typescript
import { MerkleAccumulator, verifyMerkleProof } from "@tenova/swt3-ai";

const acc = new MerkleAccumulator({ tenantId: "ACME" });

// Accumulate fingerprints as anchors are minted
acc.add("abc123def456");
acc.add("789012345678");

// Compute session root (persisted to JSONL automatically)
const session = acc.flush();
console.log(session.root);  // 64-char hex Merkle root

// Generate an inclusion proof for any fingerprint
const proof = acc.prove("abc123def456");
console.log(verifyMerkleProof("abc123def456", proof));  // true
```

Enable via config:

```yaml
merkle:
  enabled: true
  accumulator_interval: 0  # 0 = compute on every flush
```

Cross-language parity with Python SDK. Domain-separated (SWT3:LEAF: / SWT3:NODE:) to prevent second-preimage attacks.

## Gatekeeper Mode (Pre-Call Attestation)

New in v0.3.4. Require guardrails to be active *before* the model is called, not just observed after:

```typescript
import { Witness, GatekeeperError } from "@tenova/swt3-ai";

const witness = new Witness({
  endpoint: "...",
  apiKey: "axm_...",
  tenantId: "...",
  strict: true,
  guardrailsRequired: 2,
  guardrailNames: ["content-filter", "pii-scanner"],
});

const client = witness.wrap(new OpenAI()) as OpenAI;

// If fewer than 2 guardrails are active, this throws GatekeeperError
// BEFORE the model call happens. No inference runs without safeguards.
try {
  const response = await client.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "user", content: "..." }],
  });
} catch (e) {
  if (e instanceof GatekeeperError) {
    console.log(`Blocked: ${e.message}`);
    // An AI-GRD.3 FAIL anchor is minted recording the gate failure
  }
}
```

Gatekeeper mode mints an **AI-GRD.3** anchor with:
- **factor_a** = required guardrail count
- **factor_b** = actual guardrail count
- **factor_c** = 1 if gate passed, 0 if blocked

## Agent Cost Governance

Every inference witnessed by the SDK captures prompt and completion token counts from the API response. Combined with `max_tokens_per_session`, this gives you a per-agent, per-session cost ceiling with a complete audit trail.

```yaml
# .swt3.yaml
profile: cost-conscious        # Built-in budget profile (25K tokens)

mcp_policy:
  max_tokens_per_session: 25000  # Hard cutoff per session
  fail_secure: true              # Halt and record on budget exceeded
```

```typescript
import { Witness } from "@tenova/swt3-ai";

const witness = new Witness({ /* ... */ });
const client = witness.wrap(new OpenAI()) as OpenAI;

// Every call through the wrapped client automatically tracks tokens.
// When the session budget is exhausted, the chain enforcer halts
// further calls and mints a token_budget violation anchor.

// Manual token recording (for custom pipelines):
witness.recordSessionTokens(1500);
```

Token usage flows into the witness ledger alongside every other anchor. Your auditor sees what the agent did, whether it complied, and what it cost -- in one export.

## Multi-Agent Chain Linking

New in v0.3.4. Link anchors across agents in a multi-step pipeline using `cycleId`:

```typescript
const witness = new Witness({
  endpoint: "...",
  apiKey: "axm_...",
  tenantId: "...",
  agentId: "step-1-classifier",
  cycleId: "txn-review-abc123",  // shared across all agents in the chain
});
```

The `cycleId` survives all clearing levels and appears in every anchor. An auditor can reconstruct the full decision chain by filtering on a single cycle ID.

## Policy Version Binding

New in v0.3.4. Tie every anchor to the specific policy configuration that was in effect:

```typescript
const witness = new Witness({
  endpoint: "...",
  apiKey: "axm_...",
  tenantId: "...",
  policyVersion: "v2.1.0-prod-2026-04-20",
});
```

The SDK hashes the policy version string (SHA-256, first 12 characters) and includes it in every payload. When policies change between audit periods, the hash changes -proving which rules were in effect for each inference.

## What Gets Witnessed

Each inference produces anchors for these checks. Every check maps to a regulation.

| Check | What It Proves | Plain English | Regulation |
|-------|---------------|---------------|------------|
| AI-INF.1 | Prompt and response were captured | "Was the inference logged?" | EU AI Act Art. 12 |
| AI-INF.2 | Latency was within threshold | "Was response time acceptable?" | NIST AI RMF MEASURE 2.6 |
| AI-MDL.1 | Deployed model matches approved hash | "Is this the right model?" | EU AI Act Art. 9 |
| AI-MDL.2 | Model version was recorded | "Is the model version tracked?" | EU AI Act Art. 72 |
| AI-GRD.1 | Required safety guardrails were active | "Are enough guardrails running?" | NIST AI RMF MANAGE 4.1 |
| AI-GRD.2 | No refusal or content filter triggered | "Did a safety filter trigger?" | EU AI Act Art. 9 |
| AI-TOOL.1 | Tool/function call was recorded | "Did the tool call succeed?" | NIST AI RMF MANAGE 4.1 |
| AI-ACC.1 | Resource access was within scope | "Was the access authorized?" | EU AI Act Art. 14 |
| AI-ID.1 | Agent identity was attested | "Is the agent identified?" | EU AI Act Art. 13 |

### EU AI Act Article Mapping

All 76 SWT3 AI witnessing procedures map to specific EU AI Act obligations:

| Procedure | EU AI Act Article | Obligation | Demo | Production |
|-----------|-------------------|------------|------|------------|
| AI-INF.1 | Art. 12(1) | Automatic Logging of Use Periods | ✓ | ✓ |
| AI-INF.2 | Art. 15(3) | Performance Consistency Monitoring | -| ✓ |
| AI-INF.3 | Art. 12(1) | Volume & Usage Logging | -| ✓ |
| AI-MDL.1 | Art. 9(4a) | Model Risk Identification | ✓ | ✓ |
| AI-MDL.2 | Art. 12(2b) | Version & Lineage Tracking | -| ✓ |
| AI-MDL.3 | Art. 72(1) | Post-Market Drift Monitoring | -| ✓ |
| AI-MDL.4 | Art. 15(4) | Feedback Loop Isolation | -| ✓ |
| AI-GRD.1 | Art. 9(2a) | Risk Mitigation Measures | ✓ | ✓ |
| AI-GRD.2 | Art. 9(4b) | Content Safety Filtering | -| ✓ |
| AI-GRD.3 | Art. 10(2f) | PII & Data Protection | -| ✓ |
| AI-EXPL.1 | Art. 13(1) | Transparency & Explainability | -| ✓ |
| AI-EXPL.2 | Art. 13(3b) | Confidence Calibration | -| ✓ |

The demo demonstrates 5 procedures using simulated data. All 76 are available in production with real inference data. 207 cross-language test vectors ensure fingerprint parity across Python, TypeScript, Swift, Rust, C#, and Ruby. [See live conformity →](https://sovereign.tenova.io/audit/axm_audit_demo_eu_ai_act_public)

## How Verdicts Work

Every anchor carries three numbers:

- **factor_a** = the threshold (what should happen)
- **factor_b** = the observation (what actually happened)
- **factor_c** = context (extra detail)

The verdict is a simple comparison. No AI, no probability. Just math.

### Reading an Anchor

```
Check: AI-GRD.1    factor_a: 2    factor_b: 3    factor_c: 1    Verdict: PASS

Translation: "We required 2 guardrails. 3 were active. All passed."
```

```
Check: AI-ACC.1    factor_a: 1    factor_b: 0    factor_c: 0    Verdict: FAIL

Translation: "Access attempt occurred. Target was outside declared scope. Access denied."
```

### Factor Reference

| Check | factor_a | factor_b | factor_c | Verdict Rule |
|-------|----------|----------|----------|-------------|
| AI-INF.1 | 1 (required) | 1 if hashes present | 0 | PASS if b >= a |
| AI-INF.2 | Latency limit (ms) | Actual latency (ms) | 1 if over limit | PASS if b <= a |
| AI-MDL.1 | 1 (required) | 1 if hash present | 0 | PASS if b >= a |
| AI-MDL.2 | 1 (required) | 1 if version recorded | 0 | PASS if b >= a |
| AI-GRD.1 | Required count | Active count | 1 if all passed | PASS if b >= a |
| AI-GRD.2 | 1 (clean expected) | 0 if refusal | 0 | PASS if b >= a |
| AI-GRD.3 | Required count | Active count | 1=passed, 0=blocked | PASS if b >= a AND c == 1 |
| AI-TOOL.1 | 1 (called) | Latency (ms) | 1=success, 0=error | PASS if b >= a |
| AI-ACC.1 | 1 (accessed) | 1=in scope, 0=out | 1=granted, 0=denied | PASS if b >= a |
| AI-ID.1 | 1 (required) | 1 if identity present | 0 | PASS if b >= a |

### Verify Any Anchor From Your Terminal

```bash
echo -n "WITNESS:DEMO_TENANT:AI-INF.1:1:1:0:1774800000000" | sha256sum | cut -c1-12
# Produces a 12-character fingerprint. Compare it to the anchor. If it matches, the anchor is real.
```

No SDK needed. Works on any machine, any language.

## Self-Hosted Deployment

Run the full stack inside your own infrastructure. No data leaves your network boundary.

### SWT3 Gateway (LLM Proxy)

A zero-latency Go reverse proxy that witnesses every inference transparently. Deploy inside your VPC, point your app at the gateway instead of the LLM provider. One line change:

```bash
docker run -d \
  -e SWT3_API_KEY=axm_live_your_key \
  -e SWT3_TENANT_ID=YOUR_ENCLAVE \
  -e SWT3_UPSTREAM=https://api.openai.com \
  -p 8443:8443 \
  tenova/swt3-gateway:latest
```

```typescript
// One line change. Everything else stays the same.
const client = new OpenAI({ baseURL: "http://gateway:8443/v1" });
```

Multi-provider routing, model allowlist (advisory or strict), streaming support, HMAC payload signing. Helm chart included for Kubernetes.

[Gateway Documentation](https://github.com/tenova-labs/swt3-ai/tree/main/packages/swt3-gateway)

### Axiom Sovereign Engine (Full Platform)

The complete compliance platform as a container: dashboard, adjudicator, evidence chain, Merkle rollups.

```bash
# Three-service deployment (dashboard + adjudicator + postgres)
docker compose up -d

# Air-gap export for disconnected environments
docker save axiom-sovereign-engine:latest | gzip > axiom-sovereign.tar.gz
```

- UBI 9 Minimal base (Iron Bank compatible, DoD IL2-IL5)
- Non-root runtime, FIPS-validated OpenSSL 3.x
- Works air-gapped: `docker load` on the target, no internet required
- Helm chart for Kubernetes orchestration

### Deployment Options

| Mode | What You Run | Data Residency |
|------|-------------|----------------|
| **SDK only** | `npm install @tenova/swt3-ai` | Hashes leave, data stays |
| **Gateway** | Docker container in your VPC | Raw traffic never leaves your network |
| **Self-hosted platform** | Docker Compose or Helm | Everything on your infrastructure |
| **Air-gapped** | `docker load` from tarball | Zero internet connectivity required |

## Sovereign Cloud Support

The SDK works with any OpenAI-compatible endpoint. Run models on your own infrastructure and witness every inference identically:

```typescript
// vLLM with Llama 3 on your hardware
const client = witness.wrap(
  new OpenAI({ baseURL: "http://gpu-cluster.internal:8000/v1" }),
) as OpenAI;

// Ollama for local development
const localClient = witness.wrap(
  new OpenAI({ baseURL: "http://localhost:11434/v1" }),
) as OpenAI;

// Azure OpenAI
const azureClient = witness.wrap(
  new OpenAI({
    apiKey: process.env.AZURE_OPENAI_KEY,
    baseURL: "https://your-resource.openai.azure.com/openai/deployments/gpt-4o",
  }),
) as OpenAI;
```

Same anchors, same ledger, same audit trail. Regardless of where the model runs.

## Clearing Levels (Privacy Control)

You control what leaves your infrastructure. The SDK always returns the full response to your code. Clearing only affects the witness payload.

| Level | Name | What Goes on the Wire | Use Case |
|-------|------|-----------------------|----------|
| 0 | Analytics | Everything: hashes, factors, model, provider, guardrails, prompt hash | Internal analytics |
| 1 | Standard | Hashes, factors, model, provider (no raw text ever) | **Default.** Production apps |
| 2 | Sensitive | Hashes, factors, model only. No provider, no guardrail names | Healthcare, legal, PII |
| 3 | Classified | Numeric factors only. Model name hashed. Zero metadata | Defense, air-gapped |

```typescript
const witness = new Witness({
  endpoint: "...",
  apiKey: "axm_...",
  tenantId: "...",
  clearingLevel: 2, // Sensitive: strips provider and guardrail names
});
```

At every level, raw prompts and responses **never leave your infrastructure**. Only SHA-256 hashes and numeric factors travel on the wire.

## Local Mode (No Account Needed)

Try the SDK locally before connecting to a live endpoint:

```typescript
const witness = new Witness({
  endpoint: "https://your-witness-endpoint.example.com",
  apiKey: "test",
  tenantId: "LOCAL_TEST",
  factorHandoff: "file", // Writes anchors to ./swt3-handoff/ as JSON
});
```

## Local SDK vs Connected

| Capability | Local SDK | Connected (free tier) |
|---|---|---|
| Mint anchors | Yes | Yes |
| Verify one anchor | Yes | Yes |
| Evidence retention | Files on disk | 7 days (free) / 90 days (Pro) |
| Compliance dashboard | No | Yes |
| Agent Passport | No | Yes (Pro) |
| Fleet dashboard | No | Yes (Pro) |
| EU AI Act conformity | No | Yes (Pro) |
| Auditor evidence packages | No | Yes (Pro) |
| Access violation tracking | No | Yes (Pro) |
| Audit-ready evidence chain | No | Yes |

> Local mode is for development and testing. Connected mode is for production evidence.

## Resilience (Flight Recorder)

The SDK never blocks your inference. If the witness endpoint is unreachable, payloads move to a dead-letter queue. When connectivity returns, the backlog drains automatically. Your production system is never affected.

```typescript
const witness = new Witness({
  endpoint: "...",
  apiKey: "axm_...",
  tenantId: "...",
  bufferSize: 50,       // flush every 50 anchors
  flushInterval: 10,    // or every 10 seconds
  maxRetries: 5,        // retry before dead-lettering
});
```

## API Reference

### `new Witness(options)`

| Option | Default | Description |
|--------|---------|-------------|
| `endpoint` | required | Witness endpoint URL |
| `apiKey` | required | API key (axm_ prefix) |
| `tenantId` | required | Your tenant identifier |
| `clearingLevel` | 1 | Privacy level (0-3) |
| `bufferSize` | 10 | Flush after N anchors |
| `flushInterval` | 5 | Flush after N seconds |
| `timeout` | 10000 | HTTP timeout (ms) |
| `maxRetries` | 3 | Retries before dead-letter |
| `guardrailNames` | [] | Active guardrail names |
| `agentId` | - | Agent identity (survives all clearing levels) |
| `signingKey` | - | Signing key for payload non-repudiation (HMAC-SHA256 secret or ML-DSA-65 hex seed) |
| `signingAlgorithm` | - | `"hmac-sha256"` (default) or `"ml-dsa-65"` (FIPS 204 post-quantum) |
| `cycleId` | - | Multi-agent chain link (survives all clearing levels) |
| `policyVersion` | - | Policy config identifier (hashed in payloads) |
| `strict` | false | Gatekeeper mode: block inference if guardrails insufficient |
| `latencyThresholdMs` | 30000 | AI-INF.2 latency limit (ms) |
| `guardrailsRequired` | 0 | AI-GRD.1 minimum guardrail count |
| `onFlush` | - | Callback `(payloads, receipts) => void` after each flush |
| `factorHandoff` | - | "file" for local factor export |
| `factorHandoffPath` | - | Directory for handoff files |

### Methods

| Method | Description |
|--------|-------------|
| `witness.wrap(client)` | Returns a Proxy that behaves identically to the original client. Supports OpenAI, Anthropic, and AWS Bedrock. |
| `witness.wrapTool(fn, name?)` | Wraps a function for tool call witnessing (AI-TOOL.1). |
| `witness.wrapAccess(fn, resource?, scope?)` | Wraps a function for resource access witnessing (AI-ACC.1). |
| `witness.vercelOnFinish(opts?)` | Returns an onFinish callback for Vercel AI SDK streamText/generateText. |
| `witness.flush()` | Force-flush all buffered payloads. Returns receipts. |
| `witness.stop()` | Stop the witness and flush remaining payloads. |

## OpenTelemetry Export

New in v0.3.6. Send SWT3 anchors to your existing observability stack as OTel spans:

```typescript
import { Witness } from "@tenova/swt3-ai";
import { OTelExporter } from "@tenova/swt3-ai/exporters/otel";

const exporter = new OTelExporter({ tracerName: "swt3-witness" });
const witness = new Witness({
  endpoint: "...",
  apiKey: "axm_...",
  tenantId: "...",
  onFlush: exporter.export.bind(exporter),
});

// Anchors now appear as spans in Datadog, Grafana, Jaeger, Honeycomb, etc.
// Span attributes: swt3.procedure_id, swt3.verdict, swt3.fingerprint, swt3.model_id, ...
```

Install: `npm install @opentelemetry/api`

The `onFlush` callback fires after each successful batch transmission. You can use it for any custom export destination, not just OTel.

## Installation

```bash
npm install @tenova/swt3-ai

# Peer dependencies (install whichever you use)
npm install openai              # for OpenAI adapter
npm install @anthropic-ai/sdk   # for Anthropic adapter
npm install @opentelemetry/api  # for OTel exporter
```

## Regulatory Coverage

The SWT3 AI Witnessing Profile maps to:

- **EU AI Act**: Articles 9, 10, 12, 13, 14, 53, 72
- **NIST AI RMF**: GOVERN, MAP, MEASURE, MANAGE functions
- **ISO 42001**: Annex A AI management controls
- **NIST 800-53**: SI-7 (integrity), AU-2/AU-3 (audit), AC controls
- **SR 11-7**: Model risk management (financial services)

## Zero Lock-in

Remove the `witness.wrap()` call. Your code works exactly as before. Anchors already minted stay in the ledger. There is nothing to undo.

## Cross-Language Parity

This SDK produces identical fingerprints to the Python SDK (`swt3-ai`). A unified audit trail across your entire stack, verified by shared test vectors at build time.

| Layer | Language | Package |
|-------|----------|---------|
| Backend services | Python | swt3-ai |
| API routes / Edge | TypeScript | @tenova/swt3-ai |
| Frontend (Next.js) | TypeScript | @tenova/swt3-ai + Vercel AI SDK |

## Privacy

Your prompts and responses **never leave your infrastructure**. The SDK computes SHA-256 hashes locally and transmits only irreversible hashes and numeric factors. At Clearing Level 3, even the model name is hashed. The witness endpoint is a blind registrar: it stores cryptographic proofs, not your data.

---

## Upgrading to v0.5.2

**Policy-as-Code (new):** `swt3 init`, `swt3 doctor`, `extends:` composition, profile templates, YAML schema validator. No breaking changes.

**Merkle Accumulator (new):** `MerkleAccumulator` class for session-level integrity proofs. `merkle:` config section. No breaking changes.

**Trust Mesh (v0.5.0):** `presentCredential()` and `verifyTrust()`. No breaking changes for existing code.

**Credential signing (behavioral change):** If your Witness has a `signingKey`, credentials are now HMAC-signed automatically. Counterpart agents must register your key via `trustRegistry.registerSigningKey()` to verify the signature. Without key registration, signed credentials are denied with `signature_unverifiable`.

**TPM attestation (v0.5.2):** `witnessTPMAttestation()` for AI-HW.3. Reads PCR registers via tpm2-tools. Graceful degradation without TPM. No breaking changes.

**Environmental attestation (v0.5.0):** `witnessEnvironment()` and `witnessEnergyDraw()` for AI-ENV.1/AI-ENV.2. No breaking changes.

**MCP server:** 16 procedure keyword suggestions (was 8). MCP policy section in swt3.yaml. No breaking changes.

---

## Documentation

- [SDK Reference](https://sovereign.tenova.io/docs/) -- full API, all providers, clearing levels, configuration
- [10-Minute Quickstart](https://sovereign.tenova.io/guides/ai-witness-quickstart.html) -- from install to first anchor
- [SWT3 Protocol Spec](https://sovereign.tenova.io/guides/swt3-protocol.html) -- formal specification with ABNF grammar
- [Design Rationale](https://sovereign.tenova.io/guides/swt3-design-rationale.html) -- why every protocol decision was made
- [UCT Registry](https://sovereign.tenova.io/registry) -- full procedure catalog with factor definitions
- [Anchor Verifier](https://sovereign.tenova.io/verify) -- verify any anchor, zero server calls
- [Before & After](https://sovereign.tenova.io/guides/developer-before-after.html) -- manual audit evidence vs. cryptographic witness anchors
- [Integration Patterns](https://sovereign.tenova.io/guides/developer-integration-patterns.html) -- 8 instrumentation patterns mapped to regulatory requirements
- [What Your Auditor Sees](https://sovereign.tenova.io/guides/developer-auditor-bridge.html) -- both sides of a witness anchor, developer to auditor
- [CI/CD Integration](https://sovereign.tenova.io/guides/developer-cicd-guide.html) -- validate compliance configuration in your pipeline
- [Assessment Mapping](https://sovereign.tenova.io/registry/assessment.html) -- which procedures satisfy which regulatory requirements
- [All 65 Guides](https://sovereign.tenova.io/guides/) -- regulatory crosswalks, assessor walkthroughs, integration guides

---

*SWT3: Sovereign Witness Traceability. We don't run your models. We witness them.*

SWT3 and Sovereign Witness Traceability are trademarks of Tenable Nova LLC. Patent pending. Apache 2.0 licensed.

This project is not affiliated with, endorsed by, or sponsored by any third-party AI provider. All third-party trademarks are the property of their respective owners: OpenAI and GPT (OpenAI, Inc.); Claude and Anthropic (Anthropic PBC); Google, Gemini, Vertex AI, and ADK (Google LLC); Azure, Foundry, and Microsoft (Microsoft Corporation); AWS and Bedrock (Amazon Web Services, Inc.); NVIDIA and Dynamo (NVIDIA Corporation); Meta and Llama (Meta Platforms, Inc.); Ollama (Ollama, Inc.); CrewAI (CrewAI, Inc.); Vercel and Next.js (Vercel, Inc.); MCP (Anthropic PBC); vLLM (vLLM Project). Use of these names is for identification and interoperability purposes only.
