Witness your AI. Prove it followed the rules. Cryptographic accountability for every inference, tool call, and resource access.

[![PyPI](https://img.shields.io/pypi/v/swt3-ai)](https://pypi.org/project/swt3-ai/)
[![Downloads](https://img.shields.io/pypi/dm/swt3-ai)](https://pypi.org/project/swt3-ai/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/tenova-labs/swt3-ai/blob/main/LICENSE)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-io.tenova%2Fswt3--witness-blue)](https://www.npmjs.com/package/@tenova/swt3-mcp)

# swt3-ai

**SWT3 AI Witness SDK**: tamper-proof evidence that your AI is doing what you say it does. Every inference hashed. Every tool call recorded. Every resource access checked against scope. No prompts or responses ever leave your infrastructure.

GPAI transparency obligations are enforceable now. EU AI Act high-risk enforcement begins **December 2, 2027**. This SDK gives you the evidence chain.

## What's New in v0.5.6

- **METAGOV Namespace** -- 8 procedures for recursive governance: governance config attestation, layer registration, policy downgrade detection, circular dependency detection (Kahn's algorithm), governance authorization, emergency override, federation sync, attestation purity verification.
- **Japan AI Promotion Act** -- 17th regulatory framework. 10 procedure mappings to Japan's AI Promotion Act and AI Utilization Guidelines.
- **Model Trust Profiles** -- `verify_trust()` / `present_credential()` for AI-TRUST.1 and AI-TRUST.2 anchors. Chain verification across multi-agent handoffs.
- **Anchor References** -- Link related anchors with `anchor_refs` for causal chains and dependency tracking.
- **Coverage Scoring** -- `get_coverage_score()` computes namespace and framework coverage from minted anchors.
- **CLI: `swt3 procedures`** -- List and filter UCT procedures by namespace or JSON output. `swt3 quickstart` generates a working example script.
- **MCP Framework Filter** -- `list_procedures` tool now accepts `--framework` parameter for regulatory-scoped queries.
- **Lifecycle Stage** -- `LIFECYCLE_STAGE_CODES` for AI-MDL.5 model weight witnessing across all 5 languages.
- **Bidirectional Crosswalks** -- 420+ mappings across 17 frameworks in machine-readable JSON.
- **15 profiles**, 88 procedures, 47 namespaces, 12 integrations

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

**You run Agent A. Your partner runs Agent B. Both install swt3-ai:**

```python
# === Your side (Agent A) ===
witness_a = Witness(
    endpoint="...", api_key="axm_...", tenant_id="YOUR_TENANT",
    agent_id="agent-alpha", signing_key="swt3_sk_your_key",
)
witness_a.trust_registry.trust_tenant("PARTNER_B_TENANT")
witness_a.trust_registry.register_signing_key("agent-beta", os.environ["PARTNER_B_KEY"])

# === Partner's side (Agent B) ===
witness_b = Witness(
    endpoint="...", api_key="axm_...", tenant_id="PARTNER_B_TENANT",
    agent_id="agent-beta", signing_key="swt3_sk_partner_key",
)
witness_b.trust_registry.trust_tenant("YOUR_TENANT")
witness_b.trust_registry.register_signing_key("agent-alpha", os.environ["YOUR_KEY"])

# === Handshake (both directions) ===
cred_a = witness_a.present_credential()
result = witness_b.verify_trust(cred_a)       # B verifies A
if result.granted:
    cred_b = witness_b.present_credential()
    result = witness_a.verify_trust(cred_b)    # A verifies B
    if result.granted:
        # Bidirectional trust established. Exchange data.
        pass
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

Verify any witness anchor without network calls. The fingerprint formula is deterministic and identical across all 6 SDK languages -- recompute it anywhere in microseconds.

```python
from swt3_ai import verify_anchor

result = verify_anchor(
    anchor,
    tenant_id="MY_TENANT",
    procedure_id="AI-INF.1",
    factor_a=1, factor_b=1, factor_c=0,
    timestamp_ms=1773316622000,
)
# result.status: "CERTIFIED TRUTH" | "TAMPERED"
```

Zero vendor dependency. Zero network calls. Works air-gapped. The same formula runs in Python, TypeScript, Rust, C#, and Ruby with identical output for identical inputs.

## See It Work (No Account Needed)

```bash
pip install swt3-ai
python -m swt3_ai.demo
```

The demo runs the full pipeline locally: hash, extract, clear, anchor, verify. It shows a Regulatory Coverage Summary mapping each check to EU AI Act articles, with gaps highlighted. No API keys, no network calls.

## Three Lines to Start Witnessing

```python
from swt3_ai import Witness
from openai import OpenAI

witness = Witness(
    endpoint="https://your-witness-endpoint.example.com",
    api_key="axm_live_...",
    tenant_id="YOUR_TENANT",
)
client = witness.wrap(OpenAI())

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Summarize this contract..."}],
)
# response is untouched. Witnessing runs in the background.
print(response.choices[0].message.content)
```

No code changes to your existing logic. No performance impact. The SDK wraps your AI client transparently and witnesses every call.

## What the SDK Does

When your AI makes a call, the SDK:

1. **Hashes** the prompt and response locally using SHA-256 (the raw text never leaves your machine)
2. **Extracts** numeric factors: model version, latency, token count, guardrail status
3. **Clears** sensitive metadata based on your clearing level (you control what goes on the wire)
4. **Anchors** the factors into a cryptographic fingerprint that anyone can independently verify
5. **Buffers** and flushes anchors in the background (median overhead: under 1ms)
6. **Returns** your original response completely untouched

The result: an immutable record that your AI ran the right model, with the right guardrails, within the right boundaries. Without the auditor ever seeing the data.

## Witness Agent Tool Calls

If your AI agent calls tools or functions, wrap them to create a record of every invocation:

```python
@witness.wrap_tool(tool_name="search_database")
def search(query: str) -> list:
    return db.execute(query)

# Every call to search() now mints an anchor recording:
#   - Tool name
#   - Input/output hashes
#   - Latency
#   - Success or failure
```

This produces an **AI-TOOL.1** anchor recording the tool name, input/output hashes, latency, and success or failure.

## Witness Agent Resource Access

New in v0.2.10. Wrap any function your agent uses to access external resources. The SDK records what was accessed and whether it was within the agent's declared scope:

```python
@witness.wrap_access(resource_name="customer-database", scope="read-only analytics")
def query_customers(sql: str) -> list:
    return db.execute(sql)

# If the agent calls query_customers("DROP TABLE users"),
# the access is witnessed and compared against the declared scope.
# Out-of-scope access produces a FAIL verdict.
```

This produces an **AI-ACC.1** anchor with three factors:
- **Was it accessed?** (yes/no)
- **Was it within scope?** (yes/no)
- **Was access granted?** (yes/no)

Out-of-scope access produces a FAIL verdict with a full evidence trail.

## Detect Instruction Drift

New in v0.2.10. The SDK separately hashes the system prompt (base instructions) for each inference. If your agent's instructions change between audit periods, the hash changes and the platform flags it as instruction drift.

This happens automatically. No configuration needed. The system prompt hash is extracted from:
- OpenAI: messages where `role == "system"`
- Anthropic: the `system` parameter

The hash is included at clearing levels 0 and 1, stripped at levels 2 and 3.

## RAG Context Witnessing

New in v0.4.3. Witness what context chunks your RAG pipeline retrieves, from which corpus, and how relevant they are. Chunk text is never transmitted -- only SHA-256 hashes.

```python
# Zero-friction: pass raw strings, SDK handles hashing
witness.witness_rag_context(
    ["chunk text 1", "chunk text 2", "chunk text 3"],
    corpus_id="legal-docs-v3",
)
```

This mints an AI-RAG.1 (Context Retrieval Provenance) anchor. Add similarity scores to also get AI-RAG.2 (Context Relevance):

```python
from swt3_ai import RagChunk

witness.witness_rag_context(
    [
        RagChunk(content_hash="abc123...", source_id="doc-7/p3", similarity_score=0.92),
        RagChunk(content_hash="def456...", source_id="doc-2/p1", similarity_score=0.78),
        RagChunk(content_hash="789abc...", source_id="doc-4/p2", similarity_score=0.61),
    ],
    corpus_id="legal-docs-v3",
    embedding_model="text-embedding-3-small",
    similarity_threshold=0.75,  # triggers AI-RAG.2
)
```

One call. Two procedures. Complete retrieval attestation.

**LangChain auto-witnessing**: If you use the `SWT3CallbackHandler`, retriever events are captured automatically -- no code changes needed.

Maps to: EU AI Act Art. 12(2)(a) (reference database logging), Art. 10(2) (data quality), NIST AI RMF MAP 3.5 (data provenance).

## Model Weight Integrity

Witness the actual model weights, not just the model name string. Accepts a file path (auto-hashes) or pre-computed hash:

```python
# File path: SDK streams SHA-256 automatically
witness.witness_model_weights("/models/llama-3.1-70b.safetensors")

# Pre-computed hash with verification
from swt3_ai import ModelWeightInfo
witness.witness_model_weights(
    ModelWeightInfo(file_hash="abc123...", format="safetensors"),
    expected_hash="abc123...",  # PASS if match, FAIL if mismatch
)
```

Witness adapter stacks and quantization in the same pipeline:

```python
from swt3_ai import AdapterInfo
witness.witness_adapter_stack(
    [AdapterInfo(name="lora-legal", adapter_hash="aaa111")],
    base_model_id="llama-3.1-70b",
)
witness.witness_quantization("gptq", bits=4, group_size=128)
```

Maps to: EU AI Act Art. 15(4) (resilience against modification), Art. 12(2)(b) (version logging).

## TPM Platform Attestation (AI-HW.3)

Prove host firmware integrity via TPM 2.0. Reads PCR registers 0-7 and mints a hardware root-of-trust anchor. All raw values are SHA-256 hashed before leaving the module:

```python
# Auto-detect: reads /dev/tpm0 via tpm2-tools
witness.witness_tpm_attestation()

# Or provide a pre-computed snapshot
from swt3_ai.hardware import query_tpm
snapshot = query_tpm()
witness.witness_tpm_attestation(snapshot=snapshot)
```

If no TPM is available (cloud VM, dev machine), returns a valid anchor with factor_a=0. No crash, no error. Graceful degradation by design.

Use case: sovereign/air-gapped deployments where you must prove the host was not tampered with. Combined with AI-HW.1 (GPU inventory), gives full hardware root-of-trust from silicon to model.

Maps to: NIST 800-53 SC-12 (cryptographic key establishment). Patent pending.

## Environmental Attestation (Residential and Edge AI)

Witness the physical compute environment for distributed, edge-deployed, or residential AI nodes. Proves the hardware operated within safe thermal and power bounds during inference:

```python
# Zero-config: auto-detects Linux thermal sensors
witness.witness_environment()

# Manual readings from smart panel APIs or IPMI
witness.witness_environment(
    temperature_celsius=42,
    threshold_celsius=75,
    node_type="residential",
)

# Power integrity: draw vs capacity
witness.witness_energy_draw(
    power_watts=1200,
    capacity_watts=2400,
    node_type="edge",
)
```

If no sensors are available (dev machine, cloud VM), returns a valid anchor with zero readings. No crash, no error.

Use case: enterprises renting compute on distributed residential nodes need cryptographic proof that the node was operating within safe bounds, was not throttled, and was not physically tampered with during their inference window.

Maps to: NIST 800-53 PE-14 (environmental controls), EU AI Act Annex I (product safety for home-integrated AI).

## Skill Manifest Attestation

Witness which skills, tools, and plugins are loaded in your agent:

```python
# Zero-friction: just names
witness.witness_skill_manifest(["code_exec", "web_search", "file_read"])

# With memory context
from swt3_ai import MemorySource
witness.witness_memory_context([
    MemorySource(source_type="vector_store", source_id="pinecone-prod"),
    MemorySource(source_type="conversation", source_id="session-123"),
])

# Reward model binding
witness.witness_reward_model("rm-v3-legal", method="dpo")
```

Maps to: EU AI Act Art. 12(2)(b) (capability tracking), NIST AI RMF GOVERN 1.7 (capability documentation).

## Multi-Agent Chains, Violations, and Safety (v0.5.0)

New in v0.5.0. Convenience methods for 8 additional procedures covering multi-agent orchestration, policy enforcement, human oversight, and training data governance:

```python
# Multi-agent chain handoff (AI-CHAIN.1)
witness.witness_chain_handoff(depth=3, target_agent="step-2-reviewer")

# Policy violation reporting (AI-VIO.1)
witness.witness_violation(severity=3, description="PII in output", auto_detected=True, policy_category="data")

# Agent charter attestation (AI-CHR.1)
witness.witness_charter(charter_text="You are a fraud detection assistant...")

# Model registry check (AI-MDL.8)
witness.witness_model_registry("gpt-4o-2025-04-16", "eu-approved-models-v3")

# Reviewer identity binding for four-eyes rule (AI-HITL.3)
witness.witness_reviewer_identity(required=2, actual=2, method="cryptographic")

# Safe state attestation (AI-SAFE.1)
witness.witness_safe_state(mechanism_exists=True, safe_state_confirmed=True)

# Training data statistics (AI-DATA.3)
witness.witness_training_stats(row_count=50000, feature_count=128, class_balance_ratio=0.85)

# Training data PII lifecycle (AI-DATA.4)
witness.witness_training_pii_lifecycle(records_affected=10000, event_type="pseudonymization", dataset_id="training-v3")
```

Maps to: EU AI Act Art. 10(3), Art. 10(5), Art. 12(2)(a), Art. 12(3)(d), Art. 13, Art. 14(4)(e), Art. 14(5), Art. 51. NIST AI RMF MANAGE 3.2, MANAGE 4.1, GOVERN 1.2.

## Agent Identity

Bind a unique identity to every anchor your agent produces:

```python
witness = Witness(
    endpoint="...",
    api_key="axm_...",
    tenant_id="...",
    agent_id="fraud-detector-prod",
    signing_key="swt3_sk_...",  # HMAC-SHA256 signing for non-repudiation
)
```

The `agent_id` survives all clearing levels. The `signing_key` produces an HMAC-SHA256 signature on every anchor, proving which agent instance created it. When a signing key is registered server-side, the server validates the signature on ingestion and rejects tampered payloads. This enables:
- **Payload authenticity** -- server verifies the SDK that minted the anchor held the registered secret
- **Tamper detection** -- any modification after signing causes rejection (422)
- Per-agent compliance passports
- Fleet-wide governance dashboards
- Agent-scoped evidence packages for auditors

Receipts include `signature_verified: true` when the server confirms the signature.

## Trust Mesh (Mutual Agent Verification)

Before two agents exchange data or invoke each other's tools, each verifies the other's compliance posture. No anchor, no handshake.

```python
# Agent A: present a signed credential
credential_a = witness_a.present_credential()
# Send credential_a to Agent B over your transport layer

# Agent B: verify Agent A's credential
witness_b.trust_registry.trust_tenant("TENANT_A")
witness_b.trust_registry.register_signing_key("agent-alpha", "shared-secret-a")
result = witness_b.verify_trust(credential_a)

if result.granted:
    # Trust level: 1=basic, 2=verified, 3=attested, 4=sovereign
    print(f"Trusted at level {result.trust_level}")
else:
    print(f"Denied: {result.denial_reason}")
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

```python
import os

# Agent A registers B's key, B registers A's key
witness_a.trust_registry.register_signing_key("agent-beta", os.environ["AGENT_B_KEY"])
witness_b.trust_registry.register_signing_key("agent-alpha", os.environ["AGENT_A_KEY"])
```

**Zero-friction path:** Trust mesh works without signing keys. Agents without keys get TRUST_BASIC (level 1), which is sufficient for non-sensitive coordination. Add keys when you need verified or attested trust.

**Credential auto-population:** `present_credential()` automatically includes which procedures the agent has witnessed and whether hardware attestation (AI-HW.1 or AI-HW.3) has been performed. No manual tracking needed.

Every verification (pass or fail) mints AI-TRUST.1 + AI-TRUST.2 anchors. Denials produce evidence too.

Maps to: EU AI Act Art. 14 (human oversight and mutual accountability between AI systems).

## Policy-as-Code (swt3.yaml)

New in v0.5.2. Define your entire witnessing policy in a YAML file instead of passing 25+ constructor parameters:

```bash
swt3 init          # interactive profile picker
swt3 init --profile eu-ai-act-high-risk --tenant ACME
```

This generates a `swt3.yaml` file. Then load it:

```python
witness = Witness.from_config()              # auto-finds swt3.yaml
witness = Witness.from_config("prod.yaml")   # explicit path
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
swt3 doctor        # 8 checks: YAML, env vars, profile, extends, sections
swt3 doctor --json  # machine-readable for CI/CD
```

### Schema Validation

Validate config files programmatically:

```python
from swt3_ai import validate_schema

result = validate_schema(parsed_yaml)
if not result.valid:
    print(result.errors)
```

## Merkle Accumulator (Session-Level Integrity)

New in v0.5.2. Compute Merkle roots over batches of anchors for tamper-evident session integrity:

```python
from swt3_ai import MerkleAccumulator, verify_merkle_proof

acc = MerkleAccumulator(tenant_id="ACME")

# Accumulate fingerprints as anchors are minted
acc.add("abc123def456")
acc.add("789012345678")

# Compute session root (persisted to JSONL automatically)
session = acc.flush()
print(session.root)  # 64-char hex Merkle root

# Generate an inclusion proof for any fingerprint
proof = acc.prove("abc123def456")
print(verify_merkle_proof("abc123def456", proof))  # True
```

Enable via config:

```yaml
merkle:
  enabled: true
  accumulator_interval: 0  # 0 = compute on every flush
```

Cross-language parity with TypeScript SDK. Domain-separated (SWT3:LEAF: / SWT3:NODE:) to prevent second-preimage attacks.

## Gatekeeper Mode (Pre-Call Attestation)

New in v0.3.4. Require guardrails to be active *before* the model is called, not just observed after:

```python
witness = Witness(
    endpoint="...",
    api_key="axm_...",
    tenant_id="...",
    strict=True,
    guardrails_required=2,
    guardrail_names=["content-filter", "pii-scanner"],
)

client = witness.wrap(OpenAI())

# If fewer than 2 guardrails are active, this raises GatekeeperError
# BEFORE the model call happens. No inference runs without safeguards.
try:
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "..."}],
    )
except GatekeeperError as e:
    print(f"Blocked: {e}")
    # An AI-GRD.3 FAIL anchor is minted recording the gate failure
```

Gatekeeper mode mints an **AI-GRD.3** anchor with:
- **factor_a** = required guardrail count
- **factor_b** = actual guardrail count
- **factor_c** = 1 if gate passed, 0 if blocked

Import the exception: `from swt3_ai import GatekeeperError`

## Agent Cost Governance

Every inference witnessed by the SDK captures prompt and completion token counts from the API response. Combined with `max_tokens_per_session`, this gives you a per-agent, per-session cost ceiling with a complete audit trail.

```yaml
# .swt3.yaml
profile: cost-conscious        # Built-in budget profile (25K tokens)

mcp_policy:
  max_tokens_per_session: 25000  # Hard cutoff per session
  fail_secure: true              # Halt and record on budget exceeded
```

```python
from swt3_ai import Witness

witness = Witness(...)
client = witness.wrap(OpenAI())

# Every call through the wrapped client automatically tracks tokens.
# When the session budget is exhausted, the chain enforcer halts
# further calls and mints a token_budget violation anchor.

# Manual token recording (for custom pipelines):
witness.record_session_tokens(1500)
```

Token usage flows into the witness ledger alongside every other anchor. Your auditor sees what the agent did, whether it complied, and what it cost -- in one export.

## Multi-Agent Chain Linking

New in v0.3.4. Link anchors across agents in a multi-step pipeline using `cycle_id`:

```python
witness = Witness(
    endpoint="...",
    api_key="axm_...",
    tenant_id="...",
    agent_id="step-1-classifier",
    cycle_id="txn-review-abc123",  # shared across all agents in the chain
)
```

The `cycle_id` survives all clearing levels and appears in every anchor. An auditor can reconstruct the full decision chain by filtering on a single cycle ID.

## Policy Version Binding

New in v0.3.4. Tie every anchor to the specific policy configuration that was in effect:

```python
witness = Witness(
    endpoint="...",
    api_key="axm_...",
    tenant_id="...",
    policy_version="v2.1.0-prod-2026-04-20",
)
```

The SDK hashes the policy version string (SHA-256, first 12 characters) and includes it in every payload. When policies change between audit periods, the hash changes, proving which rules were in effect for each inference.

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

The demo demonstrates 5 procedures using simulated data. All 76 are available in production with real inference data. 207 cross-language test vectors ensure fingerprint parity across Python, TypeScript, Rust, C#, and Ruby. [See live conformity →](https://sovereign.tenova.io/audit/axm_audit_demo_eu_ai_act_public)

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
Check: AI-INF.2    factor_a: 30000    factor_b: 842    factor_c: 0    Verdict: PASS

Translation: "Latency limit was 30,000ms. Actual was 842ms. Under the limit."
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

No SDK needed. Works on any machine, any language. That is what independently verifiable means.

## Clearing Levels (Privacy Control)

You control what leaves your infrastructure. The SDK always returns the full response to your code. Clearing only affects the witness payload.

| Level | Name | What Goes on the Wire | Use Case |
|-------|------|-----------------------|----------|
| 0 | Analytics | Everything: hashes, factors, model, provider, guardrails, prompt hash | Internal analytics |
| 1 | Standard | Hashes, factors, model, provider (no raw text ever) | **Default.** Production apps |
| 2 | Sensitive | Hashes, factors, model only. No provider, no guardrail names | Healthcare, legal, PII |
| 3 | Classified | Numeric factors only. Model name hashed. Zero metadata | Defense, air-gapped |

```python
witness = Witness(
    endpoint="...",
    api_key="axm_...",
    tenant_id="...",
    clearing_level=2,  # Sensitive: strips provider and guardrail names
)
```

At every level, raw prompts and responses **never leave your infrastructure**. Only SHA-256 hashes and numeric factors travel on the wire.

## Local Mode (No Account Needed)

Try the SDK locally before connecting to a live endpoint:

```python
witness = Witness(
    endpoint="https://your-witness-endpoint.example.com",
    api_key="test",
    tenant_id="LOCAL_TEST",
    factor_handoff="file",  # Writes anchors to ./swt3-handoff/ as JSON
)
client = witness.wrap(OpenAI())

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "What is the EU AI Act?"}],
)
# Check ./swt3-handoff/ for JSON files with full anchor data
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

```python
# One line change. Everything else stays the same.
client = OpenAI(base_url="http://gateway:8443/v1")
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
| **SDK only** | `pip install swt3-ai` | Hashes leave, data stays |
| **Gateway** | Docker container in your VPC | Raw traffic never leaves your network |
| **Self-hosted platform** | Docker Compose or Helm | Everything on your infrastructure |
| **Air-gapped** | `docker load` from tarball | Zero internet connectivity required |

## Supported Providers

| Provider | Client | Status |
|----------|--------|--------|
| OpenAI | `openai.OpenAI` / `openai.AsyncOpenAI` | Supported |
| Anthropic | `anthropic.Anthropic` / `anthropic.AsyncAnthropic` | Supported |
| Azure OpenAI | `openai.AzureOpenAI` | Supported (via openai SDK) |
| Ollama / vLLM | `openai.OpenAI(base_url=...)` | Supported (OpenAI-compatible) |
| AWS Bedrock | `boto3` (`bedrock-runtime`) | Supported |
| LiteLLM | `litellm` module | Supported (100+ providers) |
| NVIDIA Dynamo | `@witness_endpoint()` decorator | Supported (infrastructure-layer) |
| Microsoft Foundry | `wrap_foundry(agent)` | Supported (duck-typed) |


### LiteLLM (100+ Providers)

New in v0.3.6. One adapter covers every provider LiteLLM supports:

```python
import litellm
from swt3_ai import Witness

witness = Witness(endpoint="...", api_key="axm_...", tenant_id="...")
llm = witness.wrap(litellm)

# Works with any LiteLLM-supported model
response = llm.completion(model="gpt-4o", messages=[...])
response = llm.completion(model="claude-sonnet-4-20250514", messages=[...])
response = llm.completion(model="bedrock/anthropic.claude-3", messages=[...])

# Async variant
response = await llm.acompletion(model="gpt-4o", messages=[...])
```

Install: `pip install swt3-ai litellm`

### NVIDIA Dynamo (Infrastructure-Layer Witnessing)

New in v0.4.1. Witness inference at the infrastructure layer without modifying application code. The decorator wraps any async generator endpoint that serves OpenAI-compatible responses:

```python
from swt3_ai.adapters.dynamo import witness_endpoint

@witness_endpoint(
    dsn="https://axm_live_key@sovereign.tenova.io/YOUR_TENANT",
    clearing_level=1,
)
async def generate(request):
    async for chunk in upstream_model(request):
        yield chunk
    # Every response is witnessed automatically. Zero application changes.
```

The `dsn` connection string follows the Sentry/Supabase pattern: `https://<api_key>@<host>/<tenant_id>`. You can also use individual env vars (`SWT3_ENDPOINT`, `SWT3_API_KEY`, `SWT3_TENANT_ID`).

Install: `pip install swt3-ai[dynamo]`

### Async Support

New in v0.3.6. The SDK detects async clients automatically:

```python
from openai import AsyncOpenAI

client = witness.wrap(AsyncOpenAI())
response = await client.chat.completions.create(model="gpt-4o", messages=[...])

# Async flush and stop
await witness.flush_async()
await witness.stop_async()
```

Works with `AsyncOpenAI`, `AsyncAnthropic`, and `litellm.acompletion`.

## Resilience (Flight Recorder)

The SDK never blocks your inference. Witnessing runs in a background thread.

If the witness endpoint is unreachable, payloads move to a dead-letter queue. When connectivity returns, the backlog drains automatically with exponential backoff. Your production system is never affected.

```python
witness = Witness(
    endpoint="...",
    api_key="axm_...",
    tenant_id="...",
    buffer_size=50,       # flush every 50 anchors
    flush_interval=10.0,  # or every 10 seconds
    max_retries=5,        # retry before dead-lettering
)
```

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `endpoint` | required | Witness endpoint URL |
| `api_key` | required | API key (axm_ prefix) |
| `tenant_id` | required | Your tenant identifier |
| `clearing_level` | 1 | Privacy level (0-3) |
| `buffer_size` | 10 | Flush after N anchors |
| `flush_interval` | 5.0 | Flush after N seconds |
| `timeout` | 10.0 | HTTP timeout for flush |
| `max_retries` | 3 | Retries before dead-letter |
| `latency_threshold_ms` | 30000 | AI-INF.2 latency limit |
| `guardrails_required` | 0 | AI-GRD.1 required count |
| `guardrail_names` | [] | Names of active guardrails |
| `agent_id` | None | Agent identity (survives all clearing levels) |
| `signing_key` | None | Signing key for payload non-repudiation (HMAC-SHA256 secret or ML-DSA-65 hex seed) |
| `signing_algorithm` | None | `"hmac-sha256"` (default) or `"ml-dsa-65"` (FIPS 204 post-quantum) |
| `cycle_id` | None | Multi-agent chain link (survives all clearing levels) |
| `policy_version` | None | Policy config identifier (hashed in payloads) |
| `strict` | False | Gatekeeper mode: block inference if guardrails insufficient |
| `on_flush` | None | Callback `(payloads, receipts)` after each flush |
| `factor_handoff` | None | "file" for local factor export |
| `factor_handoff_path` | None | Directory for handoff files |

## OpenTelemetry Export

New in v0.3.6. Send SWT3 anchors to your existing observability stack as OTel spans:

```python
from swt3_ai import Witness
from swt3_ai.exporters.otel import OTelExporter

exporter = OTelExporter(tracer_name="swt3-witness")
witness = Witness(..., on_flush=exporter.export)

# Anchors now appear as spans in Datadog, Grafana, Jaeger, Honeycomb, etc.
# Span attributes: swt3.procedure_id, swt3.verdict, swt3.fingerprint, swt3.model_id, ...
```

Install: `pip install swt3-ai[otel]`

The `on_flush` callback fires after each successful batch transmission. You can use it for any custom export destination, not just OTel.

## LangChain Integration

Use SWT3 with LangChain by wrapping the underlying provider client:

```python
from langchain_openai import ChatOpenAI
from openai import OpenAI
from swt3_ai import Witness

witness = Witness(endpoint="...", api_key="axm_...", tenant_id="...")
witnessed_client = witness.wrap(OpenAI())

# Pass the witnessed client to LangChain
llm = ChatOpenAI(client=witnessed_client)

# Or with LiteLLM (covers all LangChain-supported providers):
import litellm
llm_ns = witness.wrap(litellm)
# Use llm_ns.completion() in your LangChain custom LLM
```

Witness LangChain tools with `@witness.wrap_tool()`:

```python
from langchain.tools import tool

@witness.wrap_tool(tool_name="search_docs")
@tool
def search_docs(query: str) -> str:
    """Search the document database."""
    return retriever.invoke(query)

# Every LangChain tool invocation is now witnessed with an AI-TOOL.1 anchor
```

## Installation

```bash
pip install swt3-ai

# With provider extras
pip install swt3-ai[openai]
pip install swt3-ai[anthropic]
pip install swt3-ai[otel]
pip install swt3-ai[all]
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

This SDK produces identical fingerprints to the TypeScript SDK (`@tenova/swt3-ai`). A unified audit trail across your entire stack, verified by shared test vectors at build time.

## Privacy

Your prompts and responses **never leave your infrastructure**. The SDK computes SHA-256 hashes locally and transmits only irreversible hashes and numeric factors. At Clearing Level 3, even the model name is hashed. The witness endpoint is a blind registrar: it stores cryptographic proofs, not your data.

---

## Upgrading to v0.5.2

**Policy-as-Code (new):** `swt3 init`, `swt3 doctor`, `extends:` composition, profile templates, YAML schema validator. No breaking changes.

**Merkle Accumulator (new):** `MerkleAccumulator` class for session-level integrity proofs. `merkle:` config section. No breaking changes.

**Trust Mesh (v0.5.0):** `present_credential()` and `verify_trust()`. No breaking changes for existing code.

**Credential signing (behavioral change):** If your Witness has a `signing_key`, credentials are now HMAC-signed automatically. Counterpart agents must register your key via `trust_registry.register_signing_key()` to verify the signature. Without key registration, signed credentials are denied with `signature_unverifiable`.

**TPM attestation (v0.5.2):** `witness_tpm_attestation()` for AI-HW.3. Reads PCR registers via tpm2-tools. Graceful degradation without TPM. No breaking changes.

**Environmental attestation (v0.5.0):** `witness_environment()` and `witness_energy_draw()` for AI-ENV.1/AI-ENV.2. No breaking changes.

**MCP server:** 16 procedure keyword suggestions (was 8). MCP policy section in swt3.yaml. No breaking changes.

---

## Documentation

- [SDK Reference](https://sovereign.tenova.io/docs/) -- full API, all providers, clearing levels, configuration
- [10-Minute Quickstart](https://sovereign.tenova.io/guides/ai-witness-quickstart.html) -- from install to first anchor
- [NVIDIA Dynamo Guide](https://sovereign.tenova.io/guides/dynamo-integration.html) -- infrastructure-layer witnessing
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

This project is not affiliated with, endorsed by, or sponsored by any third-party AI provider. All third-party trademarks are the property of their respective owners: OpenAI and GPT (OpenAI, Inc.); Claude and Anthropic (Anthropic PBC); Google, Gemini, Vertex AI, and ADK (Google LLC); Azure, Foundry, and Microsoft (Microsoft Corporation); AWS and Bedrock (Amazon Web Services, Inc.); NVIDIA and Dynamo (NVIDIA Corporation); Meta and Llama (Meta Platforms, Inc.); Ollama (Ollama, Inc.); LangChain (LangChain, Inc.); CrewAI (CrewAI, Inc.); MCP (Anthropic PBC); LiteLLM (BerriAI); vLLM (vLLM Project); Cerebras (Cerebras Systems, Inc.). Use of these names is for identification and interoperability purposes only.
