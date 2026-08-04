Witness your AI. Prove it followed the rules. Cryptographic accountability for every inference, tool call, and resource access.

[![PyPI](https://img.shields.io/pypi/v/swt3-ai)](https://pypi.org/project/swt3-ai/)
[![Downloads](https://img.shields.io/pypi/dm/swt3-ai)](https://pypi.org/project/swt3-ai/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/tenova-labs/swt3-ai/blob/main/LICENSE)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-io.tenova%2Fswt3--witness-blue)](https://www.npmjs.com/package/@tenova/swt3-mcp)

# swt3-ai

**SWT3 AI Witness SDK**: tamper-proof evidence that your AI is doing what you say it does. Every inference hashed. Every tool call recorded. Every resource access checked against scope. No prompts or responses ever leave your infrastructure.

EU AI Act GPAI transparency obligations enforce **August 2, 2026**. High-risk enforcement follows **December 2, 2027**. This SDK gives you the evidence chain for both.

## What's New in v0.6.3

Four new witness methods that close the most-requested evidence gaps -- consent, output safety, incident reporting, and training data governance. Each maps to regulations enforcing now or within months.

- **Output Safety Witnessing** (`witness_output_filter`, AI-GRD.2) -- Guardrails run, but proving the output classification result is a separate evidence requirement. When Tencent's Doubao was shut down overnight for output violations, the gap was not whether guardrails existed but whether there was proof each output passed classification. This method records whether model output passed content safety filters, what type of filter ran, and what action was taken. Distinct from `witness_guardrail` (AI-GRD.1, input-side activation) -- this is the output-side classification result. EU AI Act Art. 15(3), NIST AI RMF GOVERN 1.5.

- **Data Provenance Witnessing** (`witness_data_provenance`, AI-DATA.1) -- Training data is the most guarded secret in AI. This method solves the tension: it attests that data governance review was performed WITHOUT disclosing what the training data was. No dataset names, no license strings, no content hashes of the data itself. Instead: governance reviewed (bool), documentation hash (SHA-256 of the data card, not the data), license compliance verified, demographic features confirmed absent. Satisfies EU AI Act Art. 10, SR 11-7 III.A, and CA-AB-2013 through diligence attestation, not disclosure.

- **Jurisdiction Resolver** (`frameworks_for_jurisdiction`) -- Pass an ISO 3166-1 country code or ISO 3166-2 subdivision and get back every applicable regulatory framework with enforcement dates and binding status (mandatory, advisory, voluntary). `frameworks_for_jurisdiction("US-CA")` returns California state laws + US federal frameworks + universal standards. Accepts lists for multi-jurisdiction deployments. 34 frameworks mapped across 50+ jurisdiction codes. Derived from the bundled crosswalks.json -- single source of truth, offline, zero API calls.

### v0.6.2

### Governance Gate (.swt3-gate.yml)

A `.swt3-gate.yml` file in your repo declares which procedures your system must witness, how fresh the evidence must be, and which gaps are critical. Generate one from any supported framework with `--init`, then enforce it in CI. The assessor reads the same file you do.

```yaml
# .swt3-gate.yml
version: "1.0"
name: "credit-decision-service"
strict: true
frameworks:
  EU-AI-ACT:
    risk_class: high
    gates:
      - group: "Article 9 -- Risk Management"
        procedures:
          - procedure: AI-INF.1
            required: true
            max_age: 24h
            description: "Every inference must be witnessed"
          - procedure: AI-GRD.1
            required: true
            critical: true
            hint: "Guardrails must be active at inference time"
```

```bash
swt3 gate --init EU-AI-ACT          # Generate from crosswalk
swt3 gate --validate                 # Check YAML syntax and structure
swt3 gate                            # Evaluate against live ledger (exit 0/1)
swt3 gate --json                     # Machine-readable for CI/CD
```

`swt3 gate` is your pre-merge compliance check. Add it to any CI pipeline that supports exit code checks -- GitHub Actions, GitLab CI, Jenkins, or a local pre-commit hook. Exit 1 means a gap exists -- fix it before it becomes an audit finding. The gate config is version-controlled policy: developers see what's required, CI enforces it, and assessors run `swt3 gate --json` independently against your ledger to confirm compliance without relying on self-reported results. When `strict: true` is set and a `critical` procedure fails, the gate blocks. Non-critical failures warn but pass.

### Auto-Chaining Context Manager

A single AI decision -- retrieve context, run inference, check guardrails -- produces multiple anchors. Without a shared identifier, those anchors are isolated events. The context manager injects a shared `cycle_id` into every witness call inside the block so the full decision is queryable as one chain.

```python
with witness.chain("credit-decision") as ctx:
    wrapped.chat.completions.create(model="gpt-4o", messages=[...])
    witness.witness_rag_context(source="policy-db", chunks=12)
    witness.witness_resource_consumption(tokens_in=8000, tokens_out=2400, api_calls=3)
```

Nesting is supported -- inner chains save and restore the outer cycle_id. Exception-safe. No manual ID management. Use `swt3 reconstruct --cycle CYCLE_ID` to replay the full chain later.

### Forensic Reconstruction (HTML Export)

`swt3 reconstruct` queries the witness ledger and rebuilds a chronological narrative of what an AI system did and when. Every line in the output is backed by a verifiable fingerprint. The `--html` flag produces a self-contained report you can hand to legal, compliance, or a regulator without giving them dashboard access.

```bash
swt3 reconstruct --cycle CYCLE_ID               # Terminal output
swt3 reconstruct --agent orchestrator --last 1h  # By agent
swt3 reconstruct --cycle CYCLE_ID --html         # Self-contained HTML report
swt3 reconstruct --last 30m --json               # Machine-readable
```

The report is independently verifiable. Assessors do not need to trust it -- they can recompute any fingerprint and confirm the evidence is intact.

### Status Findings

`swt3 status` now includes gate evaluation results. If a `.swt3-gate.yml` exists in your project, the output shows which gates pass, which fail, and which procedures need attention -- compliance posture at a glance without leaving the terminal.

### v0.6.1

- **Delegation Trees** (AI-DEL.1) -- witness hierarchical permission delegation with scope binding, cascade revocation, and depth tracking.
- **Resource Consumption Witnessing** (AI-COST.1) -- witness cumulative token usage, API calls, and estimated cost as cryptographic evidence.
- **Deployment Context Detection** -- auto-detect cloud provider, region, runtime, and accelerator from environment variables. Clearing-level aware.

### Compliance Status CLI (`swt3 status`)

Every compliance framework your AI system faces -- EU AI Act, NIST AI RMF, SR 11-7, CMMC -- maps to dozens of requirements across multiple articles. Developers integrate the SDK, mint anchors, and know their code is witnessed. But no one could answer the question that matters most before an assessment: "How much of my framework is actually covered right now?"

The answer used to require logging into a dashboard, cross-referencing a crosswalk spreadsheet, and hoping your ledger had recent entries. `swt3 status` puts that answer in the terminal where developers already live. One command, zero network calls, instant result.

```bash
$ swt3 status

  EU Artificial Intelligence Act ██████░░░░░░░░░░░░░░  30% (15/50)

  Covered:
    ✓ Art.9(2)(a)    AI-GRD.1   5m ago
    ✓ Art.13(1)      AI-EXPL.1  8m ago
    ✓ Art.27         AI-DPIA.1  2w ago

  Next steps:
    AI-COST.1    witness.witness_resource_consumption()
    AI-CONSENT.1 witness.witness_consent()
    AI-DATA.2    witness.witness_data_quality()
```

The bar goes up every time you implement another procedure. Gaps show the exact SDK method to close them -- not documentation links, not vague guidance, but the function call. Use `--json` in CI to fail builds when coverage drops. Use `--compact` for Slack notifications. Use `--full` the week before an assessment to see every article, covered or not. Hand the output to your CISO. Hand the [assessor hot sheet](https://sovereign.tenova.io/guides/assessor-hot-sheet.html) to the auditor.

### v0.6.0

Everything until now has been single-anchor-per-event. v0.6.0 introduced **lifecycle chains** -- sequences of linked anchors that capture an entire governance process from start to finish, reconstructable from a single identifier.

### Lifecycle Chains

When an operator overrides your AI, when a model drifts and triggers a circuit breaker, when you run a challenger model against production -- these are not point events. They are processes with a beginning, middle, and end. A single anchor cannot capture them. A lifecycle chain can.

Regulators and auditors do not accept point-in-time snapshots as evidence for ongoing governance decisions. When your model drifts and you escalate to an emergency override, an auditor needs to see the complete decision sequence: what triggered the escalation, who authorized the override, what fallback was activated, and when normal operation resumed. Without a chain, you reconstruct that narrative from scattered log entries during the audit. With a chain, the evidence trail is cryptographically linked and queryable from a single identifier before the auditor asks.

```python
# Promote a challenger model, monitor it, handle problems
assess_chain = witness.begin_lifecycle("AI-ASSESS.1", fa=10000, fb=23.0, fc=0.0)  # 10K inputs, divergence 0.023, threshold not breached
assess_chain.resolve(fa=10000, fb=23.0, fc=0.0)  # challenger promoted

# Monitor the promoted model for drift
drift_chain = witness.begin_lifecycle("AI-DRIFT.2", fa=0.05, fb=3.0, fc=1.0)  # low drift, operational category, monitoring
drift_chain.checkpoint(fa=0.12, fb=3.0, fc=1.0)  # drift increasing
drift_chain.checkpoint(fa=0.35, fb=0.0, fc=3.0)  # safety threshold -- circuit breaker

# Drift triggered emergency override
emrg_chain = drift_chain.escalate("AI-EMRG.1", fa=1.0, fb=1.0, fc=0.0)  # operator command, supervisor auth, safe state
emrg_chain.checkpoint(fa=1.0, fb=1.0, fc=0.0)  # system stable under fallback
emrg_chain.resolve(fa=1.0, fb=1.0, fc=0.0)  # AI control restored

# Every anchor shares the same chain ID, each links to its parent
print(emrg_chain.chain_id)  # LC-7a38936db8ecec94
```

That is the full governance loop: assessment to promotion to monitoring to escalation to override to restoration. Every transition is a cryptographic anchor. Every chain is reconstructable from a single ID. Auditors query one endpoint and get the complete evidence trail:

```
GET /api/v1/witness/chain?lifecycle_chain_id=LC-7a38936db8ecec94
```

Crash recovery is built in. If your process restarts mid-chain, reconstruct the handle from known state:

```python
chain = witness.resume_lifecycle("AI-EMRG.1", "LC-7a38936db8ecec94", "2e16e2fe92dd")
chain.checkpoint(fa=1.0, fb=0.9, fc=0.0)  # continues from where it left off
```

### Emergency Override Witnessing (AI-EMRG.1)

When a human overrides an AI system -- kills a valve controller, disables a fraud model, intervenes in a decision pipeline -- there is no standard way to produce cryptographic evidence of who authorized it, what fallback state was activated, and when control was restored. Now there is.

```python
witness.witness_operational_override(
    trigger_type="operator_command",       # emergency_stop, operator_command, escalation_protocol, external_responder
    authorization_level="supervisor",      # operator, supervisor, site_manager, emergency_responder
    fallback_state="safe_state",           # safe_state, legacy_controller, manual_mode, degraded_operation, full_shutdown
    system_id="reactor-ai-v3",
    operator_id="eng-042",
    override_reason="valve pressure anomaly",
)
```

Maps to: EU AI Act Art. 14 (human override for high-risk AI), NIST 800-53 IR-4 (incident handling), IEC 61511 (safety instrumented systems).

### Consequence-Mapped Drift (AI-DRIFT.2)

Most drift detection tells you a number changed. It does not tell you what that number means for your operation. AI-DRIFT.2 maps statistical drift to real-world consequence categories with graduated response witnessing.

```python
witness.witness_drift_consequence(
    drift_magnitude=0.15,                  # PSI, KL divergence, or any statistical metric
    consequence_category="safety",         # safety, environmental, financial, operational, reputational
    response_action="circuit_breaker",     # notification_only, increased_monitoring, throttle, circuit_breaker, forced_failover, emergency_shutdown
    drift_metric="psi",
    model_id="fraud-model-v7",
    mapping_version="2026-Q2",
)
```

Maps to: EU AI Act Art. 9(2)(b) (continuous risk estimation), OCC 2026-13 / SR 26-2 (model risk management with materiality mapping).

### Champion-Challenger Assessment (AI-ASSESS.1)

Running a shadow model alongside production? The comparison dashboard in your ML platform is a mutable database entry. AI-ASSESS.1 makes it a cryptographic evidence chain: session configuration, periodic divergence snapshots, and the promotion or rejection decision -- all linked by a shared assessment ID.

```python
witness.witness_champion_challenger(
    inputs_processed=10000,
    max_divergence=0.023,                  # highest divergence observed (raw value, x1000 internally)
    threshold_breached=False,              # True = FAIL, False = PASS
    champion_id="gpt-4o-2026-05",
    challenger_id="gpt-4o-2026-07",
    divergence_metric="kl_divergence",
)
```

Maps to: EU AI Act Art. 15 (post-market monitoring), OCC 2026-13 / SR 26-2 (challenger runs with versioned sign-off).

### v0.5.9

- **Local Witness Mode** -- `Witness()` with no args. No account, no API key, no network. Anchors saved locally, framework coverage shown in console. Try witnessing in 10 seconds.
- **Compliance Intelligence** -- `resolve("AI-FAIR.1")` returns every regulation that procedure satisfies across 34 frameworks, offline, zero dependencies. `coverage("EU-AI-ACT")` shows your session's covered/remaining controls with a score.
- **Bundled Crosswalks** -- 27 frameworks and 107 procedures ship inside the package. Offline regulatory mapping with no API calls.
- **Framework Coverage on Flush** -- after sending anchors, the SDK shows which regulations your evidence covers. Appears on first few flushes, then goes silent.
- **[Crosswalk Explorer](https://sovereign.tenova.io/crosswalks/)** -- public interactive UI to search any procedure or framework control. Browse all controls for a framework, copy results, deep-link with `?procedure=AI-FAIR.1`. No login required.

### v0.5.8

- K8s DaemonSet, Cross-Silicon Hardware Attestation, AGT + LangGraph adapters
- 21 adapters, 107 procedures, 56 namespaces, 27 frameworks, 18 profiles

### K8s Hardware Attestation -- One Command

Every node in your cluster runs AI workloads on hardware you have never attested. If a GPU fails silently, a model gets rescheduled to CPU, or your cloud provider live-migrates you to different silicon, your compliance posture changed and nobody recorded it. Your cluster has NVIDIA nodes for training and Trainium nodes for inference -- the DaemonSet attests both, and the anchor chain shows when workloads move between them.

```bash
helm install swt3 oci://ghcr.io/tenova-labs/charts/swt3-witness --version 0.5.9
```

That is the entire setup. One command. Every node gets a witness pod. Every accelerator gets discovered. Every hour, an AI-HW.1 anchor is minted with the hardware fingerprint.

```json
{
  "swt3_witness": true,
  "procedure": "AI-HW.1",
  "anchor_fingerprint": "d8491581c715",
  "silicon_vendor": "nvidia",
  "topology": "multi",
  "accelerator_count": 4,
  "gpu_count": 4,
  "total_memory_mb": 327680,
  "clearing_level": 1,
  "agent_id": "witness-node-gpu-pool-3a"
}
```

That JSON goes to stdout. Scrape it with Fluentd, Promtail, or any log pipeline. Filter: `jq 'select(.swt3_witness == true)'`.

When a node's hardware changes, consecutive anchors tell the story:

```json
// 09:00 -- 4x NVIDIA H100, training workload
{"anchor_fingerprint":"d8491581c715","silicon_vendor":"nvidia","accelerator_count":4,"total_memory_mb":327680}

// 10:00 -- cloud provider live-migrated to Trainium, same node
{"anchor_fingerprint":"a3f7c2910eb4","silicon_vendor":"aws","accelerator_count":2,"total_memory_mb":65536}
```

The fingerprints are different because the hardware changed. An auditor or drift alert can compare consecutive anchors and see exactly when the silicon shifted, on which node, and whether the compliance posture held.

When you are ready to persist anchors to the clearing house, upgrade to cloud mode:

```bash
helm upgrade swt3 oci://ghcr.io/tenova-labs/charts/swt3-witness --version 0.5.9 \
  --set config.mode=cloud \
  --set cloud.apiKey=axm_YOUR_KEY \
  --set cloud.tenantId=YOUR_TENANT
```

Both modes produce the same cryptographic anchors. The only difference is where they land.

**Security posture:** Non-root (UID 10001). Read-only root filesystem. All capabilities dropped. No privilege escalation. `/sys` mounted read-only for PCI discovery. Health endpoint on `:9090`. 46 MB image.

Open source (Apache-2.0). Source, Dockerfile, and Helm chart: [github.com/tenova-labs/swt3-ai](https://github.com/tenova-labs/swt3-ai).

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

Verify any witness anchor without network calls. The fingerprint formula is deterministic and identical across all 9 SDK languages -- recompute it anywhere in microseconds.

```python
from swt3_ai import verify_anchor

result = verify_anchor(
    anchor,
    tenant_id="<YOUR_TENANT_ID>",
    procedure_id="AI-INF.1",
    factor_a=1, factor_b=1, factor_c=0,
    timestamp_ms=1773316622000,
)
# result.status: "CERTIFIED TRUTH" | "TAMPERED"
```

Zero vendor dependency. Zero network calls. Works air-gapped. The same formula runs in Python, TypeScript, Swift, Rust, C#, Ruby, and MCP with identical output for identical inputs.

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

### Compliance Status

See your framework coverage at a glance:

```bash
swt3 status                       # brief: progress bar + next steps
swt3 status --full                # all articles, covered + gaps
swt3 status --framework EU-AI-ACT # override target framework
swt3 status --json                # machine-readable for CI/CD
swt3 status --compact             # one-line summary for scripts
```

Output shows which framework articles are covered, which procedures are missing, and the exact SDK method to close each gap:

```
  EU Artificial Intelligence Act ██████░░░░░░░░░░░░░░  30% (15/50)

  Covered:
    ✓ Art.9(2)(a)    AI-GRD.1   5m ago
    ✓ Art.13(1)      AI-EXPL.1  8m ago
    ✓ Art.27         AI-DPIA.1  2w ago

  Next steps:
    AI-COST.1    witness.witness_resource_consumption()
    AI-CONSENT.1 witness.witness_consent()
    AI-DATA.2    witness.witness_data_quality()
```

Zero network calls. Works offline. Reads your local WAL and crosswalk data.

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

SWT3 AI witnessing procedures map to specific EU AI Act obligations. Sample mapping (107 procedures total):

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

The demo demonstrates 5 procedures using simulated data. All 108 are available in production with real inference data. 226 cross-language test vectors ensure fingerprint parity across Python, TypeScript, Swift, Rust, C#, Ruby, and MCP. [See live conformity →](https://sovereign.tenova.io/audit/axm_audit_demo_eu_ai_act_public)

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

Witness your first inference with zero configuration:

```python
from swt3_ai import Witness
from openai import OpenAI

witness = Witness()  # No args. Local mode.
client = witness.wrap(OpenAI())

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "What is the EU AI Act?"}],
)

# Console output:
#   [SWT3] Local mode -- anchors saved to ./swt3-local/
#   [SWT3] 5 procedures witnessed across 7 frameworks (EU-AI-ACT, ISO-42001, ...)
#   [SWT3] Run witness.coverage("EU-AI-ACT") to see your coverage score

report = witness.coverage("EU-AI-ACT")
print(f"Score: {report['score']} ({report['covered_count']}/{report['total_controls']})")
```

Anchors are saved as JSON in `./swt3-local/`. Add `swt3-local/` to your `.gitignore`. When you are ready to persist evidence to the clearing house, add your endpoint and API key:

```python
witness = Witness(
    endpoint="https://sovereign.tenova.io/api/v1",
    api_key="axm_live_...",
    tenant_id="YOUR_TENANT",
)
```

## Compliance Intelligence

Resolve any procedure to every regulation it satisfies. Offline, zero network calls:

```python
from swt3_ai import resolve

resolve("AI-FAIR.1")
# {"EU-AI-ACT": "Art.10(2)(f)", "NIST-AI-RMF": "MEASURE 2.5", "ISO-42001": "A.8.4", ...}

resolve("AI-INF.1")
# {"EU-AI-ACT": "Art.12(1)", "FIVE-EYES-AGENTIC": "FE-2,FE-4", ...}
```

27 frameworks bundled. 107 procedures mapped. Updated with each SDK release.

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
| xAI (Grok) | `openai.OpenAI(base_url="https://api.x.ai/v1")` | Supported (OpenAI-compatible) |
| Thinking Machines (Inkling) | `openai.OpenAI(base_url="http://gpu-cluster:8000/v1")` | Supported (OpenAI-compatible, vLLM Day-0) |
| Ollama / vLLM | `openai.OpenAI(base_url=...)` | Supported (OpenAI-compatible) |
| AWS Bedrock | `boto3` (`bedrock-runtime`) | Supported |
| LiteLLM | `litellm` module | Supported (100+ providers) |
| Google ADK | `wrap_google_adk(agent)` | Supported (agent tool witnessing) |
| CrewAI | `wrap_crewai(crew)` | Supported (multi-agent orchestration) |
| A2A Protocol | `wrap_a2a(client)` | Supported (inter-agent communication) |
| Cohere | `wrap_cohere(client)` | Supported (V2 API, streaming) |
| Cerebras | `wrap_cerebras(client)` | Supported (Cerebras Inference) |
| Qdrant | `wrap_qdrant(client)` | Supported (RAG pipeline witnessing) |
| NVIDIA Dynamo | `@witness_endpoint()` decorator | Supported (infrastructure-layer) |
| NVIDIA Triton | `wrap_triton(client)` | Supported (inference server) |
| Microsoft Foundry | `wrap_foundry(agent)` | Supported (Azure AI Foundry, duck-typed) |
| Microsoft AGT | `wrap_agt(engine)` | Supported (Agent Governance Toolkit, duck-typed) |
| LangGraph | `wrap_langgraph(graph)` | Supported (state graph orchestration) |


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

This SDK produces identical fingerprints to the TypeScript, Swift, Rust, C#, and Ruby SDKs. 7 languages, one audit trail. 226 cross-language test vectors verified at build time.

## Privacy

Your prompts and responses **never leave your infrastructure**. The SDK computes SHA-256 hashes locally and transmits only irreversible hashes and numeric factors. At Clearing Level 3, even the model name is hashed. The witness endpoint is a blind registrar: it stores cryptographic proofs, not your data.

---

## Upgrading to v0.6.1

**Delegation trees (new):** `witness_delegation_tree()`, `delegation_tree_from_tools()`, `delegation_tree_from_capabilities()` added. AI-DEL.1 procedure. No breaking changes.

**Resource consumption (new):** `witness_resource_consumption()` now accepts optional `deployment_context` dict. No breaking changes.

**Deployment detection (new):** `from swt3_ai.deployment import detect_deployment_context`. New module, no changes to existing code.

## Upgrading to v0.6.0

**Lifecycle chains (new):** `begin_lifecycle()`, `resume_lifecycle()` added. New exports: `LifecycleChainHandle`, `OVERRIDE_TRIGGER_CODES`, `AUTHORIZATION_LEVEL_CODES`, `FALLBACK_STATE_CODES`, `CONSEQUENCE_CATEGORY_CODES`, `DRIFT_RESPONSE_CODES`. No breaking changes. All existing code works unchanged.

**3 new procedures:** `witness_operational_override()` (AI-EMRG.1), `witness_drift_consequence()` (AI-DRIFT.2), `witness_champion_challenger()` (AI-ASSESS.1). These are additive -- no existing behavior changes.

**Crosswalks updated:** 27 frameworks bundled (was 28). 4 new: TN-SB-1580, RI-AI-LAWS, VN-LAW-134, HEALTH-INS-AI.

## Upgrading to v0.5.9

**Local mode (new):** `Witness()` with no args enters local mode. No breaking changes. Existing code with endpoint/api_key/tenant_id works exactly as before.

**Compliance intelligence (new):** `resolve()`, `coverage()`, `crosswalk_version()` added. New exports: `resolve`, `resolve_framework`, `crosswalk_frameworks`, `crosswalk_procedures`, `crosswalk_version`. No breaking changes.

**coverage() return keys:** When called with a framework argument, the result dict uses `remaining` and `remaining_count` (not `missing`). `total_controls` and `covered_count` are also included.

**Buffer CTA updated:** The console message after first flush no longer shows the signup link or EU AI Act deadline. Connected users see a dashboard link instead.

### Previous versions

**v0.5.8:** Cross-silicon hardware, AGT + LangGraph adapters, K8s DaemonSet.

**v0.5.7:** Agent transactions, Google ADK, CrewAI, A2A.

**v0.5.2:** Policy-as-Code, `swt3 init`, built-in profiles.

**v0.5.0:** Trust Mesh, `present_credential()`, `verify_trust()`.

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
- [Assessor Hot Sheet](https://sovereign.tenova.io/guides/assessor-hot-sheet.html) -- 2-page printable guide to hand your assessor during compliance reviews
- [Edge Attestation](https://sovereign.tenova.io/guides/edge-attestation.html) -- on-device AI witnessing for Apple platforms and edge K8s
- [Crosswalk Resolver API](https://sovereign.tenova.io/api/v1/crosswalks/resolve?procedure=AI-FAIR.1) -- query any procedure or framework control across 34 frameworks
- [All 150 Guides](https://sovereign.tenova.io/guides/) -- regulatory crosswalks, assessor walkthroughs, integration guides

---

*SWT3: Sovereign Witness Traceability. We don't run your models. We witness them.*

SWT3 and Sovereign Witness Traceability are trademarks of Tenable Nova LLC. Patent pending. Apache 2.0 licensed.

This project is not affiliated with, endorsed by, or sponsored by any third-party AI provider. All third-party trademarks are the property of their respective owners: OpenAI and GPT (OpenAI, Inc.); Claude and Anthropic (Anthropic PBC); Google, Gemini, Vertex AI, and ADK (Google LLC); Azure, Foundry, and Microsoft (Microsoft Corporation); AWS and Bedrock (Amazon Web Services, Inc.); NVIDIA and Dynamo (NVIDIA Corporation); Meta and Llama (Meta Platforms, Inc.); Ollama (Ollama, Inc.); LangChain (LangChain, Inc.); CrewAI (CrewAI, Inc.); MCP (Anthropic PBC); LiteLLM (BerriAI); vLLM (vLLM Project); Cerebras (Cerebras Systems, Inc.); LangGraph and LangChain (LangChain, Inc.). Use of these names is for identification and interoperability purposes only.
