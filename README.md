Witness your AI. Prove it followed the rules. Cryptographic accountability for every inference, tool call, and resource access.

[![PyPI](https://img.shields.io/pypi/v/swt3-ai)](https://pypi.org/project/swt3-ai/)
[![Downloads](https://img.shields.io/pypi/dm/swt3-ai)](https://pypi.org/project/swt3-ai/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/tenova-labs/swt3-ai/blob/main/LICENSE)

# swt3-ai

**SWT3 AI Witness SDK**: tamper-proof evidence that your AI is doing what you say it does. Every inference hashed. Every tool call recorded. Every resource access checked against scope. No prompts or responses ever leave your infrastructure.

GPAI transparency obligations are enforceable now. EU AI Act high-risk enforcement begins **December 2, 2027**. This SDK gives you the evidence chain.

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

The `agent_id` survives all clearing levels. The `signing_key` produces a cryptographic signature on every anchor, proving which agent instance created it. This enables:
- Per-agent compliance passports
- Fleet-wide governance dashboards
- Agent-scoped evidence packages for auditors

## Gatekeeper Mode (Pre-Call Enforcement)

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

All 36 SWT3 AI witnessing procedures map to specific EU AI Act obligations:

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

The demo demonstrates 3 procedures using simulated data. All 36 are available in production with real inference data. [See live conformity →](https://sovereign.tenova.io/audit/axm_audit_demo_eu_ai_act_public)

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

## Supported Providers

| Provider | Client | Status |
|----------|--------|--------|
| OpenAI | `openai.OpenAI` / `openai.AsyncOpenAI` | Supported |
| Anthropic | `anthropic.Anthropic` / `anthropic.AsyncAnthropic` | Supported |
| Azure OpenAI | `openai.AzureOpenAI` | Supported (via openai SDK) |
| Ollama / vLLM | `openai.OpenAI(base_url=...)` | Supported (OpenAI-compatible) |
| AWS Bedrock | `boto3` (`bedrock-runtime`) | Supported |
| LiteLLM | `litellm` module | Supported (100+ providers) |

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
| `signing_key` | None | HMAC-SHA256 key for payload signing |
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

## MCP Server (Agentic AI)

AI agents can discover SWT3 compliance tools automatically via the Model Context Protocol. No developer integration required. The agent finds the tools and uses them on its own.

```bash
npm install @tenova/swt3-mcp
```

Add to your MCP config:

```json
{ "mcpServers": { "swt3": { "command": "npx", "args": ["@tenova/swt3-mcp"] } } }
```

Zero configuration required. Works immediately in demo mode. Add `SWT3_API_KEY` to connect to a production ledger. Compatible with Claude, GPT, and any MCP-compatible agent.

**Tools provided:** `witness_inference`, `verify_anchor`, `list_anchors`, `posture`, `signup`, `health`

This is the first compliance protocol with native MCP support. Agents discover witnessing through standard tool enumeration, making compliance an infrastructure capability rather than a developer burden.

## Privacy

Your prompts and responses **never leave your infrastructure**. The SDK computes SHA-256 hashes locally and transmits only irreversible hashes and numeric factors. At Clearing Level 3, even the model name is hashed. The witness endpoint is a blind registrar: it stores cryptographic proofs, not your data.

---

## Documentation

- [SDK Reference](https://sovereign.tenova.io/docs/) -- full API, all providers, clearing levels, configuration
- [10-Minute Quickstart](https://sovereign.tenova.io/guides/ai-witness-quickstart.html) -- from install to first anchor
- [NVIDIA Dynamo Guide](https://sovereign.tenova.io/guides/dynamo-integration.html) -- infrastructure-layer witnessing
- [SWT3 Protocol Spec](https://sovereign.tenova.io/guides/swt3-protocol.html) -- formal specification with ABNF grammar
- [Design Rationale](https://sovereign.tenova.io/guides/swt3-design-rationale.html) -- why every protocol decision was made
- [UCT Registry](https://sovereign.tenova.io/registry) -- 162 procedures, full factor definitions
- [Anchor Verifier](https://sovereign.tenova.io/verify) -- verify any anchor, zero server calls

---

*SWT3: Sovereign Witness Traceability. We don't run your models. We witness them.*

SWT3 and Sovereign Witness Traceability are trademarks of Tenable Nova LLC. Patent pending. Apache 2.0 licensed.
