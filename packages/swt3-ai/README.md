Witness your AI. Prove it followed the rules. Cryptographic accountability for every inference, tool call, and resource access.

[![PyPI](https://img.shields.io/pypi/v/swt3-ai)](https://pypi.org/project/swt3-ai/)
[![Downloads](https://img.shields.io/pypi/dm/swt3-ai)](https://pypi.org/project/swt3-ai/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/tenova-labs/swt3-ai/blob/main/LICENSE)

# swt3-ai

**SWT3 AI Witness SDK**: tamper-proof evidence that your AI is doing what you say it does. Every inference hashed. Every tool call recorded. Every resource access checked against scope. No prompts or responses ever leave your infrastructure.

The EU AI Act takes effect **August 2, 2026**. When regulators ask "prove your AI followed the rules," you need more than logs. You need cryptographic proof.

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

This produces an **AI-TOOL.1** anchor. When an auditor asks "what tools did your agent use and did they work?" you have the cryptographic record.

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

When a CISO asks "can you prove your AI agent only accessed what it was authorized to access?" this is the answer.

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
| **Survives an audit** | **No** | **Yes** |

> Local anchors prove it to you. A connected engine proves it to your auditor.

## Supported Providers

| Provider | Client | Status |
|----------|--------|--------|
| OpenAI | `openai.OpenAI` | Supported |
| Anthropic | `anthropic.Anthropic` | Supported |
| Azure OpenAI | `openai.AzureOpenAI` | Supported (via openai SDK) |
| Ollama / vLLM | `openai.OpenAI(base_url=...)` | Supported (OpenAI-compatible) |
| AWS Bedrock | `bedrock-runtime` | Planned |

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
| `factor_handoff` | None | "file" for local factor export |
| `factor_handoff_path` | None | Directory for handoff files |

## Installation

```bash
pip install swt3-ai

# With provider extras
pip install swt3-ai[openai]
pip install swt3-ai[anthropic]
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

*SWT3: Sovereign Witness Traceability. We don't run your models. We witness them.*

SWT3 and Sovereign Witness Traceability are trademarks of Tenable Nova LLC. Patent pending. Apache 2.0 licensed.
