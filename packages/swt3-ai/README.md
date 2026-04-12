Witness your AI agents, don't just monitor them. Deterministic accountability for every AI action.

[![PyPI](https://img.shields.io/pypi/v/swt3-ai)](https://pypi.org/project/swt3-ai/)
[![Downloads](https://img.shields.io/pypi/dm/swt3-ai)](https://pypi.org/project/swt3-ai/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/tenova-labs/swt3-ai/blob/main/LICENSE)

# swt3-ai

**SWT3 AI Witness SDK**:continuous, cryptographic attestation for AI systems. Prove your models are running approved weights, safety guardrails are active, inferences are traceable, and fairness thresholds are met. All without your prompts or responses ever leaving your infrastructure.

Built on the [SWT3 Protocol](https://github.com/tenova-labs/swt3-ai), the same cryptographic witnessing layer trusted for federal compliance (NIST 800-53, CMMC, FedRAMP).

## Why SWT3?

AI agents are making production decisions, but when regulators ask "prove your AI followed the rules," most teams have nothing but logs and dashboards. SWT3 produces cryptographic, tamper-proof evidence of every AI action. No prompt data leaves your infrastructure. The EU AI Act (enforcement: August 2, 2026) requires exactly this.

## See It Work in 10 Seconds

No API keys. No account. No network calls.

```bash
pip install swt3-ai
python -m swt3_ai.demo
```

You'll see the full SWT3 witnessing pipeline: hash, extract, clear, anchor, verify — plus a **Regulatory Coverage Summary** mapping each procedure to EU AI Act articles. The demo shows 3/12 obligations covered, with the 9 uncovered gaps listed by article citation. When you're ready to close those gaps, keep reading.

## Three Lines of Code

```python
from swt3_ai import Witness
from openai import OpenAI

witness = Witness(
    endpoint="https://sovereign.tenova.io",
    api_key="axm_live_...",
    tenant_id="YOUR_ENCLAVE",
)
client = witness.wrap(OpenAI())

# That's it. Every inference is now witnessed.
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Summarize this contract..."}],
)
# response is untouched, use it exactly as before
print(response.choices[0].message.content)
```

No code changes. No performance impact. No data leakage.

## Quick Start (Try It Locally)

Want to see the SDK work before connecting to a live endpoint? Use `factor_handoff` to write witness anchors to local JSON files. No account needed.

```python
from swt3_ai import Witness
from openai import OpenAI

witness = Witness(
    endpoint="https://sovereign.tenova.io",
    api_key="test",                # any string, handoff runs before network flush
    tenant_id="LOCAL_TEST",
    factor_handoff="file",         # write anchors to ./swt3-handoff/ as JSON
)
client = witness.wrap(OpenAI())

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "What is the EU AI Act?"}],
)
print(response.choices[0].message.content)

# Check ./swt3-handoff/ - you'll see a JSON file per inference with:
#   - SHA-256 fingerprint
#   - Model ID, latency, token count
#   - Clearing level applied
#   - Full factor data for independent verification
```

When you're ready for production, [create a free account](https://sovereign.tenova.io/signup?ref=sdk) to get your tenant ID and API key. Point the SDK at your enclave and every inference is witnessed, anchored, and verifiable.

## Local SDK vs Axiom Engine

| Capability | Local SDK | + Axiom Engine (free) |
|---|---|---|
| Mint anchors | ✓ | ✓ |
| Verify one anchor | ✓ | ✓ |
| Evidence retention | 0 (files on disk) | 7 days (free) / 90 days (Pro) |
| Compliance dashboard | — | ✓ |
| Auditor share links | — | ✓ (Pro) |
| EU AI Act conformity | — | ✓ (Pro) |
| Compliance Passport | — | ✓ (Pro) |
| Enclave integrity proof | — | ✓ (Enclave) |
| **Survives an audit** | **No** | **Yes** |

> **Local anchors prove it to you. Axiom proves it to your auditor.**
> [Create a free account →](https://sovereign.tenova.io/signup?ref=sdk)

## What Happens Per Inference

1. **Intercept**: The SDK wraps your AI client transparently
2. **Hash**: Prompts and responses are SHA-256 hashed locally
3. **Extract**: Model version, latency, token count, guardrail status captured as numeric factors
4. **Clear**: Raw text is purged from the wire payload (configurable clearing level)
5. **Anchor**: Factors are batched and flushed to the SWT3 Witness Ledger in the background
6. **Return**: Your original response returns untouched. Witnessing runs in a background thread — median overhead is <1ms on the hot path (hash + buffer, no network call)

The result: an immutable, cryptographic proof that your AI followed the rules, without the auditor ever needing to see the sensitive data.

## What Gets Witnessed

Each inference produces anchors for these AI procedures:

| Procedure | Domain | What it proves |
|-----------|--------|---------------|
| AI-INF.1 | Inference | Prompt and response were captured (provenance) |
| AI-INF.2 | Inference | Latency within threshold (detects model swaps) |
| AI-MDL.1 | Model | Deployed model matches approved hash (integrity) |
| AI-MDL.2 | Model | Model version identifier recorded (tracking) |
| AI-GRD.1 | Guardrail | Required safety filters were active (enforcement) |
| AI-GRD.2 | Safety | No refusal or content filter triggered (content safety) |
| AI-TOOL.1 | Tool Use | Agent tool/function call recorded (latency, success) |
| AI-ID.1 | Identity | Witness instance identity attested (agent accountability) |

Each procedure maps to both **NIST AI RMF** functions and **EU AI Act** articles. When a CISO looks at the ledger, they don't see "inference captured." They see "Article 12 Compliance: Verified."

## Supported Providers

| Provider | Client | Status |
|----------|--------|--------|
| OpenAI | `openai.OpenAI` | **Supported** |
| Anthropic | `anthropic.Anthropic` | **Supported** |
| Azure OpenAI | `openai.AzureOpenAI` | **Supported** (via `openai` SDK) |
| Ollama / vLLM | `openai.OpenAI(base_url=...)` | **Supported** (OpenAI-compatible) |
| AWS Bedrock | `bedrock-runtime` | Planned |

### OpenAI

```python
from swt3_ai import Witness
from openai import OpenAI

witness = Witness(endpoint="...", api_key="axm_...", tenant_id="...")
client = witness.wrap(OpenAI())

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello"}],
)
```

### Anthropic

```python
from swt3_ai import Witness
from anthropic import Anthropic

witness = Witness(endpoint="...", api_key="axm_...", tenant_id="...")
client = witness.wrap(Anthropic())

message = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello"}],
)
```

## Clearing Levels

The Clearing Engine controls what leaves your infrastructure. Your code always gets the full response. Clearing only affects the wire payload sent to the witness ledger.

| Level | Name | What's on the wire | Use case |
|-------|------|-------------------|----------|
| 0 | Analytics | Hashes + factors + model ID + provider + guardrail names | Internal analytics, non-sensitive workloads |
| 1 | Standard | Hashes + factors + model ID + provider metadata | **Default.** Production SaaS, enterprise apps |
| 2 | Sensitive | Hashes + factors + model ID only | Healthcare, legal, PII-adjacent workloads |
| 3 | Classified | Numeric factors only. Model ID hashed. No metadata. | Defense, classified environments, air-gapped |

```python
# Level 2: Sensitive, no provider names, no guardrail names on the wire
witness = Witness(
    endpoint="...",
    api_key="axm_...",
    tenant_id="...",
    clearing_level=2,
)
```

At Level 1+, raw prompts and responses **never leave your infrastructure**. Only SHA-256 hashes and numeric factors travel on the wire. This satisfies both GDPR Article 17 (right to erasure) and EU AI Act Article 12 (record-keeping) simultaneously.

## View an Anchor

A Level 1 anchor for AI-INF.1 (Inference Provenance). This is what reaches the witness ledger. No prompts, no responses, just cryptographic proof.

```json
{
  "procedure_id": "AI-INF.1",
  "factor_a": 1,
  "factor_b": 1,
  "factor_c": 0,
  "clearing_level": 1,
  "anchor_fingerprint": "c059eb5938c0",
  "anchor_epoch": 1774800000,
  "fingerprint_timestamp_ms": 1774800000000,
  "ai_prompt_hash": "315f5bdb76d078c4",
  "ai_response_hash": "a1b2c3d4e5f60718",
  "ai_latency_ms": 842,
  "ai_model_id": "gpt-4o",
  "ai_context": {
    "provider": "openai",
    "guardrails": ["content-filter", "pii-redaction"]
  }
}
```

The `anchor_fingerprint` is computed from `SHA256("WITNESS:{tenant}:{procedure}:{fa}:{fb}:{fc}:{ts}")`. Anyone with the factors can independently verify the math.

## Resilience (Flight Recorder)

The SDK never blocks your inference call. Witnessing happens in a background thread.

If the witness endpoint is unreachable (network outage, air-gapped deployment), payloads move to a **dead-letter queue** instead of being dropped. When connectivity is restored, the backlog drains automatically with exponential backoff.

```python
witness = Witness(
    endpoint="...",
    api_key="axm_...",
    tenant_id="...",
    buffer_size=50,       # flush every 50 anchors
    flush_interval=10.0,  # or every 10 seconds
    max_retries=5,        # retry 5 times before dead-lettering
)

# Check dead-letter status
print(f"Pending: {witness.pending}")
```

## Zero Lock-in

Remove the `witness.wrap()` call. Your code works exactly as before. Anchors already minted remain in the ledger.

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `endpoint` | *required* | Witness endpoint URL |
| `api_key` | *required* | API key (`axm_*` prefix) |
| `tenant_id` | *required* | Your enclave identifier |
| `clearing_level` | `1` | Clearing level (0-3) |
| `buffer_size` | `10` | Flush after N anchors |
| `flush_interval` | `5.0` | Flush after N seconds |
| `timeout` | `10.0` | HTTP timeout for flush |
| `max_retries` | `3` | Retry count before dead-letter |
| `latency_threshold_ms` | `30000` | AI-INF.2 latency threshold |
| `guardrails_required` | `0` | AI-GRD.1 required guardrail count |
| `guardrail_names` | `[]` | Names of active guardrails |
| `factor_handoff` | `None` | `"file"` to enable local factor export |
| `factor_handoff_path` | `None` | Directory for factor handoff files |

## Factor Handoff (Clearing Level 2+)

At Clearing Level 2 or 3, some or all verifiable data is stripped from the wire before it reaches the witness endpoint. The Factor Handoff ensures your factors are safely written to a local directory **before** clearing proceeds. If the write fails, the payload is not transmitted.

```python
witness = Witness(
    endpoint="https://sovereign.tenova.io",
    api_key="axm_live_...",
    tenant_id="YOUR_ENCLAVE",
    clearing_level=3,
    factor_handoff="file",
    factor_handoff_path="/secure/vault/factors/",
)
```

Each anchor gets its own JSON file (named by fingerprint) containing the full uncleared factors and metadata needed for independent re-verification. Files are written with 0600 permissions.

For the full protocol specification, see the [Factor Handoff Protocol](https://sovereign.tenova.io/docs/factor-handoff-protocol.html).

## Custom Pipelines

For non-standard LLM integrations, use the decorator or manual API:

```python
@witness.inference()
def my_custom_llm(prompt: str) -> str:
    # Your custom inference logic
    return result

# Or manual recording
from swt3_ai.types import InferenceRecord
from swt3_ai.fingerprint import sha256_truncated

record = InferenceRecord(
    model_id="my-model-v2",
    model_hash=sha256_truncated("my-model-v2"),
    prompt_hash=sha256_truncated(prompt),
    response_hash=sha256_truncated(response),
    latency_ms=elapsed_ms,
    provider="custom",
)
witness.record(record)
```

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
- **NIST AI RMF**: GOVERN, MAP, MEASURE, MANAGE (10 subcategories)
- **ISO 42001**: Annex A AI management controls
- **NIST 800-53**: SI-7 (integrity), AU-2/AU-3 (audit), AC controls

## AI Witness-as-a-Service

SWT3 AI Witness is available as a managed service through [Axiom Sovereign Engine](https://tenova.io):

| Tier | Retention | Key Features | Price |
|------|-----------|-------------|-------|
| **Open** | 7 days | SDK, dashboard, public verify | Free |
| **Pro** | 90 days | + AI conformity exports, regulatory reports | $499/mo |
| **Enclave** | 1 year | + OSCAL, Gate API, attestations, webhook feeds | $9,500/mo |
| **Sovereign** | Custom | + White-glove ATO sprint, mock assessment, on-prem | [Book Assessment](https://calendly.com/tenova-axiom/30min) |

1,600+ downloads across npm and PyPI. 151 procedures. 13 frameworks. Patent pending.

## Ready to Witness Your AI?

Get an API key and start witnessing in under 10 minutes:

- [Create a Free Account](https://sovereign.tenova.io/signup?ref=sdk) - instant API key, start witnessing in 5 minutes
- [Quickstart Guide](https://sovereign.tenova.io/guides/ai-witness-quickstart.html) - 10-minute integration walkthrough
- [Book a Strategy Call](https://calendly.com/tenova-axiom/30min) - enterprise, on-prem, or Sovereign tier

## Compliance & Privacy

Your prompts and responses **never leave your infrastructure**. The SDK computes SHA-256 hashes locally and transmits only irreversible hashes and numeric factors. At Clearing Level 3, even the model name is hashed.

- [Data Flow and Privacy Architecture](https://github.com/tenova-labs/swt3-ai/blob/main/docs/data-flow.md) - Visual data boundary for legal and DPO review
- [Clearing & Data Sovereignty Addendum](https://sovereign.tenova.io/terms/clearing-addendum) - Shared responsibility, incident response SLA, regulatory applicability
- [Air-Gap Deployment Guide](https://github.com/tenova-labs/swt3-ai/blob/main/docs/sovereign-sync.md) - Zero-egress operation, sneakernet sync, offline verification

## Documentation

- [SDK Developer Docs](https://sovereign.tenova.io/docs/) - Quickstart, providers, clearing levels, configuration
- [Factor Handoff Protocol](https://sovereign.tenova.io/docs/factor-handoff-protocol.html) - How factors are securely transferred to your custody
- [CMMC Compliance Overlay](https://sovereign.tenova.io/guides/cmmc-overlay.html) - Control mappings for defense industrial base

---

## Support the Standard

If you believe AI systems should prove they followed the rules, [give us a star](https://github.com/tenova-labs/swt3-ai). Every star signals that the industry is ready for an accountability standard.

---

*SWT3: Sovereign Witness Traceability. We don't run your models. We witness them.*

*TeNova: Defining the AI Accountability Standard. One protocol. Zero Integrity Debt. Total Sovereignty.*

SWT3 and Sovereign Witness Traceability are trademarks of Tenable Nova LLC. Patent pending. Apache 2.0 licensed.
