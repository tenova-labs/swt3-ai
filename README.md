# SWT3 - Sovereign Witness Protocol for AI

> Don't audit the agent's thoughts. Audit the agent's actions.

[![npm](https://img.shields.io/npm/v/@tenova/swt3-ai)](https://www.npmjs.com/package/@tenova/swt3-ai)
[![PyPI](https://img.shields.io/pypi/v/swt3-ai)](https://pypi.org/project/swt3-ai/)
[![npm downloads](https://img.shields.io/npm/dm/@tenova/swt3-ai)](https://www.npmjs.com/package/@tenova/swt3-ai)
[![PyPI downloads](https://img.shields.io/pypi/dm/swt3-ai)](https://pypi.org/project/swt3-ai/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## The Problem

AI agents are making production decisions: approving loans, triaging patients, managing infrastructure, writing code. When something goes wrong, there is no tamper-proof audit trail. Logs are mutable. Metrics are averaged. Nobody can prove what the agent actually did.

The EU AI Act (enforcement: August 2, 2026) requires provable evidence that high-risk AI systems operate within approved parameters. NIST AI RMF, SR 11-7, and CMMC impose similar obligations. Most teams have nothing but dashboards and hope.

## The Protocol

SWT3 (Sovereign Witness Traceability) is a deterministic witness protocol for AI systems. It intercepts AI actions, hashes the evidence, and anchors cryptographic proof to an immutable ledger. Your code gets the full response. The auditor gets tamper-proof evidence. Raw prompts and responses never leave your infrastructure.

- **Deterministic, not probabilistic.** The witness engine uses fixed logic, not AI, to evaluate compliance.
- **Zero data retention.** Configurable clearing levels strip sensitive content before it leaves your environment.
- **Framework-mapped.** Every anchor maps to EU AI Act articles, NIST AI RMF functions, and federal controls.

## Try It (10 Seconds, No Account)

**Python**
```bash
pip install swt3-ai
python -m swt3_ai.demo
```

**TypeScript**
```bash
npm install @tenova/swt3-ai
npx swt3-demo
```

No API keys. No account. No network calls. You will see the full witnessing pipeline run locally.

## Three Lines to Production

```python
from swt3_ai import Witness
from openai import OpenAI

witness = Witness(endpoint="https://sovereign.tenova.io", api_key="axm_live_...", tenant_id="YOUR_TENANT")
client = witness.wrap(OpenAI())

# Every inference is now witnessed. Your code does not change.
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Summarize this contract"}],
)
```

Works with OpenAI, Anthropic, Vercel AI SDK, and any OpenAI-compatible endpoint (vLLM, Ollama, Azure OpenAI).

## What Gets Witnessed

Each inference produces anchors for these procedures:

| Procedure | Domain | What It Proves | Regulatory Mapping |
|-----------|--------|---------------|-------------------|
| AI-INF.1 | Inference | Prompt and response captured (provenance) | EU AI Act Art. 12 |
| AI-INF.2 | Inference | Latency within threshold (detects model swaps) | NIST AI RMF MEASURE 2.6 |
| AI-MDL.1 | Model | Deployed model matches approved hash (integrity) | EU AI Act Art. 9 |
| AI-MDL.2 | Model | Model version identifier recorded (tracking) | EU AI Act Art. 72 |
| AI-GRD.1 | Guardrail | Required safety filters were active (enforcement) | NIST AI RMF MANAGE 4.1 |
| AI-GRD.2 | Safety | No content filter or refusal triggered | EU AI Act Art. 14 |
| AI-TOOL.1 | Tool Use | Agent tool/function call recorded (latency, success) | NIST AI RMF MANAGE 4.1 |
| AI-ID.1 | Identity | Witness instance identity attested (agent accountability) | EU AI Act Art. 13 |

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

The `anchor_fingerprint` is computed from `SHA256("WITNESS:{tenant}:{procedure}:{fa}:{fb}:{fc}:{ts}")`. Anyone with the factors can independently verify the math. Trust is a vulnerability. Math is the remedy.

## Clearing Levels

The clearing engine controls what leaves your infrastructure. Your code always gets the full response. Clearing only affects what reaches the witness ledger.

| Level | Name | On the Wire | Use Case |
|-------|------|------------|----------|
| 0 | Analytics | Hashes + factors + model + provider + guardrails | Internal analytics |
| 1 | Standard | Hashes + factors + model + provider | **Default.** Production apps |
| 2 | Sensitive | Hashes + factors + model only | Healthcare, legal, PII workloads |
| 3 | Classified | Numeric factors only. Model ID hashed. | Defense, air-gapped environments |

At Level 1+, raw prompts and responses **never leave your infrastructure**.

## SDKs

| Language | Package | Install |
|----------|---------|---------|
| Python | [`swt3-ai`](https://pypi.org/project/swt3-ai/) | `pip install swt3-ai` |
| TypeScript | [`@tenova/swt3-ai`](https://www.npmjs.com/package/@tenova/swt3-ai) | `npm install @tenova/swt3-ai` |

Both SDKs produce identical SWT3 fingerprints. 10 cross-language test vectors validated at build time.

## Get Started

1. [Create a free account](https://sovereign.tenova.io/signup) - instant API key, no credit card
2. `pip install swt3-ai` or `npm install @tenova/swt3-ai`
3. Wrap your AI client. Every inference is witnessed.

## Regulatory Coverage

| Framework | Coverage |
|-----------|----------|
| EU AI Act | Articles 9, 10, 12, 13, 14, 53, 72 |
| NIST AI RMF | GOVERN, MAP, MEASURE, MANAGE (10 subcategories) |
| NIST 800-53 | SI-7, AU-2, AU-3, AC controls |
| CMMC v2.0 | Level 2 practice mappings |
| SR 11-7 | Model Risk Management (5 examination areas) |
| ISO 42001 | Annex A AI management controls |

## Repository Structure

```
packages/swt3-ai/       Python SDK (PyPI: swt3-ai)
packages/swt3-ai-ts/    TypeScript SDK (npm: @tenova/swt3-ai)
packages/libswt3/       Protocol reference implementation
config/                 Control definitions and framework crosswalks
```

## Compliance & Privacy

Your prompts and responses **never leave your infrastructure**. The SDK computes SHA-256 hashes locally and transmits only irreversible hashes and numeric factors to the witness ledger. At Clearing Level 3, even the model name is hashed.

- [Data Flow and Privacy Architecture](docs/data-flow.md) - Visual data boundary for legal and DPO review
- [Clearing & Data Sovereignty Addendum](https://sovereign.tenova.io/terms/clearing-addendum) - Shared responsibility, incident response SLA, regulatory applicability
- [Air-Gap Deployment Guide](docs/sovereign-sync.md) - Zero-egress operation, sneakernet sync, offline verification

## Documentation

- [SDK Developer Docs](https://sovereign.tenova.io/docs/) - Quickstart, providers, clearing levels
- [Factor Handoff Protocol](https://sovereign.tenova.io/docs/factor-handoff-protocol.html) - Secure factor custody transfer
- [CMMC Compliance Overlay](https://sovereign.tenova.io/guides/cmmc-overlay.html) - Defense industrial base mappings
- [SR 11-7 Compliance Overlay](https://sovereign.tenova.io/guides/sr-11-7-overlay.html) - Model risk management mappings

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

Apache 2.0. See [LICENSE](LICENSE). Patent pending.

---

If you believe AI systems should prove they followed the rules, [give us a star](https://github.com/tenova-labs/swt3-ai).

*SWT3: Sovereign Witness Traceability. We don't run your models. We witness them.*

*[TeNova](https://tenova.io) - Defining the AI Accountability Standard.*
