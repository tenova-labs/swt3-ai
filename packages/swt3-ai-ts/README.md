Deterministic AI Governance for production agents. Zero latency. Zero data retention.

[![npm](https://img.shields.io/npm/v/@tenova/swt3-ai)](https://www.npmjs.com/package/@tenova/swt3-ai)
[![Downloads](https://img.shields.io/npm/dm/@tenova/swt3-ai)](https://www.npmjs.com/package/@tenova/swt3-ai)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/tenova-labs/swt3-ai/blob/main/LICENSE)

# @tenova/swt3-ai

**SWT3 AI Witness SDK for TypeScript**: continuous, cryptographic attestation for AI systems. Prove your models are running approved weights, safety guardrails are active, and inferences are traceable. All without a single prompt or response ever leaving your infrastructure.

Works with OpenAI, Anthropic, Vercel AI SDK, and any OpenAI-compatible endpoint (vLLM, Ollama, Azure, Llama.cpp).

## Why SWT3?

AI agents are making production decisions, but when regulators ask "prove your AI followed the rules," most teams have nothing but logs and dashboards. SWT3 produces cryptographic, tamper-proof evidence of every AI action. No prompt data leaves your infrastructure. The EU AI Act (enforcement: August 2, 2026) requires exactly this.

## See It Work in 10 Seconds

No API keys. No account. No network calls.

```bash
npm install @tenova/swt3-ai
npx swt3-demo
```

You'll see the full SWT3 witnessing pipeline: hash, extract, clear, anchor, verify — plus a **Regulatory Coverage Summary** mapping each procedure to EU AI Act articles. The demo shows 3/12 obligations covered, with the 9 uncovered gaps listed by article citation. When you're ready to close those gaps, keep reading.

## Three Lines of Code

### OpenAI

```typescript
import { Witness } from "@tenova/swt3-ai";
import OpenAI from "openai";

const witness = new Witness({
  endpoint: "https://sovereign.tenova.io",
  apiKey: "axm_live_...",
  tenantId: "YOUR_ENCLAVE",
});

const client = witness.wrap(new OpenAI()) as OpenAI;

// Non-streaming, works exactly as before
const response = await client.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: "Summarize this contract..." }],
});
console.log(response.choices[0].message.content);

// Streaming, also works. Chunks arrive in real-time, witnessing happens after.
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
  endpoint: "https://sovereign.tenova.io",
  apiKey: "axm_live_...",
  tenantId: "YOUR_ENCLAVE",
});

const client = witness.wrap(new Anthropic()) as Anthropic;

const message = await client.messages.create({
  model: "claude-sonnet-4-20250514",
  max_tokens: 1024,
  messages: [{ role: "user", content: "Draft a compliance memo" }],
});

// Streaming with Anthropic
const stream = await client.messages.create({
  model: "claude-sonnet-4-20250514",
  max_tokens: 1024,
  messages: [{ role: "user", content: "Analyze this dataset" }],
  stream: true,
});
for await (const event of stream) {
  // events arrive in real-time, witnessing happens after stream ends
}
```

### Vercel AI SDK (Next.js / React)

```typescript
import { Witness } from "@tenova/swt3-ai";
import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";

const witness = new Witness({
  endpoint: "https://sovereign.tenova.io",
  apiKey: "axm_live_...",
  tenantId: "YOUR_ENCLAVE",
});

const prompt = "Summarize this contract for the board";

const result = await streamText({
  model: openai("gpt-4o"),
  prompt,
  onFinish: witness.vercelOnFinish({ promptText: prompt }),
});

// Works with any Vercel AI SDK provider:OpenAI, Anthropic, Google, Mistral, custom
```

The `onFinish` hook is framework-idiomatic: no wrapping, no proxying, no monkey-patching. It fires after the stream completes and receives a normalized result regardless of provider.

## Sovereign Cloud Support

The SDK works out-of-the-box with any OpenAI-compatible endpoint. Run Llama 3 on vLLM, Mistral on Ollama, or any model behind an OpenAI-compatible API:every inference is witnessed identically.

```typescript
// vLLM with Llama 3, sovereign cloud, your hardware
const client = witness.wrap(
  new OpenAI({ baseURL: "http://gpu-cluster.internal:8000/v1" }),
) as OpenAI;

const response = await client.chat.completions.create({
  model: "meta-llama/Meta-Llama-3-70B-Instruct",
  messages: [{ role: "user", content: "Classify this threat indicator" }],
});
// Same SWT3 anchor, same ledger, same audit trail:regardless of where the model runs

// Ollama (local development)
const localClient = witness.wrap(
  new OpenAI({ baseURL: "http://localhost:11434/v1" }),
) as OpenAI;

// Azure OpenAI (enterprise deployment)
const azureClient = witness.wrap(
  new OpenAI({
    apiKey: process.env.AZURE_OPENAI_KEY,
    baseURL: "https://your-resource.openai.azure.com/openai/deployments/gpt-4o",
  }),
) as OpenAI;
```

## Quick Start (Try It Locally)

Want to see the SDK work before connecting to a live endpoint? Use `factorHandoff` to write witness anchors to local JSON files. No account needed.

```typescript
import { Witness } from "@tenova/swt3-ai";
import OpenAI from "openai";

const witness = new Witness({
  endpoint: "https://sovereign.tenova.io",
  apiKey: "test",                // any string, handoff runs before network flush
  tenantId: "LOCAL_TEST",
  factorHandoff: "file",         // write anchors to ./swt3-handoff/ as JSON
});

const client = witness.wrap(new OpenAI()) as OpenAI;

const response = await client.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: "What is the EU AI Act?" }],
});
console.log(response.choices[0].message.content);

// Check ./swt3-handoff/ - you'll see a JSON file per inference with:
//   - SHA-256 fingerprint
//   - Model ID, latency, token count
//   - Clearing level applied
//   - Full factor data for independent verification
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

1. **Intercept**: ES6 Proxy wraps your AI client transparently
2. **Hash**: Prompts and responses are SHA-256 hashed in-process
3. **Extract**: Model hash, latency, token count, refusal status as numeric factors
4. **Clear**: Raw text is purged from the wire payload (configurable clearing level)
5. **Buffer**: Factors queued in background, flushed to the SWT3 ledger asynchronously
6. **Return**: Your original response returns untouched. Witnessing runs in a background thread — median overhead is <1ms on the hot path (hash + buffer, no network call)

For streaming: chunks arrive to the developer in real-time. The SDK accumulates content in the background and witnesses after the stream completes.

## Clearing Levels

| Level | Name | On the Wire | Use Case |
|-------|------|------------|----------|
| 0 | Analytics | Hashes + factors + model + provider + guardrails | Internal analytics |
| 1 | Standard | Hashes + factors + model + provider | **Default.** Production apps |
| 2 | Sensitive | Hashes + factors + model only | Healthcare, legal, PII |
| 3 | Classified | Numeric factors only. Model ID hashed. | Defense, air-gapped |

At Level 1+, raw prompts and responses **never leave your infrastructure**. The witness endpoint is a "Blind Registrar":it stores cryptographic proofs, not data.

```typescript
// Healthcare deployment: Level 2
const witness = new Witness({
  endpoint: "https://sovereign.tenova.io",
  apiKey: "axm_live_...",
  tenantId: "HOSPITAL_ENCLAVE",
  clearingLevel: 2,
});
```

## What Gets Witnessed

| Procedure | What It Proves | Regulatory Mapping |
|-----------|---------------|-------------------|
| AI-INF.1 | Inference provenance (prompt + response hashed) | EU AI Act Art. 12 |
| AI-INF.2 | Latency within threshold (detects model swaps) | NIST AI RMF MEASURE 2.6 |
| AI-MDL.1 | Model hash matches approved version | EU AI Act Art. 9 |
| AI-MDL.2 | Model version identifier recorded | EU AI Act Art. 72 |
| AI-GRD.1 | Required guardrails were active | NIST AI RMF MANAGE 4.1 |
| AI-GRD.2 | No content filter / refusal triggered | EU AI Act Art. 9 |
| AI-TOOL.1 | Agent tool/function call recorded (latency, success) | NIST AI RMF MANAGE 4.1 |
| AI-ID.1 | Witness instance identity attested (agent accountability) | EU AI Act Art. 13 |

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

If the witness endpoint is unreachable, payloads move to a dead-letter queue instead of being dropped. When connectivity is restored, the backlog drains automatically.

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

## Zero Lock-in

Remove the `witness.wrap()` call. Your code works exactly as before. Anchors already minted remain in the ledger.

## Cross-Language Parity

This SDK produces **identical SWT3 fingerprints** to the Python SDK (`swt3-ai`) and the Axiom ingestion endpoint. A unified audit trail across your entire stack:

| Layer | Language | Package |
|-------|----------|---------|
| Backend services | Python | `swt3-ai` |
| API routes / Edge | TypeScript | `@tenova/swt3-ai` |
| Frontend (Next.js) | TypeScript | `@tenova/swt3-ai` + Vercel AI SDK |
| CLI / scripts | Python | `swt3-ai` |

10 cross-language test vectors validated at build time.

## Installation

```bash
npm install @tenova/swt3-ai

# Peer dependencies (install whichever you use)
npm install openai          # for OpenAI adapter
npm install @anthropic-ai/sdk  # for Anthropic adapter
```

## API Reference

### `new Witness(options)`

| Option | Default | Description |
|--------|---------|-------------|
| `endpoint` | *required* | Witness endpoint URL |
| `apiKey` | *required* | API key (`axm_*`) |
| `tenantId` | *required* | Enclave identifier |
| `clearingLevel` | `1` | Clearing level (0-3) |
| `bufferSize` | `10` | Flush after N anchors |
| `flushInterval` | `5` | Flush after N seconds |
| `timeout` | `10000` | HTTP timeout (ms) |
| `maxRetries` | `3` | Retries before dead-letter |
| `guardrailNames` | `[]` | Active guardrail names |
| `factorHandoff` | - | `"file"` to enable local factor export |
| `factorHandoffPath` | - | Directory for factor handoff files |

### `witness.wrap(client)`

Returns a Proxy that behaves identically to the original client. Supports OpenAI and Anthropic.

### `witness.vercelOnFinish(options?)`

Returns an `onFinish` callback for `streamText()` / `generateText()`. Pass `{ promptText }` for full provenance hashing.

### `witness.flush()`

Force-flush all buffered payloads. Returns receipts.

### `witness.stop()`

Stop the witness and flush remaining payloads.

## Factor Handoff (Clearing Level 2+)

At Clearing Level 2 or 3, some or all verifiable data is stripped before it reaches the witness endpoint. The Factor Handoff writes your factors to a local directory **before** clearing proceeds. If the write fails, the payload is not transmitted.

```typescript
const witness = new Witness({
  endpoint: "https://sovereign.tenova.io",
  apiKey: "axm_live_...",
  tenantId: "YOUR_ENCLAVE",
  clearingLevel: 3,
  factorHandoff: "file",
  factorHandoffPath: "/secure/vault/factors/",
});
```

Each anchor gets its own JSON file containing the full uncleared factors and metadata for independent re-verification.

For the full protocol specification, see the [Factor Handoff Protocol](https://sovereign.tenova.io/docs/factor-handoff-protocol.html).

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
