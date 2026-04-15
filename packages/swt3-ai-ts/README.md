Witness your AI. Prove it followed the rules. Cryptographic accountability for every inference, tool call, and resource access.

[![npm](https://img.shields.io/npm/v/@tenova/swt3-ai)](https://www.npmjs.com/package/@tenova/swt3-ai)
[![Downloads](https://img.shields.io/npm/dm/@tenova/swt3-ai)](https://www.npmjs.com/package/@tenova/swt3-ai)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/tenova-labs/swt3-ai/blob/main/LICENSE)

# @tenova/swt3-ai

**SWT3 AI Witness SDK for TypeScript**: tamper-proof evidence that your AI is doing what you say it does. Every inference hashed. Every tool call recorded. Every resource access checked against scope. No prompts or responses ever leave your infrastructure.

Works with OpenAI, Anthropic, Vercel AI SDK, and any OpenAI-compatible endpoint (vLLM, Ollama, Azure, Llama.cpp).

The EU AI Act takes effect **August 2, 2026**. When regulators ask "prove your AI followed the rules," you need more than logs. You need cryptographic proof.

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

When an auditor asks "what tools did your agent use?" you have the cryptographic record.

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

If the agent tries to access something outside its declared scope, the anchor records a FAIL verdict. When a CISO asks "can you prove your AI agent only accessed what it was authorized to access?" this is the answer.

## Detect Instruction Drift

New in v0.2.10. The SDK separately hashes the system prompt (base instructions) for each inference. If your agent's instructions change between audit periods, the hash changes and the platform flags it as instruction drift.

This happens automatically. No configuration needed. The system prompt hash is extracted from:
- OpenAI: messages where `role === "system"`
- Anthropic: the `system` parameter

The hash is included at clearing levels 0 and 1, stripped at levels 2 and 3.

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

The `agentId` survives all clearing levels. The `signingKey` produces a cryptographic signature on every anchor, proving which agent instance created it. This enables:
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

No SDK needed. Works on any machine, any language.

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
| **Survives an audit** | **No** | **Yes** |

> Local anchors prove it to you. A connected engine proves it to your auditor.

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
| `signingKey` | - | HMAC-SHA256 key for payload signing |
| `factorHandoff` | - | "file" for local factor export |
| `factorHandoffPath` | - | Directory for handoff files |

### Methods

| Method | Description |
|--------|-------------|
| `witness.wrap(client)` | Returns a Proxy that behaves identically to the original client. Supports OpenAI and Anthropic. |
| `witness.wrapTool(fn, name?)` | Wraps a function for tool call witnessing (AI-TOOL.1). |
| `witness.wrapAccess(fn, resource?, scope?)` | Wraps a function for resource access witnessing (AI-ACC.1). |
| `witness.vercelOnFinish(opts?)` | Returns an onFinish callback for Vercel AI SDK streamText/generateText. |
| `witness.flush()` | Force-flush all buffered payloads. Returns receipts. |
| `witness.stop()` | Stop the witness and flush remaining payloads. |

## Installation

```bash
npm install @tenova/swt3-ai

# Peer dependencies (install whichever you use)
npm install openai              # for OpenAI adapter
npm install @anthropic-ai/sdk   # for Anthropic adapter
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

*SWT3: Sovereign Witness Traceability. We don't run your models. We witness them.*

SWT3 and Sovereign Witness Traceability are trademarks of Tenable Nova LLC. Patent pending. Apache 2.0 licensed.
