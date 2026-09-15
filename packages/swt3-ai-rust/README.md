Witness your AI. Prove it followed the rules. Cryptographic accountability for every inference, tool call, and resource access.

[![Crates.io](https://img.shields.io/crates/v/swt3-ai)](https://crates.io/crates/swt3-ai)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/tenova-labs/swt3-ai/blob/main/LICENSE)

# swt3-ai

**SWT3 AI Witness SDK for Rust**: mint, verify, and sign SWT3 witness anchors with cross-language parity. Zero external runtime dependencies beyond `sha2`, `hmac`, and `hex`.

EU AI Act GPAI transparency obligations enforce **August 2, 2026**. High-risk enforcement follows **December 2, 2027**. This SDK gives you the cryptographic primitives for both.

## What's New in v0.7.2

Two gaps closed in one release: harness-layer governance and zero-code MCP compliance. v0.7.2 adds five new procedures for orchestration, context management, sandboxing, and eval gating -- the decisions AI harnesses make before inference that have no audit trail today. It also ships a Witness Middleware (`withSWT3(transport)`) in the companion MCP package that auto-mints AI-TOOL.1 anchors for every tool call flowing through any MCP server, with zero code changes to tool handlers.

**Why this matters for Rust:** Rust inference engines (vLLM, llama.cpp, Candle) are increasingly called through MCP tool interfaces. The middleware wraps the MCP transport layer, so every tool call hitting your Rust model server gets a cryptographic anchor without touching your inference code. The five harness governance anchors (AI-ORCH.1/2, AI-CTX.1, AI-SAND.1, AI-GATE.1) verify with the same `mint_fingerprint` call as inference anchors -- zero crate changes. When a Python or TypeScript harness orchestrates your Rust inference engine and records which agents it delegated to, how much context was truncated, and whether the eval gate passed, your Rust verifier processes those anchors identically to the inference anchors it already validates.

### 5 New Procedures

- **AI-ORCH.1** (Orchestration Topology): Records routing pattern (parallel/sequential/hierarchical), agent count, dependency depth.
- **AI-ORCH.2** (Agent Handoff): Records delegator-to-delegate identity link with permission delta direction.
- **AI-CTX.1** (Context Window Management): Records token count before/after eviction and the method used.
- **AI-SAND.1** (Sandbox Enforcement): Records tools declared vs. invoked and violation count.
- **AI-GATE.1** (Eval Gate Decision): Records eval pass/fail counts with auto-computed gate score.

### Updated Coverage

- 280 procedures across 77 namespaces (was 275/77)
- 68 MCP tools (was 63)
- 10 SDK languages with byte-identical output
- 77 framework crosswalks, 265 compliance guides
- ~3,000 tests passing across 10 languages

## What's New in v0.7.1

MCP security is under fire. OWASP published the MCP Top 10 in 2026 -- 30-82% of MCP servers are vulnerable to tool poisoning, insufficient authentication, and shadow server proliferation. v0.7.1 adds three new procedures (AI-MCP.2, AI-MCP.3, AI-MCP.4) that close the remaining OWASP gaps. SWT3 is now the first protocol to cover all 10 OWASP MCP risks with cryptographic evidence. Every new anchor type verifies with the existing `mint_fingerprint` function -- no crate update required.

**Why this matters for Rust:** Rust inference engines are increasingly called through MCP tool interfaces. When an MCP client invokes your Rust model server, the tool schema integrity anchor (AI-MCP.2) proves the schema was not tampered with between connection and invocation. The server auth anchor (AI-MCP.3) proves the caller authenticated. Zero crate changes.

### 3 New Procedures

- **AI-MCP.2** (Tool Integrity Attestation): Detects tool schema drift between connect and invoke. OWASP MCP-03.
- **AI-MCP.3** (Server Auth Attestation): Records auth method and verification. No auth = FAIL = IA-9 finding. OWASP MCP-07.
- **AI-MCP.4** (Server Discovery Attestation): Shadow server detection via allowlist check. OWASP MCP-09.

## What's New in v0.7.0

AI does not run in a vacuum. It authenticates with service accounts, runs on hardware with supply chains, and consumes enough electricity to reshape power grids. v0.7.0 extends SWT3 down the full AI infrastructure stack with 22 new procedures across three families: credential governance (NHI), hardware supply chains (HBOM/DPP), and energy management (ADR). Every new anchor type verifies with the existing `mint_fingerprint` function -- no crate update required.

**Why this matters for Rust:** Rust is the inference engine layer. vLLM, llama.cpp, and custom CUDA kernels are increasingly written in Rust. These new procedure families mean your Rust inference engine can verify credential rotation anchors for the service accounts calling it, validate that the GPU hardware it runs on has a witnessed supply chain, and confirm that the power it consumed during a training run has an independent attestation. Same `mint_fingerprint` call. Same verification logic. New evidence categories.

### 22 New Procedures

**NHI (6):** Credential scope, lifecycle, privilege changes, rotation, delegation, revocation. **HBOM/DPP (10):** Hardware inventory, component lifecycle, thermal monitoring, water, PUE, supply chain provenance, battery health, charge cycles, degradation, end-of-life. **ADR (6):** Demand response events, baseline, curtailment, settlement, carbon credits, grid signals.

- 266 procedures across 75 namespaces (was 118/64)
- 59 MCP tools (was 37)
- 10 SDK languages with byte-identical output
- 36 framework crosswalks, 237 compliance guides
- ~2,950 tests passing across 5 languages

## What's New in v0.6.6

Supply chain accountability. Four new procedures, a CI/CD gate action, and OTel GenAI conventions across the ecosystem. Every improvement flows through to Rust because fingerprints are identical across all 10 languages.

## What's New in v0.6.5

Scale governance. The protocol grew features that matter at GPAI scale, and every improvement flows through to Rust because fingerprints are identical across all 10 languages.

### Probabilistic Witnessing (Python + TypeScript)

**What it does:** A new sampling rate parameter lets the full-pipeline SDKs witness a statistical sample of inferences instead of every single one. Non-witnessed inferences are counted and summarized in periodic AI-SAMPLE.1 anchors on flush.

**Why it matters for Rust:** When your Rust inference engine processes millions of requests per second, the Python or TypeScript witness layer can sample at 0.1% for volume procedures and 100% for safety checks. The AI-SAMPLE.1 summary anchors use the same fingerprint formula this crate provides -- your Rust code can independently verify any sampled anchor or summary anchor with `mint_fingerprint`. Deterministic hash-based sampling means any verifier can reproduce the sampling decision for any given inference.

### Governance Effectiveness Metadata (Python + TypeScript)

**What it does:** Governance witness methods now accept metadata recording review duration and participant count. Assessors use this to distinguish substantive governance from governance theater.

**Why it matters for Rust:** If your Rust service verifies governance anchors, the metadata lives in the `ai_context` field at clearing levels 0-1. The data structure is forward-compatible -- unknown keys pass through. No crate changes needed to process anchors containing governance metadata.

### Go SDK (v0.1.0)

The 10th language in the SWT3 ecosystem. Zero dependencies. All 65 test vectors pass. Go covers the infrastructure layer -- Kubernetes operators, API gateways, data pipelines. Between Go for orchestration and Rust for performance-critical inference, the two lowest-level languages in the stack now have native SWT3 primitives.

### MCP Witness Middleware

`withSWT3(transport)` wraps any MCP transport to auto-witness every tool call. If your Rust service embeds or calls MCP-enabled agents, every tool call now has a cryptographic anchor verifiable with this crate.

### Updated Coverage

- 114 procedures across 62 namespaces (AI-SAMPLE.1 added)
- 10 SDK languages with byte-identical output
- 36 framework crosswalks, 215 compliance guides
- 2,515 tests passing across 5 languages

### v0.6.4

Pre-inference gate, chain reconstruction, 10 new MCP tools (33 total), Kotlin SDK (v0.1.1), 185 guides, 27 frameworks.

### v0.6.3

- **v0.6.3 across the ecosystem**: Python, TypeScript, and MCP SDKs add consent witnessing (AI-CONSENT.1), output safety classification (AI-GRD.2), incident reporting (AI-INCIDENT.1), and training data provenance (AI-DATA.1). Swift and Kotlin add typed attestation structs. Core primitives in this package remain stable: the fingerprint formula and signing functions are unchanged. 32 MCP tools, 34+ frameworks, 113 procedures.

### v0.5.9

- **Compliance Intelligence** available in Python, TypeScript, and MCP SDKs -- offline crosswalk resolution across 34+ frameworks. Core primitives in this package remain stable and unchanged.

## What You Get

- **`mint_fingerprint`** -- canonical SWT3 fingerprint from tenant, procedure, factors, and timestamp
- **`sign_payload`** -- HMAC-SHA256 signing with optional agent identity binding
- **`sha256_truncated`** -- truncated SHA-256 hashing for prompts, responses, and model weights
- **`timestamp_ms`** -- millisecond-precision timestamps matching the protocol clock
- **Types** -- `WitnessPayload`, `WitnessReceipt`, `WitnessConfig`, `RevocationReason` structs ready for serialization

All output is byte-identical to the Python, TypeScript, Swift, C#, Ruby, Go, Kotlin, and MCP SDKs. 10 languages, one audit trail. Verified by shared test vectors at build time.

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
swt3-ai = "0.3.6"
```

Mint a fingerprint:

```rust
use swt3_ai::{mint_fingerprint, sign_payload, sha256_truncated};

// Hash prompt and response locally (raw text never leaves your machine)
let prompt_hash = sha256_truncated("Summarize this contract...", 16);
let response_hash = sha256_truncated("The contract states...", 16);

// Mint a fingerprint from the canonical formula
let fp = mint_fingerprint("MY_TENANT", "AI-INF.1", 1.0, 1.0, 0.0, 1774800000000);

// Sign for non-repudiation (optional)
let sig = sign_payload("swt3_sk_my_key", &fp, Some("fraud-detector-prod"));
```

## Verify Any Anchor From Your Terminal

```bash
echo -n "WITNESS:DEMO_TENANT:AI-INF.1:1:1:0:1774800000000" | sha256sum | cut -c1-12
# Produces a 12-character fingerprint. Compare it to the anchor. If it matches, the anchor is real.
```

No SDK needed. Works on any machine, any language.

## Cross-Language Parity

All SWT3 SDKs produce identical fingerprints from the same inputs. A unified audit trail across your entire stack, verified by shared test vectors at build time.

| Language | Package | Registry |
|----------|---------|----------|
| Python | [swt3-ai](https://pypi.org/project/swt3-ai/) | PyPI |
| TypeScript | [@tenova/swt3-ai](https://www.npmjs.com/package/@tenova/swt3-ai) | npm |
| Swift | [swt3-ai](https://github.com/tenova-labs/swt3-ai-swift) | Swift Package Index |
| Rust | swt3-ai (this package) | crates.io |
| C# / .NET | [swt3-ai](https://www.nuget.org/packages/swt3-ai) | NuGet |
| Ruby | [swt3-ai](https://rubygems.org/gems/swt3-ai) | RubyGems |
| Go | [swt3-ai](https://github.com/tenova-labs/swt3-ai-go) | Go modules |
| MCP Server | [@tenova/swt3-mcp](https://www.npmjs.com/package/@tenova/swt3-mcp) | npm + MCP Registry |
| K8s Witness Agent | [swt3-witness](https://github.com/tenova-labs/swt3-ai/tree/main/packages/swt3-witness) | GHCR + Helm |

The Python and TypeScript SDKs include the full witness pipeline: transparent client wrapping, buffer management, clearing engine, adapter support (OpenAI, Anthropic, Bedrock, vLLM, Ollama, LangChain, LangGraph, Microsoft AGT, Google ADK, CrewAI), trust mesh, policy-as-code, and Merkle accumulator. Use them for production AI witnessing. Use this Rust crate for embedding fingerprint verification into systems-level code, CLI tools, or performance-critical paths.

## Regulatory Coverage

The SWT3 AI Witnessing Profile maps to:

- **EU AI Act**: Articles 9, 10, 12, 13, 14, 53, 72
- **NIST AI RMF**: GOVERN, MAP, MEASURE, MANAGE functions
- **ISO 42001**: Annex A AI management controls
- **NIST 800-53**: SI-7 (integrity), AU-2/AU-3 (audit), AC controls
- **SR 11-7**: Model risk management (financial services)

## Privacy

Your prompts and responses **never leave your infrastructure**. The SDK computes SHA-256 hashes locally and transmits only irreversible hashes and numeric factors. At Clearing Level 3, even the model name is hashed. The witness endpoint is a blind registrar: it stores cryptographic proofs, not your data.

## Links

- **Website**: [tenova.io](https://tenova.io)
- **Protocol Spec**: [SWT3-SPEC-v1.0](https://github.com/tenova-labs/swt3-ai)
- **Live Demo**: [sovereign.tenova.io/audit/axm_audit_demo_eu_ai_act_public](https://sovereign.tenova.io/audit/axm_audit_demo_eu_ai_act_public)

---

*SWT3: Sovereign Witness Traceability. We don't run your models. We witness them.*

SWT3 and Sovereign Witness Traceability are trademarks of Tenable Nova LLC. Patent pending. Apache 2.0 licensed.

This project is not affiliated with, endorsed by, or sponsored by any third-party AI provider. All third-party trademarks are the property of their respective owners. Use of these names is for identification and interoperability purposes only.
