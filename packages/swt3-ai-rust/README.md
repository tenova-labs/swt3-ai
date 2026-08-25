Witness your AI. Prove it followed the rules. Cryptographic accountability for every inference, tool call, and resource access.

[![Crates.io](https://img.shields.io/crates/v/swt3-ai)](https://crates.io/crates/swt3-ai)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/tenova-labs/swt3-ai/blob/main/LICENSE)

# swt3-ai

**SWT3 AI Witness SDK for Rust**: mint, verify, and sign SWT3 witness anchors with cross-language parity. Zero external runtime dependencies beyond `sha2`, `hmac`, and `hex`.

EU AI Act GPAI transparency obligations enforce **August 2, 2026**. High-risk enforcement follows **December 2, 2027**. This SDK gives you the cryptographic primitives for both.

## What's New in v0.6.6

Supply chain accountability. Four new procedures, a CI/CD gate action, and OTel GenAI conventions across the ecosystem. Every improvement flows through to Rust because fingerprints are identical across all 10 languages.

### 4 New Procedures

**AI-PROV.1 (Model Provenance Chain):** Records model lineage -- base model, training pipeline, fine-tuning ancestry. The G7 Hiroshima AI SBOM framework requires provenance documentation. A `parent_model_fingerprint` parameter on model weight/adapter/quantization methods links derivative models to their ancestors. Provenance anchors verify with `mint_fingerprint` like any other anchor.

**AI-DEL.2 (Delegation Boundary):** Records what an agent is NOT permitted to do -- blocked tools, restricted scopes, escalation triggers. EU AI Act Art. 14 requires documented AI system limitations. Where AI-DEL.1 tracks permissions, AI-DEL.2 tracks constraints.

**AI-DENSITY.1 (Anchor Density):** Records the ratio of witnessed events to total events over a time window. Catches the slow coverage drift from 100% to 2% that nobody notices until the audit. A DensityEnforcer class in Python and TypeScript auto-fires density anchors when coverage drops.

**AI-MCP.1 (MCP Security Posture):** Evaluates 8 security properties of an MCP server connection. Records checks passed vs. total -- never which specific checks failed. NSA and CISA flagged 200,000+ vulnerable MCP deployments in 2026. This creates evidence that security was evaluated at connection time without becoming an attack map.

**Why it matters for Rust:** All four procedures produce anchors with the same fingerprint formula. Your Rust code can verify any of these new anchor types with the existing `mint_fingerprint` function -- no crate update required for verification. If your Rust inference engine is fine-tuned from an open-weight base model, the provenance chain links your production binary back to its training lineage. The density anchors let your monitoring layer verify that the Python witness pipeline maintained consistent coverage.

### GitHub Action

`tenova-labs/swt3-gate-action@v1` evaluates `.swt3-gate.yml` in CI/CD. Fails the build when coverage drops. Works with any language -- the gate checks anchors on the server, not the SDK in your repo.

### OTel GenAI Conventions (Python + TypeScript)

The OpenTelemetry exporters now emit `gen_ai.system`, `gen_ai.request.model`, and token usage attributes following the OTel GenAI semantic conventions. If your Rust service consumes OTel spans from the Python or TypeScript witness pipeline, these new attributes appear automatically.

### Updated Coverage

- 118 procedures across 64 namespaces (+AI-PROV.1, AI-DEL.2, AI-DENSITY.1, AI-MCP.1)
- 37 MCP tools (+witness_delegation_boundary, witness_anchor_density, witness_mcp_security, witness_model_provenance)
- 10 SDK languages with byte-identical output
- 36 framework crosswalks, 222 compliance guides
- 2,825 tests passing across 5 languages

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
