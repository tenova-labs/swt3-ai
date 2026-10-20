Witness your AI. Prove it followed the rules. Cryptographic accountability for every inference, tool call, and resource access.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/tenova-labs/swt3-ai-go/blob/main/LICENSE)

# swt3-ai-go

**SWT3 AI Witness SDK for Go**: mint, verify, and sign SWT3 witness anchors with cross-language parity. Zero external dependencies -- standard library only.

**293 procedures | 10 namespaces | 10 SDKs | Zero dependencies**

Go is the dominant language for backend infrastructure at scale. Kubernetes operators, API gateways, data pipelines, and inference orchestrators are overwhelmingly written in Go. This package gives infrastructure teams the same cryptographic witnessing primitives available in the Python, TypeScript, Rust, C#, Ruby, Swift, and Kotlin SDKs, with zero external dependencies and byte-identical output across all 10 implementations.

EU AI Act GPAI transparency obligations enforced since **August 2, 2026**. High-risk enforcement follows **December 2, 2027**. This SDK gives you the cryptographic primitives for both.

> **Protocol Spec:** [swt3.ai/spec](https://swt3.ai/spec) | **Registry:** [swt3.ai/registry](https://swt3.ai/registry) | **Verify:** [swt3.ai/verify](https://swt3.ai/verify)

## What's New in v0.7.8

The three largest cloud AI platforms -- IBM watsonx, AWS Bedrock, and Mistral -- each added governance controls in 2026 but left a gap: their policy decisions produce logs that only live inside their own consoles. v0.7.8 closes that gap with six new adapters (Python + TypeScript) and four new procedures that address governance gaps no existing standard covers.

**Why this matters for Go:** All four new procedure IDs (AI-DIST.2, AI-FL.1, AI-FL.2, AI-DATA.5) verify with the existing `MintFingerprint` function -- zero module changes. Go-based federated learning orchestrators gain round provenance and session admission evidence. Go data pipelines that prepare synthetic training data can verify AI-DATA.5 anchors inline. The six new adapters (Granite, Bedrock Guardrails, Strands, Mistral, NemoClaw, ROSClaw) produce anchors in the Python and TypeScript SDKs that Go infrastructure verifies with byte-identical output.

### 6 New Adapters (Python + TypeScript)

| Provider | What it witnesses |
|----------|-------------------|
| IBM watsonx.ai (Granite) | `generate()`, streaming |
| AWS Bedrock Guardrails | `applyGuardrail()` policy decisions (AI-GRD.1) |
| AWS Strands | Agent callable invocations (AI-INF.1) |
| Mistral AI | `chat.complete()`, `chat.stream()`, async |
| NVIDIA NemoClaw | Policy engine decisions (AI-GRD.1) |
| NVIDIA ROSClaw | ROS 2 robotics audit log events |

### 4 New Procedures

- **AI-DIST.2** (Distillation Lineage Attestation): Records authorization status, generation depth, and adversarial extraction flags for model distillation chains. NSTM-4 + EU AI Act Art. 53.
- **AI-FL.1** (Federated Round Provenance): Records aggregation method, round number, and participating client count for each federated learning round.
- **AI-FL.2** (Federated Session Admission): Records consent status, organization count, and data isolation verification for cross-org FL sessions. GDPR Art. 26 joint controller evidence.
- **AI-DATA.5** (Synthetic Data Provenance): Records synthetic fraction, generation depth, and contamination check results. EU AI Act Art. 10 training data quality.

### Updated Coverage

- 293 procedures across 10 namespaces, 86 regulatory frameworks, 324 compliance guides
- [Distillation Lineage Governance](https://sovereign.tenova.io/guides/distillation-lineage-governance-crosswalk.html) | [Federated Learning Governance](https://sovereign.tenova.io/guides/federated-learning-governance-crosswalk.html) | [Synthetic Data Provenance](https://sovereign.tenova.io/guides/synthetic-data-provenance-governance-crosswalk.html)

## What's New in v0.7.6

Five standards bodies converged on agent governance requirements in Q3-Q4 2026. v0.7.6 adds three procedures -- delegation chain integrity, scope boundary attestation, and agent interrupt witnessing -- and aligns crosswalks to G7 AI-SBOM, DORA, Singapore Agentic MGF, and the upcoming NIST Agent Profile.

**Why this matters for Go:** All three new procedures verify with the existing `MintFingerprint` function -- zero module changes. Go API gateways and Kubernetes operators routing multi-agent traffic gain delegation chain and interrupt evidence with byte-identical output across all 10 SDK languages. The ROSClaw adapter (Python) consumes ROS 2 audit logs from robotics environments -- Go-based control plane services that orchestrate ROS 2 robots can feed the same evidence chain. DORA crosswalk coverage (20 mappings) brings EU operational resilience evidence to Go fintech microservices. G7 AI-SBOM crosswalk maps supply chain transparency requirements to existing procedures.

### 3 New Procedures

- **AI-DEL.3** (Delegation Chain Integrity): Records delegation chain completeness -- hops, orphaned references, chain status.
- **AI-SAND.2** (Scope Boundary Attestation): Records the operator's boundary enforcement report -- actions attempted, out-of-scope flagged, response taken.
- **AI-SAFE.2** (Agent Interrupt Witnessing): Records interrupt events -- trigger source, actions suspended, state preservation.

### Updated Coverage

- 289 procedures across 10 namespaces
- 85 regulatory frameworks, 310 compliance guides
- [G7 AI-SBOM Crosswalk](https://sovereign.tenova.io/guides/g7-ai-sbom-minimum-elements-crosswalk.html) | [DORA + ECB Crosswalk](https://sovereign.tenova.io/guides/dora-ecb-ai-cyber-crosswalk.html)

## What's New in v0.7.4

NVIDIA shipped OpenShell to 120+ partners. Agent containment is now infrastructure. But containment without evidence is a black box -- an auditor cannot verify that a sandbox policy was enforced last Tuesday at 14:00 UTC by looking at enforcement logs alone. v0.7.4 adds runtime containment attestation (AI-SHELL.1), model distillation provenance (AI-DIST.1), MCP elicitation detection (AI-MCP.6), and incident lifecycle chains. Four governance gaps closed in one release.

**Why this matters for Go:** All three new procedure IDs (AI-SHELL.1, AI-DIST.1, AI-MCP.6) verify with the existing `MintFingerprint` function. AI-SHELL.1 runtime containment attestation works with zero dependency changes -- Go distillation orchestrators and MCP gateway middleware gain attestation for runtime containment, distillation provenance, and elicitation detection with the same fingerprint parity as every other SDK language.

### 3 New Procedures

- **AI-SHELL.1** (Runtime Containment Attestation): Records that a sandboxed runtime enforced its containment policy during a specific observation window. Duck-typed: works with OpenShell, gVisor, Kata, Firecracker, WASM. [NVIDIA OpenShell Crosswalk](https://sovereign.tenova.io/guides/nvidia-openshell-crosswalk.html)
- **AI-DIST.1** (Distillation Provenance): Records teacher-to-student model lineage, compression ratio, and knowledge transfer method.
- **AI-MCP.6** (Elicitation Detection): Records prompt injection attempts via MCP tool responses. OWASP MCP-06.

### Updated Coverage

- 278 procedures across 10 namespaces (was 284)
- 75 MCP tools (was 72)
- 277 compliance guides
- [NVIDIA OpenShell Crosswalk](https://sovereign.tenova.io/guides/nvidia-openshell-crosswalk.html) -- runtime containment evidence for OpenShell, gVisor, Kata, Firecracker
- All new anchor types verify with `swt3.MintFingerprint()` -- no library update required for verification

## What's New in v0.7.3

A2A (Google's Agent-to-Agent protocol) has 150+ supporting organizations, all three hyperscalers, and a v1.0 stable specification under Linux Foundation governance. It has zero built-in audit trail. MCP OAuth adoption sits at 8.5% with 30+ CVEs filed in 60 days. v0.7.3 makes SWT3 the evidence layer for both agent communication protocols with dedicated procedures, lifecycle-aware adapters, and a new crosswalk CLI command.

**Why this matters for Go:** Go API gateways and Kubernetes operators are the infrastructure layer that routes both MCP and A2A traffic between agents. `WitnessTaskLifecycle`, `WitnessAgentCardDiscovery`, `WitnessContextChain`, and `WitnessOauthTokenBinding` let gateway middleware validate that every delegation was witnessed before forwarding to downstream agents.

### 4 New Procedures

- **AI-A2A.1** (Task Delegation Lifecycle): Records task state transitions (submitted/working/input_required/completed/failed/canceled/rejected) with delegation depth and latency.
- **AI-A2A.2** (Agent Card Discovery): Records agent discovery via well-known URLs, registries, or referrals, with verified credential count.
- **AI-A2A.3** (Context Chain Linking): Records contextId linkage across multi-agent delegation chains for forensic reconstruction.
- **AI-MCP.5** (OAuth Token Binding): Records 8 OAuth lifecycle events (discovery through revocation) with binding strength and scope governance.

### Updated Coverage

- 284 procedures across 10 namespaces (was 280/9)
- 72 MCP tools (was 68)
- A2A namespace added (10th namespace)
- `swt3 crosswalk <procedure>` CLI command for offline framework mapping lookup
- 269 compliance guides

## What's New in v0.7.2

Two gaps closed in one release: harness-layer governance and zero-code MCP compliance. v0.7.2 adds five new procedures for orchestration, context management, sandboxing, and eval gating -- the decisions AI harnesses make before inference that have no audit trail today. It also ships a Witness Middleware (`withSWT3(transport)`) in the companion MCP package that auto-mints AI-TOOL.1 anchors for every tool call flowing through any MCP server, with zero code changes to tool handlers.

**Why this matters for Go:** Go API gateways and Kubernetes operators are the infrastructure layer that routes MCP traffic between agents and tool servers. When a TypeScript or Python harness orchestrates agents behind your Go gateway, the harness governance anchors (AI-ORCH.1/2, AI-CTX.1, AI-SAND.1, AI-GATE.1) verify with the same `MintFingerprint` call as inference anchors. A Go admission controller can now validate not just that an inference was witnessed, but that the orchestration routing, context window management, and eval gating were all attested before the model ran. The Witness Middleware means any MCP server proxied through your Go infrastructure gains cryptographic attestation at the transport layer -- your Go sidecar validates those anchors in real-time.

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

MCP security is under fire. OWASP published the MCP Top 10 in 2026 -- 30-82% of MCP servers are vulnerable to tool poisoning, insufficient authentication, and shadow server proliferation. v0.7.1 adds three new procedures (AI-MCP.2, AI-MCP.3, AI-MCP.4) that close the remaining OWASP gaps. SWT3 is now the first protocol to cover all 10 OWASP MCP risks with cryptographic evidence. Every new anchor type verifies with the existing `MintFingerprint` function -- no module update required.

**Why this matters for Go:** Go API gateways and Kubernetes operators route MCP traffic between agents and tool servers. The new MCP security anchors (tool schema integrity, server authentication, server discovery) verify with the same `MintFingerprint` call. A Go admission controller can reject workloads that lack MCP server auth attestation. Zero module changes.

### 3 New Procedures

- **AI-MCP.2** (Tool Integrity Attestation): Detects tool schema drift between connect and invoke. OWASP MCP-03.
- **AI-MCP.3** (Server Auth Attestation): Records auth method and verification. No auth = FAIL = IA-9 finding. OWASP MCP-07.
- **AI-MCP.4** (Server Discovery Attestation): Shadow server detection via allowlist check. OWASP MCP-09.

## What's New in v0.7.0

AI does not run in a vacuum. It authenticates with service accounts, runs on hardware with supply chains, and consumes enough electricity to reshape power grids. v0.7.0 extends the SWT3 protocol down the full AI infrastructure stack with 22 new procedures across three families: credential governance (NHI), hardware supply chains (HBOM/DPP), and energy management (ADR). Every new anchor type verifies with the existing `MintFingerprint` function -- no module update required.

**Why this matters for Go:** Go is where AI infrastructure lives. The Kubernetes operator scheduling GPU workloads, the API gateway routing inference requests, the data pipeline feeding training data -- all written in Go. These new procedure families map directly to what Go services manage. A Go-based orchestrator can now verify NHI credential rotation anchors, validate hardware inventory attestations, and confirm demand response settlement anchors -- all with the same `MintFingerprint` call. The fingerprint formula is unchanged. A credential rotation anchor and an inference anchor verify identically.

### 22 New Procedures

**NHI (Credential Governance) -- 6 procedures:** NHI-SCOPE.1, NHI-LIFE.1, NHI-PRIV.1, NHI-ROT.1, NHI-DEL.1, NHI-REV.1. Independent audit trail for every service account, API key, and machine credential your AI agents use. NIST 800-207 (Zero Trust), EU NIS-2 Art. 21, and CISA agentic AI guidance all require credential governance evidence.

**HBOM/DPP (Hardware + Battery Passport) -- 10 procedures:** HBOM-INV.1, HBOM-LIFE.1, HBOM-THERM.1, HBOM-WATER.1, HBOM-PUE.1, HBOM-SUPPLY.1, DPP-SOH.1, DPP-CHRG.1, DPP-DEGRAD.1, DPP-EOL.1. EU Battery Regulation (Feb 2027) digital passports, CRA hardware BOMs, and EED PUE reporting.

**ADR (Energy + Demand Response) -- 6 procedures:** ADR-EVENT.1, ADR-BASE.1, ADR-CURT.1, ADR-SETTLE.1, ADR-CARBON.1, ADR-GRID.1. Independent attestation for demand response events, baseline measurement, curtailment, settlement, carbon credits, and grid signal correlation.

### Updated Coverage

- 266 procedures across 75 namespaces (was 118/64)
- 59 MCP tools (was 37)
- 10 SDK languages with byte-identical output
- 36 framework crosswalks, 237 compliance guides
- ~2,950 tests passing across 5 languages

## What's New in v0.6.6

Supply chain accountability. Four new procedures, a CI/CD gate action, and OTel GenAI conventions across the ecosystem. Every improvement flows through to Go because fingerprints are identical across all 10 languages.

## What's New in v0.6.5

This is the debut release. Go is the 10th language in the SWT3 ecosystem, shipping alongside v0.6.5 "Scale Governance."

### Why Go, Why Now

**The infrastructure gap.** Python witnesses the model. TypeScript witnesses the API layer. Rust witnesses the inference engine. But the orchestration layer -- the Kubernetes operators that schedule workloads, the API gateways that route requests, the data pipelines that feed models -- is overwhelmingly Go. Without a Go SDK, infrastructure teams had to shell out to Python, use HTTP directly, or leave the orchestration layer unwitnessed. That gap is now closed.

**Why it matters:** When an assessor asks "was the AI monitored end-to-end?", a gap in the infrastructure layer means the answer is no. A Go API gateway that routes 10,000 inference requests per second can now mint fingerprints in-process with zero dependency overhead and sub-microsecond latency. The same fingerprint formula, the same signing algorithm, the same test vectors. No translation layer between what your gateway witnessed and what your Python model witnessed.

### What Ships

- `MintFingerprint` -- canonical 12-char SHA-256 fingerprint, byte-identical to all other SDKs
- `SignPayload` -- HMAC-SHA256 with agent identity binding
- `MintLifecycleChainID` -- lifecycle chain IDs for multi-anchor governance sequences
- `Sha256Truncated` -- content hashing for prompts, responses, model weights
- `TimestampMs` -- protocol-compatible millisecond timestamps
- All 65 test vectors passing (55 fingerprint + 2 signing + 5 hash + 3 lifecycle chain)
- Zero external dependencies (standard library only)

### What Else Shipped in v0.6.5

- **Probabilistic witnessing** (Python + TypeScript): sample inferences at configurable rates while keeping safety procedures at 100%. Deterministic hash-based sampling -- any Go verifier can reproduce the sampling decision.
- **Governance effectiveness metadata** (Python + TypeScript): review duration and participant count attached to governance anchors. Forward-compatible.
- **MCP Witness Middleware**: `withSWT3(transport)` wraps any MCP transport for zero-code tool call witnessing.
- **AI-SAMPLE.1**: new procedure for probabilistic witnessing summaries. 114 total procedures, 62 namespaces.
- **2,515 tests** passing across 5 languages. 36 framework crosswalks. 215 compliance guides.

## Install

```bash
go get github.com/tenova-labs/swt3-ai-go
```

## Quick Start

```go
package main

import (
    "fmt"
    swt3 "github.com/tenova-labs/swt3-ai-go"
)

func main() {
    // Mint a fingerprint
    ts, _ := swt3.TimestampMs()
    fp := swt3.MintFingerprint("MY_TENANT", "AI-INF.1", 1, 1, 0, ts)
    fmt.Println("Fingerprint:", fp)

    // Sign the anchor
    sig := swt3.SignPayload("my-signing-key", fp, "agent-1")
    fmt.Println("Signature:", sig)

    // Lifecycle chain ID
    chainID := swt3.MintLifecycleChainID("MY_TENANT", "AI-EMRG.1", fp, ts)
    fmt.Println("Chain ID:", chainID)

    // Content hash
    hash := swt3.Sha256Truncated("gpt-4o-2024-11-20", 16)
    fmt.Println("Model hash:", hash)
}
```

## What You Get

| Function | Description |
|----------|-------------|
| `MintFingerprint(tenant, proc, fa, fb, fc, ts)` | 12-char SHA-256 witness fingerprint |
| `MintLifecycleChainID(tenant, proc, fp, ts)` | `LC-` prefixed 16-char lifecycle chain ID |
| `SignPayload(key, fingerprint, agentID)` | HMAC-SHA256 payload signature |
| `Sha256Truncated(data, length)` | Truncated SHA-256 hex digest |
| `TimestampMs()` | Current time as (ms, epoch) |

All output is byte-identical to the Python, TypeScript, Swift, Rust, C#, Ruby, Kotlin, and MCP SDKs. 10 languages, one audit trail. Verified by shared test vectors at build time.

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
| Rust | [swt3-ai](https://crates.io/crates/swt3-ai) | crates.io |
| C# / .NET | [swt3-ai](https://www.nuget.org/packages/swt3-ai) | NuGet |
| Ruby | [swt3-ai](https://rubygems.org/gems/swt3-ai) | RubyGems |
| Go | swt3-ai-go (this package) | Go modules |
| MCP Server | [@tenova/swt3-mcp](https://www.npmjs.com/package/@tenova/swt3-mcp) | npm + MCP Registry |
| K8s Witness Agent | [swt3-witness](https://github.com/tenova-labs/swt3-ai/tree/main/packages/swt3-witness) | GHCR + Helm |

The Python and TypeScript SDKs include the full witness pipeline: transparent client wrapping, buffer management, clearing engine, adapter support (OpenAI, Anthropic, Bedrock, vLLM, Ollama, LangChain, LangGraph, Microsoft AGT, Google ADK, CrewAI), trust mesh, policy-as-code, and Merkle accumulator. Use them for production AI witnessing. Use this Go package for embedding fingerprint minting and verification into infrastructure-layer code: API gateways, Kubernetes operators, data pipelines, or any Go service that touches AI.

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
- **Protocol Spec**: [SWT3 Protocol Specification](https://swt3.ai/spec)
- **Live Demo**: [sovereign.tenova.io/audit/axm_audit_demo_eu_ai_act_public](https://sovereign.tenova.io/audit/axm_audit_demo_eu_ai_act_public)

---

*SWT3: Sovereign Witness Traceability. We don't run your models. We witness them.*

SWT3 and Sovereign Witness Traceability are trademarks of Tenable Nova LLC. Patent pending. Apache 2.0 licensed.

This project is not affiliated with, endorsed by, or sponsored by any third-party AI provider. All third-party trademarks are the property of their respective owners. Use of these names is for identification and interoperability purposes only.
