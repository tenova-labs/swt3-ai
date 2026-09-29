Witness your AI at the edge. Prove it followed the rules. Cryptographic accountability for every on-device inference, model integrity check, and spatial decision.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/tenova-labs/swt3-ai/blob/main/LICENSE)

# swt3-ai

**SWT3 AI Witness SDK for Swift**: mint, verify, and sign SWT3 witness anchors on Apple platforms and Linux. Zero external dependencies on Apple platforms. CryptoKit for hashing and HMAC, Foundation for timestamps.

Your models run on-device. Your attestation stays on-device until you choose to transmit. Only irreversible hashes leave the device -- never prompts, responses, or model weights.

EU AI Act GPAI transparency obligations enforce **August 2, 2026**. High-risk enforcement follows **December 2, 2027**. Edge inference is not exempt.

> **Protocol Spec:** [swt3.ai/spec](https://swt3.ai/spec) | **Registry:** [swt3.ai/registry](https://swt3.ai/registry) | **Verify:** [swt3.ai/verify](https://swt3.ai/verify)

## What's New in v0.7.4

NVIDIA shipped OpenShell to 120+ partners. Agent containment is now infrastructure. But containment without evidence is a black box -- an auditor cannot verify that a sandbox policy was enforced last Tuesday at 14:00 UTC by looking at enforcement logs alone. v0.7.4 adds runtime containment attestation (AI-SHELL.1), model distillation provenance (AI-DIST.1), MCP elicitation detection (AI-MCP.6), and incident lifecycle chains. Four governance gaps closed in one release.

**Why this matters for Swift:** All three new procedure IDs (AI-SHELL.1, AI-DIST.1, AI-MCP.6) verify with the existing `SWT3.mintFingerprint()` function. AI-SHELL.1 runtime containment attestation works with zero dependency changes -- on-device Core ML distillation (teacher to student model compression) and sandboxed inference on Apple platforms can attest containment and lineage with the same cryptographic parity as server-side SDKs.

### 3 New Procedures

- **AI-SHELL.1** (Runtime Containment Attestation): Records that a sandboxed runtime enforced its containment policy during a specific observation window. Duck-typed: works with OpenShell, gVisor, Kata, Firecracker, WASM. [NVIDIA OpenShell Crosswalk](https://sovereign.tenova.io/guides/nvidia-openshell-crosswalk.html)
- **AI-DIST.1** (Distillation Provenance): Records teacher-to-student model lineage, compression ratio, and knowledge transfer method.
- **AI-MCP.6** (Elicitation Detection): Records prompt injection attempts via MCP tool responses. OWASP MCP-06.

### Updated Coverage

- 278 procedures across 10 namespaces (was 284)
- 75 MCP tools (was 72)
- 277 compliance guides
- [NVIDIA OpenShell Crosswalk](https://sovereign.tenova.io/guides/nvidia-openshell-crosswalk.html) -- runtime containment evidence for OpenShell, gVisor, Kata, Firecracker
- All new anchor types verify with `SWT3.mintFingerprint()` -- no library update required for verification

## What's New in v0.7.3

A2A (Google's Agent-to-Agent protocol) has 150+ supporting organizations, all three hyperscalers, and a v1.0 stable specification under Linux Foundation governance. It has zero built-in audit trail. MCP OAuth adoption sits at 8.5% with 30+ CVEs filed in 60 days. v0.7.3 makes SWT3 the evidence layer for both agent communication protocols with dedicated procedures, lifecycle-aware adapters, and a new crosswalk CLI command.

**Why this matters for Swift:** Apple platforms hosting on-device agents (Core ML, Secure Enclave signing) gain A2A task lifecycle witnessing. Agents running on Apple Silicon can now attest delegation chains with the same cryptographic parity as server-side SDKs.

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

**Why this matters for Swift:** Apple Intelligence and on-device agents increasingly use tool-calling patterns that mirror MCP. When your iOS or visionOS app delegates inference to a server-side agent pipeline, the harness governance anchors (AI-ORCH.1/2, AI-CTX.1, AI-SAND.1, AI-GATE.1) prove which agent handled the request, whether context was truncated, and whether the eval gate passed before the response reached the device. Your Swift code can verify all five anchor types with the same `SWT3.mintFingerprint` call -- zero package changes. For edge deployments where the device itself hosts an MCP server, the Witness Middleware wraps the transport to attest every tool call without modifying tool handlers.

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

MCP security is under fire. OWASP published the MCP Top 10 in 2026 -- 30-82% of MCP servers are vulnerable to tool poisoning, insufficient authentication, and shadow server proliferation. v0.7.1 adds three new procedures (AI-MCP.2, AI-MCP.3, AI-MCP.4) that close the remaining OWASP gaps. SWT3 is now the first protocol to cover all 10 OWASP MCP risks with cryptographic evidence. Every new anchor type verifies with the existing `SWT3.mintFingerprint` function -- no package update required.

**Why this matters for Swift:** When your iOS or visionOS app calls server-side MCP tools, the new MCP security anchors prove the tool schema was stable (AI-MCP.2), the server authenticated (AI-MCP.3), and the server was on your approved list (AI-MCP.4). Zero package changes.

### 3 New Procedures

- **AI-MCP.2** (Tool Integrity Attestation): Detects tool schema drift between connect and invoke. OWASP MCP-03.
- **AI-MCP.3** (Server Auth Attestation): Records auth method and verification. No auth = FAIL = IA-9 finding. OWASP MCP-07.
- **AI-MCP.4** (Server Discovery Attestation): Shadow server detection via allowlist check. OWASP MCP-09.

## What's New in v0.7.0

AI does not run in a vacuum. It authenticates with service accounts, runs on hardware with supply chains, and consumes enough electricity to reshape power grids. v0.7.0 extends SWT3 down the full AI infrastructure stack with 22 new procedures across three families: credential governance (NHI), hardware supply chains (HBOM/DPP), and energy management (ADR). Every new anchor type verifies with the existing `SWT3.mintFingerprint` function -- no package update required.

**Why this matters for Swift:** On-device Core ML inference is expanding into healthcare, automotive, and industrial settings where the hardware matters as much as the model. An iPhone running a clinical AI model now has credential governance (which health API keys does the agent hold?), hardware attestation (is the Secure Enclave intact?), and energy monitoring (is the device thermally safe for inference?) all verifiable with the same `SWT3.mintFingerprint` call. Edge devices in EV charging infrastructure can witness battery passport data using the same protocol their server-side Python pipeline uses for inference attestation.

### 22 New Procedures

**NHI (6):** Credential scope, lifecycle, privilege changes, rotation, delegation, revocation. **HBOM/DPP (10):** Hardware inventory, component lifecycle, thermal monitoring, water, PUE, supply chain provenance, battery health, charge cycles, degradation, end-of-life. **ADR (6):** Demand response events, baseline, curtailment, settlement, carbon credits, grid signals.

- 266 procedures across 75 namespaces (was 118/64)
- 59 MCP tools (was 37)
- 10 SDK languages with byte-identical output
- 36 framework crosswalks, 237 compliance guides
- ~2,950 tests passing across 5 languages

## What's New in v0.6.6

Supply chain accountability. Four new procedures, a CI/CD gate action, and OTel GenAI conventions across the ecosystem. Every improvement flows through to Swift because fingerprints are identical across all 10 languages.

## What's New in v0.6.5

Scale governance. The protocol grew features that matter at GPAI scale, and every improvement flows through to Swift because fingerprints are identical across all 10 languages.

### Probabilistic Witnessing (Python + TypeScript)

**What it does:** A new sampling rate parameter lets the full-pipeline SDKs witness a statistical sample of inferences instead of every single one. Non-witnessed inferences are counted and summarized in periodic AI-SAMPLE.1 anchors on flush.

**Why it matters for Swift:** On-device Core ML inference on iPhone and Vision Pro is inherently high-volume. When a server-side Python pipeline samples at 1% and your Swift app witnesses every on-device prediction at 100%, both produce anchors with the same fingerprint formula. The AI-SAMPLE.1 summary anchors are verifiable with `SWT3.mintFingerprint` -- your app can independently confirm that the server-side sampling was deterministic and nothing was selectively excluded.

### Governance Effectiveness Metadata (Python + TypeScript)

**What it does:** Governance witness methods now accept metadata recording review duration and participant count. Assessors use this to distinguish substantive governance from governance theater.

**Why it matters for Swift:** If your iOS app displays compliance status from governance anchors, the metadata lives in the `ai_context` field at clearing levels 0-1. The data structure is forward-compatible. Your app can surface review quality indicators (duration, participant count) without any SDK changes.

### Go SDK (v0.1.0)

The 10th language in the SWT3 ecosystem. Zero dependencies. All 65 test vectors pass. Go covers the infrastructure layer -- Kubernetes operators, API gateways, inference orchestrators. Your Swift app talks to Go-based backend services; now both ends of the chain produce identical cryptographic evidence.

### MCP Witness Middleware

`withSWT3(transport)` wraps any MCP transport to auto-witness every tool call. If your Swift app interacts with MCP-enabled agents via server-side proxies, every tool call now has a cryptographic anchor verifiable with this package.

### Updated Coverage

- 114 procedures across 62 namespaces (AI-SAMPLE.1 added)
- 10 SDK languages with byte-identical output
- 36 framework crosswalks, 215 compliance guides
- 2,515 tests passing across 5 languages

### v0.6.4

Pre-inference gate, chain reconstruction, 10 new MCP tools (33 total), Kotlin SDK (v0.1.1), 185 guides, 27 frameworks.

### v0.6.3

Four new attestation types for the procedures regulators ask about first. Each maps to regulations enforcing now or within months.

- **Output Filter Result** (`OutputFilterResult` + `FilterAction`, AI-GRD.2) -- Guardrails run, but proving the output classification result is a separate evidence requirement. When Tencent's Doubao was shut down overnight for output violations, the gap was not whether guardrails existed but whether there was proof each output passed classification. This struct records whether model output passed content safety filters, what type of filter ran, and what action was taken. Distinct from input-side guardrail activation (AI-GRD.1) -- this is the output-side classification result. EU AI Act Art. 15(3), NIST AI RMF GOVERN 1.5.

- **Data Provenance Attestation** (`DataProvenanceAttestation`, AI-DATA.1) -- Training data is the most guarded secret in AI. This type solves the tension: it attests that data governance review was performed WITHOUT disclosing what the training data was. No dataset names, no license strings, no content hashes of the data itself. Instead: governance reviewed (bool), documentation hash (SHA-256 of the data card, not the data), license compliance verified, demographic features confirmed absent. Satisfies EU AI Act Art. 10, SR 11-7 III.A, and CA-AB-2013 through diligence attestation, not disclosure.

- **Consent Attestation** (`ConsentAttestation`, AI-CONSENT.1) -- GDPR lawful basis encoding for mobile apps that collect consent before on-device inference. Basis code, subject count, withdrawal availability, jurisdiction. When an iOS app runs Core ML locally, the consent evidence must exist before inference starts.

- **Incident Report** (`IncidentReport`, AI-INCIDENT.1) -- NIS-2 gives you 24 hours to report. EU AI Act Art. 62 gives you 72. The question regulators ask is "when did you know?" This struct records severity, incident type, authority notification status, detection method, and reporting deadline -- structured evidence that the clock started when you say it did.
- **Code Maps** -- `consentBasisCodes`, `incidentSeverityCodes`, `incidentTypeCodes`, `filterActionCodes` dictionaries for factor encoding.
- **Governance Gate Types** -- `GateConfig`, `GateProcedure`, `GateGroup`, `FrameworkGate` structs for parsing .swt3-gate.yml configurations.
- **Delegation Tree Types** -- `DelegationTree` struct for AI-DEL.1 hierarchical permission delegation.
- **Resource Consumption Types** -- `ResourceConsumption` struct for AI-COST.1 token usage and cost witnessing.
- **Deployment Context Types** -- `DeploymentContext` struct for device model, OS, chip type, and container image metadata.

### v0.5.9

- Compliance Intelligence available in Python, TypeScript, and MCP SDKs. Core primitives unchanged.

## What You Get

### Core Primitives

- **`SWT3.mintFingerprint`** -- canonical SWT3 fingerprint from tenant, procedure, factors, and timestamp
- **`SWT3.signPayload`** -- HMAC-SHA256 signing with optional agent identity binding
- **`SWT3.sha256Truncated`** -- truncated SHA-256 hashing for prompts, responses, and model weights
- **`SWT3.timestampMs`** -- millisecond-precision timestamps matching the protocol clock
- **Types** -- `WitnessPayload`, `WitnessReceipt`, `WitnessConfig`, `GateConfig`, `DelegationTree`, `ResourceConsumption`, `DeploymentContext`, `RevocationReason` structs (Sendable, Equatable, Codable)
- **Model Integrity** -- `SWT3.hashFile` and `SWT3.hashDirectory` for model weight verification

### Apple Platform Features

Available on iOS, macOS, and visionOS via `#if canImport`:

- **`SWT3.witnessPrediction`** -- witness a Core ML prediction (AI-INF.1). Extracts model metadata, hashes input/output feature descriptions, computes latency, and mints a fingerprint. Raw inference data never leaves the device.
- **`SWT3.witnessModelIntegrity`** -- witness Core ML model integrity (AI-MDL.1). Hashes the compiled `.mlmodelc` bundle for tamper detection and drift monitoring.
- **`SWT3.witnessSpatialInference`** -- witness an AI decision with spatial context. Captures a 4x4 world transform matrix and hashes it into the anchor. For AI systems making decisions in physical space (navigation, object recognition, spatial reasoning on Vision Pro), this proves WHERE the decision was made, not just WHAT was decided.

All output is byte-identical to the Python, TypeScript, Rust, C#, Ruby, Go, Kotlin, and MCP SDKs. 10 languages, one audit trail. Verified by 74 tests covering 47 fingerprint vectors, 2 signing vectors, and 5 hash vectors.

## Quick Start

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/tenova-labs/swt3-ai-swift.git", from: "0.5.9"),
],
targets: [
    .target(dependencies: [
        .product(name: "SWT3", package: "swt3-ai-swift"),
    ]),
]
```

### Mint a Fingerprint

```swift
import SWT3

let promptHash = SWT3.sha256Truncated("Summarize this contract...")
let responseHash = SWT3.sha256Truncated("The contract states...")

let fp = SWT3.mintFingerprint(
    tenant: "MY_TENANT",
    procedure: "AI-INF.1",
    factorA: 1, factorB: 1, factorC: 0,
    timestampMs: 1774800000000
)

let sig = SWT3.signPayload(key: "swt3_sk_my_key", fingerprint: fp, agentId: "fraud-detector-prod")
```

### Witness a Core ML Prediction

```swift
import SWT3
import CoreML

let model = try MLModel(contentsOf: modelURL)
let input = try model.prediction(from: inputProvider)

let payload = SWT3.witnessPrediction(
    model: model,
    input: inputProvider,
    output: input,
    latencyMs: 42,
    tenant: "MY_TENANT",
    clearingLevel: 1
)
// payload.anchorFingerprint is ready to transmit or store locally
```

### Witness a Spatial Decision (Vision Pro / ARKit)

```swift
import SWT3

// worldTransform from ARKit, RealityKit, or any spatial framework
let payload = SWT3.witnessSpatialInference(
    procedure: "AI-INF.1",
    factorA: 1, factorB: 35, factorC: 0,
    worldTransform: anchor.transform,
    tenant: "MY_TENANT",
    clearingLevel: 2,
    agentId: "spatial-nav-agent"
)
// Proves WHERE the AI decision was made in physical space
```

## Platform Support

| Platform | Minimum | Status |
|----------|---------|--------|
| iOS | 13.0+ | Supported |
| macOS | 10.15+ | Supported |
| watchOS | 6.0+ | Supported |
| tvOS | 13.0+ | Supported |
| visionOS | 1.0+ | Supported |
| Linux | Swift 5.9+ | Supported (via swift-crypto) |

Zero external SPM dependencies on Apple platforms. On Linux, Apple's open-source [swift-crypto](https://github.com/apple/swift-crypto) is included as a conditional dependency.

## Edge Attestation

SWT3 is built for edge inference. Whether your model runs on an iPhone neural engine, a Mac GPU, or a Vision Pro spatial compute pipeline, the witnessing pattern is the same:

1. **Hash locally** -- prompts, responses, and model weights are hashed on-device
2. **Mint a fingerprint** -- the canonical formula produces a 12-character attestation anchor
3. **Sign for non-repudiation** -- HMAC-SHA256 binding to agent identity
4. **Transmit or store** -- only hashes and numeric factors leave the device, on your schedule

For air-gapped deployments, anchors can be accumulated locally and batch-synced when connectivity is restored.

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
| Swift | swt3-ai (this package) | Swift Package Index |
| Rust | [swt3-ai](https://crates.io/crates/swt3-ai) | crates.io |
| C# / .NET | [swt3-ai](https://www.nuget.org/packages/swt3-ai) | NuGet |
| Ruby | [swt3-ai](https://rubygems.org/gems/swt3-ai) | RubyGems |
| Go | [swt3-ai](https://github.com/tenova-labs/swt3-ai-go) | Go modules |
| MCP Server | [@tenova/swt3-mcp](https://www.npmjs.com/package/@tenova/swt3-mcp) | npm + MCP Registry |
| K8s Witness Agent | [swt3-witness](https://github.com/tenova-labs/swt3-ai/tree/main/packages/swt3-witness) | GHCR + Helm |

The Python and TypeScript SDKs include the full witness pipeline: transparent client wrapping, buffer management, clearing engine, adapter support (OpenAI, Anthropic, Bedrock, vLLM, Ollama, LangChain, LangGraph, Microsoft AGT, Google ADK, CrewAI), trust mesh, policy-as-code, and Merkle accumulator. Use them for production AI witnessing. Use this Swift package for Apple platform integration, server-side Swift, or embedding fingerprint verification into iOS/macOS/visionOS applications.

## Regulatory Coverage

The SWT3 AI Witnessing Profile maps to:

- **EU AI Act**: Articles 9, 10, 12, 13, 14, 53, 72
- **NIST AI RMF**: GOVERN, MAP, MEASURE, MANAGE functions
- **ISO 42001**: Annex A AI management controls
- **NIST 800-53**: SI-7 (integrity), AU-2/AU-3 (audit), AC controls
- **SR 11-7**: Model risk management (financial services)

## Privacy

Your prompts, responses, and model weights **never leave your device**. The SDK computes SHA-256 hashes locally and transmits only irreversible hashes and numeric factors. At Clearing Level 3, even the model name is hashed. The witness endpoint is a blind registrar: it stores cryptographic proofs, not your data.

For Core ML predictions, the SDK hashes feature provider descriptions (names and types), not the raw tensor data. For spatial witnessing, the world transform matrix is hashed into a 12-character digest -- the physical coordinates are not recoverable from the hash.

## Links

- **Website**: [tenova.io](https://tenova.io)
- **Protocol Spec**: [SWT3 Protocol Specification](https://swt3.ai/spec)
- **Live Demo**: [sovereign.tenova.io/audit/axm_audit_demo_eu_ai_act_public](https://sovereign.tenova.io/audit/axm_audit_demo_eu_ai_act_public)

---

*SWT3: Sovereign Witness Traceability. We don't run your models. We witness them.*

SWT3 and Sovereign Witness Traceability are trademarks of Tenable Nova LLC. Patent pending. Apache 2.0 licensed.

This project uses Apple's CryptoKit framework and Secure Enclave APIs. Apple, CryptoKit, Core ML, ARKit, RealityKit, Vision Pro, iOS, macOS, watchOS, tvOS, and visionOS are trademarks of Apple Inc. This project is not affiliated with, endorsed by, or sponsored by Apple Inc. or any other third-party AI provider. All third-party trademarks are the property of their respective owners. Use of these names is for identification and interoperability purposes only.
