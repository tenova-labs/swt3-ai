Witness your AI at the edge. Prove it followed the rules. Cryptographic accountability for every on-device inference, model integrity check, and spatial decision.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/tenova-labs/swt3-ai/blob/main/LICENSE)

# swt3-ai

**SWT3 AI Witness SDK for Swift**: mint, verify, and sign SWT3 witness anchors on Apple platforms and Linux. Zero external dependencies on Apple platforms. CryptoKit for hashing and HMAC, Foundation for timestamps.

Your models run on-device. Your attestation stays on-device until you choose to transmit. Only irreversible hashes leave the device -- never prompts, responses, or model weights.

EU AI Act GPAI transparency obligations enforce **August 2, 2026**. High-risk enforcement follows **December 2, 2027**. Edge inference is not exempt.

## What's New in v0.6.6

Supply chain accountability. Four new procedures, a CI/CD gate action, and OTel GenAI conventions across the ecosystem. Every improvement flows through to Swift because fingerprints are identical across all 10 languages.

### 4 New Procedures

**AI-PROV.1 (Model Provenance Chain):** Records model lineage -- base model, training pipeline, fine-tuning ancestry. The G7 Hiroshima AI SBOM framework requires provenance documentation. A `parent_model_fingerprint` parameter on model weight/adapter/quantization methods links derivative models to their ancestors. Provenance anchors verify with `SWT3.mintFingerprint` like any other anchor.

**AI-DEL.2 (Delegation Boundary):** Records what an agent is NOT permitted to do -- blocked tools, restricted scopes, escalation triggers. EU AI Act Art. 14 requires documented AI system limitations. Where AI-DEL.1 tracks permissions, AI-DEL.2 tracks constraints.

**AI-DENSITY.1 (Anchor Density):** Records the ratio of witnessed events to total events over a time window. Catches the slow coverage drift from 100% to 2% that nobody notices until the audit. A DensityEnforcer class in Python and TypeScript auto-fires density anchors when coverage drops.

**AI-MCP.1 (MCP Security Posture):** Evaluates 8 security properties of an MCP server connection. Records checks passed vs. total -- never which specific checks failed. NSA and CISA flagged 200,000+ vulnerable MCP deployments in 2026. This creates evidence that security was evaluated at connection time without becoming an attack map.

**Why it matters for Swift:** All four procedures produce anchors with the same fingerprint formula. Your Swift app can verify any of these new anchor types with the existing `SWT3.mintFingerprint` function -- no package update required for verification. On-device Core ML models fine-tuned from open-weight base models now have a provenance chain linking edge inference back to the training lineage. The delegation boundary procedure is particularly relevant for iOS agents that need to prove their constraints before operating in restricted environments like healthcare or financial services.

### GitHub Action

`tenova-labs/swt3-gate-action@v1` evaluates `.swt3-gate.yml` in CI/CD. Fails the build when coverage drops. Works with Xcode Cloud and any CI system -- the gate checks anchors on the server, not the SDK in your repo.

### OTel GenAI Conventions (Python + TypeScript)

The OpenTelemetry exporters now emit `gen_ai.system`, `gen_ai.request.model`, and token usage attributes following the OTel GenAI semantic conventions. If your Swift app's backend consumes OTel spans from the Python or TypeScript witness pipeline, these new attributes appear automatically.

### Updated Coverage

- 118 procedures across 64 namespaces (+AI-PROV.1, AI-DEL.2, AI-DENSITY.1, AI-MCP.1)
- 37 MCP tools (+witness_delegation_boundary, witness_anchor_density, witness_mcp_security, witness_model_provenance)
- 10 SDK languages with byte-identical output
- 36 framework crosswalks, 222 compliance guides
- 2,825 tests passing across 5 languages

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
- **Protocol Spec**: [SWT3-SPEC-v1.0](https://github.com/tenova-labs/swt3-ai)
- **Live Demo**: [sovereign.tenova.io/audit/axm_audit_demo_eu_ai_act_public](https://sovereign.tenova.io/audit/axm_audit_demo_eu_ai_act_public)

---

*SWT3: Sovereign Witness Traceability. We don't run your models. We witness them.*

SWT3 and Sovereign Witness Traceability are trademarks of Tenable Nova LLC. Patent pending. Apache 2.0 licensed.

This project uses Apple's CryptoKit framework and Secure Enclave APIs. Apple, CryptoKit, Core ML, ARKit, RealityKit, Vision Pro, iOS, macOS, watchOS, tvOS, and visionOS are trademarks of Apple Inc. This project is not affiliated with, endorsed by, or sponsored by Apple Inc. or any other third-party AI provider. All third-party trademarks are the property of their respective owners. Use of these names is for identification and interoperability purposes only.
