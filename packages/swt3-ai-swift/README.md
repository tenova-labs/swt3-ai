Witness your AI at the edge. Prove it followed the rules. Cryptographic accountability for every on-device inference, model integrity check, and spatial decision.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/tenova-labs/swt3-ai/blob/main/LICENSE)

# swt3-ai

**SWT3 AI Witness SDK for Swift**: mint, verify, and sign SWT3 witness anchors on Apple platforms and Linux. Zero external dependencies on Apple platforms. CryptoKit for hashing and HMAC, Foundation for timestamps.

Your models run on-device. Your attestation stays on-device until you choose to transmit. Only irreversible hashes leave the device -- never prompts, responses, or model weights.

GPAI transparency obligations are enforceable now. EU AI Act high-risk enforcement begins **December 2, 2027**. Edge inference is not exempt.

## What You Get

### Core Primitives

- **`SWT3.mintFingerprint`** -- canonical SWT3 fingerprint from tenant, procedure, factors, and timestamp
- **`SWT3.signPayload`** -- HMAC-SHA256 signing with optional agent identity binding
- **`SWT3.sha256Truncated`** -- truncated SHA-256 hashing for prompts, responses, and model weights
- **`SWT3.timestampMs`** -- millisecond-precision timestamps matching the protocol clock
- **Types** -- `WitnessPayload`, `WitnessReceipt`, `WitnessConfig`, `RevocationReason` structs (Sendable, Equatable, Codable)
- **Model Integrity** -- `SWT3.hashFile` and `SWT3.hashDirectory` for model weight verification

### Apple Platform Features

Available on iOS, macOS, and visionOS via `#if canImport`:

- **`SWT3.witnessPrediction`** -- witness a Core ML prediction (AI-INF.1). Extracts model metadata, hashes input/output feature descriptions, computes latency, and mints a fingerprint. Raw inference data never leaves the device.
- **`SWT3.witnessModelIntegrity`** -- witness Core ML model integrity (AI-MDL.1). Hashes the compiled `.mlmodelc` bundle for tamper detection and drift monitoring.
- **`SWT3.witnessSpatialInference`** -- witness an AI decision with spatial context. Captures a 4x4 world transform matrix and hashes it into the anchor. For AI systems making decisions in physical space (navigation, object recognition, spatial reasoning on Vision Pro), this proves WHERE the decision was made, not just WHAT was decided.

All output is byte-identical to the Python, TypeScript, Rust, C#, Ruby, and MCP SDKs. 7 languages, one audit trail. Verified by 74 tests covering 47 fingerprint vectors, 2 signing vectors, and 5 hash vectors.

## Quick Start

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/tenova-labs/swt3-ai-swift.git", from: "0.5.8"),
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
