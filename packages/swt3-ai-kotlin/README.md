Witness your AI. Prove it followed the rules. Cryptographic accountability for every inference, tool call, and resource access.

[![Maven Central](https://img.shields.io/maven-central/v/io.tenova/swt3-ai)](https://central.sonatype.com/artifact/io.tenova/swt3-ai)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/tenova-labs/swt3-ai/blob/main/LICENSE)

# swt3-ai

**SWT3 AI Witness SDK for Kotlin/Android**: mint, verify, and sign SWT3 witness anchors with cross-language parity. One dependency. Zero data retention. Your prompts and responses never leave your infrastructure.

EU AI Act GPAI transparency obligations enforce **August 2, 2026**. High-risk enforcement follows **December 2, 2027**. This SDK gives you the cryptographic primitives for both.

## What's New in v0.1.0

First release. Kotlin is the 8th language in the SWT3 protocol family.

Android runs 72% of the world's mobile AI. On-device inference -- Gemini Nano, MediaPipe, Samsung Galaxy AI -- produces decisions with no server-side audit trail. When a financial app approves a loan on-device, or a health app triages symptoms locally, the compliance gap is invisible until an auditor asks for evidence that doesn't exist.

This SDK closes that gap. Every on-device inference gets the same cryptographic witness anchor as server-side models. Same fingerprint formula. Same clearing levels. Same ledger. One protocol from data center to pocket.

## Quick Start

Add to your `build.gradle.kts`:

```kotlin
dependencies {
    implementation("io.tenova:swt3-ai:0.1.0")
}
```

Or Maven:

```xml
<dependency>
    <groupId>io.tenova</groupId>
    <artifactId>swt3-ai</artifactId>
    <version>0.1.0</version>
</dependency>
```

### Witness an Inference (3 lines)

```kotlin
import io.tenova.swt3.*

val witness = WitnessClient(WitnessConfig(tenantId = "YOUR_TENANT_ID"))

val result = witness.wrap(
    prompt = "Evaluate this loan application...",
    response = "Based on the applicant's credit history...",
    modelId = "gpt-4o",
    provider = "openai",
)

witness.flush()
```

That's it. The SDK hashes your prompt and response locally (raw text never leaves your machine), mints a tamper-evident fingerprint, and writes it to a local write-ahead log. No API key required for local witnessing. When you connect to the cloud ledger, the same anchors sync automatically.

### What Your Auditor Receives

Your auditor never sees your prompts, responses, or model outputs. They see:

- A 12-character fingerprint proving the inference happened
- The procedure it satisfies (e.g., AI-INF.1 for inference provenance)
- Numeric factors (latency within threshold, guardrails active, model hash matches)
- A clearing level controlling how much metadata survives

They can verify any anchor independently -- in their browser, from their terminal, or with any of the 8 SDKs. No vendor dependency. No trust required.

## Privacy Architecture

The SDK computes SHA-256 hashes on your device. Only irreversible hashes and numeric factors reach the witness ledger. At Clearing Level 2, even prompt/response hashes are stripped. At Level 3, the model name is hashed.

If the witness endpoint is unreachable, payloads queue in a local write-ahead log and drain automatically when connectivity is restored. No inference is ever blocked. No data is ever lost.

## Production Configuration

```kotlin
val witness = WitnessClient(
    WitnessConfig(
        tenantId = "YOUR_TENANT_ID",       // from sovereign.tenova.io/settings
        clearingLevel = 1,                  // 0-3, controls data minimization
        agentId = "fraud-detector-prod",    // identifies this witness instance
        signingKey = "swt3_sk_your_key",    // HMAC-SHA256 non-repudiation
        jurisdiction = "DE",                // ISO 3166-1 (EU AI Act Art. 12)
        legalBasis = "GDPR-6-1-f",         // survives all clearing levels
        purposeClass = "fraud_detection",
    )
)

val result = witness.wrap(
    prompt = "Evaluate this loan application...",
    response = "Based on the applicant's credit history...",
    modelId = "gpt-4o",
    provider = "openai",
    latencyMs = 842,
    inputTokens = 156,
    outputTokens = 89,
)

println(result.fingerprint)  // 12-char hex, matches all 8 SDKs
val receipts = witness.flush()
```

## What You Get

- **`WitnessClient`** -- high-level client with `wrap()`, `witnessInference()`, `flush()`, local WAL persistence
- **`Fingerprint.mintFingerprint`** -- canonical SWT3 fingerprint from tenant, procedure, factors, and timestamp
- **`Signing.signPayload`** -- HMAC-SHA256 signing with optional agent identity binding
- **`Fingerprint.sha256Truncated`** -- truncated SHA-256 hashing for prompts, responses, and model weights
- **Types** -- `WitnessPayload`, `WitnessReceipt`, `WitnessConfig`, `WrapResult`, `RevocationReason` data classes

All output is byte-identical to the Python, TypeScript, Rust, Swift, C#, Ruby, and MCP SDKs. 8 languages, one audit trail. Verified by shared test vectors at build time.

## Android Integration

The SDK uses only `java.security.MessageDigest` and `javax.crypto.Mac` -- both available on Android API 1+. No native libraries, no platform-specific code, no network permissions required for local witnessing.

```kotlin
// In your Android ViewModel or Repository
val witness = WitnessClient(
    WitnessConfig(
        tenantId = "YOUR_TENANT_ID",
        clearingLevel = 2,  // Strip prompt/response hashes for mobile
        agentId = "android-assistant",
    )
)

// Witness on-device inference (Gemini Nano, MediaPipe, etc.)
val result = witness.wrap(
    prompt = userQuery,
    response = modelOutput,
    modelId = "gemini-nano",
    provider = "on-device",
)
```

## Clearing Levels

| Level | What Reaches the Ledger | Use Case |
|-------|------------------------|----------|
| 0 | Everything including raw text | Analytics, internal |
| 1 | Hashed prompts/responses, model ID, factors | Standard compliance |
| 2 | Factors and metadata only, no content hashes | Sensitive workloads |
| 3 | Factors only, model ID hashed | Classified environments |

## Verify Any Anchor

No SDK needed. No vendor dependency. Works on any machine:

```bash
echo -n "WITNESS:DEMO_TENANT:AI-INF.1:1:1:0:1774800000000" | sha256sum | cut -c1-12
# Produces a 12-character fingerprint. Compare it to the anchor. If it matches, the anchor is real.
```

Or verify in your browser at [sovereign.tenova.io/verify](https://sovereign.tenova.io/verify).

## What is an SWT3 Witness Anchor?

```
SWT3-E-CLOUD-AI-AIINF1-PASS-1773316622-96b7d56c0245
     |    |    |    |     |       |          |
     |    |    |    |     |       |          +-- SHA-256 fingerprint (12 hex)
     |    |    |    |     |       +------------- Unix epoch (seconds)
     |    |    |    |     +--------------------- Verdict
     |    |    |    +--------------------------- Procedure ID
     |    |    +-------------------------------- Domain (AI)
     |    +------------------------------------- Cloud provider
     +----------------------------------------- Deployment tier
```

The fingerprint is computed from `SHA256("WITNESS:{tenant}:{procedure}:{fa}:{fb}:{fc}:{ts_ms}")`. This formula is locked and identical across all 8 SDK languages.

## Run the Demo

```bash
./gradlew run
```

## Run Tests

```bash
./gradlew test
```

10 tests validate fingerprint parity, HMAC signing, and SHA-256 hashing against the canonical test vectors shared across all SDK languages.

## Regulatory Coverage

108 AI procedures across 56 namespaces. 31 regulatory frameworks including EU AI Act, NIST AI RMF, CMMC, SR 11-7, ISO 42001, GDPR, and OWASP.

## Resources

- [SDK Documentation](https://sovereign.tenova.io/docs/) -- quickstart, provider matrix, API reference
- [UCT Registry](https://sovereign.tenova.io/registry/) -- 229 procedures, searchable
- [Public Verifier](https://sovereign.tenova.io/verify) -- verify any anchor in your browser
- [Assessor Hot Sheet](https://sovereign.tenova.io/guides/assessor-hot-sheet.html) -- 2-page printable to hand your auditor during assessment meetings
- [All 150 Guides](https://sovereign.tenova.io/guides/) -- regulatory crosswalks, assessor walkthroughs, integration guides

## License

Apache 2.0. Verification is free, forever.

Copyright (c) 2026 Tenable Nova LLC. Patent pending.
