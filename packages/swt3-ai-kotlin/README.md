Witness your AI. Prove it followed the rules. Cryptographic accountability for every inference, tool call, and resource access.

[![Maven Central](https://img.shields.io/maven-central/v/io.tenova/swt3-ai)](https://central.sonatype.com/artifact/io.tenova/swt3-ai)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/tenova-labs/swt3-ai/blob/main/LICENSE)

# swt3-ai

**SWT3 AI Witness SDK for Kotlin/Android**: mint, verify, and sign SWT3 witness anchors with cross-language parity. One dependency. Zero data retention. Your prompts and responses never leave your infrastructure.

EU AI Act GPAI transparency obligations enforce **August 2, 2026**. High-risk enforcement follows **December 2, 2027**. This SDK gives you the cryptographic primitives for both.

> **Protocol Spec:** [swt3.ai/spec](https://swt3.ai/spec) | **Registry:** [swt3.ai/registry](https://swt3.ai/registry) | **Verify:** [swt3.ai/verify](https://swt3.ai/verify)

## Ecosystem: v0.7.4

NVIDIA shipped OpenShell to 120+ partners. Agent containment is now infrastructure. But containment without evidence is a black box -- an auditor cannot verify that a sandbox policy was enforced last Tuesday at 14:00 UTC by looking at enforcement logs alone. v0.7.4 adds runtime containment attestation (AI-SHELL.1), model distillation provenance (AI-DIST.1), MCP elicitation detection (AI-MCP.6), and incident lifecycle chains. Four governance gaps closed in one release.

**Why this matters for Kotlin:** All three new procedure IDs (AI-SHELL.1, AI-DIST.1, AI-MCP.6) verify with the existing `Fingerprint.mint()` function. Kotlin/Android ML pipelines and JVM agent frameworks running in sandboxed environments gain containment attestation, distillation lineage, and elicitation detection with byte-identical output across all 10 SDK languages. Zero dependency changes required.

### 3 New Procedures

- **AI-SHELL.1** (Runtime Containment Attestation): Records that a sandboxed runtime enforced its containment policy during a specific observation window. Duck-typed: works with OpenShell, gVisor, Kata, Firecracker, WASM. [NVIDIA OpenShell Crosswalk](https://sovereign.tenova.io/guides/nvidia-openshell-crosswalk.html)
- **AI-DIST.1** (Distillation Provenance): Records teacher-to-student model lineage, distillation type (logit/feature/attention/data/hybrid), and ToS compliance status.
- **AI-MCP.6** (Elicitation Detection): Records prompt boundary violations via tool responses, consent status, scope violation type, and detection method.

### Updated Coverage

- 278 procedures across 10 namespaces (was 277). 75 MCP tools (was 74). 277 compliance guides. [NVIDIA OpenShell Crosswalk](https://sovereign.tenova.io/guides/nvidia-openshell-crosswalk.html). All new anchor types verify with `Fingerprint.mint()` -- no library update required.

## Ecosystem: v0.7.3

A2A (Google's Agent-to-Agent protocol) has 150+ supporting organizations, all three hyperscalers, and a v1.0 stable specification under Linux Foundation governance. It has zero built-in audit trail. MCP OAuth adoption sits at 8.5% with 30+ CVEs filed in 60 days. v0.7.3 makes SWT3 the evidence layer for both agent communication protocols with dedicated procedures, lifecycle-aware adapters, and a new crosswalk CLI command.

**Why this matters for Kotlin:** Kotlin/JVM agent frameworks gain A2A lifecycle attestation. The four new procedure IDs verify with the existing `mintFingerprint` function.

### 4 New Procedures

- **AI-A2A.1** (Task Delegation Lifecycle): Records task state transitions (submitted/working/input_required/completed/failed/canceled/rejected) with delegation depth and latency.
- **AI-A2A.2** (Agent Card Discovery): Records agent discovery via well-known URLs, registries, or referrals, with verified credential count.
- **AI-A2A.3** (Context Chain Linking): Records contextId linkage across multi-agent delegation chains for forensic reconstruction.
- **AI-MCP.5** (OAuth Token Binding): Records 8 OAuth lifecycle events (discovery through revocation) with binding strength and scope governance.

### Updated Coverage

- 284 procedures across 10 namespaces (was 280/9). 72 MCP tools (was 68). A2A namespace added (10th namespace). 269 compliance guides. All new anchor types verify with `Fingerprint.mint()` -- no library update required.

## Ecosystem: v0.7.2

Two gaps closed in one release: harness-layer governance and zero-code MCP compliance. The SWT3 ecosystem now includes five new procedures for orchestration topology (AI-ORCH.1), agent handoff (AI-ORCH.2), context window management (AI-CTX.1), sandbox enforcement (AI-SAND.1), and eval gating (AI-GATE.1) -- the decisions AI harnesses make before inference that have no audit trail today. The companion MCP package also ships a Witness Middleware (`withSWT3(transport)`) that auto-mints AI-TOOL.1 anchors for every tool call flowing through any MCP server with zero code changes. 280 procedures across 77 namespaces, 68 MCP tools, 265 compliance guides. All new anchor types verify with the existing `Fingerprint.mint()` method -- no library update required. Kotlin code stays at v0.1.1.

## Ecosystem: v0.7.1

OWASP published the MCP Top 10 in 2026 -- 30-82% of MCP servers are vulnerable. The SWT3 ecosystem now covers all 10 OWASP MCP risks with three new procedures: AI-MCP.2 (tool integrity attestation), AI-MCP.3 (server auth attestation), AI-MCP.4 (server discovery attestation). All new anchor types verify with `Fingerprint.mint()` -- no library update required.

## Ecosystem: v0.7.0

The SWT3 ecosystem now covers 266 procedures across 75 namespaces, including three new infrastructure families: NHI (credential governance), HBOM/DPP (hardware + battery passport), and ADR (demand response). All new anchor types verify with the existing `Fingerprint.mint()` method -- no library update required for verification. Kotlin code stays at v0.1.1. Full new procedure support available via the Python, TypeScript, and Go SDKs.

## What's New in v0.6.3

Four new attestation types and code objects for the procedures regulators ask about first. Each maps to regulations enforcing now or within months.

- **Output Filter Result** (`OutputFilterResult` + `FilterAction`, AI-GRD.2) -- Guardrails run, but proving the output classification result is a separate evidence requirement. When Tencent's Doubao was shut down overnight for output violations, the gap was not whether guardrails existed but whether there was proof each output passed classification. This data class records whether model output passed content safety filters, what type of filter ran, and what action was taken. Distinct from input-side guardrail activation (AI-GRD.1) -- this is the output-side classification result. EU AI Act Art. 15(3), NIST AI RMF GOVERN 1.5.

- **Data Provenance Attestation** (`DataProvenanceAttestation`, AI-DATA.1) -- Training data is the most guarded secret in AI. This type solves the tension: it attests that data governance review was performed WITHOUT disclosing what the training data was. No dataset names, no license strings, no content hashes of the data itself. Instead: governance reviewed (bool), documentation hash (SHA-256 of the data card, not the data), license compliance verified, demographic features confirmed absent. Satisfies EU AI Act Art. 10, SR 11-7 III.A, and CA-AB-2013 through diligence attestation, not disclosure.

- **Consent Attestation** (`ConsentAttestation` + `ConsentBasis`, AI-CONSENT.1) -- GDPR lawful basis encoding for mobile apps that collect consent before on-device inference. Basis code, subject count, withdrawal availability, jurisdiction. When an Android app runs Gemini Nano locally, the consent evidence must exist before inference starts.

- **Incident Report** (`IncidentReport` + `IncidentSeverity` / `IncidentType`, AI-INCIDENT.1) -- NIS-2 gives you 24 hours to report. EU AI Act Art. 62 gives you 72. The question regulators ask is "when did you know?" This type records severity, incident type, authority notification status, detection method, and reporting deadline -- structured evidence that the clock started when you say it did.

### v0.1.1

Four new attestation types: `ConsentAttestation`, `OutputFilterResult`, `IncidentReport`, `DataProvenanceAttestation` with supporting code objects.

### v0.1.0

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

They can verify any anchor independently -- in their browser, from their terminal, or with any of the 9 SDKs. No vendor dependency. No trust required.

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

println(result.fingerprint)  // 12-char hex, matches all 9 SDKs
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

Or verify in your browser at [swt3.ai/verify](https://swt3.ai/verify).

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

The fingerprint is computed from `SHA256("WITNESS:{tenant}:{procedure}:{fa}:{fb}:{fc}:{ts_ms}")`. This formula is locked and identical across all 9 SDK languages.

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

107 AI procedures across 56 namespaces. 34 regulatory frameworks including EU AI Act, NIST AI RMF, CMMC, SR 11-7, ISO 42001, GDPR, and OWASP.

## Resources

- [SDK Documentation](https://sovereign.tenova.io/docs/) -- quickstart, provider matrix, API reference
- [UCT Registry](https://swt3.ai/registry) -- 284 procedures, searchable
- [Public Verifier](https://swt3.ai/verify) -- verify any anchor in your browser
- [Assessor Hot Sheet](https://sovereign.tenova.io/guides/assessor-hot-sheet.html) -- 2-page printable to hand your auditor during assessment meetings
- [All 150 Guides](https://sovereign.tenova.io/guides/) -- regulatory crosswalks, assessor walkthroughs, integration guides

## License

Apache 2.0. Verification is free, forever.

Copyright (c) 2026 Tenable Nova LLC. Patent pending.
