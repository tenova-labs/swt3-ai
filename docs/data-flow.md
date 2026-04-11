# SWT3 Data Flow and Privacy Architecture

> For Legal, DPO, and CISO review. No proprietary information.

## Overview

The SWT3 AI Witness SDK produces cryptographic proof that an AI system operated within approved parameters. It does this **without transmitting prompts, responses, or any natural language content** to the witness endpoint.

This document explains exactly what data crosses the network boundary at each clearing level.

## The Sovereign Boundary

```
  YOUR INFRASTRUCTURE                    WITNESS LEDGER
  (Customer-controlled)                  (TeNova-operated)

  +---------------------------+     +---------------------------+
  |                           |     |                           |
  |  AI Client (OpenAI, etc.) |     |  Receives ONLY:           |
  |         |                 |     |                           |
  |         v                 |     |  - SHA-256 hashes         |
  |  +----------------+      |     |  - Numeric factors        |
  |  | SWT3 Witness   |      |     |  - Clearing level         |
  |  | SDK            |      |     |  - Fingerprint            |
  |  |                |      |     |  - Epoch timestamp        |
  |  | 1. Intercept   |      |     |                           |
  |  | 2. SHA-256     |      |     |  NEVER receives:          |
  |  | 3. Extract     |------+---->|                           |
  |  | 4. Clear       |      |     |  - Prompts                |
  |  | 5. Purge       |      |     |  - Responses              |
  |  | 6. Return      |      |     |  - User content           |
  |  +-------+--------+      |     |  - PII / PHI              |
  |          |                |     |  - Training data          |
  |          v                |     |  - API keys               |
  |  Original response       |     |  - Encryption keys        |
  |  returned to your code   |     |                           |
  |  (untouched)             |     +---------------------------+
  |                           |
  +---------------------------+
```

## What Crosses the Boundary (By Clearing Level)

### Level 0 - Analytics

| Field | Example | Purpose |
|-------|---------|---------|
| `procedure_id` | `AI-INF.1` | Which compliance check was evaluated |
| `factor_a`, `factor_b`, `factor_c` | `1`, `1`, `0` | Numeric compliance factors |
| `anchor_fingerprint` | `c059eb5938c0` | SHA-256 derived, 12-char hex |
| `ai_prompt_hash` | `315f5bdb76d078c4` | SHA-256 of prompt (16-char, irreversible) |
| `ai_response_hash` | `a1b2c3d4e5f60718` | SHA-256 of response (16-char, irreversible) |
| `ai_model_id` | `gpt-4o` | Model identifier |
| `ai_latency_ms` | `842` | Inference duration |
| `ai_context.provider` | `openai` | Provider name |
| `ai_context.guardrails` | `["content-filter"]` | Active guardrail names |

### Level 1 - Standard (Default)

Same as Level 0 but without guardrail names in `ai_context`. This is the default for production deployments.

**What stays on your side:** All prompt text, all response text, all user-identifiable content. Only SHA-256 hashes (one-way, irreversible) cross the boundary.

### Level 2 - Sensitive

| Field | Transmitted | Explanation |
|-------|-------------|-------------|
| `procedure_id` | Yes | Compliance procedure identifier |
| `factor_a/b/c` | Yes | Numeric values only |
| `anchor_fingerprint` | Yes | Derived from factors via SHA-256 |
| `ai_prompt_hash` | Yes | Irreversible hash |
| `ai_response_hash` | Yes | Irreversible hash |
| `ai_model_id` | Yes | Model name only |
| `ai_context` | **No** | Stripped entirely before transmission |
| `ai_latency_ms` | Yes | Numeric metric |

**Use case:** Healthcare, legal, PII-adjacent workloads where even the provider name is considered sensitive.

### Level 3 - Classified

| Field | Transmitted | Explanation |
|-------|-------------|-------------|
| `procedure_id` | Yes | Compliance procedure identifier |
| `factor_a/b/c` | Yes | Numeric values only |
| `anchor_fingerprint` | Yes | Derived from factors via SHA-256 |
| `ai_model_id` | **Hashed** | SHA-256 of model name, not the name itself |
| `ai_prompt_hash` | **No** | Not transmitted |
| `ai_response_hash` | **No** | Not transmitted |
| `ai_context` | **No** | Not transmitted |
| `ai_latency_ms` | **No** | Not transmitted |

**What the witness endpoint sees at Level 3:** Three numbers, a procedure ID, a fingerprint, and an epoch. Nothing else. The model name is hashed. No metadata survives.

**Use case:** Defense, classified environments, air-gapped deployments.

## The SHA-256 Guarantee

SHA-256 is a one-way cryptographic hash function. Given a hash like `315f5bdb76d078c4`, it is computationally infeasible to reconstruct the original input. This is not encryption (which can be reversed with a key). It is destruction of the original data, preserving only a fixed-length fingerprint.

The SWT3 protocol hashes prompts and responses **locally, inside your infrastructure**, before any network call occurs. The hash is what crosses the boundary. The original text is never serialized, never buffered, and never queued for transmission.

## The Purge Step

After factors are extracted and hashes are computed, the SDK explicitly purges all references to the original prompt and response text from its internal state. The clearing engine then removes additional fields based on the configured clearing level before the payload is queued for transmission.

At Level 1+, the sequence is:

1. Your AI client returns a response
2. The SDK computes SHA-256 hashes of prompt and response (in-process, no I/O)
3. Numeric factors are extracted (latency, token count, guardrail status)
4. **Original text references are purged from the SDK's internal state**
5. Clearing level removes additional metadata fields
6. Only the cleared payload is queued for background transmission
7. Your code receives the original, untouched response

## Factor Handoff (Levels 2 and 3)

At Clearing Level 2 or 3, some verifiable data is stripped before it reaches the witness endpoint. The Factor Handoff protocol writes the full, uncleared factors to a local file **before** clearing proceeds. If the local write fails, the payload is not transmitted.

This ensures that the customer always retains a complete copy of the evidence, even when the witness ledger receives only the minimum.

For the full protocol specification, see the [Factor Handoff Protocol](https://sovereign.tenova.io/docs/factor-handoff-protocol.html).

## Independent Verification

The `anchor_fingerprint` is computed from a deterministic formula:

```
SHA256("WITNESS:{tenant}:{procedure}:{factor_a}:{factor_b}:{factor_c}:{timestamp_ms}")
```

Anyone with the factors can recompute the fingerprint and verify it matches the anchor on the ledger. No database access, no API calls, no network connectivity required. The verification is pure math.

The open-source `libswt3` package provides standalone verification tools that work entirely offline.

## Regulatory Applicability

This data flow architecture satisfies:

- **GDPR Article 17** (Right to Erasure): No personal data is stored on the witness ledger. Hashes are not personal data under GDPR guidance.
- **EU AI Act Article 12** (Record-Keeping): Anchors provide the required record of AI system operation without storing regulated content.
- **NIST 800-53 SI-7** (Software Integrity): Cryptographic fingerprints provide tamper-evident integrity verification.
- **HIPAA / 21 CFR Part 11**: Level 2+ ensures no PHI crosses the boundary.
- **CMMC / NIST 800-171**: Compatible with CUI handling requirements at Level 2+.

## Related Documents

- [Clearing & Data Sovereignty Addendum](https://sovereign.tenova.io/terms/clearing-addendum) - Legal terms, shared responsibility matrix, incident response SLA
- [Factor Handoff Protocol](https://sovereign.tenova.io/docs/factor-handoff-protocol.html) - Custody transfer specification for Levels 2 and 3
- [CMMC Compliance Overlay](https://sovereign.tenova.io/guides/cmmc-overlay.html) - Control mappings for defense industrial base
- [SR 11-7 Compliance Overlay](https://sovereign.tenova.io/guides/sr-11-7-overlay.html) - Model risk management mappings

---

*SWT3: Sovereign Witness Traceability. We don't run your models. We witness them.*
