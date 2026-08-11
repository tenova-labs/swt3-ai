# SWT3 Protocol Specification

**Version 1.0.1 | August 2026**

**Sovereign Witness Traceability (SWT3)**

Cryptographic Witness Anchors for AI Systems and Regulated Infrastructure

---

## Table of Contents

1. [Scope](#1-scope)
2. [Normative References](#2-normative-references)
3. [Terms and Definitions](#3-terms-and-definitions)
4. [Status of This Document](#4-status-of-this-document)
5. [Protocol Overview](#5-protocol-overview)
6. [Anchor Format](#6-anchor-format)
7. [Fingerprint Algorithm](#7-fingerprint-algorithm)
8. [Factor Schema](#8-factor-schema)
9. [Clearing Protocol](#9-clearing-protocol)
10. [Signing Protocol](#10-signing-protocol)
11. [Verification Algorithm](#11-verification-algorithm)
12. [Witness Payload Schema](#12-witness-payload-schema)
13. [Lifecycle Chains](#13-lifecycle-chains)
14. [Provider-Deployer Evidence Chains](#14-provider-deployer-evidence-chains)
15. [Universal Control Taxonomy](#15-universal-control-taxonomy)
16. [Conformity Requirements](#16-conformity-requirements)
17. [Security Considerations](#17-security-considerations)
18. [Test Vectors](#18-test-vectors)
19. [Registry Considerations](#19-registry-considerations)
20. [Protocol Adoption Rationale](#20-protocol-adoption-rationale)
21. [Reference Implementations](#21-reference-implementations)
22. [Bibliography](#22-bibliography)
23. [Auditor Display Requirements](#23-auditor-display-requirements)
24. [Conformity Evidence Package](#24-conformity-evidence-package)

---

## 1. Scope

This specification defines the SWT3 (Sovereign Witness Traceability) protocol for generating, signing, and verifying cryptographic witness anchors. A witness anchor is a deterministic, independently verifiable attestation record computed from observed operational facts.

This specification covers:

- The anchor token format and its constituent fields
- The fingerprint computation algorithm
- The three-factor evidence schema
- Clearing levels that control information density on the wire
- Signing and verification algorithms
- The witness payload JSON schema
- Lifecycle chain identifiers for multi-stage operations
- Provider-deployer evidence chain delegation
- Conformity requirements for implementations

This specification does NOT cover:

- Policy frameworks, risk assessment methodologies, or organizational governance structures
- Verdict evaluation logic (procedure-specific; defined by the implementing platform)
- Platform infrastructure (ingestion endpoints, storage, analytics, dashboards)
- Compliance passport generation or OSCAL export
- Trust mesh credential exchange protocol (specified separately)

The SWT3 protocol is industry-agnostic, framework-neutral, and designed for cross-language interoperability. It operates independently of any specific AI provider, cloud platform, or regulatory regime.

---

## 2. Normative References

The following documents are referenced normatively in this specification. For dated references, only the edition cited applies. For undated references, the latest edition applies.

- **RFC 2119** -- Key words for use in RFCs to Indicate Requirement Levels (Bradner, 1997)
- **RFC 6234** -- US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF) (Eastlake & Hansen, 2011)
- **RFC 2104** -- HMAC: Keyed-Hashing for Message Authentication (Krawczyk, Bellare & Canetti, 1997)
- **FIPS 204** -- Module-Lattice-Based Digital Signature Standard (ML-DSA) (NIST, 2024)
- **ISO 8601:2019** -- Date and time format
- **RFC 4648** -- The Base16, Base32, and Base64 Data Encodings (Josefsson, 2006)

---

## 3. Terms and Definitions

For the purposes of this specification, the following terms and definitions apply. The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

**Witness Anchor** -- A deterministic, cryptographically verifiable attestation record encoding observed operational facts as a structured token string.

**Fingerprint** -- A 12-character hexadecimal string derived from the SHA-256 hash of a domain-separated input containing tenant identity, procedure identifier, factors, and timestamp.

**Factor** -- A numeric value (integer) encoding an observed operational measurement. Each witness anchor contains exactly three factors: factor_a, factor_b, and factor_c.

**Clearing Level** -- An integer (0-3) specifying the information density permitted in a witness payload. Higher clearing levels progressively remove metadata before transmission.

**Procedure** -- A named operation in the Universal Control Taxonomy (UCT) that a witness anchor attests to. Identified by a dotted-namespace format (e.g., AI-INF.1).

**UCT (Universal Control Taxonomy)** -- The namespace registry that defines all valid procedure identifiers, organized by domain.

**Tenant** -- An organizational entity whose identity is bound into the fingerprint computation. Tenants are isolated; cross-tenant fingerprint collision is computationally infeasible.

**Enclave** -- A deployment environment containing one or more witnessed systems. Enclave integrity is computed from the collective fingerprints of all anchors within it.

**Lifecycle Chain** -- A sequence of related witness anchors linked by a shared chain identifier, representing a multi-stage operation (e.g., emergency override initiation through resolution).

**CJT Fields (Compliance Jurisdiction and Traceability)** -- Metadata fields that survive all clearing levels: jurisdiction, legal_basis, purpose_class, agent_id, and cycle_id.

**Verdict** -- The binary outcome of a witnessed operation: PASS or FAIL. Verdict evaluation logic is procedure-specific and defined by the implementing platform, not by this specification.

---

## 4. Status of This Document

This is version 1.0 of the SWT3 Protocol Specification, published August 2026 by Tenable Nova LLC.

Normative sections of this specification are versioned. Breaking changes to normative sections increment the major version number. Additive extensions that do not alter existing normative requirements increment the minor version number. The UCT Registry governance process is documented in Section 19.

The fingerprint algorithm (Section 7), anchor format (Section 6), and clearing level definitions (Section 9) are locked as of this version. Implementations conforming to version 1.0 will remain compatible with all future 1.x versions of this specification.

This specification is published by Tenable Nova LLC as the protocol's originating organization. As multi-stakeholder adoption progresses, governance of the SWT3 protocol, UCT Registry, and test vector suite is expected to transition to a multi-stakeholder body. Organizations contributing to the protocol's development, implementation, or adoption are invited to participate in shaping its governance structure.

Patent pending.

---

## 5. Protocol Overview

*This section is informative.*

The SWT3 protocol operates in three phases:

**Phase 1: Witness.** An observed operational fact (e.g., an AI inference, a guardrail evaluation, a model integrity check) is captured as three numeric factors with associated metadata.

**Phase 2: Mint.** A witness anchor is deterministically computed from the factors, tenant identity, procedure identifier, and timestamp. The anchor is optionally signed with HMAC-SHA256 or ML-DSA-65. Clearing is applied to remove metadata according to the specified level before transmission.

**Phase 3: Verify.** Any party with knowledge of the input components can independently recompute the fingerprint using standard SHA-256 and compare it to the anchor's claimed fingerprint. No proprietary tooling, API access, or platform account is required for verification.

The protocol is architecturally neutral. It does not prescribe how evidence is collected, where anchors are stored, or how verdicts are evaluated. These concerns are delegated to the implementing platform.

---

## 6. Anchor Format

*This section is normative.*

A witness anchor token is a hyphen-delimited string with the following structure:

```
SWT3-{TIER}-{PROVIDER}-{UCT}-{PROCEDURE}-{VERDICT}-{EPOCH}-{FINGERPRINT}
```

### 6.1 Field Definitions

| Field | Description | Type | Constraints |
|-------|-------------|------|-------------|
| `SWT3` | Protocol identifier | Literal | Always the string `SWT3` |
| `TIER` | Deployment tier | Char(1) | `E` (Enclave), `S` (SaaS), `H` (Hybrid) |
| `PROVIDER` | Infrastructure provider | String | `VULTR`, `AWS`, `AZURE`, `GCP`, `HYBRID`, `ON-PREM`, or other registered provider codes |
| `UCT` | Universal Control Taxonomy domain | String | 2-4 uppercase alphanumeric characters (e.g., `ACC`, `NET`, `AI`) |
| `PROCEDURE` | Procedure identifier (normalized) | String | Hyphens and periods removed from the full procedure ID, including namespace prefix (e.g., `AI-INF.1` becomes `AIINF1`, `SC-7.6` becomes `SC76`) |
| `VERDICT` | Binary outcome | Literal | `PASS` or `FAIL` |
| `EPOCH` | Timestamp | Integer | Unix epoch in seconds |
| `FINGERPRINT` | Evidence fingerprint | Hex(12) | First 12 characters of the SHA-256 fingerprint (Section 7) |

### 6.2 Normalization Rules

- The PROCEDURE field MUST be normalized by removing all hyphens (`-`) and periods (`.`) from the full procedure identifier. The namespace prefix is retained. For example, `AI-INF.1` becomes `AIINF1`; `AI-METAGOV.8` becomes `AIMETAGOV8`.
- Provider codes MUST be uppercase alphanumeric.
- UCT domain codes MUST be uppercase alphanumeric, 2-4 characters.

### 6.3 Example

```
SWT3-E-VULTR-AI-AIINF1-PASS-1774800000-2e16e2fe92dd
```

Decomposition:

| Segment | Value | Meaning |
|---------|-------|---------|
| `SWT3` | Protocol | SWT3 protocol anchor |
| `E` | Tier | Enclave deployment |
| `VULTR` | Provider | Vultr infrastructure |
| `AI` | UCT | AI/ML governance domain |
| `AIINF1` | Procedure | AI-INF.1 (Inference Provenance) |
| `PASS` | Verdict | Operation passed |
| `1774800000` | Epoch | Unix timestamp (seconds) |
| `2e16e2fe92dd` | Fingerprint | SHA-256 derived, 12 hex chars |

---

## 7. Fingerprint Algorithm

*This section is normative.*

### 7.1 Canonical Formula

The fingerprint MUST be computed as follows:

```
fingerprint = SHA256("WITNESS:{tenant_id}:{procedure_id}:{factor_a}:{factor_b}:{factor_c}:{timestamp_ms}").hex()[:12]
```

Where:

| Component | Type | Description |
|-----------|------|-------------|
| `WITNESS` | Literal string | Domain separation prefix. REQUIRED. |
| `tenant_id` | String | Tenant identifier (e.g., `ENCLAVE_PROD`) |
| `procedure_id` | String | Original procedure ID with full punctuation (e.g., `AI-INF.1`) |
| `factor_a` | Integer | First factor, rendered as a decimal string (e.g., `1`, `5000`) |
| `factor_b` | Integer | Second factor, rendered as a decimal string |
| `factor_c` | Integer | Third factor, rendered as a decimal string |
| `timestamp_ms` | Integer | Millisecond-precision Unix epoch, rendered as a decimal string |

### 7.2 Computation Steps

1. Construct the input string by concatenating all components with colon (`:`, U+003A) separators.
2. Encode the input string as UTF-8.
3. Compute the SHA-256 digest (per RFC 6234).
4. Encode the digest as lowercase hexadecimal.
5. Truncate to the first 12 characters.
6. The result is the anchor fingerprint.

### 7.3 Encoding Rules

- Integer factors MUST be rendered without leading zeros, decimal points, or thousands separators. The integer `0` is rendered as `"0"`. The integer `5000` is rendered as `"5000"`.
- The timestamp MUST be in milliseconds. Seconds-precision timestamps MUST be multiplied by 1000.
- The domain separation prefix `WITNESS` MUST be uppercase.
- The procedure_id MUST preserve its original punctuation (hyphens, periods). Normalization (Section 6.2) applies only to the anchor token string, not to the fingerprint input.

### 7.4 Legacy Formula

Implementations MUST also support verification against the legacy formula for backward compatibility with anchors minted before version 1.0:

```
fingerprint_legacy = SHA256("{procedure_id}:{tenant_id}:{factor_a}:{factor_b}:{factor_c}:{timestamp_ms}").hex()[:12]
```

The legacy formula differs from the canonical formula in two ways: (1) the `WITNESS:` domain separation prefix is absent, and (2) the `procedure_id` and `tenant_id` fields are in reversed order.

When verifying an anchor, implementations MUST attempt the canonical formula first. If verification fails, implementations MUST attempt the legacy formula before reporting a verification failure.

When minting new anchors, implementations MUST use the canonical formula exclusively.

### 7.5 Determinism

The fingerprint algorithm is fully deterministic. Given identical inputs, any conforming implementation in any programming language MUST produce an identical fingerprint. This property is verified by the test vectors in Section 18.

---

## 8. Factor Schema

*This section is normative.*

### 8.1 Structure

Every witness anchor contains exactly three factors:

| Factor | Field Name | Type | Description |
|--------|-----------|------|-------------|
| A | `factor_a` | Integer | First measurement dimension |
| B | `factor_b` | Integer | Second measurement dimension |
| C | `factor_c` | Integer | Third measurement dimension (context, delta, or method code) |

### 8.2 Semantics

Factor semantics are procedure-specific. This specification defines the factor structure but does not prescribe procedure-level semantics. Procedure-specific factor definitions are maintained in the UCT Registry (Section 15).

The following common evaluation patterns are observed across procedures:

**Pattern 1: Threshold Comparison**
- `factor_a` = required/expected value
- `factor_b` = measured/observed value
- `factor_c` = additional context (delta, method code, or boolean flag)
- Typical verdict rule: `factor_b >= factor_a` implies PASS

**Pattern 2: Presence/Verification**
- `factor_a` = count of items (e.g., adapters, chunks, guardrails)
- `factor_b` = verification status (1 = verified, 0 = not verified)
- `factor_c` = method or context code
- Typical verdict rule: `factor_b >= 1` implies PASS

**Pattern 3: Inverse Threshold**
- `factor_a` = maximum allowed value (e.g., latency threshold)
- `factor_b` = observed value
- `factor_c` = context
- Typical verdict rule: `factor_b <= factor_a` implies PASS

### 8.3 Constraints

- All factors MUST be integers. Floating-point values MUST be scaled to integers before anchoring (e.g., a relevance score of 0.82 is encoded as `820` with a documented scale factor of 1000).
- Negative integers are permitted.
- There is no upper bound on factor values.
- A factor value of `0` is semantically valid and distinct from absent.

---

## 9. Clearing Protocol

*This section is normative.*

### 9.1 Clearing Levels

The clearing protocol defines four levels of information density control. Higher levels progressively remove metadata from the witness payload before transmission.

| Level | Name | Description |
|-------|------|-------------|
| 0 | Analytics | All metadata retained. Full forensic capability. |
| 1 | Standard | Raw evidence purged after factor extraction. Hashes, model identity, and context retained. **Default level.** |
| 2 | Sensitive | Hashes and model identity retained. All contextual metadata removed. |
| 3 | Classified | Factors only. Model identity hashed. All other metadata destroyed. |

### 9.2 Field Survival Matrix

The following table specifies which payload fields survive each clearing level. "Y" = retained, "N" = destroyed before transmission.

| Field | Level 0 | Level 1 | Level 2 | Level 3 |
|-------|---------|---------|---------|---------|
| `procedure_id` | Y | Y | Y | Y |
| `factor_a`, `factor_b`, `factor_c` | Y | Y | Y | Y |
| `clearing_level` | Y | Y | Y | Y |
| `anchor_fingerprint` | Y | Y | Y | Y |
| `anchor_epoch` | Y | Y | Y | Y |
| `fingerprint_timestamp_ms` | Y | Y | Y | Y |
| `ai_prompt_hash` | Y | Y | Y | N |
| `ai_response_hash` | Y | Y | Y | N |
| `ai_system_prompt_hash` | Y | Y | Y | N |
| `ai_model_id` | Y | Y | Y | N (hashed) |
| `ai_latency_ms` | Y | Y | N | N |
| `ai_input_tokens` | Y | Y | N | N |
| `ai_output_tokens` | Y | Y | N | N |
| `ai_context` | Y | Y | N | N |
| `payload_signature` | Y | Y | Y | Y |
| `signing_key_id` | Y | Y | Y | Y |
| `jurisdiction` | Y | Y | Y | Y |
| `legal_basis` | Y | Y | Y | Y |
| `purpose_class` | Y | Y | Y | Y |
| `agent_id` | Y | Y | Y | Y |
| `cycle_id` | Y | Y | Y | Y |
| `lifecycle_chain_id` | Y | Y | Y | Y |
| `lifecycle_stage` | Y | Y | Y | Y |

### 9.3 CJT Field Guarantee

The following Compliance Jurisdiction and Traceability (CJT) fields MUST survive all clearing levels (0 through 3):

- `jurisdiction` (ISO 3166-1 alpha-2 country code)
- `legal_basis` (e.g., GDPR legal basis reference)
- `purpose_class` (processing purpose classification)
- `agent_id` (AI agent identity string)
- `cycle_id` (multi-agent interaction chain link)

Implementations MUST NOT clear CJT fields regardless of clearing level. These fields are required for regulatory traceability across jurisdictions.

### 9.4 Hash Formulas

When hashing prompt, response, or system prompt content for inclusion in the witness payload:

```
hash = SHA256(text).hex()[:16]
```

The hash MUST be the first 16 characters of the lowercase hexadecimal SHA-256 digest of the UTF-8 encoded text.

When hashing `ai_model_id` at clearing level 3:

```
hashed_model_id = SHA256(ai_model_id).hex()[:16]
```

### 9.5 Irreversibility

Clearing is irreversible. Once metadata is destroyed at the source, it cannot be recovered, reconstructed, or reverse-engineered from the remaining fields. This property is by design and provides a sovereignty guarantee: raw evidence (prompts, responses, operational data) never leaves the developer's infrastructure at clearing level 1 or above.

---

## 10. Signing Protocol

*This section is normative.*

### 10.1 HMAC-SHA256 (Default)

The default signing algorithm is HMAC-SHA256 (per RFC 2104).

**Without agent identity binding:**

```
signature = HMAC-SHA256(signing_key, anchor_fingerprint)
```

**With agent identity binding:**

```
signature = HMAC-SHA256(signing_key, anchor_fingerprint + ":" + agent_id)
```

Where `+` denotes string concatenation and `":"` is the literal colon character (U+003A).

The `signing_key` is a shared secret known to the minting party. It MUST NOT be transmitted in the witness payload.

The `signing_key_id` field in the payload identifies which key was used, enabling key rotation without invalidating existing anchors.

### 10.2 ML-DSA-65 (Post-Quantum)

Implementations MAY support ML-DSA-65 (FIPS 204) as an alternative signing algorithm for post-quantum resistance.

- Algorithm identifier: `ml-dsa-65`
- Key derivation: Deterministic from a 32-byte seed
- Public key size: 1952 bytes (3904 hexadecimal characters)
- Signatures are non-deterministic (randomized per FIPS 204)

When `signing_algorithm` is `ml-dsa-65`:

```
signature = ML-DSA-65-Sign(private_key, message)
```

Where `message` follows the same construction rules as HMAC-SHA256 (fingerprint alone, or fingerprint:agent_id).

Verification is performed using the public key derived from the same seed:

```
valid = ML-DSA-65-Verify(public_key, message, signature)
```

Because ML-DSA-65 signatures are non-deterministic, cross-implementation parity is verified by round-trip testing (sign with implementation A, verify with implementation B) rather than exact signature comparison.

### 10.3 Profile Signing

Model trust profiles MUST be signed using the following canonical message format:

```
message = "PROFILE:{model_id}:{model_hash}:{generated_at}:{valid_until}:{sorted_procedures}:{coverage_score_3dp}"
```

Where:
- `sorted_procedures` is a comma-separated list of procedure IDs sorted lexicographically
- `coverage_score_3dp` is the coverage score rounded to 3 decimal places (e.g., `0.667`)

### 10.4 Key Management

- Signing keys MUST be stored securely and MUST NOT appear in witness payloads, logs, or error messages.
- Key rotation SHOULD be performed periodically. The `signing_key_id` and `signing_key_version` fields enable rotation without invalidating existing anchors.
- Implementations SHOULD support at least two concurrent active keys during rotation periods.

---

## 11. Verification Algorithm

*This section is normative.*

### 11.1 Single Anchor Verification

To verify a single witness anchor:

1. Obtain the anchor's claimed fingerprint (the last segment of the anchor token).
2. Obtain the original input components: `tenant_id`, `procedure_id`, `factor_a`, `factor_b`, `factor_c`, `fingerprint_timestamp_ms`.
3. Compute the fingerprint using the canonical formula (Section 7.1).
4. If the computed fingerprint matches the claimed fingerprint, the anchor is **VERIFIED**.
5. If not, compute the fingerprint using the legacy formula (Section 7.4).
6. If the legacy-computed fingerprint matches, the anchor is **VERIFIED (legacy)**.
7. If neither formula produces a match, the anchor is **TAMPERED**.

No API access, platform account, or proprietary tooling is required for verification. Any party with knowledge of the input components can perform verification using standard SHA-256.

### 11.2 Enclave Integrity Verification

To verify the integrity of an entire enclave (collection of anchors):

1. Collect all anchor fingerprints in the enclave.
2. Sort the fingerprints lexicographically (ascending).
3. Join the sorted fingerprints with colon separators: `"fp1:fp2:fp3:..."`.
4. Compute `SHA256(joined_string).hex()` (full 64-character hexadecimal digest).
5. The result is the enclave integrity signature.

The enclave integrity signature has the following property: identical anchors in an identical state always produce an identical signature. Any addition, removal, or modification of any anchor changes the signature.

### 11.3 Signature Verification

If the witness payload includes a `payload_signature`:

1. Determine the signing algorithm from the `signing_algorithm` field (default: `hmac-sha256`).
2. Construct the message: `anchor_fingerprint` (or `anchor_fingerprint:agent_id` if `agent_id` is present).
3. Verify the signature using the appropriate algorithm and the signing key identified by `signing_key_id`.
4. If verification succeeds, the anchor's provenance is **AUTHENTICATED**.
5. If verification fails, the anchor's provenance is **UNAUTHENTICATED**.

Signature verification is independent of fingerprint verification. An anchor can be VERIFIED (fingerprint matches) but UNAUTHENTICATED (signature does not match), or vice versa.

---

## 12. Witness Payload Schema

*This section is normative.*

### 12.1 Required Fields

The following fields MUST be present in every witness payload:

| Field | Type | Description |
|-------|------|-------------|
| `procedure_id` | String | UCT procedure identifier (e.g., `AI-INF.1`) |
| `factor_a` | Integer | First factor |
| `factor_b` | Integer | Second factor |
| `factor_c` | Integer | Third factor |
| `clearing_level` | Integer | 0, 1, 2, or 3 |
| `anchor_fingerprint` | String(12) | Computed fingerprint (Section 7) |
| `anchor_epoch` | Integer | Unix epoch in seconds |
| `fingerprint_timestamp_ms` | Integer | Millisecond timestamp used in fingerprint computation |

### 12.2 Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `ai_model_id` | String | Model identifier (e.g., `gpt-4o`) |
| `ai_prompt_hash` | String(16) | SHA-256[:16] of the prompt text |
| `ai_response_hash` | String(16) | SHA-256[:16] of the response text |
| `ai_system_prompt_hash` | String(16) | SHA-256[:16] of the system prompt |
| `ai_latency_ms` | Integer | Inference latency in milliseconds |
| `ai_input_tokens` | Integer | Input token count |
| `ai_output_tokens` | Integer | Output token count |
| `ai_context` | String | Freeform context (cleared at level 2+) |
| `agent_id` | String | AI agent identity |
| `cycle_id` | String | Multi-agent interaction chain identifier |
| `payload_signature` | String(64) | HMAC-SHA256 signature (hex) |
| `signing_algorithm` | String | `hmac-sha256` (default) or `ml-dsa-65` |
| `signing_key_id` | String | Key identifier for rotation support |
| `signing_key_version` | Integer | Key version number |
| `policy_version_hash` | String | Hash of the governance policy version |
| `jurisdiction` | String | ISO 3166-1 alpha-2 country code |
| `legal_basis` | String | Legal processing basis (e.g., `Art. 6(1)(f)`) |
| `purpose_class` | String | Processing purpose classification |
| `authorization_id` | String | Pre-inference gate authorization identifier |
| `references` | Array | Related anchor fingerprints |
| `revocation_target` | String | Fingerprint of the anchor being revoked |
| `revocation_reason` | Integer | Revocation reason code (0-6) |
| `lifecycle_chain_id` | String | Lifecycle chain identifier (Section 13) |
| `lifecycle_parent` | String | Parent anchor fingerprint in the chain |
| `lifecycle_stage` | String | Current lifecycle stage |
| `escalation_chain_id` | String | Cross-chain escalation link |

### 12.3 Revocation Reason Codes

| Code | Meaning |
|------|---------|
| 0 | unspecified |
| 1 | model_recall |
| 2 | policy_violation |
| 3 | data_contamination |
| 4 | consent_withdrawal |
| 5 | regulatory_order |
| 6 | error_correction |

### 12.4 Validation Rules

- `procedure_id` MUST be a valid UCT procedure identifier.
- `clearing_level` MUST be an integer in the range [0, 3].
- `anchor_fingerprint` MUST be exactly 12 lowercase hexadecimal characters.
- `anchor_epoch` MUST be a positive integer.
- `fingerprint_timestamp_ms` MUST be a positive integer.
- `lifecycle_chain_id`, if present, MUST match the pattern `^LC-[0-9a-f]{16}$`.

---

## 13. Lifecycle Chains

*This section is normative.*

### 13.1 Chain Identifier Formula

A lifecycle chain identifier links multiple witness anchors into a single operational sequence. The chain ID is computed as:

```
chain_id = "LC-" + SHA256("LIFECYCLE:{tenant_id}:{procedure_id}:{initiator_fingerprint}:{timestamp_ms}").hex()[:16]
```

Where:
- `tenant_id` is the tenant that initiates the chain
- `procedure_id` is the procedure of the initiating anchor
- `initiator_fingerprint` is the fingerprint of the first anchor in the chain
- `timestamp_ms` is the millisecond timestamp of the initiating anchor

The chain ID is a fixed-length string: the literal prefix `LC-` followed by 16 lowercase hexadecimal characters.

### 13.2 Lifecycle Stages

The following canonical stage codes are defined:

| Stage | Code | Terminal |
|-------|------|----------|
| `initiated` | 0 | No |
| `checkpoint` | 1 | No |
| `escalated` | 2 | No |
| `resolved` | 3 | Yes |
| `abandoned` | 4 | Yes |
| `superseded` | 5 | Yes |

- The first anchor in a lifecycle chain MUST have `lifecycle_stage` set to `initiated`.
- Subsequent anchors in the chain MUST reference the `lifecycle_chain_id` of the initiating anchor.
- The `lifecycle_parent` field SHOULD contain the fingerprint of the immediately preceding anchor in the chain.
- A chain is considered closed when any anchor in the chain has a terminal stage.
- No further non-terminal anchors SHOULD be minted for a closed chain.

### 13.3 Cross-Chain Escalation

When an event in one lifecycle chain triggers a new chain (e.g., a drift detection escalates to an emergency override), the new chain's initiating anchor SHOULD include the `escalation_chain_id` field referencing the originating chain.

---

## 14. Provider-Deployer Evidence Chains

*This section is normative.*

### 14.1 Problem Statement

Organizations that provide AI models to third parties (whether through open-weight distribution, API access, cloud platform hosting, or embedded integration) face a common challenge: demonstrating that downstream deployers are operating the model with appropriate controls, without accessing the deployer's infrastructure or proprietary data.

### 14.2 Delegation Anchors

A model provider MAY mint delegation anchors (procedure AI-DEL.1) to formally record the relationship between the provider's tenant and one or more deployer tenants.

The delegation anchor encodes:
- `factor_a`: Number of deployer tenants in the delegation scope
- `factor_b`: Number of required procedures in the delegation policy
- `factor_c`: Delegation type code (0 = open-weight, 1 = API, 2 = cloud platform, 3 = embedded)

### 14.3 Deployer Attestation Flow

1. The deployer integrates the SWT3 SDK and witnesses operations under their own tenant identity.
2. Anchors flow to the deployer's own tenant, maintaining tenant isolation.
3. The provider queries aggregated coverage metrics across deployer tenants via the platform API.
4. The provider sees anchor fingerprints, procedure coverage percentages, verdict distributions, and clearing levels. The provider never sees raw deployer data.

### 14.4 Evidence Aggregation Without Data Access

The evidence aggregation model preserves deployer sovereignty:

- Providers see: procedure coverage percentage, verdict distribution (PASS/FAIL counts), clearing level distribution, anchor count, most recent anchor timestamp.
- Providers do not see: raw factors, prompt/response hashes, model identifiers, agent identifiers, contextual metadata, or any field subject to clearing.
- Deployers control: their own clearing level, which procedures they witness, and whether they participate in provider-aggregated reporting.

### 14.5 Cross-Provider Interoperability

A deployer building applications on models from multiple providers uses a single SWT3 integration. The same anchors, minted under the deployer's tenant, can be referenced by any provider with an established delegation relationship. This eliminates the need for deployers to maintain separate compliance systems per provider.

### 14.6 Distribution Model Neutrality

The delegation mechanism is identical regardless of how the model reaches the deployer:

| Distribution Model | Example | Delegation Type Code |
|---|---|---|
| Open-weight | Model weights distributed for local deployment | 0 |
| API access | Model served via inference API | 1 |
| Cloud platform | Model hosted on provider's cloud infrastructure | 2 |
| Embedded | Model integrated into provider's application | 3 |

---

## 15. Universal Control Taxonomy

*This section is informative.*

### 15.1 Overview

The Universal Control Taxonomy (UCT) defines the namespace for all valid procedure identifiers. As of version 1.0, the taxonomy contains 113 AI-specific procedures organized across 61 namespaces.

### 15.2 Namespace Registry

Procedure identifiers follow the format `AI-{NAMESPACE}.{NUMBER}` for AI-specific procedures. The following namespaces are defined:

INF, MDL, GRD, SEC, RAG, SKILL, TOOL, ID, ACC, REV, FAIR, DATA, HITL, EXPL, CHAIN, VIO, CHR, SAFE, HW, TRUST, FIN, GOV, ENV, MARK, BASE, LIC, SBOM, REDTEAM, CONSENT, MULTI, DRIFT, AUDIT, INCIDENT, PMM, PERF, ROBUST, CYBER, TRANS, WATERMARK, DPIA, AUTO, DUALUSE, SUPPLY, METAGOV, DEL, CAP, COST, JUR, LCM, LOG, IMPACT, MOB, EMRG, ASSESS, ENG, REACH, DECOM, RECOMM, FREEZE

Non-AI procedures use domain-specific prefixes (e.g., `SC-7.6` for network security, `AC-2.1` for access control).

### 15.3 Namespace Governance

Published namespace codes are never removed, renamed, or redefined. New namespace codes require demonstrated need across two or more regulatory frameworks. The UCT Registry is the authoritative source for all procedure definitions and is publicly available.

### 15.4 Framework Crosswalks

Each procedure in the UCT Registry is mapped to one or more regulatory framework requirements through bidirectional crosswalks. As of version 1.0, crosswalks are maintained for 36 regulatory frameworks across 12 jurisdictions.

---

## 16. Conformity Requirements

*This section is normative.*

### 16.1 Conformance Levels

This specification defines three conformance levels:

**Level 1: Minimal**

An implementation at Level 1 MUST:
- Compute fingerprints using the canonical formula (Section 7.1)
- Support verification against both canonical and legacy formulas (Section 7.4)
- Implement HMAC-SHA256 signing (Section 10.1)
- Support all four clearing levels (Section 9.1)
- Preserve CJT fields at all clearing levels (Section 9.3)
- Pass all fingerprint, signing, and hash test vectors (Section 18)

**Level 2: Standard**

An implementation at Level 2 MUST satisfy all Level 1 requirements and additionally:
- Support lifecycle chain identifiers (Section 13)
- Support CJT fields (jurisdiction, legal_basis, purpose_class)
- Support revocation anchors (procedure AI-REV.1, revocation reason codes per Section 12.3)
- Support the full witness payload schema (Section 12)

**Level 3: Full**

An implementation at Level 3 MUST satisfy all Level 2 requirements and additionally:
- Support ML-DSA-65 signing (Section 10.2)
- Support profile signing (Section 10.3)
- Support provider-deployer delegation anchors (Section 14)
- Support lifecycle chain test vectors (Section 18)

### 16.2 Conformity Statement

An implementation conforms to this specification at a given level if and only if it satisfies all MUST-level requirements for that level and all levels below it. Conformance is independently verifiable via the test vectors in Section 18.

### 16.3 Partial Conformance

An implementation that satisfies some but not all requirements of a given level MUST NOT claim conformance at that level. It MAY claim conformance at the highest level for which all requirements are satisfied.

---

## 17. Security Considerations

*This section is informative.*

### 17.1 Fingerprint Properties

Fingerprints are 12 hexadecimal characters (48 bits of entropy from the SHA-256 output). This truncation is intentional: fingerprints serve as evidence identifiers, not as security tokens. The full SHA-256 digest is not needed because:

- Fingerprints are not secrets. They appear in anchor tokens, payloads, and verification interfaces.
- Collision resistance at 48 bits is sufficient for evidence identification within a single tenant's anchor population.
- The full SHA-256 is recoverable by any party with knowledge of the inputs.

### 17.2 Signing Key Security

- HMAC-SHA256 signing keys provide payload authentication but not non-repudiation. A party with the signing key can mint anchors indistinguishable from the original.
- ML-DSA-65 keys provide both authentication and non-repudiation.
- Ed25519 keys used for W3C Verifiable Credential signing are higher sensitivity than HMAC keys. Compromise of an Ed25519 private key enables universal forgery of verifiable credentials that will pass any external verifier.

### 17.3 Clearing as Privacy Mechanism

Clearing levels provide information density control, not encryption. Clearing at level 1+ ensures that raw prompts, responses, and operational data never leave the developer's infrastructure. However, the metadata that does survive (hashes, factors, model identifiers at levels 0-2) could be correlated with external data sources by a sufficiently motivated adversary.

Organizations processing highly sensitive data SHOULD use clearing level 2 or 3.

### 17.4 Domain Separation

The `WITNESS:` prefix in the fingerprint formula provides domain separation, preventing cross-protocol collision. The following domain separation prefixes are reserved by this specification:

- `WITNESS:` -- Fingerprint computation
- `LIFECYCLE:` -- Lifecycle chain ID computation
- `PROFILE:` -- Model trust profile signing
- `SWT3:LEAF:` -- Merkle tree leaf hashing
- `SWT3:NODE:` -- Merkle tree node hashing

Implementations MUST NOT use these prefixes for other purposes.

---

## 18. Test Vectors

*This section is normative.*

All conforming implementations MUST produce identical outputs for the following test vectors. The complete test vector suite is available at `test-vectors.json` in the reference implementation repository.

### 18.1 Fingerprint Vectors

Formula: `SHA256("WITNESS:{tenant}:{proc}:{fa}:{fb}:{fc}:{ts_ms}").hex()[:12]`

| ID | Tenant | Procedure | fa | fb | fc | Timestamp (ms) | Expected |
|----|--------|-----------|----|----|----|----|----------|
| 1 | ENCLAVE_PROD | AI-INF.1 | 1 | 1 | 0 | 1774800000000 | `2e16e2fe92dd` |
| 2 | AWS_NITRO_ENCLAVE | AI-INF.2 | 5000 | 8000 | 1 | 1774800001000 | `4ed784765e6c` |
| 3 | ENCLAVE_PROD | AI-GRD.1 | 2 | 3 | 0 | 1774800002000 | `a0aa7669ae6f` |
| 4 | AZURE_TRUSTED_EXEC | AI-MDL.1 | 1 | 0 | 1 | 1774800003000 | `c36d477b3c2d` |
| 5 | ACME_DEFENSE | AI-FAIR.1 | 15 | 15 | 0 | 1774800004000 | `53180f5ae221` |
| 6 | SAAS_TENANT_42 | AI-MDL.2 | 1 | 1 | 0 | 1774800005000 | `c7e61c16ee94` |
| 7 | AWS_NITRO_ENCLAVE | AI-EXPL.2 | 85 | 92 | 0 | 1774800006000 | `2f2b989bb5c6` |
| 8 | ENCLAVE_PROD | AI-HITL.1 | 1 | 1 | 0 | 1774800007000 | `afbab8c9e098` |
| 9 | DEMO_ENCLAVE | AI-INF.3 | 10000 | 9500 | 0 | 1774800008000 | `05010820e5a4` |
| 10 | AZURE_TRUSTED_EXEC | AI-DATA.1 | 0 | 0 | 0 | 1774800009000 | `289eb7452237` |

The complete test vector suite contains 55 fingerprint vectors covering edge cases (all-zero factors, large values, multiple tenant types, all clearing levels). See `test-vectors.json` for the full set.

### 18.2 Signing Vectors

Algorithm: HMAC-SHA256. Key: `test-signing-key`

| ID | Fingerprint | Agent ID | Expected Signature |
|----|-------------|----------|--------------------|
| 1 | `019eaf85fcba` | `agent-007` | `00ff82da1659e2e6a7fa875c781ed4635976c8136b8dc2c24672adb8673cb112` |
| 2 | `019eaf85fcba` | *(none)* | `d844102f40fb5dad449a2f57922f5b23f73ffb3a026b5bd5fd537ebe5c6c44d0` |

Vector 1 message: `019eaf85fcba:agent-007`
Vector 2 message: `019eaf85fcba`

### 18.3 Hash Vectors

Formula: `SHA256(input).hex()[:16]`

| Input | Expected |
|-------|----------|
| `Hello, world!` | `315f5bdb76d078c4` |
| *(empty string)* | `e3b0c44298fc1c14` |
| `What is the meaning of life?` | `318f903a83b4d30d` |
| `gpt-4o-2024-11-20:fp_abc123` | `0f6b04241d237297` |
| `You are a helpful fraud detection assistant. Flag any transaction over $10,000.` | `479eaa1ee804f844` |

### 18.4 Profile Signing Vectors

| Model | Hash | Procedures | Score | Generated At | Valid Until | Expected Message |
|-------|------|-----------|-------|-------------|------------|-----------------|
| `gpt-4o` | `abc123` | AI-GRD.1, AI-INF.1, AI-MDL.1 | 0.667 | 1700000000000 | 1700086400000 | `PROFILE:gpt-4o:abc123:1700000000000:1700086400000:AI-GRD.1,AI-INF.1,AI-MDL.1:0.667` |

Signing key: `test-key-123`
Expected HMAC-SHA256: `bdce7111c3a6e9968a5de1973f3a977aadb42c2d7327f38de79729019c7baa42`

Note: Procedures in the message MUST be sorted lexicographically.

### 18.5 ML-DSA-65 Vectors

ML-DSA-65 signatures are non-deterministic. Conformance is verified by round-trip testing:

1. Generate a keypair from seed `60ef3bf0e31e764953cf67c6806d0c6512ce54a6e83a9328b7042b3896cf8f40` (32 bytes, hex).
2. The derived public key MUST be 1952 bytes (3904 hex characters).
3. Sign message `019eaf85fcba:agent-007`. The signature will differ on each invocation.
4. Verify the signature using the derived public key. Verification MUST succeed.
5. Sign message `019eaf85fcba` (without agent_id). Verification MUST succeed.
6. Verify that the public key derived from the same seed is identical across implementations.

### 18.6 Lifecycle Chain Vectors

Formula: `"LC-" + SHA256("LIFECYCLE:{tenant}:{proc}:{fp}:{ts_ms}").hex()[:16]`

| ID | Tenant | Procedure | Initiator FP | Timestamp (ms) | Expected Chain ID |
|----|--------|-----------|-------------|---------|-------------------|
| 1 | ENCLAVE_PROD | AI-EMRG.1 | 2e16e2fe92dd | 1774800000000 | `LC-7a38936db8ecec94` |
| 2 | ENCLAVE_PROD | AI-DRIFT.2 | 4ed784765e6c | 1774800001000 | `LC-60c720a257e2d3b9` |
| 3 | AWS_NITRO_ENCLAVE | AI-ASSESS.1 | 66209137510b | 1774800010000 | `LC-9caadba335ca64cd` |

---

## 19. Registry Considerations

*This section is informative.*

### 19.1 Reserved Prefixes

The following domain separation prefixes are reserved by this specification and MUST NOT be used by implementations for other purposes:

| Prefix | Usage | Section |
|--------|-------|---------|
| `WITNESS:` | Fingerprint computation | 7 |
| `LIFECYCLE:` | Lifecycle chain ID computation | 13 |
| `PROFILE:` | Profile signing messages | 10.3 |
| `SWT3:LEAF:` | Merkle tree leaf hashing | N/A (separate specification) |
| `SWT3:NODE:` | Merkle tree node hashing | N/A (separate specification) |

### 19.2 UCT Registry Governance

The UCT Registry is maintained as a public JSON document (`uct-registry.json`) in the reference implementation repository. Changes to the registry follow these rules:

- Published procedure identifiers are never removed, renamed, or redefined.
- New procedures require demonstrated need across two or more regulatory frameworks.
- New namespaces require review and approval through the governance process described in Section 4.
- Registry versions are tagged and immutable once published.

### 19.3 Provider Code Registration

Provider codes (Section 6.1) are not centrally registered. Implementations MAY use any uppercase alphanumeric string as a provider code. The following codes are in common use: `VULTR`, `AWS`, `AZURE`, `GCP`, `HYBRID`, `ON-PREM`.

---

## 20. Protocol Adoption Rationale

*This section is informative.*

This section describes the considerations that motivate adoption of an open, standardized witness protocol rather than proprietary alternatives.

**Assessor portability.** When multiple assessment bodies (Notified Bodies, C3PAOs, auditors) understand a common evidence format, conformity assessments are faster and less expensive. A proprietary evidence format requires each assessment body to learn and maintain custom verification tooling per provider.

**Deployer interoperability.** A deployer building applications on models from multiple providers needs one compliance system, not N proprietary formats. SWT3 is provider-neutral and distribution-model-neutral. A single SDK integration produces evidence that is valid across all provider relationships.

**Verification independence.** Any party can recompute a fingerprint using standard SHA-256 with no proprietary SDK, API access, or platform account. Verification requires only the input components and a conforming SHA-256 implementation, both of which are universally available.

**Cross-provider network effects.** Each new provider that adopts SWT3 reduces compliance cost for every deployer already using it, and each new deployer reduces the marginal cost of the next provider's adoption. This creates a positive-sum dynamic where early adoption yields compounding returns.

**Governance participation.** Organizations implementing and deploying SWT3 are positioned to participate in the governance of the protocol as it matures. Early adopters of open protocols shape the standards that follow.

Historical precedent supports this pattern. TLS (formerly SSL) began as a single-vendor protocol and became the universal transport security layer. SWIFT began as a cooperative of 239 banks and became the global financial messaging standard. XBRL began at a single accounting body and became the international standard for regulatory financial reporting. In each case, the protocol's value derived from its neutrality and universal adoption, not from any single vendor's implementation.

---

## 21. Reference Implementations

*This section is informative.*

Conforming reference implementations are available in seven programming languages. All implementations achieve 100% parity on the test vectors in Section 18.

| Language | Package | Registry |
|----------|---------|----------|
| Python | `swt3-ai` | PyPI |
| TypeScript | `@tenova/swt3-ai` | npm |
| Rust | `swt3-ai` | crates.io |
| C# | `swt3-ai` | NuGet |
| Ruby | `swt3-ai` | RubyGems |
| Swift | `swt3-ai` | Swift Package Index |
| Kotlin | `swt3-ai` | Maven Central |

A Model Context Protocol (MCP) server implementation is also available:

| Type | Package | Registry |
|------|---------|----------|
| MCP Server | `@tenova/swt3-mcp` | npm |

---

## 22. Bibliography

*This section is informative.*

The following documents are referenced informatively in this specification:

- **Regulation (EU) 2024/1689** -- Artificial Intelligence Act (European Parliament and Council, 2024)
- **NIST AI 100-1** -- Artificial Intelligence Risk Management Framework (NIST, 2023)
- **ISO/IEC 42001:2023** -- Artificial intelligence management system (ISO/IEC, 2023)
- **ISO/IEC 23894:2023** -- Guidance on AI risk management (ISO/IEC, 2023)
- **W3C Verifiable Credentials Data Model v2.0** -- (W3C, 2024)
- **NIST SP 800-53 Rev. 5** -- Security and Privacy Controls for Information Systems and Organizations (NIST, 2020)
- **CMMC Model 2.0** -- Cybersecurity Maturity Model Certification (DoD, 2021)

---

## 23. Auditor Display Requirements

*This section is normative.*

This section defines minimum display requirements for tools that render SWT3 Witness Anchors to human assessors. Compliance with this section is OPTIONAL for implementations that do not render anchors to humans (e.g., machine-to-machine pipelines). Compliance is REQUIRED for any tool that claims "SWT3 Verified Display" conformity.

When multiple tools present SWT3 anchors in different formats, assessors must learn each tool's layout before they can evaluate evidence. This increases assessment time and cost, and introduces the risk that a non-standard display obscures critical information (e.g., a truncated fingerprint that cannot be independently verified, or a missing timestamp that prevents timeline reconstruction). A uniform display standard ensures that assessors who learn to read SWT3 evidence in one tool can immediately read it in any other, reducing assessment friction and increasing confidence in the evidence chain. This is the same principle that drives standardized formats in financial messaging (SWIFT MT), transport security indicators (TLS certificate displays), and regulatory filings (XBRL).

### 23.1 Anchor Decomposition Display

When rendering a single witness anchor to a human assessor, a conforming display MUST present the following fields, in this order:

| # | Field | Display Label | Format | Requirement |
|---|-------|--------------|--------|-------------|
| 1 | Full anchor token | "Witness Anchor" | Monospace, untruncated | MUST |
| 2 | Protocol identifier | "Protocol" | Literal "SWT3" | MUST |
| 3 | Deployment tier | "Tier" | Full label: Enclave, SaaS, or Hybrid | MUST |
| 4 | Provider | "Provider" | Uppercase alphanumeric | MUST |
| 5 | UCT domain | "Domain" | Uppercase | MUST |
| 6 | Procedure ID | "Procedure" | Original punctuated form (e.g., AI-INF.1) | MUST |
| 7 | Verdict | "Verdict" | PASS or FAIL with semantic color per Section 23.2 | MUST |
| 8 | Timestamp | "Witnessed" | Per Section 23.5 | MUST |
| 9 | Fingerprint | "Fingerprint" | Per Section 23.3 | MUST |

Implementations SHOULD also display the following when available in the witness payload:

| Field | Display Label | Source |
|-------|--------------|--------|
| Factor values | "Evidence Factors" | factor_a, factor_b, factor_c from payload |
| Signing status | "Signature" | "Verified", "Unsigned", or "Invalid" |
| Clearing level | "Clearing Level" | Integer 0-3 with label (Analytics, Standard, Sensitive, Classified) |
| Merkle inclusion | "Merkle Proof" | "Available" or "Unavailable" |
| Lifecycle chain | "Chain ID" | lifecycle_chain_id if present |
| Agent identity | "Agent" | agent_id if present |

### 23.2 Verdict Color Semantics

Conforming displays MUST use the following semantic color mapping:

| Verdict | Required Color Family | HSL Hue Range | Reference Hex | Prohibited Colors |
|---------|----------------------|---------------|---------------|-------------------|
| PASS | Green | 100-160 | `#16a34a` | Red, amber, gray |
| FAIL | Red | 340-20 | `#dc2626` | Green, blue, gray |
| INHERITED | Blue | 190-230 | `#2563eb` | Red, green |

The exact shade within each family is implementation-defined. Implementations MUST NOT use identical colors for PASS and FAIL. Implementations MUST NOT render verdicts without visual differentiation.

For print media and accessibility: conforming displays MUST include a text indicator ("PASS"/"FAIL" label, checkmark/cross symbol, or equivalent) in addition to color. Color MUST NOT be the sole differentiator.

### 23.3 Fingerprint Display Rules

- Fingerprints MUST be rendered in a monospace typeface.
- Fingerprints MUST NOT be truncated; all 12 hexadecimal characters MUST be visible without user interaction.
- Fingerprints MUST be rendered in lowercase hexadecimal.
- Implementations SHOULD provide a copy-to-clipboard affordance.
- Implementations MUST NOT apply word-wrap, hyphenation, or line-breaking within a fingerprint string.

Example of a correctly rendered fingerprint: `2e16e2fe92dd`

### 23.4 Verification Affordance

A conforming display MUST include at least one of the following verification mechanisms:

(a) A hyperlink to a public verification endpoint where the assessor can independently recompute the fingerprint from its input components.

(b) An inline verification command using standard tools (e.g., a shell one-liner using SHA-256 utilities available on any POSIX system).

(c) An embedded client-side verification function that recomputes the fingerprint in the assessor's browser or local environment with no network requests required.

The verification affordance MUST NOT require the assessor to create an account, install proprietary software, pay a fee, or authenticate with any service. Verification independence is a core protocol guarantee (Section 11).

**Example inline verification command** (option b):

```
echo -n "WITNESS:my_tenant:AI-INF.1:1:0:2500:1774800000000" | sha256sum | cut -c1-12
# Expected output: 2e16e2fe92dd
```

This command uses only standard POSIX utilities. The assessor substitutes the tenant ID, procedure ID, factor values, and timestamp from the anchor's witness payload. If the output matches the anchor's fingerprint, the anchor is verified.

### 23.5 Timestamp Display

- Timestamps MUST be rendered in ISO 8601 format with an explicit UTC indicator (e.g., `2026-08-11T14:30:00Z`).
- Implementations MAY additionally show a relative time (e.g., "2 hours ago") but MUST NOT use relative time as the sole representation.
- Raw epoch integers MUST NOT be displayed without an accompanying human-readable conversion.

### 23.6 Tabular Display of Multiple Anchors

When rendering multiple anchors in a table or list view, the following column order is REQUIRED for the first four columns:

1. Procedure ID
2. Verdict (with semantic color per Section 23.2)
3. Witnessed (timestamp per Section 23.5)
4. Fingerprint (monospace per Section 23.3)

These four columns MUST NOT be reordered or omitted. Additional columns MAY be appended after column 4. Implementations SHOULD provide filtering by verdict (at minimum: ALL, PASS, FAIL). Implementations SHOULD provide sorting by timestamp.

### 23.7 Evidence Provenance Watermark

Evidence bundles carry a provenance tier indicating how the evidence was collected and verified. This is not a commercial designation; it describes the strength of the evidence chain. Displays that render evidence bundles SHOULD display the provenance tier when present in the bundle metadata:

| Provenance | Display Label | Meaning | Visual Treatment |
|------------|--------------|---------|-----------------|
| demo | "LOCAL ONLY" | Evidence generated offline, not transmitted to any verification service | Amber or warning background |
| connected | "CLOUD VERIFIED" | Evidence transmitted to and recorded by a verification service | Green or success background |
| sovereign | "HARDWARE ATTESTED" | Evidence cryptographically bound to a hardware root of trust | Gold or distinguished background |

When displayed, the provenance indicator SHOULD be visible without scrolling on initial render. Implementations MUST NOT misrepresent the provenance tier (e.g., displaying "HARDWARE ATTESTED" for evidence that was not hardware-attested).

### 23.8 Conformity Evidence Package Display

When rendering a Conformity Evidence Package (Section 24), a conforming display MUST present:

- Package metadata: generator name and version, generation timestamp, framework identifier, tenant name
- Anchor summary: total count, verdict distribution (PASS, FAIL, INHERITED counts), compliance rate
- Gate decision: PASS, FAIL, or CONDITIONAL with semantic color
- Merkle root and rollup date (if present), with proof verification status
- Package integrity: the packageHash value and its verification status (valid/invalid)
- Individual anchor decomposition per Section 23.1 for each anchor in the package

### 23.9 Extensibility

Conforming implementations MAY add fields, columns, visualizations, or interactive features beyond those specified in this section. Extensions MUST NOT alter the order, format, or semantics of required fields. Extensions MUST NOT replace required fields with alternative representations.

### 23.10 Conformity Statement

A display that satisfies all MUST-level requirements in this section MAY include the following conformity statement:

> Conforms to SWT3-SPEC Section 23 (Auditor Display Standard)

A display that does not satisfy all MUST-level requirements MUST NOT display this conformity statement or any variation that implies conformity with this section.

---

## 24. Conformity Evidence Package

*This section is normative.*

A Conformity Evidence Package (CEP) is a self-contained, portable JSON document containing all witness evidence required for a conformity or compliance assessment. Any tool MAY produce a CEP. Any assessor tool that can parse JSON can consume one. The CEP format enables interoperability between evidence producers (SDKs, platforms, agents) and evidence consumers (assessor tools, GRC platforms, regulatory portals).

### 24.1 Package Schema

A conforming CEP MUST contain the following top-level structure:

```json
{
  "_meta": { },
  "summary": { },
  "anchors": [ ],
  "merkle": null,
  "packageHash": ""
}
```

### 24.2 Metadata Object

The `_meta` object MUST contain the following fields:

| Field | Type | Description | Requirement |
|-------|------|-------------|-------------|
| format | string | Literal: `swt3-conformity-evidence-package` | MUST |
| version | string | Semantic version of this format (currently "1.0") | MUST |
| framework | string | Primary framework identifier (e.g., "NIST-800-53") | MUST |
| generatedAt | string | ISO 8601 UTC timestamp of package generation | MUST |
| generator | string | Name and version of the producing tool | MUST |
| tenantId | string | Tenant identifier | MUST |
| tenantName | string | Human-readable organization name | MUST |

Additional fields MAY be included in `_meta`. Consumers MUST ignore unrecognized fields.

### 24.3 Summary Object

The `summary` object MUST contain the following fields:

| Field | Type | Description | Requirement |
|-------|------|-------------|-------------|
| totalProcedures | integer | Total number of procedures assessed | MUST |
| passing | integer | Count of PASS verdicts | MUST |
| failing | integer | Count of FAIL verdicts | MUST |
| inherited | integer | Count of INHERITED verdicts | MUST |
| complianceRate | number | Percentage (0-100), passing / totalProcedures * 100 | MUST |
| gateDecision | string | "PASS", "FAIL", or "CONDITIONAL" | MUST |

### 24.4 Anchor Array

The `anchors` array MUST contain one object per witness anchor. Each anchor object MUST contain:

| Field | Type | Description | Requirement |
|-------|------|-------------|-------------|
| token | string | Full SWT3 anchor token string | MUST |
| procedureId | string | Procedure identifier (e.g., "AI-INF.1") | MUST |
| verdict | string | "PASS" or "FAIL" | MUST |
| epoch | integer | Unix epoch seconds | MUST |
| fingerprint | string | 12-character lowercase hex fingerprint | MUST |
| factorA | number | First evidence factor | MUST |
| factorB | number | Second evidence factor | MUST |
| factorC | number | Third evidence factor | MUST |

Each anchor object MAY also contain:

| Field | Type | Description |
|-------|------|-------------|
| clearingLevel | integer | 0-3 |
| signature | string | HMAC-SHA256 hex signature |
| agentId | string | Agent identity |
| chainId | string | Lifecycle chain identifier |
| jurisdictionCode | string | ISO 3166-1 jurisdiction |
| legalBasis | string | Lawful processing basis |

Anchors MUST be ordered by epoch ascending (oldest first). Consumers MUST NOT assume any other ordering.

### 24.5 Merkle Object

The `merkle` object contains Merkle rollup information. If no rollup data is available, the value MUST be `null`.

When present, the `merkle` object MUST contain:

| Field | Type | Description | Requirement |
|-------|------|-------------|-------------|
| root | string | SHA-256 Merkle root (hex) | MUST |
| rollupDate | string | ISO 8601 date (YYYY-MM-DD) of the rollup | MUST |
| anchorCount | integer | Number of anchors included in the rollup | MUST |
| algorithm | string | Literal: `SWT3-DOMAIN-SEPARATED-SHA256` | MUST |

The `merkle` object MAY also contain:

| Field | Type | Description |
|-------|------|-------------|
| tsaTimestamp | string | RFC 3161 TSA timestamp (ISO 8601) |
| tsaUrl | string | TSA service URL |
| proofAvailable | boolean | Whether inclusion proofs can be requested |

### 24.6 Package Integrity

The `packageHash` field MUST contain the SHA-256 hex digest of the canonical JSON serialization of the package with `packageHash` set to the empty string `""`. Canonical serialization is defined as: keys sorted lexicographically at all nesting levels, no whitespace outside quoted strings, UTF-8 encoding.

Consumers SHOULD verify `packageHash` before trusting package contents. A mismatched hash indicates the package has been modified after generation.

**Verification example** (using standard command-line tools):

```
# 1. Extract the package JSON and set packageHash to ""
cat package.json | jq '.packageHash = ""' | jq -S -c '.' > canonical.json

# 2. Compute SHA-256 of the canonical form
sha256sum canonical.json | cut -d' ' -f1

# 3. Compare output to the packageHash value in the original file
```

If the computed hash matches `packageHash`, the package has not been modified since generation.

### 24.7 Framework-Specific Extensions

Implementations MAY include a `frameworkExtensions` object at the top level containing framework-specific metadata (e.g., CMMC level, FedRAMP baseline, EU AI Act risk classification). The schema of `frameworkExtensions` is not defined by this specification. Consumers MUST ignore unrecognized extension fields.

### 24.8 Versioning

The `_meta.version` field follows semantic versioning. Minor version increments (e.g., 1.0 to 1.1) add optional fields only. Major version increments (e.g., 1.0 to 2.0) may change required fields or remove existing fields. Consumers SHOULD accept any package whose major version matches the consumer's supported major version.

### 24.9 Complete Example

*This subsection is informative.*

The following is a complete, minimal Conformity Evidence Package containing three anchors (PASS, FAIL, and INHERITED) with a Merkle rollup:

```json
{
  "_meta": {
    "format": "swt3-conformity-evidence-package",
    "version": "1.0",
    "framework": "NIST-800-53",
    "generatedAt": "2026-08-11T14:30:00Z",
    "generator": "axiom-sovereign-engine/5.42.0",
    "tenantId": "acme-defense-001",
    "tenantName": "ACME Defense Corp"
  },
  "summary": {
    "totalProcedures": 3,
    "passing": 1,
    "failing": 1,
    "inherited": 1,
    "complianceRate": 33.3,
    "gateDecision": "FAIL"
  },
  "anchors": [
    {
      "token": "SWT3-E-VULTR-AI-AIINF1-PASS-1774800000-2e16e2fe92dd",
      "procedureId": "AI-INF.1",
      "verdict": "PASS",
      "epoch": 1774800000,
      "fingerprint": "2e16e2fe92dd",
      "factorA": 1,
      "factorB": 0,
      "factorC": 2500
    },
    {
      "token": "SWT3-E-VULTR-AI-AIFAIR1-FAIL-1774800060-cb06b911a3c3",
      "procedureId": "AI-FAIR.1",
      "verdict": "FAIL",
      "epoch": 1774800060,
      "fingerprint": "cb06b911a3c3",
      "factorA": 0,
      "factorB": 3,
      "factorC": 0
    },
    {
      "token": "SWT3-E-VULTR-NET-SC76-PASS-1774800120-f0ed4dd73cc2",
      "procedureId": "SC-7.6",
      "verdict": "PASS",
      "epoch": 1774800120,
      "fingerprint": "f0ed4dd73cc2",
      "factorA": 1,
      "factorB": 0,
      "factorC": 443,
      "clearingLevel": 1,
      "signature": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    }
  ],
  "merkle": {
    "root": "c22dcec3e8aa9a684f1b2e3d4c5a6b7890abcdef1234567890abcdef12345678",
    "rollupDate": "2026-08-11",
    "anchorCount": 390,
    "algorithm": "SWT3-DOMAIN-SEPARATED-SHA256",
    "tsaTimestamp": "2026-08-12T00:01:05Z",
    "proofAvailable": true
  },
  "packageHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

### 24.10 Assessor Validation Walkthrough

*This subsection is informative.*

When an assessor receives a Conformity Evidence Package, the following three-step validation confirms the package has not been tampered with and the evidence is independently verifiable:

**Step 1: Verify package integrity.** Set `packageHash` to `""`, serialize the JSON canonically (keys sorted, no whitespace), and compute SHA-256. Compare the result to the original `packageHash`. If they match, the package has not been modified since generation.

**Step 2: Spot-check a fingerprint.** Select any anchor from the `anchors` array. Using the fingerprint formula from Section 7, recompute the fingerprint from the anchor's input components (tenant ID, procedure ID, factors, timestamp in milliseconds). If the recomputed fingerprint matches, the anchor is authentic.

```
echo -n "WITNESS:acme-defense-001:AI-INF.1:1:0:2500:1774800000000" | sha256sum | cut -c1-12
# Expected: 2e16e2fe92dd
```

**Step 3: Verify Merkle inclusion (if available).** If `merkle.proofAvailable` is `true`, request an inclusion proof for the spot-checked fingerprint from the verification service. Walk the proof from leaf to root using the domain-separated algorithm (Section 7). If the computed root matches `merkle.root`, the anchor was included in the daily rollup and has not been altered since the rollup was timestamped.

If all three steps pass, the assessor has independent, cryptographic assurance that the evidence package is authentic and unmodified.

---

*Copyright 2026 Tenable Nova LLC. Patent pending. SWT3 and Sovereign Witness Traceability are trademarks of Tenable Nova LLC.*

*This specification is provided for informational purposes and does not constitute legal, regulatory, or compliance advice. Consult qualified legal counsel before making compliance decisions based on this content.*
