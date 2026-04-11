# SWT3 Protocol Specification v1.0

## Sovereign Witness Traceability Protocol

**Status:** Draft Standard
**Version:** 1.2.0
**Date:** 2026-03-29
**Authors:** Tenable Nova LLC (DBA TeNova)
**License:** Apache 2.0

---

## 1. Abstract

SWT3 (Sovereign Witness Traceability) is an open protocol for cryptographically
anchoring evidence to immutable witness records while preserving data sovereignty.
The "3" in SWT3 represents the three phases of the evidence lifecycle:

1. **Provenance** — Evidence collection and factor capture at the point of observation.
   Raw telemetry is decomposed into a structured Factor Matrix and cryptographically
   bound to a sub-second hardware epoch, establishing an immutable record of what was
   observed, when, and under what conditions.

2. **Verification** — SHA-256 fingerprint computation binding factors to a self-describing,
   portable anchor token. Any party can independently re-derive the fingerprint from
   the original factors and confirm that evidence has not been altered — without network
   access, without database connectivity, and without trust in the issuing system.

3. **Clearing** — Controlled purging of raw evidence after anchoring, ensuring that
   sensitive telemetry (command outputs, configuration files, API responses, log entries)
   does not persist beyond its operational usefulness. The cryptographic proof survives;
   the underlying data does not. This achieves 100% integrity verification and 100%
   data sovereignty simultaneously — not as a tradeoff, but as complementary guarantees.

SWT3 enables any party — auditor, assessor, or automated system — to independently
verify that a piece of evidence has not been altered since the moment it was
witnessed, even after the raw source data has been cleared.

SWT3 does not prescribe how evidence is collected (Provenance). It defines how
evidence is **fingerprinted and anchored** (Verification), and how raw evidence
can be **sovereignly purged while preserving cryptographic proof** (Clearing).
This separation allows any evidence collection tool to produce SWT3-compatible
anchors, while any platform can consume and verify them without vendor lock-in.

## 2. Terminology

| Term | Definition |
|------|-----------|
| **Witness** | The act of observing a state and recording its factors at the point of origin |
| **Factor** | A measurable input to a determination (e.g., open port count, patch age, sensor reading) |
| **Factor Matrix** | The structured triple (factor_a, factor_b, factor_c) captured during Provenance |
| **Anchor** | A self-describing cryptographic receipt binding factors to a verdict at a specific point in time |
| **Fingerprint** | The truncated SHA-256 digest that seals the anchor |
| **Verdict** | The determination outcome: PASS, FAIL, INHERITED, LAPSED, or UNKNOWN |
| **Enclave** | A trust boundary within which anchors share a common verification chain |
| **Clearing** | The controlled purging of raw evidence after anchoring, preserving the cryptographic proof while destroying the source telemetry to maintain data sovereignty |
| **Administrative Trust** | The legacy trust model where data integrity depends on trusting the custodian (database admin, cloud provider, agency) rather than independent mathematical verification |

## 3. Anchor Format

An SWT3 anchor is a structured string token with the following format:

```
SWT3-{TIER}-{PROVIDER}-{UCT}-{PROCEDURE}-{VERDICT}-{EPOCH}-{FINGERPRINT}
```

### 3.1 Field Definitions

| Field | Width | Values | Description |
|-------|-------|--------|-------------|
| Protocol | 4 | `SWT3` | Fixed protocol identifier |
| Tier | 1 | `E`, `S`, `H` | Deployment tier: Enclave, SaaS, Hybrid |
| Provider | 2-6 | `VULTR`, `AWS`, `AZURE`, `GCP`, `HYBRID`, `ON-PREM` | Infrastructure provider |
| UCT | 2-3 | See Section 3.2 | Universal Control Taxonomy category (UCT Registry v1.0) |
| Procedure | 2-6 | e.g. `SC76`, `AC21` | Procedure identifier (alphanumeric, no hyphens) |
| Verdict | 4-9 | `PASS`, `FAIL`, `INHERITED`, `LAPSED`, `UNKNOWN` | Compliance determination |
| Epoch | 10 | Unix timestamp | Seconds since Unix epoch at witness time |
| Fingerprint | 12 | Hex string | First 12 characters of SHA-256 digest |

### 3.2 UCT Registry (v1.0)

The Universal Control Taxonomy (UCT) is a framework-agnostic classification
system that categorizes every witnessed control into a domain. UCT codes are
the bridge that allows SWT3 anchors to be meaningful across compliance
frameworks — a `CRY` anchor carries the same semantic meaning whether it
originated from a NIST SC-13 check, a PCI-DSS Requirement 4 assessment, or
a HIPAA §164.312(a)(2)(iv) encryption review.

The UCT Registry is **additive-only**: codes are never removed or redefined
once published. New codes may be added in future registry versions. Anchors
minted under any registry version remain valid under all subsequent versions.

#### 3.2.1 Core Codes

Core codes represent the fundamental security domains present in every major
compliance framework. All SWT3 implementations MUST recognize core codes.

| Code | Domain | Description |
|------|--------|-------------|
| `ACC` | Access Control | Authorization, privileges, least privilege, account management — who can get in and what they can do |
| `AUD` | Audit & Accountability | Logging, log retention, audit review, event correlation — proving who did what |
| `CFG` | Configuration Management | Baselines, hardening, change control, inventory — how systems are set |
| `CRY` | Cryptography | Encryption at rest, encryption in transit, key management, certificate lifecycle |
| `IDN` | Identity & Authentication | Authentication mechanisms, MFA, credential management — proving who you are |
| `INT` | System Integrity | Patching, file integrity monitoring, malware defense, code signing — tamper evidence |
| `NET` | Network Security | Firewalls, segmentation, boundary protection, traffic filtering — network boundaries |
| `BCP` | Business Continuity | Backup, disaster recovery, contingency planning, availability — surviving failure |
| `GOV` | Governance & Policy | Security policy, planning, system security plans, authorization — the policy layer |
| `IRP` | Incident Response | Detection, response, recovery, lessons learned — handling the breach |
| `PHY` | Physical Security | Facility access, media protection, environmental controls — the physical layer |

#### 3.2.2 Extended Codes

Extended codes represent specialized domains that apply in specific regulatory
contexts or industry verticals. Implementations SHOULD recognize extended codes
relevant to their compliance scope. Unrecognized extended codes MUST NOT cause
verification failure — the anchor remains valid; only the domain classification
is opaque to that implementation.

| Code | Domain | Description |
|------|--------|-------------|
| `ACQ` | Supply Chain & Acquisition | Vendor risk, third-party assessment, supply chain integrity |
| `AI`  | AI / ML Governance | Model integrity, algorithmic fairness, AI risk management (NIST AI RMF) |
| `CHG` | Change Management | Change approval, maintenance windows, controlled modification |
| `DEV` | Secure Development | SDLC, code review, application security testing |
| `EVI` | Evidence & Artifacts | Ingested proof artifacts, external evidence anchoring |
| `HRS` | Personnel Security | Screening, termination, role-based access tied to employment status |
| `MON` | Continuous Monitoring | Ongoing surveillance, posture dashboards, trend analysis (CA-7) |
| `OT`  | Operational Technology | ICS/SCADA, industrial control systems, NERC CIP |
| `PRI` | Privacy | PII protection, consent management, data subject rights (GDPR, HIPAA Privacy Rule) |
| `RSK` | Risk Management | Risk assessments, POA&Ms, risk acceptance, vulnerability prioritization |
| `TRN` | Training & Awareness | Security training, phishing exercises, role-based training requirements |
| `VUL` | Vulnerability Management | Scanning, patching cadence, CISA KEV, remediation tracking |

#### 3.2.3 NIST 800-53 Family Mapping

The following table defines the canonical mapping from NIST 800-53 control
families to UCT codes. This mapping is normative for NIST-derived frameworks
(FedRAMP, CMMC, 800-171, DoD RMF) and informative for all others.

| NIST Family | UCT Code | Notes |
|-------------|----------|-------|
| AC (Access Control) | `ACC` | |
| AU (Audit & Accountability) | `AUD` | |
| CM (Configuration Management) | `CFG` | |
| IA (Identification & Authentication) | `IDN` | |
| SC (System & Communications) | `NET` | Default for SC family |
| SC-8, SC-8.x (Transmission Confidentiality) | `CRY` | Encryption in transit |
| SC-13 (Cryptographic Protection) | `CRY` | Cryptographic mechanisms |
| SC-28, SC-28.x (Protection of Information at Rest) | `CRY` | Encryption at rest |
| SI (System & Information Integrity) | `INT` | Default for SI family |
| SI-2 (Flaw Remediation) | `VUL` | Patching and remediation |
| SI-5 (Security Alerts & Advisories) | `VUL` | Advisory monitoring |
| AT (Awareness & Training) | `TRN` | |
| CP (Contingency Planning) | `BCP` | |
| IR (Incident Response) | `IRP` | |
| MA (Maintenance) | `CHG` | |
| MP (Media Protection) | `PHY` | |
| PE (Physical & Environmental) | `PHY` | |
| PL (Planning) | `GOV` | |
| PS (Personnel Security) | `HRS` | |
| RA (Risk Assessment) | `RSK` | |
| SA (System & Services Acquisition) | `ACQ` | |
| CA (Assessment, Authorization & Monitoring) | `MON` | CA-7 specifically maps to MON |

#### 3.2.4 Cross-Framework Reference

UCT codes map consistently across major compliance frameworks:

| UCT | NIST 800-53 | SOC 2 (TSC) | HIPAA | PCI-DSS 4.0 | ISO 27001:2022 |
|-----|-------------|-------------|-------|-------------|----------------|
| `ACC` | AC | CC6.1, CC6.3 | §164.312(a)(1) | Req 7, 8 | A.5.15, A.8.3 |
| `AUD` | AU | CC7.2 | §164.312(b) | Req 10 | A.8.15 |
| `CFG` | CM | CC8.1 | §164.310(d)(2)(iii) | Req 2 | A.8.9 |
| `CRY` | SC-8, SC-13, SC-28 | CC6.1 (enc.) | §164.312(a)(2)(iv), §164.312(e)(2)(ii) | Req 3, 4 | A.8.24 |
| `IDN` | IA | CC6.1 (auth.) | §164.312(d) | Req 8 | A.8.5 |
| `INT` | SI | CC7.1 | §164.312(c)(1) | Req 5, 6, 11 | A.8.7 |
| `NET` | SC (network) | CC6.6 | §164.312(e)(1) | Req 1 | A.8.20, A.8.21 |
| `BCP` | CP | A1.2 | §164.308(a)(7) | Req 12.10.1 | A.5.29, A.5.30 |
| `GOV` | PL | CC1.1-CC1.5 | §164.308(a)(1) | Req 12 | A.5.1 |
| `IRP` | IR | CC7.3, CC7.4 | §164.308(a)(6) | Req 12.10 | A.5.24-A.5.28 |
| `PHY` | PE, MP | CC6.4 | §164.310(a), §164.310(d) | Req 9 | A.7.1-A.7.14 |

#### 3.2.5 Registry Governance

- **Maintainer:** Tenable Nova LLC (DBA TeNova)
- **Versioning:** UCT Registry follows semantic versioning independent of the SWT3 spec version
- **Additions:** New codes require (a) demonstrated need across two or more compliance frameworks, (b) clear semantic distinction from existing codes, and (c) a 3-letter uppercase alphabetic identifier
- **Immutability:** Published codes are never removed, renamed, or redefined
- **Deprecation:** A code may be marked DEPRECATED with a recommended successor, but MUST remain valid for parsing and verification indefinitely
- **Reserved codes:** `SWT`, `UCT`, `NIL`, `ERR`, `RAW`, `TBD` are reserved and MUST NOT be assigned
- **Legacy code — `POL`:** Pre-v1.0 implementations used `POL` (Policy) as a catch-all for governance, personnel, incident response, training, physical security, risk, and acquisition domains. Anchors minted with `POL` remain valid and MUST be accepted by all implementations. New anchors SHOULD use the specific code from the registry. Implementations MAY reclassify historical `POL` anchors using the procedure ID prefix and the NIST Family Mapping (Section 3.2.3).

### 3.3 Examples

```
SWT3-E-VULTR-NET-SC76-PASS-1773316622-96b7d56c0245
SWT3-S-AWS-ACC-AC21-FAIL-1773400000-a3f7c2e91b04
SWT3-H-AZURE-CFG-CM61-INHERITED-1773500000-d2620f999950
SWT3-E-ON-PREM-CRY-SC28-PASS-1773600000-b1a9c3d4e5f6
SWT3-S-AWS-IRP-IR41-PASS-1773700000-7f8e9d0c1b2a
SWT3-E-VULTR-VUL-SI21-FAIL-1773800000-4d5e6f7a8b9c
```

### 3.4 Parsing Rules

- Fields are separated by hyphens (`-`)
- The fingerprint is always the **last** segment
- The epoch is always the **second-to-last** segment
- Minimum 8 segments required for a valid anchor
- Protocol field MUST be `SWT3`

## 4. Fingerprint Algorithm

The fingerprint is the cryptographic core of SWT3. It binds the evidence factors
to the anchor in a deterministic, reproducible way.

### 4.1 Input Construction

The fingerprint input is a colon-separated string of exactly six fields:

```
{procedure_id}:{tenant_id}:{factor_a}:{factor_b}:{factor_c}:{timestamp_ms}
```

| Field | Type | Description |
|-------|------|-------------|
| `procedure_id` | string | The procedure identifier (e.g., `SC-7.6`) |
| `tenant_id` | string | The organization/tenant identifier |
| `factor_a` | integer | Baseline/threshold factor (string representation of decimal integer) |
| `factor_b` | integer | Measured/observed factor |
| `factor_c` | integer | Delta factor (typically `factor_b - factor_a`) |
| `timestamp_ms` | integer | Millisecond-precision Unix timestamp at witness time |

### 4.2 Hash Computation

```
fingerprint = SHA-256(input_string)[0:12]
```

1. Encode the input string as UTF-8 bytes
2. Compute the SHA-256 digest
3. Convert to lowercase hexadecimal
4. Truncate to the first **12 characters**

### 4.3 Determinism Guarantee

Given identical inputs, the fingerprint MUST always produce the identical output.
This property enables cross-platform verification: an anchor minted in Python
can be verified in TypeScript, Go, Rust, or any language with SHA-256 support.

### 4.4 Reference Computation

```
Input:  "SC-7.6:DEMO_ENCLAVE:4:3:-1:1773316622000"
SHA-256: 96b7d56c0245... (64 hex chars)
Fingerprint: 96b7d56c0245 (first 12 hex chars)
```

### 4.5 Why 12 Characters?

Twelve hexadecimal characters provide 48 bits of entropy (2^48 = ~281 trillion
combinations). This provides collision resistance sufficient for compliance
ledgers while keeping anchors human-readable and auditor-friendly. The full
64-character digest SHOULD be stored alongside the anchor for maximum
verification fidelity.

## 5. Witness Requirements

A valid SWT3 witness MUST satisfy all of the following:

### 5.1 Factor Integrity

All three factors (`factor_a`, `factor_b`, `factor_c`) MUST be recorded at the
moment of observation. Factors MUST be integer values. Implementations SHOULD
use signed 32-bit integers minimum.

### 5.2 Temporal Binding

The `timestamp_ms` MUST be captured at the moment of witnessing, not at a later
processing stage. Millisecond precision is REQUIRED. The `epoch` field in the
anchor token uses second precision (floor of `timestamp_ms / 1000`).

### 5.3 Clearing Protocol (Phase 3)

The Clearing phase is the third pillar of SWT3 and the mechanism by which data
sovereignty is achieved without sacrificing integrity.

After an anchor is minted and its fingerprint is sealed, the **raw evidence**
used during Provenance — command outputs, file contents, API responses, log
entries, sensor readings, and any other source telemetry — SHOULD be purged
from the witness system. Only the **Factor Matrix** (factor_a, factor_b,
factor_c), the **timestamp**, and the **anchor token** should persist.

The cryptographic proof survives the data. The fingerprint remains independently
verifiable even after the raw evidence that produced the factors has been
destroyed. This is the core insight of SWT3: **integrity does not require
data retention**.

#### 5.3.1 Clearing Levels

Implementations SHOULD support one or more of the following clearing levels:

| Level | Name | Behavior |
|-------|------|----------|
| 0 | **RETAIN** | Raw evidence retained alongside factors. Maximum forensic capability, maximum attack surface. |
| 1 | **FACTOR-ONLY** | Raw evidence purged after factor extraction. Factors and anchor persist. RECOMMENDED default. |
| 2 | **ANCHOR-ONLY** | Factors purged after fingerprint computation. Only the anchor token persists. Verification requires the verifier to have obtained factors through a separate channel. |
| 3 | **SOVEREIGN** | All local evidence destroyed after anchor is transmitted to the verifier. The minting system retains nothing. Maximum data sovereignty. |

The clearing level SHOULD be configurable per enclave or per sensitivity
classification. Implementations MUST document their clearing level in their
security posture.

#### 5.3.2 Clearing and Verification Compatibility

Clearing levels 0 and 1 support full self-contained verification (the verifier
has both the anchor and the factors). Clearing levels 2 and 3 require
out-of-band factor exchange — the factors must be transmitted to the verifier
before or at the time of clearing. This is appropriate for classified or
air-gapped environments where the minting system cannot retain any data.

#### 5.3.3 Irreversibility

Clearing MUST be irreversible. Once raw evidence is purged, it MUST NOT be
recoverable from the witness system. The purpose of clearing is to ensure
that sensitive telemetry cannot be exfiltrated, subpoenaed, or reverse-engineered
from the witness ledger. Implementations that offer a "soft delete" or
"recoverable purge" MUST NOT claim SWT3 Clearing compliance.

### 5.4 Non-Repudiation

Once an anchor is minted, the factors used to compute its fingerprint MUST be
immutable. Any system that stores anchors MUST prevent modification of:
- `factor_a`, `factor_b`, `factor_c`
- `fingerprint_timestamp_ms`
- `swt_token`

Modification of any of these fields will cause verification to return `TAMPERED`.

## 6. Verification

### 6.1 Single Anchor Verification

To verify an anchor, a verifier needs:
1. The SWT3 anchor token (to extract the claimed fingerprint)
2. The original factors: `procedure_id`, `tenant_id`, `factor_a`, `factor_b`, `factor_c`, `timestamp_ms`

**Algorithm:**
```
1. Extract claimed_fingerprint from anchor token (last segment)
2. Construct input: "{procedure_id}:{tenant_id}:{factor_a}:{factor_b}:{factor_c}:{timestamp_ms}"
3. Compute SHA-256 of UTF-8 encoded input
4. Truncate to 12 hex characters
5. Compare: recomputed == claimed_fingerprint
6. Return VERIFIED if match, TAMPERED if mismatch
```

### 6.2 Verification Results

| Status | Meaning |
|--------|---------|
| `CERTIFIED TRUTH` | Fingerprints match. Evidence integrity confirmed. |
| `TAMPERED` | Fingerprints do not match. Evidence or factors have been modified. |
| `INVALID TOKEN` | Anchor does not conform to SWT3 format. |
| `LEGACY ANCHOR` | Anchor predates timestamp-based fingerprinting. Cannot verify. |

### 6.3 Enclave Integrity Verification

An enclave is a collection of anchors sharing a trust boundary (typically a
single tenant or organization). Enclave integrity is computed as:

```
1. Collect all anchor fingerprints in the enclave
2. Sort fingerprints lexicographically
3. Join with colons: "fp1:fp2:fp3:..."
4. Compute SHA-256 of the joined string
5. The full 64-character hex digest is the Enclave Integrity Signature
```

**Property:** The same set of anchors in the same state always produces the same
signature. Any addition, removal, or modification of an anchor changes the
signature. This enables point-in-time integrity snapshots.

## 7. OSCAL Integration

SWT3 anchors are designed to embed naturally into NIST OSCAL (Open Security
Controls Assessment Language) documents.

### 7.1 Assessment Results Mapping

An SWT3 anchor maps to an OSCAL Assessment Result as follows:

```json
{
  "results": [{
    "uuid": "<generated>",
    "title": "SWT3 Automated Assessment",
    "start": "<witnessed_at ISO-8601>",
    "observations": [{
      "uuid": "<generated>",
      "title": "<procedure_id> Evidence Observation",
      "description": "Automated evidence collection for <procedure_id>",
      "methods": ["TEST"],
      "subjects": [{
        "subject-uuid": "<control-uuid>",
        "type": "component"
      }],
      "relevant-evidence": [{
        "description": "SWT3 Witness Anchor: <swt_token>",
        "links": [{
          "href": "#swt3-protocol",
          "rel": "evidence-source"
        }]
      }],
      "props": [
        { "name": "swt3-anchor", "value": "<full SWT3 token>" },
        { "name": "swt3-fingerprint", "value": "<12-char fingerprint>" },
        { "name": "swt3-factor-a", "value": "<factor_a>" },
        { "name": "swt3-factor-b", "value": "<factor_b>" },
        { "name": "swt3-factor-c", "value": "<factor_c>" },
        { "name": "swt3-timestamp-ms", "value": "<timestamp_ms>" }
      ]
    }],
    "findings": [{
      "uuid": "<generated>",
      "title": "<procedure_id> Finding",
      "target": {
        "type": "objective-id",
        "target-id": "<control-id>",
        "status": {
          "state": "<satisfied|not-satisfied>"
        }
      },
      "related-observations": [{
        "observation-uuid": "<observation-uuid-above>"
      }]
    }]
  }]
}
```

### 7.2 Back-Matter Reference

SWT3-enabled OSCAL documents SHOULD include a back-matter resource identifying
the protocol:

```json
{
  "back-matter": {
    "resources": [{
      "uuid": "<generated>",
      "title": "SWT3 Protocol Specification v1.0",
      "description": "Sovereign Witness Traceability Protocol for evidence integrity",
      "props": [
        { "name": "type", "value": "protocol-specification" },
        { "name": "version", "value": "1.0.0" }
      ],
      "rlinks": [{
        "href": "https://github.com/tenova-ai/libswt3/blob/main/SWT3-SPEC-v1.0.md"
      }]
    }]
  }
}
```

### 7.3 Verdict-to-OSCAL Status Mapping

| SWT3 Verdict | OSCAL Finding Status |
|-------------|---------------------|
| `PASS` | `satisfied` |
| `FAIL` | `not-satisfied` |
| `INHERITED` | `satisfied` (with prop `inheritance-source`) |
| `LAPSED` | `not-satisfied` (with prop `lapse-reason`) |
| `UNKNOWN` | `not-satisfied` (with prop `assessment-pending: true`) |

## 8. Transport

### 8.1 JSON Evidence Factor

The canonical transport format for SWT3 evidence is a JSON object:

```json
{
  "swt3_version": "1.0",
  "anchor": "SWT3-E-VULTR-NET-SC76-PASS-1773316622-96b7d56c0245",
  "factors": {
    "procedure_id": "SC-7.6",
    "tenant_id": "DEMO_ENCLAVE",
    "factor_a": 4,
    "factor_b": 3,
    "factor_c": -1,
    "timestamp_ms": 1773316622000
  },
  "verdict": "PASS",
  "witnessed_at": "2026-03-18T12:00:00Z",
  "metadata": {
    "source": "example-collector-v1.0",
    "check_type": "command",
    "control_family": "SC"
  }
}
```

### 8.2 Batch Transport

Multiple evidence factors MAY be transported as a JSON array:

```json
{
  "swt3_version": "1.0",
  "enclave_id": "DEMO_ENCLAVE",
  "anchors": [
    { "anchor": "SWT3-...", "factors": {...} },
    { "anchor": "SWT3-...", "factors": {...} }
  ],
  "enclave_signature": "<64-char SHA-256 of sorted fingerprints>"
}
```

## 9. AI Witnessing Profile

This section defines the application of SWT3 to artificial intelligence and
machine learning systems. The AI Witnessing Profile enables cryptographic
attestation of model behavior, safety controls, and operational integrity
throughout the AI lifecycle.

The AI Witnessing Profile is designed to satisfy requirements from:
- **NIST AI RMF** (AI 100-1): MAP, MEASURE, MANAGE, GOVERN functions
- **EU AI Act** (Regulation 2024/1689): Articles 9, 12, 13, 14, 72
- **ISO/IEC 42001**: AI Management System controls
- **NIST 800-53 AI family**: Controls prefixed AI- in the Axiom taxonomy

### 9.1 AI Procedure Registry

AI procedures use the `AI` UCT code and follow the naming convention
`AI-{DOMAIN}.{SEQUENCE}`, where DOMAIN identifies the witnessing category.

| Procedure ID | Domain | Description | Regulatory Basis |
|-------------|--------|-------------|------------------|
| `AI-INF.1` | Inference Provenance | Witness that a specific model produced a specific output | EU AI Act Art. 12 (Record-keeping), NIST AI RMF MEASURE 2.6 |
| `AI-INF.2` | Inference Latency | Witness response time against SLA thresholds | NIST AI RMF MANAGE 2.2 |
| `AI-INF.3` | Inference Volume | Witness request throughput for capacity governance | NIST AI RMF MANAGE 2.4 |
| `AI-MDL.1` | Model Integrity | Witness that deployed weights match the approved registry hash | EU AI Act Art. 9(4)(b), NIST AI RMF MANAGE 1.3 |
| `AI-MDL.2` | Model Version | Witness which model version served production traffic | EU AI Act Art. 12(2)(a) |
| `AI-MDL.3` | Model Drift | Witness accuracy/performance degradation against baseline | NIST AI RMF MEASURE 1.1 |
| `AI-GRD.1` | Guardrail Enforcement | Witness that required safety filters were active | EU AI Act Art. 9(4)(a), NIST AI RMF MANAGE 4.1 |
| `AI-GRD.2` | Content Safety | Witness content filter activation and block rate | EU AI Act Art. 9(8) |
| `AI-GRD.3` | PII Redaction | Witness PII detection and scrubbing before/after inference | GDPR Art. 25, NIST AI RMF GOVERN 1.7 |
| `AI-FAIR.1` | Bias Measurement | Witness demographic parity or equalized odds metrics | EU AI Act Art. 10(2)(f), NIST AI RMF MEASURE 2.11 |
| `AI-FAIR.2` | Fairness Threshold | Witness pass/fail against defined fairness bounds | NIST AI RMF MAP 2.3 |
| `AI-DATA.1` | Training Data Provenance | Witness dataset hash at training time | EU AI Act Art. 10, NIST AI RMF MAP 4.1 |
| `AI-DATA.2` | Training Data License | Witness that training data provenance includes license verification | EU AI Act Art. 53(1)(d) |
| `AI-HITL.1` | Human Review | Witness that a human reviewed an AI-generated decision | EU AI Act Art. 14, NIST AI RMF GOVERN 1.4 |
| `AI-HITL.2` | Override Decision | Witness that a human overrode the AI recommendation | EU AI Act Art. 14(4)(a) |
| `AI-EXPL.1` | Explainability | Witness that an explanation was generated alongside output | EU AI Act Art. 13, NIST AI RMF GOVERN 1.5 |
| `AI-EXPL.2` | Confidence Score | Witness model confidence against minimum threshold | NIST AI RMF MEASURE 2.9 |

### 9.2 Factor Matrix Semantics for AI

The SWT3 Factor Matrix (factor_a, factor_b, factor_c) carries domain-specific
meaning for each AI procedure. The following table defines the canonical
factor semantics. Implementations MUST use these semantics for interoperability.

| Procedure | factor_a (baseline/threshold) | factor_b (observed) | factor_c (delta) |
|-----------|------|------|------|
| `AI-INF.1` | Model weight hash (first 10 digits as integer) | Input hash (first 10 digits as integer) | Output hash (first 10 digits as integer) |
| `AI-INF.2` | Latency SLA threshold (ms) | Actual latency (ms) | `factor_b - factor_a` (negative = within SLA) |
| `AI-INF.3` | Capacity threshold (req/min) | Actual throughput (req/min) | `factor_b - factor_a` |
| `AI-MDL.1` | Approved hash (first 10 digits as integer) | Running hash (first 10 digits as integer) | Match flag (1 = match, 0 = mismatch) |
| `AI-MDL.2` | Expected version (integer encoding) | Deployed version (integer encoding) | Match flag (1 = match, 0 = mismatch) |
| `AI-MDL.3` | Baseline accuracy (× 1000, e.g., 950 = 95.0%) | Current accuracy (× 1000) | `factor_b - factor_a` (negative = degradation) |
| `AI-GRD.1` | Required guardrail count | Active guardrail count | `factor_b - factor_a` (negative = missing) |
| `AI-GRD.2` | Block rate threshold (× 1000) | Actual block rate (× 1000) | `factor_b - factor_a` |
| `AI-GRD.3` | PII fields requiring redaction | PII fields successfully redacted | `factor_b - factor_a` (0 = compliant) |
| `AI-FAIR.1` | Parity threshold (× 1000, e.g., 800 = 80.0%) | Measured parity ratio (× 1000) | `factor_b - factor_a` (negative = violation) |
| `AI-FAIR.2` | Fairness bound (× 1000) | Measured fairness score (× 1000) | `factor_b - factor_a` |
| `AI-DATA.1` | Approved dataset hash (first 10 digits) | Actual training hash (first 10 digits) | Match flag (1 = match, 0 = unauthorized) |
| `AI-DATA.2` | Required license flags (bitmask) | Verified license flags (bitmask) | `factor_b AND factor_a` XOR `factor_a` (0 = compliant) |
| `AI-HITL.1` | Review required flag (1 = yes) | Review completed flag (1 = yes) | `factor_b - factor_a` (0 = compliant) |
| `AI-HITL.2` | AI recommendation hash (first 10 digits) | Final decision hash (first 10 digits) | Override flag (1 = overridden, 0 = accepted) |
| `AI-EXPL.1` | Explanation required flag (1 = yes) | Explanation generated flag (1 = yes) | `factor_b - factor_a` (0 = compliant) |
| `AI-EXPL.2` | Minimum confidence threshold (× 1000) | Actual confidence score (× 1000) | `factor_b - factor_a` (negative = below threshold) |

### 9.3 Clearing Protocol for AI Systems

AI systems present unique Clearing considerations due to the sensitivity of
inference data (prompts may contain PII, trade secrets, medical records, or
classified information). The Clearing Protocol (Section 5.3) applies to AI
systems with these additional guidance:

#### 9.3.1 Recommended Clearing Levels by AI Context

| Context | Recommended Level | Rationale |
|---------|-------------------|-----------|
| Internal analytics | Level 0 (RETAIN) | Full forensic capability for model debugging |
| B2B SaaS inference | Level 1 (FACTOR-ONLY) | Factors retained, prompts/responses cleared |
| Healthcare / PII | Level 2 (ANCHOR-ONLY) | Factors may reveal PHI; only anchor persists |
| Classified / defense | Level 3 (SOVEREIGN) | Nothing persists on the minting system |

#### 9.3.2 Inference Clearing Sequence

For AI-INF procedures, the clearing sequence is:

```
1. Capture prompt and response (Provenance)
2. Compute input_hash = SHA-256(prompt)[0:20] as integer
3. Compute output_hash = SHA-256(response)[0:20] as integer
4. Mint SWT3 anchor with factor matrix (Verification)
5. Clear prompt and response from memory/storage (Clearing)
```

After step 5, the implementation retains only the anchor and factor matrix.
The original prompt and response are irrecoverable from the factors — only
their hashes are preserved, and SHA-256 is pre-image resistant. This satisfies
GDPR Article 17 (Right to Erasure) while preserving Article 12 (Transparency)
of the EU AI Act: you can prove the inference happened and verify its integrity
without being able to reconstruct the data.

### 9.4 AI Enclave Verification

AI systems SHOULD support enclave-level verification analogous to Section 6.3.
An AI Enclave encompasses all anchors produced by a single AI system (model +
infrastructure + guardrails) within a trust boundary.

The AI Enclave Integrity Signature covers:
- All AI-INF anchors (inference provenance)
- All AI-MDL anchors (model integrity)
- All AI-GRD anchors (guardrail enforcement)
- All AI-FAIR anchors (fairness measurements)
- All AI-HITL anchors (human oversight)
- All AI-EXPL anchors (explainability)

This enables a single verification command to attest the complete operational
integrity of an AI system over any time window:

```bash
swt3-verify --enclave --filter "AI-*" --from 2026-01-01 --to 2026-03-31
```

The resulting Enclave Integrity Signature can be included in:
- EU AI Act conformity assessment documentation
- NIST AI RMF assessment reports
- ISO 42001 management review evidence
- SOC 2 + AI supplementary criteria reports

### 9.5 AI Witness Transport Extension

The JSON transport format (Section 8.1) is extended for AI procedures with
an `ai_context` field in the metadata object:

```json
{
  "swt3_version": "1.0",
  "anchor": "SWT3-S-AWS-AI-AIINF1-PASS-1773900000-a4c7e2f91b03",
  "factors": {
    "procedure_id": "AI-INF.1",
    "tenant_id": "ACME_CORP",
    "factor_a": 2847593016,
    "factor_b": 1938274650,
    "factor_c": 7462019385,
    "timestamp_ms": 1773900000000
  },
  "verdict": "PASS",
  "witnessed_at": "2026-04-15T14:30:00Z",
  "metadata": {
    "source": "swt3-ai-sdk-v1.0",
    "check_type": "inference",
    "ai_context": {
      "model_id": "gpt-4o-2025-04-16",
      "model_provider": "openai",
      "guardrails_active": ["content_safety", "pii_redaction", "fairness_monitor"],
      "clearing_level": 1,
      "risk_tier": "high",
      "regulatory_scope": ["eu-ai-act", "nist-ai-rmf"]
    }
  }
}
```

The `ai_context` metadata is OPTIONAL and is not included in the fingerprint
computation. It provides operational context for ledger queries, dashboards,
and reporting. Implementations at Clearing Level 2+ SHOULD omit `ai_context`
or restrict it to non-sensitive fields.

### 9.6 Regulatory Mapping

#### 9.6.1 EU AI Act Coverage

| EU AI Act Article | Requirement | SWT3 AI Procedure |
|-------------------|-------------|-------------------|
| Art. 9(4)(a) | Risk management measures operational | AI-GRD.1, AI-GRD.2 |
| Art. 9(4)(b) | Appropriate testing and validation | AI-MDL.1, AI-MDL.3 |
| Art. 9(8) | Residual risk mitigation | AI-GRD.2, AI-FAIR.1 |
| Art. 10 | Data governance | AI-DATA.1, AI-DATA.2 |
| Art. 10(2)(f) | Bias examination | AI-FAIR.1, AI-FAIR.2 |
| Art. 12(1) | Automatic logging capability | AI-INF.1 (all inferences anchored) |
| Art. 12(2)(a) | Log identification of input/output | AI-INF.1 (input/output hashes) |
| Art. 13 | Transparency and information | AI-EXPL.1, AI-EXPL.2 |
| Art. 14 | Human oversight | AI-HITL.1, AI-HITL.2 |
| Art. 14(4)(a) | Ability to override | AI-HITL.2 |
| Art. 53(1)(d) | Training data transparency (GPAI) | AI-DATA.2 |
| Art. 72 | Post-market monitoring | AI-MDL.3, AI-FAIR.1 (continuous) |

#### 9.6.2 NIST AI RMF Coverage

| AI RMF Function | Category | SWT3 AI Procedure |
|-----------------|----------|-------------------|
| GOVERN 1.4 | Oversight mechanisms | AI-HITL.1, AI-HITL.2 |
| GOVERN 1.5 | Ongoing monitoring plans | AI-MDL.3, AI-GRD.1 |
| GOVERN 1.7 | Privacy and civil liberties | AI-GRD.3, AI-FAIR.1 |
| MAP 2.3 | Fairness criteria defined | AI-FAIR.2 |
| MAP 4.1 | Data requirements | AI-DATA.1, AI-DATA.2 |
| MEASURE 1.1 | Performance measurement | AI-MDL.3, AI-INF.2 |
| MEASURE 2.6 | Traceability of outputs | AI-INF.1 |
| MEASURE 2.9 | Confidence characterization | AI-EXPL.2 |
| MEASURE 2.11 | Fairness assessment | AI-FAIR.1, AI-FAIR.2 |
| MANAGE 1.3 | Deployment integrity | AI-MDL.1, AI-MDL.2 |
| MANAGE 2.2 | Performance monitoring | AI-INF.2, AI-INF.3 |
| MANAGE 2.4 | Resource allocation | AI-INF.3 |
| MANAGE 4.1 | Risk controls operational | AI-GRD.1, AI-GRD.2 |

## 10. Security Considerations

### 9.1 Truncation Risk

The 12-character (48-bit) fingerprint is not intended as a cryptographic
signature. It is a **verification shortcut**. Systems requiring full
cryptographic assurance SHOULD store and verify against the full 64-character
SHA-256 digest.

### 9.2 Factor Confidentiality

Factor values (especially `factor_a` thresholds) may reveal security posture
details (e.g., expected port counts, patch windows). Implementations SHOULD
apply access controls to factor data and leverage the Clearing Protocol
(Section 5.3) at Level 1 or higher for sensitive environments.

### 9.5 Clearing and Data Sovereignty

The Clearing Protocol (Section 5.3) is designed to prevent raw evidence from
becoming a persistent attack surface. However, implementations must consider:

- **Pre-clearing exfiltration:** An attacker with access during the Provenance
  phase (before clearing) can capture raw evidence. Clearing protects against
  post-anchoring data exposure, not real-time interception.
- **Factor inference:** Even at Clearing Level 1, retained factors may allow
  partial reconstruction of the original state (e.g., factor_b = 3 open ports
  reveals network topology). Clearing Level 2 or 3 is RECOMMENDED for
  environments where factor values themselves are sensitive.
- **Clearing verification:** Implementations SHOULD provide a mechanism to
  confirm that clearing has occurred (e.g., a clearing timestamp or clearing
  receipt). This supports SI-12 (Information Management and Retention) audit
  requirements.

### 9.3 Timestamp Manipulation

The `timestamp_ms` is a critical input to the fingerprint. An attacker who can
control the timestamp can forge a valid fingerprint with different factors.
Implementations MUST ensure timestamps are generated by trusted sources (system
clock, NTP-synchronized) and not accepted from untrusted input.

### 9.4 Collision Resistance

At 48 bits, the birthday paradox threshold is approximately 2^24 (~16.7 million)
anchors before a 50% collision probability. For most compliance ledgers (tens of
thousands of anchors), this provides adequate uniqueness. Enclave integrity
verification (Section 6.3) uses the full 64-character digest.

## 11. Conformance

An implementation is SWT3-conformant if it:

1. Produces anchors matching the format in Section 3
2. Uses only registered UCT codes from the UCT Registry (Section 3.2)
3. Computes fingerprints using the algorithm in Section 4
4. Can verify anchors using the algorithm in Section 6.1
5. Uses the JSON transport format in Section 8 for interoperability
6. Documents its Clearing Level (Section 5.3.1) in its security posture
7. Documents its AI Clearing Level (Section 9.3) if implementing AI procedures

An implementation claiming **SWT3-Sovereign** conformance MUST additionally:

8. Implement Clearing Level 1 or higher as the default behavior
9. Ensure clearing irreversibility per Section 5.3.3

Implementations MAY extend the metadata field with additional properties.
Implementations MUST NOT modify the fingerprint algorithm or anchor format.

## 12. IANA Considerations

This specification does not require any IANA registrations. The `SWT3` protocol
identifier and the UCT Registry are maintained by Tenable Nova LLC (DBA TeNova).
The UCT Registry governance process is defined in Section 3.2.5.

---

**Copyright (c) 2026 Tenable Nova LLC (DBA TeNova). Licensed under Apache 2.0.**

SWT3 and Sovereign Witness Traceability are trademarks of Tenable Nova LLC. Patent pending.

---

*SWT3: Sovereign Witness Traceability — Provenance, Verification, Clearing.*
