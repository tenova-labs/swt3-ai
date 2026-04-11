# SWT3 Clearing Protocol: CMMC and NIST 800-171 Compliance Overlay

**Version:** 1.0.0
**Date:** April 4, 2026
**Applies to:** Organizations pursuing CMMC Level 2 or Level 3 certification
**Parent document:** SWT3 ToS Clearing Addendum (April 4, 2026)

---

## Who This Document Is For

This overlay is for ISSMs, security engineers, C3PAO assessors, and compliance officers working in the Defense Industrial Base (DIB) who need to understand how SWT3 Clearing Levels map to specific CMMC and NIST 800-171 requirements.

If you are evaluating TeNova Axiom for a system that handles Controlled Unclassified Information (CUI), this document tells you which clearing level to choose, which controls it satisfies, and what to show an assessor when they ask about data retention and disposal.

---

## Quick Reference: Clearing Level Selection for CUI Systems

| Your environment | Recommended clearing level | Why |
|---|---|---|
| Development / staging (no CUI) | Level 0 or 1 | Full audit trail, no regulatory data at risk |
| Production with CUI | Level 2 | Meets MP-6, SI-12, and SC-28 without exposing operational metadata |
| Air-gapped or classified enclave | Level 3 | Zero-knowledge proof; TeNova sees nothing identifiable |
| Managed service (you host for others) | Level 2 minimum | Your tenants' metadata is their CUI, not yours to share |

If you are unsure, start with Level 2. It gives you the strongest balance of auditability and data protection for CUI environments. You can always move to Level 3 later; you cannot retroactively raise the clearing level on existing anchors.

---

## Control-by-Control Mapping

### Media Protection

**MP-6: Media Sanitization**
CMMC requires that CUI is sanitized from media before disposal or reuse.

How SWT3 addresses it: At Clearing Level 2 and above, contextual metadata (provider names, guardrail configurations, system fingerprints) is destroyed before transmission. At Level 3, all identifying information is destroyed after the anchor is sealed. The SDK's clearing engine operates on the wire payload and then purges local temporary buffers. This satisfies the sanitization requirement for AI inference metadata.

What to show the assessor: The clearing engine source code in the published SDK (Python: `swt3_ai/clearing.py`, TypeScript: `src/clearing.ts`). Point them to the `_apply_clearing` function which implements the per-level sanitization logic. The code is open source and auditable.

---

### System and Information Integrity

**SI-12: Information Management and Retention**
CMMC requires that CUI is retained and disposed of in accordance with applicable laws, regulations, and organizational policies.

How SWT3 addresses it: The four clearing levels give you explicit, configurable control over what is retained and what is disposed of. Your clearing level selection becomes part of your system security plan. The Factor Handoff Protocol (see parent document) defines how disposed data is transferred to your custody before destruction, creating a documented chain of custody.

What to show the assessor: Your clearing level configuration in the SDK, the Factor Handoff Protocol specification, and your organization's factor backup and retention procedure. The assessor should see that you made a deliberate, documented choice about data retention, not that data was silently discarded.

**SI-7: Software, Firmware, and Information Integrity**
CMMC requires integrity verification of software and security-relevant information.

How SWT3 addresses it: Every SWT3 Witness Anchor is a SHA-256 fingerprint that seals the compliance fact at the moment it was observed. If any factor is altered after the fact, the fingerprint will not match on re-verification. The daily enclave signature (and forthcoming Merkle tree rollup) binds all anchors into a tamper-evident chain. Altering one anchor breaks the chain.

What to show the assessor: Run a verification on any anchor using the public verifier at sovereign.tenova.io/verify or the offline verification formula. Demonstrate that the math matches. Then show the enclave signature and explain that it binds all anchors for the period into a single root hash.

---

### System and Communications Protection

**SC-28: Protection of Information at Rest**
CMMC requires that CUI at rest is protected.

How SWT3 addresses it: At Clearing Level 2 and above, the sensitive metadata never reaches TeNova's systems, so there is nothing to protect at rest on our side. On your side, the Factor Handoff Protocol supports encrypted storage via Cloud KMS Envelope (AES-256-GCM with a key you control) or HashiCorp Vault. The factor backup recommendations specify encryption at rest as a baseline expectation.

What to show the assessor: Your factor storage configuration (Vault path, KMS key ARN, or encrypted filesystem), and your factor backup encryption policy.

**SC-8: Transmission Confidentiality and Integrity**
CMMC requires that CUI in transit is protected.

How SWT3 addresses it: All communication between the SWT3 SDK and TeNova uses HTTPS (TLS 1.2 or higher). The webhook handoff method enforces HTTPS and rejects plaintext connections. At Level 3, even if the transmission were intercepted, the payload contains only numeric factors and a hashed model ID with no identifying context.

What to show the assessor: The SDK's TLS enforcement (the webhook method rejects HTTP), your platform's TLS configuration, and the secure reverse proxy HSTS headers on the TeNova endpoint.

---

### Access Control

**AC-3: Access Enforcement**
CMMC requires that access to CUI is enforced based on applicable policies.

How SWT3 addresses it: Clearing level selection is a configuration-time decision made by the system administrator. The SDK enforces the selected level programmatically; individual users cannot override it at runtime. Factor handoff destinations (Vault paths, webhook URLs, KMS keys) are set in configuration, not chosen per-request.

What to show the assessor: Your SDK configuration showing the clearing level and handoff destination. Demonstrate that a developer using the SDK cannot change the clearing level without modifying the system configuration.

---

### Audit and Accountability

**AU-3: Content of Audit Records**
CMMC requires that audit records contain enough information to establish what happened, when, where, and the outcome.

How SWT3 addresses it: Every SWT3 Witness Anchor records the procedure ID (what was checked), the timestamp (when), the tenant ID (where), the verdict (outcome), and the three factors (the evidence). At Clearing Level 0 and 1, additional context is available. At all levels, the anchor itself is a complete, self-contained audit record of the compliance fact.

What to show the assessor: A sample anchor from your ledger. Walk through the SWT3 format: `SWT3-{TIER}-{PROVIDER}-{UCT}-{PROCEDURE}-{VERDICT}-{EPOCH}-{FINGERPRINT}`. Each field maps to one of the AU-3 requirements.

**AU-11: Audit Record Retention**
CMMC requires that audit records are retained for a defined period.

How SWT3 addresses it: SWT3 anchors on the TeNova ledger are permanent and do not expire. For factors held on your systems (Levels 2 and 3), retention is your responsibility. The Factor Handoff Protocol recommends retaining factors for at least as long as your records retention schedule requires. For most NIST 800-171 environments, three years is the baseline.

What to show the assessor: Your factor retention policy and evidence that your backup/restore process has been tested.

---

### Identification and Authentication

**IA-5: Authenticator Management**
CMMC requires that authenticators (passwords, tokens, keys) are managed securely.

How SWT3 addresses it: Factor handoff credentials (Vault tokens, webhook bearer tokens, KMS key references) are authenticators under IA-5. The Factor Handoff Protocol recommends dedicated, scoped credentials for each handoff method. Vault tokens should be limited to `create` on the SWT3 factor path. Webhook tokens should be single-purpose.

What to show the assessor: Your Vault policy or webhook credential management procedure. Demonstrate that the handoff token cannot access anything beyond the SWT3 factor storage path.

---

## AI-Specific Controls (NIST AI RMF / CMMC + AI Overlay)

If your system includes AI components and you are using the SWT3 AI Witness SDK, the following additional mappings apply.

**AI-INF.1: Inference Provenance**
The SDK witnesses every AI inference and creates an anchor proving the model, inputs, and outputs were recorded. At Clearing Level 2+, the raw inputs and outputs stay on your system. Only hashes are transmitted.

**AI-MDL.1: Model Weight Integrity**
The SDK records a hash of the model identifier at inference time. If the model changes between inferences, the hash changes and the drift is detectable.

**AI-GRD.1: Guardrail Enforcement**
The SDK records how many guardrails were required, how many were active, and whether they passed. At Clearing Level 2+, the guardrail names are stripped, but the numeric compliance fact (required vs. active) is preserved.

For organizations subject to the NIST AI RMF, these three procedures map to MAP 1.1, MEASURE 2.6, and MANAGE 3.2 respectively. A full AI RMF crosswalk is available in the AI Witness documentation.

---

## Assessor Quick Reference

When a C3PAO assessor asks about SWT3 and data handling, use this table to find the right answer.

| Assessor question | Where to look |
|---|---|
| "How is CUI protected during AI witnessing?" | Clearing Level definitions (ToS Addendum, Section A). Level 2+ strips all identifying metadata. |
| "How do you prove the data was actually cleared?" | Clearing engine source code in the open-source SDK. The `_apply_clearing` function is auditable. |
| "What if the vendor is breached?" | ToS Addendum, Section E (Incident Response). At Level 3, exposure is near zero by design. |
| "Where are the factors stored?" | Factor Handoff Protocol, Section 3. Client chooses: local file, webhook, Vault, or KMS. |
| "What happens if factors are lost?" | ToS Addendum, Section D. The anchor is intact but un-verifiable. Client holds sole custody. |
| "How do you handle incorrect verdicts?" | ToS Addendum, Section F. Revocation record appended; original anchor stays for integrity. |
| "What is the retention period for audit records?" | Anchors on TeNova are permanent. Client-held factors follow client's retention schedule. |
| "Can I verify an anchor independently?" | Factor Handoff Protocol, Section 5. Offline verification with a 4-line code snippet. No TeNova dependency. |
| "Is the protocol proprietary?" | No. Open-source SDKs, published spec, public verifier. Patent pending on the implementation, not the math. |
| "How does this map to NIST 800-171?" | This document. See Control-by-Control Mapping above. |

---

## Recommended SSP Language

When documenting SWT3 in your System Security Plan, consider language similar to the following (adjust to match your system specifics):

> The system uses the SWT3 Witness Anchor protocol (TeNova Axiom) to create tamper-evident compliance records for AI inference operations and system control evaluations. The SWT3 Clearing Protocol is configured at Level [2/3] to ensure that Controlled Unclassified Information, including AI model metadata and operational context, is not transmitted to the external witnessing service. Evidence factors are retained on [describe your factor storage] in accordance with the organization's Records Retention Schedule. The protocol's SHA-256 fingerprint algorithm provides integrity verification (SI-7), and the clearing engine's open-source implementation supports independent audit of the sanitization process (MP-6).

---

## Document Lineage

This overlay references and depends on:

- **SWT3 ToS Clearing Addendum** (April 4, 2026) - the protocol-level terms and shared responsibility model
- **SWT3 Factor Handoff Protocol** (v1.0.0, April 4, 2026) - the technical specification for factor custody transfer
- **NIST SP 800-171 Rev. 2** - Security Requirements for Protecting CUI
- **CMMC v2.0 Assessment Guide** - Level 2 and Level 3 practices
- **NIST AI RMF 1.0** - AI Risk Management Framework (for AI-specific controls)

---

*Patent Pending. SWT3 and Sovereign Witness Traceability are trademarks of Tenable Nova LLC.*
