# Terms of Service Addendum: SWT3 Clearing Protocol and Shared Responsibility

**Effective Date:** April 4, 2026
**Applies to:** All TeNova Axiom subscription tiers and AI Witness SDK users
**Governing Agreement:** TeNova Axiom Terms of Service (March 30, 2026)

---

## Purpose

This addendum defines who is responsible for what when you use SWT3 Clearing Levels to manage how your compliance evidence and AI inference data is retained, transmitted, or disposed of.

The SWT3 protocol gives you control over how much data leaves your environment. That control comes with a clear division of responsibility between you and TeNova. This document spells out that division so there is no ambiguity about what is protected, what is kept, and who is accountable.

---

## Section A: The Four Clearing Levels

When you configure the SWT3 AI Witness SDK or the Axiom platform, you choose a Clearing Level. That choice determines what data is sent to TeNova and what stays on your systems.

### Level 0 - Retain

Everything is transmitted and stored: cryptographic hashes, numeric factors, model identifiers, performance data, token counts, and contextual metadata such as provider name, guardrail configuration, and system fingerprint.

Important: no raw prompts or responses are transmitted at any clearing level. That is true at Level 0 and every level above it.

**Best for:** Development, internal testing, and environments where you need a full forensic trail for later review.

### Level 1 - Standard

Cryptographic hashes, numeric factors, model identifier, and contextual metadata are transmitted. This is the default level and the right starting point for most organizations.

**Best for:** Production environments that need compliance witnessing with a solid audit trail, without exposing unnecessary operational detail.

### Level 2 - Sensitive

Cryptographic hashes, numeric factors, and the model identifier are transmitted. All contextual metadata is stripped before anything leaves your environment. The provider name, guardrail names, and system fingerprint stay with you.

**Best for:** Environments handling regulated data where even metadata could reveal sensitive operational patterns. If your data classification policy restricts what can leave your boundary, this is likely your level.

### Level 3 - Sovereign

Only numeric factors are transmitted. The model identifier is hashed before transmission so the original value never leaves your environment. All other identifying information is destroyed before it hits the wire. After the SWT3 Witness Anchor is sealed, the local system purges its temporary memory.

**Best for:** Air-gapped systems, high-sensitivity environments, and organizations that require zero-knowledge proof of compliance. At this level, TeNova operates as a purely stateless verification provider. We see three numbers and a 12-character fingerprint. Nothing more.

---

## Section B: Shared Responsibility

### What TeNova is responsible for

1. **Protocol integrity.** The SWT3 fingerprint algorithm is mathematically sound, deterministic, and one-way. The fingerprint cannot be reversed to reconstruct your data.

2. **Anchor permanence.** Once a SWT3 Witness Anchor is sealed and written to the compliance ledger, it cannot be altered, backdated, or deleted by anyone, including TeNova.

3. **Clearing enforcement on our side.** When you select a Clearing Level, our platform and SDKs enforce that level at the network boundary. Data excluded by your clearing level is never transmitted to, received by, or stored on TeNova systems.

4. **Enclave integrity.** We maintain the cryptographic chain that binds all anchors for a given period into a tamper-evident record. If any anchor is altered after the fact, the chain breaks and the tampering is detectable.

5. **Open verification.** The SWT3 protocol specification and the libswt3 reference implementation are published and auditable. You do not need to take our word for any of the above. You can verify it yourself.

### What you are responsible for

1. **Choosing your clearing level.** You select the level that matches your data classification, regulatory requirements, and risk posture. TeNova does not make this decision for you, and different parts of your organization may choose different levels for different workloads.

2. **Factor custody (Levels 2 and 3).** At Clearing Level 2 and above, you hold sole custody of some or all of the data needed to re-verify an anchor. If you lose that data, the anchor becomes mathematically un-verifiable. TeNova cannot recover what we never received.

3. **Factor security.** You are responsible for the confidentiality, integrity, and availability of any factors, metadata, or evidence that stays on your systems. If your factors are compromised, exposed, or corrupted, TeNova is not liable for unauthorized re-verification or evidence tampering.

4. **SDK configuration.** You are responsible for correctly setting the clearing level in the SWT3 SDK. A misconfigured level may send more or less data than you intend.

5. **Downstream submissions.** If you submit SWT3 anchors, compliance artifacts, or evidence packages to any regulatory body, auditor, or reviewing authority, you are responsible for the accuracy and completeness of that submission. TeNova provides the evidence. You own the submission.

---

## Section C: What TeNova Never Receives

Regardless of which clearing level you select, the following data never leaves your systems:

- **Raw prompts and responses.** The SWT3 protocol works with cryptographic hashes that are computed locally. Your actual AI inputs and outputs are never transmitted to TeNova at any level.
- **Training data.** TeNova does not access, collect, or process your model training data.
- **Encryption keys.** TeNova does not manage, store, or hold your encryption keys.

This is not a policy decision. It is an architectural guarantee. The SDKs are open source and you can verify this by reading the code.

---

## Section D: The Self-Custody Trade-off

Clearing Levels 2 and 3 provide maximum privacy by design. We built them that way intentionally because holding your sensitive data creates risk for both of us. But that privacy comes with a trade-off: at higher clearing levels, you become the sole custodian of the evidence needed to prove your compliance history.

We designed this so that both parties are protected. Here is how the responsibility divides at each level.

**For Clearing Level 2 (Sensitive):**

You acknowledge that TeNova does not retain contextual metadata (provider name, guardrail configuration, system fingerprint) for anchors created at Clearing Level 2. Re-verification of the anchor remains possible using the factors you hold. If you lose those factors, the anchor itself is still intact on our ledger, but you will not be able to independently prove what it represents.

**For Clearing Level 3 (Sovereign):**

You acknowledge that for anchors created at Clearing Level 3, TeNova operates solely as a stateless verification provider. You hold sole custody of all factors and metadata required for re-verification. TeNova does not maintain backups of factors or metadata for Sovereign-tier anchors. If your factors are lost, corrupted, or compromised, the corresponding anchor becomes mathematically un-verifiable. TeNova assumes no liability for data loss, evidence gaps, or the inability to provide compliance proof that results from factor loss at this level.

**For all Clearing Levels:**

You assume sole responsibility for the confidentiality, integrity, and availability of all data retained on your systems, including factors, metadata, raw evidence, and encryption keys. TeNova's liability is limited to the integrity of the SWT3 protocol, the correctness of the fingerprint algorithm, and the permanence of anchors stored on TeNova systems, as described in the primary Terms of Service.

---

## Section E: Incident Response and Breach Notification

**If TeNova experiences a security incident** that could affect the integrity of anchors or any metadata stored on our systems, we will notify affected clients within 72 hours of confirmed discovery. The notification will include: what data was affected, which clearing levels are impacted, and what actions (if any) you should take.

For clients operating at Clearing Level 3, a breach on TeNova's side exposes only numeric factors and hashed model identifiers with no identifying context. There is nothing to reconstruct. We will still notify you, but the practical exposure is near zero by design.

**If you experience a security incident** and need access to metadata stored on TeNova systems (Levels 0 and 1), we will cooperate with your incident response team and provide relevant records in a timely manner, subject to our Privacy Policy and applicable law.

TeNova does not currently hold SOC 2 Type II certification. We are committed to independent security review of the clearing engine and will publish results when available. In the interim, the SWT3 protocol specification and SDK source code are publicly auditable.

---

## Section F: Anchor Corrections and Revocation

SWT3 Witness Anchors are permanent records of a compliance fact observed at a specific point in time. They are not editable and they do not expire.

However, mistakes happen. If you discover that an anchor reflects an incorrect verdict (for example, an attestation that should not have been made), the anchor is not deleted. Instead, a **revocation record** is appended to the ledger referencing the original anchor. The original anchor remains in the cryptographic chain for integrity purposes, but is marked as revoked.

This means the compliance record is always complete and honest. An auditor can see: "This anchor was created on this date, and it was revoked on this date, for this reason." Nothing is hidden or rewritten.

TeNova does not revoke anchors on your behalf. You initiate the revocation, and the platform records it.

---

## Section G: Anchor Validity Over Time

Anchors are permanent, but compliance is not. An anchor from six months ago tells you what was true six months ago, not what is true today.

It is the responsibility of the reviewing party (whether that is an auditor, an assessor, a regulator, or your own internal team) to decide whether an anchor's age is acceptable for their purposes. TeNova does not impose expiration dates because different industries, frameworks, and jurisdictions have different expectations for how current evidence needs to be.

We recommend running scans at a frequency that matches your compliance cadence. For most organizations, this means daily or weekly collection with periodic review.

---

## Section H: Regulatory Applicability

The SWT3 Clearing Protocol is designed to be framework-agnostic. It addresses data retention, disposal, and custody principles that appear across multiple regulatory environments, including but not limited to:

- NIST 800-53 and NIST 800-171 (U.S. federal and defense)
- CMMC v2.0 (U.S. defense industrial base)
- FedRAMP (U.S. cloud services)
- HIPAA (U.S. healthcare)
- PCI-DSS (payment card industry)
- SOC 2 (service organization controls)
- EU AI Act (European Union artificial intelligence regulation)
- NIST AI RMF (AI risk management)

TeNova publishes separate compliance overlay documents that map clearing levels to specific controls within each framework. Contact us or visit our documentation for the overlay relevant to your environment.

---

## Section I: Contact

Questions about this addendum should be directed to:

Tenable Nova LLC
Email: legal@tenovaai.com
Web: sovereign.tenova.io

---

*This addendum supplements and is incorporated into the TeNova Axiom Terms of Service. In the event of a conflict between this addendum and the primary Terms of Service, this addendum controls with respect to the SWT3 Clearing Protocol. All other terms remain in full force.*
