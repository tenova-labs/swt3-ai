# THE SWT3 MANIFESTO: A NEW PRIMITIVE FOR SOVEREIGN TRUTH

**Version:** 1.0 (Draft for Federal & Industry Adoption)
**Author:** TeNova Engineering, Tenable Nova LLC (DBA TeNova)
**Date:** March 28, 2026

---

## 1. The Crisis of Trust

In an era of ubiquitous AI, automated cyber-attacks, and fragmented global supply chains, the fundamental unit of governance — **The Fact** — is under siege.

Current systems of record rely on what we call **Administrative Trust**: we trust data because we trust the database administrator, the cloud provider, or the government agency hosting it. The auditor checks the spreadsheet. The assessor reviews the screenshot. The regulator accepts the PDF. At every level, the question is the same: *do you trust the custodian?*

This model is failing.

- Centralized databases are **honeypots** for exfiltration and tampering.
- Audits are **point-in-time snapshots** — expensive, manual, and trivially manipulated between cycles.
- Compliance evidence is stored as **unstructured artifacts** (screenshots, Word documents, spreadsheets) with no cryptographic binding to the moment of observation.
- The verifier must trust the system that produced the claim. There is no independent verification path.

The result: billions spent annually on compliance processes that prove nothing more than *"the custodian says this is true."*

We can do better. We must.

---

## 2. The SWT3 Protocol: Sovereign Witness Traceability

SWT3 introduces a new cryptographic primitive: **The Sovereign Witness**.

It moves the root of trust from the *custodian of the data* to the *mathematics of the observation*.

The **"3"** in SWT3 represents the three phases of the evidence lifecycle — the complete chain from observation to sovereignty:

### Phase 1: Provenance

Every claim is witnessed at its point of origin. Raw telemetry — command outputs, sensor readings, system states — is captured and decomposed into a **Factor Matrix** (factor_a, factor_b, factor_c). A verdict is not an opinion; it is the deterministic output of a locked mathematical expression evaluated against measured evidence.

The observation is cryptographically bound to a sub-second hardware epoch, creating a **temporal anchor** that cannot be backdated or forward-dated. The evidence has a birth certificate signed by mathematics, not by an administrator.

### Phase 2: Verification

The factors, procedure identifier, tenant, and timestamp are hashed through SHA-256 into a **fingerprint** — a deterministic, reproducible digest that seals the observation. This fingerprint is embedded into a self-describing **SWT3 Witness Anchor**:

```
SWT3-E-VULTR-NET-SC76-PASS-1773316622-96b7d56c0245
│     │  │     │   │    │       │          │
│     │  │     │   │    │       │          └─ SHA-256 fingerprint
│     │  │     │   │    │       └─ epoch (when)
│     │  │     │   │    └─ verdict (what was decided)
│     │  │     │   └─ procedure (what was evaluated)
│     │  │     └─ domain category
│     │  └─ provider (where)
│     └─ deployment tier
└─ protocol identifier
```

The anchor is **self-describing and portable**. A human can read it. A machine can verify it. No network access, no database connection, no trust in the issuing system — just the token, the factors, and SHA-256. If the recomputed fingerprint matches the claimed fingerprint, the evidence is intact. If it doesn't: **TAMPERED**.

At the enclave level, all fingerprints are sorted, concatenated, and hashed into a single **Enclave Integrity Signature** — one deterministic value that represents the integrity of an entire compliance posture. Same ledger state, same signature — always.

### Phase 3: Clearing

This is the phase that no existing system addresses.

After the anchor is minted and integrity is cryptographically provable, the **raw evidence is purged**. The original telemetry — command outputs, configuration files, API responses, log entries — is destroyed. Only the factors and the fingerprint persist.

The proof survives. The data does not.

This resolves a tension that the industry treats as an unsolvable tradeoff: **integrity versus data sovereignty**. Today, organizations must choose — keep raw evidence to prove compliance (creating persistent attack surface, CUI spillage risk, and data residency violations), or purge it to protect sovereignty (losing the ability to prove what happened).

SWT3 eliminates the tradeoff. The anchor is mathematical proof that the state existed exactly as claimed. The clearing phase ensures that sensitive telemetry never persists beyond its operational usefulness. **100% integrity. 100% data sovereignty. Not a compromise between them — both, fully.**

---

## 3. How SWT3 Differs

### From Traditional Hashing

A hash proves that a blob of data hasn't changed. It says nothing about what the data *means*, when it was captured, or who it belongs to. The verifier must trust the issuer's description of what was hashed.

SWT3 hashes a **canonical structured input** — every field has semantic meaning. The resulting anchor is self-describing: the verifier can read the claim, understand its context, and independently re-derive the proof. A hash is opaque. An SWT3 anchor is transparent.

### From Blockchain

Blockchain provides tamper-evidence through distributed consensus — an expensive, slow, network-dependent mechanism that stores data permanently and publicly.

SWT3 provides tamper-evidence through **deterministic mathematics** — no consensus mechanism, no mining, no gas fees, no network dependency, no permanent data retention.

| | Blockchain | SWT3 |
|---|---|---|
| Consensus mechanism | Required (expensive) | None needed |
| Network dependency | Must be online | Works fully offline |
| Verification speed | Seconds to minutes | Milliseconds |
| Infrastructure | Nodes, validators, gas | Zero — SHA-256 only |
| Verifier trust model | Trust the chain | Trust nothing — just math |
| Data persistence | Append-only, permanent | Factors + anchor (clearing-capable) |
| Data sovereignty | Data lives on-chain, publicly | Raw evidence purged after anchoring |
| Air-gap capable | No | Yes |

SWT3 delivers the **one thing** organizations actually want from blockchain — tamper-evident proof — without any of the overhead. And it adds the one thing blockchain *cannot* provide: the ability to **destroy the underlying data** while preserving the integrity proof.

### From Digital Signatures (PKI)

Digital signatures bind a claim to an identity via certificate chains. They answer: *"who signed this?"* SWT3 answers a different question: *"has this evidence been altered since it was observed?"* — and it answers it without requiring certificate authorities, key management infrastructure, or trust in any identity provider.

SWT3 and PKI are complementary, not competitive. An organization MAY digitally sign an SWT3 anchor for identity binding while relying on the SWT3 fingerprint for integrity verification.

---

## 4. Beyond Compliance: Universal Applications

SWT3 is not a GRC feature. It is a **verification layer** for any state that requires integrity.

**The AI Flight Recorder**
Witnessing AI model inferences — input prompts, output responses, confidence scores, model versions — to ensure safety, prevent hallucination-drift in critical infrastructure, and provide auditable AI governance. Every inference gets an anchor. The raw prompt data is cleared. The proof that the inference occurred, with specific factors, persists indefinitely.

**The Supply Chain Notary**
Anchoring every handoff, inspection, and quality check in physical supply chains. CHIPS Act semiconductor provenance, pharmaceutical cold chain integrity, defense logistics chain of custody. Each node in the chain mints an anchor. An end-consumer verifies the full chain without accessing any upstream system.

**The Forensic Gold Standard**
Anchoring digital and physical evidence at the moment of collection — creating admissibility proof via mathematics, not institutional reputation. Chain of custody becomes cryptographically verifiable. Evidence clearing ensures that sensitive forensic data doesn't persist in custody tracking systems after adjudication.

**Financial Audit Integrity**
Every journal entry, reconciliation, and valuation anchored at the moment of recording. External auditors run an enclave integrity check against the general ledger and receive a single deterministic signature. SOX compliance becomes provable, not asserted.

**Election Verification**
Precinct tallies anchored with SWT3 at the moment of count. Independent observers verify the integrity of results without accessing the tabulation system. Same results, same enclave signature — always. Recounts become cryptographically confirmable.

**IoT and Sensor Networks**
Environmental readings, industrial sensor data, SCADA telemetry — anchored at the edge, verified at the center. Regulatory agencies (FDA, EPA, OSHA, NRC) can verify sensor data integrity without accessing the operational network. Critical for environments where network isolation is mandatory.

**Software Supply Chain (SBOM)**
Build artifacts, dependency trees, test results — anchored at CI/CD time. Downstream consumers verify that the software they deploy matches what was built and tested. The raw build logs are cleared; the integrity proof persists.

---

## 5. The Standards Path: A Call to Action

We propose SWT3 as an **open standard** — a lightweight, offline-capable, independently verifiable alternative to high-overhead blockchain and centralized trust models.

**To NIST:**
We propose SWT3 as a reference architecture for non-blockchain cryptographic data integrity, complementing the work outlined in NISTIR 8202. The protocol's native OSCAL integration makes it immediately applicable to the federal assessment and authorization ecosystem.

**To CISA:**
We offer SWT3 as the integrity backbone for Software Bill of Materials (SBOM) transparency and supply chain risk management. Its offline capability and clearing phase make it uniquely suited to classified and air-gapped environments.

**To DoD and the Intelligence Community:**
SWT3's clearing phase solves the fundamental tension between compliance evidence requirements and classified data handling. Prove the state. Purge the source. Verify from outside the boundary.

**To the GRC Industry:**
We challenge every compliance platform to adopt verifiable evidence. If your verdicts can't be independently verified by an assessor without trusting your database, you're selling Administrative Trust — not proof.

**To the Open Source Community:**
We release **libswt3** as the reference implementation — Apache 2.0 licensed, zero dependencies, one universal algorithm. The protocol belongs to everyone. Build verifiers in every language. Embed anchors in every system. Make integrity the default, not the exception.

---

## 6. First Principles

1. **Trust mathematics, not custodians.** If a fact requires institutional trust to verify, it is not yet a fact — it is a claim.
2. **Evidence must be self-proving.** A proof that requires access to the system that generated it is not independent verification — it is a courtesy.
3. **Data sovereignty and integrity are not a tradeoff.** The proof must survive the data. The data must not outlive its purpose.
4. **Verification must work in isolation.** No network. No database. No API. No vendor. Just the anchor, the factors, and SHA-256.
5. **The protocol must be open.** A trust primitive that requires a proprietary implementation is a contradiction.

---

*SWT3: Sovereign Witness Traceability — Provenance, Verification, Clearing.*

*Trust Nothing. Verify Everything.*

**Copyright (c) 2026 Tenable Nova LLC (DBA TeNova). Licensed under Apache 2.0.**

SWT3 and Sovereign Witness Traceability are trademarks of Tenable Nova LLC. Patent pending.
