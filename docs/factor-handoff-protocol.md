# SWT3 Factor Handoff Protocol

**Version:** 1.0.0
**Date:** April 4, 2026
**Status:** Draft
**Author:** Tenable Nova LLC

---

## What This Document Covers

When you choose Clearing Level 2 or 3, the SWT3 protocol strips some or all verifiable data from the payload before it reaches TeNova. That means you become the sole holder of the information needed to re-verify your compliance anchors.

This document explains how that handoff works: what data you receive, how it gets to you, and what happens if something goes wrong along the way.

If you are evaluating this document from a governance or procurement perspective, start with Sections 1 and 2, then skip to Sections 4, 6, and the FAQ. The technical integration details in Sections 3 and 5 are written for development teams.

---

## 1. The Core Idea

The Factor Handoff is a custody transfer, not a backup.

When the SWT3 SDK creates an anchor on your system, it holds the raw data (the "factors") needed to prove that anchor is real. At Clearing Level 2 or 3, the SDK needs to get that data safely into your hands before it wipes its own copy and sends the stripped payload to TeNova.

Once the handoff is complete, your copy is the only copy that exists. TeNova's copy has been destroyed. If you lose your copy, no one can help you re-verify that anchor. That is the trade-off of higher clearing levels, and it is by design.

---

## 2. What You Receive

The data included in a handoff depends on your clearing level.

### At Clearing Level 2

At Level 2, your factors and hashes still go to TeNova. What gets stripped is contextual metadata. The handoff captures what was removed:

| What you receive | What it is | Example |
|---|---|---|
| Provider name | Which AI service was used | `"openai"` |
| Guardrail names | Which safety filters were active | `["content_filter", "pii_redactor"]` |
| System fingerprint | Provider's internal system ID | `"fp-abc123"` |
| Clearing level | The level that was applied | `2` |
| Anchor fingerprint | The sealed SWT3 fingerprint | `"96b7d56c0245"` |
| Timestamp | When the anchor was created | `1712188800000` |

### At Clearing Level 3

At Level 3, nearly everything is stripped. The handoff captures all the data you would need to independently prove any anchor is real:

| What you receive | What it is | Example |
|---|---|---|
| Procedure ID | Which compliance check was witnessed | `"AI-INF.1"` |
| Factor A, B, C | The three numeric values that form the proof | `1`, `1`, `0` |
| Model ID | The original (unhashed) model name | `"gpt-4o-2024-05-13"` |
| Prompt hash | SHA-256 hash of the input | `"a1b2c3..."` |
| Response hash | SHA-256 hash of the output | `"d4e5f6..."` |
| Latency | How long the inference took | `1240 ms` |
| Token counts | Input and output token usage | `512 in / 1024 out` |
| Full context | Provider, guardrails, system fingerprint | `{"provider": "openai", ...}` |
| Anchor fingerprint | The sealed SWT3 fingerprint | `"96b7d56c0245"` |
| Timestamp | When the anchor was created | `1712188800000` |

---

## 3. How the Handoff Works (Integration Guide)

The SWT3 SDK supports four methods for receiving your factors. You choose one (or more) when you set up the SDK. The handoff always fires after the anchor is sealed but before the clearing engine wipes the local copy.

### 3.1 Local File Export (Default)

The simplest option. The SDK writes your factor data to a JSON file on your local system. Works everywhere, including air-gapped environments.

**Python:**
```python
from swt3_ai import Witness

witness = Witness(
    tenant_id="ACME_DEFENSE",
    clearing_level=3,
    factor_handoff="file",
    factor_handoff_path="/secure/vault/factors/"
)
```

**TypeScript:**
```typescript
import { Witness } from "@tenova/swt3-ai";

const witness = new Witness({
  tenantId: "ACME_DEFENSE",
  clearingLevel: 3,
  factorHandoff: "file",
  factorHandoffPath: "/secure/vault/factors/"
});
```

Each anchor gets its own file, named by its fingerprint. Files should be stored on an encrypted filesystem with restricted permissions (owner read/write only).

### 3.2 Webhook (Push to Your Vault)

The SDK sends factor data to an HTTPS endpoint you control. This is ideal if you run a centralized secrets manager or compliance vault.

**Python:**
```python
witness = Witness(
    tenant_id="ACME_DEFENSE",
    clearing_level=3,
    factor_handoff="webhook",
    factor_handoff_url="https://vault.acme-defense.com/api/v1/factors",
    factor_handoff_headers={"Authorization": "Bearer <your-vault-token>"}
)
```

The SDK sends an HTTP POST with the factor data wrapped in an envelope that includes the handoff version, clearing level, tenant ID, anchor fingerprint, timestamp, factors, and metadata.

**Safety rules:**
- The SDK rejects plaintext HTTP. Your endpoint must use HTTPS (TLS 1.2 or higher).
- Your endpoint must respond with a success code within 5 seconds.
- If your endpoint is unreachable, the SDK retries once after 2 seconds. If that fails, the record goes to a local recovery queue and clearing does NOT proceed. Your factors are safe.

### 3.3 HashiCorp Vault

For organizations already using HashiCorp Vault, the SDK writes factors directly to a KV v2 secrets engine.

**Python:**
```python
witness = Witness(
    tenant_id="ACME_DEFENSE",
    clearing_level=3,
    factor_handoff="vault",
    factor_handoff_vault_addr="https://vault.acme-defense.com",
    factor_handoff_vault_token="hvs.your-token",
    factor_handoff_vault_path="secret/data/swt3/factors"
)
```

Each anchor is stored at its own path under the configured root. We recommend a dedicated Vault policy scoped to the SWT3 factor path so the SDK token can only write to that location.

### 3.4 Cloud KMS Envelope (AWS, Azure, GCP)

For organizations using cloud key management, the SDK encrypts factor data with a key you control before writing it locally. The encrypted file can then be stored anywhere because the data is unreadable without your KMS key.

**Python (AWS example):**
```python
witness = Witness(
    tenant_id="ACME_DEFENSE",
    clearing_level=3,
    factor_handoff="kms",
    factor_handoff_kms_key_id="arn:aws:kms:us-east-1:123456789:key/abc-def",
    factor_handoff_path="/secure/factors/"
)
```

The output is one encrypted file per anchor. Decryption requires access to the KMS key. Key rotation is managed by your cloud provider.

---

## 4. The Safety Guarantee

The handoff follows a strict sequence designed to prevent data loss:

1. The SDK receives the AI inference response
2. The SDK computes factors and creates the SWT3 fingerprint locally
3. The SDK seals the anchor (the fingerprint is now permanent)
4. **The SDK delivers your factors to the destination you chose**
5. **The SDK confirms delivery was successful**
6. Only then does the SDK apply clearing to the wire payload
7. The SDK sends the cleared payload to TeNova
8. The SDK wipes its local temporary memory

Steps 4 and 5 are the key. If the handoff fails for any reason (your vault is down, the disk is full, the network is unreachable), the SDK stops. It does not clear. It does not transmit. Your factors stay on your system until the handoff succeeds.

If a failure is permanent, the record is written to a local recovery queue. When the issue is resolved, you can replay the queue to complete all pending handoffs.

**The bottom line:** Your data is never destroyed until it is safely in your hands. That is a hard guarantee, not a best-effort policy.

---

## 5. How to Re-Verify an Anchor on Your Own

Once you hold the factors, you can verify any anchor at any time without contacting TeNova and without any network connection. The formula is:

```
fingerprint = SHA256("WITNESS:" + tenant_id + ":" + procedure_id + ":" + factor_a + ":" + factor_b + ":" + factor_c + ":" + timestamp_ms)
take the first 12 characters of the hex result
```

If the fingerprint you compute matches the one in the SWT3 Anchor string, the anchor is valid and has not been tampered with.

**Python:**
```python
import hashlib

def verify(tenant_id, procedure_id, fa, fb, fc, ts_ms, expected):
    msg = f"WITNESS:{tenant_id}:{procedure_id}:{fa}:{fb}:{fc}:{ts_ms}"
    return hashlib.sha256(msg.encode()).hexdigest()[:12] == expected
```

**TypeScript:**
```typescript
import { createHash } from "crypto";

function verify(tenantId: string, procId: string, fa: number, fb: number,
  fc: number, tsMs: number, expected: string): boolean {
  const msg = `WITNESS:${tenantId}:${procId}:${fa}:${fb}:${fc}:${tsMs}`;
  return createHash("sha256").update(msg).digest("hex").slice(0, 12) === expected;
}
```

This is the same algorithm used by the TeNova platform, the public verifier at sovereign.tenova.io/verify, and the libswt3 reference implementation. There is no proprietary step, no secret key, and no TeNova dependency.

---

## 6. Taking Care of Your Factors

TeNova does not tell you how to store your factors. That is your decision based on your security requirements and regulatory environment. But we strongly recommend the following:

**Treat factors like credentials.** At Clearing Level 3, if you lose them, no one can help you re-verify those anchors. Not TeNova. Not anyone.

**Encrypt them at rest.** Whether you use local files, a vault, or cloud storage, factors should always be encrypted. They contain the proof behind your compliance history.

**Test your recovery process.** Pick a random anchor from your ledger, pull the factors from your backup, and run the verification formula. If the result matches, your backup is healthy. Do this periodically.

**Store factors separately from the monitored system.** If your application server is compromised, your factor backup should not be on the same machine. The handoff is designed to push factors to a separate location for exactly this reason.

**Retention period.** Keep factors for at least as long as your applicable data retention requirements. This varies by industry and jurisdiction. Three years is common in federal environments. Seven years is typical in financial services. Some healthcare and legal contexts require indefinite retention. Check with your compliance team.

---

## 7. Frequently Asked Questions

**What happens if I start at Level 1 and later move to Level 3?**

The change applies to new anchors only. Anchors created at Level 1 keep whatever data was transmitted at Level 1. You cannot retroactively apply a higher clearing level to existing anchors. You can request deletion of stored metadata for prior anchors through a data removal request (see our Privacy Policy).

**Can TeNova see my factors at Level 3?**

TeNova receives three numbers and a 12-character fingerprint. We cannot determine what system, model, or inference those numbers relate to because all the context that would make them meaningful was cleared before transmission.

**What if my webhook is down during a handoff?**

The SDK retries once after a 2-second wait. If that fails, the record goes to a local recovery queue and clearing does not proceed. Your factors are safe. When your webhook recovers, replay the queue to finish the handoff.

**Can I use more than one handoff method at the same time?**

Yes. You can configure a local file export and a webhook, for example. Both run before clearing proceeds. This gives you redundancy.

**Is the handoff payload signed?**

The payload includes the SWT3 anchor fingerprint, which is a SHA-256 digest of the factors. If someone tampers with the factors during the handoff, the fingerprint will not match when you try to re-verify. That gives you tamper detection without needing a separate signing step.

**What if I need to correct an anchor?**

Anchors cannot be edited or deleted. If you discover a verdict was wrong, you create a revocation record that references the original anchor. The original stays in the chain for integrity, but it is marked as revoked with a reason and timestamp. See the ToS Clearing Addendum, Section F.

---

## 8. Implementation Status

| Method | Python SDK | TypeScript SDK | Status |
|---|---|---|---|
| Local File Export | v0.2.1 | v0.2.1 | Implemented |
| Webhook | v0.3.0 | v0.3.0 | Specification complete |
| HashiCorp Vault | v0.4.0 | v0.4.0 | Specification complete |
| Cloud KMS Envelope | v0.4.0 | v0.4.0 | Specification complete |

Local File Export is available now in both SDKs. Configure `factor_handoff="file"` and `factor_handoff_path` on the Witness constructor. The webhook, Vault, and KMS methods are specified and planned for future releases.

---

*Patent Pending. SWT3 and Sovereign Witness Traceability are trademarks of Tenable Nova LLC.*
