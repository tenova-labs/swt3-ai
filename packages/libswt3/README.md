# libswt3

**SWT3 (Sovereign Witness Traceability) Protocol - Reference Implementation**

An open, zero-dependency library for minting and verifying cryptographic compliance evidence anchors.

SWT3 enables any party - auditor, assessor, GRC platform, or CI/CD pipeline - to independently verify that compliance evidence has not been altered since the moment it was witnessed.

The "3" in SWT3 represents the three phases of the evidence lifecycle:
1. **Provenance** - Evidence collection and factor capture at the point of observation
2. **Verification** - SHA-256 fingerprint computation binding factors to an immutable anchor
3. **Clearing** - Independent third-party validation that evidence matches its anchor

## Why SWT3?

In 2026, the GRC industry has a trust gap: compliance tools generate reports, but auditors have no way to verify the underlying evidence hasn't been modified between collection and assessment.

SWT3 solves this with a simple primitive: **a SHA-256 fingerprint that binds evidence factors to a verdict at a specific point in time.**

- **Open Standard:** Any tool can mint and verify SWT3 anchors
- **Zero Dependencies:** Pure Node.js crypto, nothing to audit
- **OSCAL-Native:** Anchors embed directly into NIST Assessment Results
- **Auditor-Verifiable:** Give your C3PAO the `swt3-verify` CLI and the factors - they can check your work independently

## Install

```bash
npm install @tenova/libswt3
```

## Quick Start

### Mint an Anchor

```typescript
import { mintAnchor } from "@tenova/libswt3";

const result = mintAnchor({
  tier: "E",
  provider: "AWS",
  uct: "NET",
  procedure_id: "SC-7.6",
  tenant_id: "ACME_DEFENSE",
  verdict: "PASS",
  factor_a: 4,    // expected open ports
  factor_b: 3,    // observed open ports
  factor_c: -1,   // delta
});

console.log(result.anchor);
// SWT3-E-AWS-NET-SC76-PASS-1773316622-96b7d56c0245

console.log(result.fingerprint);
// 96b7d56c0245

console.log(result.fingerprint_full);
// 96b7d56c0245... (64 chars, store this for maximum fidelity)
```

### Verify an Anchor

```typescript
import { verifyAnchor } from "@tenova/libswt3";

const result = verifyAnchor(
  "SWT3-E-AWS-NET-SC76-PASS-1773316622-96b7d56c0245",
  {
    procedure_id: "SC-7.6",
    tenant_id: "ACME_DEFENSE",
    factor_a: 4,
    factor_b: 3,
    factor_c: -1,
    timestamp_ms: 1773316622000,
  }
);

if (result.verified) {
  console.log("CERTIFIED TRUTH - evidence integrity confirmed");
} else {
  console.log("TAMPERED - evidence has been modified");
}
```

### Verify an Entire Enclave

```typescript
import { verifyEnclave } from "@tenova/libswt3";

const { results, integrity } = verifyEnclave([
  { anchor: "SWT3-...", factors: { /* ... */ } },
  { anchor: "SWT3-...", factors: { /* ... */ } },
]);

console.log(`${integrity.verified}/${integrity.total} verified`);
console.log(`Enclave Signature: ${integrity.enclave_signature}`);
// Same anchors + same state = same signature. Always.
```

## CLI: swt3-verify

The auditor's tool. No database, no API keys, no vendor lock-in - just math.

```bash
# Install globally
npm install -g @tenova/libswt3

# Verify a single evidence factor
swt3-verify --file evidence.json

# Verify with separate anchor and factors
swt3-verify --anchor SWT3-E-AWS-NET-SC76-PASS-1773316622-96b7d56c0245 \
           --evidence factors.json

# Batch verify an enclave
swt3-verify --file enclave-export.json --batch

# JSON output for CI/CD pipelines
swt3-verify --file evidence.json --json
```

### Evidence Factor JSON Format

```json
{
  "swt3_version": "1.0",
  "anchor": "SWT3-E-AWS-NET-SC76-PASS-1773316622-96b7d56c0245",
  "factors": {
    "procedure_id": "SC-7.6",
    "tenant_id": "ACME_DEFENSE",
    "factor_a": 4,
    "factor_b": 3,
    "factor_c": -1,
    "timestamp_ms": 1773316622000
  },
  "verdict": "PASS",
  "witnessed_at": "2026-03-18T12:00:00Z"
}
```

## For GRC Platforms (RegScale, FutureFeed, Apptega, etc.)

SWT3 is designed for ingestion. To verify Axiom-generated evidence in your platform:

1. **Parse** the SWT3 anchor from the evidence payload
2. **Extract** the factors (procedure_id, tenant_id, factor_a/b/c, timestamp_ms)
3. **Call** `verifyAnchor(anchor, factors)` - returns `CERTIFIED TRUTH` or `TAMPERED`
4. **Map** to your internal control model using the CMMC Practice ID or NIST control ID

That's it. ~50 lines of code in any language with SHA-256 support.

### OSCAL Integration

SWT3 anchors embed natively into NIST OSCAL Assessment Results:

```json
{
  "observations": [{
    "methods": ["TEST"],
    "relevant-evidence": [{
      "description": "SWT3 Witness Anchor: SWT3-E-AWS-NET-SC76-PASS-..."
    }],
    "props": [
      { "name": "swt3-anchor", "value": "SWT3-E-AWS-NET-SC76-PASS-..." },
      { "name": "swt3-fingerprint", "value": "96b7d56c0245" }
    ]
  }]
}
```

See `SWT3-SPEC-v1.0.md` Section 7 for complete OSCAL mapping.

## The Fingerprint Algorithm

```
Input:  "{procedure_id}:{tenant_id}:{factor_a}:{factor_b}:{factor_c}:{timestamp_ms}"
Hash:   SHA-256(UTF-8 encoded input)
Output: First 12 hex characters of the digest
```

48 bits of entropy. Deterministic. Cross-platform verifiable. The same input in Python, TypeScript, Go, or Rust produces the identical fingerprint.

## API Reference

### `mintAnchor(params: MintParams): MintResult`
Mint a new SWT3 Witness Anchor from evidence factors.

### `verifyAnchor(anchor: string, factors: Factors): VerifyResult`
Verify an anchor against its original factors. No database required.

### `verifyEnclave(entries: { anchor, factors }[]): { results, integrity }`
Batch-verify and compute Enclave Integrity Signature.

### `generateFingerprint(procedureId, tenantId, factorA, factorB, factorC, timestampMs): string`
Compute the 12-char truncated SHA-256 fingerprint directly.

### `parseAnchor(token: string): AnchorComponents | null`
Parse an SWT3 token into its component fields.

### `computeEnclaveSignature(fingerprints: string[]): string`
Compute the Enclave Integrity Signature from a set of fingerprints.

## Protocol Specification

The full SWT3 Protocol Specification v1.0 is included in this package:
[`SWT3-SPEC-v1.0.md`](./SWT3-SPEC-v1.0.md)

## Support the Standard

If you believe AI systems should prove they followed the rules, [give us a star](https://github.com/tenova-labs/swt3-ai). Every star signals that the industry is ready for an accountability standard.

## License

*TeNova: Defining the AI Accountability Standard. One protocol. Zero Integrity Debt. Total Sovereignty.*

Apache 2.0 - Copyright (c) 2026 Tenable Nova LLC. Patent pending.
