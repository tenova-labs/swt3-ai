# Air-Gap Deployment Guide

> For disconnected, SCIF, and zero-egress environments.

## Overview

SWT3 is designed to operate in environments with no internet access. The SDK, the verification tools, and the entire compliance workflow can run on a machine that has never touched a network.

This guide covers three deployment patterns:

1. **Local Ledger Mode** - Zero egress, all anchors stay on your machine
2. **Delayed Sync** - Sneakernet transfer of anchors to an audit terminal
3. **Offline Verification** - Verify anchors with no network access

## 1. Local Ledger Mode

Use `factor_handoff` to write every anchor to local JSON files instead of transmitting to a remote endpoint.

**Python:**
```python
from swt3_ai import Witness
from openai import OpenAI

witness = Witness(
    endpoint="https://localhost",   # never contacted
    api_key="axm_local_placeholder",
    tenant_id="DISCONNECTED_ENCLAVE",
    clearing_level=3,               # classified: factors only
    factor_handoff="file",          # write to local filesystem
    factor_handoff_path="/secure/swt3-anchors/",
)

client = witness.wrap(OpenAI(base_url="http://gpu-node.local:8000/v1"))
```

**TypeScript:**
```typescript
import { Witness } from "@tenova/swt3-ai";
import OpenAI from "openai";

const witness = new Witness({
  endpoint: "https://localhost",
  apiKey: "axm_local_placeholder",
  tenantId: "DISCONNECTED_ENCLAVE",
  clearingLevel: 3,
  factorHandoff: "file",
  factorHandoffPath: "/secure/swt3-anchors/",
});

const client = witness.wrap(
  new OpenAI({ baseURL: "http://gpu-node.local:8000/v1" })
) as OpenAI;
```

Each inference produces a JSON file in the handoff directory:

```
/secure/swt3-anchors/
  c059eb5938c0.json
  0d446d2f9c39.json
  9b2923db0f62.json
```

Each file contains the full factor data needed for independent verification. Files are written with `0600` permissions (owner read/write only).

**What happens to the network flush:** The SDK will attempt to flush to the endpoint and fail silently. Payloads move to the dead-letter queue. Since `factor_handoff` runs *before* the network flush, your local copies are guaranteed to exist regardless of network state.

## 2. Delayed Sync (Sneakernet)

For environments where anchors must eventually reach an audit system but cannot do so in real-time.

### Export

Collect the handoff files from the disconnected machine:

```bash
# On the disconnected machine
tar czf swt3-anchors-$(date +%Y%m%d).tar.gz /secure/swt3-anchors/

# Transfer via approved media (USB, optical disc, cross-domain solution)
```

### Import

On the audit terminal (which may or may not have network access):

```bash
# Extract
tar xzf swt3-anchors-20260411.tar.gz

# Verify each anchor independently
for f in /secure/swt3-anchors/*.json; do
  node -e "
    const { verifyAnchor } = require('@tenova/libswt3');
    const data = require('$f');
    const result = verifyAnchor(data.anchor, data.factors);
    console.log(result.status, '$f');
  "
done
```

### Optional: Batch Upload

If the audit terminal has network access to the witness ledger:

```bash
# Combine individual anchor files into a batch payload
node -e "
  const fs = require('fs');
  const files = fs.readdirSync('/secure/swt3-anchors/')
    .filter(f => f.endsWith('.json'))
    .map(f => JSON.parse(fs.readFileSync('/secure/swt3-anchors/' + f)));
  console.log(JSON.stringify({ payloads: files }));
" > batch-upload.json

# Submit to the witness batch endpoint
curl -X POST https://sovereign.tenova.io/api/v1/witness/batch \
  -H "Authorization: Bearer axm_live_..." \
  -H "Content-Type: application/json" \
  -d @batch-upload.json
```

## 3. Offline Verification

The `libswt3` package provides verification tools that work with zero network access. All verification is pure SHA-256 math.

### Single Anchor Verification

```typescript
import { verifyAnchor } from "@tenova/libswt3";

const result = verifyAnchor(
  "SWT3-E-LOCAL-INF-AIINF1-PASS-1774800000-c059eb5938c0",
  {
    tenantId: "DISCONNECTED_ENCLAVE",
    procedureId: "AI-INF.1",
    factorA: 1,
    factorB: 1,
    factorC: 0,
    timestampMs: 1774800000000,
  }
);

console.log(result.status);
// "CERTIFIED TRUTH" if fingerprint matches
// "TAMPERED" if fingerprint does not match
```

### Batch Verification

```typescript
import { verifyEnclave } from "@tenova/libswt3";

const entries = anchors.map(a => ({
  anchor: a.anchor_token,
  factors: a.factors,
}));

const result = verifyEnclave(entries);
console.log(`Verified: ${result.integrity.verified}/${result.integrity.total}`);
```

### Command-Line Verification

```bash
# Verify a single anchor (no network required)
npx swt3-verify "SWT3-E-LOCAL-INF-AIINF1-PASS-1774800000-c059eb5938c0" \
  --tenant DISCONNECTED_ENCLAVE \
  --procedure AI-INF.1 \
  --factors 1,1,0 \
  --timestamp 1774800000000
```

## STIG and KEV Updates (Pulse Bundles)

For disconnected environments that need updated STIG benchmarks or CISA KEV feeds:

```bash
# On a connected machine: generate a signed pulse bundle
axiom pulse --generate --output /media/usb/axiom-pulse-$(date +%Y%m%d).pulse

# On the disconnected machine: verify and load the bundle
axiom pulse --verify /media/usb/axiom-pulse-20260411.pulse
axiom pulse --load /media/usb/axiom-pulse-20260411.pulse
```

Pulse bundles contain SHA-256 manifests for integrity verification. The `--verify` step checks all file hashes before loading.

## Security Considerations

- **Level 3 is recommended** for air-gapped deployments. At Level 3, only numeric factors and a hashed model ID are present in the anchor. No metadata, no provider names, no guardrail names.
- **Factor handoff files** contain the full uncleared data. Protect them with filesystem permissions and encryption at rest appropriate to your classification level.
- **USB transfer** of anchor files is acceptable because the files contain only hashes and numeric factors (at Level 3). No prompt or response content is present in any file at any clearing level.
- **The verification formula is public.** Anyone can verify an anchor with the factors and a SHA-256 implementation. There is no secret key, no proprietary algorithm, and no vendor dependency in the verification path.

## Related Documents

- [Data Flow and Privacy Architecture](data-flow.md) - What crosses the network boundary at each clearing level
- [Clearing & Data Sovereignty Addendum](https://sovereign.tenova.io/terms/clearing-addendum) - Legal terms and shared responsibility
- [Factor Handoff Protocol](https://sovereign.tenova.io/docs/factor-handoff-protocol.html) - Custody transfer specification

---

*SWT3: Sovereign Witness Traceability. We don't run your models. We witness them.*
