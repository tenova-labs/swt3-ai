// ── SWT3 Anchor Verification ──────────────────────────────────────
//
// Verify that evidence factors match their claimed anchor fingerprint.
// This is the core trust primitive: no database, no network — just math.
//
// Spec reference: SWT3-SPEC-v1.0.md, Section 6

import { extractFingerprint } from "./anchor.js";
import { computeEnclaveSignature, generateFingerprint } from "./fingerprint.js";
import { getMerkleRoot } from "./merkle.js";
import type { EnclaveIntegrity, Factors, VerifyResult } from "./types.js";

/**
 * Verify an SWT3 anchor against its evidence factors.
 *
 * This function requires NO database access. Given the anchor token and the
 * original factors, it recomputes the SHA-256 fingerprint and compares it
 * to the fingerprint embedded in the anchor.
 *
 * This is the function you hand to a C3PAO auditor.
 *
 * @param anchor - The full SWT3 anchor token string
 * @param factors - The original evidence factors used to mint the anchor
 * @returns Verification result with status and fingerprint comparison
 */
export function verifyAnchor(anchor: string, factors: Factors): VerifyResult {
  const claimed = extractFingerprint(anchor);
  if (claimed === null) {
    return {
      verified: false,
      status: "INVALID TOKEN",
      claimed_fingerprint: "",
      recomputed_fingerprint: "",
    };
  }

  const recomputed = generateFingerprint(
    factors.procedure_id,
    factors.tenant_id,
    factors.factor_a,
    factors.factor_b,
    factors.factor_c,
    factors.timestamp_ms,
  );

  const verified = claimed === recomputed;

  return {
    verified,
    status: verified ? "CERTIFIED TRUTH" : "TAMPERED",
    claimed_fingerprint: claimed,
    recomputed_fingerprint: recomputed,
    factors,
  };
}

/**
 * Batch-verify a set of anchor/factor pairs and compute enclave integrity.
 *
 * Returns per-anchor results plus the Enclave Integrity Signature — a single
 * SHA-256 digest that represents the entire enclave's verification state.
 * Same anchors in same state = same signature, always.
 *
 * @param entries - Array of { anchor, factors } pairs
 * @returns Per-anchor results plus enclave-level integrity summary
 */
export function verifyEnclave(
  entries: Array<{ anchor: string; factors: Factors }>,
): { results: VerifyResult[]; integrity: EnclaveIntegrity } {
  const results: VerifyResult[] = [];
  const fingerprints: string[] = [];
  let verified = 0;
  let tampered = 0;

  for (const entry of entries) {
    const result = verifyAnchor(entry.anchor, entry.factors);
    results.push(result);
    fingerprints.push(result.recomputed_fingerprint);

    if (result.verified) {
      verified++;
    } else {
      tampered++;
    }
  }

  const enclave_signature = fingerprints.length > 0
    ? computeEnclaveSignature(fingerprints)
    : "";

  const integrity_digest = fingerprints.length > 0
    ? getMerkleRoot(fingerprints)
    : "";

  return {
    results,
    integrity: {
      total: entries.length,
      verified,
      tampered,
      enclave_signature,
      integrity_digest,
    },
  };
}
