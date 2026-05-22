// ── SWT3 Fingerprint Engine ────────────────────────────────────────
//
// Core SHA-256 hashing logic for the SWT3 protocol.
// Zero dependencies — uses Node.js built-in crypto module.
//
// Spec reference: SWT3-SPEC-v1.0.md, Section 4

import { createHash } from "node:crypto";

/** Standard SWT3 fingerprint truncation length (hex characters). */
export const FINGERPRINT_LENGTH = 12;

/**
 * Construct the canonical fingerprint input string.
 *
 * Format: "{procedure_id}:{tenant_id}:{factor_a}:{factor_b}:{factor_c}:{timestamp_ms}"
 *
 * All numeric values are converted to their decimal string representation.
 * This matches the algorithm used across all SWT3 SDK implementations.
 */
export function buildFingerprintInput(
  procedureId: string,
  tenantId: string,
  factorA: number,
  factorB: number,
  factorC: number,
  timestampMs: number,
): string {
  return [
    procedureId,
    tenantId,
    String(factorA),
    String(factorB),
    String(factorC),
    String(timestampMs),
  ].join(":");
}

/**
 * Compute the full SHA-256 digest of a fingerprint input string.
 * Returns the complete 64-character hexadecimal digest.
 */
export function sha256(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/**
 * Generate a truncated SWT3 fingerprint (12 hex chars) from evidence factors.
 *
 * This is the core algorithm of the SWT3 protocol:
 *   SHA-256(procedure_id:tenant_id:factor_a:factor_b:factor_c:timestamp_ms)[0:12]
 */
export function generateFingerprint(
  procedureId: string,
  tenantId: string,
  factorA: number,
  factorB: number,
  factorC: number,
  timestampMs: number,
): string {
  const input = buildFingerprintInput(procedureId, tenantId, factorA, factorB, factorC, timestampMs);
  return sha256(input).slice(0, FINGERPRINT_LENGTH);
}

/**
 * Generate both truncated (12-char) and full (64-char) fingerprints.
 * The full digest is recommended for storage alongside the anchor.
 */
export function generateFingerprintFull(
  procedureId: string,
  tenantId: string,
  factorA: number,
  factorB: number,
  factorC: number,
  timestampMs: number,
): { truncated: string; full: string } {
  const input = buildFingerprintInput(procedureId, tenantId, factorA, factorB, factorC, timestampMs);
  const digest = sha256(input);
  return {
    truncated: digest.slice(0, FINGERPRINT_LENGTH),
    full: digest,
  };
}

/**
 * Compute the Enclave Integrity Signature from a set of fingerprints.
 * Sorts fingerprints lexicographically, joins with colons, and returns
 * the full SHA-256 digest.
 *
 * Spec reference: SWT3-SPEC-v1.0.md, Section 6.3
 */
export function computeEnclaveSignature(fingerprints: string[]): string {
  const sorted = [...fingerprints].sort();
  const chain = sorted.join(":");
  return sha256(chain);
}
