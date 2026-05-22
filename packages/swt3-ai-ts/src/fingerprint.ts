/**
 * SWT3 AI Witness SDK — Fingerprint minting and SHA-256 utilities.
 *
 * The fingerprint formula MUST match the Python SDK and the ingestion endpoint:
 *   SHA256("WITNESS:{tenant}:{proc}:{fa}:{fb}:{fc}:{ts_ms}").hex().slice(0, 12)
 *
 * Uses Node.js crypto module for server-side compatibility.
 */

import { createHash } from "crypto";

/**
 * SHA-256 hash a string, return first `length` hex characters.
 */
export function sha256Hex(data: string, length: number = 64): string {
  return createHash("sha256").update(data, "utf-8").digest("hex").slice(0, length);
}

/**
 * SHA-256 hash a string, return first 16 hex chars (prompt/response hashing).
 */
export function sha256Truncated(data: string, length: number = 16): string {
  return sha256Hex(data, length);
}

/**
 * Format a numeric factor for the fingerprint formula.
 *
 * CRITICAL: Must match Python's behavior exactly.
 * Integer-valued floats → "1" (no decimal), true floats → "1.5"
 * JavaScript JSON.stringify(1) → "1", JSON.stringify(1.5) → "1.5"
 * so we can use String() which matches.
 */
function numStr(v: number): string {
  if (Number.isInteger(v)) {
    return String(v);
  }
  return String(v);
}

/**
 * Mint an SWT3 anchor fingerprint.
 *
 * This MUST match the endpoint's `validateFingerprint()` and the Python SDK's
 * `mint_fingerprint()`:
 *   SHA256("WITNESS:{tenant}:{proc}:{fa}:{fb}:{fc}:{ts_ms}").hex().slice(0, 12)
 */
export function mintFingerprint(
  tenantId: string,
  procedureId: string,
  factorA: number,
  factorB: number,
  factorC: number,
  timestampMs: number,
): string {
  const fpInput =
    `WITNESS:${tenantId}:${procedureId}` +
    `:${numStr(factorA)}:${numStr(factorB)}:${numStr(factorC)}` +
    `:${timestampMs}`;
  return createHash("sha256").update(fpInput, "utf-8").digest("hex").slice(0, 12);
}

/**
 * Return [millisecond timestamp, epoch seconds] for anchor minting.
 */
export function timestampMs(): [number, number] {
  const ts = Date.now();
  const epoch = Math.floor(ts / 1000);
  return [ts, epoch];
}
