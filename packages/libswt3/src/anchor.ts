// ── SWT3 Anchor Minting & Parsing ─────────────────────────────────
//
// Mint new SWT3 anchors and parse existing ones.
// Spec reference: SWT3-SPEC-v1.0.md, Sections 3 and 4

import { generateFingerprintFull } from "./fingerprint.js";
import type { AnchorComponents, MintParams, MintResult } from "./types.js";

/** Minimum number of hyphen-separated segments in a valid SWT3 anchor. */
const MIN_SEGMENTS = 8;

/**
 * Normalize a procedure ID for the anchor token.
 * Removes hyphens and dots: "SC-7.6" -> "SC76", "AC-2.1" -> "AC21"
 */
function normalizeProcedure(procedureId: string): string {
  return procedureId.replace(/[-._]/g, "");
}

/**
 * Mint a new SWT3 Witness Anchor.
 *
 * Generates the SHA-256 fingerprint from the provided factors and constructs
 * the canonical SWT3 token string.
 *
 * If `timestamp_ms` is not provided, the current time (Date.now()) is used.
 */
export function mintAnchor(params: MintParams): MintResult {
  const timestampMs = params.timestamp_ms ?? Date.now();
  const epoch = Math.floor(timestampMs / 1000);

  const { truncated, full } = generateFingerprintFull(
    params.procedure_id,
    params.tenant_id,
    params.factor_a,
    params.factor_b,
    params.factor_c,
    timestampMs,
  );

  const anchor = [
    "SWT3",
    params.tier,
    params.provider,
    params.uct,
    normalizeProcedure(params.procedure_id),
    params.verdict,
    String(epoch),
    truncated,
  ].join("-");

  return {
    anchor,
    fingerprint: truncated,
    fingerprint_full: full,
    epoch,
    timestamp_ms: timestampMs,
    factors: {
      procedure_id: params.procedure_id,
      tenant_id: params.tenant_id,
      factor_a: params.factor_a,
      factor_b: params.factor_b,
      factor_c: params.factor_c,
      timestamp_ms: timestampMs,
    },
  };
}

/**
 * Parse an SWT3 anchor token into its component fields.
 * Returns null if the token does not conform to SWT3 format.
 */
export function parseAnchor(token: string): AnchorComponents | null {
  const parts = token.trim().split("-");
  if (parts.length < MIN_SEGMENTS || parts[0] !== "SWT3") {
    return null;
  }

  return {
    protocol: "SWT3",
    tier: parts[1],
    provider: parts[2],
    uct: parts[3],
    procedure: parts[4],
    verdict: parts[5],
    epoch: parseInt(parts[parts.length - 2], 10),
    fingerprint: parts[parts.length - 1],
  };
}

/**
 * Extract the 12-character fingerprint from an SWT3 anchor token.
 * Returns null if the token cannot be parsed.
 */
export function extractFingerprint(token: string): string | null {
  const parts = token.trim().split("-");
  if (parts.length < MIN_SEGMENTS || parts[0] !== "SWT3") {
    return null;
  }
  return parts[parts.length - 1];
}
