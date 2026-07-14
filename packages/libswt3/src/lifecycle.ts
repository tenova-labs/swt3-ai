// ── SWT3 Lifecycle Chain Utilities (v6.0) ────────────────────────────
//
// Deterministic chain ID generation and validation for multi-anchor
// lifecycle sequences. Protocol-locked once shipped.
//
// Chain ID format: LC-{SHA256("LIFECYCLE:{tenant}:{proc}:{fp}:{ts}").hex()[:16]}

import { sha256, FINGERPRINT_LENGTH } from "./fingerprint.js";
import { LIFECYCLE_CHAIN_STAGES, type LifecycleStage } from "./types.js";

/** Chain ID prefix. */
const CHAIN_ID_PREFIX = "LC-";

/** Chain ID hex length (after prefix). */
const CHAIN_ID_HEX_LENGTH = 16;

/** Regex for validating a lifecycle chain ID. */
const CHAIN_ID_PATTERN = /^LC-[0-9a-f]{16}$/;

/**
 * Generate a deterministic lifecycle chain ID.
 *
 * Formula: LC-{SHA256("LIFECYCLE:{tenantId}:{procedureId}:{initiatorFingerprint}:{timestampMs}").hex()[:16]}
 *
 * The initiatorFingerprint is the 12-char fingerprint of the first anchor
 * in the chain (the "initiated" anchor). This ties the chain ID to a
 * specific, verifiable event.
 */
export function generateLifecycleChainId(
  tenantId: string,
  procedureId: string,
  initiatorFingerprint: string,
  timestampMs: number,
): string {
  const input = `LIFECYCLE:${tenantId}:${procedureId}:${initiatorFingerprint}:${timestampMs}`;
  const digest = sha256(input);
  return `${CHAIN_ID_PREFIX}${digest.slice(0, CHAIN_ID_HEX_LENGTH)}`;
}

/**
 * Validate that a string is a well-formed lifecycle chain ID.
 * Returns true if the string matches LC- followed by exactly 16 hex chars.
 */
export function isLifecycleChainId(id: string): boolean {
  return CHAIN_ID_PATTERN.test(id);
}

/**
 * Validate that a string is a canonical lifecycle stage.
 * Returns true if the stage is one of the 6 defined stages.
 */
export function validateLifecycleStage(stage: string): stage is LifecycleStage {
  return stage in LIFECYCLE_CHAIN_STAGES;
}

/**
 * Check if a lifecycle stage is terminal (no further anchors expected).
 */
export function isTerminalStage(stage: LifecycleStage): boolean {
  return stage === "resolved" || stage === "abandoned" || stage === "superseded";
}

/**
 * Validate a 12-char hex fingerprint (used for lifecycle_parent).
 */
export function isValidFingerprint(fp: string): boolean {
  return typeof fp === "string" && new RegExp(`^[0-9a-f]{${FINGERPRINT_LENGTH}}$`).test(fp);
}
