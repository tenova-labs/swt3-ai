/**
 * SWT3 AI Witness SDK - Payload Signing.
 *
 * Supports HMAC-SHA256 (default) and ML-DSA-65 (FIPS 204, post-quantum).
 * The signature input is deterministic and must match the Python SDK.
 *
 * ML-DSA-65 requires: npm install @noble/post-quantum
 */

import { createHmac } from "node:crypto";
import { createRequire } from "node:module";

// ── Algorithm Constants ──────────────────────────────────────────────

export const SIGNING_ALGORITHM_HMAC = "hmac-sha256" as const;
export const SIGNING_ALGORITHM_MLDSA = "ml-dsa-65" as const;
export type SigningAlgorithm = typeof SIGNING_ALGORITHM_HMAC | typeof SIGNING_ALGORITHM_MLDSA;
export const VALID_SIGNING_ALGORITHMS = new Set<string>([SIGNING_ALGORITHM_HMAC, SIGNING_ALGORITHM_MLDSA]);
export const DEFAULT_SIGNING_ALGORITHM: SigningAlgorithm = SIGNING_ALGORITHM_HMAC;

// ── Message Builder ──────────────────────────────────────────────────

function buildMessage(anchorFingerprint: string, agentId?: string): string {
  return agentId ? `${anchorFingerprint}:${agentId}` : anchorFingerprint;
}

// ── HMAC-SHA256 ──────────────────────────────────────────────────────

function signHmac(signingKey: string, message: string): string {
  return createHmac("sha256", signingKey)
    .update(message, "utf-8")
    .digest("hex");
}

// ── ML-DSA-65 (FIPS 204) ────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let _mlDsa: any = null;

type MlDsaModule = { ml_dsa65: { keygen: (seed?: Uint8Array) => { secretKey: Uint8Array; publicKey: Uint8Array }; sign: (msg: Uint8Array, secretKey: Uint8Array) => Uint8Array; verify: (sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array) => boolean } };

function getMlDsa(): MlDsaModule {
  if (_mlDsa) return _mlDsa;
  try {
    // Use createRequire for ESM-compatible sync import of @noble/post-quantum
    const esmRequire = createRequire(import.meta.url);
    _mlDsa = esmRequire("@noble/post-quantum/ml-dsa.js");
    return _mlDsa!;
  } catch {
    throw new Error(
      "ML-DSA-65 signing requires @noble/post-quantum. " +
      "Install with: npm install @noble/post-quantum",
    );
  }
}

/**
 * Generate an ML-DSA-65 key pair from a random 32-byte seed.
 * @returns { seed: Uint8Array, publicKey: Uint8Array } - seed is 32 bytes, publicKey is 1952 bytes.
 */
export function generateMldsaKeypair(): { seed: Uint8Array; publicKey: Uint8Array } {
  const { ml_dsa65 } = getMlDsa();
  const seed = globalThis.crypto?.getRandomValues?.(new Uint8Array(32))
    ?? require("node:crypto").randomBytes(32);
  const kp = ml_dsa65.keygen(seed);
  return { seed, publicKey: kp.publicKey };
}

function signMlDsa(seedHex: string, message: string): string {
  const { ml_dsa65 } = getMlDsa();
  const seed = hexToBytes(seedHex);
  // Expand seed to full 4032-byte secret key via deterministic keygen
  const kp = ml_dsa65.keygen(seed);
  const msgBytes = new TextEncoder().encode(message);
  const sig = ml_dsa65.sign(msgBytes, kp.secretKey);
  return bytesToHex(sig);
}

/**
 * Verify an ML-DSA-65 signature.
 * @param publicKeyHex - Hex-encoded public key (1952 bytes = 3904 hex chars).
 * @param message - The canonical message that was signed.
 * @param signatureHex - Hex-encoded ML-DSA-65 signature.
 * @returns True if valid, false otherwise.
 */
export function verifyMldsa(
  publicKeyHex: string,
  message: string,
  signatureHex: string,
): boolean {
  const { ml_dsa65 } = getMlDsa();
  const publicKey = hexToBytes(publicKeyHex);
  const msgBytes = new TextEncoder().encode(message);
  const sig = hexToBytes(signatureHex);
  try {
    return ml_dsa65.verify(sig, msgBytes, publicKey);
  } catch {
    return false;
  }
}

// ── Hex Utilities ────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const len = hex.length;
  const bytes = new Uint8Array(len / 2);
  for (let i = 0; i < len; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// ── Public API ───────────────────────────────────────────────────────

/**
 * Sign an anchor fingerprint.
 *
 * @param signingKey - For hmac-sha256: shared secret string.
 *                     For ml-dsa-65: hex-encoded 32-byte seed.
 * @param anchorFingerprint - The 12-char hex fingerprint to sign.
 * @param agentId - Optional agent identifier to bind to the signature.
 * @param algorithm - "hmac-sha256" (default) or "ml-dsa-65".
 * @returns Hex-encoded signature string.
 *
 * Message format:
 *   "{fingerprint}:{agentId}" if agentId is provided
 *   "{fingerprint}"           if agentId is undefined
 */
export function signPayload(
  signingKey: string,
  anchorFingerprint: string,
  agentId?: string,
  algorithm: SigningAlgorithm = DEFAULT_SIGNING_ALGORITHM,
): string {
  if (!VALID_SIGNING_ALGORITHMS.has(algorithm)) {
    throw new Error(
      `Unknown signing algorithm: '${algorithm}'. ` +
      `Valid: ${[...VALID_SIGNING_ALGORITHMS].sort().join(", ")}`,
    );
  }

  const message = buildMessage(anchorFingerprint, agentId);

  if (algorithm === SIGNING_ALGORITHM_HMAC) {
    return signHmac(signingKey, message);
  }

  // ML-DSA-65: signingKey is hex-encoded private key bytes
  return signMlDsa(signingKey, message);
}
