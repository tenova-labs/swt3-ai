/**
 * SWT3 AI Witness SDK - Payload Signing (HMAC-SHA256).
 *
 * Signs anchor fingerprints to prove which SDK instance minted them.
 * The signature input is deterministic and must match the Python SDK.
 */

import { createHmac } from "node:crypto";

/**
 * Sign an anchor fingerprint with HMAC-SHA256.
 *
 * @param signingKey - Shared secret between SDK and server.
 * @param anchorFingerprint - The 12-char hex fingerprint to sign.
 * @param agentId - Optional agent identifier to bind to the signature.
 * @returns 64-char hex HMAC-SHA256 digest.
 *
 * Message format:
 *   "{fingerprint}:{agentId}" if agentId is provided
 *   "{fingerprint}"           if agentId is undefined
 */
export function signPayload(
  signingKey: string,
  anchorFingerprint: string,
  agentId?: string,
): string {
  const message = agentId
    ? `${anchorFingerprint}:${agentId}`
    : anchorFingerprint;
  return createHmac("sha256", signingKey)
    .update(message, "utf-8")
    .digest("hex");
}
