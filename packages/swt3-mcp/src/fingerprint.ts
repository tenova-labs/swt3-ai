/**
 * SWT3 MCP Server — Fingerprint minting and SHA-256 utilities.
 *
 * Inlined from @tenova/swt3-ai to keep this package self-contained.
 * The fingerprint formula is LOCKED:
 *   SHA256("WITNESS:{tenant}:{proc}:{fa}:{fb}:{fc}:{ts_ms}").hex().slice(0, 12)
 */

import { createHash, createHmac } from "crypto";

export function sha256Hex(data: string, length: number = 64): string {
  return createHash("sha256").update(data, "utf-8").digest("hex").slice(0, length);
}

export function sha256Truncated(data: string, length: number = 16): string {
  return sha256Hex(data, length);
}

function numStr(v: number): string {
  return String(v);
}

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

export function timestampMs(): [number, number] {
  const ts = Date.now();
  const epoch = Math.floor(ts / 1000);
  return [ts, epoch];
}

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
