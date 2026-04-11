/**
 * @tenova/swt3-ai — SWT3 AI Witness SDK for TypeScript/Node.js
 *
 * Usage:
 *   import { Witness } from "@tenova/swt3-ai";
 *   import OpenAI from "openai";
 *
 *   const witness = new Witness({
 *     endpoint: "https://sovereign.tenova.io",
 *     apiKey: "axm_live_...",
 *     tenantId: "YOUR_TENANT_ID",
 *   });
 *
 *   const client = witness.wrap(new OpenAI()) as OpenAI;
 */

export { Witness } from "./witness.js";
export type { WitnessOptions } from "./witness.js";
export type {
  WitnessConfig,
  WitnessPayload,
  WitnessReceipt,
  InferenceRecord,
  BatchResponse,
} from "./types.js";
export { mintFingerprint, sha256Truncated, sha256Hex, timestampMs } from "./fingerprint.js";
export { extractPayloads } from "./clearing.js";
export { signPayload } from "./signing.js";
