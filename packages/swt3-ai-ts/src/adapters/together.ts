/**
 * SWT3 AI Witness SDK -- Together AI Adapter.
 *
 * Thin wrapper around the OpenAI adapter that tags records with
 * provider="together". Together AI uses an OpenAI-compatible API.
 *
 * Together AI has no first-party TypeScript SDK. Users typically
 * construct an OpenAI client with baseURL pointed at Together:
 *
 *   const client = new OpenAI({
 *     baseURL: "https://api.together.xyz/v1",
 *     apiKey: process.env.TOGETHER_API_KEY,
 *   });
 *
 * Auto-detected by witness.wrap() when baseURL contains "together.xyz"
 * or constructor name is "Together".
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import { wrapOpenAI } from "./openai.js";
import type { Witness } from "../witness.js";

/**
 * Wrap a Together AI client with transparent witnessing.
 *
 * Identical to the OpenAI adapter but tags all InferenceRecords with
 * provider="together" for accurate lineage tracking.
 */
export function wrapTogether(client: unknown, witness: Witness): unknown {
  return wrapOpenAI(client, witness, "together");
}

export function isTogetherClient(client: unknown): boolean {
  if (client === null || client === undefined) return false;
  const proto = Object.getPrototypeOf(client);
  const name = proto?.constructor?.name ?? "";
  return name === "Together";
}

export function isTogetherURL(client: unknown): boolean {
  return getBaseURL(client).includes("together.xyz");
}

function getBaseURL(client: unknown): string {
  if (client === null || client === undefined) return "";
  const obj = client as Record<string, unknown>;
  const url = obj.baseURL ?? obj.base_url ?? "";
  return String(url);
}
