/**
 * SWT3 AI Witness SDK -- DeepSeek Adapter.
 *
 * Thin wrapper around the OpenAI adapter that tags records with
 * provider="deepseek". DeepSeek has no official TypeScript SDK;
 * users construct an OpenAI client with baseURL pointed at DeepSeek:
 *
 *   const client = new OpenAI({
 *     baseURL: "https://api.deepseek.com",
 *     apiKey: process.env.DEEPSEEK_API_KEY,
 *   });
 *
 * Auto-detected by witness.wrap() when baseURL contains "deepseek.com".
 *
 * DeepSeek R1 reasoning models return thinking tokens (<think>...</think>)
 * in the response content. These are hashed as part of the response.
 *
 * Deployers are responsible for assessing data residency and content
 * policy requirements when using the DeepSeek API.
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import { wrapOpenAI } from "./openai.js";
import type { Witness } from "../witness.js";

/**
 * Wrap an OpenAI client (pointed at DeepSeek) with transparent witnessing.
 *
 * Identical to the OpenAI adapter but tags all InferenceRecords with
 * provider="deepseek" for accurate lineage tracking.
 */
export function wrapDeepSeek(client: unknown, witness: Witness): unknown {
  return wrapOpenAI(client, witness, "deepseek");
}

export function isDeepSeekClient(client: unknown): boolean {
  return getBaseURL(client).includes("deepseek.com");
}

function getBaseURL(client: unknown): string {
  if (client === null || client === undefined) return "";
  const obj = client as Record<string, unknown>;
  const url = obj.baseURL ?? obj.base_url ?? "";
  return String(url);
}
