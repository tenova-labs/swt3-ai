/**
 * SWT3 AI Witness SDK -- Groq Adapter.
 *
 * Thin wrapper around the OpenAI adapter that tags records with
 * provider="groq". Groq uses an OpenAI-compatible API
 * (chat.completions.create).
 *
 * Auto-detected by witness.wrap() when the constructor name is "Groq"
 * or baseURL contains "groq.com".
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import { wrapOpenAI } from "./openai.js";
import type { Witness } from "../witness.js";

/**
 * Wrap a Groq client with transparent witnessing.
 *
 * Identical to the OpenAI adapter but tags all InferenceRecords with
 * provider="groq" for accurate lineage tracking.
 */
export function wrapGroq(client: unknown, witness: Witness): unknown {
  return wrapOpenAI(client, witness, "groq");
}

export function isGroqClient(client: unknown): boolean {
  if (client === null || client === undefined) return false;
  const proto = Object.getPrototypeOf(client);
  const name = proto?.constructor?.name ?? "";
  return name === "Groq";
}

export function isGroqURL(client: unknown): boolean {
  return getBaseURL(client).includes("groq.com");
}

function getBaseURL(client: unknown): string {
  if (client === null || client === undefined) return "";
  const obj = client as Record<string, unknown>;
  const url = obj.baseURL ?? obj.base_url ?? "";
  return String(url);
}
