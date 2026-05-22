/**
 * SWT3 AI Witness SDK -- Ollama Adapter.
 *
 * Thin wrapper around the OpenAI adapter that tags records with
 * provider="ollama". Ollama uses an OpenAI-compatible API at
 * http://localhost:11434/v1.
 *
 * Auto-detected by witness.wrap() when base_url contains ":11434".
 */

import { wrapOpenAI } from "./openai.js";
import type { Witness } from "../witness.js";

export function wrapOllama(client: unknown, witness: Witness): unknown {
  return wrapOpenAI(client, witness, "ollama");
}

export function isOllamaClient(client: unknown): boolean {
  const baseURL = getBaseURL(client);
  return baseURL.includes(":11434");
}

function getBaseURL(client: unknown): string {
  if (client === null || client === undefined) return "";
  const obj = client as Record<string, unknown>;
  const url = obj.baseURL ?? obj.base_url ?? "";
  return String(url);
}
