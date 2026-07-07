/**
 * SWT3 AI Witness SDK -- Ollama Adapter.
 *
 * Thin wrapper around the OpenAI adapter that tags records with
 * provider="ollama". Ollama uses an OpenAI-compatible API at
 * http://localhost:11434/v1.
 *
 * Compatible with Ollama 0.30+ (GGUF models, structured outputs via
 * OpenAI-compatible API). Model names with tags and quantization suffixes
 * are preserved as-is (e.g., "llama3.2:latest", "qwen2.5:7b-instruct-q4_0").
 *
 * Auto-detected by witness.wrap() when base_url contains ":11434".
 */

import { wrapOpenAI } from "./openai.js";
import type { Witness } from "../witness.js";

/**
 * Wrap an OpenAI client (pointed at Ollama) with transparent witnessing.
 *
 * Identical to the OpenAI adapter but tags all InferenceRecords with
 * provider="ollama" for accurate lineage tracking.
 */
export function wrapOllama(client: unknown, witness: Witness): unknown {
  return wrapOpenAI(client, witness, "ollama");
}

export function isOllamaClient(client: unknown): boolean {
  const baseURL = getBaseURL(client);
  return baseURL.includes(":11434");
}

/**
 * Normalize an Ollama model name, preserving GGUF tags and quantization.
 *
 * Ollama 0.30+ model names include tags and quantization suffixes that
 * are significant for lineage tracking:
 *   "llama3.2:latest"           -> "llama3.2:latest"
 *   "qwen2.5:7b-instruct-q4_0" -> "qwen2.5:7b-instruct-q4_0"
 *   "mistral"                   -> "mistral"
 */
export function normalizeOllamaModel(model: string): string {
  return model?.trim() || "unknown";
}

function getBaseURL(client: unknown): string {
  if (client === null || client === undefined) return "";
  const obj = client as Record<string, unknown>;
  const url = obj.baseURL ?? obj.base_url ?? "";
  return String(url);
}
