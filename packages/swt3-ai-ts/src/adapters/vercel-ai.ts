/**
 * SWT3 AI Witness SDK — Vercel AI SDK Integration.
 *
 * Provides an `onFinish` callback factory for the Vercel AI SDK's
 * `streamText()` and `generateText()` functions. This is the most
 * idiomatic integration for Next.js / React developers.
 *
 * Usage:
 *   import { streamText } from "ai";
 *   import { openai } from "@ai-sdk/openai";
 *
 *   const result = await streamText({
 *     model: openai("gpt-4o"),
 *     prompt: "Summarize this contract...",
 *     onFinish: witness.vercelOnFinish(),
 *   });
 *
 * The `onFinish` callback receives a normalized result regardless of
 * provider (OpenAI, Anthropic, Google, custom), so this single hook
 * works with any Vercel AI SDK provider — no per-provider adapters needed.
 *
 * Vercel AI SDK onFinish payload:
 *   {
 *     text: string,                    // Complete response text
 *     usage: { promptTokens, completionTokens },
 *     finishReason: "stop" | "length" | "content-filter" | "tool-calls" | ...,
 *     response: { id, model, timestamp, headers },
 *     experimental_providerMetadata?: { ... },
 *   }
 */

import { sha256Truncated } from "../fingerprint.js";
import type { InferenceRecord } from "../types.js";
import type { Witness } from "../witness.js";

/**
 * Vercel AI SDK onFinish callback shape.
 * We define this locally to avoid requiring `ai` as a dependency.
 */
interface VercelOnFinishResult {
  text: string;
  usage: {
    promptTokens: number;
    completionTokens: number;
  };
  finishReason: string;
  response: {
    id?: string;
    model?: string;
    timestamp?: Date;
    headers?: Record<string, string>;
  };
  experimental_providerMetadata?: Record<string, unknown>;
}

export interface VercelOnFinishOptions {
  /** Override the prompt text for hashing (if not using the `prompt` param). */
  promptText?: string;
  /** Model name override (if response.model is missing). */
  modelId?: string;
}

/**
 * Create a Vercel AI SDK `onFinish` callback that witnesses the inference.
 *
 * Works with both `streamText()` and `generateText()`.
 */
export function createVercelOnFinish(
  witness: Witness,
  options: VercelOnFinishOptions = {},
): (result: VercelOnFinishResult) => void {
  const capturedStart = performance.now();

  return (result: VercelOnFinishResult) => {
    const elapsedMs = Math.round(performance.now() - capturedStart);
    const model = result.response?.model ?? options.modelId ?? "unknown";
    const responseText = result.text ?? "";

    // Prompt text: caller can provide it, or we hash empty
    // (The Vercel AI SDK doesn't expose the prompt in onFinish,
    //  so the caller should pass it via options for full provenance)
    const promptText = options.promptText ?? "";

    // Detect content filtering / refusal
    const hasRefusal =
      result.finishReason === "content-filter" ||
      result.finishReason === "error";

    const record: InferenceRecord = {
      modelId: model,
      modelHash: sha256Truncated(model),
      promptHash: sha256Truncated(promptText),
      responseHash: sha256Truncated(responseText),
      latencyMs: elapsedMs,
      inputTokens: result.usage?.promptTokens,
      outputTokens: result.usage?.completionTokens,
      guardrailsActive: 0,
      guardrailsRequired: 0,
      guardrailPassed: true,
      hasRefusal,
      provider: "vercel-ai",
      guardrailNames: [],
    };

    witness.record(record);
  };
}
