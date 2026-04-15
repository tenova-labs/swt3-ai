/**
 * SWT3 AI Witness SDK — OpenAI Adapter (ES6 Proxy).
 *
 * Uses JavaScript's native Proxy to intercept property access on the
 * OpenAI client, following the chain: client.chat.completions.create()
 *
 * Handles both:
 *   - Non-streaming: ChatCompletion response object
 *   - Streaming: AsyncIterable<ChatCompletionChunk> — accumulates chunks
 *     for hashing, then witnesses after stream completes
 *
 * The developer's code sees zero difference from using the raw client.
 */

import { sha256Truncated } from "../fingerprint.js";
import type { InferenceRecord } from "../types.js";
import type { Witness } from "../witness.js";

/**
 * Methods to intercept at each path level.
 * "chat.completions" → intercept "create"
 */
const INTERCEPT_PATHS: Record<string, Set<string>> = {
  "chat.completions": new Set(["create"]),
};

/**
 * Wrap an OpenAI client with an ES6 Proxy for transparent witnessing.
 */
export function wrapOpenAI(client: unknown, witness: Witness): unknown {
  return createProxy(client, witness, "");
}

function createProxy(target: unknown, witness: Witness, path: string): unknown {
  return new Proxy(target as object, {
    get(obj: object, prop: string | symbol): unknown {
      if (typeof prop === "symbol") return Reflect.get(obj, prop);

      const realValue = Reflect.get(obj, prop);
      const currentPath = path ? `${path}.${prop}` : prop;

      // Check if this property is an interceptable method
      if (path in INTERCEPT_PATHS && INTERCEPT_PATHS[path].has(prop)) {
        // This IS the method to intercept
        return createInterceptor(realValue as (...args: unknown[]) => unknown, witness);
      }

      // Check if this path could lead to interceptable methods
      const hasChildren = Object.keys(INTERCEPT_PATHS).some(
        (p) => p === currentPath || p.startsWith(currentPath + "."),
      );

      if (hasChildren && typeof realValue === "object" && realValue !== null) {
        return createProxy(realValue, witness, currentPath);
      }

      // Pass through
      return realValue;
    },
  });
}

function createInterceptor(
  realMethod: (...args: unknown[]) => unknown,
  witness: Witness,
): (...args: unknown[]) => unknown {
  return function interceptedCreate(this: unknown, ...args: unknown[]): unknown {
    const kwargs = (args[0] ?? {}) as Record<string, unknown>;
    const messages = kwargs.messages as unknown[];
    const model = (kwargs.model as string) ?? "unknown";
    const isStreaming = kwargs.stream === true;

    // Hash prompt before the call
    const promptText = extractPromptText(messages);
    const promptHash = sha256Truncated(promptText);

    // Hash system prompt separately (instruction drift detection)
    const systemPromptText = extractSystemPrompt(messages);
    const systemPromptHash = systemPromptText ? sha256Truncated(systemPromptText) : undefined;

    // Start latency timer
    const start = performance.now();

    // Call the real method (bound to its original this)
    const result = realMethod.call(this, ...args);

    if (isStreaming) {
      // Streaming: wrap the async iterable to accumulate chunks
      return handleStreaming(result, witness, model, promptHash, start, systemPromptHash);
    }

    // Non-streaming: result is a Promise<ChatCompletion>
    return (result as Promise<unknown>).then((response: unknown) => {
      const elapsedMs = Math.round(performance.now() - start);
      const record = extractRecord(response, model, promptHash, elapsedMs, systemPromptHash);
      witness.record(record);
      return response; // Return UNTOUCHED
    });
  };
}

// ── Streaming Handler ──────────────────────────────────────────────
//
// OpenAI's streaming returns an object with:
//   - Symbol.asyncIterator (for `for await...of`)
//   - .controller for abort
//   - .toReadableStream() for web streams
//
// We wrap the async iterator to accumulate content chunks, then
// witness after the stream completes. The developer's stream
// behavior is completely unchanged.

async function* streamAccumulator(
  stream: AsyncIterable<unknown>,
  witness: Witness,
  model: string,
  promptHash: string,
  startTime: number,
  systemPromptHash?: string,
): AsyncGenerator<unknown, void, undefined> {
  const textParts: string[] = [];
  let actualModel = model;
  let systemFingerprint: string | undefined;
  let hasRefusal = false;
  let finishReason = "";
  let inputTokens: number | undefined;
  let outputTokens: number | undefined;

  for await (const chunk of stream) {
    // Yield chunk to the developer immediately (untouched)
    yield chunk;

    // Extract data from chunk for witnessing
    const c = chunk as Record<string, unknown>;

    if (c.model) actualModel = c.model as string;
    if (c.system_fingerprint) systemFingerprint = c.system_fingerprint as string;

    const choices = c.choices as Array<Record<string, unknown>> | undefined;
    if (choices?.[0]) {
      const delta = choices[0].delta as Record<string, unknown> | undefined;
      if (delta?.content) {
        textParts.push(delta.content as string);
      }
      if (delta?.refusal) {
        hasRefusal = true;
      }
      if (choices[0].finish_reason) {
        finishReason = choices[0].finish_reason as string;
      }
    }

    // Usage info comes in the final chunk (stream_options: {include_usage: true})
    const usage = c.usage as Record<string, unknown> | undefined;
    if (usage) {
      inputTokens = usage.prompt_tokens as number | undefined;
      outputTokens = usage.completion_tokens as number | undefined;
    }
  }

  // Stream complete — witness the full inference
  const elapsedMs = Math.round(performance.now() - startTime);
  const responseText = textParts.join("");

  if (finishReason === "content_filter") hasRefusal = true;

  const modelHashInput = systemFingerprint
    ? `${actualModel}:${systemFingerprint}`
    : actualModel;

  const record: InferenceRecord = {
    modelId: actualModel,
    modelHash: sha256Truncated(modelHashInput),
    promptHash,
    responseHash: sha256Truncated(responseText),
    latencyMs: elapsedMs,
    inputTokens,
    outputTokens,
    guardrailsActive: 0,
    guardrailsRequired: 0,
    guardrailPassed: true,
    hasRefusal,
    provider: "openai",
    systemFingerprint,
    systemPromptHash,
    guardrailNames: [],
  };

  witness.record(record);
}

function handleStreaming(
  streamResult: unknown,
  witness: Witness,
  model: string,
  promptHash: string,
  startTime: number,
  systemPromptHash?: string,
): unknown {
  // The stream result is a Promise that resolves to the stream object
  // (OpenAI SDK returns Promise<Stream<ChatCompletionChunk>>)
  if (streamResult && typeof (streamResult as Promise<unknown>).then === "function") {
    return (streamResult as Promise<unknown>).then((stream: unknown) => {
      return wrapStream(stream, witness, model, promptHash, startTime, systemPromptHash);
    });
  }

  // Direct stream object (shouldn't happen but handle gracefully)
  return wrapStream(streamResult, witness, model, promptHash, startTime, systemPromptHash);
}

function wrapStream(
  stream: unknown,
  witness: Witness,
  model: string,
  promptHash: string,
  startTime: number,
  systemPromptHash?: string,
): unknown {
  const s = stream as Record<string | symbol, unknown>;

  // Create the accumulating async generator
  const gen = streamAccumulator(
    s as unknown as AsyncIterable<unknown>,
    witness,
    model,
    promptHash,
    startTime,
    systemPromptHash,
  );

  // Return a proxy that preserves all stream methods but overrides the iterator
  return new Proxy(s, {
    get(target: Record<string | symbol, unknown>, prop: string | symbol): unknown {
      // Override the async iterator
      if (prop === Symbol.asyncIterator) {
        return () => gen;
      }

      // Preserve other methods (controller, toReadableStream, etc.)
      const value = Reflect.get(target, prop);
      if (typeof value === "function") {
        return (value as Function).bind(target);
      }
      return value;
    },
  });
}

// ── Factor Extraction ──────────────────────────────────────────────

function extractSystemPrompt(messages: unknown): string | undefined {
  if (!Array.isArray(messages)) return undefined;

  const parts: string[] = [];
  for (const msg of messages) {
    if (typeof msg === "object" && msg !== null) {
      const m = msg as Record<string, unknown>;
      if (m.role !== "system") continue;
      const content = m.content;
      if (typeof content === "string") {
        parts.push(content);
      } else if (Array.isArray(content)) {
        for (const part of content) {
          if (typeof part === "object" && part !== null) {
            const p = part as Record<string, unknown>;
            if (p.type === "text" && typeof p.text === "string") {
              parts.push(p.text);
            }
          }
        }
      }
    }
  }
  return parts.length > 0 ? parts.join("\n") : undefined;
}

function extractPromptText(messages: unknown): string {
  if (typeof messages === "string") return messages;
  if (!Array.isArray(messages)) return "";

  const parts: string[] = [];
  for (const msg of messages) {
    if (typeof msg === "object" && msg !== null) {
      const m = msg as Record<string, unknown>;
      const content = m.content;
      if (typeof content === "string") {
        parts.push(content);
      } else if (Array.isArray(content)) {
        for (const part of content) {
          if (typeof part === "object" && part !== null) {
            const p = part as Record<string, unknown>;
            if (p.type === "text" && typeof p.text === "string") {
              parts.push(p.text);
            }
          }
        }
      }
    }
  }
  return parts.join("\n");
}

function extractRecord(
  response: unknown,
  model: string,
  promptHash: string,
  elapsedMs: number,
  systemPromptHash?: string,
): InferenceRecord {
  const r = response as Record<string, unknown>;
  let responseText = "";
  let hasRefusal = false;

  const choices = r.choices as Array<Record<string, unknown>> | undefined;
  if (choices?.[0]) {
    const message = choices[0].message as Record<string, unknown> | undefined;
    if (message) {
      responseText = (message.content as string) ?? "";
      if (message.refusal) hasRefusal = true;
    }
    if (choices[0].finish_reason === "content_filter") hasRefusal = true;
  }

  let inputTokens: number | undefined;
  let outputTokens: number | undefined;
  const usage = r.usage as Record<string, unknown> | undefined;
  if (usage) {
    inputTokens = usage.prompt_tokens as number | undefined;
    outputTokens = usage.completion_tokens as number | undefined;
  }

  const actualModel = (r.model as string) ?? model;
  const systemFingerprint = r.system_fingerprint as string | undefined;

  const modelHashInput = systemFingerprint
    ? `${actualModel}:${systemFingerprint}`
    : actualModel;

  return {
    modelId: actualModel,
    modelHash: sha256Truncated(modelHashInput),
    promptHash,
    responseHash: sha256Truncated(responseText),
    latencyMs: elapsedMs,
    inputTokens,
    outputTokens,
    guardrailsActive: 0,
    guardrailsRequired: 0,
    guardrailPassed: true,
    hasRefusal,
    provider: "openai",
    systemFingerprint,
    systemPromptHash,
    guardrailNames: [],
  };
}
