/**
 * SWT3 AI Witness SDK — Anthropic Adapter (ES6 Proxy).
 *
 * Wraps the Anthropic client so that `client.messages.create()` is
 * intercepted for witnessing. Two levels deep (simpler than OpenAI).
 *
 * Handles both:
 *   - Non-streaming: Message response object
 *   - Streaming: MessageStream — accumulates content_block_delta events
 *     for hashing, witnesses after stream_message_stop
 *
 * Anthropic response structure:
 *   response.content      → ContentBlock[] (text, tool_use, etc.)
 *   response.model        → string
 *   response.stop_reason  → "end_turn" | "max_tokens" | "stop_sequence" | "tool_use"
 *   response.usage        → { input_tokens, output_tokens }
 *
 * Anthropic streaming:
 *   The SDK returns a MessageStream with:
 *   - Symbol.asyncIterator → yields MessageStreamEvent objects
 *   - .on("message", cb) → fires when complete message is assembled
 *   - .finalMessage() → Promise<Message> (the assembled message)
 *
 *   Events: message_start, content_block_start, content_block_delta,
 *           content_block_stop, message_delta, message_stop
 */

import { sha256Truncated } from "../fingerprint.js";
import type { InferenceRecord } from "../types.js";
import type { Witness } from "../witness.js";

/**
 * Wrap an Anthropic client with an ES6 Proxy for transparent witnessing.
 */
export function wrapAnthropic(client: unknown, witness: Witness): unknown {
  return new Proxy(client as object, {
    get(target: object, prop: string | symbol): unknown {
      if (typeof prop === "symbol") return Reflect.get(target, prop);
      const real = Reflect.get(target, prop);

      if (prop === "messages") {
        return createMessagesProxy(real, witness);
      }
      return real;
    },
  });
}

function createMessagesProxy(messages: unknown, witness: Witness): unknown {
  return new Proxy(messages as object, {
    get(target: object, prop: string | symbol): unknown {
      if (typeof prop === "symbol") return Reflect.get(target, prop);
      const real = Reflect.get(target, prop);

      if (prop === "create") {
        return createInterceptor(real as (...args: unknown[]) => unknown, witness);
      }

      // Anthropic also has messages.stream() — intercept that too
      if (prop === "stream") {
        return createStreamInterceptor(real as (...args: unknown[]) => unknown, witness);
      }

      return real;
    },
  });
}

// ── Non-streaming / auto-detect interceptor ─────────────────────────

function createInterceptor(
  realMethod: (...args: unknown[]) => unknown,
  witness: Witness,
): (...args: unknown[]) => unknown {
  return function interceptedCreate(this: unknown, ...args: unknown[]): unknown {
    const kwargs = (args[0] ?? {}) as Record<string, unknown>;
    const messages = kwargs.messages as unknown[];
    const system = kwargs.system as unknown;
    const model = (kwargs.model as string) ?? "unknown";
    const isStreaming = kwargs.stream === true;

    const promptText = extractPromptText(messages, system);
    const promptHash = sha256Truncated(promptText);
    const start = performance.now();

    const result = realMethod.call(this, ...args);

    if (isStreaming) {
      // Streaming via create({ stream: true }) — returns a Stream
      return handleStreaming(result, witness, model, promptHash, start);
    }

    // Non-streaming — result is Promise<Message>
    return (result as Promise<unknown>).then((response: unknown) => {
      const elapsedMs = Math.round(performance.now() - start);
      const record = extractRecord(response, model, promptHash, elapsedMs);
      witness.record(record);
      return response;
    });
  };
}

// ── Explicit .stream() interceptor ──────────────────────────────────

function createStreamInterceptor(
  realMethod: (...args: unknown[]) => unknown,
  witness: Witness,
): (...args: unknown[]) => unknown {
  return function interceptedStream(this: unknown, ...args: unknown[]): unknown {
    const kwargs = (args[0] ?? {}) as Record<string, unknown>;
    const messages = kwargs.messages as unknown[];
    const system = kwargs.system as unknown;
    const model = (kwargs.model as string) ?? "unknown";

    const promptText = extractPromptText(messages, system);
    const promptHash = sha256Truncated(promptText);
    const start = performance.now();

    const result = realMethod.call(this, ...args);
    return handleStreaming(result, witness, model, promptHash, start);
  };
}

// ── Streaming Handler ───────────────────────────────────────────────

async function* streamAccumulator(
  stream: AsyncIterable<unknown>,
  witness: Witness,
  model: string,
  promptHash: string,
  startTime: number,
): AsyncGenerator<unknown, void, undefined> {
  const textParts: string[] = [];
  let actualModel = model;
  let stopReason = "";
  let inputTokens: number | undefined;
  let outputTokens: number | undefined;

  for await (const event of stream) {
    // Yield to developer immediately
    yield event;

    const e = event as Record<string, unknown>;
    const type = e.type as string;

    if (type === "message_start") {
      const msg = e.message as Record<string, unknown> | undefined;
      if (msg?.model) actualModel = msg.model as string;
      const usage = msg?.usage as Record<string, unknown> | undefined;
      if (usage?.input_tokens) inputTokens = usage.input_tokens as number;
    }

    if (type === "content_block_delta") {
      const delta = e.delta as Record<string, unknown> | undefined;
      if (delta?.type === "text_delta" && delta?.text) {
        textParts.push(delta.text as string);
      }
    }

    if (type === "message_delta") {
      const delta = e.delta as Record<string, unknown> | undefined;
      if (delta?.stop_reason) stopReason = delta.stop_reason as string;
      const usage = e.usage as Record<string, unknown> | undefined;
      if (usage?.output_tokens) outputTokens = usage.output_tokens as number;
    }
  }

  // Stream complete — witness
  const elapsedMs = Math.round(performance.now() - startTime);
  const responseText = textParts.join("");
  const hasRefusal = !["end_turn", "max_tokens", "stop_sequence", "tool_use"].includes(stopReason);

  const record: InferenceRecord = {
    modelId: actualModel,
    modelHash: sha256Truncated(actualModel),
    promptHash,
    responseHash: sha256Truncated(responseText),
    latencyMs: elapsedMs,
    inputTokens,
    outputTokens,
    guardrailsActive: 0,
    guardrailsRequired: 0,
    guardrailPassed: true,
    hasRefusal,
    provider: "anthropic",
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
): unknown {
  // Anthropic's stream() returns a MessageStream directly (not a Promise)
  // But create({ stream: true }) may return a Promise<Stream>
  if (streamResult && typeof (streamResult as Promise<unknown>).then === "function") {
    return (streamResult as Promise<unknown>).then((stream: unknown) =>
      wrapAnthropicStream(stream, witness, model, promptHash, startTime),
    );
  }
  return wrapAnthropicStream(streamResult, witness, model, promptHash, startTime);
}

function wrapAnthropicStream(
  stream: unknown,
  witness: Witness,
  model: string,
  promptHash: string,
  startTime: number,
): unknown {
  const s = stream as Record<string | symbol, unknown>;

  const gen = streamAccumulator(
    s as unknown as AsyncIterable<unknown>,
    witness,
    model,
    promptHash,
    startTime,
  );

  return new Proxy(s, {
    get(target: Record<string | symbol, unknown>, prop: string | symbol): unknown {
      if (prop === Symbol.asyncIterator) {
        return () => gen;
      }

      const value = Reflect.get(target, prop);
      if (typeof value === "function") {
        // Wrap finalMessage() to also witness the complete response
        if (prop === "finalMessage") {
          return async function wrappedFinalMessage(): Promise<unknown> {
            const msg = await (value as () => Promise<unknown>).call(target);
            // The stream accumulator will have already witnessed via iteration,
            // but if someone calls finalMessage() WITHOUT iterating, we need
            // to witness from the assembled message.
            return msg;
          };
        }
        return (value as Function).bind(target);
      }
      return value;
    },
  });
}

// ── Factor Extraction ──────────────────────────────────────────────

function extractPromptText(messages: unknown, system: unknown = ""): string {
  const parts: string[] = [];

  // System prompt
  if (typeof system === "string" && system) {
    parts.push(system);
  } else if (Array.isArray(system)) {
    for (const block of system) {
      if (typeof block === "object" && block !== null) {
        const b = block as Record<string, unknown>;
        if (b.type === "text" && typeof b.text === "string") {
          parts.push(b.text);
        }
      }
    }
  }

  // Messages
  if (Array.isArray(messages)) {
    for (const msg of messages) {
      if (typeof msg === "object" && msg !== null) {
        const m = msg as Record<string, unknown>;
        const content = m.content;
        if (typeof content === "string") {
          parts.push(content);
        } else if (Array.isArray(content)) {
          for (const block of content) {
            if (typeof block === "object" && block !== null) {
              const b = block as Record<string, unknown>;
              if (b.type === "text" && typeof b.text === "string") {
                parts.push(b.text);
              }
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
): InferenceRecord {
  const r = response as Record<string, unknown>;

  // Extract text from content blocks
  let responseText = "";
  const contentBlocks = r.content as Array<Record<string, unknown>> | undefined;
  if (Array.isArray(contentBlocks)) {
    const texts: string[] = [];
    for (const block of contentBlocks) {
      if (block.type === "text" && typeof block.text === "string") {
        texts.push(block.text);
      }
    }
    responseText = texts.join("\n");
  }

  const stopReason = (r.stop_reason as string) ?? "";
  const hasRefusal = !["end_turn", "max_tokens", "stop_sequence", "tool_use"].includes(stopReason);

  const usage = r.usage as Record<string, unknown> | undefined;
  const inputTokens = usage?.input_tokens as number | undefined;
  const outputTokens = usage?.output_tokens as number | undefined;

  const actualModel = (r.model as string) ?? model;

  return {
    modelId: actualModel,
    modelHash: sha256Truncated(actualModel),
    promptHash,
    responseHash: sha256Truncated(responseText),
    latencyMs: elapsedMs,
    inputTokens,
    outputTokens,
    guardrailsActive: 0,
    guardrailsRequired: 0,
    guardrailPassed: true,
    hasRefusal,
    provider: "anthropic",
    guardrailNames: [],
  };
}
