/**
 * SWT3 AI Witness SDK -- Cohere Adapter (ES6 Proxy).
 *
 * Wraps the Cohere client so that chat() and chatStream() are
 * intercepted for witnessing. Flat API -- only one level of proxy.
 *
 * Cohere V2 response structure:
 *   response.message.content[0].text  -> response text
 *   response.model                    -> string
 *   response.finishReason             -> "COMPLETE" | "MAX_TOKENS" | "ERROR"
 *   response.usage.tokens.inputTokens / outputTokens
 *
 * Cohere streaming:
 *   chat_stream() returns an async iterable of events:
 *     message-start, content-delta, message-end
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import { sha256Truncated } from "../fingerprint.js";
import type { InferenceRecord } from "../types.js";
import type { Witness } from "../witness.js";

/**
 * Wrap a Cohere client with an ES6 Proxy for transparent witnessing.
 *
 * Works with both sync and async Cohere clients. Intercepts:
 *   - chat() for non-streaming completions
 *   - chatStream() for streaming completions
 */
export function wrapCohere(client: unknown, witness: Witness): unknown {
  return new Proxy(client as object, {
    get(target: object, prop: string | symbol): unknown {
      if (typeof prop === "symbol") return Reflect.get(target, prop);
      const real = Reflect.get(target, prop);

      if (prop === "chat") {
        return createChatInterceptor(
          real as (...args: unknown[]) => unknown,
          witness,
        );
      }

      if (prop === "chatStream" || prop === "chat_stream") {
        return createStreamInterceptor(
          real as (...args: unknown[]) => unknown,
          witness,
        );
      }

      return real;
    },
  });
}

// -- chat() interceptor -------------------------------------------------------

function createChatInterceptor(
  realMethod: (...args: unknown[]) => unknown,
  witness: Witness,
): (...args: unknown[]) => unknown {
  return function interceptedChat(this: unknown, ...args: unknown[]): unknown {
    const kwargs = (args[0] ?? {}) as Record<string, unknown>;
    const messages = kwargs.messages as unknown[];
    const model = (kwargs.model as string) ?? "unknown";

    const promptText = extractPromptText(messages);
    const promptHash = sha256Truncated(promptText);

    // Hash system prompt separately (instruction drift detection)
    const systemPromptText = extractSystemPrompt(messages);
    const systemPromptHash = systemPromptText
      ? sha256Truncated(systemPromptText)
      : undefined;

    // Gatekeeper pre-call check (strict mode only)
    let authorizationId: string | undefined;
    if ((witness as any).strict) {
      authorizationId = (witness as any).gateCheck(messages, model);
    }

    const start = performance.now();
    const result = realMethod.call(this, ...args);

    // Result is Promise<ChatResponse>
    return (result as Promise<unknown>).then((response: unknown) => {
      const elapsedMs = Math.round(performance.now() - start);
      const record = extractRecord(
        response,
        model,
        promptHash,
        elapsedMs,
        systemPromptHash,
      );
      witness.record(record, authorizationId);
      return response;
    });
  };
}

// -- chatStream() interceptor -------------------------------------------------

function createStreamInterceptor(
  realMethod: (...args: unknown[]) => unknown,
  witness: Witness,
): (...args: unknown[]) => unknown {
  return function interceptedStream(this: unknown, ...args: unknown[]): unknown {
    const kwargs = (args[0] ?? {}) as Record<string, unknown>;
    const messages = kwargs.messages as unknown[];
    const model = (kwargs.model as string) ?? "unknown";

    const promptText = extractPromptText(messages);
    const promptHash = sha256Truncated(promptText);

    const systemPromptText = extractSystemPrompt(messages);
    const systemPromptHash = systemPromptText
      ? sha256Truncated(systemPromptText)
      : undefined;

    let authorizationId: string | undefined;
    if ((witness as any).strict) {
      authorizationId = (witness as any).gateCheck(messages, model);
    }

    const start = performance.now();
    const result = realMethod.call(this, ...args);

    // chat_stream may return an async iterable directly or a Promise
    if (result && typeof (result as Promise<unknown>).then === "function") {
      return (result as Promise<unknown>).then((stream: unknown) =>
        wrapCohereStream(
          stream,
          witness,
          model,
          promptHash,
          start,
          systemPromptHash,
          authorizationId,
        ),
      );
    }
    return wrapCohereStream(
      result,
      witness,
      model,
      promptHash,
      start,
      systemPromptHash,
      authorizationId,
    );
  };
}

// -- Stream Accumulator -------------------------------------------------------

async function* streamAccumulator(
  stream: AsyncIterable<unknown>,
  witness: Witness,
  model: string,
  promptHash: string,
  startTime: number,
  systemPromptHash?: string,
  authorizationId?: string,
): AsyncGenerator<unknown, void, undefined> {
  const textParts: string[] = [];
  let actualModel = model;
  let inputTokens: number | undefined;
  let outputTokens: number | undefined;

  for await (const event of stream) {
    // Yield to developer immediately
    yield event;

    const e = event as Record<string, unknown>;
    const type = e.type as string;

    if (type === "message-start") {
      const delta = e.delta as Record<string, unknown> | undefined;
      if (delta) {
        const message = delta.message as Record<string, unknown> | undefined;
        if (message?.model) actualModel = message.model as string;
      }
    }

    if (type === "content-delta") {
      const delta = e.delta as Record<string, unknown> | undefined;
      if (delta) {
        const message = delta.message as Record<string, unknown> | undefined;
        if (message) {
          const content = message.content as Record<string, unknown> | undefined;
          if (content?.text) {
            textParts.push(content.text as string);
          }
        }
      }
    }

    if (type === "message-end") {
      const delta = e.delta as Record<string, unknown> | undefined;
      if (delta) {
        const usage = delta.usage as Record<string, unknown> | undefined;
        if (usage) {
          const tokens = usage.tokens as Record<string, unknown> | undefined;
          if (tokens) {
            if (tokens.input_tokens !== undefined)
              inputTokens = tokens.input_tokens as number;
            if (tokens.output_tokens !== undefined)
              outputTokens = tokens.output_tokens as number;
          }
          // Also check camelCase variants
          if (tokens === undefined) {
            if (usage.inputTokens !== undefined)
              inputTokens = usage.inputTokens as number;
            if (usage.outputTokens !== undefined)
              outputTokens = usage.outputTokens as number;
          }
        }
      }
    }
  }

  // Stream complete -- witness
  const elapsedMs = Math.round(performance.now() - startTime);
  const responseText = textParts.join("");

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
    hasRefusal: false,
    provider: "cohere",
    guardrailNames: [],
    systemPromptHash,
  };

  witness.record(record, authorizationId);
}

function wrapCohereStream(
  stream: unknown,
  witness: Witness,
  model: string,
  promptHash: string,
  startTime: number,
  systemPromptHash?: string,
  authorizationId?: string,
): unknown {
  const s = stream as Record<string | symbol, unknown>;

  const gen = streamAccumulator(
    s as unknown as AsyncIterable<unknown>,
    witness,
    model,
    promptHash,
    startTime,
    systemPromptHash,
    authorizationId,
  );

  return new Proxy(s, {
    get(
      target: Record<string | symbol, unknown>,
      prop: string | symbol,
    ): unknown {
      if (prop === Symbol.asyncIterator) {
        return () => gen;
      }

      const value = Reflect.get(target, prop);
      if (typeof value === "function") {
        return (value as Function).bind(target);
      }
      return value;
    },
  });
}

// -- Factor Extraction --------------------------------------------------------

function extractSystemPrompt(messages: unknown): string | undefined {
  if (!Array.isArray(messages)) return undefined;

  for (const msg of messages) {
    if (typeof msg !== "object" || msg === null) continue;
    const m = msg as Record<string, unknown>;
    if (m.role !== "system") continue;

    const content = m.content;
    if (typeof content === "string") return content;
    if (Array.isArray(content)) {
      const parts: string[] = [];
      for (const block of content) {
        if (typeof block === "object" && block !== null) {
          const b = block as Record<string, unknown>;
          if (typeof b.text === "string") parts.push(b.text);
        }
      }
      return parts.length > 0 ? parts.join("\n") : undefined;
    }
  }
  return undefined;
}

function extractPromptText(messages: unknown): string {
  const parts: string[] = [];

  if (Array.isArray(messages)) {
    for (const msg of messages) {
      if (typeof msg !== "object" || msg === null) continue;
      const m = msg as Record<string, unknown>;
      const content = m.content;
      if (typeof content === "string") {
        parts.push(content);
      } else if (Array.isArray(content)) {
        for (const block of content) {
          if (typeof block === "object" && block !== null) {
            const b = block as Record<string, unknown>;
            if (typeof b.text === "string") parts.push(b.text);
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

  // Extract text from message.content
  let responseText = "";
  const message = r.message as Record<string, unknown> | undefined;
  if (message) {
    const content = message.content as Array<Record<string, unknown>> | undefined;
    if (Array.isArray(content)) {
      const texts: string[] = [];
      for (const block of content) {
        if (typeof block.text === "string") texts.push(block.text);
      }
      responseText = texts.join("\n");
    }
  }

  // Finish reason
  const finishReason = (r.finish_reason as string) ?? (r.finishReason as string) ?? "";
  const hasRefusal = !["COMPLETE", "MAX_TOKENS", "TOOL_CALL"].includes(finishReason);

  // Token usage
  const usage = r.usage as Record<string, unknown> | undefined;
  let inputTokens: number | undefined;
  let outputTokens: number | undefined;
  if (usage) {
    const tokens = usage.tokens as Record<string, unknown> | undefined;
    if (tokens) {
      inputTokens = tokens.input_tokens as number | undefined;
      outputTokens = tokens.output_tokens as number | undefined;
      // camelCase fallback
      if (inputTokens === undefined)
        inputTokens = tokens.inputTokens as number | undefined;
      if (outputTokens === undefined)
        outputTokens = tokens.outputTokens as number | undefined;
    }
  }

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
    provider: "cohere",
    systemPromptHash,
    guardrailNames: [],
  };
}
