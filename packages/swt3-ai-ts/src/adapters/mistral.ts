/**
 * SWT3 AI Witness SDK -- Mistral Adapter (ES6 Proxy).
 *
 * Wraps the Mistral client so that chat.complete() and chat.stream()
 * are intercepted for witnessing. Two levels deep (like Anthropic):
 * client.chat -> _ChatProxy -> complete/stream interceptors.
 *
 * Mistral response structure:
 *   response.choices[0].message.content  -> response text
 *   response.model                       -> actual model name
 *   response.choices[0].finishReason     -> "stop" | "length" | "model_length" | "tool_calls"
 *   response.usage.promptTokens / completionTokens
 *
 * Mistral streaming:
 *   chat.stream() returns an async iterable of CompletionChunk objects.
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import { sha256Truncated } from "../fingerprint.js";
import type { InferenceRecord } from "../types.js";
import type { Witness } from "../witness.js";

/**
 * Wrap a Mistral client with an ES6 Proxy for transparent witnessing.
 *
 * Intercepts:
 *   - chat.complete() for non-streaming completions
 *   - chat.stream() for streaming completions
 */
export function wrapMistral(client: unknown, witness: Witness): unknown {
  return new Proxy(client as object, {
    get(target: object, prop: string | symbol): unknown {
      if (typeof prop === "symbol") return Reflect.get(target, prop);
      const real = Reflect.get(target, prop);

      if (prop === "chat") {
        return createChatProxy(real, witness);
      }

      return real;
    },
  });
}

// -- Chat namespace proxy -----------------------------------------------------

function createChatProxy(chatNamespace: unknown, witness: Witness): unknown {
  return new Proxy(chatNamespace as object, {
    get(target: object, prop: string | symbol): unknown {
      if (typeof prop === "symbol") return Reflect.get(target, prop);
      const real = Reflect.get(target, prop);

      if (prop === "complete" || prop === "completeAsync" || prop === "complete_async") {
        return createCompleteInterceptor(
          real as (...args: unknown[]) => unknown,
          witness,
        );
      }

      if (prop === "stream" || prop === "streamAsync" || prop === "stream_async") {
        return createStreamInterceptor(
          real as (...args: unknown[]) => unknown,
          witness,
        );
      }

      return real;
    },
  });
}

// -- complete() interceptor ---------------------------------------------------

function createCompleteInterceptor(
  realMethod: (...args: unknown[]) => unknown,
  witness: Witness,
): (...args: unknown[]) => unknown {
  return function interceptedComplete(this: unknown, ...args: unknown[]): unknown {
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

// -- stream() interceptor -----------------------------------------------------

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

    if (result && typeof (result as Promise<unknown>).then === "function") {
      return (result as Promise<unknown>).then((stream: unknown) =>
        wrapMistralStream(
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
    return wrapMistralStream(
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

async function* mistralStreamAccumulator(
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
  let finishReason: string | undefined;

  for await (const chunk of stream) {
    yield chunk;

    // Handle both wrapped (chunk.data.choices) and unwrapped (chunk.choices)
    const c = chunk as Record<string, unknown>;
    const data = (c.data ?? chunk) as Record<string, unknown>;

    const choices = data.choices as Array<Record<string, unknown>> | undefined;
    if (Array.isArray(choices) && choices.length > 0) {
      const choice = choices[0];
      const delta = choice.delta as Record<string, unknown> | undefined;
      if (delta) {
        const content = delta.content;
        if (typeof content === "string" && content) {
          textParts.push(content);
        }
      }
      const fr = choice.finish_reason ?? choice.finishReason;
      if (fr !== undefined && fr !== null) {
        finishReason = String(fr);
      }
    }

    const m = data.model;
    if (typeof m === "string" && m) {
      actualModel = m;
    }

    const usage = data.usage as Record<string, unknown> | undefined;
    if (usage) {
      const pt = usage.prompt_tokens ?? usage.promptTokens;
      const ct = usage.completion_tokens ?? usage.completionTokens;
      if (typeof pt === "number") inputTokens = pt;
      if (typeof ct === "number") outputTokens = ct;
    }
  }

  const elapsedMs = Math.round(performance.now() - startTime);
  const responseText = textParts.join("");

  const hasRefusal =
    finishReason !== undefined &&
    !["stop", "length", "model_length", "tool_calls"].includes(finishReason);

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
    provider: "mistral",
    guardrailNames: [],
    systemPromptHash,
  };

  witness.record(record, authorizationId);
}

function wrapMistralStream(
  stream: unknown,
  witness: Witness,
  model: string,
  promptHash: string,
  startTime: number,
  systemPromptHash?: string,
  authorizationId?: string,
): unknown {
  const s = stream as Record<string | symbol, unknown>;

  const gen = mistralStreamAccumulator(
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

// -- Extraction helpers -------------------------------------------------------

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

  // Extract text from choices[0].message.content
  let responseText = "";
  let hasRefusal = false;

  const choices = r.choices as Array<Record<string, unknown>> | undefined;
  if (Array.isArray(choices) && choices.length > 0) {
    const choice = choices[0];
    const message = choice.message as Record<string, unknown> | undefined;
    if (message) {
      const content = message.content;
      if (typeof content === "string") {
        responseText = content;
      } else if (Array.isArray(content)) {
        const texts: string[] = [];
        for (const block of content) {
          if (typeof block === "string") texts.push(block);
          else if (typeof block === "object" && block !== null) {
            const b = block as Record<string, unknown>;
            if (typeof b.text === "string") texts.push(b.text);
          }
        }
        responseText = texts.join("\n");
      }
    }

    const fr = (choice.finish_reason ?? choice.finishReason) as string | undefined;
    if (fr && !["stop", "length", "model_length", "tool_calls"].includes(fr)) {
      hasRefusal = true;
    }
  }

  // Token usage
  const usage = r.usage as Record<string, unknown> | undefined;
  let inputTokens: number | undefined;
  let outputTokens: number | undefined;
  if (usage) {
    inputTokens = (usage.prompt_tokens ?? usage.promptTokens) as number | undefined;
    outputTokens = (usage.completion_tokens ?? usage.completionTokens) as number | undefined;
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
    provider: "mistral",
    guardrailNames: [],
    systemPromptHash,
  };
}
