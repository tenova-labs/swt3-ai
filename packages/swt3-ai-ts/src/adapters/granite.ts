/**
 * SWT3 AI Witness SDK -- IBM Granite Adapter (ES6 Proxy).
 *
 * Wraps ibm-watsonx-ai ModelInference so that generate(),
 * generateText(), and generateTextStream() are intercepted
 * for witnessing. Flat API -- only one level of proxy.
 *
 * watsonx generate() response structure:
 *   { model_id: string, results: [{ generated_text: string,
 *     generated_token_count: number, input_token_count: number,
 *     stop_reason: "eos_token" | "max_tokens" | "stop_sequence" }] }
 *
 * watsonx generateTextStream() yields plain text strings.
 *
 * For Granite models served via Ollama or vLLM, use the existing
 * OpenAI or vLLM adapters instead.
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import { sha256Truncated } from "../fingerprint.js";
import type { InferenceRecord } from "../types.js";
import type { Witness } from "../witness.js";

/**
 * Wrap an ibm-watsonx-ai ModelInference with an ES6 Proxy
 * for transparent witnessing.
 *
 * Intercepts:
 *   - generate() for structured dict responses
 *   - generateText() / generate_text() for bare string responses
 *   - generateTextStream() / generate_text_stream() for streaming
 */
export function wrapGranite(client: unknown, witness: Witness): unknown {
  const target = client as Record<string, unknown>;

  return new Proxy(target as object, {
    get(t: object, prop: string | symbol): unknown {
      if (typeof prop === "symbol") return Reflect.get(t, prop);
      const real = Reflect.get(t, prop);

      if (prop === "generate") {
        return createGenerateInterceptor(
          real as (...args: unknown[]) => unknown,
          witness,
          target,
        );
      }

      if (prop === "generateText" || prop === "generate_text") {
        return createGenerateTextInterceptor(
          real as (...args: unknown[]) => unknown,
          witness,
          target,
        );
      }

      if (prop === "generateTextStream" || prop === "generate_text_stream") {
        return createStreamInterceptor(
          real as (...args: unknown[]) => unknown,
          witness,
          target,
        );
      }

      return real;
    },
  });
}

// -- generate() interceptor ---------------------------------------------------

function createGenerateInterceptor(
  realMethod: (...args: unknown[]) => unknown,
  witness: Witness,
  target: Record<string, unknown>,
): (...args: unknown[]) => unknown {
  return function interceptedGenerate(this: unknown, ...args: unknown[]): unknown {
    const kwargs = (args[0] ?? {}) as Record<string, unknown>;
    const prompt = (kwargs.prompt as string) ?? "";
    const promptHash = sha256Truncated(prompt);
    const modelId = getModelId(target);

    let authorizationId: string | undefined;
    if ((witness as any).strict) {
      authorizationId = (witness as any).gateCheck(prompt, modelId);
    }

    const start = performance.now();
    const result = realMethod.call(this, ...args);

    return (result as Promise<unknown>).then((response: unknown) => {
      const elapsedMs = Math.round(performance.now() - start);
      const record = extractRecord(response, modelId, promptHash, elapsedMs);
      witness.record(record, authorizationId);
      return response;
    });
  };
}

// -- generateText() interceptor -----------------------------------------------

function createGenerateTextInterceptor(
  realMethod: (...args: unknown[]) => unknown,
  witness: Witness,
  target: Record<string, unknown>,
): (...args: unknown[]) => unknown {
  return function interceptedGenerateText(this: unknown, ...args: unknown[]): unknown {
    const kwargs = (args[0] ?? {}) as Record<string, unknown>;
    const prompt = (kwargs.prompt as string) ?? "";
    const promptHash = sha256Truncated(prompt);
    const modelId = getModelId(target);

    let authorizationId: string | undefined;
    if ((witness as any).strict) {
      authorizationId = (witness as any).gateCheck(prompt, modelId);
    }

    const start = performance.now();
    const result = realMethod.call(this, ...args);

    return (result as Promise<unknown>).then((responseText: unknown) => {
      const elapsedMs = Math.round(performance.now() - start);
      const text = typeof responseText === "string" ? responseText : "";

      const record: InferenceRecord = {
        modelId,
        modelHash: sha256Truncated(modelId),
        promptHash,
        responseHash: sha256Truncated(text),
        latencyMs: elapsedMs,
        guardrailsActive: 0,
        guardrailsRequired: 0,
        guardrailPassed: true,
        hasRefusal: false,
        provider: "ibm-watsonx",
        guardrailNames: [],
      };
      witness.record(record, authorizationId);
      return responseText;
    });
  };
}

// -- generateTextStream() interceptor -----------------------------------------

function createStreamInterceptor(
  realMethod: (...args: unknown[]) => unknown,
  witness: Witness,
  target: Record<string, unknown>,
): (...args: unknown[]) => unknown {
  return function interceptedStream(this: unknown, ...args: unknown[]): unknown {
    const kwargs = (args[0] ?? {}) as Record<string, unknown>;
    const prompt = (kwargs.prompt as string) ?? "";
    const promptHash = sha256Truncated(prompt);
    const modelId = getModelId(target);

    let authorizationId: string | undefined;
    if ((witness as any).strict) {
      authorizationId = (witness as any).gateCheck(prompt, modelId);
    }

    const start = performance.now();
    const result = realMethod.call(this, ...args);

    if (result && typeof (result as Promise<unknown>).then === "function") {
      return (result as Promise<unknown>).then((stream: unknown) =>
        wrapGraniteStream(
          stream,
          witness,
          modelId,
          promptHash,
          start,
          authorizationId,
        ),
      );
    }
    return wrapGraniteStream(
      result,
      witness,
      modelId,
      promptHash,
      start,
      authorizationId,
    );
  };
}

// -- Stream Accumulator -------------------------------------------------------

async function* graniteStreamAccumulator(
  stream: AsyncIterable<unknown>,
  witness: Witness,
  modelId: string,
  promptHash: string,
  startTime: number,
  authorizationId?: string,
): AsyncGenerator<unknown, void, undefined> {
  const textParts: string[] = [];

  for await (const chunk of stream) {
    yield chunk;

    if (typeof chunk === "string") {
      textParts.push(chunk);
    }
  }

  const elapsedMs = Math.round(performance.now() - startTime);
  const responseText = textParts.join("");

  const record: InferenceRecord = {
    modelId,
    modelHash: sha256Truncated(modelId),
    promptHash,
    responseHash: sha256Truncated(responseText),
    latencyMs: elapsedMs,
    guardrailsActive: 0,
    guardrailsRequired: 0,
    guardrailPassed: true,
    hasRefusal: false,
    provider: "ibm-watsonx",
    guardrailNames: [],
  };

  witness.record(record, authorizationId);
}

function wrapGraniteStream(
  stream: unknown,
  witness: Witness,
  modelId: string,
  promptHash: string,
  startTime: number,
  authorizationId?: string,
): unknown {
  const s = stream as Record<string | symbol, unknown>;

  const gen = graniteStreamAccumulator(
    s as unknown as AsyncIterable<unknown>,
    witness,
    modelId,
    promptHash,
    startTime,
    authorizationId,
  );

  return new Proxy(s, {
    get(
      proxyTarget: Record<string | symbol, unknown>,
      prop: string | symbol,
    ): unknown {
      if (prop === Symbol.asyncIterator) {
        return () => gen;
      }

      const value = Reflect.get(proxyTarget, prop);
      if (typeof value === "function") {
        return (value as Function).bind(proxyTarget);
      }
      return value;
    },
  });
}

// -- Extraction helpers -------------------------------------------------------

function getModelId(target: Record<string, unknown>): string {
  const modelId = target.model_id ?? target.modelId ?? target.model;
  return typeof modelId === "string" && modelId ? modelId : "unknown";
}

function extractRecord(
  response: unknown,
  modelId: string,
  promptHash: string,
  elapsedMs: number,
): InferenceRecord {
  let responseText = "";
  let inputTokens: number | undefined;
  let outputTokens: number | undefined;
  let hasRefusal = false;

  const r = response as Record<string, unknown> | undefined;
  if (r && typeof r === "object") {
    const actualModel = (r.model_id as string) ?? modelId;
    if (actualModel) modelId = actualModel;

    const results = r.results as Array<Record<string, unknown>> | undefined;
    if (Array.isArray(results) && results.length > 0) {
      const first = results[0];
      if (typeof first.generated_text === "string") {
        responseText = first.generated_text;
      }
      if (typeof first.generated_token_count === "number") {
        outputTokens = first.generated_token_count;
      }
      if (typeof first.input_token_count === "number") {
        inputTokens = first.input_token_count;
      }
      const stopReason = first.stop_reason as string | undefined;
      if (
        stopReason &&
        !["eos_token", "max_tokens", "stop_sequence", "not_finished"].includes(stopReason)
      ) {
        hasRefusal = true;
      }
    }
  }

  return {
    modelId,
    modelHash: sha256Truncated(modelId),
    promptHash,
    responseHash: sha256Truncated(responseText),
    latencyMs: elapsedMs,
    inputTokens,
    outputTokens,
    guardrailsActive: 0,
    guardrailsRequired: 0,
    guardrailPassed: true,
    hasRefusal,
    provider: "ibm-watsonx",
    guardrailNames: [],
  };
}
