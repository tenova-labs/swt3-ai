/**
 * SWT3 AI Witness SDK -- LangGraph Adapter.
 *
 * Wraps a LangGraph CompiledGraph to witness every graph invocation.
 * Supports invoke() and stream() methods (sync and async).
 *
 * Usage:
 *   import { wrapLangGraph } from "@tenova/swt3-ai/adapters/langgraph";
 *   const witnessed = wrapLangGraph(compiledGraph, witness);
 *   const result = await witnessed.invoke({ messages: [["user", "Hello"]] });
 *
 * Duck-typed: works with any object that has an invoke() method.
 * No langgraph import required.
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import type { Witness } from "../witness.js";
import type { InferenceRecord } from "../types.js";
import { sha256Truncated } from "../fingerprint.js";

export interface LangGraphGraph {
  invoke(input: unknown, ...args: unknown[]): unknown;
  stream?(input: unknown, ...args: unknown[]): unknown;
  name?: string;
}

function resolveModelId(graph: LangGraphGraph, explicit?: string): string {
  if (explicit) return explicit;
  if (typeof process !== "undefined") {
    if (process.env.SWT3_MODEL_ID) return process.env.SWT3_MODEL_ID;
    if (process.env.LANGGRAPH_MODEL) return process.env.LANGGRAPH_MODEL;
  }
  if (graph.name) return graph.name;
  return "langgraph-agent";
}

function stringifyValue(val: unknown): string {
  if (val === null || val === undefined) return "";
  if (typeof val === "string") return val;
  try {
    return JSON.stringify(val);
  } catch {
    return String(val);
  }
}

function buildRecord(
  modelId: string,
  input: unknown,
  output: unknown,
  elapsedMs: number,
): InferenceRecord {
  return {
    modelId,
    modelHash: sha256Truncated(modelId),
    promptHash: sha256Truncated(stringifyValue(input)),
    responseHash: sha256Truncated(stringifyValue(output)),
    latencyMs: elapsedMs,
    inputTokens: 0,
    outputTokens: 0,
    guardrailsActive: 0,
    guardrailsRequired: 0,
    guardrailPassed: true,
    hasRefusal: false,
    provider: "langgraph",
    guardrailNames: [],
  };
}

export function wrapLangGraph<T extends LangGraphGraph>(
  graph: T,
  witness: Witness,
  modelId?: string,
): T {
  const mid = resolveModelId(graph, modelId);
  const wrapped = Object.create(graph) as T;

  // Wrap invoke() -- handles both sync and async
  const originalInvoke = graph.invoke.bind(graph);
  wrapped.invoke = (input: unknown, ...args: unknown[]): unknown => {
    const start = performance.now();
    const result = originalInvoke(input, ...args);

    const finish = (res: unknown): unknown => {
      const elapsed = Math.round(performance.now() - start);
      witness.record(buildRecord(mid, input, res, elapsed));
      return res;
    };

    if (result && typeof (result as any).then === "function") {
      return (result as Promise<unknown>).then(finish);
    }
    return finish(result);
  };

  // Wrap stream() if present -- returns async generator
  if (graph.stream) {
    const originalStream = graph.stream.bind(graph);
    wrapped.stream = (input: unknown, ...args: unknown[]): unknown => {
      const result = originalStream(input, ...args);

      // If it returns an async iterable, wrap it
      if (result && typeof (result as any)[Symbol.asyncIterator] === "function") {
        const start = performance.now();
        return (async function* () {
          let lastChunk: unknown = undefined;
          for await (const chunk of result as AsyncIterable<unknown>) {
            lastChunk = chunk;
            yield chunk;
          }
          const elapsed = Math.round(performance.now() - start);
          witness.record(buildRecord(mid, input, lastChunk, elapsed));
        })();
      }

      // If it returns a sync iterable, wrap it
      if (result && typeof (result as any)[Symbol.iterator] === "function") {
        const start = performance.now();
        return (function* () {
          let lastChunk: unknown = undefined;
          for (const chunk of result as Iterable<unknown>) {
            lastChunk = chunk;
            yield chunk;
          }
          const elapsed = Math.round(performance.now() - start);
          witness.record(buildRecord(mid, input, lastChunk, elapsed));
        })();
      }

      return result;
    };
  }

  return wrapped;
}
