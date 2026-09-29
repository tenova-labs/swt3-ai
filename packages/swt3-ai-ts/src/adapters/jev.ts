/**
 * SWT3 AI Witness SDK -- Jev (TypeSafe AI) Adapter (ES6 Proxy).
 *
 * Wraps a Jev client to auto-witness Choice, Score, and Noul API calls.
 * Jev returns typed decisions with calibrated probabilities instead of text.
 * Zero dependency -- pure duck-typing, no import of the Jev SDK.
 *
 * Factor mapping:
 *   Choice: fa=option_index, fb=confidence*1000 (int), fc=cardinality
 *   Score:  fa=score_value*1000, fb=confidence*1000, fc=num_classes
 *   Noul:   fa=0 (null output), fb=0, fc=0
 *
 * Expected Jev client interface (duck-typed):
 *   client.choice(options, ...args) -> { index, confidence, options }
 *   client.score(input, ...args)    -> { value, confidence, classes }
 *   client.noul(input, ...args)     -> { } (null/abstain decision)
 *   client.model? (optional string) -> model identifier
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import { sha256Truncated } from "../fingerprint.js";
import type { InferenceRecord } from "../types.js";
import type { Witness } from "../witness.js";

/** Duck-typed Jev client interface for documentation. */
export interface JevLikeClient {
  choice(...args: unknown[]): unknown;
  score(...args: unknown[]): unknown;
  noul(...args: unknown[]): unknown;
  model?: string;
}

/**
 * Wrap a Jev client with an ES6 Proxy for transparent witnessing.
 *
 * Works with any object that has choice(), score(), noul() methods.
 */
export function wrapJev(client: unknown, witness: Witness): unknown {
  return new Proxy(client as object, {
    get(target: object, prop: string | symbol): unknown {
      if (typeof prop === "symbol") return Reflect.get(target, prop);
      const real = Reflect.get(target, prop);

      if (prop === "choice" || prop === "score" || prop === "noul") {
        return createInterceptor(
          real as (...args: unknown[]) => unknown,
          witness,
          prop,
          target,
        );
      }

      return real;
    },
  });
}

function getModelId(target: object): string {
  return (target as Record<string, unknown>).model as string || "jev";
}

function extractChoiceFactors(result: Record<string, unknown>): [number, number, number] {
  const index = (result.index as number) ?? 0;
  const confidence = (result.confidence as number) ?? 0;
  const options = result.options as unknown[];
  const cardinality = Array.isArray(options) ? options.length : 0;
  return [index, Math.round(confidence * 1000), cardinality];
}

function extractScoreFactors(result: Record<string, unknown>): [number, number, number] {
  const value = (result.value as number) ?? 0;
  const confidence = (result.confidence as number) ?? 0;
  const classes = result.classes as unknown[];
  const numClasses = Array.isArray(classes) ? classes.length : 0;
  return [Math.round(value * 1000), Math.round(confidence * 1000), numClasses];
}

function buildRecord(
  method: string,
  target: object,
  result: unknown,
  elapsedMs: number,
): InferenceRecord {
  const modelId = getModelId(target);
  const r = result as Record<string, unknown>;
  let fa: number, fb: number, fc: number;

  if (method === "choice") {
    [fa, fb, fc] = extractChoiceFactors(r);
  } else if (method === "score") {
    [fa, fb, fc] = extractScoreFactors(r);
  } else {
    fa = 0; fb = 0; fc = 0;
  }

  return {
    modelId: `jev-${method}`,
    modelHash: sha256Truncated(modelId, 16),
    promptHash: sha256Truncated(String(Date.now()), 12),
    responseHash: sha256Truncated(JSON.stringify(r).slice(0, 256), 12),
    latencyMs: Math.round(elapsedMs),
    guardrailsActive: 0,
    guardrailsRequired: 0,
    guardrailPassed: true,
    hasRefusal: method === "noul",
    provider: "jev",
    guardrailNames: [],
  };
}

function createInterceptor(
  realMethod: (...args: unknown[]) => unknown,
  witness: Witness,
  method: string,
  target: object,
): (...args: unknown[]) => unknown {
  return (...args: unknown[]) => {
    const t0 = performance.now();
    const maybePromise = realMethod.apply(target, args);

    if (maybePromise && typeof (maybePromise as Promise<unknown>).then === "function") {
      return (maybePromise as Promise<unknown>).then((result) => {
        const elapsedMs = performance.now() - t0;
        const record = buildRecord(method, target, result, elapsedMs);
        witness.record(record);
        return result;
      });
    }

    const elapsedMs = performance.now() - t0;
    const record = buildRecord(method, target, maybePromise, elapsedMs);
    witness.record(record);
    return maybePromise;
  };
}
