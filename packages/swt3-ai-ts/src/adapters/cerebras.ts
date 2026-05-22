/**
 * SWT3 AI Witness SDK -- Cerebras WSE-3 Adapter.
 *
 * Host-side compliance witnessing for Cerebras wafer-scale inference.
 * Wraps any object with launch()/memcpyD2H() methods, minting anchors
 * on device-to-host transfers without modifying CSL kernels.
 *
 * Usage:
 *   import { wrapCerebrasRuntime } from "@tenova/swt3-ai/adapters/cerebras";
 *   const witnessed = wrapCerebrasRuntime(runtime, witness);
 *   witnessed.launch("kernel_name");
 *   const result = witnessed.memcpyD2H(symbol, shape);
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import type { Witness } from "../witness.js";
import type { InferenceRecord } from "../types.js";
import { sha256Truncated } from "../fingerprint.js";
import { createHash } from "crypto";

export interface CerebrasRuntime {
  launch(kernelName: string, ...args: unknown[]): unknown;
  memcpyD2H?(...args: unknown[]): unknown;
  memcpyH2D?(...args: unknown[]): unknown;
}

interface CerebrasState {
  launchTime: number | null;
  kernelName: string | null;
  launchCount: number;
}

function hashBuffer(data: unknown): string {
  if (data === null || data === undefined) return "";
  if (data instanceof Buffer || data instanceof Uint8Array) {
    return createHash("sha256").update(data).digest("hex").slice(0, 16);
  }
  if (typeof data === "string") {
    return sha256Truncated(data);
  }
  if (data instanceof ArrayBuffer) {
    return createHash("sha256").update(Buffer.from(data)).digest("hex").slice(0, 16);
  }
  return sha256Truncated(String(data));
}

export function wrapCerebrasRuntime(
  runtime: CerebrasRuntime,
  witness: Witness,
  modelId?: string,
): CerebrasRuntime & { readonly launchCount: number } {
  const mid = modelId ?? process.env.SWT3_MODEL_ID ?? process.env.CEREBRAS_MODEL_NAME ?? "cerebras-wse3";

  const state: CerebrasState = {
    launchTime: null,
    kernelName: null,
    launchCount: 0,
  };

  const originalLaunch = runtime.launch.bind(runtime);
  const originalMemcpy = runtime.memcpyD2H?.bind(runtime);

  const wrapped: CerebrasRuntime & { readonly launchCount: number } = Object.create(runtime);

  wrapped.launch = (kernelName: string, ...args: unknown[]): unknown => {
    state.launchTime = performance.now();
    state.kernelName = kernelName;
    state.launchCount++;
    return originalLaunch(kernelName, ...args);
  };

  if (originalMemcpy) {
    wrapped.memcpyD2H = (...args: unknown[]): unknown => {
      const result = originalMemcpy(...args);
      const elapsed = state.launchTime !== null
        ? Math.round(performance.now() - state.launchTime)
        : 0;

      const record: InferenceRecord = {
        modelId: mid,
        modelHash: sha256Truncated(mid),
        promptHash: state.kernelName ? sha256Truncated(state.kernelName) : "",
        responseHash: hashBuffer(result),
        latencyMs: elapsed,
        inputTokens: 0,
        outputTokens: 0,
        guardrailsActive: 0,
        guardrailsRequired: 0,
        guardrailPassed: true,
        hasRefusal: false,
        provider: "cerebras-wse3",
        guardrailNames: [],
      };
      witness.record(record);
      return result;
    };
  }

  Object.defineProperty(wrapped, "launchCount", {
    get: () => state.launchCount,
    enumerable: true,
  });

  return wrapped;
}
