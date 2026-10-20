/**
 * SWT3 AI Witness SDK -- AWS Bedrock Guardrails Adapter (ES6 Proxy).
 *
 * Wraps a boto3/AWS SDK bedrock-runtime client so that applyGuardrail()
 * is intercepted for witnessing. Flat API -- one level of proxy.
 *
 * This is a governance decision adapter (AI-GRD.1), not an inference
 * adapter. It witnesses guardrail evaluations (INTERVENED vs NONE).
 * For inference witnessing on Bedrock, use the existing bedrock adapter.
 *
 * Bedrock applyGuardrail() response:
 *   { action: "GUARDRAIL_INTERVENED" | "NONE",
 *     outputs: [...], assessments: [...], usage: {...} }
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import { sha256Truncated } from "../fingerprint.js";
import type { InferenceRecord } from "../types.js";
import type { Witness } from "../witness.js";

/**
 * Wrap an AWS Bedrock Runtime client with guardrail witnessing.
 *
 * Intercepts applyGuardrail() / apply_guardrail() calls.
 * All other methods pass through.
 */
export function wrapBedrockGuardrails(
  client: unknown,
  witness: Witness,
): unknown {
  return new Proxy(client as object, {
    get(target: object, prop: string | symbol): unknown {
      if (typeof prop === "symbol") return Reflect.get(target, prop);
      const real = Reflect.get(target, prop);

      if (prop === "applyGuardrail" || prop === "apply_guardrail") {
        return createApplyGuardrailInterceptor(
          real as (...args: unknown[]) => unknown,
          witness,
        );
      }

      return real;
    },
  });
}

// -- applyGuardrail() interceptor ---------------------------------------------

function createApplyGuardrailInterceptor(
  realMethod: (...args: unknown[]) => unknown,
  witness: Witness,
): (...args: unknown[]) => unknown {
  return function interceptedApplyGuardrail(
    this: unknown,
    ...args: unknown[]
  ): unknown {
    const kwargs = (args[0] ?? {}) as Record<string, unknown>;
    const guardrailId =
      (kwargs.guardrailIdentifier as string) ??
      (kwargs.GuardrailIdentifier as string) ??
      "unknown";
    const guardrailVersion =
      (kwargs.guardrailVersion as string) ??
      (kwargs.GuardrailVersion as string) ??
      "DRAFT";
    const source =
      (kwargs.source as string) ?? (kwargs.Source as string) ?? "INPUT";
    const content = kwargs.content ?? kwargs.Content ?? [];

    const contentText = extractContentText(content);
    const promptHash = sha256Truncated(contentText);

    const modelId = `guardrail:${guardrailId}:${guardrailVersion}`;

    const start = performance.now();
    const result = realMethod.call(this, ...args);

    // applyGuardrail returns a Promise
    return (result as Promise<unknown>).then((response: unknown) => {
      const elapsedMs = Math.round(performance.now() - start);
      const r = (response ?? {}) as Record<string, unknown>;

      const action = (r.action as string) ?? "NONE";
      const guardrailPassed = action === "NONE";

      const assessments = r.assessments ?? [];
      const outputs = r.outputs ?? [];
      const responseSummary = stableStringify({
        action,
        assessments,
        outputs,
      });
      const responseHash = sha256Truncated(responseSummary);

      // Usage: sum all numeric values -- resilient to new policy types
      const usage = (r.usage ?? {}) as Record<string, unknown>;
      let totalUnits = 0;
      for (const v of Object.values(usage)) {
        if (typeof v === "number") totalUnits += v;
      }

      const record: InferenceRecord = {
        modelId,
        modelHash: sha256Truncated(modelId),
        promptHash,
        responseHash,
        latencyMs: elapsedMs,
        inputTokens: totalUnits > 0 ? totalUnits : undefined,
        guardrailsActive: 1,
        guardrailsRequired: 1,
        guardrailPassed,
        hasRefusal: !guardrailPassed,
        provider: "aws-bedrock-guardrails",
        guardrailNames: [],
        accessTarget: source,
        accessGranted: guardrailPassed,
      };

      witness.record(record);
      return response;
    });
  };
}

// -- Content extraction -------------------------------------------------------

function extractContentText(content: unknown): string {
  const parts: string[] = [];

  if (Array.isArray(content)) {
    for (const item of content) {
      if (typeof item !== "object" || item === null) continue;
      const i = item as Record<string, unknown>;
      const textBlock = i.text;
      if (typeof textBlock === "object" && textBlock !== null) {
        const tb = textBlock as Record<string, unknown>;
        if (typeof tb.text === "string") parts.push(tb.text);
      } else if (typeof textBlock === "string") {
        parts.push(textBlock);
      }
    }
  }

  return parts.join("\n");
}

// -- Stable JSON serialization (cross-language parity with Python sort_keys) --

function stableStringify(obj: unknown): string {
  if (obj === null || obj === undefined) return "null";
  if (typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(stableStringify).join(",") + "]";
  const o = obj as Record<string, unknown>;
  const keys = Object.keys(o).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + stableStringify(o[k])).join(",") + "}";
}
