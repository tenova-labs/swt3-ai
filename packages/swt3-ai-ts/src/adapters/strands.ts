/**
 * SWT3 AI Witness SDK -- AWS Strands Agent Adapter (ES6 Proxy).
 *
 * Wraps a Strands Agent so that invoke() calls are witnessed,
 * minting anchors for each agent execution (AI-INF.1).
 *
 * Strands TS agents use: const result = await agent.invoke("prompt")
 * This adapter intercepts invoke() to witness the outer invocation.
 *
 * Usage:
 *   import { wrapStrands } from "@tenova/swt3-ai/adapters/strands";
 *
 *   const witnessed = wrapStrands(agent, witness);
 *   const result = await witnessed.invoke("What is 2+2?");
 *
 * Duck-typed -- zero @strands-agents/sdk import at runtime.
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import { sha256Truncated } from "../fingerprint.js";
import type { InferenceRecord } from "../types.js";
import type { Witness } from "../witness.js";

/**
 * Wrap a Strands Agent with an ES6 Proxy for transparent witnessing.
 *
 * Intercepts invoke() calls. All other methods pass through.
 *
 * @param agent - A Strands Agent instance (or any object with invoke()).
 * @param witness - Witness instance for minting anchors.
 * @param modelId - Override model identifier. If undefined, extracted from agent.
 */
export function wrapStrands(
  agent: unknown,
  witness: Witness,
  modelId?: string,
): unknown {
  return new Proxy(agent as object, {
    get(target: object, prop: string | symbol): unknown {
      if (typeof prop === "symbol") return Reflect.get(target, prop);
      const real = Reflect.get(target, prop);

      if (prop === "invoke" || prop === "run") {
        return createInvokeInterceptor(
          real as (...args: unknown[]) => unknown,
          witness,
          target,
          modelId,
        );
      }

      return real;
    },
  });
}

// -- invoke() interceptor -----------------------------------------------------

function createInvokeInterceptor(
  realMethod: (...args: unknown[]) => unknown,
  witness: Witness,
  target: object,
  modelIdOverride?: string,
): (...args: unknown[]) => unknown {
  return function interceptedInvoke(
    this: unknown,
    ...args: unknown[]
  ): unknown {
    // First arg is the prompt string
    const prompt = args[0];
    const promptText = typeof prompt === "string" ? prompt : String(prompt ?? "");
    const promptHash = sha256Truncated(promptText);

    const resolvedModelId = getModelId(target, modelIdOverride);

    let authorizationId: string | undefined;
    if ((witness as any).strict) {
      authorizationId = (witness as any).gateCheck(promptText, resolvedModelId);
    }

    const start = performance.now();
    const result = realMethod.call(this, ...args);

    // invoke() returns a Promise<AgentResult>
    return (result as Promise<unknown>).then((agentResult: unknown) => {
      const elapsedMs = Math.round(performance.now() - start);

      const resultText = stringifyResult(agentResult);
      const responseHash = sha256Truncated(resultText);

      const record: InferenceRecord = {
        modelId: resolvedModelId,
        modelHash: sha256Truncated(resolvedModelId),
        promptHash,
        responseHash,
        latencyMs: elapsedMs,
        guardrailsActive: 0,
        guardrailsRequired: 0,
        guardrailPassed: true,
        hasRefusal: false,
        provider: "aws-strands",
        guardrailNames: [],
      };

      witness.record(record, authorizationId);
      return agentResult;
    });
  };
}

// -- Extraction helpers -------------------------------------------------------

function getModelId(target: object, override?: string): string {
  if (override) return override;

  const t = target as Record<string, unknown>;

  const model = t.model;
  if (typeof model === "string" && model) return model;
  if (model && typeof model === "object") {
    const m = model as Record<string, unknown>;
    const id = m.modelId ?? m.model_id ?? m.id;
    if (typeof id === "string" && id) return id;
  }

  const modelId = t.modelId ?? t.model_id;
  if (typeof modelId === "string" && modelId) return modelId;

  const name = t.name;
  if (typeof name === "string" && name) return `strands-${name}`;

  return "strands-agent";
}

function stringifyResult(result: unknown): string {
  if (result === null || result === undefined) return "";
  if (typeof result === "string") return result;

  // AgentResult has a toString/message property
  const r = result as Record<string, unknown>;
  if (typeof r.message === "string") return r.message;

  try {
    const s = String(result);
    if (s && s !== "[object Object]") return s;
  } catch {
    // fall through
  }

  try {
    return JSON.stringify(result);
  } catch {
    return "";
  }
}
