/**
 * SWT3 AI Witness SDK -- Microsoft Foundry Adapter.
 *
 * Wraps any object with an execute() method (Microsoft Agent Framework pattern),
 * minting witness anchors on each agent execution without modifying
 * the agent logic or adding framework dependencies.
 *
 * Usage:
 *   import { wrapFoundry } from "@tenova/swt3-ai/adapters/foundry";
 *   const witnessed = wrapFoundry(agent, witness);
 *   const result = await witnessed.execute("Summarize this document");
 *
 * Duck-typed: works with any object that has an execute() method.
 * No Microsoft SDK import required.
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import type { Witness } from "../witness.js";
import type { InferenceRecord } from "../types.js";
import { sha256Truncated } from "../fingerprint.js";

export interface FoundryAgent {
  execute(prompt: unknown, ...args: unknown[]): unknown;
  interceptToolCall?(toolName: string, toolInput: unknown, ...args: unknown[]): unknown;
  name?: string;
  model?: string;
}

function resolveModelId(agent: FoundryAgent, explicit?: string): string {
  if (explicit) return explicit;
  if (typeof process !== "undefined" && process.env.SWT3_MODEL_ID) {
    return process.env.SWT3_MODEL_ID;
  }
  if (agent.model) return agent.model;
  if (agent.name) return `foundry-${agent.name}`;
  return "foundry-agent";
}

function stringifyMessage(msg: unknown): string {
  if (msg === null || msg === undefined) return "";
  if (typeof msg === "string") return msg;
  try {
    return JSON.stringify(msg);
  } catch {
    return String(msg);
  }
}

function wrapMethod<T extends FoundryAgent>(
  target: T,
  methodName: "execute" | "interceptToolCall",
  witness: Witness,
  mid: string,
): void {
  const original = (target as any)[methodName];
  if (typeof original !== "function") return;
  const bound = original.bind(target);

  if (methodName === "execute") {
    (target as any)[methodName] = (prompt: unknown, ...args: unknown[]): unknown => {
      const start = performance.now();
      const result = bound(prompt, ...args);

      const finish = (res: unknown): unknown => {
        const elapsed = Math.round(performance.now() - start);
        const record: InferenceRecord = {
          modelId: mid,
          modelHash: sha256Truncated(mid),
          promptHash: sha256Truncated(stringifyMessage(prompt)),
          responseHash: sha256Truncated(stringifyMessage(res)),
          latencyMs: elapsed,
          inputTokens: 0,
          outputTokens: 0,
          guardrailsActive: 0,
          guardrailsRequired: 0,
          guardrailPassed: true,
          hasRefusal: false,
          provider: "microsoft-foundry",
          guardrailNames: [],
        };
        witness.record(record);
        return res;
      };

      if (result && typeof (result as any).then === "function") {
        return (result as Promise<unknown>).then(finish);
      }
      return finish(result);
    };
  } else {
    (target as any)[methodName] = (toolName: string, toolInput: unknown, ...args: unknown[]): unknown => {
      const start = performance.now();
      const result = bound(toolName, toolInput, ...args);

      const finish = (res: unknown): unknown => {
        const elapsed = Math.round(performance.now() - start);
        const record: InferenceRecord = {
          modelId: mid,
          modelHash: sha256Truncated(mid),
          promptHash: sha256Truncated(`${toolName}:${stringifyMessage(toolInput)}`),
          responseHash: sha256Truncated(stringifyMessage(res)),
          latencyMs: elapsed,
          inputTokens: 0,
          outputTokens: 0,
          guardrailsActive: 0,
          guardrailsRequired: 0,
          guardrailPassed: true,
          hasRefusal: false,
          provider: "microsoft-foundry",
          guardrailNames: [],
        };
        witness.record(record);
        return res;
      };

      if (result && typeof (result as any).then === "function") {
        return (result as Promise<unknown>).then(finish);
      }
      return finish(result);
    };
  }
}

export function wrapFoundry<T extends FoundryAgent>(
  agent: T,
  witness: Witness,
  modelId?: string,
): T {
  const mid = resolveModelId(agent, modelId);
  const wrapped = Object.create(agent) as T;

  wrapMethod(wrapped, "execute", witness, mid);
  if (agent.interceptToolCall) {
    wrapMethod(wrapped, "interceptToolCall", witness, mid);
  }

  return wrapped;
}
