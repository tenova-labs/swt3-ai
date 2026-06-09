/**
 * SWT3 AI Witness SDK -- A2A (Agent-to-Agent) Protocol Adapter.
 *
 * Wraps any object with a send() method (Google A2A protocol pattern),
 * minting witness anchors on each inter-agent message without modifying
 * the agent logic or adding protocol dependencies.
 *
 * Usage:
 *   import { wrapA2A } from "@tenova/swt3-ai/adapters/a2a";
 *   const witnessed = wrapA2A(agent, witness);
 *   const result = await witnessed.send({ text: "Analyze this data" });
 *
 * Duck-typed: works with any object that has a send() method.
 * No A2A protocol import required.
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import type { Witness } from "../witness.js";
import type { InferenceRecord } from "../types.js";
import { sha256Truncated } from "../fingerprint.js";

export interface A2AAgent {
  send(message: unknown, ...args: unknown[]): unknown;
  handleMessage?(message: unknown, ...args: unknown[]): unknown;
  name?: string;
  model?: string;
}

function resolveModelId(agent: A2AAgent, explicit?: string): string {
  if (explicit) return explicit;
  if (typeof process !== "undefined" && process.env.SWT3_MODEL_ID) {
    return process.env.SWT3_MODEL_ID;
  }
  if (agent.model) return agent.model;
  if (agent.name) return `a2a-${agent.name}`;
  return "a2a-agent";
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

function wrapMethod<T extends A2AAgent>(
  target: T,
  methodName: "send" | "handleMessage",
  witness: Witness,
  mid: string,
): void {
  const original = (target as any)[methodName];
  if (typeof original !== "function") return;
  const bound = original.bind(target);

  (target as any)[methodName] = (message: unknown, ...args: unknown[]): unknown => {
    const start = performance.now();
    const result = bound(message, ...args);

    const finish = (res: unknown): unknown => {
      const elapsed = Math.round(performance.now() - start);
      const record: InferenceRecord = {
        modelId: mid,
        modelHash: sha256Truncated(mid),
        promptHash: sha256Truncated(stringifyMessage(message)),
        responseHash: sha256Truncated(stringifyMessage(res)),
        latencyMs: elapsed,
        inputTokens: 0,
        outputTokens: 0,
        guardrailsActive: 0,
        guardrailsRequired: 0,
        guardrailPassed: true,
        hasRefusal: false,
        provider: "a2a",
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

export function wrapA2A<T extends A2AAgent>(
  agent: T,
  witness: Witness,
  modelId?: string,
): T {
  const mid = resolveModelId(agent, modelId);
  const wrapped = Object.create(agent) as T;

  wrapMethod(wrapped, "send", witness, mid);
  if (agent.handleMessage) {
    wrapMethod(wrapped, "handleMessage", witness, mid);
  }

  return wrapped;
}
