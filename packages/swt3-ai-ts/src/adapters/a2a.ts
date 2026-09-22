/**
 * SWT3 AI Witness SDK -- A2A (Agent-to-Agent) Protocol Adapter.
 *
 * Wraps any object with a send() method (Google A2A protocol pattern),
 * minting witness anchors on each inter-agent message without modifying
 * the agent logic or adding protocol dependencies.
 *
 * v0.7.3: Also wraps createTask/getTask/cancelTask and auto-mints
 * AI-A2A.1 (task lifecycle) and AI-A2A.3 (context chain) anchors.
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
  createTask?(params: unknown, ...args: unknown[]): unknown;
  getTask?(taskId: unknown, ...args: unknown[]): unknown;
  cancelTask?(taskId: unknown, ...args: unknown[]): unknown;
  name?: string;
  model?: string;
}

/** Maps A2A task state strings to numeric codes. */
export const A2A_STATE_MAP: Record<string, number> = {
  submitted: 0,
  working: 1,
  input_required: 2,
  completed: 3,
  canceled: 4,
  failed: 5,
  rejected: 6,
};

/** Extract task state from a duck-typed result. */
function extractTaskState(result: unknown): string | undefined {
  if (result === null || result === undefined) return undefined;
  if (typeof result === "object") {
    const r = result as Record<string, unknown>;
    // Property-style access
    if (typeof r.state === "string") return r.state;
    if (typeof r.status === "string") return r.status;
    // Nested task object
    if (r.task && typeof r.task === "object") {
      const task = r.task as Record<string, unknown>;
      if (typeof task.state === "string") return task.state;
      if (typeof task.status === "string") return task.status;
    }
    // Dict-style: result["state"]
    if (typeof r["state"] === "string") return r["state"] as string;
  }
  return undefined;
}

/** Extract context ID from a duck-typed result. */
function extractContextId(result: unknown): string | undefined {
  if (result === null || result === undefined) return undefined;
  if (typeof result === "object") {
    const r = result as Record<string, unknown>;
    if (typeof r.contextId === "string") return r.contextId;
    if (typeof r.context_id === "string") return r.context_id;
    if (typeof r.sessionId === "string") return r.sessionId;
    if (typeof r.session_id === "string") return r.session_id;
    if (r.task && typeof r.task === "object") {
      const task = r.task as Record<string, unknown>;
      if (typeof task.contextId === "string") return task.contextId;
      if (typeof task.context_id === "string") return task.context_id;
      if (typeof task.sessionId === "string") return task.sessionId;
      if (typeof task.session_id === "string") return task.session_id;
    }
  }
  return undefined;
}

/** Extract task ID from a duck-typed result. */
function extractTaskId(result: unknown): string | undefined {
  if (result === null || result === undefined) return undefined;
  if (typeof result === "object") {
    const r = result as Record<string, unknown>;
    if (typeof r.id === "string") return r.id;
    if (typeof r.taskId === "string") return r.taskId;
    if (typeof r.task_id === "string") return r.task_id;
    if (r.task && typeof r.task === "object") {
      const task = r.task as Record<string, unknown>;
      if (typeof task.id === "string") return task.id;
      if (typeof task.taskId === "string") return task.taskId;
      if (typeof task.task_id === "string") return task.task_id;
    }
  }
  return undefined;
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

/**
 * Auto-witness task lifecycle and context chain from a task result.
 * Called after any method that may return A2A task state.
 */
function _witnessTaskResult(
  witness: Witness,
  result: unknown,
  startMs: number,
  agentName?: string,
): void {
  const state = extractTaskState(result);
  if (state === undefined) return;

  const stateCode = A2A_STATE_MAP[state] ?? A2A_STATE_MAP[state.toLowerCase()] ?? -1;
  if (stateCode < 0) return;

  const elapsed = Math.round(performance.now() - startMs);
  const taskId = extractTaskId(result);
  const contextId = extractContextId(result);

  // Mint AI-A2A.1 (task lifecycle)
  witness.witnessTaskLifecycle({
    stateCode,
    latencyMs: elapsed,
    depth: 1,
    taskId,
    fromAgent: agentName,
  });

  // Mint AI-A2A.3 (context chain) if contextId is present
  if (contextId) {
    witness.witnessContextChain({
      chainLength: 1,
      contextId,
      agentsInChain: 1,
      currentAgentId: agentName,
    });
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

      // Auto-witness task result from send/handleMessage
      _witnessTaskResult(witness, res, start, target.name);

      return res;
    };

    if (result && typeof (result as any).then === "function") {
      return (result as Promise<unknown>).then(finish);
    }
    return finish(result);
  };
}

function wrapTaskMethod<T extends A2AAgent>(
  target: T,
  methodName: "createTask" | "getTask" | "cancelTask",
  witness: Witness,
): void {
  const original = (target as any)[methodName];
  if (typeof original !== "function") return;
  const bound = original.bind(target);

  (target as any)[methodName] = (param: unknown, ...args: unknown[]): unknown => {
    const start = performance.now();
    const result = bound(param, ...args);

    const finish = (res: unknown): unknown => {
      _witnessTaskResult(witness, res, start, target.name);
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

  // Wrap task lifecycle methods if present
  if (agent.createTask) {
    wrapTaskMethod(wrapped, "createTask", witness);
  }
  if (agent.getTask) {
    wrapTaskMethod(wrapped, "getTask", witness);
  }
  if (agent.cancelTask) {
    wrapTaskMethod(wrapped, "cancelTask", witness);
  }

  return wrapped;
}
