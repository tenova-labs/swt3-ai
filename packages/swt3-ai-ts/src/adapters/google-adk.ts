/**
 * SWT3 AI Witness SDK -- Google ADK (Agent Development Kit) Adapter.
 *
 * Wraps any object with a run() method (Google ADK Agent pattern),
 * minting witness anchors on each agent execution without modifying
 * the agent logic or adding framework dependencies.
 *
 * Usage:
 *   import { wrapGoogleADK } from "@tenova/swt3-ai/adapters/google-adk";
 *   const witnessed = wrapGoogleADK(agent, witness);
 *   const result = await witnessed.run("What is the weather?");
 *
 * Duck-typed: works with any object that has a run() method.
 * No google-adk import required.
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import type { Witness } from "../witness.js";
import type { InferenceRecord } from "../types.js";
import { sha256Truncated } from "../fingerprint.js";

export interface GoogleADKAgent {
  run(prompt: string, ...args: unknown[]): unknown;
  model?: string;
  name?: string;
}

function resolveModelId(agent: GoogleADKAgent, explicit?: string): string {
  if (explicit) return explicit;
  if (typeof process !== "undefined") {
    if (process.env.SWT3_MODEL_ID) return process.env.SWT3_MODEL_ID;
    if (process.env.GOOGLE_ADK_MODEL) return process.env.GOOGLE_ADK_MODEL;
  }
  if (agent.model) return agent.model;
  if (agent.name) return `google-adk-${agent.name}`;
  return "google-adk-agent";
}

function stringifyResult(result: unknown): string {
  if (result === null || result === undefined) return "";
  if (typeof result === "string") return result;
  try {
    return JSON.stringify(result);
  } catch {
    return String(result);
  }
}

export function wrapGoogleADK<T extends GoogleADKAgent>(
  agent: T,
  witness: Witness,
  modelId?: string,
): T {
  const mid = resolveModelId(agent, modelId);
  const originalRun = agent.run.bind(agent);

  const wrapped = Object.create(agent) as T;

  wrapped.run = (prompt: string, ...args: unknown[]): unknown => {
    const start = performance.now();
    const result = originalRun(prompt, ...args);

    const finish = (res: unknown): unknown => {
      const elapsed = Math.round(performance.now() - start);
      const record: InferenceRecord = {
        modelId: mid,
        modelHash: sha256Truncated(mid),
        promptHash: sha256Truncated(prompt),
        responseHash: sha256Truncated(stringifyResult(res)),
        latencyMs: elapsed,
        inputTokens: 0,
        outputTokens: 0,
        guardrailsActive: 0,
        guardrailsRequired: 0,
        guardrailPassed: true,
        hasRefusal: false,
        provider: "google-adk",
        guardrailNames: [],
      };
      witness.record(record);
      return res;
    };

    // Handle both sync and async run() methods
    if (result && typeof (result as any).then === "function") {
      return (result as Promise<unknown>).then(finish);
    }
    return finish(result);
  };

  return wrapped;
}
