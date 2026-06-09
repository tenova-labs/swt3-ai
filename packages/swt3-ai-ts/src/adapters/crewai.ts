/**
 * SWT3 AI Witness SDK -- CrewAI Adapter.
 *
 * Wraps any object with a kickoff() method (CrewAI Crew pattern),
 * minting witness anchors on each crew execution without modifying
 * the crew logic or adding framework dependencies.
 *
 * Usage:
 *   import { wrapCrewAI } from "@tenova/swt3-ai/adapters/crewai";
 *   const witnessed = wrapCrewAI(crew, witness);
 *   const result = await witnessed.kickoff();
 *
 * Duck-typed: works with any object that has a kickoff() method.
 * No crewai import required.
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import type { Witness } from "../witness.js";
import type { InferenceRecord } from "../types.js";
import { sha256Truncated } from "../fingerprint.js";

export interface CrewAICrew {
  kickoff(inputs?: Record<string, unknown>): unknown;
  name?: string;
  agents?: unknown[];
  tasks?: unknown[];
}

function resolveModelId(crew: CrewAICrew, explicit?: string): string {
  if (explicit) return explicit;
  if (typeof process !== "undefined" && process.env.SWT3_MODEL_ID) {
    return process.env.SWT3_MODEL_ID;
  }
  if (crew.name) return `crewai-${crew.name}`;
  return "crewai-crew";
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

export function wrapCrewAI<T extends CrewAICrew>(
  crew: T,
  witness: Witness,
  modelId?: string,
): T {
  const mid = resolveModelId(crew, modelId);
  const originalKickoff = crew.kickoff.bind(crew);
  const agentCount = Array.isArray(crew.agents) ? crew.agents.length : 0;
  const taskCount = Array.isArray(crew.tasks) ? crew.tasks.length : 0;

  const wrapped = Object.create(crew) as T;

  wrapped.kickoff = (inputs?: Record<string, unknown>): unknown => {
    const start = performance.now();
    const inputStr = inputs ? JSON.stringify(inputs) : "kickoff";
    const result = originalKickoff(inputs);

    const finish = (res: unknown): unknown => {
      const elapsed = Math.round(performance.now() - start);
      const record: InferenceRecord = {
        modelId: mid,
        modelHash: sha256Truncated(mid),
        promptHash: sha256Truncated(inputStr),
        responseHash: sha256Truncated(stringifyResult(res)),
        latencyMs: elapsed,
        inputTokens: agentCount,
        outputTokens: taskCount,
        guardrailsActive: 0,
        guardrailsRequired: 0,
        guardrailPassed: true,
        hasRefusal: false,
        provider: "crewai",
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

  return wrapped;
}
