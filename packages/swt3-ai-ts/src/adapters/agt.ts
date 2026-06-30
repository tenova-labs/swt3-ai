/**
 * SWT3 AI Witness SDK -- Microsoft AGT (Agent Governance Toolkit) Adapter.
 *
 * Wraps any object with an evaluate() method (Microsoft AGT policy engine pattern),
 * minting witness anchors on each policy evaluation without modifying
 * the governance logic or adding framework dependencies.
 *
 * SWT3 is the independent witness layer for AGT-managed agents. AGT enforces
 * policy; SWT3 proves what AGT decided, cryptographically, out-of-band.
 *
 * Usage:
 *   import { wrapAGT } from "@tenova/swt3-ai/adapters/agt";
 *   const witnessed = wrapAGT(policyEngine, witness);
 *   const decision = await witnessed.evaluate(prompt, { model: "gpt-4o" });
 *
 * Duck-typed: works with any object that has an evaluate() method.
 * No Microsoft SDK import required.
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import type { Witness } from "../witness.js";
import type { InferenceRecord } from "../types.js";
import { sha256Truncated } from "../fingerprint.js";

export interface AGTEngine {
  evaluate(prompt: unknown, ...args: unknown[]): unknown;
  assess?(config: unknown, ...args: unknown[]): unknown;
  name?: string;
  model?: string;
}

function resolveModelId(engine: AGTEngine, explicit?: string): string {
  if (explicit) return explicit;
  if (typeof process !== "undefined") {
    if (process.env.SWT3_MODEL_ID) return process.env.SWT3_MODEL_ID;
    if (process.env.AGT_MODEL_ID) return process.env.AGT_MODEL_ID;
  }
  if (engine.model) return engine.model;
  if (engine.name) return `agt-${engine.name}`;
  return "agt-policy-engine";
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

interface GuardrailInfo {
  active: number;
  names: string[];
  passed: boolean;
}

function extractGuardrails(result: unknown): GuardrailInfo {
  const info: GuardrailInfo = { active: 0, names: [], passed: true };

  if (result && typeof result === "object" && !Array.isArray(result)) {
    const r = result as Record<string, unknown>;
    const policies = (r.policies_evaluated ?? r.guardrails) as unknown[] | undefined;
    if (Array.isArray(policies)) {
      info.active = policies.length;
      for (const p of policies) {
        if (p && typeof p === "object") {
          const pol = p as Record<string, unknown>;
          const name = (pol.name ?? pol.policy_name) as string | undefined;
          if (name) info.names.push(String(name));
          if (pol.result === "fail" || pol.passed === false) info.passed = false;
        } else if (typeof p === "string") {
          info.names.push(p);
        }
      }
    }
    const verdict = (r.verdict ?? r.decision) as string | undefined;
    if (typeof verdict === "string" && ["deny", "block", "fail", "rejected"].includes(verdict.toLowerCase())) {
      info.passed = false;
    }
  }

  return info;
}

function wrapMethod<T extends AGTEngine>(
  target: T,
  methodName: "evaluate" | "assess",
  witness: Witness,
  mid: string,
): void {
  const original = (target as any)[methodName];
  if (typeof original !== "function") return;
  const bound = original.bind(target);

  (target as any)[methodName] = (input: unknown, ...args: unknown[]): unknown => {
    const start = performance.now();
    const result = bound(input, ...args);

    const finish = (res: unknown): unknown => {
      const elapsed = Math.round(performance.now() - start);
      const guardrails = extractGuardrails(res);
      const record: InferenceRecord = {
        modelId: mid,
        modelHash: sha256Truncated(mid),
        promptHash: sha256Truncated(stringifyValue(input)),
        responseHash: sha256Truncated(stringifyValue(res)),
        latencyMs: elapsed,
        inputTokens: 0,
        outputTokens: 0,
        guardrailsActive: guardrails.active,
        guardrailsRequired: guardrails.active,
        guardrailPassed: guardrails.passed,
        hasRefusal: !guardrails.passed,
        provider: "microsoft-agt",
        guardrailNames: guardrails.names,
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

export function wrapAGT<T extends AGTEngine>(
  engine: T,
  witness: Witness,
  modelId?: string,
): T {
  const mid = resolveModelId(engine, modelId);
  const wrapped = Object.create(engine) as T;

  wrapMethod(wrapped, "evaluate", witness, mid);
  if (engine.assess) {
    wrapMethod(wrapped, "assess", witness, mid);
  }

  return wrapped;
}
