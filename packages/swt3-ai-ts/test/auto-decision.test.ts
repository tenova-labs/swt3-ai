/**
 * Tests for AI-AUTO.1 Automated Decision Witnessing.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Witness } from "../src/witness.js";
import { DECISION_TYPE_CODES } from "../src/types.js";

function mkWitness(opts: Record<string, unknown> = {}) {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "test_tenant",
    disableFlush: true,
    ...opts,
  });
}

describe("witnessAutomatedDecision (AI-AUTO.1)", () => {
  let origConsole: typeof console.log;
  beforeEach(() => { origConsole = console.log; console.log = vi.fn(); });
  afterEach(() => { console.log = origConsole; });

  it("mints correct procedure and factors", () => {
    const w = mkWitness();
    const p = w.witnessAutomatedDecision({
      decisionsMade: 500, humanReviewed: 50,
      decisionType: "credit",
    });
    expect(p.procedure_id).toBe("AI-AUTO.1");
    expect(p.factor_a).toBe(500);
    expect(p.factor_b).toBe(50);
    expect(p.factor_c).toBe(DECISION_TYPE_CODES["credit"]);
    expect(p.anchor_fingerprint).toBeTruthy();
  });

  it("maps all decision type codes", () => {
    const w = mkWitness();
    for (const [type, code] of Object.entries(DECISION_TYPE_CODES)) {
      const p = w.witnessAutomatedDecision({
        decisionsMade: 10, humanReviewed: 5, decisionType: type,
      });
      expect(p.factor_c).toBe(code);
    }
  });

  it("unknown type defaults to 5", () => {
    const w = mkWitness();
    const p = w.witnessAutomatedDecision({
      decisionsMade: 10, humanReviewed: 5,
      decisionType: "unknown_decision",
    });
    expect(p.factor_c).toBe(5);
  });

  it("includes context at clearing level 1", () => {
    const w = mkWitness({ clearingLevel: 1 });
    const p = w.witnessAutomatedDecision({
      decisionsMade: 500, humanReviewed: 50,
      decisionType: "credit",
    });
    expect(p.ai_context).toBeTruthy();
    expect(p.ai_context!.decision_type).toBe("credit");
  });

  it("strips context at clearing level 2", () => {
    const w = mkWitness({ clearingLevel: 2 });
    const p = w.witnessAutomatedDecision({
      decisionsMade: 500, humanReviewed: 50,
      decisionType: "credit",
    });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(500);
    expect(p.factor_b).toBe(50);
  });

  it("propagates agent_id from config", () => {
    const w = mkWitness({ agentId: "auto-decision-agent" });
    const p = w.witnessAutomatedDecision({
      decisionsMade: 100, humanReviewed: 10,
      decisionType: "credit",
    });
    expect(p.agent_id).toBe("auto-decision-agent");
  });

  it("mints valid 12-char hex fingerprint", () => {
    const w = mkWitness();
    const p = w.witnessAutomatedDecision({
      decisionsMade: 1, humanReviewed: 1,
      decisionType: "credit",
    });
    expect(p.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
  });
});
