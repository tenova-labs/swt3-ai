/**
 * Tests for AI-ROBUST.1 Robustness Testing Witnessing.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Witness } from "../src/witness.js";
import { PERTURBATION_TYPE_CODES } from "../src/types.js";

function mkWitness(opts: Record<string, unknown> = {}) {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "test_tenant",
    disableFlush: true,
    ...opts,
  });
}

describe("witnessRobustness (AI-ROBUST.1)", () => {
  let origConsole: typeof console.log;
  beforeEach(() => { origConsole = console.log; console.log = vi.fn(); });
  afterEach(() => { console.log = origConsole; });

  it("mints correct procedure and factors", () => {
    const w = mkWitness();
    const p = w.witnessRobustness({
      perturbationsTested: 100, perturbationsSurvived: 95,
      perturbationType: "noise",
    });
    expect(p.procedure_id).toBe("AI-ROBUST.1");
    expect(p.factor_a).toBe(100);
    expect(p.factor_b).toBe(95);
    expect(p.factor_c).toBe(PERTURBATION_TYPE_CODES["noise"]);
    expect(p.anchor_fingerprint).toBeTruthy();
  });

  it("maps all perturbation type codes", () => {
    const w = mkWitness();
    for (const [type, code] of Object.entries(PERTURBATION_TYPE_CODES)) {
      const p = w.witnessRobustness({
        perturbationsTested: 50, perturbationsSurvived: 40, perturbationType: type,
      });
      expect(p.factor_c).toBe(code);
    }
  });

  it("unknown type defaults to 5", () => {
    const w = mkWitness();
    const p = w.witnessRobustness({
      perturbationsTested: 50, perturbationsSurvived: 40,
      perturbationType: "unknown_perturbation",
    });
    expect(p.factor_c).toBe(5);
  });

  it("includes context at clearing level 1", () => {
    const w = mkWitness({ clearingLevel: 1 });
    const p = w.witnessRobustness({
      perturbationsTested: 100, perturbationsSurvived: 95,
      perturbationType: "noise",
    });
    expect(p.ai_context).toBeTruthy();
    expect(p.ai_context!.perturbation_type).toBe("noise");
  });

  it("strips context at clearing level 2", () => {
    const w = mkWitness({ clearingLevel: 2 });
    const p = w.witnessRobustness({
      perturbationsTested: 100, perturbationsSurvived: 95,
      perturbationType: "noise",
    });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(100);
    expect(p.factor_b).toBe(95);
  });

  it("propagates agent_id from config", () => {
    const w = mkWitness({ agentId: "robustness-test-agent" });
    const p = w.witnessRobustness({
      perturbationsTested: 10, perturbationsSurvived: 9,
      perturbationType: "noise",
    });
    expect(p.agent_id).toBe("robustness-test-agent");
  });

  it("mints valid 12-char hex fingerprint", () => {
    const w = mkWitness();
    const p = w.witnessRobustness({
      perturbationsTested: 1, perturbationsSurvived: 1,
      perturbationType: "noise",
    });
    expect(p.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
  });
});
