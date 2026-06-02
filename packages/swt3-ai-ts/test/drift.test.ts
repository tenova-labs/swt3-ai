/**
 * Tests for AI-DRIFT.1 Model Drift Detection Witnessing.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Witness } from "../src/witness.js";
import { DRIFT_TYPE_CODES } from "../src/types.js";

function mkWitness(opts: Record<string, unknown> = {}) {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "test_tenant",
    disableFlush: true,
    ...opts,
  });
}

describe("witnessDrift (AI-DRIFT.1)", () => {
  let origConsole: typeof console.log;
  beforeEach(() => { origConsole = console.log; console.log = vi.fn(); });
  afterEach(() => { console.log = origConsole; });

  it("mints correct procedure and factors", () => {
    const w = mkWitness();
    const p = w.witnessDrift({
      metricsEvaluated: 10, driftedCount: 3,
      driftType: "data",
    });
    expect(p.procedure_id).toBe("AI-DRIFT.1");
    expect(p.factor_a).toBe(10);
    expect(p.factor_b).toBe(3);
    expect(p.factor_c).toBe(DRIFT_TYPE_CODES["data"]);
    expect(p.anchor_fingerprint).toBeTruthy();
  });

  it("maps all drift type codes", () => {
    const w = mkWitness();
    for (const [type, code] of Object.entries(DRIFT_TYPE_CODES)) {
      const p = w.witnessDrift({
        metricsEvaluated: 10, driftedCount: 3, driftType: type,
      });
      expect(p.factor_c).toBe(code);
    }
  });

  it("unknown type defaults to 0", () => {
    const w = mkWitness();
    const p = w.witnessDrift({
      metricsEvaluated: 10, driftedCount: 3,
      driftType: "unknown_drift_type",
    });
    expect(p.factor_c).toBe(0);
  });

  it("includes context at clearing level 1", () => {
    const w = mkWitness({ clearingLevel: 1 });
    const p = w.witnessDrift({
      metricsEvaluated: 10, driftedCount: 3,
      driftType: "data",
    });
    expect(p.ai_context).toBeTruthy();
    expect(p.ai_context!.drift_type).toBe("data");
  });

  it("strips context at clearing level 2", () => {
    const w = mkWitness({ clearingLevel: 2 });
    const p = w.witnessDrift({
      metricsEvaluated: 10, driftedCount: 3,
      driftType: "data",
    });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(10);
    expect(p.factor_b).toBe(3);
  });

  it("propagates agent_id from config", () => {
    const w = mkWitness({ agentId: "drift-monitor-agent" });
    const p = w.witnessDrift({
      metricsEvaluated: 10, driftedCount: 3,
      driftType: "data",
    });
    expect(p.agent_id).toBe("drift-monitor-agent");
  });

  it("mints valid 12-char hex fingerprint", () => {
    const w = mkWitness();
    const p = w.witnessDrift({
      metricsEvaluated: 1, driftedCount: 0,
      driftType: "data",
    });
    expect(p.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
  });
});
