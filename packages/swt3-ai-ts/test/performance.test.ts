/**
 * Tests for AI-PERF.1 Performance Benchmark Witnessing.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Witness } from "../src/witness.js";
import { BENCHMARK_TYPE_CODES } from "../src/types.js";

function mkWitness(opts: Record<string, unknown> = {}) {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "test_tenant",
    disableFlush: true,
    ...opts,
  });
}

describe("witnessPerformance (AI-PERF.1)", () => {
  let origConsole: typeof console.log;
  beforeEach(() => { origConsole = console.log; console.log = vi.fn(); });
  afterEach(() => { console.log = origConsole; });

  it("mints correct procedure and factors", () => {
    const w = mkWitness();
    const p = w.witnessPerformance({
      metricsEvaluated: 20, metricsPassing: 18,
      benchmarkType: "accuracy",
    });
    expect(p.procedure_id).toBe("AI-PERF.1");
    expect(p.factor_a).toBe(20);
    expect(p.factor_b).toBe(18);
    expect(p.factor_c).toBe(BENCHMARK_TYPE_CODES["accuracy"]);
    expect(p.anchor_fingerprint).toBeTruthy();
  });

  it("maps all benchmark type codes", () => {
    const w = mkWitness();
    for (const [type, code] of Object.entries(BENCHMARK_TYPE_CODES)) {
      const p = w.witnessPerformance({
        metricsEvaluated: 10, metricsPassing: 8, benchmarkType: type,
      });
      expect(p.factor_c).toBe(code);
    }
  });

  it("unknown type defaults to 5", () => {
    const w = mkWitness();
    const p = w.witnessPerformance({
      metricsEvaluated: 10, metricsPassing: 8,
      benchmarkType: "unknown_benchmark",
    });
    expect(p.factor_c).toBe(5);
  });

  it("includes context at clearing level 1", () => {
    const w = mkWitness({ clearingLevel: 1 });
    const p = w.witnessPerformance({
      metricsEvaluated: 20, metricsPassing: 18,
      benchmarkType: "accuracy",
    });
    expect(p.ai_context).toBeTruthy();
    expect(p.ai_context!.benchmark_type).toBe("accuracy");
  });

  it("strips context at clearing level 2", () => {
    const w = mkWitness({ clearingLevel: 2 });
    const p = w.witnessPerformance({
      metricsEvaluated: 20, metricsPassing: 18,
      benchmarkType: "accuracy",
    });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(20);
    expect(p.factor_b).toBe(18);
  });

  it("propagates agent_id from config", () => {
    const w = mkWitness({ agentId: "perf-benchmark-agent" });
    const p = w.witnessPerformance({
      metricsEvaluated: 5, metricsPassing: 5,
      benchmarkType: "accuracy",
    });
    expect(p.agent_id).toBe("perf-benchmark-agent");
  });

  it("mints valid 12-char hex fingerprint", () => {
    const w = mkWitness();
    const p = w.witnessPerformance({
      metricsEvaluated: 1, metricsPassing: 1,
      benchmarkType: "accuracy",
    });
    expect(p.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
  });
});
