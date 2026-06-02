/**
 * SWT3 AI Witness SDK -- AI-BASE.1 Agent Behavioral Baseline Tests.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Witness } from "../src/witness.js";
import { BASELINE_MODE_CODES } from "../src/types.js";

beforeEach(() => {
  vi.spyOn(console, "info").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
});
afterEach(() => vi.restoreAllMocks());

function mkWitness(overrides: Record<string, unknown> = {}): Witness {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "test_tenant",
    flushInterval: 999999,
    ...overrides,
  } as any);
}

describe("witnessAgentBaseline (AI-BASE.1)", () => {
  it("mints correct procedure for establishing mode", () => {
    const w = mkWitness();
    const p = w.witnessAgentBaseline({
      dimensions: 8,
      withinEnvelope: true,
      mode: "establishing",
      driftScore: 0.0,
      baselineHash: "baseline_abc",
      currentHash: "current_abc",
    });
    expect(p.procedure_id).toBe("AI-BASE.1");
    expect(p.factor_a).toBe(8);
    expect(p.factor_b).toBe(1);
    expect(p.factor_c).toBe(0); // establishing
    expect(p.anchor_fingerprint).toBeTruthy();
  });

  it("maps all mode codes correctly", () => {
    const w = mkWitness();
    for (const [mode, code] of Object.entries(BASELINE_MODE_CODES)) {
      const p = w.witnessAgentBaseline({
        dimensions: 5,
        withinEnvelope: mode !== "drift_detected",
        mode,
        driftScore: mode === "drift_detected" ? 0.8 : 0.1,
        baselineHash: "bh",
        currentHash: "ch",
      });
      expect(p.factor_c).toBe(code);
    }
  });

  it("sets factor_b=0 when drift detected", () => {
    const w = mkWitness();
    const p = w.witnessAgentBaseline({
      dimensions: 12,
      withinEnvelope: false,
      mode: "drift_detected",
      driftScore: 0.85,
      baselineHash: "bh",
      currentHash: "ch",
    });
    expect(p.factor_b).toBe(0);
    expect(p.factor_c).toBe(2);
  });

  it("includes drift_score and hashes in ai_context", () => {
    const w = mkWitness();
    const p = w.witnessAgentBaseline({
      dimensions: 10,
      withinEnvelope: true,
      mode: "monitoring",
      driftScore: 0.23,
      baselineHash: "bl_hash",
      currentHash: "cur_hash",
      driftThreshold: 0.6,
      baselineWindowHours: 72,
    });
    expect(p.ai_context?.drift_score).toBe(0.23);
    expect(p.ai_context?.baseline_hash).toBe("bl_hash");
    expect(p.ai_context?.current_hash).toBe("cur_hash");
    expect(p.ai_context?.drift_threshold).toBe(0.6);
    expect(p.ai_context?.baseline_window_hours).toBe(72);
  });

  it("defaults drift_threshold to 0.5", () => {
    const w = mkWitness();
    const p = w.witnessAgentBaseline({
      dimensions: 5,
      withinEnvelope: true,
      mode: "monitoring",
      driftScore: 0.1,
      baselineHash: "bh",
      currentHash: "ch",
    });
    expect(p.ai_context?.drift_threshold).toBe(0.5);
  });

  it("auto-hashes agent_id into ai_context", () => {
    const w = mkWitness({ agentId: "agent-sentinel-1" });
    const p = w.witnessAgentBaseline({
      dimensions: 5,
      withinEnvelope: true,
      mode: "monitoring",
      driftScore: 0.1,
      baselineHash: "bh",
      currentHash: "ch",
    });
    expect(p.ai_context?.agent_id_hash).toBeTruthy();
    expect(typeof p.ai_context?.agent_id_hash).toBe("string");
    expect(p.agent_id).toBe("agent-sentinel-1");
  });

  it("strips ai_context at clearing_level 3", () => {
    const w = mkWitness({ clearingLevel: 3 });
    const p = w.witnessAgentBaseline({
      dimensions: 20,
      withinEnvelope: false,
      mode: "drift_detected",
      driftScore: 0.9,
      baselineHash: "bh",
      currentHash: "ch",
    });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(20);
    expect(p.factor_b).toBe(0);
    expect(p.factor_c).toBe(2);
  });

  it("defaults unknown mode to code 0", () => {
    const w = mkWitness();
    const p = w.witnessAgentBaseline({
      dimensions: 5,
      withinEnvelope: true,
      mode: "unknown_mode",
      driftScore: 0.1,
      baselineHash: "bh",
      currentHash: "ch",
    });
    expect(p.factor_c).toBe(0);
  });

  it("baseline_reset sets factor_c=3", () => {
    const w = mkWitness();
    const p = w.witnessAgentBaseline({
      dimensions: 15,
      withinEnvelope: true,
      mode: "baseline_reset",
      driftScore: 0.0,
      baselineHash: "new_baseline",
      currentHash: "new_current",
    });
    expect(p.factor_c).toBe(3);
  });
});
