/**
 * Tests for AI-DPIA.1 Data Protection Impact Assessment Witnessing.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Witness } from "../src/witness.js";
import { PROCESSING_TYPE_CODES } from "../src/types.js";

function mkWitness(opts: Record<string, unknown> = {}) {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "test_tenant",
    disableFlush: true,
    ...opts,
  });
}

describe("witnessDpia (AI-DPIA.1)", () => {
  let origConsole: typeof console.log;
  beforeEach(() => { origConsole = console.log; console.log = vi.fn(); });
  afterEach(() => { console.log = origConsole; });

  it("mints correct procedure and factors", () => {
    const w = mkWitness();
    const p = w.witnessDpia({
      risksIdentified: 12, risksMitigated: 10,
      processingType: "profiling",
    });
    expect(p.procedure_id).toBe("AI-DPIA.1");
    expect(p.factor_a).toBe(12);
    expect(p.factor_b).toBe(10);
    expect(p.factor_c).toBe(PROCESSING_TYPE_CODES["profiling"]);
    expect(p.anchor_fingerprint).toBeTruthy();
  });

  it("maps all processing type codes", () => {
    const w = mkWitness();
    for (const [type, code] of Object.entries(PROCESSING_TYPE_CODES)) {
      const p = w.witnessDpia({
        risksIdentified: 5, risksMitigated: 3, processingType: type,
      });
      expect(p.factor_c).toBe(code);
    }
  });

  it("unknown type defaults to 4", () => {
    const w = mkWitness();
    const p = w.witnessDpia({
      risksIdentified: 5, risksMitigated: 3,
      processingType: "unknown_processing",
    });
    expect(p.factor_c).toBe(4);
  });

  it("includes context at clearing level 1", () => {
    const w = mkWitness({ clearingLevel: 1 });
    const p = w.witnessDpia({
      risksIdentified: 12, risksMitigated: 10,
      processingType: "profiling",
    });
    expect(p.ai_context).toBeTruthy();
    expect(p.ai_context!.processing_type).toBe("profiling");
  });

  it("strips context at clearing level 2", () => {
    const w = mkWitness({ clearingLevel: 2 });
    const p = w.witnessDpia({
      risksIdentified: 12, risksMitigated: 10,
      processingType: "profiling",
    });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(12);
    expect(p.factor_b).toBe(10);
  });

  it("propagates agent_id from config", () => {
    const w = mkWitness({ agentId: "dpia-assessment-agent" });
    const p = w.witnessDpia({
      risksIdentified: 5, risksMitigated: 4,
      processingType: "profiling",
    });
    expect(p.agent_id).toBe("dpia-assessment-agent");
  });

  it("mints valid 12-char hex fingerprint", () => {
    const w = mkWitness();
    const p = w.witnessDpia({
      risksIdentified: 1, risksMitigated: 1,
      processingType: "profiling",
    });
    expect(p.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
  });
});
