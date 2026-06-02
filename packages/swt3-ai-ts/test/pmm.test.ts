/**
 * Tests for AI-PMM.1 Post-Market Monitoring Witnessing.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Witness } from "../src/witness.js";
import { PMM_TYPE_CODES } from "../src/types.js";

function mkWitness(opts: Record<string, unknown> = {}) {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "test_tenant",
    disableFlush: true,
    ...opts,
  });
}

describe("witnessPostMarketMonitoring (AI-PMM.1)", () => {
  let origConsole: typeof console.log;
  beforeEach(() => { origConsole = console.log; console.log = vi.fn(); });
  afterEach(() => { console.log = origConsole; });

  it("mints correct procedure and factors", () => {
    const w = mkWitness();
    const p = w.witnessPostMarketMonitoring({
      monitoringChecksRun: 200, anomaliesDetected: 5,
      monitoringType: "performance",
    });
    expect(p.procedure_id).toBe("AI-PMM.1");
    expect(p.factor_a).toBe(200);
    expect(p.factor_b).toBe(5);
    expect(p.factor_c).toBe(PMM_TYPE_CODES["performance"]);
    expect(p.anchor_fingerprint).toBeTruthy();
  });

  it("maps all PMM type codes", () => {
    const w = mkWitness();
    for (const [type, code] of Object.entries(PMM_TYPE_CODES)) {
      const p = w.witnessPostMarketMonitoring({
        monitoringChecksRun: 10, anomaliesDetected: 1, monitoringType: type,
      });
      expect(p.factor_c).toBe(code);
    }
  });

  it("unknown type defaults to 4", () => {
    const w = mkWitness();
    const p = w.witnessPostMarketMonitoring({
      monitoringChecksRun: 10, anomaliesDetected: 1,
      monitoringType: "unknown_monitoring",
    });
    expect(p.factor_c).toBe(4);
  });

  it("includes context at clearing level 1", () => {
    const w = mkWitness({ clearingLevel: 1 });
    const p = w.witnessPostMarketMonitoring({
      monitoringChecksRun: 200, anomaliesDetected: 5,
      monitoringType: "performance",
    });
    expect(p.ai_context).toBeTruthy();
    expect(p.ai_context!.monitoring_type).toBe("performance");
  });

  it("strips context at clearing level 2", () => {
    const w = mkWitness({ clearingLevel: 2 });
    const p = w.witnessPostMarketMonitoring({
      monitoringChecksRun: 200, anomaliesDetected: 5,
      monitoringType: "performance",
    });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(200);
    expect(p.factor_b).toBe(5);
  });

  it("propagates agent_id from config", () => {
    const w = mkWitness({ agentId: "pmm-monitor-agent" });
    const p = w.witnessPostMarketMonitoring({
      monitoringChecksRun: 50, anomaliesDetected: 2,
      monitoringType: "performance",
    });
    expect(p.agent_id).toBe("pmm-monitor-agent");
  });

  it("mints valid 12-char hex fingerprint", () => {
    const w = mkWitness();
    const p = w.witnessPostMarketMonitoring({
      monitoringChecksRun: 1, anomaliesDetected: 0,
      monitoringType: "performance",
    });
    expect(p.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
  });
});
