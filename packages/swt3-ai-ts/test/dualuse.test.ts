/**
 * Tests for AI-DUALUSE.1 Dual-Use Classification Witnessing.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Witness } from "../src/witness.js";
import { REPORTING_STATUS_CODES } from "../src/types.js";

function mkWitness(opts: Record<string, unknown> = {}) {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "test_tenant",
    disableFlush: true,
    ...opts,
  });
}

describe("witnessDualUse (AI-DUALUSE.1)", () => {
  let origConsole: typeof console.log;
  beforeEach(() => { origConsole = console.log; console.log = vi.fn(); });
  afterEach(() => { console.log = origConsole; });

  it("mints correct procedure and factors", () => {
    const w = mkWitness();
    const p = w.witnessDualUse({
      classificationCode: 1, reportingStatus: "notified",
      daysSinceClassification: 30,
    });
    expect(p.procedure_id).toBe("AI-DUALUSE.1");
    expect(p.factor_a).toBe(1);
    expect(p.factor_b).toBe(REPORTING_STATUS_CODES["notified"]);
    expect(p.factor_c).toBe(30);
    expect(p.anchor_fingerprint).toBeTruthy();
  });

  it("maps all reporting status codes", () => {
    const w = mkWitness();
    for (const [status, code] of Object.entries(REPORTING_STATUS_CODES)) {
      const p = w.witnessDualUse({
        classificationCode: 1, reportingStatus: status,
        daysSinceClassification: 10,
      });
      expect(p.factor_b).toBe(code);
    }
  });

  it("unknown type defaults to 0", () => {
    const w = mkWitness();
    const p = w.witnessDualUse({
      classificationCode: 1, reportingStatus: "unknown_status",
      daysSinceClassification: 10,
    });
    expect(p.factor_b).toBe(0);
  });

  it("includes context at clearing level 1", () => {
    const w = mkWitness({ clearingLevel: 1 });
    const p = w.witnessDualUse({
      classificationCode: 1, reportingStatus: "notified",
      daysSinceClassification: 30,
    });
    expect(p.ai_context).toBeTruthy();
    expect(p.ai_context!.reporting_status).toBe("notified");
  });

  it("strips context at clearing level 2", () => {
    const w = mkWitness({ clearingLevel: 2 });
    const p = w.witnessDualUse({
      classificationCode: 1, reportingStatus: "notified",
      daysSinceClassification: 30,
    });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(1);
  });

  it("propagates agent_id from config", () => {
    const w = mkWitness({ agentId: "dualuse-classifier-agent" });
    const p = w.witnessDualUse({
      classificationCode: 2, reportingStatus: "notified",
      daysSinceClassification: 15,
    });
    expect(p.agent_id).toBe("dualuse-classifier-agent");
  });

  it("mints valid 12-char hex fingerprint", () => {
    const w = mkWitness();
    const p = w.witnessDualUse({
      classificationCode: 1, reportingStatus: "notified",
      daysSinceClassification: 1,
    });
    expect(p.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
  });
});
