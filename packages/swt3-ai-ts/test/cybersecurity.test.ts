/**
 * Tests for AI-CYBER.1 Cybersecurity Assessment Witnessing.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Witness } from "../src/witness.js";
import { CYBER_FRAMEWORK_CODES } from "../src/types.js";

function mkWitness(opts: Record<string, unknown> = {}) {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "test_tenant",
    disableFlush: true,
    ...opts,
  });
}

describe("witnessCybersecurity (AI-CYBER.1)", () => {
  let origConsole: typeof console.log;
  beforeEach(() => { origConsole = console.log; console.log = vi.fn(); });
  afterEach(() => { console.log = origConsole; });

  it("mints correct procedure and factors", () => {
    const w = mkWitness();
    const p = w.witnessCybersecurity({
      controlsAssessed: 50, controlsCompliant: 48,
      framework: "nist_csf",
    });
    expect(p.procedure_id).toBe("AI-CYBER.1");
    expect(p.factor_a).toBe(50);
    expect(p.factor_b).toBe(48);
    expect(p.factor_c).toBe(CYBER_FRAMEWORK_CODES["nist_csf"]);
    expect(p.anchor_fingerprint).toBeTruthy();
  });

  it("maps all cyber framework codes", () => {
    const w = mkWitness();
    for (const [fw, code] of Object.entries(CYBER_FRAMEWORK_CODES)) {
      const p = w.witnessCybersecurity({
        controlsAssessed: 10, controlsCompliant: 8, framework: fw,
      });
      expect(p.factor_c).toBe(code);
    }
  });

  it("unknown type defaults to 4", () => {
    const w = mkWitness();
    const p = w.witnessCybersecurity({
      controlsAssessed: 10, controlsCompliant: 8,
      framework: "unknown_framework",
    });
    expect(p.factor_c).toBe(4);
  });

  it("includes context at clearing level 1", () => {
    const w = mkWitness({ clearingLevel: 1 });
    const p = w.witnessCybersecurity({
      controlsAssessed: 50, controlsCompliant: 48,
      framework: "nist_csf",
    });
    expect(p.ai_context).toBeTruthy();
    expect(p.ai_context!.framework).toBe("nist_csf");
  });

  it("strips context at clearing level 2", () => {
    const w = mkWitness({ clearingLevel: 2 });
    const p = w.witnessCybersecurity({
      controlsAssessed: 50, controlsCompliant: 48,
      framework: "nist_csf",
    });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(50);
    expect(p.factor_b).toBe(48);
  });

  it("propagates agent_id from config", () => {
    const w = mkWitness({ agentId: "cyber-assessment-agent" });
    const p = w.witnessCybersecurity({
      controlsAssessed: 20, controlsCompliant: 18,
      framework: "nist_csf",
    });
    expect(p.agent_id).toBe("cyber-assessment-agent");
  });

  it("mints valid 12-char hex fingerprint", () => {
    const w = mkWitness();
    const p = w.witnessCybersecurity({
      controlsAssessed: 1, controlsCompliant: 1,
      framework: "nist_csf",
    });
    expect(p.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
  });
});
