/**
 * Tests for AI-SUPPLY.1 Supply Chain Risk Witnessing.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Witness } from "../src/witness.js";
import { SUPPLY_RISK_CODES } from "../src/types.js";

function mkWitness(opts: Record<string, unknown> = {}) {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "test_tenant",
    disableFlush: true,
    ...opts,
  });
}

describe("witnessSupplyChainRisk (AI-SUPPLY.1)", () => {
  let origConsole: typeof console.log;
  beforeEach(() => { origConsole = console.log; console.log = vi.fn(); });
  afterEach(() => { console.log = origConsole; });

  it("mints correct procedure and factors", () => {
    const w = mkWitness();
    const p = w.witnessSupplyChainRisk({
      suppliersAssessed: 10, suppliersCompliant: 8,
      riskLevel: "low",
    });
    expect(p.procedure_id).toBe("AI-SUPPLY.1");
    expect(p.factor_a).toBe(10);
    expect(p.factor_b).toBe(8);
    expect(p.factor_c).toBe(SUPPLY_RISK_CODES["low"]);
    expect(p.anchor_fingerprint).toBeTruthy();
  });

  it("maps all supply risk codes", () => {
    const w = mkWitness();
    for (const [level, code] of Object.entries(SUPPLY_RISK_CODES)) {
      const p = w.witnessSupplyChainRisk({
        suppliersAssessed: 5, suppliersCompliant: 3, riskLevel: level,
      });
      expect(p.factor_c).toBe(code);
    }
  });

  it("unknown type defaults to 0", () => {
    const w = mkWitness();
    const p = w.witnessSupplyChainRisk({
      suppliersAssessed: 5, suppliersCompliant: 3,
      riskLevel: "unknown_risk",
    });
    expect(p.factor_c).toBe(0);
  });

  it("includes context at clearing level 1", () => {
    const w = mkWitness({ clearingLevel: 1 });
    const p = w.witnessSupplyChainRisk({
      suppliersAssessed: 10, suppliersCompliant: 8,
      riskLevel: "low",
    });
    expect(p.ai_context).toBeTruthy();
    expect(p.ai_context!.risk_level).toBe("low");
  });

  it("strips context at clearing level 2", () => {
    const w = mkWitness({ clearingLevel: 2 });
    const p = w.witnessSupplyChainRisk({
      suppliersAssessed: 10, suppliersCompliant: 8,
      riskLevel: "low",
    });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(10);
    expect(p.factor_b).toBe(8);
  });

  it("propagates agent_id from config", () => {
    const w = mkWitness({ agentId: "supply-chain-agent" });
    const p = w.witnessSupplyChainRisk({
      suppliersAssessed: 3, suppliersCompliant: 2,
      riskLevel: "low",
    });
    expect(p.agent_id).toBe("supply-chain-agent");
  });

  it("mints valid 12-char hex fingerprint", () => {
    const w = mkWitness();
    const p = w.witnessSupplyChainRisk({
      suppliersAssessed: 1, suppliersCompliant: 1,
      riskLevel: "low",
    });
    expect(p.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
  });
});
