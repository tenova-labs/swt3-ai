/**
 * Tests for AI-REDTEAM.1 Adversarial Test Campaign Witnessing.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Witness } from "../src/witness.js";
import { REDTEAM_CATEGORY_CODES } from "../src/types.js";

function mkWitness(opts: Record<string, unknown> = {}) {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "test_tenant",
    disableFlush: true,
    ...opts,
  });
}

describe("witnessRedTeam (AI-REDTEAM.1)", () => {
  let origConsole: typeof console.log;
  beforeEach(() => { origConsole = console.log; console.log = vi.fn(); });
  afterEach(() => { console.log = origConsole; });

  it("mints correct procedure and factors", () => {
    const w = mkWitness();
    const p = w.witnessRedTeam({
      testsExecuted: 100, testsPassed: 95,
      coverageCategory: "prompt_injection",
    });
    expect(p.procedure_id).toBe("AI-REDTEAM.1");
    expect(p.factor_a).toBe(100);
    expect(p.factor_b).toBe(95);
    expect(p.factor_c).toBe(0); // prompt_injection
    expect(p.anchor_fingerprint).toBeTruthy();
  });

  it("maps all category codes", () => {
    const w = mkWitness();
    for (const [cat, code] of Object.entries(REDTEAM_CATEGORY_CODES)) {
      const p = w.witnessRedTeam({
        testsExecuted: 10, testsPassed: 8, coverageCategory: cat,
      });
      expect(p.factor_c).toBe(code);
    }
  });

  it("unknown category defaults to 10 (comprehensive)", () => {
    const w = mkWitness();
    const p = w.witnessRedTeam({
      testsExecuted: 50, testsPassed: 45,
      coverageCategory: "novel_attack_vector",
    });
    expect(p.factor_c).toBe(10);
  });

  it("includes context with framework and campaign_id", () => {
    const w = mkWitness({ clearingLevel: 1 });
    const p = w.witnessRedTeam({
      testsExecuted: 200, testsPassed: 190,
      coverageCategory: "jailbreak",
      framework: "OWASP-LLM-Top10",
      campaignId: "rt-2026-05-29",
      modelUnderTest: "gpt-4.1",
      attackTaxonomy: "MITRE-ATLAS-v4",
      passRate: 0.95,
      durationSeconds: 3600,
    });
    expect(p.ai_context).toBeTruthy();
    expect(p.ai_context!.provider).toBe("red-team");
    expect(p.ai_context!.coverage_category).toBe("jailbreak");
    expect(p.ai_context!.framework).toBe("OWASP-LLM-Top10");
    expect(p.ai_context!.campaign_id).toBe("rt-2026-05-29");
    expect(p.ai_context!.model_under_test).toBe("gpt-4.1");
    expect(p.ai_context!.attack_taxonomy).toBe("MITRE-ATLAS-v4");
    expect(p.ai_context!.pass_rate).toBe(0.95);
    expect(p.ai_context!.duration_seconds).toBe(3600);
    expect(p.ai_model_id).toBe("redteam-jailbreak");
  });

  it("handles zero tests case", () => {
    const w = mkWitness();
    const p = w.witnessRedTeam({
      testsExecuted: 0, testsPassed: 0,
      coverageCategory: "data_poisoning",
    });
    expect(p.factor_a).toBe(0);
    expect(p.factor_b).toBe(0);
    expect(p.factor_c).toBe(2); // data_poisoning
  });

  it("strips context at clearing level 2", () => {
    const w = mkWitness({ clearingLevel: 2 });
    const p = w.witnessRedTeam({
      testsExecuted: 100, testsPassed: 95,
      coverageCategory: "supply_chain",
      framework: "NIST-AI-100-2",
    });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(100);
    expect(p.factor_b).toBe(95);
    expect(p.factor_c).toBe(6); // supply_chain
  });

  it("strips context at clearing level 3", () => {
    const w = mkWitness({ clearingLevel: 3 });
    const p = w.witnessRedTeam({
      testsExecuted: 50, testsPassed: 48,
      coverageCategory: "comprehensive",
    });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_c).toBe(10);
  });

  it("propagates agent_id from config", () => {
    const w = mkWitness({ agentId: "red-team-agent" });
    const p = w.witnessRedTeam({
      testsExecuted: 10, testsPassed: 9,
      coverageCategory: "model_extraction",
    });
    expect(p.agent_id).toBe("red-team-agent");
  });

  it("mints valid 12-char hex fingerprint", () => {
    const w = mkWitness();
    const p = w.witnessRedTeam({
      testsExecuted: 1, testsPassed: 1,
      coverageCategory: "prompt_injection",
    });
    expect(p.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
  });
});
