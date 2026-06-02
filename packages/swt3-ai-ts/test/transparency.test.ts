/**
 * Tests for AI-TRANS.1 Transparency Disclosure Witnessing.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Witness } from "../src/witness.js";
import { DISCLOSURE_TYPE_CODES, RECIPIENT_TYPE_CODES } from "../src/types.js";

function mkWitness(opts: Record<string, unknown> = {}) {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "test_tenant",
    disableFlush: true,
    ...opts,
  });
}

describe("witnessTransparency (AI-TRANS.1)", () => {
  let origConsole: typeof console.log;
  beforeEach(() => { origConsole = console.log; console.log = vi.fn(); });
  afterEach(() => { console.log = origConsole; });

  it("mints correct procedure and factors", () => {
    const w = mkWitness();
    const p = w.witnessTransparency({
      disclosuresMade: 100,
      disclosureType: "ai_usage",
      recipientType: "deployer",
    });
    expect(p.procedure_id).toBe("AI-TRANS.1");
    expect(p.factor_a).toBe(100);
    expect(p.factor_b).toBe(DISCLOSURE_TYPE_CODES["ai_usage"]);
    expect(p.factor_c).toBe(RECIPIENT_TYPE_CODES["deployer"]);
    expect(p.anchor_fingerprint).toBeTruthy();
  });

  it("maps all type codes", () => {
    const w = mkWitness();
    for (const [type, code] of Object.entries(DISCLOSURE_TYPE_CODES)) {
      const p = w.witnessTransparency({
        disclosuresMade: 1, disclosureType: type, recipientType: "deployer",
      });
      expect(p.factor_b).toBe(code);
    }
    for (const [type, code] of Object.entries(RECIPIENT_TYPE_CODES)) {
      const p = w.witnessTransparency({
        disclosuresMade: 1, disclosureType: "ai_usage", recipientType: type,
      });
      expect(p.factor_c).toBe(code);
    }
  });

  it("unknown type defaults to N", () => {
    const w = mkWitness();
    const p = w.witnessTransparency({
      disclosuresMade: 1,
      disclosureType: "unknown_disclosure",
      recipientType: "unknown_recipient",
    });
    // Unknown disclosure and recipient types should get default values
    expect(typeof p.factor_b).toBe("number");
    expect(typeof p.factor_c).toBe("number");
  });

  it("includes context at clearing level 1", () => {
    const w = mkWitness({ clearingLevel: 1 });
    const p = w.witnessTransparency({
      disclosuresMade: 100,
      disclosureType: "ai_usage",
      recipientType: "deployer",
    });
    expect(p.ai_context).toBeTruthy();
    expect(p.ai_context!.disclosure_type).toBe("ai_usage");
    expect(p.ai_context!.recipient_type).toBe("deployer");
  });

  it("strips context at clearing level 2", () => {
    const w = mkWitness({ clearingLevel: 2 });
    const p = w.witnessTransparency({
      disclosuresMade: 100,
      disclosureType: "ai_usage",
      recipientType: "deployer",
    });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(100);
  });

  it("propagates agent_id from config", () => {
    const w = mkWitness({ agentId: "transparency-agent" });
    const p = w.witnessTransparency({
      disclosuresMade: 50,
      disclosureType: "ai_usage",
      recipientType: "deployer",
    });
    expect(p.agent_id).toBe("transparency-agent");
  });

  it("mints valid 12-char hex fingerprint", () => {
    const w = mkWitness();
    const p = w.witnessTransparency({
      disclosuresMade: 1,
      disclosureType: "ai_usage",
      recipientType: "deployer",
    });
    expect(p.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
  });
});
