/**
 * Cross-language parity test: factor values must match Python SDK exactly.
 * Python values computed with tenant_id="PARITY", clearing_level=1.
 */
import { describe, it, expect } from "vitest";
import { Witness } from "../src/witness.js";

function w() {
  return new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "PARITY", clearingLevel: 1, disableFlush: true });
}

describe("cross-language factor parity", () => {
  it("AI-JUR.1: US->DE compliant matches Python fa=840 fb=276 fc=1", () => {
    const p = w().witnessRouting({ servingRegion: "US", userRegion: "DE", complianceStatus: "compliant" });
    expect(p.factor_a).toBe(840);
    expect(p.factor_b).toBe(276);
    expect(p.factor_c).toBe(1);
  });

  it("AI-TOOL.2: 3 tools, match, added matches Python fa=3 fb=1 fc=1", () => {
    const p = w().witnessToolPermissions({ tools: ["a", "b", "c"], charterMatch: true, changeType: "added" });
    expect(p.factor_a).toBe(3);
    expect(p.factor_b).toBe(1);
    expect(p.factor_c).toBe(1);
  });

  it("AI-FIN.1: human 5000 authorized matches Python fa=2 fb=5000 fc=1", () => {
    const p = w().witnessTransaction({ amountCents: 5000, authorizationType: "human", status: "authorized" });
    expect(p.factor_a).toBe(2);
    expect(p.factor_b).toBe(5000);
    expect(p.factor_c).toBe(1);
  });

  it("AI-LCM.1: spawn 128000 no-hash matches Python fa=0 fb=128000 fc=0", () => {
    const p = w().witnessLifecycle({ event: "spawn", contextTokens: 128000 });
    expect(p.factor_a).toBe(0);
    expect(p.factor_b).toBe(128000);
    expect(p.factor_c).toBe(0);
  });

  it("AI-JUR.1: unchecked matches Python fc=0", () => {
    const p = w().witnessRouting({ servingRegion: "US", userRegion: "US", complianceStatus: "unchecked" });
    expect(p.factor_c).toBe(0);
  });

  it("AI-JUR.1: blocked matches Python fc=2", () => {
    const p = w().witnessRouting({ servingRegion: "US", userRegion: "CN", complianceStatus: "blocked" });
    expect(p.factor_c).toBe(2);
  });

  it("AI-JUR.1: override matches Python fc=3", () => {
    const p = w().witnessRouting({ servingRegion: "US", userRegion: "CN", complianceStatus: "override" });
    expect(p.factor_c).toBe(3);
  });

  it("AI-TOOL.2: none matches Python fc=0", () => {
    const p = w().witnessToolPermissions({ tools: ["a"], charterMatch: true, changeType: "none" });
    expect(p.factor_c).toBe(0);
  });

  it("AI-TOOL.2: removed matches Python fc=2", () => {
    const p = w().witnessToolPermissions({ tools: ["a"], charterMatch: true, changeType: "removed" });
    expect(p.factor_c).toBe(2);
  });

  it("AI-TOOL.2: escalated matches Python fc=3", () => {
    const p = w().witnessToolPermissions({ tools: ["a"], charterMatch: true, changeType: "escalated" });
    expect(p.factor_c).toBe(3);
  });
});
