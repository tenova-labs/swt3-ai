/**
 * Tests for AI-CONSENT.1 Data Subject Consent Witnessing.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Witness } from "../src/witness.js";
import { CONSENT_BASIS_CODES } from "../src/types.js";

function mkWitness(opts: Record<string, unknown> = {}) {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "test_tenant",
    disableFlush: true,
    ...opts,
  });
}

describe("witnessConsent (AI-CONSENT.1)", () => {
  let origConsole: typeof console.log;
  beforeEach(() => { origConsole = console.log; console.log = vi.fn(); });
  afterEach(() => { console.log = origConsole; });

  it("mints correct procedure and factors", () => {
    const w = mkWitness();
    const p = w.witnessConsent({
      subjectsCovered: 1000, legalBasisType: "consent",
      withdrawalAvailable: true,
    });
    expect(p.procedure_id).toBe("AI-CONSENT.1");
    expect(p.factor_a).toBe(1000);
    expect(p.factor_b).toBe(0); // consent code
    expect(p.factor_c).toBe(1); // withdrawal available
    expect(p.anchor_fingerprint).toBeTruthy();
  });

  it("maps all basis codes", () => {
    const w = mkWitness();
    for (const [basis, code] of Object.entries(CONSENT_BASIS_CODES)) {
      const p = w.witnessConsent({
        subjectsCovered: 1, legalBasisType: basis,
        withdrawalAvailable: false,
      });
      expect(p.factor_b).toBe(code);
    }
  });

  it("unknown basis defaults to 0 (consent)", () => {
    const w = mkWitness();
    const p = w.witnessConsent({
      subjectsCovered: 50, legalBasisType: "unknown_basis",
      withdrawalAvailable: true,
    });
    expect(p.factor_b).toBe(0);
  });

  it("withdrawal not available sets factor_c to 0", () => {
    const w = mkWitness();
    const p = w.witnessConsent({
      subjectsCovered: 500, legalBasisType: "legitimate_interest",
      withdrawalAvailable: false,
    });
    expect(p.factor_c).toBe(0);
    expect(p.factor_b).toBe(5); // legitimate_interest
  });

  it("includes context at clearing level 1", () => {
    const w = mkWitness({ clearingLevel: 1 });
    const p = w.witnessConsent({
      subjectsCovered: 2000, legalBasisType: "contract",
      withdrawalAvailable: true,
      purpose: "fraud detection",
      retentionDays: 365,
      consentMechanism: "api-consent-endpoint",
      consentHash: "sha256abc",
      dataCategories: ["financial", "identity"],
    });
    expect(p.ai_context).toBeTruthy();
    expect(p.ai_context!.provider).toBe("consent-management");
    expect(p.ai_context!.legal_basis_type).toBe("contract");
    expect(p.ai_context!.purpose).toBe("fraud detection");
    expect(p.ai_context!.retention_days).toBe(365);
    expect(p.ai_context!.consent_mechanism).toBe("api-consent-endpoint");
    expect(p.ai_context!.consent_hash).toBe("sha256abc");
    expect(p.ai_context!.data_categories).toEqual(["financial", "identity"]);
    expect(p.ai_model_id).toBe("consent-contract");
  });

  it("omits optional context fields when not provided", () => {
    const w = mkWitness({ clearingLevel: 0 });
    const p = w.witnessConsent({
      subjectsCovered: 10, legalBasisType: "consent",
      withdrawalAvailable: true,
    });
    expect(p.ai_context).toBeTruthy();
    expect(p.ai_context!.purpose).toBeUndefined();
    expect(p.ai_context!.retention_days).toBeUndefined();
  });

  it("strips context at clearing level 2", () => {
    const w = mkWitness({ clearingLevel: 2 });
    const p = w.witnessConsent({
      subjectsCovered: 1000, legalBasisType: "legal_obligation",
      withdrawalAvailable: false,
      purpose: "regulatory reporting",
    });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(1000);
    expect(p.factor_b).toBe(2); // legal_obligation
    expect(p.factor_c).toBe(0);
  });

  it("handles single subject", () => {
    const w = mkWitness();
    const p = w.witnessConsent({
      subjectsCovered: 1, legalBasisType: "vital_interest",
      withdrawalAvailable: true,
    });
    expect(p.factor_a).toBe(1);
    expect(p.factor_b).toBe(3); // vital_interest
  });

  it("mints valid 12-char hex fingerprint", () => {
    const w = mkWitness();
    const p = w.witnessConsent({
      subjectsCovered: 1, legalBasisType: "consent",
      withdrawalAvailable: false,
    });
    expect(p.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
  });
});
