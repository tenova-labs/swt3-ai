/**
 * Tests for AI-ENG.1-5 Physical AI / LEM Witness Methods.
 */
import { describe, it, expect } from "vitest";
import { Witness } from "../src/witness.js";
import { DESIGN_DOMAIN_CODES, SIMULATION_TYPE_CODES, APPROVAL_TYPE_CODES, MATERIAL_STANDARD_CODES, CHAIN_STATUS_CODES, RELEASE_TYPE_CODES } from "../src/types.js";
import { mintFingerprint } from "../src/fingerprint.js";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

function w(opts: Record<string, unknown> = {}) {
  return new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "TEST", clearingLevel: 1, disableFlush: true, ...opts });
}

describe("witnessDesignProvenance (AI-ENG.1)", () => {
  it("mints correct procedure and factors", () => {
    const p = w().witnessDesignProvenance({ constraintsApplied: 12, parametersGenerated: 500, designDomain: "mechanical" });
    expect(p.procedure_id).toBe("AI-ENG.1");
    expect(p.factor_a).toBe(12);
    expect(p.factor_b).toBe(500);
    expect(p.factor_c).toBe(DESIGN_DOMAIN_CODES["mechanical"]);
  });

  it("maps all domain codes", () => {
    for (const [type, code] of Object.entries(DESIGN_DOMAIN_CODES)) {
      const p = w().witnessDesignProvenance({ constraintsApplied: 1, parametersGenerated: 1, designDomain: type });
      expect(p.factor_c).toBe(code);
    }
  });

  it("unknown domain defaults to 7 (custom)", () => {
    const p = w().witnessDesignProvenance({ constraintsApplied: 1, parametersGenerated: 1, designDomain: "unknown_xyz" });
    expect(p.factor_c).toBe(7);
  });

  it("includes context at clearing level 1", () => {
    const p = w().witnessDesignProvenance({ constraintsApplied: 5, parametersGenerated: 100, designDomain: "semiconductor", designHash: "abc123" });
    expect(p.ai_context!.design_domain).toBe("semiconductor");
    expect(p.ai_context!.design_hash).toBe("abc123");
  });

  it("strips context at clearing level 2", () => {
    const w2 = w({ clearingLevel: 2 });
    const p = w2.witnessDesignProvenance({ constraintsApplied: 5, parametersGenerated: 100, designDomain: "mechanical" });
    expect(p.ai_context).toBeUndefined();
  });

  it("mints valid 12-char hex fingerprint", () => {
    const p = w().witnessDesignProvenance({ constraintsApplied: 1, parametersGenerated: 1, designDomain: "mechanical" });
    expect(p.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
  });
});

describe("witnessSimulationValidation (AI-ENG.2)", () => {
  it("mints correct procedure and factors", () => {
    const p = w().witnessSimulationValidation({ simulationsRun: 1000, simulationsPassed: 998, simulationType: "fea" });
    expect(p.procedure_id).toBe("AI-ENG.2");
    expect(p.factor_a).toBe(1000);
    expect(p.factor_b).toBe(998);
    expect(p.factor_c).toBe(SIMULATION_TYPE_CODES["fea"]);
  });

  it("maps all simulation types", () => {
    for (const [type, code] of Object.entries(SIMULATION_TYPE_CODES)) {
      const p = w().witnessSimulationValidation({ simulationsRun: 1, simulationsPassed: 1, simulationType: type });
      expect(p.factor_c).toBe(code);
    }
  });

  it("unknown type defaults to 6 (custom)", () => {
    const p = w().witnessSimulationValidation({ simulationsRun: 1, simulationsPassed: 1, simulationType: "unknown_sim" });
    expect(p.factor_c).toBe(6);
  });

  it("includes acceptance criteria in context", () => {
    const p = w().witnessSimulationValidation({ simulationsRun: 50, simulationsPassed: 48, simulationType: "cfd", acceptanceCriteria: "drag < 0.3" });
    expect(p.ai_context!.acceptance_criteria).toBe("drag < 0.3");
  });
});

describe("witnessSafetyReview (AI-ENG.3)", () => {
  it("mints correct procedure and factors", () => {
    const p = w().witnessSafetyReview({ reviewersRequired: 3, reviewersApproved: 3, approvalType: "pe_stamp" });
    expect(p.procedure_id).toBe("AI-ENG.3");
    expect(p.factor_a).toBe(3);
    expect(p.factor_b).toBe(3);
    expect(p.factor_c).toBe(APPROVAL_TYPE_CODES["pe_stamp"]);
  });

  it("maps all approval types", () => {
    for (const [type, code] of Object.entries(APPROVAL_TYPE_CODES)) {
      const p = w().witnessSafetyReview({ reviewersRequired: 1, reviewersApproved: 1, approvalType: type });
      expect(p.factor_c).toBe(code);
    }
  });

  it("includes PE license in context", () => {
    const p = w().witnessSafetyReview({ reviewersRequired: 1, reviewersApproved: 1, approvalType: "pe_stamp", peLicense: "PE-12345-TX" });
    expect(p.ai_context!.pe_license).toBe("PE-12345-TX");
  });
});

describe("witnessMaterialCompliance (AI-ENG.4)", () => {
  it("mints correct procedure and factors", () => {
    const p = w().witnessMaterialCompliance({ specificationsChecked: 15, specificationsMet: 15, standard: "asme" });
    expect(p.procedure_id).toBe("AI-ENG.4");
    expect(p.factor_a).toBe(15);
    expect(p.factor_b).toBe(15);
    expect(p.factor_c).toBe(MATERIAL_STANDARD_CODES["asme"]);
  });

  it("maps all standard codes", () => {
    for (const [type, code] of Object.entries(MATERIAL_STANDARD_CODES)) {
      const p = w().witnessMaterialCompliance({ specificationsChecked: 1, specificationsMet: 1, standard: type });
      expect(p.factor_c).toBe(code);
    }
  });

  it("unknown standard defaults to 6 (custom)", () => {
    const p = w().witnessMaterialCompliance({ specificationsChecked: 1, specificationsMet: 1, standard: "unknown_std" });
    expect(p.factor_c).toBe(6);
  });
});

describe("witnessDesignChain (AI-ENG.5)", () => {
  it("mints correct procedure and factors", () => {
    const p = w().witnessDesignChain({ totalRevisions: 10, aiGeneratedRevisions: 7, chainStatus: "approved" });
    expect(p.procedure_id).toBe("AI-ENG.5");
    expect(p.factor_a).toBe(10);
    expect(p.factor_b).toBe(7);
    expect(p.factor_c).toBe(CHAIN_STATUS_CODES["approved"]);
  });

  it("maps all chain statuses", () => {
    for (const [type, code] of Object.entries(CHAIN_STATUS_CODES)) {
      const p = w().witnessDesignChain({ totalRevisions: 1, aiGeneratedRevisions: 1, chainStatus: type });
      expect(p.factor_c).toBe(code);
    }
  });

  it("calculates AI revision ratio", () => {
    const p = w().witnessDesignChain({ totalRevisions: 10, aiGeneratedRevisions: 7, chainStatus: "approved" });
    expect(p.ai_context!.ai_revision_ratio).toBe(0.7);
  });

  it("handles zero revisions without divide-by-zero", () => {
    const p = w().witnessDesignChain({ totalRevisions: 0, aiGeneratedRevisions: 0, chainStatus: "in_progress" });
    expect(p.ai_context!.ai_revision_ratio).toBe(0);
  });

  it("strips context at clearing level 2", () => {
    const w2 = w({ clearingLevel: 2 });
    const p = w2.witnessDesignChain({ totalRevisions: 5, aiGeneratedRevisions: 3, chainStatus: "approved" });
    expect(p.ai_context).toBeUndefined();
  });
});

describe("witnessFabricationRelease (AI-ENG.6)", () => {
  it("mints correct procedure and factors", () => {
    const p = w().witnessFabricationRelease({ designHashVerified: true, authorizationCount: 5, releaseType: "mass_production" });
    expect(p.procedure_id).toBe("AI-ENG.6");
    expect(p.factor_a).toBe(1);
    expect(p.factor_b).toBe(5);
    expect(p.factor_c).toBe(RELEASE_TYPE_CODES["mass_production"]);
  });

  it("hash mismatch sets factor_a to 0", () => {
    const p = w().witnessFabricationRelease({ designHashVerified: false, authorizationCount: 3, releaseType: "prototype" });
    expect(p.factor_a).toBe(0);
  });

  it("maps all release types", () => {
    for (const [type, code] of Object.entries(RELEASE_TYPE_CODES)) {
      const p = w().witnessFabricationRelease({ designHashVerified: true, authorizationCount: 1, releaseType: type });
      expect(p.factor_c).toBe(code);
    }
  });

  it("includes context at clearing level 1", () => {
    const p = w().witnessFabricationRelease({ designHashVerified: true, authorizationCount: 3, releaseType: "mass_production", productionSystemId: "FAB-001", approvedDesignHash: "abc123" });
    expect(p.ai_context!.production_system_id).toBe("FAB-001");
    expect(p.ai_context!.approved_design_hash).toBe("abc123");
    expect(p.ai_context!.design_hash_verified).toBe(true);
  });

  it("strips context at clearing level 2", () => {
    const w2 = w({ clearingLevel: 2 });
    const p = w2.witnessFabricationRelease({ designHashVerified: true, authorizationCount: 1, releaseType: "prototype" });
    expect(p.ai_context).toBeUndefined();
  });
});

describe("AI-ENG fingerprint vectors", () => {
  it("all 6 vectors produce correct fingerprints", () => {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const vectors = JSON.parse(readFileSync(join(__dirname, "test-vectors.json"), "utf-8"));
    const engVectors = vectors.fingerprint_vectors.filter((v: { procedure_id: string }) => v.procedure_id.startsWith("AI-ENG"));
    expect(engVectors.length).toBe(6);
    for (const v of engVectors) {
      const computed = mintFingerprint(v.tenant_id, v.procedure_id, v.factor_a, v.factor_b, v.factor_c, v.fingerprint_timestamp_ms);
      expect(computed).toBe(v.expected_fingerprint);
    }
  });
});
