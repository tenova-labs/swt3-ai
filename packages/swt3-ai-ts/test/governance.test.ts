/**
 * Tests for governance namespace procedures (AI-GOV.1-6, AI-RISK.1, AI-IMPACT.1, AI-LOG.1, AI-IR.1).
 *
 * v0.6.6 TypeScript parity with Python SDK governance methods.
 * Also verifies governanceMetadata parameter on 5 existing METAGOV methods.
 */

import { describe, it, expect } from "vitest";
import { Witness, mintFingerprint } from "../src/index.js";

function makeWitness(clearingLevel: 0 | 1 | 2 | 3 = 1): Witness {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "TEST_GOV",
    clearingLevel,
  });
}

// ── AI-RISK.1 Risk Assessment ──────────────────────────────────────────

describe("AI-RISK.1 witnessRiskAssessment", () => {
  it("mints AI-RISK.1 anchor with correct factors", () => {
    const w = makeWitness();
    const p = w.witnessRiskAssessment({
      risksIdentified: 12,
      risksMitigated: 10,
      riskLevel: "high",
    });
    expect(p.procedure_id).toBe("AI-RISK.1");
    expect(p.factor_a).toBe(12);
    expect(p.factor_b).toBe(10);
    expect(p.factor_c).toBe(2); // high = 2
  });

  it("uses correct risk level codes", () => {
    const w = makeWitness();
    for (const [level, code] of Object.entries({ low: 0, medium: 1, high: 2, critical: 3, unacceptable: 4 })) {
      const p = w.witnessRiskAssessment({ risksIdentified: 1, risksMitigated: 0, riskLevel: level });
      expect(p.factor_c).toBe(code);
    }
  });

  it("defaults unknown risk level to 1 (medium)", () => {
    const w = makeWitness();
    const p = w.witnessRiskAssessment({ risksIdentified: 1, risksMitigated: 0, riskLevel: "unknown_level" });
    expect(p.factor_c).toBe(1);
  });

  it("includes context at clearing level 1", () => {
    const w = makeWitness(1);
    const p = w.witnessRiskAssessment({
      risksIdentified: 5, risksMitigated: 3, riskLevel: "critical",
      assessmentId: "RA-2026-001", methodology: "ISO31000", residualRiskScore: 0.15, reviewer: "ciso@acme.com",
    });
    expect(p.ai_model_id).toBe("risk-assessment-critical");
    const ctx = p.ai_context as Record<string, unknown>;
    expect(ctx.provider).toBe("risk-management");
    expect(ctx.assessment_id).toBe("RA-2026-001");
    expect(ctx.methodology).toBe("ISO31000");
    expect(ctx.residual_risk_score).toBe(0.15);
    expect(ctx.reviewer).toBe("ciso@acme.com");
  });

  it("strips context at clearing level 2", () => {
    const w = makeWitness(2);
    const p = w.witnessRiskAssessment({ risksIdentified: 5, risksMitigated: 3, riskLevel: "high" });
    expect(p.ai_context).toBeUndefined();
  });
});

// ── AI-GOV.1 Governance Framework ──────────────────────────────────────

describe("AI-GOV.1 witnessGovernanceFramework", () => {
  it("mints AI-GOV.1 anchor with correct factors", () => {
    const w = makeWitness();
    const p = w.witnessGovernanceFramework({ controlsDefined: 10, controlsActive: 10 });
    expect(p.procedure_id).toBe("AI-GOV.1");
    expect(p.factor_a).toBe(10);
    expect(p.factor_b).toBe(10);
    expect(p.factor_c).toBe(1); // all active
  });

  it("sets fc=0 when not all controls active", () => {
    const w = makeWitness();
    const p = w.witnessGovernanceFramework({ controlsDefined: 10, controlsActive: 7 });
    expect(p.factor_c).toBe(0);
  });

  it("includes governanceMetadata in context", () => {
    const w = makeWitness(1);
    const p = w.witnessGovernanceFramework({
      controlsDefined: 10, controlsActive: 10,
      frameworkVersion: "v3.1",
      governanceMetadata: { review_duration_minutes: 90, participant_count: 5 },
    });
    const ctx = p.ai_context as Record<string, unknown>;
    expect(ctx.framework_version).toBe("v3.1");
    expect(ctx.review_duration_minutes).toBe(90);
    expect(ctx.participant_count).toBe(5);
  });
});

// ── AI-GOV.2 Governance Review ─────────────────────────────────────────

describe("AI-GOV.2 witnessGovernanceReview", () => {
  it("mints AI-GOV.2 with default 90-day period", () => {
    const w = makeWitness();
    const p = w.witnessGovernanceReview({ reviewsScheduled: 4, reviewsCompleted: 3 });
    expect(p.procedure_id).toBe("AI-GOV.2");
    expect(p.factor_a).toBe(4);
    expect(p.factor_b).toBe(3);
    expect(p.factor_c).toBe(90);
  });

  it("uses custom review period", () => {
    const w = makeWitness();
    const p = w.witnessGovernanceReview({ reviewsScheduled: 12, reviewsCompleted: 12, reviewPeriodDays: 30 });
    expect(p.factor_c).toBe(30);
  });
});

// ── AI-GOV.3 Governance Escalation ─────────────────────────────────────

describe("AI-GOV.3 witnessGovernanceEscalation", () => {
  it("mints AI-GOV.3 with escalation tested = PASS", () => {
    const w = makeWitness();
    const p = w.witnessGovernanceEscalation({ escalationPathsDefined: 3, escalationPathsTested: 3 });
    expect(p.factor_c).toBe(1); // all tested
  });

  it("sets fc=0 when not all paths tested", () => {
    const w = makeWitness();
    const p = w.witnessGovernanceEscalation({ escalationPathsDefined: 5, escalationPathsTested: 2 });
    expect(p.factor_c).toBe(0);
  });
});

// ── AI-GOV.4 Governance Update ─────────────────────────────────────────

describe("AI-GOV.4 witnessGovernanceUpdate", () => {
  it("mints AI-GOV.4 with version delta", () => {
    const w = makeWitness();
    const p = w.witnessGovernanceUpdate({ previousVersion: 3, currentVersion: 5 });
    expect(p.factor_a).toBe(3);
    expect(p.factor_b).toBe(5);
    expect(p.factor_c).toBe(2); // delta
  });
});

// ── AI-GOV.5 Governance Accountability ─────────────────────────────────

describe("AI-GOV.5 witnessGovernanceAccountability", () => {
  it("mints AI-GOV.5 with all roles acknowledged", () => {
    const w = makeWitness();
    const p = w.witnessGovernanceAccountability({ rolesAssigned: 8, rolesAcknowledged: 8 });
    expect(p.factor_c).toBe(1);
  });

  it("sets fc=0 when not all roles acknowledged", () => {
    const w = makeWitness();
    const p = w.witnessGovernanceAccountability({ rolesAssigned: 8, rolesAcknowledged: 5 });
    expect(p.factor_c).toBe(0);
  });
});

// ── AI-GOV.6 Risk Scope ────────────────────────────────────────────────

describe("AI-GOV.6 witnessRiskScope", () => {
  it("mints AI-GOV.6 with exclusion count", () => {
    const w = makeWitness();
    const p = w.witnessRiskScope({ systemsInScope: 20, systemsAssessed: 18, exclusionCount: 2 });
    expect(p.factor_a).toBe(20);
    expect(p.factor_b).toBe(18);
    expect(p.factor_c).toBe(2);
  });

  it("defaults exclusionCount to 0", () => {
    const w = makeWitness();
    const p = w.witnessRiskScope({ systemsInScope: 10, systemsAssessed: 10 });
    expect(p.factor_c).toBe(0);
  });
});

// ── AI-IMPACT.1 Impact Assessment ──────────────────────────────────────

describe("AI-IMPACT.1 witnessImpactAssessment", () => {
  it("mints AI-IMPACT.1 with defaults", () => {
    const w = makeWitness();
    const p = w.witnessImpactAssessment({ affectedPopulation: 50000, riskCategoriesAssessed: 7 });
    expect(p.procedure_id).toBe("AI-IMPACT.1");
    expect(p.factor_a).toBe(50000);
    expect(p.factor_b).toBe(7);
    expect(p.factor_c).toBe(0); // default highRiskFindings
  });

  it("includes assessment type in model_id", () => {
    const w = makeWitness(1);
    const p = w.witnessImpactAssessment({
      affectedPopulation: 1000, riskCategoriesAssessed: 3,
      assessmentType: "dpia", highRiskFindings: 2,
    });
    expect(p.ai_model_id).toBe("impact-dpia");
    expect(p.factor_c).toBe(2);
  });
});

// ── AI-LOG.1 Log Completeness ──────────────────────────────────────────

describe("AI-LOG.1 witnessLogCompleteness", () => {
  it("mints AI-LOG.1 with retention days", () => {
    const w = makeWitness();
    const p = w.witnessLogCompleteness({ eventsExpected: 1000, eventsLogged: 998, logRetentionDays: 365 });
    expect(p.procedure_id).toBe("AI-LOG.1");
    expect(p.factor_a).toBe(1000);
    expect(p.factor_b).toBe(998);
    expect(p.factor_c).toBe(365);
  });
});

// ── AI-IR.1 Incident Response ──────────────────────────────────────────

describe("AI-IR.1 witnessIncidentResponse", () => {
  it("mints AI-IR.1 with contact list current", () => {
    const w = makeWitness();
    const p = w.witnessIncidentResponse({ playbooksDefined: 5, playbooksTested: 4 });
    expect(p.procedure_id).toBe("AI-IR.1");
    expect(p.factor_a).toBe(5);
    expect(p.factor_b).toBe(4);
    expect(p.factor_c).toBe(1); // contactListCurrent defaults true
  });

  it("sets fc=0 when contact list not current", () => {
    const w = makeWitness();
    const p = w.witnessIncidentResponse({
      playbooksDefined: 5, playbooksTested: 5, contactListCurrent: false,
    });
    expect(p.factor_c).toBe(0);
  });

  it("includes drill date and response time in context", () => {
    const w = makeWitness(1);
    const p = w.witnessIncidentResponse({
      playbooksDefined: 3, playbooksTested: 3,
      lastDrillDate: "2026-08-01", meanResponseMinutes: 15,
    });
    const ctx = p.ai_context as Record<string, unknown>;
    expect(ctx.last_drill_date).toBe("2026-08-01");
    expect(ctx.mean_response_minutes).toBe(15);
  });
});

// ── governanceMetadata on existing METAGOV methods ─────────────────────

describe("governanceMetadata parity on existing methods", () => {
  it("checkPolicyDowngrade accepts governanceMetadata", () => {
    const w = makeWitness();
    // Force a downgrade by setting a high known-good version
    (w as any)._lastKnownGoodVersion = 10;
    const p = w.checkPolicyDowngrade({
      policyVersion: 5,
      policyContentHash: "abc123",
      governanceMetadata: { participant_count: 3, review_duration_minutes: 45 },
    });
    expect(p).not.toBeNull();
    const ctx = p!.ai_context as Record<string, unknown>;
    expect(ctx.participant_count).toBe(3);
    expect(ctx.review_duration_minutes).toBe(45);
  });

  it("registerGovernanceLayer accepts governanceMetadata", () => {
    const w = makeWitness();
    const p = w.registerGovernanceLayer({
      layerId: "layer-1", configHash: "abc123", stackPosition: 0,
      governanceMetadata: { quorum_met: true },
    });
    const ctx = p.ai_context as Record<string, unknown>;
    expect(ctx.quorum_met).toBe(true);
  });

  it("authorizeGovernanceChange accepts governanceMetadata", () => {
    const w = makeWitness();
    const p = w.authorizeGovernanceChange({
      scopeDomain: "verdict_rules", permissionLevel: "modify",
      operatorId: "op-1", changeDescription: "test",
      operatorCredentialHash: "abc123",
      governanceMetadata: { participant_count: 2 },
    });
    const ctx = p.ai_context as Record<string, unknown>;
    expect(ctx.participant_count).toBe(2);
  });

  it("witnessEmergencyOverride accepts governanceMetadata", () => {
    const w = makeWitness();
    const p = w.witnessEmergencyOverride({
      overrideReason: "incident_response", reviewWindowHours: 24,
      operatorId: "op-1", changeDescription: "test",
      governanceMetadata: { review_duration_minutes: 120 },
    });
    const ctx = p.ai_context as Record<string, unknown>;
    expect(ctx.review_duration_minutes).toBe(120);
  });

  it("verifyAttestationPurity accepts governanceMetadata", () => {
    const w = makeWitness();
    const p = w.verifyAttestationPurity({
      sourceFiles: [{ path: "src/main.ts", hash: "abc" }],
      governanceMetadata: { participant_count: 4 },
    });
    const ctx = p.ai_context as Record<string, unknown>;
    expect(ctx.participant_count).toBe(4);
  });
});

// ── Cross-language fingerprint parity ──────────────────────────────────

describe("Governance fingerprint parity", () => {
  it("produces correct fingerprints for all governance procedures", () => {
    const procedures = [
      "AI-GOV.1", "AI-GOV.2", "AI-GOV.3", "AI-GOV.4", "AI-GOV.5", "AI-GOV.6",
      "AI-RISK.1", "AI-IMPACT.1", "AI-LOG.1", "AI-IR.1",
    ];
    for (const proc of procedures) {
      const fp = mintFingerprint("ENCLAVE_PROD", proc, 10, 8, 1, 1774800000000);
      expect(fp).toHaveLength(12);
      expect(/^[0-9a-f]{12}$/.test(fp)).toBe(true);
    }
  });
});
