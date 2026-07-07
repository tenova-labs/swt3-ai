/**
 * Tests for METAGOV namespace procedures (AI-METAGOV.1 through AI-METAGOV.8).
 *
 * Covers:
 * - Fingerprint parity with test-vectors.json
 * - witnessGovernanceConfig (AI-METAGOV.1)
 * - registerGovernanceLayer / witnessGovernanceOutput (AI-METAGOV.2)
 * - checkPolicyDowngrade (AI-METAGOV.3)
 * - validateGovernanceGraph cycle detection (AI-METAGOV.4)
 * - authorizeGovernanceChange (AI-METAGOV.5)
 * - witnessEmergencyOverride (AI-METAGOV.6)
 * - witnessGovernanceSync (AI-METAGOV.7)
 * - verifyAttestationPurity (AI-METAGOV.8)
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Witness, mintFingerprint } from "../src/index.js";
import { validateGovernanceGraph } from "../src/witness.js";

interface FingerprintVector {
  id: number;
  description: string;
  tenant_id: string;
  procedure_id: string;
  factor_a: number;
  factor_b: number;
  factor_c: number;
  fingerprint_timestamp_ms: number;
  clearing_level: number;
  expected_fingerprint: string;
}

const vectorsPath = join(__dirname, "test-vectors.json");
const allVectors = JSON.parse(readFileSync(vectorsPath, "utf-8"));
const metagovVectors: FingerprintVector[] = allVectors.fingerprint_vectors.filter(
  (v: FingerprintVector) => v.procedure_id.includes("METAGOV"),
);

function makeWitness(): Witness {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "TEST_METAGOV",
    clearingLevel: 1,
  });
}

// ── Fingerprint parity with test vectors ────────────────────────────────

describe("METAGOV Fingerprint Parity", () => {
  it("has 8 METAGOV vectors", () => {
    expect(metagovVectors).toHaveLength(8);
  });

  it("covers all 8 procedures", () => {
    const procs = new Set(metagovVectors.map((v) => v.procedure_id));
    for (let i = 1; i <= 8; i++) {
      expect(procs.has(`AI-METAGOV.${i}`)).toBe(true);
    }
  });

  it.each(metagovVectors.map((v) => [v.procedure_id, v]))(
    "%s fingerprint matches expected",
    (_proc, v) => {
      const vec = v as FingerprintVector;
      const computed = mintFingerprint(
        vec.tenant_id,
        vec.procedure_id,
        vec.factor_a,
        vec.factor_b,
        vec.factor_c,
        vec.fingerprint_timestamp_ms,
      );
      expect(computed).toBe(vec.expected_fingerprint);
    },
  );

  it("all vectors use ENCLAVE_PROD tenant", () => {
    for (const v of metagovVectors) {
      expect(v.tenant_id).toBe("ENCLAVE_PROD");
    }
  });

  it("all vectors use clearing_level 1", () => {
    for (const v of metagovVectors) {
      expect(v.clearing_level).toBe(1);
    }
  });
});

// ── AI-METAGOV.1: Governance Config ────────────────────────────────────

describe("AI-METAGOV.1 witnessGovernanceConfig", () => {
  it("mints AI-METAGOV.1 anchor", () => {
    const w = makeWitness();
    const payload = w.witnessGovernanceConfig({
      rules: [
        { id: "R1", expression: "trust_level >= 3", version: "1" },
        { id: "R2", expression: "signing_required", version: "1" },
      ],
      governanceVersion: 1,
    });
    expect(payload.procedure_id).toBe("AI-METAGOV.1");
    expect(payload.factor_a).toBe(2); // 2 rules
    expect(payload.factor_c).toBe(1); // version 1
  });

  it("produces deterministic config hash", () => {
    const w = makeWitness();
    const rules = [{ id: "A", expression: "x", version: "1" }];
    const p1 = w.witnessGovernanceConfig({ rules, governanceVersion: 1 });
    const p2 = w.witnessGovernanceConfig({ rules, governanceVersion: 1 });
    expect(p1.factor_b).toBe(p2.factor_b);
  });

  it("different rules produce different hash", () => {
    const w = makeWitness();
    const p1 = w.witnessGovernanceConfig({
      rules: [{ id: "A", expression: "x", version: "1" }],
      governanceVersion: 1,
    });
    const p2 = w.witnessGovernanceConfig({
      rules: [{ id: "A", expression: "y", version: "1" }],
      governanceVersion: 1,
    });
    expect(p1.factor_b).not.toBe(p2.factor_b);
  });

  it("includes operator in context", () => {
    const w = makeWitness();
    const payload = w.witnessGovernanceConfig({
      rules: [{ id: "R1", expression: "x" }],
      governanceVersion: 2,
      operatorId: "admin-1",
    });
    expect(payload.ai_context?.operator_id).toBe("admin-1");
    expect(payload.ai_context?.governance_version).toBe(2);
  });
});

// ── AI-METAGOV.2: Governance Layer ────────────────────────────────────

describe("AI-METAGOV.2 Governance Layer", () => {
  it("registerGovernanceLayer mints AI-METAGOV.2", () => {
    const w = makeWitness();
    const payload = w.registerGovernanceLayer({
      layerId: "nemo-guardrails",
      configHash: "abc123hash",
      stackPosition: 0,
    });
    expect(payload.procedure_id).toBe("AI-METAGOV.2");
    expect(payload.factor_a).toBe(1);
    expect(payload.factor_c).toBe(0); // stack position 0
  });

  it("witnessGovernanceOutput PASS", () => {
    const w = makeWitness();
    const payload = w.witnessGovernanceOutput({
      layerId: "nemo-guardrails",
      verdict: "PASS",
      evidenceHash: "a1b2c3d4e5f60000",
    });
    expect(payload.procedure_id).toBe("AI-METAGOV.2");
    expect(payload.factor_c).toBe(1); // PASS
  });

  it("witnessGovernanceOutput FAIL", () => {
    const w = makeWitness();
    const payload = w.witnessGovernanceOutput({
      layerId: "nemo-guardrails",
      verdict: "FAIL",
      evidenceHash: "f0e1d2c3b4a50000",
    });
    expect(payload.factor_c).toBe(0); // FAIL
  });
});

// ── AI-METAGOV.3: Policy Downgrade ────────────────────────────────────

describe("AI-METAGOV.3 checkPolicyDowngrade", () => {
  it("returns null when no downgrade", () => {
    const w = makeWitness();
    const result = w.checkPolicyDowngrade({ policyVersion: 5, policyContentHash: "a1b2c3d4e5f6" });
    expect(result).toBeNull();
  });

  it("detects downgrade", () => {
    const w = makeWitness();
    w.checkPolicyDowngrade({ policyVersion: 5, policyContentHash: "a1b2c3d4e5f6" });
    const payload = w.checkPolicyDowngrade({ policyVersion: 3, policyContentHash: "f0e1d2c3b4a5" });
    expect(payload).not.toBeNull();
    expect(payload!.procedure_id).toBe("AI-METAGOV.3");
    expect(payload!.factor_a).toBe(3); // loaded version
    expect(payload!.factor_c).toBe(1); // downgrade detected
  });

  it("throws in strict mode on downgrade", () => {
    const w = makeWitness();
    w.checkPolicyDowngrade({ policyVersion: 5, policyContentHash: "a1b2c3d4e5f6" });
    expect(() =>
      w.checkPolicyDowngrade({ policyVersion: 2, policyContentHash: "f0e1d2c3b4a5", strict: true }),
    ).toThrow(/[Pp]olicy downgrade/);
  });
});

// ── AI-METAGOV.4: Governance Graph ────────────────────────────────────

describe("AI-METAGOV.4 validateGovernanceGraph", () => {
  it("accepts valid DAG", () => {
    const result = validateGovernanceGraph([
      { id: "A", dependencies: [] },
      { id: "B", dependencies: ["A"] },
      { id: "C", dependencies: ["A", "B"] },
    ]);
    expect(result.valid).toBe(true);
    expect(result.cycles).toHaveLength(0);
    expect(result.ruleCount).toBe(3);
    expect(result.maxDepth).toBe(2);
  });

  it("detects cycle", () => {
    const result = validateGovernanceGraph([
      { id: "A", dependencies: ["B"] },
      { id: "B", dependencies: ["A"] },
    ]);
    expect(result.valid).toBe(false);
    expect(result.cycles.length).toBeGreaterThan(0);
  });

  it("detects self-cycle", () => {
    const result = validateGovernanceGraph([{ id: "A", dependencies: ["A"] }]);
    expect(result.valid).toBe(false);
  });

  it("handles empty graph", () => {
    const result = validateGovernanceGraph([]);
    expect(result.valid).toBe(true);
    expect(result.ruleCount).toBe(0);
  });

  it("single node", () => {
    const result = validateGovernanceGraph([{ id: "A", dependencies: [] }]);
    expect(result.valid).toBe(true);
    expect(result.maxDepth).toBe(0);
  });

  it("deep chain", () => {
    const rules = Array.from({ length: 10 }, (_, i) => ({
      id: `N${i}`,
      dependencies: i > 0 ? [`N${i - 1}`] : [],
    }));
    const result = validateGovernanceGraph(rules);
    expect(result.valid).toBe(true);
    expect(result.maxDepth).toBe(9);
  });
});

// ── AI-METAGOV.5: Governance Authorization ────────────────────────────

describe("AI-METAGOV.5 authorizeGovernanceChange", () => {
  it("mints AI-METAGOV.5 anchor", () => {
    const w = makeWitness();
    const payload = w.authorizeGovernanceChange({
      scopeDomain: "verdict_rules",
      permissionLevel: "modify",
      operatorId: "admin-1",
      changeDescription: "Update trust threshold",
      operatorCredentialHash: "a1b2c3d4e5f60000",
    });
    expect(payload.procedure_id).toBe("AI-METAGOV.5");
    expect(payload.factor_a).toBe(0); // verdict_rules = 0
    expect(payload.factor_b).toBe(1); // modify = 1
  });

  it("maps scope codes correctly", () => {
    const w = makeWitness();
    const scopes: [string, number][] = [
      ["verdict_rules", 0],
      ["trust_mesh", 1],
      ["enforcement", 2],
      ["clearing", 3],
      ["full", 4],
    ];
    for (const [scope, expected] of scopes) {
      const payload = w.authorizeGovernanceChange({
        scopeDomain: scope,
        permissionLevel: "read",
        operatorId: "op",
        changeDescription: "desc",
        operatorCredentialHash: "a1b2c3d4e5f60000",
      });
      expect(payload.factor_a).toBe(expected);
    }
  });
});

// ── AI-METAGOV.6: Emergency Override ──────────────────────────────────

describe("AI-METAGOV.6 witnessEmergencyOverride", () => {
  it("mints AI-METAGOV.6 anchor", () => {
    const w = makeWitness();
    const payload = w.witnessEmergencyOverride({
      overrideReason: "incident_response",
      reviewWindowHours: 48,
      operatorId: "admin-1",
      changeDescription: "Disabling guardrails for incident",
    });
    expect(payload.procedure_id).toBe("AI-METAGOV.6");
    expect(payload.factor_a).toBe(1); // incident_response = 1
    expect(payload.factor_b).toBe(48);
    expect(payload.factor_c).toBe(0); // unreviewed
  });

  it("maps reason codes correctly", () => {
    const w = makeWitness();
    const reasons: [string, number][] = [
      ["unspecified", 0],
      ["incident_response", 1],
      ["regulatory_deadline", 2],
      ["system_failure", 3],
      ["security_breach", 4],
    ];
    for (const [reason, expected] of reasons) {
      const payload = w.witnessEmergencyOverride({
        overrideReason: reason,
        reviewWindowHours: 24,
        operatorId: "op",
        changeDescription: "desc",
      });
      expect(payload.factor_a).toBe(expected);
    }
  });
});

// ── AI-METAGOV.7: Governance Sync ────────────────────────────────────

describe("AI-METAGOV.7 witnessGovernanceSync", () => {
  it("mints AI-METAGOV.7 anchor", () => {
    const w = makeWitness();
    const payload = w.witnessGovernanceSync({
      divergenceType: "version_divergent",
      localPolicyHash: "a1b2c3d4e5f60000",
      remotePolicyHash: "f0e1d2c3b4a50000",
    });
    expect(payload.procedure_id).toBe("AI-METAGOV.7");
    expect(payload.factor_a).toBe(1); // version_divergent = 1
  });

  it("equivalent has code 0", () => {
    const w = makeWitness();
    const payload = w.witnessGovernanceSync({
      divergenceType: "equivalent",
      localPolicyHash: "abcdef1234567890",
      remotePolicyHash: "abcdef1234567890",
    });
    expect(payload.factor_a).toBe(0);
  });

  it("includes remote tenant in context", () => {
    const w = makeWitness();
    const payload = w.witnessGovernanceSync({
      divergenceType: "equivalent",
      localPolicyHash: "a1b2c3d4e5f60000",
      remotePolicyHash: "f0e1d2c3b4a50000",
      remoteTenantId: "PARTNER_TENANT",
    });
    expect(payload.ai_context?.remote_tenant_id).toBe("PARTNER_TENANT");
  });
});

// ── AI-METAGOV.8: Attestation Purity ────────────────────────────────

describe("AI-METAGOV.8 verifyAttestationPurity", () => {
  it("mints AI-METAGOV.8 anchor", () => {
    const w = makeWitness();
    const payload = w.verifyAttestationPurity({
      sourceFiles: [
        { path: "witness.ts", hash: "abc123" },
        { path: "clearing.ts", hash: "def456" },
      ],
    });
    expect(payload.procedure_id).toBe("AI-METAGOV.8");
    expect(payload.factor_a).toBe(2); // 2 source files
    expect(payload.factor_c).toBe(1); // pure
  });

  it("produces deterministic hash", () => {
    const w = makeWitness();
    const files = [{ path: "a.ts", hash: "h1" }, { path: "b.ts", hash: "h2" }];
    const p1 = w.verifyAttestationPurity({ sourceFiles: files });
    const p2 = w.verifyAttestationPurity({ sourceFiles: files });
    expect(p1.factor_b).toBe(p2.factor_b);
  });

  it("order-independent hash", () => {
    const w = makeWitness();
    const p1 = w.verifyAttestationPurity({
      sourceFiles: [{ path: "a.ts", hash: "h1" }, { path: "b.ts", hash: "h2" }],
    });
    const p2 = w.verifyAttestationPurity({
      sourceFiles: [{ path: "b.ts", hash: "h2" }, { path: "a.ts", hash: "h1" }],
    });
    expect(p1.factor_b).toBe(p2.factor_b);
  });

  it("includes build hash in context", () => {
    const w = makeWitness();
    const payload = w.verifyAttestationPurity({
      sourceFiles: [{ path: "x.ts", hash: "abc" }],
      buildHash: "build123",
    });
    expect(payload.ai_context?.build_hash).toBe("build123");
  });
});
