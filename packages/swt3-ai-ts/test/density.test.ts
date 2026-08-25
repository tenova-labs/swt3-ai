/**
 * Tests for AI-DENSITY.1 Witnessing Density Attestation (v0.6.6).
 *
 * Cross-language fingerprint parity with test-vectors.json vectors 59-60.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Witness, mintFingerprint } from "../src/index.js";

interface FingerprintVector {
  id: number;
  tenant_id: string;
  procedure_id: string;
  factor_a: number;
  factor_b: number;
  factor_c: number;
  fingerprint_timestamp_ms: number;
  expected_fingerprint: string;
  description: string;
}

const vectorsPath = join(__dirname, "test-vectors.json");
const allVectors = JSON.parse(readFileSync(vectorsPath, "utf-8"));
const densityVectors: FingerprintVector[] = allVectors.fingerprint_vectors.filter(
  (v: FingerprintVector) => v.procedure_id === "AI-DENSITY.1",
);

function makeWitness(clearingLevel: 0 | 1 | 2 | 3 = 1): Witness {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "TEST_DENSITY",
    clearingLevel,
  });
}

// ── Cross-language fingerprint parity ──────────────────────────────────

describe("AI-DENSITY.1 Fingerprint Parity", () => {
  it("has 2 AI-DENSITY.1 test vectors", () => {
    expect(densityVectors).toHaveLength(2);
  });

  for (const v of densityVectors) {
    it(`vector ${v.id}: ${v.description}`, () => {
      const fp = mintFingerprint(
        v.tenant_id, v.procedure_id,
        v.factor_a, v.factor_b, v.factor_c,
        v.fingerprint_timestamp_ms,
      );
      expect(fp).toBe(v.expected_fingerprint);
    });
  }
});

// ── Method behavior ────────────────────────────────────────────────────

describe("AI-DENSITY.1 witnessAnchorDensity", () => {
  it("mints AI-DENSITY.1 anchor with auto-sufficient status", () => {
    const w = makeWitness();
    const p = w.witnessAnchorDensity({ expectedAnchors: 100, actualAnchors: 120 });
    expect(p.procedure_id).toBe("AI-DENSITY.1");
    expect(p.factor_a).toBe(100);
    expect(p.factor_b).toBe(120);
    expect(p.factor_c).toBe(0); // sufficient (auto-derived)
  });

  it("auto-derives insufficient when actual < expected", () => {
    const w = makeWitness();
    const p = w.witnessAnchorDensity({ expectedAnchors: 100, actualAnchors: 30 });
    expect(p.factor_c).toBe(1); // insufficient
  });

  it("accepts explicit density status override", () => {
    const w = makeWitness();
    const p = w.witnessAnchorDensity({
      expectedAnchors: 100, actualAnchors: 80, densityStatus: "degraded",
    });
    expect(p.factor_c).toBe(2); // degraded
  });

  it("uses correct density status codes", () => {
    const w = makeWitness();
    for (const [status, code] of Object.entries({ sufficient: 0, insufficient: 1, degraded: 2 })) {
      const p = w.witnessAnchorDensity({ expectedAnchors: 10, actualAnchors: 5, densityStatus: status });
      expect(p.factor_c).toBe(code);
    }
  });

  it("includes context at clearing level 1", () => {
    const w = makeWitness(1);
    const p = w.witnessAnchorDensity({
      expectedAnchors: 100, actualAnchors: 120,
      evaluationWindowSeconds: 1800,
      procedureFilter: "AI-INF.1",
    });
    const ctx = p.ai_context as Record<string, unknown>;
    expect(ctx.provider).toBe("density-attestation");
    expect(ctx.density_status).toBe("sufficient");
    expect(ctx.evaluation_window_seconds).toBe(1800);
    expect(ctx.procedure_filter).toBe("AI-INF.1");
  });

  it("defaults evaluation window to 3600 seconds", () => {
    const w = makeWitness(1);
    const p = w.witnessAnchorDensity({ expectedAnchors: 10, actualAnchors: 10 });
    const ctx = p.ai_context as Record<string, unknown>;
    expect(ctx.evaluation_window_seconds).toBe(3600);
  });

  it("strips context at clearing level 2", () => {
    const w = makeWitness(2);
    const p = w.witnessAnchorDensity({ expectedAnchors: 100, actualAnchors: 50 });
    expect(p.ai_context).toBeUndefined();
  });

  it("accepts governanceMetadata", () => {
    const w = makeWitness(1);
    const p = w.witnessAnchorDensity({
      expectedAnchors: 100, actualAnchors: 100,
      governanceMetadata: { review_duration_minutes: 15 },
    });
    const ctx = p.ai_context as Record<string, unknown>;
    expect(ctx.review_duration_minutes).toBe(15);
  });
});
