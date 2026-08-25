/**
 * Tests for AI-DEL.2 Delegation Boundary Attestation (v0.6.6).
 *
 * Cross-language fingerprint parity with test-vectors.json vectors 56-58.
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
const delVectors: FingerprintVector[] = allVectors.fingerprint_vectors.filter(
  (v: FingerprintVector) => v.procedure_id === "AI-DEL.2",
);

function makeWitness(clearingLevel: 0 | 1 | 2 | 3 = 1): Witness {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "TEST_DEL",
    clearingLevel,
  });
}

// ── Cross-language fingerprint parity ──────────────────────────────────

describe("AI-DEL.2 Fingerprint Parity", () => {
  it("has 3 AI-DEL.2 test vectors", () => {
    expect(delVectors).toHaveLength(3);
  });

  for (const v of delVectors) {
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

describe("AI-DEL.2 witnessDelegationBoundary", () => {
  it("mints AI-DEL.2 anchor with correct factors", () => {
    const w = makeWitness();
    const p = w.witnessDelegationBoundary({
      maxDepth: 5, actualDepth: 3, boundaryAction: "allowed",
    });
    expect(p.procedure_id).toBe("AI-DEL.2");
    expect(p.factor_a).toBe(5);
    expect(p.factor_b).toBe(3);
    expect(p.factor_c).toBe(3); // allowed = 3
  });

  it("uses correct boundary action codes", () => {
    const w = makeWitness();
    for (const [action, code] of Object.entries({ blocked: 0, warned: 1, escalated: 2, allowed: 3 })) {
      const p = w.witnessDelegationBoundary({ maxDepth: 5, actualDepth: 3, boundaryAction: action });
      expect(p.factor_c).toBe(code);
    }
  });

  it("defaults unknown action to 3 (allowed)", () => {
    const w = makeWitness();
    const p = w.witnessDelegationBoundary({ maxDepth: 5, actualDepth: 3, boundaryAction: "custom_action" });
    expect(p.factor_c).toBe(3);
  });

  it("includes depth_exceeded=true when actual > max", () => {
    const w = makeWitness(1);
    const p = w.witnessDelegationBoundary({
      maxDepth: 3, actualDepth: 7, boundaryAction: "blocked",
      delegatorId: "agent-root",
    });
    const ctx = p.ai_context as Record<string, unknown>;
    expect(ctx.depth_exceeded).toBe(true);
    expect(ctx.delegator_id).toBe("agent-root");
    expect(ctx.boundary_action).toBe("blocked");
  });

  it("includes depth_exceeded=false when within bounds", () => {
    const w = makeWitness(1);
    const p = w.witnessDelegationBoundary({ maxDepth: 5, actualDepth: 2, boundaryAction: "allowed" });
    const ctx = p.ai_context as Record<string, unknown>;
    expect(ctx.depth_exceeded).toBe(false);
  });

  it("strips context at clearing level 2", () => {
    const w = makeWitness(2);
    const p = w.witnessDelegationBoundary({ maxDepth: 5, actualDepth: 3, boundaryAction: "allowed" });
    expect(p.ai_context).toBeUndefined();
  });

  it("accepts governanceMetadata", () => {
    const w = makeWitness(1);
    const p = w.witnessDelegationBoundary({
      maxDepth: 5, actualDepth: 3, boundaryAction: "allowed",
      governanceMetadata: { participant_count: 3, review_duration_minutes: 30 },
    });
    const ctx = p.ai_context as Record<string, unknown>;
    expect(ctx.participant_count).toBe(3);
    expect(ctx.review_duration_minutes).toBe(30);
  });

  it("includes parent_grant_fingerprint when provided", () => {
    const w = makeWitness(1);
    const p = w.witnessDelegationBoundary({
      maxDepth: 5, actualDepth: 1, boundaryAction: "allowed",
      parentGrantFingerprint: "abc123def456",
    });
    const ctx = p.ai_context as Record<string, unknown>;
    expect(ctx.parent_grant_fingerprint).toBe("abc123def456");
  });
});
