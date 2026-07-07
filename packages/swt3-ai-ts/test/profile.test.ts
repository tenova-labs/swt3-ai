import { describe, it, expect } from "vitest";
import {
  generateProfile,
  signProfile,
  verifyProfileSignature,
  isProfileValid,
  coverageScore,
  buildProfileMessage,
  RECOMMENDED_PROCEDURES,
} from "../src/profile.js";
import type { ProcedureAttestation, AnchorReference } from "../src/types.js";

const NOW = 1_700_000_000_000;
const KEY = "test-signing-key-256bit-abcdef";

function mkAttestation(proc: string, status: "pass" | "fail" | "missing" = "pass"): ProcedureAttestation {
  return { procedure: proc, fingerprint: `fp_${proc}`, timestamp: NOW - 1000, status };
}

describe("generateProfile", () => {
  it("builds a profile with correct coverage score", () => {
    const attestations = [mkAttestation("AI-INF.1"), mkAttestation("AI-GRD.1"), mkAttestation("AI-MDL.1", "fail")];
    const profile = generateProfile({ modelId: "gpt-4o", modelHash: "abc123", attestations, nowMs: NOW });
    expect(profile.model_id).toBe("gpt-4o");
    expect(profile.model_hash).toBe("abc123");
    expect(profile.coverage_score).toBeCloseTo(2 / 3, 10);
    expect(profile.generated_at).toBe(NOW);
    expect(profile.valid_until).toBe(NOW + 86_400_000);
    expect(profile.signature).toBeUndefined();
  });

  it("returns score 0 for empty attestations", () => {
    const profile = generateProfile({ modelId: "m", modelHash: "h", attestations: [], nowMs: NOW });
    expect(profile.coverage_score).toBe(0);
  });

  it("returns score 1 when all pass", () => {
    const attestations = [mkAttestation("AI-INF.1"), mkAttestation("AI-GRD.1")];
    const profile = generateProfile({ modelId: "m", modelHash: "h", attestations, nowMs: NOW });
    expect(profile.coverage_score).toBe(1);
  });

  it("signs when signingKey is provided", () => {
    const attestations = [mkAttestation("AI-INF.1")];
    const profile = generateProfile({ modelId: "m", modelHash: "h", attestations, signingKey: KEY, nowMs: NOW });
    expect(profile.signature).toBeDefined();
    expect(profile.signature!.length).toBe(64); // SHA-256 hex
  });

  it("includes upstream references", () => {
    const refs: AnchorReference[] = [{ fingerprint: "upstream_fp" }];
    const profile = generateProfile({ modelId: "m", modelHash: "h", attestations: [], upstreamReferences: refs, nowMs: NOW });
    expect(profile.upstream_references).toHaveLength(1);
    expect(profile.upstream_references[0].fingerprint).toBe("upstream_fp");
  });

  it("uses custom TTL", () => {
    const profile = generateProfile({ modelId: "m", modelHash: "h", attestations: [], ttlMs: 3600_000, nowMs: NOW });
    expect(profile.valid_until).toBe(NOW + 3600_000);
  });
});

describe("signProfile / verifyProfileSignature", () => {
  it("round-trips signing and verification", () => {
    const attestations = [mkAttestation("AI-INF.1"), mkAttestation("AI-GRD.1")];
    const profile = generateProfile({ modelId: "m", modelHash: "h", attestations, signingKey: KEY, nowMs: NOW });
    expect(verifyProfileSignature(profile, KEY)).toBe(true);
  });

  it("rejects tampered model_id", () => {
    const attestations = [mkAttestation("AI-INF.1")];
    const profile = generateProfile({ modelId: "m", modelHash: "h", attestations, signingKey: KEY, nowMs: NOW });
    profile.model_id = "tampered";
    expect(verifyProfileSignature(profile, KEY)).toBe(false);
  });

  it("rejects wrong key", () => {
    const attestations = [mkAttestation("AI-INF.1")];
    const profile = generateProfile({ modelId: "m", modelHash: "h", attestations, signingKey: KEY, nowMs: NOW });
    expect(verifyProfileSignature(profile, "wrong-key")).toBe(false);
  });

  it("returns false for unsigned profile", () => {
    const profile = generateProfile({ modelId: "m", modelHash: "h", attestations: [], nowMs: NOW });
    expect(verifyProfileSignature(profile, KEY)).toBe(false);
  });
});

describe("buildProfileMessage", () => {
  it("sorts procedures alphabetically in canonical message", () => {
    const attestations = [mkAttestation("AI-GRD.1"), mkAttestation("AI-INF.1"), mkAttestation("AI-ACC.1")];
    const profile = generateProfile({ modelId: "m", modelHash: "h", attestations, nowMs: NOW });
    const msg = buildProfileMessage(profile);
    expect(msg).toContain("AI-ACC.1,AI-GRD.1,AI-INF.1");
  });

  it("formats score to 3 decimal places", () => {
    const attestations = [mkAttestation("AI-INF.1"), mkAttestation("AI-GRD.1"), mkAttestation("AI-MDL.1", "fail")];
    const profile = generateProfile({ modelId: "m", modelHash: "h", attestations, nowMs: NOW });
    const msg = buildProfileMessage(profile);
    expect(msg).toContain(":0.667");
  });
});

describe("isProfileValid", () => {
  it("returns true within validity window", () => {
    const profile = generateProfile({ modelId: "m", modelHash: "h", attestations: [], nowMs: NOW });
    expect(isProfileValid(profile, NOW + 1000)).toBe(true);
  });

  it("returns false after expiry", () => {
    const profile = generateProfile({ modelId: "m", modelHash: "h", attestations: [], ttlMs: 1000, nowMs: NOW });
    expect(isProfileValid(profile, NOW + 2000)).toBe(false);
  });

  it("returns true at exact boundary", () => {
    const profile = generateProfile({ modelId: "m", modelHash: "h", attestations: [], ttlMs: 1000, nowMs: NOW });
    expect(isProfileValid(profile, NOW + 1000)).toBe(true);
  });
});

describe("coverageScore", () => {
  it("returns 1.0 for full coverage", () => {
    const result = coverageScore(["AI-INF.1", "AI-INF.2", "AI-MDL.1", "AI-MDL.2", "AI-GRD.1", "AI-GRD.2"], "standard");
    expect(result.score).toBe(1);
    expect(result.missing).toHaveLength(0);
    expect(result.extra).toHaveLength(0);
  });

  it("returns 0.5 for half coverage", () => {
    const result = coverageScore(["AI-INF.1", "AI-INF.2", "AI-MDL.1"], "standard");
    expect(result.score).toBe(0.5);
    expect(result.covered).toHaveLength(3);
    expect(result.missing).toHaveLength(3);
  });

  it("defaults to standard profile", () => {
    const result = coverageScore(["AI-INF.1"]);
    expect(result.target).toEqual(RECOMMENDED_PROCEDURES["standard"]);
  });

  it("accepts custom array target", () => {
    const result = coverageScore(["AI-INF.1", "AI-GRD.1"], ["AI-INF.1", "AI-GRD.1", "AI-FAIR.1"]);
    expect(result.score).toBeCloseTo(2 / 3, 10);
    expect(result.missing).toEqual(["AI-FAIR.1"]);
  });

  it("identifies extra procedures", () => {
    const result = coverageScore(["AI-INF.1", "AI-HW.1"], "minimal");
    expect(result.extra).toEqual(["AI-HW.1"]);
  });

  it("throws for unknown profile name", () => {
    expect(() => coverageScore([], "nonexistent")).toThrow('Unknown profile: "nonexistent"');
  });

  it("returns 0 for empty target", () => {
    const result = coverageScore(["AI-INF.1"], []);
    expect(result.score).toBe(0);
  });
});
