import { describe, it, expect } from "vitest";
import { validateSchema } from "../src/schema.js";

describe("Schema Validator", () => {
  it("valid config passes", () => {
    const result = validateSchema({
      api_key: "axm_test",
      tenant_id: "TEST",
      clearing_level: 2,
      trust_mesh: { mode: "strict", min_trust_level: 2 },
      policy: { require_signing: true },
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("unknown top-level key returns error", () => {
    const result = validateSchema({
      api_key: "axm_test",
      bogus_field: true,
    });
    expect(result.valid).toBe(false);
    expect(result.errors[0].path).toBe("bogus_field");
    expect(result.errors[0].message).toContain("unknown top-level key");
  });

  it("wrong type for clearing_level returns error", () => {
    const result = validateSchema({
      api_key: "axm_test",
      clearing_level: "high",
    });
    expect(result.valid).toBe(false);
    expect(result.errors[0].path).toBe("clearing_level");
  });

  it("invalid enum value returns error", () => {
    const result = validateSchema({
      api_key: "axm_test",
      trust_mesh: { mode: "aggressive" },
    });
    expect(result.valid).toBe(false);
    expect(result.errors[0].path).toBe("trust_mesh.mode");
  });

  it("wrong type in section returns error", () => {
    const result = validateSchema({
      api_key: "axm_test",
      policy: { require_signing: "yes" },
    });
    expect(result.valid).toBe(false);
    expect(result.errors[0].path).toBe("policy.require_signing");
    expect(result.errors[0].message).toContain("expected boolean");
  });

  it("multiple errors accumulated correctly", () => {
    const result = validateSchema({
      bogus1: true,
      bogus2: true,
      clearing_level: 99,
      trust_mesh: { mode: "invalid", bad_key: true },
    });
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThanOrEqual(4);
  });

  // ── digest_algorithm ────────────────────────────────────────

  it("accepts digest_algorithm: sha256", () => {
    const result = validateSchema({ api_key: "axm_test", digest_algorithm: "sha256" });
    expect(result.valid).toBe(true);
  });

  it("rejects unsupported digest_algorithm", () => {
    const result = validateSchema({ api_key: "axm_test", digest_algorithm: "sha3-256" });
    expect(result.valid).toBe(false);
    expect(result.errors[0].path).toBe("digest_algorithm");
    expect(result.errors[0].message).toContain("sha256");
  });

  it("rejects non-string digest_algorithm", () => {
    const result = validateSchema({ api_key: "axm_test", digest_algorithm: 256 });
    expect(result.valid).toBe(false);
    expect(result.errors[0].path).toBe("digest_algorithm");
  });

  // ── skill_card ──────────────────────────────────────────────

  it("accepts valid skill_card section", () => {
    const result = validateSchema({
      api_key: "axm_test",
      skill_card: { skills: ["web_search"], expected_manifest_hash: "abc" },
    });
    expect(result.valid).toBe(true);
  });

  it("rejects unknown skill_card key", () => {
    const result = validateSchema({
      api_key: "axm_test",
      skill_card: { skills: [], bogus_key: true },
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path === "skill_card.bogus_key")).toBe(true);
  });
});
