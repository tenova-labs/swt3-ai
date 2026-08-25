/**
 * AI-MCP.1 MCP Security Posture tests.
 *
 * Tests the witnessMcpSecurity method and verifies fingerprint parity
 * with Python SDK test vectors.
 */
import { describe, it, expect } from "vitest";
import { Witness } from "../src/witness.js";
import { mintFingerprint } from "../src/fingerprint.js";
import vectors from "./test-vectors.json" with { type: "json" };

const BASE_CONFIG = {
  endpoint: "http://localhost",
  apiKey: "axm_test_key",
  tenantId: "ENCLAVE_PROD",
  clearingLevel: 1 as const,
  bufferSize: 100,
  flushInterval: 999,
  timeout: 1000,
  maxRetries: 0,
  latencyThresholdMs: 5000,
  guardrailsRequired: 0,
  guardrailNames: [],
};

describe("AI-MCP.1 Fingerprint Parity", () => {
  const mcpVectors = vectors.fingerprint_vectors.filter(
    (v: any) => v.procedure_id === "AI-MCP.1",
  );

  it("has AI-MCP.1 test vectors", () => {
    expect(mcpVectors.length).toBeGreaterThanOrEqual(2);
  });

  for (const vec of mcpVectors) {
    it(`vector ${vec.id}: ${vec.description}`, () => {
      const fp = mintFingerprint(
        vec.tenant_id, vec.procedure_id,
        vec.factor_a, vec.factor_b, vec.factor_c,
        vec.fingerprint_timestamp_ms,
      );
      expect(fp).toBe(vec.expected_fingerprint);
    });
  }
});

describe("AI-MCP.1 witnessMcpSecurity", () => {
  it("mints AI-MCP.1 anchor with correct factors", () => {
    const w = new Witness(BASE_CONFIG);
    const p = w.witnessMcpSecurity({ checksPassed: 8 });
    expect(p.procedure_id).toBe("AI-MCP.1");
    expect(p.factor_a).toBe(8); // total checks
    expect(p.factor_b).toBe(8); // passed
    expect(p.factor_c).toBe(100); // score
  });

  it("auto-derives score from checks", () => {
    const w = new Witness(BASE_CONFIG);
    const p = w.witnessMcpSecurity({ checksPassed: 6 });
    expect(p.factor_c).toBe(75); // 6/8 = 75%
  });

  it("accepts custom total checks and score", () => {
    const w = new Witness(BASE_CONFIG);
    const p = w.witnessMcpSecurity({ checksPassed: 4, totalChecks: 10, score: 40 });
    expect(p.factor_a).toBe(10);
    expect(p.factor_b).toBe(4);
    expect(p.factor_c).toBe(40);
  });

  it("includes context at clearing level 1", () => {
    const w = new Witness(BASE_CONFIG);
    const p = w.witnessMcpSecurity({
      checksPassed: 7,
      serverName: "my-mcp-server",
      transportType: "sse",
    });
    expect(p.ai_context).toBeDefined();
    expect(p.ai_context!.provider).toBe("mcp-security-posture");
    expect(p.ai_context!.checks_total).toBe(8);
    expect(p.ai_context!.checks_passed).toBe(7);
    expect(p.ai_context!.posture_score).toBe(88);
    expect(p.ai_context!.server_name).toBe("my-mcp-server");
    expect(p.ai_context!.transport_type).toBe("sse");
    expect(p.ai_model_id).toBe("mcp-security-sse");
  });

  it("strips context at clearing level 2", () => {
    const w = new Witness({ ...BASE_CONFIG, clearingLevel: 2 });
    const p = w.witnessMcpSecurity({ checksPassed: 8 });
    expect(p.ai_context).toBeUndefined();
  });

  it("defaults transport to stdio in model ID", () => {
    const w = new Witness(BASE_CONFIG);
    const p = w.witnessMcpSecurity({ checksPassed: 8 });
    expect(p.ai_model_id).toBe("mcp-security-stdio");
  });

  it("never reveals individual check results", () => {
    const w = new Witness(BASE_CONFIG);
    const p = w.witnessMcpSecurity({ checksPassed: 5 });
    // Context should NOT contain which checks failed -- only counts
    const ctx = p.ai_context as Record<string, unknown>;
    expect(ctx).not.toHaveProperty("failed_checks");
    expect(ctx).not.toHaveProperty("check_results");
    expect(ctx).not.toHaveProperty("checks_failed");
  });

  it("accepts governanceMetadata", () => {
    const w = new Witness(BASE_CONFIG);
    const p = w.witnessMcpSecurity({
      checksPassed: 8,
      governanceMetadata: { review_id: "SEC-2026-001" },
    });
    expect(p.ai_context!.review_id).toBe("SEC-2026-001");
  });

  it("exposes MCP_SECURITY_CHECKS static list", () => {
    expect(Witness.MCP_SECURITY_CHECKS).toHaveLength(8);
    expect(Witness.MCP_SECURITY_CHECKS).toContain("input_validation");
    expect(Witness.MCP_SECURITY_CHECKS).toContain("error_masking");
  });
});
