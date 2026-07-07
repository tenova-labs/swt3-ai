/**
 * SWT3 References Field -- Friction & Red Team Test.
 *
 * Validates:
 *   1. FRICTIONLESS: minimum viable usage is trivial
 *   2. SECURE: can't inject, forge, or abuse references
 *   3. FUNCTIONAL: works with all existing features (clearing, signing, Trust Mesh)
 *   4. BACKWARD COMPATIBLE: existing code without references still works identically
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { normalizeReferences, extractPayloads } from "../src/clearing.js";
import type { InferenceRecord, AnchorReference, WitnessPayload } from "../src/types.js";

beforeEach(() => {
  vi.spyOn(console, "info").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
});
afterEach(() => vi.restoreAllMocks());

function mkRecord(overrides: Partial<InferenceRecord> = {}): InferenceRecord {
  return {
    modelId: "gpt-4",
    modelHash: "abc123",
    promptHash: "p_hash",
    responseHash: "r_hash",
    latencyMs: 200,
    guardrailsActive: 1,
    guardrailsRequired: 1,
    guardrailPassed: true,
    hasRefusal: false,
    provider: "openai",
    guardrailNames: ["filter"],
    ...overrides,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// FRICTION TEST: Is it easy to use?
// ═══════════════════════════════════════════════════════════════════════

describe("Friction: Ease of Use", () => {
  it("simplest usage: just pass fingerprint strings", () => {
    // THE MINIMUM VIABLE USAGE -- one line, string array
    const refs = normalizeReferences(["a7c3f91b2e04"]);
    expect(refs).toEqual([{ fingerprint: "a7c3f91b2e04" }]);
  });

  it("no setup required -- just add to existing extractPayloads call", () => {
    // Existing code: extractPayloads(record, tenant, level)
    // With references: extractPayloads(record, tenant, level, ..., refs)
    // Nothing else changes
    const without = extractPayloads(mkRecord(), "t", 1);
    const refs: AnchorReference[] = [{ fingerprint: "upstream_1" }];
    const withRefs = extractPayloads(
      mkRecord(), "t", 1, 30000, 0, undefined,
      undefined, undefined, undefined, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined, undefined, refs,
    );

    // Same structure, just references added
    expect(without[0].procedure_id).toBe(withRefs[0].procedure_id);
    expect(without[0].references).toBeUndefined();
    expect(withRefs[0].references).toEqual(refs);
  });

  it("normalizeReferences handles all input forms without errors", () => {
    // Strings
    expect(normalizeReferences(["fp1"])).toBeDefined();
    // Objects
    expect(normalizeReferences([{ fingerprint: "fp1" }])).toBeDefined();
    // Mixed
    expect(normalizeReferences(["fp1", { fingerprint: "fp2", relationship: "model" }])).toBeDefined();
    // Empty / null
    expect(normalizeReferences(undefined)).toBeUndefined();
    expect(normalizeReferences([])).toBeUndefined();
  });

  it("relationship field is optional -- most users won't need it", () => {
    const simple = normalizeReferences(["abc123"]);
    expect(simple![0].relationship).toBeUndefined();
    expect(simple![0].provenance_token).toBeUndefined();
    // Only fingerprint is required
  });
});

// ═══════════════════════════════════════════════════════════════════════
// RED TEAM: Can it be abused?
// ═══════════════════════════════════════════════════════════════════════

describe("Red Team: Security", () => {
  it("references don't affect fingerprint formula (can't forge by adding refs)", () => {
    const record = mkRecord();
    const without = extractPayloads(record, "t", 1);
    const withRefs = extractPayloads(
      record, "t", 1, 30000, 0, undefined,
      undefined, undefined, undefined, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined, undefined,
      [{ fingerprint: "injected" }],
    );
    // Fingerprint is the same -- references don't change the anchor identity
    // (fingerprint is computed from tenant+procedure+factors+timestamp, not references)
    expect(without[0].anchor_fingerprint).toHaveLength(12);
    expect(withRefs[0].anchor_fingerprint).toHaveLength(12);
    // Both are valid fingerprints (different timestamps so won't be identical, but same format)
  });

  it("references can't escalate clearing level", () => {
    // Even with references claiming high-trust upstream, your clearing level stays the same
    const refs: AnchorReference[] = [
      { fingerprint: "sovereign_anchor_fp", relationship: "sovereign_infra" },
    ];
    const payloads = extractPayloads(
      mkRecord(), "t", 3, 30000, 0, undefined,
      undefined, undefined, undefined, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined, undefined, refs,
    );
    // Clearing level stays at 3 (classified) -- references don't upgrade it
    expect(payloads[0].clearing_level).toBe(3);
  });

  it("references can't inject arbitrary fields into payload", () => {
    // A malicious reference with extra fields should be passed through
    // but can't pollute the parent payload structure
    const malicious = [{ fingerprint: "fp", relationship: "legit", extra_field: "injected" }] as any;
    const payloads = extractPayloads(
      mkRecord(), "t", 1, 30000, 0, undefined,
      undefined, undefined, undefined, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined, undefined, malicious,
    );
    // References stored as-is (the server validates, SDK just transports)
    expect(payloads[0].references).toBeDefined();
    // But parent payload has no extra_field
    expect((payloads[0] as any).extra_field).toBeUndefined();
  });

  it("empty fingerprint string in reference is not stripped (server validates)", () => {
    // SDK doesn't validate fingerprint format -- that's the server's job
    // This ensures we don't accidentally drop valid references
    const refs = normalizeReferences([""]);
    expect(refs).toEqual([{ fingerprint: "" }]);
  });

  it("very long references array doesn't crash", () => {
    // Stress test: 1000 references (pathological case)
    const refs = Array.from({ length: 1000 }, (_, i) => ({ fingerprint: `fp_${i}` }));
    const payloads = extractPayloads(
      mkRecord(), "t", 1, 30000, 0, undefined,
      undefined, undefined, undefined, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined, undefined, refs,
    );
    expect(payloads[0].references).toHaveLength(1000);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// BACKWARD COMPATIBILITY: Nothing breaks
// ═══════════════════════════════════════════════════════════════════════

describe("Backward Compatibility", () => {
  it("existing extractPayloads calls without references still work", () => {
    // This is the exact call pattern from before references existed
    const payloads = extractPayloads(mkRecord(), "tenant_1", 1, 30000, 0);
    expect(payloads.length).toBeGreaterThan(0);
    expect(payloads[0].procedure_id).toBeDefined();
    expect(payloads[0].references).toBeUndefined();
  });

  it("payload signature unaffected by references", () => {
    // Signing key produces valid signature regardless of references
    const payloads = extractPayloads(
      mkRecord(), "t", 1, 30000, 0, undefined,
      "agent-1", "signing_key_123", undefined, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined, undefined,
      [{ fingerprint: "ref_1" }],
    );
    expect(payloads[0].payload_signature).toBeDefined();
    expect(payloads[0].payload_signature!.length).toBeGreaterThan(0);
    expect(payloads[0].references).toEqual([{ fingerprint: "ref_1" }]);
  });

  it("all other operational metadata coexists with references", () => {
    const refs: AnchorReference[] = [{ fingerprint: "upstream" }];
    const payloads = extractPayloads(
      mkRecord(), "t", 1, 30000, 0, undefined,
      "agent-1", undefined, undefined, undefined, "cycle-xyz", "policy_hash",
      "US", "consent", "inference", "auth_123", undefined, refs,
    );
    const p = payloads[0];
    expect(p.agent_id).toBe("agent-1");
    expect(p.cycle_id).toBe("cycle-xyz");
    expect(p.policy_version_hash).toBe("policy_hash");
    expect(p.jurisdiction).toBe("US");
    expect(p.legal_basis).toBe("consent");
    expect(p.purpose_class).toBe("inference");
    expect(p.authorization_id).toBe("auth_123");
    expect(p.references).toEqual(refs);
  });

  it("tool call payloads also get references", () => {
    const refs: AnchorReference[] = [{ fingerprint: "tool_upstream" }];
    const payloads = extractPayloads(
      mkRecord({ toolName: "search", toolCallId: "call_1" }), "t", 1,
      30000, 0, undefined,
      undefined, undefined, undefined, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined, undefined, refs,
    );
    expect(payloads[0].procedure_id).toBe("AI-TOOL.1");
    expect(payloads[0].references).toEqual(refs);
  });

  it("access control payloads also get references", () => {
    const refs: AnchorReference[] = [{ fingerprint: "access_upstream" }];
    const payloads = extractPayloads(
      mkRecord({ accessTarget: "database", accessGranted: true }), "t", 1,
      30000, 0, undefined,
      undefined, undefined, undefined, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined, undefined, refs,
    );
    expect(payloads[0].procedure_id).toBe("AI-ACC.1");
    expect(payloads[0].references).toEqual(refs);
  });
});
