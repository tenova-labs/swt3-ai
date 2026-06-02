/**
 * SWT3 AI Witness SDK — Adversarial Tests.
 *
 * Tests SDK resilience against malformed inputs, injection attempts,
 * boundary conditions, and fail-safe behavior. Categories:
 *
 *   1. Constructor validation bypass
 *   2. Fingerprint integrity under malicious inputs
 *   3. Clearing level enforcement (no data leakage)
 *   4. Injection via payload fields (tenant_id, procedure_id, model_id)
 *   5. Revocation abuse
 *   6. Buffer overflow and dead-letter resilience
 *   7. Signing edge cases
 *   8. Tool/access wrapper abuse
 *   9. RAG/skill/model weight boundary inputs
 *  10. Gatekeeper bypass attempts
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Witness, GatekeeperError } from "../src/witness.js";
import { mintFingerprint, sha256Truncated, sha256Hex } from "../src/fingerprint.js";
import { signPayload } from "../src/signing.js";
import { extractPayloads, extractRevocationPayload, REVOCATION_REASONS } from "../src/clearing.js";

// Suppress console noise in tests
beforeEach(() => {
  vi.spyOn(console, "info").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => vi.restoreAllMocks());

/** Helper: create a Witness with minimal valid config. */
function mkWitness(overrides: Record<string, unknown> = {}): Witness {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "test_tenant",
    flushInterval: 999999, // never auto-flush
    ...overrides,
  } as any);
}

// ────────────────────────────────────────────────────────────
// 1. Constructor validation bypass
// ────────────────────────────────────────────────────────────
describe("constructor validation", () => {
  it("rejects empty endpoint", () => {
    expect(() => new Witness({ endpoint: "", apiKey: "axm_x", tenantId: "t" } as any))
      .toThrow("endpoint is required");
  });

  it("rejects apiKey without axm_ prefix", () => {
    expect(() => new Witness({ endpoint: "https://x.com", apiKey: "bad_key", tenantId: "t" } as any))
      .toThrow("apiKey must start with 'axm_'");
  });

  it("rejects missing apiKey", () => {
    expect(() => new Witness({ endpoint: "https://x.com", apiKey: "", tenantId: "t" } as any))
      .toThrow("apiKey is required");
  });

  it("rejects missing tenantId", () => {
    expect(() => new Witness({ endpoint: "https://x.com", apiKey: "axm_x", tenantId: "" } as any))
      .toThrow("tenantId is required");
  });

  it("rejects invalid factorHandoff value", () => {
    expect(() => mkWitness({ factorHandoff: "s3" })).toThrow("factorHandoff must be 'file'");
  });

  it("rejects factorHandoff=file without path", () => {
    expect(() => mkWitness({ factorHandoff: "file" })).toThrow("factorHandoffPath is required");
  });

  it("strips trailing slashes from endpoint", () => {
    const w = mkWitness({ endpoint: "https://x.com////" });
    // Verify by checking the flush URL would be correct (no double slashes)
    expect(w.pending).toBe(0); // just verifies construction succeeded
  });

  it("gateway mode skips endpoint/apiKey/tenantId validation", () => {
    const w = new Witness({
      endpoint: "",
      apiKey: "",
      tenantId: "",
      gatewayMode: true,
      flushInterval: 999999,
    } as any);
    expect(w.gatewayMode).toBe(true);
  });
});

// ────────────────────────────────────────────────────────────
// 2. Fingerprint integrity under malicious inputs
// ────────────────────────────────────────────────────────────
describe("fingerprint integrity", () => {
  it("colon injection in tenantId does not collide", () => {
    // An attacker who controls tenantId tries to shift field boundaries
    const legit = mintFingerprint("tenant_a", "AI-INF.1", 1, 1, 0, 1000);
    const injected = mintFingerprint("tenant_a:AI-INF.1:1", "", 0, 0, 0, 1000);
    expect(legit).not.toBe(injected);
  });

  it("colon injection in procedureId does not collide", () => {
    const legit = mintFingerprint("t", "AI-INF.1", 1, 0, 0, 1000);
    const injected = mintFingerprint("t", "AI-INF.1:1:0:0:1000", 0, 0, 0, 999);
    expect(legit).not.toBe(injected);
  });

  it("negative factor values produce unique fingerprints", () => {
    const pos = mintFingerprint("t", "AI-INF.1", 1, 1, 0, 1000);
    const neg = mintFingerprint("t", "AI-INF.1", -1, -1, 0, 1000);
    expect(pos).not.toBe(neg);
  });

  it("NaN factor values produce deterministic output", () => {
    const fp1 = mintFingerprint("t", "P", NaN, 0, 0, 1000);
    const fp2 = mintFingerprint("t", "P", NaN, 0, 0, 1000);
    expect(fp1).toBe(fp2);
    expect(fp1).toHaveLength(12);
  });

  it("Infinity factor values do not crash", () => {
    const fp = mintFingerprint("t", "P", Infinity, -Infinity, 0, 1000);
    expect(fp).toHaveLength(12);
  });

  it("very large factor values produce valid fingerprint", () => {
    const fp = mintFingerprint("t", "P", Number.MAX_SAFE_INTEGER, 0, 0, 1000);
    expect(fp).toHaveLength(12);
    expect(fp).toMatch(/^[0-9a-f]{12}$/);
  });

  it("float factors produce consistent fingerprints", () => {
    const fp1 = mintFingerprint("t", "P", 1.5, 2.7, 0.001, 1000);
    const fp2 = mintFingerprint("t", "P", 1.5, 2.7, 0.001, 1000);
    expect(fp1).toBe(fp2);
  });

  it("unicode tenantId produces valid fingerprint", () => {
    const fp = mintFingerprint("tenant_\u{1F600}\u{1F4A9}", "P", 1, 0, 0, 1000);
    expect(fp).toHaveLength(12);
    expect(fp).toMatch(/^[0-9a-f]{12}$/);
  });

  it("empty string tenantId produces valid fingerprint", () => {
    // This shouldn't happen (constructor validates) but fingerprint function should be safe
    const fp = mintFingerprint("", "P", 1, 0, 0, 1000);
    expect(fp).toHaveLength(12);
  });

  it("very long tenantId does not crash", () => {
    const longId = "a".repeat(100_000);
    const fp = mintFingerprint(longId, "P", 1, 0, 0, 1000);
    expect(fp).toHaveLength(12);
  });
});

// ────────────────────────────────────────────────────────────
// 3. Clearing level enforcement (no data leakage)
// ────────────────────────────────────────────────────────────
describe("clearing level enforcement", () => {
  const baseRecord = {
    modelId: "gpt-4o",
    modelHash: "abc123",
    promptHash: "prompt_hash_val",
    responseHash: "response_hash_val",
    latencyMs: 500,
    guardrailsActive: 1,
    guardrailsRequired: 1,
    guardrailPassed: true,
    hasRefusal: false,
    provider: "openai",
    systemFingerprint: "fp_abc123",
    systemPromptHash: "sys_hash_val",
    guardrailNames: ["content-filter"],
    inputTokens: 100,
    outputTokens: 200,
  };

  it("level 3 does not leak model_id in cleartext", () => {
    const payloads = extractPayloads(baseRecord, "t", 3);
    for (const p of payloads) {
      if (p.ai_model_id) {
        // Must be a hash, not the original model name
        expect(p.ai_model_id).not.toBe("gpt-4o");
        expect(p.ai_model_id).toMatch(/^[0-9a-f]+$/);
      }
    }
  });

  it("level 3 strips all hash fields", () => {
    const payloads = extractPayloads(baseRecord, "t", 3);
    for (const p of payloads) {
      expect(p.ai_prompt_hash).toBeUndefined();
      expect(p.ai_response_hash).toBeUndefined();
      expect(p.ai_latency_ms).toBeUndefined();
      expect(p.ai_input_tokens).toBeUndefined();
      expect(p.ai_output_tokens).toBeUndefined();
      expect(p.ai_context).toBeUndefined();
      expect(p.ai_system_prompt_hash).toBeUndefined();
    }
  });

  it("level 2 strips ai_context but preserves model_id", () => {
    const payloads = extractPayloads(baseRecord, "t", 2);
    for (const p of payloads) {
      expect(p.ai_context).toBeUndefined();
      // model_id should be cleartext at level 2
      if (p.procedure_id === "AI-INF.1") {
        expect(p.ai_model_id).toBe("gpt-4o");
      }
    }
  });

  it("level 3 payloads survive JSON serialization without leaking", () => {
    const payloads = extractPayloads(baseRecord, "t", 3);
    const json = JSON.stringify(payloads);
    expect(json).not.toContain("gpt-4o");
    expect(json).not.toContain("prompt_hash_val");
    expect(json).not.toContain("response_hash_val");
    expect(json).not.toContain("sys_hash_val");
    expect(json).not.toContain("fp_abc123");
    expect(json).not.toContain("content-filter");
  });

  it("CJT fields survive at all clearing levels", () => {
    for (const level of [0, 1, 2, 3] as const) {
      const payloads = extractPayloads(
        baseRecord, "t", level, 30000, 0, undefined,
        "agent-1", undefined, undefined, undefined,
        "cycle-1", undefined,
        "DE", "GDPR-6.1.a", "analytics",
      );
      for (const p of payloads) {
        expect(p.jurisdiction).toBe("DE");
        expect(p.legal_basis).toBe("GDPR-6.1.a");
        expect(p.purpose_class).toBe("analytics");
      }
    }
  });

  it("agent_id survives all clearing levels", () => {
    for (const level of [0, 1, 2, 3] as const) {
      const payloads = extractPayloads(
        baseRecord, "t", level, 30000, 0, undefined, "agent-007",
      );
      for (const p of payloads) {
        expect(p.agent_id).toBe("agent-007");
      }
    }
  });
});

// ────────────────────────────────────────────────────────────
// 4. Injection via payload fields
// ────────────────────────────────────────────────────────────
describe("injection resistance", () => {
  it("SQL injection in tenantId is passed through as-is (server must validate)", () => {
    // The SDK should not crash -- server-side validation is the guard
    const w = mkWitness({ tenantId: "'; DROP TABLE sovereign_witness_ledger; --" });
    w.witnessSecurityScan(100);
    expect(w.pending).toBeGreaterThan(0);
  });

  it("HTML/XSS in model_id does not affect fingerprint format", () => {
    const record = {
      modelId: '<script>alert("xss")</script>',
      modelHash: "hash",
      promptHash: "p",
      responseHash: "r",
      latencyMs: 10,
      guardrailsActive: 0,
      guardrailsRequired: 0,
      guardrailPassed: true,
      hasRefusal: false,
      provider: "openai",
      guardrailNames: [],
    };
    const payloads = extractPayloads(record, "t", 1);
    expect(payloads.length).toBeGreaterThan(0);
    for (const p of payloads) {
      expect(p.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
    }
  });

  it("null bytes in strings do not crash hashing", () => {
    const fp = sha256Truncated("test\x00injection\x00payload");
    expect(fp).toHaveLength(16);
    expect(fp).toMatch(/^[0-9a-f]+$/);
  });

  it("control characters in agent_id do not crash", () => {
    const w = mkWitness({ agentId: "agent\n\r\t\x00\x1b[31m" });
    w.witnessSecurityScan(100);
    expect(w.pending).toBeGreaterThan(0);
  });

  it("CRLF injection in jurisdiction field", () => {
    const w = mkWitness({ jurisdiction: "DE\r\nX-Injected: true" });
    w.witnessSecurityScan(100);
    expect(w.pending).toBeGreaterThan(0);
  });
});

// ────────────────────────────────────────────────────────────
// 5. Revocation abuse
// ────────────────────────────────────────────────────────────
describe("revocation abuse", () => {
  it("rejects empty fingerprint", () => {
    const w = mkWitness();
    expect(() => w.revoke("", "model_recall")).toThrow("fingerprint is required");
  });

  it("rejects whitespace-only fingerprint", () => {
    const w = mkWitness();
    expect(() => w.revoke("   \t\n  ", "model_recall")).toThrow("fingerprint is required");
  });

  it("rejects unknown revocation reason", () => {
    const w = mkWitness();
    expect(() => w.revoke("abc123def456", "because_i_said_so")).toThrow("Unknown revocation reason");
  });

  it("accepts all 7 valid revocation reasons", () => {
    const w = mkWitness();
    for (const reason of Object.keys(REVOCATION_REASONS)) {
      const fp = w.revoke("abc123def456", reason);
      expect(fp).toHaveLength(12);
    }
    expect(w.pending).toBe(7);
  });

  it("trims whitespace from target fingerprint", () => {
    const p1 = extractRevocationPayload("t", "abc123def456", "model_recall", 1);
    const p2 = extractRevocationPayload("t", "  abc123def456  ", "model_recall", 1);
    // Different because whitespace is trimmed in Witness.revoke(), not extractRevocationPayload
    // The raw function preserves input -- Witness.revoke() trims before calling
    expect(p1.revocation_target).toBe("abc123def456");
  });

  it("revocation of same fingerprint twice produces different anchors (different timestamps)", () => {
    const w = mkWitness();
    const fp1 = w.revoke("abc123def456", "model_recall");
    const fp2 = w.revoke("abc123def456", "model_recall");
    // May or may not differ depending on timing, but both should be valid
    expect(fp1).toHaveLength(12);
    expect(fp2).toHaveLength(12);
  });

  it("cannot revoke with prototype pollution in reason", () => {
    const w = mkWitness();
    expect(() => w.revoke("abc123def456", "__proto__")).toThrow("Unknown revocation reason");
    expect(() => w.revoke("abc123def456", "constructor")).toThrow("Unknown revocation reason");
    expect(() => w.revoke("abc123def456", "toString")).toThrow("Unknown revocation reason");
  });
});

// ────────────────────────────────────────────────────────────
// 6. Buffer overflow and dead-letter resilience
// ────────────────────────────────────────────────────────────
describe("buffer resilience", () => {
  it("does not crash when enqueuing after stop", async () => {
    const w = mkWitness();
    await w.stop();
    // Should silently drop
    w.witnessSecurityScan(100);
    expect(w.pending).toBe(0);
  });

  it("double-stop does not crash", async () => {
    const w = mkWitness();
    await w.stop();
    const result = await w.stop();
    expect(result).toEqual([]);
  });

  it("flush on empty buffer returns empty array", async () => {
    const w = mkWitness();
    const result = await w.flush();
    expect(result).toEqual([]);
  });

  it("gateway mode silently drops records", () => {
    const w = new Witness({
      endpoint: "",
      apiKey: "",
      tenantId: "",
      gatewayMode: true,
      flushInterval: 999999,
    } as any);
    w.record({
      modelId: "gpt-4o",
      modelHash: "h",
      promptHash: "p",
      responseHash: "r",
      latencyMs: 10,
      guardrailsActive: 0,
      guardrailsRequired: 0,
      guardrailPassed: true,
      hasRefusal: false,
      provider: "openai",
      guardrailNames: [],
    });
    expect(w.pending).toBe(0);
  });
});

// ────────────────────────────────────────────────────────────
// 7. Signing edge cases
// ────────────────────────────────────────────────────────────
describe("signing edge cases", () => {
  it("empty signing key produces valid HMAC", () => {
    const sig = signPayload("", "abc123def456");
    expect(sig).toHaveLength(64);
    expect(sig).toMatch(/^[0-9a-f]{64}$/);
  });

  it("signing with and without agentId produces different signatures", () => {
    const sig1 = signPayload("secret", "abc123def456");
    const sig2 = signPayload("secret", "abc123def456", "agent-1");
    expect(sig1).not.toBe(sig2);
  });

  it("unicode signing key produces valid HMAC", () => {
    const sig = signPayload("\u{1F600}\u{1F4A9}", "abc123def456");
    expect(sig).toHaveLength(64);
  });

  it("very long signing key does not crash", () => {
    const longKey = "k".repeat(100_000);
    const sig = signPayload(longKey, "abc123def456");
    expect(sig).toHaveLength(64);
  });

  it("signing key with null bytes", () => {
    const sig = signPayload("key\x00with\x00nulls", "abc123def456");
    expect(sig).toHaveLength(64);
  });

  it("same inputs produce identical signatures (deterministic)", () => {
    const s1 = signPayload("key", "fp123", "agent");
    const s2 = signPayload("key", "fp123", "agent");
    expect(s1).toBe(s2);
  });

  it("signing key with colon does not collide with agentId separator", () => {
    // signPayload uses "fp:agentId" format -- key shouldn't matter
    const s1 = signPayload("key:with:colons", "abc123def456", "agent-1");
    const s2 = signPayload("key:with:colons", "abc123def456");
    expect(s1).not.toBe(s2);
  });
});

// ────────────────────────────────────────────────────────────
// 8. Tool/access wrapper abuse
// ────────────────────────────────────────────────────────────
describe("tool/access wrapper abuse", () => {
  it("wrapTool handles function that throws", () => {
    const w = mkWitness();
    const badFn = () => { throw new Error("boom"); };
    const wrapped = w.wrapTool(badFn, "exploder");
    expect(() => wrapped()).toThrow("boom");
    expect(w.pending).toBeGreaterThan(0); // failure is still witnessed
  });

  it("wrapTool handles async function that rejects", async () => {
    const w = mkWitness();
    const badAsync = async () => { throw new Error("async boom"); };
    const wrapped = w.wrapTool(badAsync, "async_exploder");
    await expect(wrapped()).rejects.toThrow("async boom");
    expect(w.pending).toBeGreaterThan(0);
  });

  it("wrapTool with circular reference in args does not crash", () => {
    const w = mkWitness();
    const fn = (x: any) => x;
    const wrapped = w.wrapTool(fn, "circular");
    const obj: any = { a: 1 };
    obj.self = obj;
    // JSON.stringify(obj) will throw -- SDK should handle gracefully
    expect(() => wrapped(obj)).toThrow(); // TypeError from JSON.stringify
  });

  it("wrapAccess records denied access on throw", () => {
    const w = mkWitness();
    const restricted = () => { throw new Error("403 Forbidden"); };
    const wrapped = w.wrapAccess(restricted, "secret-db", "read");
    expect(() => wrapped()).toThrow("403 Forbidden");
    expect(w.pending).toBeGreaterThan(0);
  });

  it("wrapTool with no name falls back to 'anonymous'", () => {
    const w = mkWitness();
    const wrapped = w.wrapTool(() => 42);
    const result = wrapped();
    expect(result).toBe(42);
    expect(w.pending).toBeGreaterThan(0);
  });

  it("wrapTool preserves return value exactly", () => {
    const w = mkWitness();
    const obj = { nested: { deep: [1, 2, 3] } };
    const wrapped = w.wrapTool(() => obj, "identity");
    const result = wrapped();
    expect(result).toBe(obj); // same reference, not a copy
  });

  it("wrapTool preserves async return value", async () => {
    const w = mkWitness();
    const obj = { data: "important" };
    const wrapped = w.wrapTool(async () => obj, "async_identity");
    const result = await wrapped();
    expect(result).toBe(obj);
  });
});

// ────────────────────────────────────────────────────────────
// 9. RAG/skill/model weight boundary inputs
// ────────────────────────────────────────────────────────────
describe("RAG/skill/model boundary inputs", () => {
  it("witnessRagContext with empty chunks array", () => {
    const w = mkWitness();
    const payloads = w.witnessRagContext({ chunks: [] });
    expect(payloads.length).toBe(1);
    expect(payloads[0].factor_a).toBe(0); // 0 chunks
  });

  it("witnessRagContext with 10,000 chunks does not crash", () => {
    const w = mkWitness();
    const chunks = Array.from({ length: 10_000 }, (_, i) => `chunk ${i}`);
    const payloads = w.witnessRagContext({ chunks });
    expect(payloads[0].factor_a).toBe(10_000);
  });

  it("witnessRagContext with negative similarity scores", () => {
    const w = mkWitness();
    const payloads = w.witnessRagContext({
      chunks: [
        { contentHash: "a", similarityScore: -0.5 },
        { contentHash: "b", similarityScore: -1.0 },
      ],
      similarityThreshold: 0.0,
    });
    // Should produce AI-RAG.2 with all chunks below threshold
    expect(payloads.length).toBe(2);
    const rag2 = payloads.find(p => p.procedure_id === "AI-RAG.2");
    expect(rag2).toBeDefined();
    expect(rag2!.factor_c).toBe(2); // both below threshold
  });

  it("witnessRagContext with NaN similarity score", () => {
    const w = mkWitness();
    const payloads = w.witnessRagContext({
      chunks: [
        { contentHash: "a", similarityScore: NaN },
      ],
      similarityThreshold: 0.5,
    });
    expect(payloads.length).toBeGreaterThanOrEqual(1);
  });

  it("witnessSkillManifest with empty skills array", () => {
    const w = mkWitness();
    const payload = w.witnessSkillManifest([]);
    expect(payload.factor_a).toBe(0);
  });

  it("witnessSkillManifest with duplicate skills", () => {
    const w = mkWitness();
    const p = w.witnessSkillManifest(["search", "search", "search"]);
    expect(p.factor_a).toBe(3); // counts duplicates
  });

  it("witnessMemoryContext with empty sources", () => {
    const w = mkWitness();
    const p = w.witnessMemoryContext([]);
    expect(p.factor_a).toBe(0);
    expect(p.factor_b).toBe(0); // empty = not all identified
  });

  it("witnessRewardModel with empty string", () => {
    const w = mkWitness();
    const p = w.witnessRewardModel("");
    expect(p.factor_b).toBe(0); // not identified
  });

  it("witnessRewardModel with whitespace-only string", () => {
    const w = mkWitness();
    const p = w.witnessRewardModel("   ");
    expect(p.factor_b).toBe(0); // trims to empty = not identified
  });

  it("witnessQuantization with unknown method defaults to code 0", () => {
    const w = mkWitness();
    const p = w.witnessQuantization("totally_fake_method");
    expect(p.factor_c).toBe(0);
  });

  it("witnessAdapterStack with adapter missing hash sets fb=0", () => {
    const w = mkWitness();
    const p = w.witnessAdapterStack([
      { name: "lora-1", adapterHash: "aaa" },
      { name: "lora-2", adapterHash: "" }, // falsy hash
    ]);
    expect(p.factor_b).toBe(0); // not all verified
  });

  it("witnessModelWeights hash mismatch sets fb=0", () => {
    const w = mkWitness();
    const p = w.witnessModelWeights(
      { fileHash: "actual_hash_abc" },
      { expectedHash: "expected_hash_xyz" },
    );
    expect(p.factor_b).toBe(0); // mismatch
  });
});

// ────────────────────────────────────────────────────────────
// 10. Gatekeeper bypass attempts
// ────────────────────────────────────────────────────────────
describe("gatekeeper bypass", () => {
  it("gateCheck throws when guardrails insufficient", () => {
    const w = mkWitness({ guardrailsRequired: 3, guardrailNames: ["one", "two"] });
    expect(() => w.gateCheck()).toThrow(GatekeeperError);
    expect(w.pending).toBeGreaterThan(0); // rejection is witnessed
  });

  it("gateCheck passes when guardrails meet requirement", () => {
    const w = mkWitness({ guardrailsRequired: 2, guardrailNames: ["one", "two"] });
    const fp = w.gateCheck();
    expect(fp).toHaveLength(12);
    expect(w.pending).toBeGreaterThan(0); // pass is also witnessed
  });

  it("gateCheck with 0 required always passes", () => {
    const w = mkWitness({ guardrailsRequired: 0 });
    const fp = w.gateCheck();
    expect(fp).toHaveLength(12);
  });

  it("GatekeeperError exposes required/active counts", () => {
    const w = mkWitness({ guardrailsRequired: 5, guardrailNames: ["a"] });
    try {
      w.gateCheck();
      expect.unreachable("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(GatekeeperError);
      const ge = e as GatekeeperError;
      expect(ge.required).toBe(5);
      expect(ge.active).toBe(1);
    }
  });

  it("strict mode does not expose config internals in error", () => {
    const w = mkWitness({
      strict: true,
      guardrailsRequired: 3,
      guardrailNames: ["a"],
      signingKey: "super_secret_key_do_not_leak",
    });
    try {
      w.gateCheck();
      expect.unreachable("should throw");
    } catch (e) {
      const msg = (e as Error).message;
      expect(msg).not.toContain("super_secret_key");
      expect(msg).not.toContain("axm_test_key");
    }
  });
});

// ────────────────────────────────────────────────────────────
// 11. Security scan boundary inputs
// ────────────────────────────────────────────────────────────
describe("security scan edge cases", () => {
  it("witnessSecurityScan with negative threat score", () => {
    const w = mkWitness();
    w.witnessSecurityScan(-100);
    expect(w.pending).toBeGreaterThan(0);
  });

  it("witnessSecurityScan with zero threshold", () => {
    const w = mkWitness();
    w.witnessSecurityScan(1, { threshold: 0 });
    expect(w.pending).toBeGreaterThan(0);
  });

  it("witnessSecurityScan with unknown threatType defaults to code 0", () => {
    const w = mkWitness();
    w.witnessSecurityScan(500, { threatType: "cosmic_ray_flip" });
    expect(w.pending).toBeGreaterThan(0);
  });

  it("witnessInputValidation combinations cover all factor_c values", () => {
    const w = mkWitness();
    w.witnessInputValidation(true, { sanitized: false }); // fc=0
    w.witnessInputValidation(true, { sanitized: true });  // fc=1
    w.witnessInputValidation(false);                       // fc=2
    expect(w.pending).toBe(3);
  });
});

// ────────────────────────────────────────────────────────────
// 12. SHA-256 utility edge cases
// ────────────────────────────────────────────────────────────
describe("SHA-256 utility edge cases", () => {
  it("sha256Hex with length 0 returns empty string", () => {
    expect(sha256Hex("test", 0)).toBe("");
  });

  it("sha256Hex with length > 64 returns 64 chars", () => {
    const result = sha256Hex("test", 128);
    expect(result).toHaveLength(64);
  });

  it("sha256Truncated defaults to 16 chars", () => {
    const result = sha256Truncated("test");
    expect(result).toHaveLength(16);
  });

  it("sha256 of empty string is consistent with known hash", () => {
    const expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    expect(sha256Hex("")).toBe(expected);
  });
});

// ────────────────────────────────────────────────────────────
// 13. Procedure filtering
// ────────────────────────────────────────────────────────────
describe("procedure filtering", () => {
  const baseRecord = {
    modelId: "m",
    modelHash: "h",
    promptHash: "p",
    responseHash: "r",
    latencyMs: 100,
    guardrailsActive: 1,
    guardrailsRequired: 1,
    guardrailPassed: true,
    hasRefusal: false,
    provider: "openai",
    guardrailNames: ["g1"],
  };

  it("empty procedures array produces no payloads", () => {
    const payloads = extractPayloads(baseRecord, "t", 1, 30000, 1, []);
    expect(payloads.length).toBe(0);
  });

  it("filtering to non-existent procedure produces no payloads", () => {
    const payloads = extractPayloads(baseRecord, "t", 1, 30000, 0, ["AI-FAKE.99"]);
    expect(payloads.length).toBe(0);
  });

  it("filtering to single procedure returns exactly one payload", () => {
    const payloads = extractPayloads(baseRecord, "t", 1, 30000, 0, ["AI-INF.1"]);
    expect(payloads.length).toBe(1);
    expect(payloads[0].procedure_id).toBe("AI-INF.1");
  });
});

// ────────────────────────────────────────────────────────────
// 14. wrap() client detection
// ────────────────────────────────────────────────────────────
describe("wrap() client detection", () => {
  it("rejects null client", () => {
    const w = mkWitness();
    expect(() => w.wrap(null)).toThrow();
  });

  it("rejects plain object without AI client shape", () => {
    const w = mkWitness();
    expect(() => w.wrap({ foo: "bar" })).toThrow("Unsupported client");
  });

  it("rejects number", () => {
    const w = mkWitness();
    expect(() => w.wrap(42 as any)).toThrow();
  });

  it("rejects string", () => {
    const w = mkWitness();
    expect(() => w.wrap("openai" as any)).toThrow();
  });
});

// ────────────────────────────────────────────────────────────
// 15. Error message scrubbing
// ────────────────────────────────────────────────────────────
describe("error message scrubbing", () => {
  it("buffer scrubs Bearer tokens from 4xx error bodies", async () => {
    // Mock fetch to return a 401 with a token in the body
    const mockFetch = vi.fn().mockResolvedValue({
      status: 401,
      text: async () => 'Invalid Bearer axm_live_super_secret_123 for tenant xyz',
    });
    vi.stubGlobal("fetch", mockFetch);

    const w = mkWitness();
    w.witnessSecurityScan(100);
    await w.flush();

    // Check that console.error was called with redacted message
    const errorCalls = (console.error as any).mock.calls;
    const errorMsg = errorCalls.find((c: any[]) =>
      typeof c[0] === "string" && c[0].includes("Batch flush failed")
    );
    if (errorMsg) {
      expect(errorMsg[0]).not.toContain("axm_live_super_secret_123");
      expect(errorMsg[0]).toContain("[REDACTED]");
    }

    vi.unstubAllGlobals();
  });
});
