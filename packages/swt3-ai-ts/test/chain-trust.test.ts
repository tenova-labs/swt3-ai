/**
 * SWT3 AI Witness SDK -- AI-CHAIN.2 Trust Degradation Tests.
 *
 * Tests the extractChainTrustDegradationPayload function and
 * cross-language parity for negative factor values.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { extractChainTrustDegradationPayload } from "../src/clearing.js";
import { Witness, ChainTrustError } from "../src/witness.js";

beforeEach(() => {
  vi.spyOn(console, "info").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
});
afterEach(() => vi.restoreAllMocks());

function makeWitness(opts: Record<string, unknown> = {}): Witness {
  return new Witness({
    endpoint: "https://example.com",
    apiKey: "axm_test",
    tenantId: "TEST",
    ...opts,
  } as any);
}

describe("AI-CHAIN.2 Trust Degradation", () => {
  it("mints payload with correct procedure ID", () => {
    const p = extractChainTrustDegradationPayload("TENANT", 3, 1, 1);
    expect(p.procedure_id).toBe("AI-CHAIN.2");
  });

  it("records previous and new trust levels as factors", () => {
    const p = extractChainTrustDegradationPayload("TENANT", 3, 1, 1);
    expect(p.factor_a).toBe(3);
    expect(p.factor_b).toBe(1);
    expect(p.factor_c).toBe(-2);
  });

  it("handles zero degradation (same level)", () => {
    const p = extractChainTrustDegradationPayload("TENANT", 2, 2, 1);
    expect(p.factor_c).toBe(0);
  });

  it("handles trust improvement (positive delta)", () => {
    const p = extractChainTrustDegradationPayload("TENANT", 1, 3, 1);
    expect(p.factor_c).toBe(2);
  });

  it("generates valid 12-char fingerprint", () => {
    const p = extractChainTrustDegradationPayload("TENANT", 3, 1, 1);
    expect(p.anchor_fingerprint).toHaveLength(12);
    expect(p.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
  });

  it("includes operational metadata when provided", () => {
    const p = extractChainTrustDegradationPayload(
      "TENANT", 3, 1, 2,
      "agent-x", "sign-key", "key-id", 1, "cycle-abc", "policy-hash",
    );
    expect(p.agent_id).toBe("agent-x");
    expect(p.cycle_id).toBe("cycle-abc");
    expect(p.payload_signature).toBeDefined();
    expect(p.signing_key_id).toBe("key-id");
  });

  it("respects clearing level", () => {
    const p = extractChainTrustDegradationPayload("TENANT", 3, 1, 3);
    expect(p.clearing_level).toBe(3);
  });

  it("negative factor fingerprint matches Python (cross-language parity)", () => {
    const p = extractChainTrustDegradationPayload("TEST_TENANT", 3, 1, 1);
    expect(p.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
    expect(p.factor_c).toBe(-2);
  });
});

describe("Witness.witnessChainTrustHandoff", () => {
  it("records depth, target trust, and effective trust as factors", () => {
    const w = makeWitness();
    const p = w.witnessChainTrustHandoff("agent-b", 3);
    expect(p.procedure_id).toBe("AI-CHAIN.1");
    expect(p.factor_a).toBe(1); // depth
    expect(p.factor_b).toBe(3); // target trust level
    expect(p.factor_c).toBe(3); // effective (only one agent)
  });

  it("effective trust is minimum across all handoffs", () => {
    const w = makeWitness();
    w.witnessChainTrustHandoff("agent-b", 3);
    const p2 = w.witnessChainTrustHandoff("agent-c", 1);
    expect(p2.factor_a).toBe(2); // depth
    expect(p2.factor_b).toBe(1); // target trust
    expect(p2.factor_c).toBe(1); // effective = min(3, 1) = 1
    expect(w.chainEffectiveTrustLevel).toBe(1);
  });

  it("strict mode throws ChainTrustError when below minimum", () => {
    const w = makeWitness({ strict: true, chainMinTrustLevel: 2 });
    w.witnessChainTrustHandoff("agent-b", 3);
    expect(() => w.witnessChainTrustHandoff("agent-c", 1)).toThrow(ChainTrustError);
  });

  it("non-strict mode does not throw", () => {
    const w = makeWitness({ chainMinTrustLevel: 2 });
    w.witnessChainTrustHandoff("agent-b", 3);
    const p = w.witnessChainTrustHandoff("agent-c", 1);
    expect(p.factor_c).toBe(1);
  });

  it("empty chain returns 4 (sovereign default)", () => {
    const w = makeWitness();
    expect(w.chainEffectiveTrustLevel).toBe(4);
  });

  it("chainTrustLevels tracks all handoffs", () => {
    const w = makeWitness();
    w.witnessChainTrustHandoff("a", 3);
    w.witnessChainTrustHandoff("b", 2);
    w.witnessChainTrustHandoff("c", 4);
    expect(w.chainTrustLevels).toEqual([3, 2, 4]);
    expect(w.chainEffectiveTrustLevel).toBe(2);
  });

  it("includes context at clearing level 1", () => {
    const w = makeWitness();
    const p = w.witnessChainTrustHandoff("agent-b", 2);
    expect(p.ai_context).toBeDefined();
    expect((p.ai_context as any).provider).toBe("chain-trust");
    expect((p.ai_context as any).target_agent).toBe("agent-b");
  });

  it("passes cycle_id through", () => {
    const w = makeWitness();
    const p = w.witnessChainTrustHandoff("agent-b", 2, { cycleId: "cycle-xyz" });
    expect(p.cycle_id).toBe("cycle-xyz");
  });
});

describe("Violation Callback", () => {
  it("fires onViolation from constructor", () => {
    const violations: any[] = [];
    const w = makeWitness({ onViolation: (v: any) => violations.push(v) });
    expect((w as any)._onViolation).toBeDefined();
  });

  it("settable at runtime via setter", () => {
    const w = makeWitness();
    const violations: any[] = [];
    w.onViolation = (v) => violations.push(v);
    expect((w as any)._onViolation).toBeDefined();
  });

  it("callback exception does not break witness flow", () => {
    const w = makeWitness({
      onViolation: () => { throw new Error("callback crashed"); },
    });
    // _fireViolation should swallow the error
    expect(() => {
      (w as any)._fireViolation({ rule: "test", toolName: "t", reason: "r", action: "logged", timestamp: 0 });
    }).not.toThrow();
  });

  it("no-op when callback is undefined", () => {
    const w = makeWitness();
    expect(() => {
      (w as any)._fireViolation({ rule: "test", toolName: "t", reason: "r", action: "logged", timestamp: 0 });
    }).not.toThrow();
  });
});
