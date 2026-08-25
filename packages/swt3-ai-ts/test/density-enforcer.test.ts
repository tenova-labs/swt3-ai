/**
 * Tests for DensityEnforcer runtime class (v0.6.6).
 *
 * Verifies rate limiting, cold start, token-based and time-based density
 * calculation, and auto-fire on flush.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { DensityEnforcer } from "../src/witness.js";
import type { DensityPolicyConfig } from "../src/types.js";
import { Witness } from "../src/index.js";

function makePolicy(overrides?: Partial<DensityPolicyConfig>): DensityPolicyConfig {
  return {
    minAnchorsPerThousandTokens: 1,
    requiredProviders: [],
    maxChainGapSeconds: 60,
    requireSigningKey: false,
    minTrustLevel: 0,
    ...overrides,
  };
}

// ── Unit tests for DensityEnforcer ─────────────────────────────────────

describe("DensityEnforcer", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-21T12:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns null during cold start (< 5 minutes)", () => {
    const e = new DensityEnforcer(makePolicy());
    for (let i = 0; i < 20; i++) e.recordAnchor("AI-INF.1");
    e.recordTokens(5000);
    // Only 0ms elapsed, cold start not met
    expect(e.evaluate()).toBeNull();
  });

  it("returns null during cold start (< 10 anchors)", () => {
    const e = new DensityEnforcer(makePolicy());
    for (let i = 0; i < 5; i++) e.recordAnchor("AI-INF.1");
    e.recordTokens(5000);
    // Advance past 5 minutes
    vi.advanceTimersByTime(6 * 60 * 1000);
    // Only 5 anchors, minimum is 10
    expect(e.evaluate()).toBeNull();
  });

  it("returns result after cold start with token-based calculation", () => {
    const e = new DensityEnforcer(makePolicy({ minAnchorsPerThousandTokens: 2 }));
    for (let i = 0; i < 15; i++) e.recordAnchor("AI-INF.1");
    e.recordTokens(5000); // 5000 tokens * 2/1000 = 10 expected
    vi.advanceTimersByTime(6 * 60 * 1000);
    const result = e.evaluate();
    expect(result).not.toBeNull();
    expect(result!.expected).toBe(10);
    expect(result!.actual).toBe(15);
    expect(result!.status).toBe("sufficient");
  });

  it("returns insufficient when actual < expected", () => {
    const e = new DensityEnforcer(makePolicy({ minAnchorsPerThousandTokens: 10 }));
    for (let i = 0; i < 12; i++) e.recordAnchor("AI-INF.1");
    e.recordTokens(10000); // 10000 tokens * 10/1000 = 100 expected
    vi.advanceTimersByTime(6 * 60 * 1000);
    const result = e.evaluate();
    expect(result).not.toBeNull();
    expect(result!.expected).toBe(100);
    expect(result!.actual).toBe(12);
    expect(result!.status).toBe("insufficient");
  });

  it("returns degraded when actual is 50-99% of expected", () => {
    const e = new DensityEnforcer(makePolicy({ minAnchorsPerThousandTokens: 2 }));
    for (let i = 0; i < 12; i++) e.recordAnchor("AI-INF.1");
    e.recordTokens(10000); // 10000 * 2/1000 = 20 expected, 12 actual = 60% = degraded
    vi.advanceTimersByTime(6 * 60 * 1000);
    const result = e.evaluate();
    expect(result).not.toBeNull();
    expect(result!.status).toBe("degraded");
  });

  it("falls back to time-based when no tokens recorded", () => {
    const e = new DensityEnforcer(makePolicy({ maxChainGapSeconds: 30 }));
    for (let i = 0; i < 15; i++) e.recordAnchor("AI-INF.1");
    // No tokens recorded, fallback to time-based
    vi.advanceTimersByTime(6 * 60 * 1000); // 360s / 30s gap = 12 expected
    const result = e.evaluate();
    expect(result).not.toBeNull();
    expect(result!.expected).toBe(12);
    expect(result!.actual).toBe(15);
    expect(result!.status).toBe("sufficient");
  });

  it("rate limits to one attestation per hour", () => {
    const e = new DensityEnforcer(makePolicy());
    // First evaluation
    for (let i = 0; i < 15; i++) e.recordAnchor("AI-INF.1");
    e.recordTokens(5000);
    vi.advanceTimersByTime(6 * 60 * 1000);
    const first = e.evaluate();
    expect(first).not.toBeNull();

    // Second attempt 30 minutes later -- should be rate-limited
    for (let i = 0; i < 15; i++) e.recordAnchor("AI-INF.1");
    e.recordTokens(5000);
    vi.advanceTimersByTime(30 * 60 * 1000);
    expect(e.evaluate()).toBeNull();

    // Third attempt 31 minutes later (total 61 min) -- should succeed
    for (let i = 0; i < 15; i++) e.recordAnchor("AI-INF.1");
    e.recordTokens(5000);
    vi.advanceTimersByTime(31 * 60 * 1000);
    const third = e.evaluate();
    expect(third).not.toBeNull();
  });

  it("resets counters after successful evaluation", () => {
    const e = new DensityEnforcer(makePolicy());
    for (let i = 0; i < 15; i++) e.recordAnchor("AI-INF.1");
    e.recordTokens(5000);
    vi.advanceTimersByTime(6 * 60 * 1000);
    const result = e.evaluate();
    expect(result!.actual).toBe(15);

    // After reset, need to accumulate again
    vi.advanceTimersByTime(61 * 60 * 1000);
    // Only 3 anchors -- below minimum 10
    for (let i = 0; i < 3; i++) e.recordAnchor("AI-INF.1");
    expect(e.evaluate()).toBeNull(); // cold start not met (< 10 anchors)
  });
});

// ── Integration: auto-fire on flush ────────────────────────────────────

describe("DensityEnforcer auto-fire on flush", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-21T12:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("does not create density enforcer without density policy", () => {
    const w = new Witness({
      endpoint: "https://test.example.com",
      apiKey: "axm_test_key",
      tenantId: "TEST_DENSITY",
      clearingLevel: 1,
    });
    // No density policy configured -- _densityEnforcer should be undefined
    expect((w as any)._densityEnforcer).toBeUndefined();
  });
});
