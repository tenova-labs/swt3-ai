/**
 * Tests for Cerebras WSE-3 adapter.
 */

import { describe, it, expect, vi } from "vitest";
import { wrapCerebrasRuntime } from "../src/adapters/cerebras.js";
import type { CerebrasRuntime } from "../src/adapters/cerebras.js";

function mockWitness() {
  return {
    record: vi.fn(),
    config: {
      clearingLevel: 1,
      tenantId: "TEST",
      guardrailNames: [],
      guardrailsRequired: 0,
      procedures: [],
    },
  } as any;
}

function mockRuntime(): CerebrasRuntime {
  return {
    launch: vi.fn(),
    memcpyD2H: vi.fn(() => Buffer.from([0xDE, 0xAD, 0xBE, 0xEF])),
    memcpyH2D: vi.fn(),
  };
}

describe("wrapCerebrasRuntime", () => {
  it("wraps launch and tracks count", () => {
    const rt = mockRuntime();
    const w = mockWitness();
    const wrapped = wrapCerebrasRuntime(rt, w, "test-wse3");

    wrapped.launch("k1");
    wrapped.launch("k2");

    expect(wrapped.launchCount).toBe(2);
    expect(rt.launch).toHaveBeenCalledTimes(2);
  });

  it("mints anchor on memcpyD2H", () => {
    const rt = mockRuntime();
    const w = mockWitness();
    const wrapped = wrapCerebrasRuntime(rt, w, "wse3-model");

    wrapped.launch("attention_kernel");
    wrapped.memcpyD2H!("output_sym", [10]);

    expect(w.record).toHaveBeenCalledTimes(1);
    const record = w.record.mock.calls[0][0];
    expect(record.modelId).toBe("wse3-model");
    expect(record.provider).toBe("cerebras-wse3");
    expect(record.promptHash.length).toBe(16);
    expect(record.hasRefusal).toBe(false);
  });

  it("preserves return value from memcpyD2H", () => {
    const expected = Buffer.from([1, 2, 3, 4]);
    const rt = mockRuntime();
    rt.memcpyD2H = vi.fn(() => expected);
    const w = mockWitness();
    const wrapped = wrapCerebrasRuntime(rt, w);

    wrapped.launch("k1");
    const result = wrapped.memcpyD2H!(["out"]);
    expect(result).toBe(expected);
  });

  it("uses default model_id cerebras-wse3", () => {
    const rt = mockRuntime();
    const w = mockWitness();
    const wrapped = wrapCerebrasRuntime(rt, w);

    wrapped.launch("k1");
    wrapped.memcpyD2H!("out");

    const record = w.record.mock.calls[0][0];
    expect(record.modelId).toBe("cerebras-wse3");
  });

  it("measures latency", async () => {
    const rt: CerebrasRuntime = {
      launch: vi.fn(() => {
        // simulate 10ms kernel
        const start = performance.now();
        while (performance.now() - start < 10) { /* spin */ }
      }),
      memcpyD2H: vi.fn(() => Buffer.from([0])),
    };
    const w = mockWitness();
    const wrapped = wrapCerebrasRuntime(rt, w);

    wrapped.launch("slow_kernel");
    wrapped.memcpyD2H!("out");

    const record = w.record.mock.calls[0][0];
    expect(record.latencyMs).toBeGreaterThanOrEqual(9);
  });

  it("works without memcpyD2H", () => {
    const rt: CerebrasRuntime = { launch: vi.fn() };
    const w = mockWitness();
    const wrapped = wrapCerebrasRuntime(rt, w);

    wrapped.launch("k1");
    expect(wrapped.launchCount).toBe(1);
    // No memcpy, no anchor
    expect(w.record).not.toHaveBeenCalled();
  });

  it("hashes buffer response", () => {
    const rt = mockRuntime();
    rt.memcpyD2H = vi.fn(() => Buffer.from("hello world"));
    const w = mockWitness();
    const wrapped = wrapCerebrasRuntime(rt, w);

    wrapped.launch("k1");
    wrapped.memcpyD2H!("out");

    const record = w.record.mock.calls[0][0];
    expect(record.responseHash.length).toBe(16); // all hashes 16 chars
  });

  it("populates guardrail defaults", () => {
    const rt = mockRuntime();
    const w = mockWitness();
    const wrapped = wrapCerebrasRuntime(rt, w);

    wrapped.launch("k1");
    wrapped.memcpyD2H!("out");

    const record = w.record.mock.calls[0][0];
    expect(record.guardrailsActive).toBe(0);
    expect(record.guardrailsRequired).toBe(0);
    expect(record.guardrailPassed).toBe(true);
    expect(record.guardrailNames).toEqual([]);
  });
});
