import { describe, it, expect, vi } from "vitest";
import { wrapAGT } from "../src/adapters/agt.js";

function mockWitness() {
  return {
    record: vi.fn(),
    flush: vi.fn().mockResolvedValue(undefined),
    _buffer: [],
    _strict: false,
  } as any;
}

function mockEngine(overrides: Record<string, any> = {}) {
  return {
    name: "test-policy",
    model: "gpt-4o",
    evaluate: vi.fn().mockReturnValue({ verdict: "allow", policies_evaluated: [] }),
    assess: vi.fn().mockReturnValue({ score: 0.95 }),
    ...overrides,
  };
}

describe("wrapAGT", () => {
  it("witnesses evaluate() calls", () => {
    const engine = mockEngine();
    const witness = mockWitness();
    const wrapped = wrapAGT(engine, witness);

    const result = wrapped.evaluate("Test prompt");

    expect(result).toEqual({ verdict: "allow", policies_evaluated: [] });
    expect(witness.record).toHaveBeenCalledOnce();
    const record = witness.record.mock.calls[0][0];
    expect(record.provider).toBe("microsoft-agt");
    expect(record.modelId).toBe("gpt-4o");
  });

  it("witnesses assess() calls", () => {
    const engine = mockEngine();
    const witness = mockWitness();
    const wrapped = wrapAGT(engine, witness);

    const result = wrapped.assess!({ agent: "fraud-detector" });

    expect(result).toEqual({ score: 0.95 });
    expect(witness.record).toHaveBeenCalledOnce();
    const record = witness.record.mock.calls[0][0];
    expect(record.provider).toBe("microsoft-agt");
  });

  it("handles async evaluate()", async () => {
    const engine = mockEngine({
      evaluate: vi.fn().mockResolvedValue({ verdict: "deny" }),
    });
    const witness = mockWitness();
    const wrapped = wrapAGT(engine, witness);

    const result = await wrapped.evaluate("async prompt");

    expect(result).toEqual({ verdict: "deny" });
    expect(witness.record).toHaveBeenCalledOnce();
  });

  it("uses explicit model ID", () => {
    const engine = mockEngine();
    const witness = mockWitness();
    const wrapped = wrapAGT(engine, witness, "custom-model");

    wrapped.evaluate("test");

    const record = witness.record.mock.calls[0][0];
    expect(record.modelId).toBe("custom-model");
  });

  it("falls back to agt-policy-engine", () => {
    const engine = { evaluate: vi.fn().mockReturnValue({}) };
    const witness = mockWitness();
    const wrapped = wrapAGT(engine as any, witness);

    wrapped.evaluate("test");

    const record = witness.record.mock.calls[0][0];
    expect(record.modelId).toBe("agt-policy-engine");
  });

  it("falls back to agt-{name}", () => {
    const engine = { name: "safety", evaluate: vi.fn().mockReturnValue({}) };
    const witness = mockWitness();
    const wrapped = wrapAGT(engine as any, witness);

    wrapped.evaluate("test");

    const record = witness.record.mock.calls[0][0];
    expect(record.modelId).toBe("agt-safety");
  });

  it("passes through unknown attributes", () => {
    const engine = mockEngine({ customProp: "hello" });
    const witness = mockWitness();
    const wrapped = wrapAGT(engine, witness);

    expect((wrapped as any).customProp).toBe("hello");
  });

  it("records latency", () => {
    const engine = mockEngine();
    const witness = mockWitness();
    const wrapped = wrapAGT(engine, witness);

    wrapped.evaluate("test");

    const record = witness.record.mock.calls[0][0];
    expect(record.latencyMs).toBeGreaterThanOrEqual(0);
  });

  it("extracts guardrail metadata from Decision BOM", () => {
    const engine = mockEngine({
      evaluate: vi.fn().mockReturnValue({
        verdict: "allow",
        policies_evaluated: [
          { name: "pii-filter", result: "pass" },
          { name: "toxicity-check", result: "pass" },
        ],
      }),
    });
    const witness = mockWitness();
    const wrapped = wrapAGT(engine, witness);

    wrapped.evaluate("test");

    const record = witness.record.mock.calls[0][0];
    expect(record.guardrailsActive).toBe(2);
    expect(record.guardrailNames).toEqual(["pii-filter", "toxicity-check"]);
    expect(record.guardrailPassed).toBe(true);
  });

  it("detects guardrail failure", () => {
    const engine = mockEngine({
      evaluate: vi.fn().mockReturnValue({
        verdict: "deny",
        policies_evaluated: [
          { name: "pii-filter", result: "fail" },
        ],
      }),
    });
    const witness = mockWitness();
    const wrapped = wrapAGT(engine, witness);

    wrapped.evaluate("test with PII");

    const record = witness.record.mock.calls[0][0];
    expect(record.guardrailPassed).toBe(false);
    expect(record.hasRefusal).toBe(true);
  });

  it("returns response untouched", () => {
    const expected = { verdict: "deny", reason: "PII detected" };
    const engine = mockEngine({
      evaluate: vi.fn().mockReturnValue(expected),
    });
    const witness = mockWitness();
    const wrapped = wrapAGT(engine, witness);

    const result = wrapped.evaluate("test");
    expect(result).toBe(expected);
  });
});
