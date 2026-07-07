/**
 * Tests for Microsoft Foundry adapter.
 */

import { describe, it, expect, vi } from "vitest";
import { wrapFoundry } from "../src/adapters/foundry.js";
import type { FoundryAgent } from "../src/adapters/foundry.js";

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

function mockAgent(response: unknown = { text: "Document summarized." }): FoundryAgent {
  return {
    execute: vi.fn(() => response),
    interceptToolCall: vi.fn(() => ({ tool: "search", result: "ok" })),
    name: "document-agent",
    model: "gpt-4o",
  };
}

describe("wrapFoundry", () => {
  it("wraps execute and calls witness.record", () => {
    const agent = mockAgent();
    const w = mockWitness();
    const wrapped = wrapFoundry(agent, w);

    wrapped.execute("Summarize this document");

    expect(agent.execute).toHaveBeenCalledTimes(1);
    expect(w.record).toHaveBeenCalledTimes(1);
  });

  it("preserves return value from execute", () => {
    const expected = { text: "Summary", confidence: 0.98 };
    const agent = mockAgent(expected);
    const w = mockWitness();
    const wrapped = wrapFoundry(agent, w);

    const result = wrapped.execute("Summarize Q4 earnings");

    expect(result).toBe(expected);
  });

  it("wraps interceptToolCall when present", () => {
    const agent = mockAgent();
    const w = mockWitness();
    const wrapped = wrapFoundry(agent, w);

    wrapped.interceptToolCall!("search", { query: "revenue" });

    expect(agent.interceptToolCall).toHaveBeenCalledTimes(1);
    expect(w.record).toHaveBeenCalledTimes(1);
    const record = w.record.mock.calls[0][0];
    expect(record.provider).toBe("microsoft-foundry");
  });

  it("uses explicit modelId when provided", () => {
    const agent = mockAgent();
    const w = mockWitness();
    const wrapped = wrapFoundry(agent, w, "mai-ds-1.0");

    wrapped.execute("test");

    const record = w.record.mock.calls[0][0];
    expect(record.modelId).toBe("mai-ds-1.0");
  });

  it("falls back to agent.model", () => {
    const agent = mockAgent();
    const w = mockWitness();
    const wrapped = wrapFoundry(agent, w);

    wrapped.execute("test");

    const record = w.record.mock.calls[0][0];
    expect(record.modelId).toBe("gpt-4o");
  });

  it("falls back to foundry-{name} when no model", () => {
    const agent: FoundryAgent = { execute: vi.fn(() => "ok"), name: "router" };
    const w = mockWitness();
    const wrapped = wrapFoundry(agent, w);

    wrapped.execute("test");

    const record = w.record.mock.calls[0][0];
    expect(record.modelId).toBe("foundry-router");
  });

  it("defaults to foundry-agent", () => {
    const agent: FoundryAgent = { execute: vi.fn(() => "ok") };
    const w = mockWitness();
    const wrapped = wrapFoundry(agent, w);

    wrapped.execute("test");

    const record = w.record.mock.calls[0][0];
    expect(record.modelId).toBe("foundry-agent");
  });

  it("sets provider to microsoft-foundry", () => {
    const agent = mockAgent();
    const w = mockWitness();
    const wrapped = wrapFoundry(agent, w);

    wrapped.execute("test");

    const record = w.record.mock.calls[0][0];
    expect(record.provider).toBe("microsoft-foundry");
  });

  it("measures latency", () => {
    const agent = mockAgent();
    const w = mockWitness();
    const wrapped = wrapFoundry(agent, w);

    wrapped.execute("test");

    const record = w.record.mock.calls[0][0];
    expect(record.latencyMs).toBeGreaterThanOrEqual(0);
  });

  it("hashes prompt content to 16 chars", () => {
    const agent = mockAgent();
    const w = mockWitness();
    const wrapped = wrapFoundry(agent, w);

    wrapped.execute({ text: "important data", metadata: { source: "scout" } });

    const record = w.record.mock.calls[0][0];
    expect(record.promptHash.length).toBe(16);
    expect(record.responseHash.length).toBe(16);
  });

  it("handles async execute", async () => {
    const agent: FoundryAgent = {
      execute: vi.fn(() => Promise.resolve({ text: "async response" })),
    };
    const w = mockWitness();
    const wrapped = wrapFoundry(agent, w);

    const result = await wrapped.execute("async query");

    expect(result).toEqual({ text: "async response" });
    expect(w.record).toHaveBeenCalledTimes(1);
  });

  it("does not wrap interceptToolCall when absent", () => {
    const agent: FoundryAgent = { execute: vi.fn(() => "ok") };
    const w = mockWitness();
    const wrapped = wrapFoundry(agent, w);

    expect(wrapped.interceptToolCall).toBeUndefined();
  });
});
