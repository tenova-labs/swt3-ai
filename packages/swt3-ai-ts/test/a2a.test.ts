/**
 * Tests for A2A (Agent-to-Agent) adapter.
 */

import { describe, it, expect, vi } from "vitest";
import { wrapA2A } from "../src/adapters/a2a.js";
import type { A2AAgent } from "../src/adapters/a2a.js";

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

function mockAgent(response: unknown = { text: "Analysis complete." }): A2AAgent {
  return {
    send: vi.fn(() => response),
    handleMessage: vi.fn(() => response),
    name: "analyst-agent",
    model: "gemini-2.0",
  };
}

describe("wrapA2A", () => {
  it("wraps send and calls witness.record", () => {
    const agent = mockAgent();
    const w = mockWitness();
    const wrapped = wrapA2A(agent, w);

    wrapped.send({ text: "Analyze this data" });

    expect(agent.send).toHaveBeenCalledTimes(1);
    expect(w.record).toHaveBeenCalledTimes(1);
  });

  it("preserves return value from send", () => {
    const expected = { text: "Result", confidence: 0.95 };
    const agent = mockAgent(expected);
    const w = mockWitness();
    const wrapped = wrapA2A(agent, w);

    const result = wrapped.send({ text: "query" });

    expect(result).toBe(expected);
  });

  it("wraps handleMessage when present", () => {
    const agent = mockAgent();
    const w = mockWitness();
    const wrapped = wrapA2A(agent, w);

    wrapped.handleMessage!({ text: "incoming" });

    expect(agent.handleMessage).toHaveBeenCalledTimes(1);
    expect(w.record).toHaveBeenCalledTimes(1);
    const record = w.record.mock.calls[0][0];
    expect(record.provider).toBe("a2a");
  });

  it("uses explicit modelId when provided", () => {
    const agent = mockAgent();
    const w = mockWitness();
    const wrapped = wrapA2A(agent, w, "custom-a2a-v2");

    wrapped.send({ text: "test" });

    const record = w.record.mock.calls[0][0];
    expect(record.modelId).toBe("custom-a2a-v2");
  });

  it("falls back to agent.model", () => {
    const agent = mockAgent();
    const w = mockWitness();
    const wrapped = wrapA2A(agent, w);

    wrapped.send({ text: "test" });

    const record = w.record.mock.calls[0][0];
    expect(record.modelId).toBe("gemini-2.0");
  });

  it("falls back to a2a-{name} when no model", () => {
    const agent: A2AAgent = { send: vi.fn(() => "ok"), name: "router" };
    const w = mockWitness();
    const wrapped = wrapA2A(agent, w);

    wrapped.send("test");

    const record = w.record.mock.calls[0][0];
    expect(record.modelId).toBe("a2a-router");
  });

  it("defaults to a2a-agent", () => {
    const agent: A2AAgent = { send: vi.fn(() => "ok") };
    const w = mockWitness();
    const wrapped = wrapA2A(agent, w);

    wrapped.send("test");

    const record = w.record.mock.calls[0][0];
    expect(record.modelId).toBe("a2a-agent");
  });

  it("sets provider to a2a", () => {
    const agent = mockAgent();
    const w = mockWitness();
    const wrapped = wrapA2A(agent, w);

    wrapped.send("test");

    const record = w.record.mock.calls[0][0];
    expect(record.provider).toBe("a2a");
  });

  it("measures latency", () => {
    const agent = mockAgent();
    const w = mockWitness();
    const wrapped = wrapA2A(agent, w);

    wrapped.send("test");

    const record = w.record.mock.calls[0][0];
    expect(record.latencyMs).toBeGreaterThanOrEqual(0);
  });

  it("hashes message content to 16 chars", () => {
    const agent = mockAgent();
    const w = mockWitness();
    const wrapped = wrapA2A(agent, w);

    wrapped.send({ text: "important data", metadata: { source: "sensor-1" } });

    const record = w.record.mock.calls[0][0];
    expect(record.promptHash.length).toBe(16);
    expect(record.responseHash.length).toBe(16);
  });

  it("handles async send", async () => {
    const agent: A2AAgent = {
      send: vi.fn(() => Promise.resolve({ text: "async response" })),
    };
    const w = mockWitness();
    const wrapped = wrapA2A(agent, w);

    const result = await wrapped.send({ text: "async query" });

    expect(result).toEqual({ text: "async response" });
    expect(w.record).toHaveBeenCalledTimes(1);
  });
});
