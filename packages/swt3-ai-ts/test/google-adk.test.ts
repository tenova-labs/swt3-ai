/**
 * Tests for Google ADK adapter.
 */

import { describe, it, expect, vi } from "vitest";
import { wrapGoogleADK } from "../src/adapters/google-adk.js";
import type { GoogleADKAgent } from "../src/adapters/google-adk.js";

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

function mockAgent(response: unknown = "The weather is sunny."): GoogleADKAgent {
  return {
    run: vi.fn(() => response),
    model: "gemini-2.0-flash",
    name: "weather-agent",
  };
}

describe("wrapGoogleADK", () => {
  it("wraps run and calls witness.record", () => {
    const agent = mockAgent();
    const w = mockWitness();
    const wrapped = wrapGoogleADK(agent, w);

    wrapped.run("What is the weather?");

    expect(agent.run).toHaveBeenCalledTimes(1);
    expect(w.record).toHaveBeenCalledTimes(1);
  });

  it("preserves return value", () => {
    const expected = { text: "It is 72F", tools: ["weather_api"] };
    const agent = mockAgent(expected);
    const w = mockWitness();
    const wrapped = wrapGoogleADK(agent, w);

    const result = wrapped.run("temperature?");

    expect(result).toBe(expected);
  });

  it("uses explicit modelId when provided", () => {
    const agent = mockAgent();
    const w = mockWitness();
    const wrapped = wrapGoogleADK(agent, w, "custom-model-v2");

    wrapped.run("test");

    const record = w.record.mock.calls[0][0];
    expect(record.modelId).toBe("custom-model-v2");
  });

  it("falls back to agent.model when no explicit modelId", () => {
    const agent = mockAgent();
    const w = mockWitness();
    const wrapped = wrapGoogleADK(agent, w);

    wrapped.run("test");

    const record = w.record.mock.calls[0][0];
    expect(record.modelId).toBe("gemini-2.0-flash");
  });

  it("falls back to agent.name when no model property", () => {
    const agent: GoogleADKAgent = {
      run: vi.fn(() => "ok"),
      name: "my-agent",
    };
    const w = mockWitness();
    const wrapped = wrapGoogleADK(agent, w);

    wrapped.run("test");

    const record = w.record.mock.calls[0][0];
    expect(record.modelId).toBe("google-adk-my-agent");
  });

  it("defaults to google-adk-agent when no model or name", () => {
    const agent: GoogleADKAgent = { run: vi.fn(() => "ok") };
    const w = mockWitness();
    const wrapped = wrapGoogleADK(agent, w);

    wrapped.run("test");

    const record = w.record.mock.calls[0][0];
    expect(record.modelId).toBe("google-adk-agent");
  });

  it("sets provider to google-adk", () => {
    const agent = mockAgent();
    const w = mockWitness();
    const wrapped = wrapGoogleADK(agent, w);

    wrapped.run("test");

    const record = w.record.mock.calls[0][0];
    expect(record.provider).toBe("google-adk");
  });

  it("measures latency", () => {
    const agent = mockAgent();
    const w = mockWitness();
    const wrapped = wrapGoogleADK(agent, w);

    wrapped.run("test");

    const record = w.record.mock.calls[0][0];
    expect(record.latencyMs).toBeGreaterThanOrEqual(0);
  });

  it("hashes prompt and response to 16 chars", () => {
    const agent = mockAgent();
    const w = mockWitness();
    const wrapped = wrapGoogleADK(agent, w);

    wrapped.run("What is AI compliance?");

    const record = w.record.mock.calls[0][0];
    expect(record.promptHash.length).toBe(16);
    expect(record.responseHash.length).toBe(16);
  });

  it("handles async run methods", async () => {
    const agent: GoogleADKAgent = {
      run: vi.fn(() => Promise.resolve("async result")),
    };
    const w = mockWitness();
    const wrapped = wrapGoogleADK(agent, w);

    const result = await wrapped.run("async test");

    expect(result).toBe("async result");
    expect(w.record).toHaveBeenCalledTimes(1);
  });
});
