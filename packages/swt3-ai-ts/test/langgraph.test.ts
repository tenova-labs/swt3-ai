import { describe, it, expect, vi } from "vitest";
import { wrapLangGraph } from "../src/adapters/langgraph.js";

function mockWitness() {
  return {
    record: vi.fn(),
    flush: vi.fn().mockResolvedValue(undefined),
    _buffer: [],
    _strict: false,
  } as any;
}

function mockGraph(overrides: Record<string, any> = {}) {
  return {
    name: "chatbot-graph",
    invoke: vi.fn().mockReturnValue({ messages: [["assistant", "Hello!"]] }),
    stream: vi.fn().mockReturnValue(
      (function* () {
        yield { messages: [["assistant", "Hel"]] };
        yield { messages: [["assistant", "Hello!"]] };
      })(),
    ),
    ...overrides,
  };
}

describe("wrapLangGraph", () => {
  it("witnesses invoke() calls", () => {
    const graph = mockGraph();
    const witness = mockWitness();
    const wrapped = wrapLangGraph(graph, witness);

    const result = wrapped.invoke({ messages: [["user", "Hi"]] });

    expect(result).toEqual({ messages: [["assistant", "Hello!"]] });
    expect(witness.record).toHaveBeenCalledOnce();
    const record = witness.record.mock.calls[0][0];
    expect(record.provider).toBe("langgraph");
    expect(record.modelId).toBe("chatbot-graph");
  });

  it("handles async invoke()", async () => {
    const graph = mockGraph({
      invoke: vi.fn().mockResolvedValue({ messages: [["assistant", "Async!"]] }),
    });
    const witness = mockWitness();
    const wrapped = wrapLangGraph(graph, witness);

    const result = await wrapped.invoke({ messages: [["user", "Hi"]] });

    expect(result).toEqual({ messages: [["assistant", "Async!"]] });
    expect(witness.record).toHaveBeenCalledOnce();
  });

  it("witnesses sync stream()", () => {
    const graph = mockGraph();
    const witness = mockWitness();
    const wrapped = wrapLangGraph(graph, witness);

    const chunks: unknown[] = [];
    for (const chunk of wrapped.stream!({ messages: [["user", "Hi"]] }) as Iterable<unknown>) {
      chunks.push(chunk);
    }

    expect(chunks).toHaveLength(2);
    expect(witness.record).toHaveBeenCalledOnce();
    const record = witness.record.mock.calls[0][0];
    expect(record.provider).toBe("langgraph");
  });

  it("witnesses async stream()", async () => {
    const graph = mockGraph({
      stream: vi.fn().mockReturnValue(
        (async function* () {
          yield { messages: [["assistant", "Hel"]] };
          yield { messages: [["assistant", "Hello!"]] };
        })(),
      ),
    });
    const witness = mockWitness();
    const wrapped = wrapLangGraph(graph, witness);

    const chunks: unknown[] = [];
    for await (const chunk of wrapped.stream!({ messages: [["user", "Hi"]] }) as AsyncIterable<unknown>) {
      chunks.push(chunk);
    }

    expect(chunks).toHaveLength(2);
    expect(witness.record).toHaveBeenCalledOnce();
    const record = witness.record.mock.calls[0][0];
    expect(record.responseHash).toBeTruthy();
  });

  it("uses explicit model ID", () => {
    const graph = mockGraph();
    const witness = mockWitness();
    const wrapped = wrapLangGraph(graph, witness, "custom-graph");

    wrapped.invoke({});

    const record = witness.record.mock.calls[0][0];
    expect(record.modelId).toBe("custom-graph");
  });

  it("falls back to langgraph-agent", () => {
    const graph = { invoke: vi.fn().mockReturnValue({}) };
    const witness = mockWitness();
    const wrapped = wrapLangGraph(graph as any, witness);

    wrapped.invoke({});

    const record = witness.record.mock.calls[0][0];
    expect(record.modelId).toBe("langgraph-agent");
  });

  it("passes through unknown attributes", () => {
    const graph = mockGraph({ customProp: "hello" });
    const witness = mockWitness();
    const wrapped = wrapLangGraph(graph, witness);

    expect((wrapped as any).customProp).toBe("hello");
  });

  it("records latency", () => {
    const graph = mockGraph();
    const witness = mockWitness();
    const wrapped = wrapLangGraph(graph, witness);

    wrapped.invoke({});

    const record = witness.record.mock.calls[0][0];
    expect(record.latencyMs).toBeGreaterThanOrEqual(0);
  });

  it("returns response untouched from invoke()", () => {
    const expected = { messages: [["assistant", "Hello!"]] };
    const graph = mockGraph({ invoke: vi.fn().mockReturnValue(expected) });
    const witness = mockWitness();
    const wrapped = wrapLangGraph(graph, witness);

    const result = wrapped.invoke({});
    expect(result).toBe(expected);
  });
});
