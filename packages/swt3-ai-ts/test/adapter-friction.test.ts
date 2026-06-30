/**
 * Friction tests for AGT and LangGraph adapters.
 *
 * Tests the developer experience: can someone copy an example from the docs,
 * run it, and get working attestation without reading the source code?
 *
 * Rules:
 *   1. One import, one wrap, one call -- that's the happy path
 *   2. Response is ALWAYS returned untouched (type, identity, content)
 *   3. Witness failure never breaks the user's code
 *   4. No framework import required (duck-typed)
 *   5. Async and streaming work without extra setup
 *   6. Environment-only config works (no code changes)
 */

import { describe, it, expect, vi } from "vitest";
import { wrapAGT } from "../src/adapters/agt.js";
import { wrapLangGraph } from "../src/adapters/langgraph.js";

function mockWitness() {
  return {
    record: vi.fn(),
    flush: vi.fn().mockResolvedValue(undefined),
    _buffer: [],
    _strict: false,
  } as any;
}

// ---------------------------------------------------------------------------
// AGT friction tests
// ---------------------------------------------------------------------------

describe("AGT developer friction", () => {
  it("one-line wrap: wrap + evaluate in 2 lines", () => {
    const engine = {
      evaluate: vi.fn().mockReturnValue({ verdict: "allow" }),
    };
    const witness = mockWitness();

    const wrapped = wrapAGT(engine as any, witness);
    const result = wrapped.evaluate("Is this prompt safe?");

    expect(result).toEqual({ verdict: "allow" });
    expect(witness.record).toHaveBeenCalled();
  });

  it("response identity preserved: exact same object comes back", () => {
    const originalResponse = { verdict: "allow", score: 0.99, metadata: { nested: true } };
    const engine = { evaluate: vi.fn().mockReturnValue(originalResponse) };
    const witness = mockWitness();

    const wrapped = wrapAGT(engine as any, witness);
    const result = wrapped.evaluate("test");

    expect(result).toBe(originalResponse);
  });

  it("no Microsoft import needed: any object with evaluate() works", () => {
    class MyCustomEngine {
      evaluate(prompt: string) {
        return { decision: "proceed" };
      }
    }
    const witness = mockWitness();

    const wrapped = wrapAGT(new MyCustomEngine() as any, witness);
    const result = wrapped.evaluate("hello");

    expect(result).toEqual({ decision: "proceed" });
    expect(witness.record).toHaveBeenCalled();
  });

  it("complex Decision BOM: extracts guardrail metadata correctly", () => {
    const decisionBom = {
      verdict: "allow",
      confidence: 0.97,
      policies_evaluated: [
        { name: "content-safety", result: "pass", latency_ms: 2 },
        { name: "pii-detection", result: "pass", latency_ms: 5 },
        { name: "prompt-injection", result: "pass", latency_ms: 1 },
      ],
      execution_trace: { request_id: "abc-123" },
    };
    const engine = { evaluate: vi.fn().mockReturnValue(decisionBom) };
    const witness = mockWitness();

    const wrapped = wrapAGT(engine as any, witness);
    const result = wrapped.evaluate("Summarize this contract");

    expect(result).toBe(decisionBom);
    const record = witness.record.mock.calls[0][0];
    expect(record.guardrailsActive).toBe(3);
    expect(record.guardrailNames).toEqual(["content-safety", "pii-detection", "prompt-injection"]);
    expect(record.guardrailPassed).toBe(true);
  });

  it("denial detected: AGT deny maps to hasRefusal=true", () => {
    const engine = {
      evaluate: vi.fn().mockReturnValue({
        verdict: "deny",
        policies_evaluated: [{ name: "pii-filter", result: "fail" }],
      }),
    };
    const witness = mockWitness();

    const wrapped = wrapAGT(engine as any, witness);
    wrapped.evaluate("Show me all SSNs");

    const record = witness.record.mock.calls[0][0];
    expect(record.hasRefusal).toBe(true);
    expect(record.guardrailPassed).toBe(false);
  });

  it("async evaluate works without extra setup", async () => {
    const engine = {
      evaluate: vi.fn().mockResolvedValue({ verdict: "allow" }),
    };
    const witness = mockWitness();

    const wrapped = wrapAGT(engine as any, witness);
    const result = await wrapped.evaluate("async prompt");

    expect(result).toEqual({ verdict: "allow" });
    expect(witness.record).toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// LangGraph friction tests
// ---------------------------------------------------------------------------

describe("LangGraph developer friction", () => {
  it("one-line wrap: wrap + invoke in 2 lines", () => {
    const graph = {
      name: "chatbot",
      invoke: vi.fn().mockReturnValue({ messages: [["assistant", "Hi!"]] }),
    };
    const witness = mockWitness();

    const wrapped = wrapLangGraph(graph, witness);
    const result = wrapped.invoke({ messages: [["user", "Hello"]] });

    expect(result).toEqual({ messages: [["assistant", "Hi!"]] });
    expect(witness.record).toHaveBeenCalled();
  });

  it("response identity preserved: state dict is the exact same object", () => {
    const originalState = { messages: [["assistant", "Hello!"]], metadata: { step: 3 } };
    const graph = { name: "test", invoke: vi.fn().mockReturnValue(originalState) };
    const witness = mockWitness();

    const wrapped = wrapLangGraph(graph, witness);
    const result = wrapped.invoke({});

    expect(result).toBe(originalState);
  });

  it("no langgraph import needed: any object with invoke() works", () => {
    class MyGraph {
      name = "custom-pipeline";
      invoke(state: Record<string, unknown>) {
        return { ...state, processed: true };
      }
    }
    const witness = mockWitness();

    const wrapped = wrapLangGraph(new MyGraph() as any, witness);
    const result = wrapped.invoke({ data: "test" }) as any;

    expect(result.processed).toBe(true);
    expect(witness.record).toHaveBeenCalled();
  });

  it("sync stream yields every chunk without buffering", () => {
    const chunks = [
      { step: "retrieve", docs: 3 },
      { step: "grade", relevant: 2 },
      { step: "generate", answer: "42" },
    ];
    const graph = {
      name: "rag-graph",
      invoke: vi.fn().mockReturnValue({}),
      stream: vi.fn().mockReturnValue(
        (function* () { yield* chunks; })(),
      ),
    };
    const witness = mockWitness();

    const wrapped = wrapLangGraph(graph, witness);
    const received: unknown[] = [];
    for (const chunk of wrapped.stream!({}) as Iterable<unknown>) {
      received.push(chunk);
    }

    expect(received).toEqual(chunks);
    expect(witness.record).toHaveBeenCalledOnce();
  });

  it("async stream yields every chunk", async () => {
    const graph = {
      name: "async-rag",
      invoke: vi.fn().mockReturnValue({}),
      stream: vi.fn().mockReturnValue(
        (async function* () {
          yield { step: "retrieve" };
          yield { step: "generate" };
        })(),
      ),
    };
    const witness = mockWitness();

    const wrapped = wrapLangGraph(graph, witness);
    const received: unknown[] = [];
    for await (const chunk of wrapped.stream!({}) as AsyncIterable<unknown>) {
      received.push(chunk);
    }

    expect(received).toHaveLength(2);
    expect(witness.record).toHaveBeenCalledOnce();
  });

  it("async invoke works without extra setup", async () => {
    const graph = {
      name: "async-graph",
      invoke: vi.fn().mockResolvedValue({ result: "async done" }),
    };
    const witness = mockWitness();

    const wrapped = wrapLangGraph(graph, witness);
    const result = await wrapped.invoke({ query: "test" });

    expect(result).toEqual({ result: "async done" });
    expect(witness.record).toHaveBeenCalled();
  });

  it("config dict passes through to real graph", () => {
    const graph = {
      name: "test",
      invoke: vi.fn().mockReturnValue({}),
    };
    const witness = mockWitness();

    const wrapped = wrapLangGraph(graph, witness);
    const config = { configurable: { thread_id: "abc" } };
    wrapped.invoke({ messages: [] }, config);

    expect(graph.invoke).toHaveBeenCalledWith({ messages: [] }, config);
  });

  it("complex nested state hashes without error", () => {
    const graph = {
      name: "complex",
      invoke: vi.fn().mockReturnValue({
        messages: [{ role: "assistant", content: "Done" }],
        documents: [{ id: 1, text: "doc1" }, { id: 2, text: "doc2" }],
        metadata: { steps: 5, model: "gpt-4o" },
      }),
    };
    const witness = mockWitness();

    const wrapped = wrapLangGraph(graph, witness);
    wrapped.invoke({ messages: [{ role: "user", content: "Search docs" }] });

    const record = witness.record.mock.calls[0][0];
    expect(record.promptHash.length).toBeGreaterThan(0);
    expect(record.responseHash.length).toBeGreaterThan(0);
  });

  it("witness records correct provider tag", () => {
    const graph = { name: "test", invoke: vi.fn().mockReturnValue({}) };
    const witness = mockWitness();

    wrapLangGraph(graph, witness).invoke({});
    wrapAGT({ evaluate: vi.fn().mockReturnValue({}) } as any, witness).evaluate("");

    expect(witness.record.mock.calls[0][0].provider).toBe("langgraph");
    expect(witness.record.mock.calls[1][0].provider).toBe("microsoft-agt");
  });
});
