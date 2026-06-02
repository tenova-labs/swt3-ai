/**
 * Unified adapter tests: Ollama + vLLM (TypeScript).
 *
 * No external AI SDK installs required -- uses mock objects
 * that match the OpenAI client shape.
 */

import { describe, it, expect, vi } from "vitest";
import { isOllamaClient, wrapOllama } from "../src/adapters/ollama.js";
import { wrapVllm } from "../src/adapters/vllm.js";
import { wrapOpenAI } from "../src/adapters/openai.js";

// ---------------------------------------------------------------------------
// Mock helpers
// ---------------------------------------------------------------------------

function mockWitness() {
  return {
    record: vi.fn(),
    strict: false,
    gateCheck: vi.fn(),
    _strict: false,
  };
}

function mockOpenAIResponse() {
  return {
    choices: [
      {
        message: { content: "Hello!", refusal: null },
        finish_reason: "stop",
      },
    ],
    usage: { prompt_tokens: 10, completion_tokens: 5 },
    model: "llama3.2",
    system_fingerprint: null,
  };
}

function mockOpenAIClient(baseURL: string) {
  const response = mockOpenAIResponse();
  const client = {
    baseURL,
    chat: {
      completions: {
        create: vi.fn().mockResolvedValue(response),
      },
    },
  };
  return { client, response };
}

// ---------------------------------------------------------------------------
// isOllamaClient detection
// ---------------------------------------------------------------------------

describe("isOllamaClient", () => {
  it("detects standard Ollama port", () => {
    expect(isOllamaClient({ baseURL: "http://localhost:11434/v1" })).toBe(true);
  });

  it("detects remote Ollama", () => {
    expect(isOllamaClient({ baseURL: "http://gpu-server:11434/v1" })).toBe(true);
  });

  it("rejects standard OpenAI", () => {
    expect(isOllamaClient({ baseURL: "https://api.openai.com/v1" })).toBe(false);
  });

  it("handles null client", () => {
    expect(isOllamaClient(null)).toBe(false);
  });

  it("handles missing baseURL", () => {
    expect(isOllamaClient({})).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Ollama adapter provider tagging
// ---------------------------------------------------------------------------

describe("wrapOllama", () => {
  it("tags records with provider=ollama", async () => {
    const { client } = mockOpenAIClient("http://localhost:11434/v1");
    const witness = mockWitness();
    const proxy = wrapOllama(client, witness as any) as typeof client;

    await proxy.chat.completions.create({
      model: "llama3.2",
      messages: [{ role: "user", content: "hi" }],
    } as any);

    expect(witness.record).toHaveBeenCalledTimes(1);
    const record = witness.record.mock.calls[0][0];
    expect(record.provider).toBe("ollama");
    expect(record.modelId).toBe("llama3.2");
  });

  it("records latency", async () => {
    const { client } = mockOpenAIClient("http://localhost:11434/v1");
    const witness = mockWitness();
    const proxy = wrapOllama(client, witness as any) as typeof client;

    await proxy.chat.completions.create({
      model: "llama3.2",
      messages: [{ role: "user", content: "hi" }],
    } as any);

    const record = witness.record.mock.calls[0][0];
    expect(record.latencyMs).toBeGreaterThanOrEqual(0);
  });
});

// ---------------------------------------------------------------------------
// vLLM adapter provider tagging
// ---------------------------------------------------------------------------

describe("wrapVllm", () => {
  it("tags records with provider=vllm", async () => {
    const { client } = mockOpenAIClient("http://localhost:8000/v1");
    const witness = mockWitness();
    const proxy = wrapVllm(client, witness as any) as typeof client;

    await proxy.chat.completions.create({
      model: "mistral-7b",
      messages: [{ role: "user", content: "hi" }],
    } as any);

    expect(witness.record).toHaveBeenCalledTimes(1);
    const record = witness.record.mock.calls[0][0];
    expect(record.provider).toBe("vllm");
  });

  it("extracts token usage", async () => {
    const { client } = mockOpenAIClient("http://localhost:8000/v1");
    const witness = mockWitness();
    const proxy = wrapVllm(client, witness as any) as typeof client;

    await proxy.chat.completions.create({
      model: "mistral-7b",
      messages: [{ role: "user", content: "hi" }],
    } as any);

    const record = witness.record.mock.calls[0][0];
    expect(record.inputTokens).toBe(10);
    expect(record.outputTokens).toBe(5);
  });
});

// ---------------------------------------------------------------------------
// OpenAI default provider unchanged
// ---------------------------------------------------------------------------

describe("wrapOpenAI default", () => {
  it("keeps provider=openai by default", async () => {
    const { client } = mockOpenAIClient("https://api.openai.com/v1");
    const witness = mockWitness();
    const proxy = wrapOpenAI(client, witness as any) as typeof client;

    await proxy.chat.completions.create({
      model: "gpt-4o",
      messages: [{ role: "user", content: "hi" }],
    } as any);

    const record = witness.record.mock.calls[0][0];
    expect(record.provider).toBe("openai");
  });
});

// ---------------------------------------------------------------------------
// Fingerprint parity across adapters
// ---------------------------------------------------------------------------

describe("fingerprint parity", () => {
  it("same prompt produces same hash across Ollama and vLLM", async () => {
    const messages = [{ role: "user", content: "What is 2+2?" }];

    // Ollama
    const { client: clientA } = mockOpenAIClient("http://localhost:11434/v1");
    const witnessA = mockWitness();
    const proxyA = wrapOllama(clientA, witnessA as any) as typeof clientA;
    await proxyA.chat.completions.create({ model: "llama3", messages } as any);
    const hashA = witnessA.record.mock.calls[0][0].promptHash;

    // vLLM
    const { client: clientB } = mockOpenAIClient("http://localhost:8000/v1");
    const witnessB = mockWitness();
    const proxyB = wrapVllm(clientB, witnessB as any) as typeof clientB;
    await proxyB.chat.completions.create({ model: "llama3", messages } as any);
    const hashB = witnessB.record.mock.calls[0][0].promptHash;

    expect(hashA).toBe(hashB);
    expect(hashA).toHaveLength(16);
  });
});
