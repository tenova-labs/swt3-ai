/**
 * Friction tests for Groq, Together AI, DeepSeek, and Azure OpenAI adapters.
 *
 * Tests the developer experience: can someone copy an example from the docs,
 * run it, and get working attestation without reading the source code?
 *
 * Rules:
 *   1. One import, one wrap, one call -- that's the happy path
 *   2. Response is ALWAYS returned untouched (type, identity, content)
 *   3. Witness failure never breaks the user's code
 *   4. No SDK import required (duck-typed)
 *   5. Record shape is complete (all InferenceRecord fields populated)
 *   6. wrap_X() and witness.wrap() produce identical provider tags
 *   7. Detection ordering is correct across all providers
 */

import { describe, it, expect, vi } from "vitest";
import { wrapGroq } from "../src/adapters/groq.js";
import { wrapTogether } from "../src/adapters/together.js";
import { wrapDeepSeek } from "../src/adapters/deepseek.js";
import { wrapAzureOpenAI } from "../src/adapters/azure-openai.js";
import { Witness } from "../src/witness.js";
import { sha256Truncated } from "../src/fingerprint.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function mockWitness() {
  return {
    record: vi.fn(),
    flush: vi.fn().mockResolvedValue(undefined),
    _buffer: [],
    _strict: false,
    strict: false,
    gateCheck: vi.fn(),
  } as any;
}

function mockOAIResponse(model: string, content: string, finishReason = "stop") {
  return {
    choices: [{ message: { content, refusal: null }, finish_reason: finishReason }],
    usage: { prompt_tokens: 15, completion_tokens: 8 },
    model,
    system_fingerprint: "fp_abc123",
  };
}

function mockOAIClient(baseURL: string, model: string, content: string) {
  const response = mockOAIResponse(model, content);
  return {
    client: {
      baseURL,
      chat: { completions: { create: vi.fn().mockResolvedValue(response) } },
    },
    response,
  };
}

// ---------------------------------------------------------------------------
// Groq friction tests
// ---------------------------------------------------------------------------

describe("Groq developer friction", () => {
  it("one-line wrap: wrap + create in 2 lines", async () => {
    const { client } = mockOAIClient("https://api.groq.com/openai/v1", "llama-3.3-70b-versatile", "Qubits!");
    const witness = mockWitness();
    const proxy = wrapGroq(client, witness) as any;
    const result = await proxy.chat.completions.create({
      model: "llama-3.3-70b-versatile",
      messages: [{ role: "user", content: "Explain quantum computing" }],
    });
    expect(result.choices[0].message.content).toBe("Qubits!");
    expect(witness.record).toHaveBeenCalled();
  });

  it("response identity preserved", async () => {
    const { client, response } = mockOAIClient("https://api.groq.com/openai/v1", "llama-3.3-70b-versatile", "test");
    const witness = mockWitness();
    const proxy = wrapGroq(client, witness) as any;
    const result = await proxy.chat.completions.create({
      model: "llama-3.3-70b-versatile",
      messages: [{ role: "user", content: "test" }],
    });
    expect(result).toBe(response);
  });

  it("no Groq import needed: any object with chat.completions.create works", async () => {
    const fakeClient = {
      baseURL: "https://api.groq.com/openai/v1",
      chat: {
        completions: {
          create: vi.fn().mockResolvedValue(mockOAIResponse("llama-3.3-70b-versatile", "duck-typed!")),
        },
      },
    };
    const witness = mockWitness();
    const proxy = wrapGroq(fakeClient, witness) as any;
    const result = await proxy.chat.completions.create({
      model: "llama-3.3-70b-versatile",
      messages: [{ role: "user", content: "hello" }],
    });
    expect(result.choices[0].message.content).toBe("duck-typed!");
    expect(witness.record).toHaveBeenCalled();
  });

  it("record shape complete", async () => {
    const { client } = mockOAIClient("https://api.groq.com/openai/v1", "llama-3.3-70b-versatile", "output");
    const witness = mockWitness();
    const proxy = wrapGroq(client, witness) as any;
    await proxy.chat.completions.create({
      model: "llama-3.3-70b-versatile",
      messages: [
        { role: "system", content: "You are helpful." },
        { role: "user", content: "test input" },
      ],
    });
    const record = witness.record.mock.calls[0][0];
    expect(record.provider).toBe("groq");
    expect(record.modelId).toBe("llama-3.3-70b-versatile");
    expect(record.modelHash).toHaveLength(16);
    expect(record.promptHash).toHaveLength(16);
    expect(record.responseHash).toHaveLength(16);
    expect(record.systemPromptHash).toBeDefined();
    expect(record.systemPromptHash).toHaveLength(16);
    expect(record.latencyMs).toBeGreaterThanOrEqual(0);
    expect(record.inputTokens).toBe(15);
    expect(record.outputTokens).toBe(8);
    expect(record.hasRefusal).toBe(false);
  });

  it("kwargs forwarded to real client", async () => {
    const { client } = mockOAIClient("https://api.groq.com/openai/v1", "llama-3.3-70b-versatile", "test");
    const witness = mockWitness();
    const proxy = wrapGroq(client, witness) as any;
    await proxy.chat.completions.create({
      model: "llama-3.3-70b-versatile",
      messages: [{ role: "user", content: "test" }],
      temperature: 0.7,
      max_tokens: 100,
    });
    const callArgs = client.chat.completions.create.mock.calls[0][0];
    expect(callArgs.temperature).toBe(0.7);
    expect(callArgs.max_tokens).toBe(100);
  });
});

// ---------------------------------------------------------------------------
// Together AI friction tests
// ---------------------------------------------------------------------------

describe("Together AI developer friction", () => {
  it("one-line wrap", async () => {
    const { client } = mockOAIClient("https://api.together.xyz/v1", "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo", "Weights!");
    const witness = mockWitness();
    const proxy = wrapTogether(client, witness) as any;
    const result = await proxy.chat.completions.create({
      model: "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
      messages: [{ role: "user", content: "test" }],
    });
    expect(result.choices[0].message.content).toBe("Weights!");
    expect(witness.record).toHaveBeenCalled();
  });

  it("record shape complete", async () => {
    const { client } = mockOAIClient("https://api.together.xyz/v1", "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo", "output");
    const witness = mockWitness();
    const proxy = wrapTogether(client, witness) as any;
    await proxy.chat.completions.create({
      model: "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
      messages: [{ role: "user", content: "input" }],
    });
    const record = witness.record.mock.calls[0][0];
    expect(record.provider).toBe("together");
    expect(record.modelId).toBe("meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo");
    expect(record.inputTokens).toBe(15);
    expect(record.outputTokens).toBe(8);
  });

  it("slash model IDs preserved", async () => {
    const { client } = mockOAIClient("https://api.together.xyz/v1", "mistralai/Mixtral-8x7B-Instruct-v0.1", "mixed");
    const witness = mockWitness();
    const proxy = wrapTogether(client, witness) as any;
    await proxy.chat.completions.create({
      model: "mistralai/Mixtral-8x7B-Instruct-v0.1",
      messages: [{ role: "user", content: "test" }],
    });
    const record = witness.record.mock.calls[0][0];
    expect(record.modelId).toBe("mistralai/Mixtral-8x7B-Instruct-v0.1");
  });
});

// ---------------------------------------------------------------------------
// DeepSeek friction tests
// ---------------------------------------------------------------------------

describe("DeepSeek developer friction", () => {
  it("one-line wrap", async () => {
    const { client } = mockOAIClient("https://api.deepseek.com", "deepseek-chat", "Hello from DeepSeek!");
    const witness = mockWitness();
    const proxy = wrapDeepSeek(client, witness) as any;
    const result = await proxy.chat.completions.create({
      model: "deepseek-chat",
      messages: [{ role: "user", content: "Hello" }],
    });
    expect(result.choices[0].message.content).toBe("Hello from DeepSeek!");
    expect(witness.record).toHaveBeenCalled();
  });

  it("R1 thinking tokens included in response hash", async () => {
    const r1Output = "<think>Step 1: x=2</think>\n\nThe answer is 2.";
    const { client } = mockOAIClient("https://api.deepseek.com", "deepseek-reasoner", r1Output);
    const witness = mockWitness();
    const proxy = wrapDeepSeek(client, witness) as any;
    await proxy.chat.completions.create({
      model: "deepseek-reasoner",
      messages: [{ role: "user", content: "Solve x+1=3" }],
    });
    const record = witness.record.mock.calls[0][0];
    expect(record.responseHash).toBe(sha256Truncated(r1Output));
  });

  it("record shape complete", async () => {
    const { client } = mockOAIClient("https://api.deepseek.com", "deepseek-chat", "response");
    const witness = mockWitness();
    const proxy = wrapDeepSeek(client, witness) as any;
    await proxy.chat.completions.create({
      model: "deepseek-chat",
      messages: [{ role: "user", content: "test" }],
    });
    const record = witness.record.mock.calls[0][0];
    expect(record.provider).toBe("deepseek");
    expect(record.modelId).toBe("deepseek-chat");
    expect(record.modelHash).toHaveLength(16);
    expect(record.promptHash).toHaveLength(16);
    expect(record.responseHash).toHaveLength(16);
    expect(record.inputTokens).toBe(15);
    expect(record.outputTokens).toBe(8);
    expect(record.hasRefusal).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Azure OpenAI friction tests
// ---------------------------------------------------------------------------

describe("Azure OpenAI developer friction", () => {
  it("one-line wrap", async () => {
    const { client } = mockOAIClient("https://myresource.openai.azure.com", "my-gpt4o-deployment", "Azure response!");
    const witness = mockWitness();
    const proxy = wrapAzureOpenAI(client, witness) as any;
    const result = await proxy.chat.completions.create({
      model: "my-gpt4o-deployment",
      messages: [{ role: "user", content: "test" }],
    });
    expect(result.choices[0].message.content).toBe("Azure response!");
    expect(witness.record).toHaveBeenCalled();
  });

  it("deployment name preserved, not resolved", async () => {
    const { client } = mockOAIClient("https://myresource.openai.azure.com", "prod-gpt4o-east", "deployed");
    const witness = mockWitness();
    const proxy = wrapAzureOpenAI(client, witness) as any;
    await proxy.chat.completions.create({
      model: "prod-gpt4o-east",
      messages: [{ role: "user", content: "test" }],
    });
    const record = witness.record.mock.calls[0][0];
    expect(record.modelId).toBe("prod-gpt4o-east");
  });

  it("content_filter sets hasRefusal", async () => {
    const response = mockOAIResponse("my-deploy", "", "content_filter");
    const client = {
      baseURL: "https://myresource.openai.azure.com",
      chat: { completions: { create: vi.fn().mockResolvedValue(response) } },
    };
    const witness = mockWitness();
    const proxy = wrapAzureOpenAI(client, witness) as any;
    await proxy.chat.completions.create({
      model: "my-deploy",
      messages: [{ role: "user", content: "bad" }],
    });
    const record = witness.record.mock.calls[0][0];
    expect(record.hasRefusal).toBe(true);
  });

  it("record shape complete with system prompt", async () => {
    const { client } = mockOAIClient("https://myresource.openai.azure.com", "my-gpt4o-deployment", "output");
    const witness = mockWitness();
    const proxy = wrapAzureOpenAI(client, witness) as any;
    await proxy.chat.completions.create({
      model: "my-gpt4o-deployment",
      messages: [
        { role: "system", content: "You are an analyst." },
        { role: "user", content: "Summarize." },
      ],
    });
    const record = witness.record.mock.calls[0][0];
    expect(record.provider).toBe("azure-openai");
    expect(record.modelId).toBe("my-gpt4o-deployment");
    expect(record.systemPromptHash).toBeDefined();
    expect(record.systemPromptHash).toHaveLength(16);
    expect(record.inputTokens).toBe(15);
    expect(record.outputTokens).toBe(8);
    expect(record.hasRefusal).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// witness.wrap() detection ordering integration tests
// ---------------------------------------------------------------------------

describe("witness.wrap() detection ordering", () => {
  function spiedWitness() {
    const w = new Witness();
    const records: any[] = [];
    const originalRecord = w.record.bind(w);
    w.record = function (record: any, ...args: any[]) {
      records.push(record);
      return originalRecord(record, ...args);
    } as any;
    return { w, records };
  }

  it("Groq SDK client -> provider='groq'", async () => {
    const { w, records } = spiedWitness();
    const { client } = mockOAIClient("https://api.groq.com/openai/v1", "llama-3.3-70b-versatile", "test");
    Object.setPrototypeOf(client, { constructor: { name: "Groq" } });
    const proxy = w.wrap(client) as any;
    await proxy.chat.completions.create({
      model: "llama-3.3-70b-versatile",
      messages: [{ role: "user", content: "test" }],
    });
    expect(records.length).toBeGreaterThan(0);
    expect(records[records.length - 1].provider).toBe("groq");
  });

  it("Together SDK client -> provider='together'", async () => {
    const { w, records } = spiedWitness();
    const { client } = mockOAIClient("https://api.together.xyz/v1", "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo", "test");
    Object.setPrototypeOf(client, { constructor: { name: "Together" } });
    const proxy = w.wrap(client) as any;
    await proxy.chat.completions.create({
      model: "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
      messages: [{ role: "user", content: "test" }],
    });
    expect(records.length).toBeGreaterThan(0);
    expect(records[records.length - 1].provider).toBe("together");
  });

  it("OpenAI + deepseek.com URL -> provider='deepseek'", async () => {
    const { w, records } = spiedWitness();
    const { client } = mockOAIClient("https://api.deepseek.com/v1", "deepseek-chat", "test");
    Object.setPrototypeOf(client, { constructor: { name: "OpenAI" } });
    const proxy = w.wrap(client) as any;
    await proxy.chat.completions.create({
      model: "deepseek-chat",
      messages: [{ role: "user", content: "test" }],
    });
    expect(records.length).toBeGreaterThan(0);
    expect(records[records.length - 1].provider).toBe("deepseek");
  });

  it("AzureOpenAI constructor -> provider='azure-openai'", async () => {
    const { w, records } = spiedWitness();
    const { client } = mockOAIClient("https://myresource.openai.azure.com", "my-deployment", "test");
    Object.setPrototypeOf(client, { constructor: { name: "AzureOpenAI" } });
    const proxy = w.wrap(client) as any;
    await proxy.chat.completions.create({
      model: "my-deployment",
      messages: [{ role: "user", content: "test" }],
    });
    expect(records.length).toBeGreaterThan(0);
    expect(records[records.length - 1].provider).toBe("azure-openai");
  });

  it("OpenAI + azure URL -> provider='azure-openai'", async () => {
    const { w, records } = spiedWitness();
    const { client } = mockOAIClient("https://myresource.openai.azure.com/openai", "my-deployment", "test");
    Object.setPrototypeOf(client, { constructor: { name: "OpenAI" } });
    const proxy = w.wrap(client) as any;
    await proxy.chat.completions.create({
      model: "my-deployment",
      messages: [{ role: "user", content: "test" }],
    });
    expect(records.length).toBeGreaterThan(0);
    expect(records[records.length - 1].provider).toBe("azure-openai");
  });

  it("OpenAI + groq.com URL fallback -> provider='groq'", async () => {
    const { w, records } = spiedWitness();
    const { client } = mockOAIClient("https://api.groq.com/openai/v1", "llama-3.3-70b-versatile", "test");
    Object.setPrototypeOf(client, { constructor: { name: "OpenAI" } });
    const proxy = w.wrap(client) as any;
    await proxy.chat.completions.create({
      model: "llama-3.3-70b-versatile",
      messages: [{ role: "user", content: "test" }],
    });
    expect(records.length).toBeGreaterThan(0);
    expect(records[records.length - 1].provider).toBe("groq");
  });

  it("OpenAI + together.xyz URL fallback -> provider='together'", async () => {
    const { w, records } = spiedWitness();
    const { client } = mockOAIClient("https://api.together.xyz/v1", "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo", "test");
    Object.setPrototypeOf(client, { constructor: { name: "OpenAI" } });
    const proxy = w.wrap(client) as any;
    await proxy.chat.completions.create({
      model: "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
      messages: [{ role: "user", content: "test" }],
    });
    expect(records.length).toBeGreaterThan(0);
    expect(records[records.length - 1].provider).toBe("together");
  });

  it("plain OpenAI -> provider='openai' (regression)", async () => {
    const { w, records } = spiedWitness();
    const { client } = mockOAIClient("https://api.openai.com/v1", "gpt-4o", "test");
    Object.setPrototypeOf(client, { constructor: { name: "OpenAI" } });
    const proxy = w.wrap(client) as any;
    await proxy.chat.completions.create({
      model: "gpt-4o",
      messages: [{ role: "user", content: "test" }],
    });
    expect(records.length).toBeGreaterThan(0);
    expect(records[records.length - 1].provider).toBe("openai");
  });

  it("Ollama still detected (regression)", async () => {
    const { w, records } = spiedWitness();
    const { client } = mockOAIClient("http://localhost:11434/v1", "llama3.2", "test");
    Object.setPrototypeOf(client, { constructor: { name: "OpenAI" } });
    const proxy = w.wrap(client) as any;
    await proxy.chat.completions.create({
      model: "llama3.2",
      messages: [{ role: "user", content: "test" }],
    });
    expect(records.length).toBeGreaterThan(0);
    expect(records[records.length - 1].provider).toBe("ollama");
  });
});
