/**
 * Adapter parity tests for Groq, Together AI, DeepSeek, and Azure OpenAI.
 *
 * Cross-language parity: the expected hash values here MUST match the
 * Python test file (tests/test_ecosystem_adapters.py). If a test fails
 * here but passes in Python (or vice versa), it means the adapters diverge.
 */

import { describe, it, expect, vi } from "vitest";
import { sha256Truncated } from "../src/fingerprint.js";
import { wrapGroq, isGroqClient, isGroqURL } from "../src/adapters/groq.js";
import { wrapTogether, isTogetherClient, isTogetherURL } from "../src/adapters/together.js";
import { wrapDeepSeek, isDeepSeekClient } from "../src/adapters/deepseek.js";
import { wrapAzureOpenAI, isAzureOpenAIClient } from "../src/adapters/azure-openai.js";

// ---------------------------------------------------------------------------
// Cross-language parity constants (computed from Python, verified here)
// ---------------------------------------------------------------------------

const GROQ_PROMPT = "Explain quantum computing briefly.";
const GROQ_RESPONSE = "Quantum computing uses qubits that can exist in superposition, enabling parallel computation for certain problems.";
const GROQ_MODEL = "llama-3.3-70b-versatile";
const GROQ_SYSTEM = "You are a physics tutor.";

const EXPECTED_GROQ_PROMPT_HASH = "93dbeba4c831d02f";
const EXPECTED_GROQ_RESPONSE_HASH = "02482cb21f3f0ff6";
const EXPECTED_GROQ_MODEL_HASH = "3d066009f1527f27";
const EXPECTED_GROQ_SYSTEM_HASH = "348cccd4bddf8d95";

const TOGETHER_PROMPT = "Write a haiku about open-weight models.";
const TOGETHER_RESPONSE = "Weights freely given\nTransparency lights the path\nTrust through openness";
const TOGETHER_MODEL = "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo";

const EXPECTED_TOGETHER_PROMPT_HASH = "c8a4a3842d54034f";
const EXPECTED_TOGETHER_RESPONSE_HASH = "6e98a24614ab3a54";
const EXPECTED_TOGETHER_MODEL_HASH = "0109d18002277f35";

const DEEPSEEK_PROMPT = "Solve: 2x + 3 = 7";
const DEEPSEEK_RESPONSE = "<think>Let me solve step by step.\n2x + 3 = 7\n2x = 4\nx = 2</think>\n\nThe solution is x = 2.";
const DEEPSEEK_MODEL = "deepseek-reasoner";

const EXPECTED_DEEPSEEK_PROMPT_HASH = "0559ee0f82f2427a";
const EXPECTED_DEEPSEEK_RESPONSE_HASH = "57fb4bbd3ebf6c37";
const EXPECTED_DEEPSEEK_MODEL_HASH = "2524619d26e98571";

const AZURE_PROMPT = "Summarize this quarterly report.";
const AZURE_RESPONSE = "Revenue increased 12% year-over-year driven by cloud services growth.";
const AZURE_MODEL = "my-gpt4o-deployment";
const AZURE_SYSTEM = "You are a financial analyst.";

const EXPECTED_AZURE_PROMPT_HASH = "d3817bf5fea06df4";
const EXPECTED_AZURE_RESPONSE_HASH = "f4fc2f4906791ccd";
const EXPECTED_AZURE_MODEL_HASH = "08b365b7cd032f00";
const EXPECTED_AZURE_SYSTEM_HASH = "3f85bf54e7d0287c";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function mockWitness() {
  return {
    record: vi.fn(),
    strict: false,
    gateCheck: vi.fn(),
    _strict: false,
  };
}

function mockOAIResponse(model: string, content: string) {
  return {
    choices: [{ message: { content, refusal: null }, finish_reason: "stop" }],
    usage: { prompt_tokens: 10, completion_tokens: 5 },
    model,
    system_fingerprint: null,
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
// Hash parity tests
// ---------------------------------------------------------------------------

describe("Hash parity (cross-language)", () => {
  it("groq prompt hash", () => expect(sha256Truncated(GROQ_PROMPT)).toBe(EXPECTED_GROQ_PROMPT_HASH));
  it("groq response hash", () => expect(sha256Truncated(GROQ_RESPONSE)).toBe(EXPECTED_GROQ_RESPONSE_HASH));
  it("groq model hash", () => expect(sha256Truncated(GROQ_MODEL)).toBe(EXPECTED_GROQ_MODEL_HASH));
  it("groq system hash", () => expect(sha256Truncated(GROQ_SYSTEM)).toBe(EXPECTED_GROQ_SYSTEM_HASH));
  it("together prompt hash", () => expect(sha256Truncated(TOGETHER_PROMPT)).toBe(EXPECTED_TOGETHER_PROMPT_HASH));
  it("together response hash", () => expect(sha256Truncated(TOGETHER_RESPONSE)).toBe(EXPECTED_TOGETHER_RESPONSE_HASH));
  it("together model hash", () => expect(sha256Truncated(TOGETHER_MODEL)).toBe(EXPECTED_TOGETHER_MODEL_HASH));
  it("deepseek prompt hash", () => expect(sha256Truncated(DEEPSEEK_PROMPT)).toBe(EXPECTED_DEEPSEEK_PROMPT_HASH));
  it("deepseek response hash", () => expect(sha256Truncated(DEEPSEEK_RESPONSE)).toBe(EXPECTED_DEEPSEEK_RESPONSE_HASH));
  it("deepseek model hash", () => expect(sha256Truncated(DEEPSEEK_MODEL)).toBe(EXPECTED_DEEPSEEK_MODEL_HASH));
  it("azure prompt hash", () => expect(sha256Truncated(AZURE_PROMPT)).toBe(EXPECTED_AZURE_PROMPT_HASH));
  it("azure response hash", () => expect(sha256Truncated(AZURE_RESPONSE)).toBe(EXPECTED_AZURE_RESPONSE_HASH));
  it("azure model hash", () => expect(sha256Truncated(AZURE_MODEL)).toBe(EXPECTED_AZURE_MODEL_HASH));
  it("azure system hash", () => expect(sha256Truncated(AZURE_SYSTEM)).toBe(EXPECTED_AZURE_SYSTEM_HASH));
});

// ---------------------------------------------------------------------------
// Groq adapter tests
// ---------------------------------------------------------------------------

describe("Groq adapter", () => {
  it("tags provider as groq", async () => {
    const witness = mockWitness();
    const { client } = mockOAIClient("https://api.groq.com/openai/v1", GROQ_MODEL, GROQ_RESPONSE);
    const proxy = wrapGroq(client, witness as any) as any;
    await proxy.chat.completions.create({
      model: GROQ_MODEL,
      messages: [{ role: "user", content: GROQ_PROMPT }],
    });
    expect(witness.record).toHaveBeenCalledTimes(1);
    const record = witness.record.mock.calls[0][0];
    expect(record.provider).toBe("groq");
  });

  it("preserves model_id", async () => {
    const witness = mockWitness();
    const { client } = mockOAIClient("https://api.groq.com/openai/v1", GROQ_MODEL, GROQ_RESPONSE);
    const proxy = wrapGroq(client, witness as any) as any;
    await proxy.chat.completions.create({
      model: GROQ_MODEL,
      messages: [{ role: "user", content: GROQ_PROMPT }],
    });
    const record = witness.record.mock.calls[0][0];
    expect(record.modelId).toBe(GROQ_MODEL);
  });

  it("propagates errors transparently", async () => {
    const witness = mockWitness();
    const client = {
      baseURL: "https://api.groq.com/openai/v1",
      chat: { completions: { create: vi.fn().mockRejectedValue(new Error("rate limited")) } },
    };
    const proxy = wrapGroq(client, witness as any) as any;
    await expect(proxy.chat.completions.create({ model: GROQ_MODEL, messages: [] }))
      .rejects.toThrow("rate limited");
    expect(witness.record).not.toHaveBeenCalled();
  });
});

describe("Groq detection", () => {
  it("isGroqClient: positive (Groq constructor)", () => {
    const client = Object.create({ constructor: { name: "Groq" } });
    expect(isGroqClient(client)).toBe(true);
  });

  it("isGroqClient: negative (OpenAI constructor)", () => {
    const client = Object.create({ constructor: { name: "OpenAI" } });
    expect(isGroqClient(client)).toBe(false);
  });

  it("isGroqURL: positive", () => {
    expect(isGroqURL({ baseURL: "https://api.groq.com/openai/v1" })).toBe(true);
  });

  it("isGroqURL: negative", () => {
    expect(isGroqURL({ baseURL: "https://api.openai.com/v1" })).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Together AI adapter tests
// ---------------------------------------------------------------------------

describe("Together AI adapter", () => {
  it("tags provider as together", async () => {
    const witness = mockWitness();
    const { client } = mockOAIClient("https://api.together.xyz/v1", TOGETHER_MODEL, TOGETHER_RESPONSE);
    const proxy = wrapTogether(client, witness as any) as any;
    await proxy.chat.completions.create({
      model: TOGETHER_MODEL,
      messages: [{ role: "user", content: TOGETHER_PROMPT }],
    });
    expect(witness.record).toHaveBeenCalledTimes(1);
    const record = witness.record.mock.calls[0][0];
    expect(record.provider).toBe("together");
  });

  it("propagates errors transparently", async () => {
    const witness = mockWitness();
    const client = {
      baseURL: "https://api.together.xyz/v1",
      chat: { completions: { create: vi.fn().mockRejectedValue(new Error("timeout")) } },
    };
    const proxy = wrapTogether(client, witness as any) as any;
    await expect(proxy.chat.completions.create({ model: TOGETHER_MODEL, messages: [] }))
      .rejects.toThrow("timeout");
    expect(witness.record).not.toHaveBeenCalled();
  });
});

describe("Together detection", () => {
  it("isTogetherURL: positive", () => {
    expect(isTogetherURL({ baseURL: "https://api.together.xyz/v1" })).toBe(true);
  });

  it("isTogetherURL: negative", () => {
    expect(isTogetherURL({ baseURL: "https://api.openai.com/v1" })).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DeepSeek adapter tests
// ---------------------------------------------------------------------------

describe("DeepSeek adapter", () => {
  it("tags provider as deepseek", async () => {
    const witness = mockWitness();
    const { client } = mockOAIClient("https://api.deepseek.com", DEEPSEEK_MODEL, DEEPSEEK_RESPONSE);
    const proxy = wrapDeepSeek(client, witness as any) as any;
    await proxy.chat.completions.create({
      model: DEEPSEEK_MODEL,
      messages: [{ role: "user", content: DEEPSEEK_PROMPT }],
    });
    expect(witness.record).toHaveBeenCalledTimes(1);
    const record = witness.record.mock.calls[0][0];
    expect(record.provider).toBe("deepseek");
  });

  it("hashes R1 thinking tokens in response", async () => {
    const witness = mockWitness();
    const { client } = mockOAIClient("https://api.deepseek.com", DEEPSEEK_MODEL, DEEPSEEK_RESPONSE);
    const proxy = wrapDeepSeek(client, witness as any) as any;
    await proxy.chat.completions.create({
      model: DEEPSEEK_MODEL,
      messages: [{ role: "user", content: DEEPSEEK_PROMPT }],
    });
    const record = witness.record.mock.calls[0][0];
    expect(record.responseHash).toBe(EXPECTED_DEEPSEEK_RESPONSE_HASH);
  });

  it("propagates errors transparently", async () => {
    const witness = mockWitness();
    const client = {
      baseURL: "https://api.deepseek.com",
      chat: { completions: { create: vi.fn().mockRejectedValue(new Error("invalid api key")) } },
    };
    const proxy = wrapDeepSeek(client, witness as any) as any;
    await expect(proxy.chat.completions.create({ model: DEEPSEEK_MODEL, messages: [] }))
      .rejects.toThrow("invalid api key");
    expect(witness.record).not.toHaveBeenCalled();
  });
});

describe("DeepSeek detection", () => {
  it("isDeepSeekClient: positive", () => {
    expect(isDeepSeekClient({ baseURL: "https://api.deepseek.com" })).toBe(true);
  });

  it("isDeepSeekClient: positive with /v1 path", () => {
    expect(isDeepSeekClient({ baseURL: "https://api.deepseek.com/v1" })).toBe(true);
  });

  it("isDeepSeekClient: negative", () => {
    expect(isDeepSeekClient({ baseURL: "https://api.openai.com/v1" })).toBe(false);
  });

  it("isDeepSeekClient: null", () => {
    expect(isDeepSeekClient(null)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Azure OpenAI adapter tests
// ---------------------------------------------------------------------------

describe("Azure OpenAI adapter", () => {
  it("tags provider as azure-openai", async () => {
    const witness = mockWitness();
    const { client } = mockOAIClient("https://myresource.openai.azure.com", AZURE_MODEL, AZURE_RESPONSE);
    const proxy = wrapAzureOpenAI(client, witness as any) as any;
    await proxy.chat.completions.create({
      model: AZURE_MODEL,
      messages: [
        { role: "system", content: AZURE_SYSTEM },
        { role: "user", content: AZURE_PROMPT },
      ],
    });
    expect(witness.record).toHaveBeenCalledTimes(1);
    const record = witness.record.mock.calls[0][0];
    expect(record.provider).toBe("azure-openai");
  });

  it("preserves deployment name as modelId", async () => {
    const witness = mockWitness();
    const { client } = mockOAIClient("https://myresource.openai.azure.com", AZURE_MODEL, AZURE_RESPONSE);
    const proxy = wrapAzureOpenAI(client, witness as any) as any;
    await proxy.chat.completions.create({
      model: AZURE_MODEL,
      messages: [{ role: "user", content: AZURE_PROMPT }],
    });
    const record = witness.record.mock.calls[0][0];
    expect(record.modelId).toBe(AZURE_MODEL);
  });

  it("detects content_filter refusal", async () => {
    const witness = mockWitness();
    const response = {
      choices: [{ message: { content: "", refusal: null }, finish_reason: "content_filter" }],
      usage: { prompt_tokens: 10, completion_tokens: 0 },
      model: AZURE_MODEL,
      system_fingerprint: null,
    };
    const client = {
      baseURL: "https://myresource.openai.azure.com",
      chat: { completions: { create: vi.fn().mockResolvedValue(response) } },
    };
    const proxy = wrapAzureOpenAI(client, witness as any) as any;
    await proxy.chat.completions.create({
      model: AZURE_MODEL,
      messages: [{ role: "user", content: "bad content" }],
    });
    const record = witness.record.mock.calls[0][0];
    expect(record.hasRefusal).toBe(true);
  });

  it("propagates errors transparently", async () => {
    const witness = mockWitness();
    const client = {
      baseURL: "https://myresource.openai.azure.com",
      chat: { completions: { create: vi.fn().mockRejectedValue(new Error("auth failed")) } },
    };
    const proxy = wrapAzureOpenAI(client, witness as any) as any;
    await expect(proxy.chat.completions.create({ model: AZURE_MODEL, messages: [] }))
      .rejects.toThrow("auth failed");
    expect(witness.record).not.toHaveBeenCalled();
  });
});

describe("Azure OpenAI detection", () => {
  it("isAzureOpenAIClient: positive by constructor name", () => {
    const client = Object.create({ constructor: { name: "AzureOpenAI" } });
    expect(isAzureOpenAIClient(client)).toBe(true);
  });

  it("isAzureOpenAIClient: positive by URL", () => {
    const client = Object.create({ constructor: { name: "OpenAI" } });
    client.baseURL = "https://myresource.openai.azure.com/openai";
    expect(isAzureOpenAIClient(client)).toBe(true);
  });

  it("isAzureOpenAIClient: negative (plain OpenAI)", () => {
    const client = Object.create({ constructor: { name: "OpenAI" } });
    client.baseURL = "https://api.openai.com/v1";
    expect(isAzureOpenAIClient(client)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Collision tests
// ---------------------------------------------------------------------------

describe("Collision detection", () => {
  it("plain OpenAI not detected as any specialized provider", () => {
    const client = { baseURL: "https://api.openai.com/v1" };
    expect(isDeepSeekClient(client)).toBe(false);
    expect(isAzureOpenAIClient(client)).toBe(false);
    expect(isGroqURL(client)).toBe(false);
    expect(isTogetherURL(client)).toBe(false);
  });

  it("OpenAI SDK + Groq URL -> detected as Groq", () => {
    const client = { baseURL: "https://api.groq.com/openai/v1" };
    expect(isGroqURL(client)).toBe(true);
    expect(isDeepSeekClient(client)).toBe(false);
    expect(isTogetherURL(client)).toBe(false);
  });

  it("OpenAI SDK + Together URL -> detected as Together", () => {
    const client = { baseURL: "https://api.together.xyz/v1" };
    expect(isTogetherURL(client)).toBe(true);
    expect(isGroqURL(client)).toBe(false);
    expect(isDeepSeekClient(client)).toBe(false);
  });

  it("OpenAI SDK + DeepSeek URL -> detected as DeepSeek", () => {
    const client = { baseURL: "https://api.deepseek.com/v1" };
    expect(isDeepSeekClient(client)).toBe(true);
    expect(isGroqURL(client)).toBe(false);
    expect(isTogetherURL(client)).toBe(false);
  });

  it("OpenAI SDK + Azure URL -> detected as Azure", () => {
    const client = Object.create({ constructor: { name: "OpenAI" } });
    client.baseURL = "https://myresource.openai.azure.com/openai";
    expect(isAzureOpenAIClient(client)).toBe(true);
    expect(isDeepSeekClient(client)).toBe(false);
    expect(isGroqURL(client)).toBe(false);
  });
});
