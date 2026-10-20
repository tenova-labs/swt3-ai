/**
 * Adapter parity tests for Mistral, Bedrock Guardrails, and Strands.
 *
 * Cross-language parity: the expected hash values here MUST match the
 * Python test file (tests/test_new_adapters.py). If a test fails here
 * but passes in Python (or vice versa), it means the adapters diverge.
 *
 * No external SDK installs required -- uses mock objects.
 */

import { describe, it, expect, vi } from "vitest";
import { sha256Truncated } from "../src/fingerprint.js";
import { wrapMistral } from "../src/adapters/mistral.js";
import { wrapBedrockGuardrails } from "../src/adapters/bedrock_guardrails.js";
import { wrapStrands } from "../src/adapters/strands.js";

// ---------------------------------------------------------------------------
// Cross-language parity constants (must match Python exactly)
// ---------------------------------------------------------------------------

const MISTRAL_PROMPT_TEXT = "You are a financial advisor.\nAnalyze this portfolio risk.";
const MISTRAL_SYSTEM_TEXT = "You are a financial advisor.";
const MISTRAL_RESPONSE_TEXT = "Based on the analysis, the portfolio has moderate risk.";
const MISTRAL_MODEL_ID = "mistral-large-2411";

const EXPECTED_MISTRAL_PROMPT_HASH = "9e6c5530135bf590";
const EXPECTED_MISTRAL_SYSTEM_HASH = "a933c605958009be";
const EXPECTED_MISTRAL_RESPONSE_HASH = "de776ac3330266ab";
const EXPECTED_MISTRAL_MODEL_HASH = "82cac7c231d55cb8";

const BEDROCK_CONTENT_TEXT = "Evaluate this user message for policy violations";
const BEDROCK_MODEL_ID = "guardrail:my-content-policy:1";

const EXPECTED_BEDROCK_PROMPT_HASH = "778b0662d1d7997f";
const EXPECTED_BEDROCK_MODEL_HASH = "8fed24ba506b00c3";
const EXPECTED_BEDROCK_NONE_HASH = "59c83661ea2d62f2";

const STRANDS_PROMPT = "What is 2+2?";
const STRANDS_RESULT = "The answer is 4.";
const STRANDS_MODEL = "us.anthropic.claude-sonnet-4-20250514";

const EXPECTED_STRANDS_PROMPT_HASH = "52cb6b5e4a038af1";
const EXPECTED_STRANDS_RESPONSE_HASH = "ae758477f843049b";
const EXPECTED_STRANDS_MODEL_HASH = "12087e2a951571ed";

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

// ---------------------------------------------------------------------------
// Hash parity: these must match Python exactly
// ---------------------------------------------------------------------------

describe("cross-language hash parity", () => {
  it("mistral prompt hash matches Python", () => {
    expect(sha256Truncated(MISTRAL_PROMPT_TEXT)).toBe(EXPECTED_MISTRAL_PROMPT_HASH);
  });
  it("mistral system hash matches Python", () => {
    expect(sha256Truncated(MISTRAL_SYSTEM_TEXT)).toBe(EXPECTED_MISTRAL_SYSTEM_HASH);
  });
  it("mistral response hash matches Python", () => {
    expect(sha256Truncated(MISTRAL_RESPONSE_TEXT)).toBe(EXPECTED_MISTRAL_RESPONSE_HASH);
  });
  it("mistral model hash matches Python", () => {
    expect(sha256Truncated(MISTRAL_MODEL_ID)).toBe(EXPECTED_MISTRAL_MODEL_HASH);
  });
  it("bedrock prompt hash matches Python", () => {
    expect(sha256Truncated(BEDROCK_CONTENT_TEXT)).toBe(EXPECTED_BEDROCK_PROMPT_HASH);
  });
  it("bedrock model hash matches Python", () => {
    expect(sha256Truncated(BEDROCK_MODEL_ID)).toBe(EXPECTED_BEDROCK_MODEL_HASH);
  });
  it("strands prompt hash matches Python", () => {
    expect(sha256Truncated(STRANDS_PROMPT)).toBe(EXPECTED_STRANDS_PROMPT_HASH);
  });
  it("strands response hash matches Python", () => {
    expect(sha256Truncated(STRANDS_RESULT)).toBe(EXPECTED_STRANDS_RESPONSE_HASH);
  });
  it("strands model hash matches Python", () => {
    expect(sha256Truncated(STRANDS_MODEL)).toBe(EXPECTED_STRANDS_MODEL_HASH);
  });
});

// ---------------------------------------------------------------------------
// Mistral adapter
// ---------------------------------------------------------------------------

describe("wrapMistral", () => {
  it("witnesses chat.complete() with correct provider and hashes", async () => {
    const response = {
      choices: [
        {
          message: { content: MISTRAL_RESPONSE_TEXT },
          finish_reason: "stop",
        },
      ],
      usage: { prompt_tokens: 10, completion_tokens: 5 },
      model: MISTRAL_MODEL_ID,
    };

    const client = {
      chat: {
        complete: vi.fn().mockResolvedValue(response),
      },
    };

    const witness = mockWitness();
    const proxy = wrapMistral(client, witness as any) as typeof client;

    const result = await proxy.chat.complete({
      model: "mistral-large-latest",
      messages: [
        { role: "system", content: MISTRAL_SYSTEM_TEXT },
        { role: "user", content: "Analyze this portfolio risk." },
      ],
    } as any);

    expect(result).toBe(response);
    expect(witness.record).toHaveBeenCalledTimes(1);

    const record = witness.record.mock.calls[0][0];
    expect(record.provider).toBe("mistral");
    expect(record.modelId).toBe(MISTRAL_MODEL_ID);
    expect(record.modelHash).toBe(EXPECTED_MISTRAL_MODEL_HASH);
    expect(record.promptHash).toBe(EXPECTED_MISTRAL_PROMPT_HASH);
    expect(record.responseHash).toBe(EXPECTED_MISTRAL_RESPONSE_HASH);
    expect(record.systemPromptHash).toBe(EXPECTED_MISTRAL_SYSTEM_HASH);
    expect(record.hasRefusal).toBe(false);
    expect(record.inputTokens).toBe(10);
    expect(record.outputTokens).toBe(5);
  });

  it("detects refusal from non-standard finish_reason", async () => {
    const response = {
      choices: [{ message: { content: "" }, finish_reason: "error" }],
      usage: null,
      model: "mistral-large-2411",
    };

    const client = { chat: { complete: vi.fn().mockResolvedValue(response) } };
    const witness = mockWitness();
    const proxy = wrapMistral(client, witness as any) as typeof client;

    await proxy.chat.complete({
      model: "mistral-large-latest",
      messages: [{ role: "user", content: "test" }],
    } as any);

    const record = witness.record.mock.calls[0][0];
    expect(record.hasRefusal).toBe(true);
  });

  it("passes through non-chat attributes", () => {
    const client = {
      chat: { complete: vi.fn() },
      models: { list: vi.fn().mockReturnValue(["model1"]) },
    };
    const witness = mockWitness();
    const proxy = wrapMistral(client, witness as any) as any;

    expect(proxy.models.list()).toEqual(["model1"]);
  });
});

// ---------------------------------------------------------------------------
// Bedrock Guardrails adapter
// ---------------------------------------------------------------------------

describe("wrapBedrockGuardrails", () => {
  it("witnesses applyGuardrail with correct provider and hashes", async () => {
    const response = {
      action: "NONE",
      assessments: [],
      outputs: [],
      usage: { topicPolicyUnits: 10, contentPolicyUnits: 5 },
    };

    const client = { applyGuardrail: vi.fn().mockResolvedValue(response) };
    const witness = mockWitness();
    const proxy = wrapBedrockGuardrails(client, witness as any) as typeof client;

    const result = await proxy.applyGuardrail({
      guardrailIdentifier: "my-content-policy",
      guardrailVersion: "1",
      source: "INPUT",
      content: [{ text: { text: BEDROCK_CONTENT_TEXT } }],
    } as any);

    expect(result).toBe(response);
    expect(witness.record).toHaveBeenCalledTimes(1);

    const record = witness.record.mock.calls[0][0];
    expect(record.provider).toBe("aws-bedrock-guardrails");
    expect(record.modelId).toBe(BEDROCK_MODEL_ID);
    expect(record.modelHash).toBe(EXPECTED_BEDROCK_MODEL_HASH);
    expect(record.promptHash).toBe(EXPECTED_BEDROCK_PROMPT_HASH);
    expect(record.responseHash).toBe(EXPECTED_BEDROCK_NONE_HASH);
    expect(record.hasRefusal).toBe(false);
    expect(record.guardrailPassed).toBe(true);
    expect(record.accessTarget).toBe("INPUT");
    expect(record.inputTokens).toBe(15);
  });

  it("detects guardrail intervention", async () => {
    const response = {
      action: "GUARDRAIL_INTERVENED",
      assessments: [],
      outputs: [],
      usage: {},
    };

    const client = { applyGuardrail: vi.fn().mockResolvedValue(response) };
    const witness = mockWitness();
    const proxy = wrapBedrockGuardrails(client, witness as any) as typeof client;

    await proxy.applyGuardrail({
      guardrailIdentifier: "policy",
      guardrailVersion: "1",
      source: "OUTPUT",
      content: [{ text: { text: "blocked content" } }],
    } as any);

    const record = witness.record.mock.calls[0][0];
    expect(record.hasRefusal).toBe(true);
    expect(record.guardrailPassed).toBe(false);
    expect(record.accessTarget).toBe("OUTPUT");
  });
});

// ---------------------------------------------------------------------------
// Strands adapter
// ---------------------------------------------------------------------------

describe("wrapStrands", () => {
  it("witnesses invoke() with correct provider and hashes", async () => {
    const agent = {
      model: STRANDS_MODEL,
      invoke: vi.fn().mockResolvedValue(STRANDS_RESULT),
    };

    const witness = mockWitness();
    const proxy = wrapStrands(agent, witness as any) as typeof agent;

    const result = await proxy.invoke(STRANDS_PROMPT);

    expect(result).toBe(STRANDS_RESULT);
    expect(witness.record).toHaveBeenCalledTimes(1);

    const record = witness.record.mock.calls[0][0];
    expect(record.provider).toBe("aws-strands");
    expect(record.modelId).toBe(STRANDS_MODEL);
    expect(record.modelHash).toBe(EXPECTED_STRANDS_MODEL_HASH);
    expect(record.promptHash).toBe(EXPECTED_STRANDS_PROMPT_HASH);
    expect(record.responseHash).toBe(EXPECTED_STRANDS_RESPONSE_HASH);
    expect(record.hasRefusal).toBe(false);
  });

  it("uses model_id override", async () => {
    const agent = {
      model: "ignored",
      invoke: vi.fn().mockResolvedValue("result"),
    };

    const witness = mockWitness();
    const proxy = wrapStrands(agent, witness as any, "custom-model") as typeof agent;
    await proxy.invoke("test");

    const record = witness.record.mock.calls[0][0];
    expect(record.modelId).toBe("custom-model");
  });

  it("passes through other attributes", () => {
    const agent = {
      name: "test-agent",
      tools: ["calculator"],
      invoke: vi.fn(),
    };

    const witness = mockWitness();
    const proxy = wrapStrands(agent, witness as any) as any;

    expect(proxy.name).toBe("test-agent");
    expect(proxy.tools).toEqual(["calculator"]);
  });
});
