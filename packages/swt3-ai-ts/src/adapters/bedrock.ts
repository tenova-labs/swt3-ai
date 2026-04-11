/**
 * SWT3 AI Witness SDK — AWS Bedrock Adapter (ES6 Proxy).
 *
 * Wraps the @aws-sdk/client-bedrock-runtime client so that
 * `client.send(new ConverseCommand(...))` and
 * `client.send(new InvokeModelCommand(...))` are intercepted.
 *
 * AWS Bedrock uses the Command pattern:
 *   const response = await client.send(new ConverseCommand({ modelId, messages }));
 *
 * The adapter intercepts `send()` and checks if the command is a
 * ConverseCommand or InvokeModelCommand to extract factors.
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import { sha256Truncated } from "../fingerprint.js";
import type { InferenceRecord } from "../types.js";
import type { Witness } from "../witness.js";

/**
 * Wrap a BedrockRuntimeClient with transparent witnessing.
 *
 * Usage:
 *   import { BedrockRuntimeClient, ConverseCommand } from "@aws-sdk/client-bedrock-runtime";
 *   import { Witness } from "@tenova/swt3-ai";
 *
 *   const witness = new Witness({ endpoint, apiKey, tenantId });
 *   const client = witness.wrap(new BedrockRuntimeClient({ region: "us-east-1" }));
 *
 *   const response = await client.send(new ConverseCommand({
 *     modelId: "anthropic.claude-3-5-sonnet-20241022-v2:0",
 *     messages: [{ role: "user", content: [{ text: "Hello" }] }],
 *   }));
 */
export function wrapBedrock(client: unknown, witness: Witness): unknown {
  return new Proxy(client as object, {
    get(target: object, prop: string | symbol): unknown {
      if (typeof prop === "symbol") return Reflect.get(target, prop);
      const real = Reflect.get(target, prop);

      if (prop === "send" && typeof real === "function") {
        return createSendInterceptor(real as (...args: unknown[]) => Promise<unknown>, witness, target);
      }

      return real;
    },
  });
}

function createSendInterceptor(
  realSend: (...args: unknown[]) => Promise<unknown>,
  witness: Witness,
  thisArg: object,
): (...args: unknown[]) => Promise<unknown> {
  return async function interceptedSend(...args: unknown[]): Promise<unknown> {
    const command = args[0] as Record<string, unknown> | undefined;
    if (!command) return realSend.call(thisArg, ...args);

    // Detect command type by constructor name
    const commandName = command.constructor?.name ?? "";

    if (commandName === "ConverseCommand") {
      return handleConverse(realSend, thisArg, command, witness, args);
    }

    if (commandName === "InvokeModelCommand") {
      return handleInvokeModel(realSend, thisArg, command, witness, args);
    }

    // Not a command we intercept — pass through
    return realSend.call(thisArg, ...args);
  };
}

// ── Converse Command Handler ──────────────────────────────────────

async function handleConverse(
  realSend: (...args: unknown[]) => Promise<unknown>,
  thisArg: object,
  command: Record<string, unknown>,
  witness: Witness,
  args: unknown[],
): Promise<unknown> {
  const input = (command as { input?: Record<string, unknown> }).input ?? command;
  const modelId = (input.modelId as string) ?? "unknown";
  const messages = input.messages as unknown[] ?? [];

  const promptText = extractConversePrompt(messages);
  const promptHash = sha256Truncated(promptText);

  const start = performance.now();
  const response = await realSend.call(thisArg, ...args);
  const elapsedMs = Math.round(performance.now() - start);

  const resp = response as Record<string, unknown>;
  const record = extractConverseRecord(resp, modelId, promptHash, elapsedMs);
  witness.record(record);

  return response;
}

// ── InvokeModel Command Handler ──────────────────────────────────

async function handleInvokeModel(
  realSend: (...args: unknown[]) => Promise<unknown>,
  thisArg: object,
  command: Record<string, unknown>,
  witness: Witness,
  args: unknown[],
): Promise<unknown> {
  const input = (command as { input?: Record<string, unknown> }).input ?? command;
  const modelId = (input.modelId as string) ?? "unknown";

  // Parse the body to get prompt
  let body: Record<string, unknown> = {};
  const rawBody = input.body;
  if (typeof rawBody === "string") {
    try { body = JSON.parse(rawBody); } catch { /* empty */ }
  } else if (rawBody instanceof Uint8Array) {
    try { body = JSON.parse(new TextDecoder().decode(rawBody)); } catch { /* empty */ }
  }

  const promptText = extractInvokePrompt(body, modelId);
  const promptHash = sha256Truncated(promptText);

  const start = performance.now();
  const response = await realSend.call(thisArg, ...args);
  const elapsedMs = Math.round(performance.now() - start);

  const resp = response as Record<string, unknown>;
  const record = extractInvokeRecord(resp, modelId, promptHash, elapsedMs);
  witness.record(record);

  return response;
}

// ── Prompt Extraction ─────────────────────────────────────────────

function extractConversePrompt(messages: unknown[]): string {
  const parts: string[] = [];
  for (const msg of messages) {
    const m = msg as Record<string, unknown>;
    const content = m.content;
    if (Array.isArray(content)) {
      for (const block of content) {
        const b = block as Record<string, unknown>;
        if (b.text) parts.push(b.text as string);
      }
    } else if (typeof content === "string") {
      parts.push(content);
    }
  }
  return parts.join("\n");
}

function extractInvokePrompt(body: Record<string, unknown>, modelId: string): string {
  // Anthropic on Bedrock
  const messages = body.messages as unknown[] | undefined;
  if (messages?.length) {
    const parts: string[] = [];
    for (const msg of messages) {
      const m = msg as Record<string, unknown>;
      const content = m.content;
      if (typeof content === "string") {
        parts.push(content);
      } else if (Array.isArray(content)) {
        for (const block of content) {
          const b = block as Record<string, unknown>;
          if (b.type === "text" && b.text) parts.push(b.text as string);
        }
      }
    }
    if (parts.length) return parts.join("\n");
  }

  // Amazon Titan
  if (body.inputText) return body.inputText as string;

  // Meta Llama
  if (body.prompt) return body.prompt as string;

  return JSON.stringify(body);
}

// ── Record Extraction ─────────────────────────────────────────────

function extractConverseRecord(
  response: Record<string, unknown>,
  modelId: string,
  promptHash: string,
  elapsedMs: number,
): InferenceRecord {
  let responseText = "";
  let hasRefusal = false;

  const output = response.output as Record<string, unknown> | undefined;
  const message = output?.message as Record<string, unknown> | undefined;
  const content = message?.content as Array<Record<string, unknown>> | undefined;

  if (content) {
    for (const block of content) {
      if (block.text) responseText += block.text as string;
    }
  }

  const stopReason = response.stopReason as string | undefined;
  if (stopReason === "content_filtered") hasRefusal = true;

  const usage = response.usage as Record<string, unknown> | undefined;
  const inputTokens = usage?.inputTokens as number | undefined;
  const outputTokens = usage?.outputTokens as number | undefined;

  return {
    modelId: modelId,
    modelHash: sha256Truncated(modelId),
    promptHash: promptHash,
    responseHash: sha256Truncated(responseText || ""),
    latencyMs: elapsedMs,
    inputTokens: inputTokens ?? undefined,
    outputTokens: outputTokens ?? undefined,
    hasRefusal: hasRefusal,
    provider: "bedrock",
    systemFingerprint: undefined,
    guardrailsActive: 0,
    guardrailsRequired: 0,
    guardrailPassed: true,
    guardrailNames: [],
  };
}

function extractInvokeRecord(
  response: Record<string, unknown>,
  modelId: string,
  promptHash: string,
  elapsedMs: number,
): InferenceRecord {
  let responseText = "";
  let hasRefusal = false;
  let inputTokens: number | null = null;
  let outputTokens: number | null = null;

  try {
    let body: Record<string, unknown> = {};
    const rawBody = response.body;
    if (rawBody instanceof Uint8Array) {
      body = JSON.parse(new TextDecoder().decode(rawBody));
    } else if (typeof rawBody === "string") {
      body = JSON.parse(rawBody);
    }

    // Anthropic on Bedrock
    if (body.content) {
      const content = body.content;
      if (Array.isArray(content)) {
        for (const block of content as Array<Record<string, unknown>>) {
          if (block.type === "text" && block.text) responseText += block.text as string;
        }
      } else if (typeof content === "string") {
        responseText = content;
      }
    }
    // Amazon Titan
    else if (body.results) {
      const results = body.results as Array<Record<string, unknown>>;
      if (results[0]?.outputText) responseText = results[0].outputText as string;
    }
    // Meta Llama
    else if (body.generation) {
      responseText = body.generation as string;
    }

    // Usage
    const usage = body.usage as Record<string, unknown> | undefined;
    if (usage) {
      inputTokens = (usage.input_tokens ?? usage.inputTokens ?? null) as number | null;
      outputTokens = (usage.output_tokens ?? usage.outputTokens ?? null) as number | null;
    }

    // Refusal
    const stopReason = (body.stop_reason ?? body.stopReason ?? "") as string;
    if (stopReason.toLowerCase().includes("content_filter")) hasRefusal = true;
  } catch {
    // Parse failure — still witness with what we have
  }

  return {
    modelId: modelId,
    modelHash: sha256Truncated(modelId),
    promptHash: promptHash,
    responseHash: sha256Truncated(responseText || ""),
    latencyMs: elapsedMs,
    inputTokens: inputTokens ?? undefined,
    outputTokens: outputTokens ?? undefined,
    hasRefusal: hasRefusal,
    provider: "bedrock",
    systemFingerprint: undefined,
    guardrailsActive: 0,
    guardrailsRequired: 0,
    guardrailPassed: true,
    guardrailNames: [],
  };
}
