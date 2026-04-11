/**
 * SWT3 AI Witness SDK — Core Witness class.
 *
 * Usage:
 *   import { Witness } from "@tenova/swt3-ai";
 *   import OpenAI from "openai";
 *
 *   const witness = new Witness({
 *     endpoint: "https://sovereign.tenova.io",
 *     apiKey: "axm_live_...",
 *     tenantId: "YOUR_TENANT_ID",
 *   });
 *
 *   const client = witness.wrap(new OpenAI()) as OpenAI;
 *   const response = await client.chat.completions.create({ ... });
 *
 *   // Graceful shutdown
 *   await witness.flush();
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import { randomUUID } from "node:crypto";
import { sha256Truncated } from "./fingerprint.js";
import { extractPayloads } from "./clearing.js";
import { WitnessBuffer } from "./buffer.js";
import { writeHandoffFiles } from "./handoff.js";
import { wrapOpenAI } from "./adapters/openai.js";
import { wrapAnthropic } from "./adapters/anthropic.js";
import { wrapBedrock } from "./adapters/bedrock.js";
import { createVercelOnFinish, type VercelOnFinishOptions } from "./adapters/vercel-ai.js";
import type { WitnessConfig, WitnessPayload, WitnessReceipt, InferenceRecord } from "./types.js";

export interface WitnessOptions {
  endpoint: string;
  apiKey: string;
  tenantId: string;
  clearingLevel?: 0 | 1 | 2 | 3;
  bufferSize?: number;
  flushInterval?: number;
  timeout?: number;
  maxRetries?: number;
  latencyThresholdMs?: number;
  guardrailsRequired?: number;
  guardrailNames?: string[];
  procedures?: string[];
  factorHandoff?: "file";
  factorHandoffPath?: string;
  agentId?: string;
  signingKey?: string;
}

export class Witness {
  private config: WitnessConfig;
  private buffer: WitnessBuffer;

  constructor(options: WitnessOptions) {
    if (!options.endpoint) throw new Error("endpoint is required");
    if (!options.apiKey) throw new Error("apiKey is required");
    if (!options.apiKey.startsWith("axm_")) throw new Error("apiKey must start with 'axm_'");
    if (!options.tenantId) throw new Error("tenantId is required");
    if (options.factorHandoff && options.factorHandoff !== "file") {
      throw new Error("factorHandoff must be 'file' (other methods planned for v0.4.0)");
    }
    if (options.factorHandoff === "file" && !options.factorHandoffPath) {
      throw new Error("factorHandoffPath is required when factorHandoff is 'file'");
    }

    this.config = {
      endpoint: options.endpoint.replace(/\/+$/, ""),
      apiKey: options.apiKey,
      tenantId: options.tenantId,
      clearingLevel: options.clearingLevel ?? 1,
      bufferSize: options.bufferSize ?? 10,
      flushInterval: options.flushInterval ?? 5.0,
      timeout: options.timeout ?? 10000,
      maxRetries: options.maxRetries ?? 3,
      latencyThresholdMs: options.latencyThresholdMs ?? 30000,
      guardrailsRequired: options.guardrailsRequired ?? 0,
      guardrailNames: options.guardrailNames ?? [],
      procedures: options.procedures,
      factorHandoff: options.factorHandoff,
      factorHandoffPath: options.factorHandoffPath,
      agentId: options.agentId,
      signingKey: options.signingKey,
    };

    this.buffer = new WitnessBuffer(this.config);
  }

  /**
   * Wrap an AI client with transparent witnessing.
   *
   * Supported: OpenAI, Anthropic
   * Returns a proxy that behaves identically to the original client.
   *
   * Usage:
   *   const client = witness.wrap(new OpenAI()) as OpenAI;
   *   const client = witness.wrap(new Anthropic()) as Anthropic;
   */
  wrap(client: unknown): unknown {
    const proto = Object.getPrototypeOf(client);
    const name = proto?.constructor?.name ?? "";
    const obj = client as Record<string, unknown>;

    // OpenAI: has client.chat.completions
    if (name === "OpenAI" || obj?.chat) {
      return wrapOpenAI(client, this);
    }

    // Anthropic: has client.messages
    if (name === "Anthropic" || (obj?.messages && !obj?.chat)) {
      return wrapAnthropic(client, this);
    }

    // AWS Bedrock: has client.send and client.config
    if (name === "BedrockRuntimeClient" || (obj?.send && (obj as Record<string, unknown>)?.config)) {
      return wrapBedrock(client, this);
    }

    throw new TypeError(
      `Unsupported client: ${name || "unknown"}. Supported: OpenAI, Anthropic, BedrockRuntimeClient.`,
    );
  }

  /**
   * Wrap a function as a witnessed tool call (AI-TOOL.1).
   *
   * Usage:
   *   const search = witness.wrapTool(searchDatabase, "search_db");
   *   const result = await search("SELECT ...");
   *
   * Each call mints an AI-TOOL.1 anchor with:
   *   factor_a = 1 (tool was called)
   *   factor_b = latency_ms
   *   factor_c = 1 if succeeded, 0 if exception raised
   */
  wrapTool<T extends (...args: any[]) => any>(fn: T, toolName?: string): T {
    const name = toolName ?? fn.name ?? "anonymous";
    const self = this;

    const wrapper = function (this: any, ...args: any[]): any {
      const callId = randomUUID().replace(/-/g, "").slice(0, 12);
      const start = performance.now();
      let succeeded = true;
      let result: any;

      const finish = () => {
        const elapsedMs = Math.round(performance.now() - start);
        const inputHash = sha256Truncated(JSON.stringify(args));
        const outputHash = sha256Truncated(succeeded ? JSON.stringify(result) : "ERROR");

        const record: InferenceRecord = {
          modelId: name,
          modelHash: sha256Truncated(name),
          promptHash: inputHash,
          responseHash: outputHash,
          latencyMs: elapsedMs,
          guardrailsActive: 0,
          guardrailsRequired: 0,
          guardrailPassed: true,
          hasRefusal: !succeeded,
          provider: "tool",
          guardrailNames: [],
          toolName: name,
          toolCallId: callId,
        };

        self.record(record);
      };

      try {
        result = fn.apply(this, args);
      } catch (err) {
        succeeded = false;
        finish();
        throw err;
      }

      // Handle async functions (Promise detection)
      if (result && typeof result.then === "function") {
        return result.then(
          (v: any) => {
            result = v;
            finish();
            return v;
          },
          (err: any) => {
            succeeded = false;
            finish();
            throw err;
          },
        );
      }

      finish();
      return result;
    };

    return wrapper as unknown as T;
  }

  /**
   * Record a witnessed inference. Extracts factors, applies clearing,
   * and enqueues payloads for background flush.
   *
   * If factorHandoff is configured, factors are written to the handoff
   * destination BEFORE clearing proceeds. If the handoff fails, the
   * payload is NOT transmitted.
   */
  record(inference: InferenceRecord): void {
    // Merge guardrail config
    if (this.config.guardrailNames.length > 0 && inference.guardrailNames.length === 0) {
      inference.guardrailNames = this.config.guardrailNames;
      inference.guardrailsActive = this.config.guardrailNames.length;
      inference.guardrailsRequired = this.config.guardrailsRequired;
    }

    const payloads = extractPayloads(
      inference,
      this.config.tenantId,
      this.config.clearingLevel,
      this.config.latencyThresholdMs,
      this.config.guardrailsRequired,
      this.config.procedures,
      this.config.agentId,
      this.config.signingKey,
    );

    // Factor handoff: write full (uncleared) data to custody destination
    // BEFORE enqueuing the cleared payload for transmission.
    // If this fails, we do NOT proceed.
    if (this.config.factorHandoff === "file" && this.config.factorHandoffPath) {
      writeHandoffFiles(payloads, inference, this.config.tenantId, this.config.factorHandoffPath);
    }

    this.buffer.enqueueMany(payloads);
  }

  /**
   * Create a Vercel AI SDK `onFinish` callback for streamText / generateText.
   *
   * Usage:
   *   const result = await streamText({
   *     model: openai("gpt-4o"),
   *     prompt: myPrompt,
   *     onFinish: witness.vercelOnFinish({ promptText: myPrompt }),
   *   });
   */
  vercelOnFinish(options?: VercelOnFinishOptions): (result: unknown) => void {
    return createVercelOnFinish(this, options) as (result: unknown) => void;
  }

  /** Force-flush all buffered payloads. */
  async flush(): Promise<WitnessReceipt[]> {
    return this.buffer.flush();
  }

  /** Stop the witness and flush remaining payloads. */
  async stop(): Promise<WitnessReceipt[]> {
    return this.buffer.stop();
  }

  /** Number of payloads waiting. */
  get pending(): number {
    return this.buffer.pending;
  }

  /** All receipts from completed flushes. */
  get receipts(): WitnessReceipt[] {
    return this.buffer.receipts;
  }
}
