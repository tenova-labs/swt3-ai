/**
 * SWT3 MCP Witness Middleware
 *
 * Zero-integration compliance witnessing for any MCP server.
 * Wraps the Transport layer to observe tool call request/response pairs
 * and mint AI-TOOL.1 witness anchors out-of-band.
 *
 * Architecture: response is already sent before witness fires.
 * Cannot block, cannot fail the tool call. Fire-and-forget by design.
 *
 * Features:
 * - Batching: buffer payloads, flush on size/interval/close
 * - Sampling: deterministic hash-based, per-tool rates, AI-SAMPLE.1 summaries
 * - Multi-tenant: resolveTenant callback per tool call
 * - Retry: in-memory bounded queue with exponential backoff
 *
 * Usage:
 *   import { withSWT3 } from "@tenova/swt3-mcp/middleware";
 *   const transport = withSWT3(new StdioServerTransport(), { apiKey: "axm_..." });
 *   await server.connect(transport);
 *   // On shutdown:
 *   await transport.flush();
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import { createHash } from "crypto";
import { mintFingerprint, timestampMs, signPayload } from "./fingerprint.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface TransportTapConfig {
  /** Axiom API endpoint. Default: https://sovereign.tenova.io */
  endpoint?: string;
  /** API key (axm_...). Demo mode if absent -- logs to stderr, no POST. */
  apiKey?: string;
  /** Tenant ID. Auto-resolved from first API response if omitted. */
  tenantId?: string;
  /** Clearing level (0=analytics, 1=standard, 2=sensitive, 3=classified). Default: 1. */
  clearingLevel?: 0 | 1 | 2 | 3;
  /** Agent identity (AI-ID.1). */
  agentId?: string;
  /** HMAC signing key for payload non-repudiation. */
  signingKey?: string;
  /** Max pending calls tracked before drop-oldest eviction. Default: 100. */
  maxBuffer?: number;
  /** Callback fired after each witness attempt (success or failure). */
  onWitness?: (receipt: TapReceipt) => void;

  // -- Batching --
  /** Flush after N payloads. Default: 10. */
  batchSize?: number;
  /** Flush interval in milliseconds. Default: 5000. */
  flushIntervalMs?: number;

  // -- Sampling --
  /** Global sampling rate 0.0-1.0. Default: 1.0 (witness all). */
  samplingRate?: number;
  /** Per-tool sampling rate overrides (key = tool name). */
  samplingRates?: Record<string, number>;

  // -- Multi-tenant --
  /** Resolve tenant per tool call. Falls back to tenantId config. */
  resolveTenant?: (toolName: string, params: Record<string, unknown>) => string | undefined;

  // -- Retry --
  /** Max retries per failed batch. Default: 3. */
  maxRetries?: number;
  /** Max payloads in retry queue. Default: 500. */
  maxRetryBuffer?: number;
}

export interface TapReceipt {
  toolName: string;
  fingerprint: string;
  latencyMs: number;
  timestamp: number;
  /** Witness POST error message. Undefined on success. Tool call was NOT affected. */
  error?: string;
}

// ---------------------------------------------------------------------------
// Duck-typed MCP Transport interface (no SDK import)
// ---------------------------------------------------------------------------

interface JSONRPCMessage {
  jsonrpc?: string;
  id?: string | number;
  method?: string;
  params?: Record<string, unknown>;
  result?: unknown;
  error?: unknown;
}

interface McpTransport {
  start(): Promise<void>;
  send(message: JSONRPCMessage, options?: unknown): Promise<void>;
  close(): Promise<void>;
  onmessage?: (message: JSONRPCMessage) => void;
  onclose?: () => void;
  onerror?: (error: Error) => void;
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

interface PendingCall {
  toolName: string;
  startMs: number;
  tenant: string;
}

interface RetryEntry {
  payloads: Record<string, unknown>[];
  attempts: number;
  retryAfterMs: number;
}

const DEFAULT_ENDPOINT = "https://sovereign.tenova.io";
const DEFAULT_MAX_BUFFER = 100;
const DEFAULT_BATCH_SIZE = 10;
const DEFAULT_FLUSH_INTERVAL_MS = 5000;
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_MAX_RETRY_BUFFER = 500;

// ---------------------------------------------------------------------------
// withSWT3 -- the witness middleware
// ---------------------------------------------------------------------------

/**
 * Wrap an MCP transport to auto-witness every tool call as an AI-TOOL.1 anchor.
 *
 * The wrapped transport observes `tools/call` JSON-RPC requests and their
 * responses. After the response is already committed (sent to the client),
 * it buffers witness payloads and flushes them in batches.
 *
 * @param transport - Any MCP-compatible transport (Stdio, SSE, HTTP, custom)
 * @param config - Optional witness configuration
 * @returns The same transport object (mutated in place) with flush() added
 */
export function withSWT3<T extends McpTransport>(
  transport: T,
  config?: TransportTapConfig,
): T & { flush(): Promise<void> } {
  const endpoint = (config?.endpoint ?? DEFAULT_ENDPOINT).replace(/\/+$/, "");
  const apiKey = config?.apiKey ?? "";
  const configTenantId = config?.tenantId ?? "DEMO_LOCAL";
  const clearingLevel = config?.clearingLevel ?? 1;
  const agentId = config?.agentId;
  const signingKey = config?.signingKey;
  const maxBuffer = config?.maxBuffer ?? DEFAULT_MAX_BUFFER;
  const onWitness = config?.onWitness;
  const batchSize = config?.batchSize ?? DEFAULT_BATCH_SIZE;
  const flushIntervalMs = config?.flushIntervalMs ?? DEFAULT_FLUSH_INTERVAL_MS;
  const globalSamplingRate = config?.samplingRate ?? 1.0;
  const samplingRates = config?.samplingRates;
  const resolveTenant = config?.resolveTenant;
  const maxRetries = config?.maxRetries ?? DEFAULT_MAX_RETRIES;
  const maxRetryBuffer = config?.maxRetryBuffer ?? DEFAULT_MAX_RETRY_BUFFER;
  const demo = !apiKey || !apiKey.startsWith("axm_") || apiKey === "axm_demo_local";

  // Auto-resolve tenant from first witness response
  let resolvedTenant = configTenantId;

  // Bounded pending-call map (FIFO eviction on overflow)
  const pending = new Map<string | number, PendingCall>();

  // Batching state
  const payloadBuffer: Record<string, unknown>[] = [];
  const receiptBuffer: TapReceipt[] = [];
  let flushing = false;

  // Sampling state
  const skipCounters = new Map<string, number>();

  // Retry state
  const retryQueue: RetryEntry[] = [];

  function evictOldest(): void {
    if (pending.size > maxBuffer) {
      const firstKey = pending.keys().next().value;
      if (firstKey !== undefined) pending.delete(firstKey);
    }
  }

  // --- Sampling ---

  function getSamplingRate(toolName: string): number {
    if (samplingRates && toolName in samplingRates) return samplingRates[toolName];
    return globalSamplingRate;
  }

  function shouldWitness(fpInput: string, toolName: string): boolean {
    const rate = getSamplingRate(toolName);
    if (rate >= 1.0) return true;
    if (rate <= 0.0) return false;
    const hash = createHash("sha256").update(fpInput, "utf-8").digest();
    const threshold = (hash[0] << 8) | hash[1];
    return threshold < Math.floor(rate * 0xffff);
  }

  // --- Wrap onmessage to capture tools/call requests ---

  const origOnMessage = transport.onmessage;

  let currentHandler = origOnMessage;

  Object.defineProperty(transport, "onmessage", {
    get() {
      return currentHandler;
    },
    set(handler: ((message: JSONRPCMessage) => void) | undefined) {
      const userHandler = handler;
      currentHandler = userHandler
        ? (message: JSONRPCMessage) => {
            captureRequest(message);
            userHandler(message);
          }
        : undefined;
    },
    configurable: true,
    enumerable: true,
  });

  if (origOnMessage) {
    transport.onmessage = origOnMessage;
  }

  function captureRequest(message: JSONRPCMessage): void {
    if (message.method === "tools/call" && message.id !== undefined) {
      const params = message.params as { name?: string } | undefined;
      const toolName = params?.name ?? "unknown";

      // Multi-tenant resolution
      let tenant = configTenantId;
      if (resolveTenant) {
        const resolved = resolveTenant(toolName, (message.params ?? {}) as Record<string, unknown>);
        if (resolved) tenant = resolved;
      }

      pending.set(message.id, { toolName, startMs: Date.now(), tenant });
      evictOldest();
    }
  }

  // --- Wrap send() to observe responses ---

  const origSend = transport.send.bind(transport);

  transport.send = async function tappedSend(
    message: JSONRPCMessage,
    options?: unknown,
  ): Promise<void> {
    // Send the response first -- tool call result is committed
    await origSend(message, options);

    // Check if this is a response to a tracked tool call
    if (message.id !== undefined && pending.has(message.id)) {
      const call = pending.get(message.id)!;
      pending.delete(message.id);

      const latencyMs = Date.now() - call.startMs;
      const isError = message.error !== undefined && message.error !== null;

      // Fire-and-forget witness (buffers, does not block)
      enqueueWitness(call.toolName, latencyMs, isError, call.tenant).catch(() => {});
    }
  };

  // --- Witness enqueue (buffer or demo log) ---

  async function enqueueWitness(
    toolName: string,
    latencyMs: number,
    isError: boolean,
    tenant: string,
  ): Promise<void> {
    const [ts, epoch] = timestampMs();
    const fpInput =
      `WITNESS:${tenant}:AI-TOOL.1` +
      `:${1}:${latencyMs}:${isError ? 0 : 1}` +
      `:${ts}`;
    const fp = mintFingerprint(tenant, "AI-TOOL.1", 1, latencyMs, isError ? 0 : 1, ts);

    const receipt: TapReceipt = {
      toolName,
      fingerprint: fp,
      latencyMs,
      timestamp: ts,
    };

    if (demo) {
      process.stderr.write(
        `swt3-mware: ${toolName} -> AI-TOOL.1 [${fp}] ${latencyMs}ms (demo)\n`,
      );
      onWitness?.(receipt);
      return;
    }

    // Sampling check (before buffer push)
    if (!shouldWitness(fpInput, toolName)) {
      skipCounters.set(toolName, (skipCounters.get(toolName) ?? 0) + 1);
      return;
    }

    const payload: Record<string, unknown> = {
      procedure_id: "AI-TOOL.1",
      factor_a: 1,
      factor_b: latencyMs,
      factor_c: isError ? 0 : 1,
      clearing_level: clearingLevel,
      anchor_fingerprint: fp,
      anchor_epoch: epoch,
      fingerprint_timestamp_ms: ts,
      ai_model_id: toolName,
      ai_context: { tool_name: toolName, latency_ms: latencyMs, provider: "mcp-witness" },
      witness_source: "mcp-witness",
      tenant_id: tenant,
    };

    if (agentId) payload.agent_id = agentId;
    if (signingKey) payload.payload_signature = signPayload(signingKey, fp, agentId);

    payloadBuffer.push(payload);
    receiptBuffer.push(receipt);

    // Check size-based flush trigger
    if (payloadBuffer.length >= batchSize) {
      await flush();
    }
  }

  // --- AI-SAMPLE.1 summaries ---

  function buildSamplingSummaries(tenant: string): Record<string, unknown>[] {
    const summaries: Record<string, unknown>[] = [];
    for (const [toolName, count] of skipCounters) {
      if (count <= 0) continue;
      const [ts, epoch] = timestampMs();
      const fp = mintFingerprint(tenant, "AI-SAMPLE.1", count, 0, 1, ts);
      summaries.push({
        procedure_id: "AI-SAMPLE.1",
        factor_a: count,
        factor_b: 0,
        factor_c: 1,
        clearing_level: clearingLevel,
        anchor_fingerprint: fp,
        anchor_epoch: epoch,
        fingerprint_timestamp_ms: ts,
        ai_model_id: toolName,
        ai_context: {
          tool_name: toolName,
          skipped_count: count,
          sampling_rate: getSamplingRate(toolName),
          provider: "mcp-witness",
        },
        witness_source: "mcp-witness",
        tenant_id: tenant,
      });
    }
    skipCounters.clear();
    return summaries;
  }

  // --- Flush (batch POST + retry) ---

  async function flush(): Promise<void> {
    if (flushing) return;
    flushing = true;

    try {
      // Retry eligible batches first
      await processRetryQueue();

      // Nothing to send
      if (payloadBuffer.length === 0) return;

      // Drain buffer
      const batch = payloadBuffer.splice(0);
      const receipts = receiptBuffer.splice(0);

      // Prepend sampling summaries
      const summaries = buildSamplingSummaries(resolvedTenant);
      if (summaries.length > 0) batch.unshift(...summaries);

      await sendBatch(batch, receipts, 0);
    } finally {
      flushing = false;
    }
  }

  async function sendBatch(
    batch: Record<string, unknown>[],
    receipts: TapReceipt[],
    attempts: number,
  ): Promise<void> {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 10_000);

      const res = await fetch(`${endpoint}/api/v1/witness/batch`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({ witnesses: batch }),
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (res.ok) {
        const body = (await res.json()) as { tenant_id?: string };
        if (body.tenant_id && resolvedTenant === "DEMO_LOCAL") {
          resolvedTenant = body.tenant_id;
        }
        // Success: fire receipts
        for (const r of receipts) onWitness?.(r);
      } else if (res.status >= 400 && res.status < 500) {
        // Client error: do not retry, fire error receipts
        const errMsg = `${res.status} ${res.statusText}`;
        for (const r of receipts) {
          r.error = errMsg;
          onWitness?.(r);
        }
      } else {
        // Server error: queue for retry
        enqueueRetry(batch, receipts, attempts, `${res.status} ${res.statusText}`);
      }
    } catch (err) {
      // Network error: queue for retry
      enqueueRetry(batch, receipts, attempts, (err as Error).message);
    }
  }

  // --- Retry queue ---

  function enqueueRetry(
    batch: Record<string, unknown>[],
    receipts: TapReceipt[],
    attempts: number,
    errorMsg: string,
  ): void {
    const nextAttempt = attempts + 1;
    if (nextAttempt >= maxRetries) {
      // Max retries exhausted: fire error receipts
      for (const r of receipts) {
        r.error = `max retries exceeded: ${errorMsg}`;
        onWitness?.(r);
      }
      return;
    }

    // Enforce bounded retry buffer (count total payloads across all entries)
    let totalPayloads = batch.length;
    for (const entry of retryQueue) totalPayloads += entry.payloads.length;

    while (totalPayloads > maxRetryBuffer && retryQueue.length > 0) {
      const evicted = retryQueue.shift()!;
      totalPayloads -= evicted.payloads.length;
    }

    // Still too many? Drop this batch
    if (totalPayloads > maxRetryBuffer) return;

    const backoffMs = 1000 * Math.pow(2, nextAttempt - 1); // 1s, 2s, 4s
    retryQueue.push({
      payloads: batch,
      attempts: nextAttempt,
      retryAfterMs: Date.now() + backoffMs,
    });
  }

  async function processRetryQueue(): Promise<void> {
    const now = Date.now();
    const eligible: RetryEntry[] = [];
    const remaining: RetryEntry[] = [];

    for (const entry of retryQueue) {
      if (entry.retryAfterMs <= now) eligible.push(entry);
      else remaining.push(entry);
    }

    retryQueue.length = 0;
    retryQueue.push(...remaining);

    for (const entry of eligible) {
      // Rebuild empty receipts for retry (original receipts already fired or will be on final failure)
      const receipts: TapReceipt[] = entry.payloads.map((p) => ({
        toolName: (p.ai_model_id as string) ?? "unknown",
        fingerprint: (p.anchor_fingerprint as string) ?? "",
        latencyMs: (p.factor_b as number) ?? 0,
        timestamp: (p.fingerprint_timestamp_ms as number) ?? Date.now(),
      }));
      await sendBatch(entry.payloads, receipts, entry.attempts);
    }
  }

  // --- Flush interval timer ---

  const flushTimer = setInterval(() => {
    flush().catch(() => {});
  }, flushIntervalMs);

  // .unref() so the timer does not prevent Node.js process exit
  if (flushTimer && typeof flushTimer === "object" && "unref" in flushTimer) {
    (flushTimer as NodeJS.Timeout).unref();
  }

  // --- Wrap close() for best-effort flush ---

  const origClose = transport.close.bind(transport);

  transport.close = async function wrappedClose(): Promise<void> {
    if (flushTimer) clearInterval(flushTimer);
    try {
      await flush();
    } catch {
      // Best-effort: do not block teardown
    }
    return origClose();
  };

  // --- Attach flush() to transport ---

  (transport as T & { flush(): Promise<void> }).flush = flush;

  return transport as T & { flush(): Promise<void> };
}
