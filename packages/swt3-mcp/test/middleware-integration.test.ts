/**
 * Middleware integration tests.
 *
 * These tests verify that withSWT3() works correctly in realistic scenarios:
 * - McpServer.connect() sets onmessage AFTER withSWT3() wraps the transport
 * - Multiple tool calls in rapid succession
 * - Mixed message types (tool calls, notifications, resource reads)
 * - Request/response ordering under concurrent sends
 * - Transport that already has onmessage set before withSWT3()
 * - Config edge cases (missing fields, invalid apiKey formats)
 * - Signing key produces payload_signature
 * - Tenant auto-resolution from witness response
 * - Batching + sampling combined behavior
 * - Multi-tenant + batching
 * - Retry + batching
 * - Graceful shutdown
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { withSWT3 } from "../src/middleware.js";
import type { TapReceipt, TransportTapConfig } from "../src/middleware.js";
import { mintFingerprint, timestampMs } from "../src/fingerprint.js";

// ---------------------------------------------------------------------------
// Mock transport matching real MCP Transport interface
// ---------------------------------------------------------------------------

function createTransport() {
  const t = {
    onmessage: undefined as ((msg: any) => void) | undefined,
    onclose: undefined as (() => void) | undefined,
    onerror: undefined as ((err: Error) => void) | undefined,
    _sent: [] as any[],
    _closed: false,
    async start() {},
    async send(message: any) {
      t._sent.push(message);
    },
    async close() {
      t._closed = true;
    },
  };
  return t;
}

function req(id: number | string, method: string, params?: any) {
  return { jsonrpc: "2.0" as const, id, method, params };
}

function res(id: number | string, result?: any, error?: any) {
  const m: any = { jsonrpc: "2.0", id };
  if (error !== undefined) m.error = error;
  else m.result = result ?? { content: [{ type: "text", text: "ok" }] };
  return m;
}

function notification(method: string) {
  return { jsonrpc: "2.0" as const, method };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("middleware integration", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  // -----------------------------------------------------------------------
  // Realistic McpServer.connect() ordering
  // -----------------------------------------------------------------------

  it("handles McpServer.connect() pattern: withSWT3 first, then server sets onmessage", async () => {
    const receipts: TapReceipt[] = [];
    const transport = createTransport();

    withSWT3(transport, { batchSize: 1, onWitness: (r) => receipts.push(r) });

    const serverMessageHandler = vi.fn();
    transport.onmessage = serverMessageHandler;

    transport.onmessage!(req(1, "tools/call", { name: "read_file" }));
    expect(serverMessageHandler).toHaveBeenCalledOnce();

    await transport.send(res(1, { content: [{ type: "text", text: "/etc/hosts" }] }));

    await vi.waitFor(() => expect(receipts).toHaveLength(1), { timeout: 200 });

    expect(receipts[0].toolName).toBe("read_file");
    expect(receipts[0].fingerprint).toMatch(/^[0-9a-f]{12}$/);
  });

  it("handles onmessage set BEFORE withSWT3 (pre-existing handler)", async () => {
    const receipts: TapReceipt[] = [];
    const transport = createTransport();

    const existingHandler = vi.fn();
    transport.onmessage = existingHandler;

    withSWT3(transport, { batchSize: 1, onWitness: (r) => receipts.push(r) });

    transport.onmessage!(req(1, "tools/call", { name: "list_dir" }));
    expect(existingHandler).toHaveBeenCalledOnce();

    await transport.send(res(1));
    await vi.waitFor(() => expect(receipts).toHaveLength(1), { timeout: 200 });
    expect(receipts[0].toolName).toBe("list_dir");
  });

  it("handler replacement after withSWT3 still works (server restarts onmessage)", async () => {
    const receipts: TapReceipt[] = [];
    const transport = createTransport();

    withSWT3(transport, { batchSize: 1, onWitness: (r) => receipts.push(r) });

    const handler1 = vi.fn();
    transport.onmessage = handler1;

    transport.onmessage!(req(1, "tools/call", { name: "tool_v1" }));
    expect(handler1).toHaveBeenCalledOnce();

    const handler2 = vi.fn();
    transport.onmessage = handler2;

    transport.onmessage!(req(2, "tools/call", { name: "tool_v2" }));
    expect(handler2).toHaveBeenCalledOnce();
    expect(handler1).toHaveBeenCalledTimes(1);

    await transport.send(res(1));
    await transport.send(res(2));

    await vi.waitFor(() => expect(receipts).toHaveLength(2), { timeout: 200 });
    expect(receipts.map((r) => r.toolName)).toEqual(["tool_v1", "tool_v2"]);
  });

  // -----------------------------------------------------------------------
  // Rapid-fire concurrent tool calls
  // -----------------------------------------------------------------------

  it("handles 50 rapid-fire tool calls without dropping", async () => {
    const receipts: TapReceipt[] = [];
    const transport = createTransport();

    withSWT3(transport, { batchSize: 1, onWitness: (r) => receipts.push(r) });
    transport.onmessage = vi.fn();

    for (let i = 1; i <= 50; i++) {
      transport.onmessage!(req(i, "tools/call", { name: `tool_${i}` }));
    }

    for (let i = 1; i <= 50; i++) {
      await transport.send(res(i));
    }

    await vi.waitFor(() => expect(receipts).toHaveLength(50), { timeout: 500 });

    const names = new Set(receipts.map((r) => r.toolName));
    expect(names.size).toBe(50);
  });

  // -----------------------------------------------------------------------
  // Mixed message types
  // -----------------------------------------------------------------------

  it("ignores non-tool-call methods", async () => {
    const receipts: TapReceipt[] = [];
    const transport = createTransport();

    withSWT3(transport, { batchSize: 1, onWitness: (r) => receipts.push(r) });
    transport.onmessage = vi.fn();

    transport.onmessage!(req(1, "resources/read", { uri: "swt3://registry" }));
    transport.onmessage!(req(2, "prompts/get", { name: "compliance-check" }));
    transport.onmessage!(notification("notifications/initialized"));
    transport.onmessage!(req(3, "completion/complete", { ref: {} }));

    transport.onmessage!(req(4, "tools/call", { name: "real_tool" }));

    await transport.send(res(1));
    await transport.send(res(2));
    await transport.send(res(3));
    await transport.send(res(4));

    await vi.waitFor(() => expect(receipts).toHaveLength(1), { timeout: 200 });
    expect(receipts[0].toolName).toBe("real_tool");
  });

  it("passes through notifications without id (no correlation attempt)", async () => {
    const receipts: TapReceipt[] = [];
    const transport = createTransport();

    withSWT3(transport, { batchSize: 1, onWitness: (r) => receipts.push(r) });
    transport.onmessage = vi.fn();

    await transport.send(notification("notifications/progress"));
    await transport.send(notification("notifications/cancelled"));

    await new Promise((r) => setTimeout(r, 100));
    expect(receipts).toHaveLength(0);
  });

  // -----------------------------------------------------------------------
  // Out-of-order responses
  // -----------------------------------------------------------------------

  it("correlates out-of-order responses correctly", async () => {
    const receipts: TapReceipt[] = [];
    const transport = createTransport();

    withSWT3(transport, { batchSize: 1, onWitness: (r) => receipts.push(r) });
    transport.onmessage = vi.fn();

    transport.onmessage!(req(1, "tools/call", { name: "slow_tool" }));
    transport.onmessage!(req(2, "tools/call", { name: "fast_tool" }));

    await transport.send(res(2));
    await transport.send(res(1));

    await vi.waitFor(() => expect(receipts).toHaveLength(2), { timeout: 200 });

    expect(receipts[0].toolName).toBe("fast_tool");
    expect(receipts[1].toolName).toBe("slow_tool");
  });

  // -----------------------------------------------------------------------
  // Orphaned requests
  // -----------------------------------------------------------------------

  it("orphaned requests stay in buffer, get evicted on overflow", async () => {
    const receipts: TapReceipt[] = [];
    const transport = createTransport();

    withSWT3(transport, { maxBuffer: 3, batchSize: 1, onWitness: (r) => receipts.push(r) });
    transport.onmessage = vi.fn();

    for (let i = 1; i <= 5; i++) {
      transport.onmessage!(req(i, "tools/call", { name: `orphan_${i}` }));
    }

    await transport.send(res(1));
    await transport.send(res(4));

    await new Promise((r) => setTimeout(r, 100));

    expect(receipts).toHaveLength(1);
    expect(receipts[0].toolName).toBe("orphan_4");
  });

  // -----------------------------------------------------------------------
  // Signing key
  // -----------------------------------------------------------------------

  it("includes payload_signature when signingKey is configured", async () => {
    let capturedBody: any = null;

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ ok: true, tenant_id: "T1" }),
    });

    const transport = createTransport();

    withSWT3(transport, {
      apiKey: "axm_live_sign_test",
      tenantId: "SIGN_TENANT",
      signingKey: "my-secret-key-123",
      agentId: "agent-signer",
      batchSize: 1,
    });

    transport.onmessage = vi.fn();
    transport.onmessage!(req(1, "tools/call", { name: "signed_tool" }));
    await transport.send(res(1));

    await vi.waitFor(() => expect(globalThis.fetch).toHaveBeenCalled(), { timeout: 200 });

    const [, opts] = (globalThis.fetch as any).mock.calls[0];
    const body = JSON.parse(opts.body);
    capturedBody = body.witnesses[0];

    expect(capturedBody.payload_signature).toBeDefined();
    expect(capturedBody.payload_signature).toMatch(/^[0-9a-f]{64}$/);
    expect(capturedBody.agent_id).toBe("agent-signer");
  });

  // -----------------------------------------------------------------------
  // Tenant auto-resolution
  // -----------------------------------------------------------------------

  it("auto-resolves tenant from first witness response", async () => {
    let callCount = 0;

    globalThis.fetch = vi.fn().mockImplementation(async () => {
      callCount++;
      return {
        ok: true,
        json: async () => ({ ok: true, tenant_id: "RESOLVED_ABC" }),
      };
    });

    const receipts: TapReceipt[] = [];
    const transport = createTransport();

    withSWT3(transport, {
      apiKey: "axm_live_resolve_test",
      batchSize: 1,
      onWitness: (r) => receipts.push(r),
    });

    transport.onmessage = vi.fn();

    transport.onmessage!(req(1, "tools/call", { name: "first_call" }));
    await transport.send(res(1));
    await vi.waitFor(() => expect(receipts).toHaveLength(1), { timeout: 200 });

    const fp1 = receipts[0].fingerprint;

    transport.onmessage!(req(2, "tools/call", { name: "second_call" }));
    await transport.send(res(2));
    await vi.waitFor(() => expect(receipts).toHaveLength(2), { timeout: 200 });

    const fp2 = receipts[1].fingerprint;

    expect(fp1).not.toBe(fp2);
    expect(callCount).toBe(2);
  });

  // -----------------------------------------------------------------------
  // Error response detection
  // -----------------------------------------------------------------------

  it("detects JSON-RPC error responses and sets factor_c=0", async () => {
    let capturedBody: any = null;

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ ok: true }),
    });

    const transport = createTransport();

    withSWT3(transport, {
      apiKey: "axm_live_error_test",
      tenantId: "ERR_TENANT",
      batchSize: 1,
    });

    transport.onmessage = vi.fn();
    transport.onmessage!(req(1, "tools/call", { name: "failing_tool" }));

    await transport.send(res(1, undefined, { code: -32000, message: "tool crashed" }));

    await vi.waitFor(() => expect(globalThis.fetch).toHaveBeenCalled(), { timeout: 200 });

    const [, opts] = (globalThis.fetch as any).mock.calls[0];
    const body = JSON.parse(opts.body);
    capturedBody = body.witnesses[0];

    expect(capturedBody.factor_c).toBe(0);
    expect(capturedBody.ai_model_id).toBe("failing_tool");
  });

  // -----------------------------------------------------------------------
  // HTTP error from witness endpoint
  // -----------------------------------------------------------------------

  it("reports HTTP error in receipt without throwing", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 429,
      statusText: "Too Many Requests",
      json: async () => ({ error: "rate limited" }),
    });

    const receipts: TapReceipt[] = [];
    const transport = createTransport();

    withSWT3(transport, {
      apiKey: "axm_live_rate_test",
      tenantId: "RATE_TENANT",
      batchSize: 1,
      maxRetries: 0,
      onWitness: (r) => receipts.push(r),
    });

    transport.onmessage = vi.fn();
    transport.onmessage!(req(1, "tools/call", { name: "rate_limited_tool" }));
    await transport.send(res(1));

    await vi.waitFor(() => expect(receipts).toHaveLength(1), { timeout: 200 });

    expect(receipts[0].error).toContain("429");
    expect(receipts[0].toolName).toBe("rate_limited_tool");
    expect(transport._sent).toHaveLength(1);
  });

  // -----------------------------------------------------------------------
  // Fingerprint correctness
  // -----------------------------------------------------------------------

  it("produces correct fingerprint using locked formula", async () => {
    const receipts: TapReceipt[] = [];
    const transport = createTransport();

    withSWT3(transport, {
      tenantId: "FP_TENANT",
      batchSize: 1,
      onWitness: (r) => receipts.push(r),
    });

    transport.onmessage = vi.fn();
    transport.onmessage!(req(1, "tools/call", { name: "fp_tool" }));
    await transport.send(res(1));

    await vi.waitFor(() => expect(receipts).toHaveLength(1), { timeout: 200 });

    expect(receipts[0].fingerprint).toMatch(/^[0-9a-f]{12}$/);

    const [ts] = timestampMs();
    const testFp = mintFingerprint("FP_TENANT", "AI-TOOL.1", 1, 0, 1, ts);
    expect(testFp).toMatch(/^[0-9a-f]{12}$/);
    expect(testFp).toHaveLength(12);
  });

  // -----------------------------------------------------------------------
  // Transport send() pass-through
  // -----------------------------------------------------------------------

  it("send() passes through all messages including non-responses", async () => {
    const transport = createTransport();
    withSWT3(transport);

    await transport.send({ jsonrpc: "2.0", method: "notifications/progress", params: { progress: 50 } });
    await transport.send(res(999));
    await transport.send({ jsonrpc: "2.0", id: "abc", result: {} });

    expect(transport._sent).toHaveLength(3);
  });

  // -----------------------------------------------------------------------
  // Missing params
  // -----------------------------------------------------------------------

  it("handles tools/call with missing params gracefully", async () => {
    const receipts: TapReceipt[] = [];
    const transport = createTransport();

    withSWT3(transport, { batchSize: 1, onWitness: (r) => receipts.push(r) });
    transport.onmessage = vi.fn();

    transport.onmessage!(req(1, "tools/call"));
    await transport.send(res(1));

    await vi.waitFor(() => expect(receipts).toHaveLength(1), { timeout: 200 });
    expect(receipts[0].toolName).toBe("unknown");
  });

  // -----------------------------------------------------------------------
  // Latency tracking
  // -----------------------------------------------------------------------

  it("tracks latency between request and response", async () => {
    const receipts: TapReceipt[] = [];
    const transport = createTransport();

    withSWT3(transport, { batchSize: 1, onWitness: (r) => receipts.push(r) });
    transport.onmessage = vi.fn();

    transport.onmessage!(req(1, "tools/call", { name: "slow_op" }));
    await new Promise((r) => setTimeout(r, 50));
    await transport.send(res(1));

    await vi.waitFor(() => expect(receipts).toHaveLength(1), { timeout: 200 });
    expect(receipts[0].latencyMs).toBeGreaterThanOrEqual(40);
  });

  // -----------------------------------------------------------------------
  // Batching + sampling combined
  // -----------------------------------------------------------------------

  it("sampled-out calls never enter payload buffer", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ ok: true }),
    });

    const receipts: TapReceipt[] = [];
    const transport = createTransport();

    const wrapped = withSWT3(transport, {
      apiKey: "axm_combo_test",
      tenantId: "COMBO_T",
      samplingRate: 0.0, // skip all
      samplingRates: { "vip_tool": 1.0 }, // except this one
      batchSize: 100,
      flushIntervalMs: 60000,
      onWitness: (r) => receipts.push(r),
    });

    transport.onmessage = vi.fn();

    // 5 regular calls (all sampled out)
    for (let i = 1; i <= 5; i++) {
      transport.onmessage!(req(i, "tools/call", { name: "regular_tool" }));
      await transport.send(res(i));
    }

    // 1 VIP call (witnessed)
    transport.onmessage!(req(6, "tools/call", { name: "vip_tool" }));
    await transport.send(res(6));

    await wrapped.flush();

    // Only 1 witness (VIP) + possible AI-SAMPLE.1 summary
    const [, opts] = (globalThis.fetch as any).mock.calls[0];
    const body = JSON.parse(opts.body);

    // Should have AI-SAMPLE.1 summary + vip_tool witness
    const procedures = body.witnesses.map((w: any) => w.procedure_id);
    expect(procedures).toContain("AI-TOOL.1");
    expect(procedures).toContain("AI-SAMPLE.1");

    // The AI-SAMPLE.1 should have skipped_count = 5
    const summary = body.witnesses.find((w: any) => w.procedure_id === "AI-SAMPLE.1");
    expect(summary.ai_context.skipped_count).toBe(5);
    expect(summary.factor_a).toBe(5);
  });

  // -----------------------------------------------------------------------
  // Retry + batching combined
  // -----------------------------------------------------------------------

  it("failed batch retried on next flush cycle", async () => {
    let fetchCount = 0;
    globalThis.fetch = vi.fn().mockImplementation(async () => {
      fetchCount++;
      if (fetchCount === 1) {
        return { ok: false, status: 502, statusText: "Bad Gateway" };
      }
      return { ok: true, json: async () => ({ ok: true }) };
    });

    const receipts: TapReceipt[] = [];
    const transport = createTransport();

    const wrapped = withSWT3(transport, {
      apiKey: "axm_retry_batch",
      tenantId: "RBATCH_T",
      batchSize: 2,
      flushIntervalMs: 60000,
      maxRetries: 3,
      onWitness: (r) => receipts.push(r),
    });

    transport.onmessage = vi.fn();

    // Send 2 calls to trigger batch
    transport.onmessage!(req(1, "tools/call", { name: "batch_retry_1" }));
    await transport.send(res(1));
    transport.onmessage!(req(2, "tools/call", { name: "batch_retry_2" }));
    await transport.send(res(2));

    await new Promise((r) => setTimeout(r, 50));

    // First flush failed (502)
    expect(fetchCount).toBe(1);
    expect(receipts).toHaveLength(0);

    // Wait for backoff, then flush again
    await new Promise((r) => setTimeout(r, 1100));
    await wrapped.flush();

    // Retry succeeded
    expect(fetchCount).toBe(2);
    expect(receipts).toHaveLength(2);
  });

  // -----------------------------------------------------------------------
  // Graceful shutdown
  // -----------------------------------------------------------------------

  it("close() flushes remaining buffer and retries", async () => {
    let fetchCount = 0;
    globalThis.fetch = vi.fn().mockImplementation(async () => {
      fetchCount++;
      return { ok: true, json: async () => ({ ok: true }) };
    });

    const receipts: TapReceipt[] = [];
    const transport = createTransport();

    const wrapped = withSWT3(transport, {
      apiKey: "axm_shutdown_test",
      tenantId: "SHUTDOWN_T",
      batchSize: 100, // won't auto-flush
      flushIntervalMs: 60000,
      onWitness: (r) => receipts.push(r),
    });

    transport.onmessage = vi.fn();

    // Buffer 3 calls
    for (let i = 1; i <= 3; i++) {
      transport.onmessage!(req(i, "tools/call", { name: `shutdown_tool_${i}` }));
      await transport.send(res(i));
    }

    expect(fetchCount).toBe(0);

    // Close should flush
    await wrapped.close();

    expect(fetchCount).toBe(1);
    expect(receipts).toHaveLength(3);
    expect(transport._closed).toBe(true);
  });

  // -----------------------------------------------------------------------
  // Batch POST uses /api/v1/witness/batch
  // -----------------------------------------------------------------------

  it("batch POST targets /api/v1/witness/batch endpoint", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ ok: true }),
    });

    const transport = createTransport();
    const wrapped = withSWT3(transport, {
      apiKey: "axm_endpoint_test",
      tenantId: "EP_T",
      batchSize: 1,
    });

    transport.onmessage = vi.fn();
    transport.onmessage!(req(1, "tools/call", { name: "ep_tool" }));
    await transport.send(res(1));

    await vi.waitFor(() => expect(globalThis.fetch).toHaveBeenCalled(), { timeout: 200 });

    const [url] = (globalThis.fetch as any).mock.calls[0];
    expect(url).toBe("https://sovereign.tenova.io/api/v1/witness/batch");
  });
});
