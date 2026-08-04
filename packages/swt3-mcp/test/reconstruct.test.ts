import { describe, it, expect, vi } from "vitest";
import { handleReconstructTimeline } from "../src/tools/reconstruct.js";
import type { McpConfig } from "../src/config.js";
import type { AxiomClient } from "../src/client.js";

const mockConfig: McpConfig = {
  endpoint: "https://test.example.com",
  apiKey: "axm_live_test",
  tenantId: "TEST_ENCLAVE",
  clearingLevel: 1,
  demo: false,
};

const demoConfig: McpConfig = { ...mockConfig, demo: true };

function mockClient(timeline: Record<string, unknown>): AxiomClient {
  return {
    fetchTimeline: vi.fn().mockResolvedValue(timeline),
  } as unknown as AxiomClient;
}

const sampleEntries = [
  {
    timestamp_server: "2026-07-29T10:00:00Z",
    agent_id: "fraud-detector",
    procedure_id: "AI-INF.1",
    verdict: "PASS",
    fingerprint: "abc123def456",
    swt3_anchor: "SWT3-E-TEST-AI-AIINF1-PASS-...",
    clearing_level: 1,
    detail: { model_id: "gpt-4o", tokens_in: 500, tokens_out: 200 },
    is_drift: false,
    is_override: false,
  },
  {
    timestamp_server: "2026-07-29T10:00:05Z",
    agent_id: "fraud-detector",
    procedure_id: "AI-GRD.1",
    verdict: "PASS",
    fingerprint: "def456abc789",
    swt3_anchor: "SWT3-E-TEST-AI-AIGRD1-PASS-...",
    clearing_level: 1,
    detail: {},
    is_drift: false,
    is_override: false,
  },
  {
    timestamp_server: "2026-07-29T10:00:10Z",
    agent_id: null,
    procedure_id: "AI-VIO.1",
    verdict: "FAIL",
    fingerprint: "vio123456789",
    swt3_anchor: "SWT3-E-TEST-AI-AIVIO1-FAIL-...",
    clearing_level: 1,
    detail: {},
    is_violation: true,
  },
];

describe("reconstruct_timeline tool", () => {
  it("rejects demo mode", async () => {
    const client = mockClient({ entries: [] });
    const result = await handleReconstructTimeline(
      { cycle_id: "test" },
      demoConfig,
      client,
    );

    expect(result).toContain("requires a live account");
    expect((client.fetchTimeline as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(0);
  });

  it("requires at least one query parameter", async () => {
    const client = mockClient({ entries: [] });
    const result = await handleReconstructTimeline(
      {},
      mockConfig,
      client,
    );

    expect(result).toContain("Provide at least one query parameter");
  });

  it("formats timeline with entries", async () => {
    const client = mockClient({ entries: sampleEntries });

    const result = await handleReconstructTimeline(
      { cycle_id: "CYCLE-abc123" },
      mockConfig,
      client,
    );

    expect(result).toContain("Timeline: cycle CYCLE-abc123");
    expect(result).toContain("Anchors: 3");
    expect(result).toContain("fraud-detector");
    expect(result).toContain("Inference");
    expect(result).toContain("Guardrail Check");
    expect(result).toContain("VIOLATION");
    expect(result).toContain("2 PASS, 1 FAIL");
  });

  it("shows model and token details", async () => {
    const client = mockClient({ entries: [sampleEntries[0]] });

    const result = await handleReconstructTimeline(
      { agent_id: "fraud-detector" },
      mockConfig,
      client,
    );

    expect(result).toContain("model: gpt-4o");
    expect(result).toContain("tokens: 500 in / 200 out");
  });

  it("handles empty timeline", async () => {
    const client = mockClient({ entries: [] });

    const result = await handleReconstructTimeline(
      { fingerprint: "nonexistent" },
      mockConfig,
      client,
    );

    expect(result).toContain("No anchors found");
  });

  it("passes time window parameters", async () => {
    const client = mockClient({ entries: [] });

    await handleReconstructTimeline(
      { agent_id: "test", last: "6h" },
      mockConfig,
      client,
    );

    const call = (client.fetchTimeline as ReturnType<typeof vi.fn>).mock.calls[0][0] as URLSearchParams;
    expect(call.get("agent_id")).toBe("test");
    expect(call.get("from")).toBeTruthy();
    expect(call.get("to")).toBeTruthy();
  });

  it("rejects invalid time window", async () => {
    const client = mockClient({ entries: [] });

    const result = await handleReconstructTimeline(
      { last: "abc" },
      mockConfig,
      client,
    );

    expect(result).toContain("Invalid time window");
  });

  it("handles API errors gracefully", async () => {
    const client = {
      fetchTimeline: vi.fn().mockRejectedValue(new Error("401: Invalid API key")),
    } as unknown as AxiomClient;

    const result = await handleReconstructTimeline(
      { cycle_id: "test" },
      mockConfig,
      client,
    );

    expect(result).toContain("Error:");
    expect(result).toContain("401");
  });

  it("handles cost details", async () => {
    const costEntry = {
      ...sampleEntries[0],
      procedure_id: "AI-COST.1",
      detail: { cost_cents: 150 },
      is_cost: true,
    };
    const client = mockClient({ entries: [costEntry] });

    const result = await handleReconstructTimeline(
      { cycle_id: "test" },
      mockConfig,
      client,
    );

    expect(result).toContain("cost: $1.50");
    expect(result).toContain("COST");
  });
});
