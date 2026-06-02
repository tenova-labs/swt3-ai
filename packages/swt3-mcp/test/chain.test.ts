import { describe, it, expect, vi } from "vitest";
import { handleStartChain, handleChainHandoff } from "../src/tools/chain.js";
import { createSessionState } from "../src/state.js";
import type { McpConfig } from "../src/config.js";
import type { AxiomClient } from "../src/client.js";

const mockConfig: McpConfig = {
  endpoint: "https://test.example.com",
  apiKey: "axm_live_test",
  tenantId: "TEST_ENCLAVE",
  clearingLevel: 1,
  demo: false,
};

function mockClient(receipt: Record<string, unknown>): AxiomClient {
  return {
    postWitness: vi.fn().mockResolvedValue(receipt),
  } as unknown as AxiomClient;
}

const baseReceipt = {
  ok: true,
  procedure_id: "AI-CHAIN.1",
  verdict: "PASS",
  swt3_anchor: "SWT3-E-TEST-AI-AICHAIN1-PASS-1700000000-abcdef123456",
  clearing_level: 1,
  witnessed_at: "2026-05-01T10:00:00Z",
  verification_url: "/api/v1/attest/verify?token=SWT3-...",
};

describe("start_chain", () => {
  it("generates a UUID cycle_id", () => {
    const state = createSessionState();
    const result = handleStartChain({}, state);

    expect(result).toContain("Chain started");
    expect(result).toContain("Cycle ID:");
    expect(state.activeChain).not.toBeNull();
    expect(state.activeChain!.cycleId).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("accepts a description", () => {
    const state = createSessionState();
    const result = handleStartChain({ description: "contract review pipeline" }, state);

    expect(result).toContain("contract review pipeline");
    expect(state.activeChain!.description).toBe("contract review pipeline");
  });

  it("is idempotent -- returns existing chain", () => {
    const state = createSessionState();
    handleStartChain({ description: "first" }, state);
    const cycleId = state.activeChain!.cycleId;

    const result = handleStartChain({ description: "second" }, state);
    expect(result).toContain("already active");
    expect(state.activeChain!.cycleId).toBe(cycleId);
  });
});

describe("chain_handoff", () => {
  it("mints AI-CHAIN.1 anchor with from/to agents", async () => {
    const client = mockClient(baseReceipt);
    const result = await handleChainHandoff(
      { cycle_id: "cycle-001", from_agent: "summarizer", to_agent: "reviewer" },
      mockConfig, client,
    );

    expect(result).toContain("Chain Handoff Witnessed");
    expect(result).toContain("From: summarizer");
    expect(result).toContain("To: reviewer");
    expect(result).toContain("Cycle ID: cycle-001");

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.procedure_id).toBe("AI-CHAIN.1");
    expect(call.factor_a).toBe(1);
    expect(call.factor_b).toBe(1);
    expect(call.factor_c).toBe(0);
    expect(call.cycle_id).toBe("cycle-001");
    expect(call.anchor_fingerprint).toHaveLength(12);
    expect(call.witness_source).toBe("mcp");
  });

  it("clearing level 3 hashes agent names", async () => {
    const config = { ...mockConfig, clearingLevel: 3 as const };
    const client = mockClient(baseReceipt);

    await handleChainHandoff(
      { cycle_id: "c1", from_agent: "agent-a", to_agent: "agent-b" },
      config, client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.ai_model_id).toHaveLength(16); // hashed
    expect(call.ai_model_id).not.toContain("agent-a");
    expect(call.ai_context).toBeUndefined();
  });

  it("clearing level 0 includes full handoff context", async () => {
    const config = { ...mockConfig, clearingLevel: 0 as const };
    const client = mockClient(baseReceipt);

    await handleChainHandoff(
      { cycle_id: "c1", from_agent: "a", to_agent: "b", context: "passing summary" },
      config, client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.ai_context).toEqual({
      provider: "chain",
      from_agent: "a",
      to_agent: "b",
      handoff_context: "passing summary",
    });
  });

  it("demo mode returns local anchor", async () => {
    const config = { ...mockConfig, demo: true };
    const client = mockClient(baseReceipt);

    const result = await handleChainHandoff(
      { cycle_id: "c1", from_agent: "a", to_agent: "b" },
      config, client,
    );

    expect(result).toContain("[DEMO MODE");
    expect(result).toContain("SWT3-DEMO-LOCAL");
    expect(client.postWitness).not.toHaveBeenCalled();
  });

  it("signing key produces payload_signature", async () => {
    const config = { ...mockConfig, signingKey: "test-key" };
    const client = mockClient(baseReceipt);

    await handleChainHandoff(
      { cycle_id: "c1", from_agent: "a", to_agent: "b" },
      config, client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.payload_signature).toHaveLength(64);
  });
});
