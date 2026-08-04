import { describe, it, expect, vi } from "vitest";
import { handleWitnessHumanReview } from "../src/tools/hitl.js";
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

function mockClient(receipt: Record<string, unknown>): AxiomClient {
  return {
    postWitness: vi.fn().mockResolvedValue(receipt),
  } as unknown as AxiomClient;
}

const baseReceipt = {
  ok: true,
  procedure_id: "AI-HITL.1",
  verdict: "PASS",
  swt3_anchor: "SWT3-E-TEST-AI-AIHITL1-PASS-1700000000-abcdef123456",
  clearing_level: 1,
  witnessed_at: "2026-07-29T10:00:00Z",
  verification_url: "/api/v1/attest/verify?token=SWT3-...",
};

describe("witness_human_review tool", () => {
  it("witnesses approved review with correct factors", async () => {
    const client = mockClient(baseReceipt);

    const result = await handleWitnessHumanReview(
      { review_outcome: "approved" },
      mockConfig,
      client,
    );

    expect(result).toContain("Human Review Witnessed (AI-HITL.1)");
    expect(result).toContain("Verdict: PASS");
    expect(result).toContain("Outcome: Approved");
    expect(result).toContain("Items Reviewed: 1");

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.procedure_id).toBe("AI-HITL.1");
    expect(call.factor_a).toBe(1); // items_reviewed default
    expect(call.factor_b).toBe(1); // approved
    expect(call.factor_c).toBe(0); // no reviewer hash
  });

  it("witnesses rejected review", async () => {
    const client = mockClient(baseReceipt);

    await handleWitnessHumanReview(
      { review_outcome: "rejected", items_reviewed: 5 },
      mockConfig,
      client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.factor_a).toBe(5);
    expect(call.factor_b).toBe(0); // rejected
  });

  it("witnesses modified review with modification hash", async () => {
    const client = mockClient(baseReceipt);

    await handleWitnessHumanReview(
      {
        review_outcome: "modified",
        modification_hash: "abc123",
        reviewer_id_hash: "rev456",
      },
      mockConfig,
      client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.factor_b).toBe(2); // modified
    expect(call.factor_c).toBe(1); // has reviewer
    expect(call.ai_context.modification_hash).toBe("abc123");
    expect(call.ai_context.reviewer_id_hash).toBe("rev456");
  });

  it("witnesses escalated review with reason", async () => {
    const client = mockClient(baseReceipt);

    const result = await handleWitnessHumanReview(
      {
        review_outcome: "escalated",
        escalation_reason: "regulatory concern",
      },
      mockConfig,
      client,
    );

    expect(result).toContain("Outcome: Escalated");
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.factor_b).toBe(3); // escalated
    expect(call.ai_context.escalation_reason).toBe("regulatory concern");
  });

  it("records review latency", async () => {
    const client = mockClient(baseReceipt);

    await handleWitnessHumanReview(
      { review_outcome: "approved", review_latency_ms: 45000 },
      mockConfig,
      client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.ai_latency_ms).toBe(45000);
    expect(call.ai_context.review_latency_ms).toBe(45000);
  });

  it("works in demo mode", async () => {
    const client = mockClient(baseReceipt);

    const result = await handleWitnessHumanReview(
      { review_outcome: "approved" },
      demoConfig,
      client,
    );

    expect(result).toContain("DEMO MODE");
    expect(result).toContain("AI-HITL.1");
    expect(result).toContain("Outcome: Approved");
    expect((client.postWitness as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(0);
  });

  it("strips context at clearing level 3", async () => {
    const cl3Config = { ...mockConfig, clearingLevel: 3 as const };
    const client = mockClient(baseReceipt);

    await handleWitnessHumanReview(
      { review_outcome: "approved", reviewer_id_hash: "secret", model_id: "gpt-4o" },
      cl3Config,
      client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.ai_context).toBeUndefined();
    expect(call.ai_model_id).not.toBe("gpt-4o");
  });
});
