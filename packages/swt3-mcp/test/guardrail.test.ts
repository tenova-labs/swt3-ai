import { describe, it, expect, vi } from "vitest";
import { handleWitnessGuardrail } from "../src/tools/guardrail.js";
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
  procedure_id: "AI-GRD.1",
  verdict: "PASS",
  swt3_anchor: "SWT3-E-TEST-AI-AIGRD1-PASS-1700000000-abcdef123456",
  clearing_level: 1,
  witnessed_at: "2026-07-29T10:00:00Z",
  verification_url: "/api/v1/attest/verify?token=SWT3-...",
};

describe("witness_guardrail tool", () => {
  it("witnesses triggered guardrail with correct factors", async () => {
    const client = mockClient(baseReceipt);

    const result = await handleWitnessGuardrail(
      { guardrail_name: "content-filter", triggered: true, action_taken: "blocked" },
      mockConfig,
      client,
    );

    expect(result).toContain("Guardrail Witnessed (AI-GRD.1)");
    expect(result).toContain("Verdict: PASS");
    expect(result).toContain("Triggered: YES");
    expect(result).toContain("Action: blocked");

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.procedure_id).toBe("AI-GRD.1");
    expect(call.factor_a).toBe(1);
    expect(call.factor_b).toBe(1); // triggered
    expect(call.factor_c).toBe(3); // blocked
  });

  it("witnesses non-triggered guardrail", async () => {
    const client = mockClient(baseReceipt);

    await handleWitnessGuardrail(
      { guardrail_name: "pii-redaction", triggered: false },
      mockConfig,
      client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.factor_b).toBe(0); // not triggered
    expect(call.factor_c).toBe(0); // allowed (default for non-triggered)
  });

  it("defaults action to flagged when triggered without action_taken", async () => {
    const client = mockClient(baseReceipt);

    const result = await handleWitnessGuardrail(
      { guardrail_name: "toxicity-check", triggered: true },
      mockConfig,
      client,
    );

    expect(result).toContain("Action: flagged");
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.factor_c).toBe(1); // flagged
  });

  it("includes version in output", async () => {
    const client = mockClient(baseReceipt);

    const result = await handleWitnessGuardrail(
      { guardrail_name: "llm-guard", guardrail_version: "2.1.0", triggered: false },
      mockConfig,
      client,
    );

    expect(result).toContain("llm-guard v2.1.0");
  });

  it("works in demo mode", async () => {
    const client = mockClient(baseReceipt);

    const result = await handleWitnessGuardrail(
      { guardrail_name: "demo-guard", triggered: true, action_taken: "redacted" },
      demoConfig,
      client,
    );

    expect(result).toContain("DEMO MODE");
    expect(result).toContain("AI-GRD.1");
    expect(result).toContain("Action: redacted");
    expect((client.postWitness as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(0);
  });

  it("strips context at clearing level 3", async () => {
    const cl3Config = { ...mockConfig, clearingLevel: 3 as const };
    const client = mockClient(baseReceipt);

    await handleWitnessGuardrail(
      { guardrail_name: "secret-filter", triggered: true, action_taken: "blocked", model_id: "gpt-4o" },
      cl3Config,
      client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.ai_context).toBeUndefined();
    expect(call.ai_model_id).not.toBe("gpt-4o");
  });
});
