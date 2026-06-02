import { describe, it, expect, vi } from "vitest";
import { handleReportViolation } from "../src/tools/violation.js";
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
  procedure_id: "AI-VIO.1",
  verdict: "FAIL",
  swt3_anchor: "SWT3-E-TEST-AI-AIVIO1-FAIL-1700000000-abcdef123456",
  clearing_level: 1,
  witnessed_at: "2026-05-01T10:00:00Z",
  verification_url: "/api/v1/attest/verify?token=SWT3-...",
};

describe("report_violation", () => {
  it("always mints FAIL anchor", async () => {
    const client = mockClient(baseReceipt);
    const result = await handleReportViolation(
      { violation_type: "unauthorized_model", description: "Used GPT-4 instead of approved model" },
      mockConfig, client,
    );

    expect(result).toContain("Violation Self-Reported");
    expect(result).toContain("Verdict: FAIL");
    expect(result).toContain("Type: unauthorized_model");

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.procedure_id).toBe("AI-VIO.1");
    expect(call.factor_a).toBe(1);
    expect(call.factor_b).toBe(0); // always FAIL
    expect(call.anchor_fingerprint).toHaveLength(12);
    expect(call.witness_source).toBe("mcp");
  });

  it("maps severity to factor_c correctly", async () => {
    const severities = [
      { severity: "low", expected: 1 },
      { severity: "medium", expected: 2 },
      { severity: "high", expected: 3 },
      { severity: "critical", expected: 4 },
    ];

    for (const { severity, expected } of severities) {
      const client = mockClient(baseReceipt);
      await handleReportViolation(
        { violation_type: "test", description: "test", severity },
        mockConfig, client,
      );
      const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
      expect(call.factor_c).toBe(expected);
    }
  });

  it("defaults severity to medium", async () => {
    const client = mockClient(baseReceipt);
    await handleReportViolation(
      { violation_type: "test", description: "test" },
      mockConfig, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.factor_c).toBe(2); // medium
  });

  it("clearing level 3 hashes violation type", async () => {
    const config = { ...mockConfig, clearingLevel: 3 as const };
    const client = mockClient(baseReceipt);

    await handleReportViolation(
      { violation_type: "data_leak", description: "leaked PII" },
      config, client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.ai_model_id).toHaveLength(16);
    expect(call.ai_model_id).not.toBe("data_leak");
    expect(call.ai_context).toBeUndefined();
  });

  it("clearing level 0 includes full violation context", async () => {
    const config = { ...mockConfig, clearingLevel: 0 as const };
    const client = mockClient(baseReceipt);

    await handleReportViolation(
      { violation_type: "jurisdiction_mismatch", description: "Processed EU data on US server", severity: "high" },
      config, client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.ai_model_id).toBe("jurisdiction_mismatch");
    expect(call.ai_context).toEqual({
      provider: "self-report",
      violation_type: "jurisdiction_mismatch",
      description: "Processed EU data on US server",
      severity: "high",
    });
  });

  it("demo mode returns local FAIL anchor", async () => {
    const config = { ...mockConfig, demo: true };
    const client = mockClient(baseReceipt);

    const result = await handleReportViolation(
      { violation_type: "test", description: "test" },
      config, client,
    );

    expect(result).toContain("[DEMO MODE");
    expect(result).toContain("Verdict: FAIL");
    expect(result).toContain("SWT3-DEMO-LOCAL");
    expect(result).toContain("FAIL");
    expect(client.postWitness).not.toHaveBeenCalled();
  });

  it("agent_id and cycle_id survive all clearing levels", async () => {
    const config = { ...mockConfig, clearingLevel: 3 as const };
    const client = mockClient(baseReceipt);

    await handleReportViolation(
      { violation_type: "test", description: "test", agent_id: "agent-007", cycle_id: "chain-42" },
      config, client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.agent_id).toBe("agent-007");
    expect(call.cycle_id).toBe("chain-42");
  });

  it("signing key produces payload_signature", async () => {
    const config = { ...mockConfig, signingKey: "secret-key" };
    const client = mockClient(baseReceipt);

    await handleReportViolation(
      { violation_type: "test", description: "test" },
      config, client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.payload_signature).toHaveLength(64);
  });
});
