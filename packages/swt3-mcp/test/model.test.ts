import { describe, it, expect, vi } from "vitest";
import { handleWitnessModelIntegrity, handleWitnessAdapterStack } from "../src/tools/model.js";
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

// ---------------------------------------------------------------------------
// AI-MDL.5: witness_model_integrity
// ---------------------------------------------------------------------------

const mdl5Receipt = {
  ok: true,
  procedure_id: "AI-MDL.5",
  verdict: "PASS",
  swt3_anchor: "SWT3-E-TEST-AI-AIMDL5-PASS-1700000000-abcdef123456",
  clearing_level: 1,
  witnessed_at: "2026-05-02T10:00:00Z",
  verification_url: "/api/v1/attest/verify?token=SWT3-...",
};

describe("witness_model_integrity", () => {
  it("mints AI-MDL.5 anchor with correct factors", async () => {
    const client = mockClient(mdl5Receipt);
    const result = await handleWitnessModelIntegrity(
      { model_id: "llama-3.1-70b", weight_hash: "abc123def456" },
      mockConfig, client,
    );

    expect(result).toContain("Model Weight Integrity");
    expect(result).toContain("Verdict: PASS");

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.procedure_id).toBe("AI-MDL.5");
    expect(call.factor_a).toBe(1);
    expect(call.factor_b).toBe(1); // no expected_hash = attested
    expect(call.factor_c).toBe(0);
    expect(call.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
    expect(call.witness_source).toBe("mcp");
  });

  it("PASS when hash matches expected", async () => {
    const client = mockClient(mdl5Receipt);
    await handleWitnessModelIntegrity(
      { model_id: "llama", weight_hash: "matching", expected_hash: "matching" },
      mockConfig, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.factor_b).toBe(1);
  });

  it("FAIL when hash mismatches expected", async () => {
    const client = mockClient({ ...mdl5Receipt, verdict: "FAIL" });
    await handleWitnessModelIntegrity(
      { model_id: "llama", weight_hash: "actual", expected_hash: "different" },
      mockConfig, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.factor_b).toBe(0);
  });

  it("clearing level 0 includes full context", async () => {
    const config = { ...mockConfig, clearingLevel: 0 as const };
    const client = mockClient(mdl5Receipt);
    await handleWitnessModelIntegrity(
      { model_id: "llama", weight_hash: "abc123", format: "safetensors", file_size_bytes: 140000000000 },
      config, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.ai_model_id).toBe("llama");
    expect(call.ai_context.provider).toBe("model-weights");
    expect(call.ai_context.file_hash).toBe("abc123");
    expect(call.ai_context.format).toBe("safetensors");
    expect(call.ai_context.file_size_bytes).toBe(140000000000);
  });

  it("clearing level 2 strips context", async () => {
    const config = { ...mockConfig, clearingLevel: 2 as const };
    const client = mockClient(mdl5Receipt);
    await handleWitnessModelIntegrity(
      { model_id: "llama", weight_hash: "abc123" },
      config, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.ai_model_id).toBe("llama");
    expect(call.ai_context).toBeUndefined();
  });

  it("clearing level 3 hashes model_id", async () => {
    const config = { ...mockConfig, clearingLevel: 3 as const };
    const client = mockClient(mdl5Receipt);
    await handleWitnessModelIntegrity(
      { model_id: "llama-3.1-70b", weight_hash: "abc" },
      config, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.ai_model_id).toHaveLength(16);
    expect(call.ai_model_id).not.toBe("llama-3.1-70b");
    expect(call.ai_context).toBeUndefined();
  });

  it("demo mode returns local anchor", async () => {
    const config = { ...mockConfig, demo: true };
    const client = mockClient(mdl5Receipt);
    const result = await handleWitnessModelIntegrity(
      { model_id: "llama", weight_hash: "abc" },
      config, client,
    );
    expect(result).toContain("[DEMO MODE");
    expect(result).toContain("SWT3-DEMO-LOCAL");
    expect(client.postWitness).not.toHaveBeenCalled();
  });

  it("agent_id and cycle_id survive level 3", async () => {
    const config = { ...mockConfig, clearingLevel: 3 as const };
    const client = mockClient(mdl5Receipt);
    await handleWitnessModelIntegrity(
      { model_id: "llama", weight_hash: "abc", agent_id: "agent-1", cycle_id: "chain-1" },
      config, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.agent_id).toBe("agent-1");
    expect(call.cycle_id).toBe("chain-1");
  });

  it("signing key produces signature", async () => {
    const config = { ...mockConfig, signingKey: "test-key" };
    const client = mockClient(mdl5Receipt);
    await handleWitnessModelIntegrity(
      { model_id: "llama", weight_hash: "abc" },
      config, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.payload_signature).toHaveLength(64);
  });
});

// ---------------------------------------------------------------------------
// AI-MDL.6: witness_adapter_stack
// ---------------------------------------------------------------------------

const mdl6Receipt = {
  ok: true,
  procedure_id: "AI-MDL.6",
  verdict: "PASS",
  swt3_anchor: "SWT3-E-TEST-AI-AIMDL6-PASS-1700000000-abcdef123456",
  clearing_level: 1,
  witnessed_at: "2026-05-02T10:00:00Z",
  verification_url: "/api/v1/attest/verify?token=SWT3-...",
};

describe("witness_adapter_stack", () => {
  it("mints AI-MDL.6 with adapter count", async () => {
    const client = mockClient(mdl6Receipt);
    const result = await handleWitnessAdapterStack(
      {
        base_model: "llama-3.1-70b",
        adapters: [
          { name: "lora-legal", hash: "aaa111" },
          { name: "lora-medical", hash: "bbb222" },
        ],
      },
      mockConfig, client,
    );

    expect(result).toContain("Adapter Stack Attestation");
    expect(result).toContain("Adapters: 2");

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.procedure_id).toBe("AI-MDL.6");
    expect(call.factor_a).toBe(2);
    expect(call.factor_b).toBe(1); // all verified
    expect(call.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
    expect(call.witness_source).toBe("mcp");
  });

  it("empty adapter stack is PASS", async () => {
    const client = mockClient(mdl6Receipt);
    await handleWitnessAdapterStack(
      { base_model: "llama", adapters: [] },
      mockConfig, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.factor_a).toBe(0);
    expect(call.factor_b).toBe(1);
  });

  it("clearing level 0 includes adapter details", async () => {
    const config = { ...mockConfig, clearingLevel: 0 as const };
    const client = mockClient(mdl6Receipt);
    await handleWitnessAdapterStack(
      {
        base_model: "llama-3.1",
        adapters: [{ name: "lora-v1", hash: "h1", base_model: "llama-3.1" }],
      },
      config, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.ai_context.provider).toBe("adapter");
    expect(call.ai_context.base_model_id).toBe("llama-3.1");
    expect(call.ai_context.adapters).toHaveLength(1);
    expect(call.ai_context.adapters[0].name).toBe("lora-v1");
  });

  it("clearing level 3 hashes model_id and strips context", async () => {
    const config = { ...mockConfig, clearingLevel: 3 as const };
    const client = mockClient(mdl6Receipt);
    await handleWitnessAdapterStack(
      { base_model: "llama", adapters: [{ name: "l", hash: "h" }] },
      config, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.ai_model_id).toHaveLength(16);
    expect(call.ai_context).toBeUndefined();
  });

  it("demo mode returns local anchor", async () => {
    const config = { ...mockConfig, demo: true };
    const client = mockClient(mdl6Receipt);
    const result = await handleWitnessAdapterStack(
      { base_model: "llama", adapters: [] },
      config, client,
    );
    expect(result).toContain("[DEMO MODE");
    expect(result).toContain("SWT3-DEMO-LOCAL");
    expect(client.postWitness).not.toHaveBeenCalled();
  });

  it("signing key produces signature", async () => {
    const config = { ...mockConfig, signingKey: "test-key" };
    const client = mockClient(mdl6Receipt);
    await handleWitnessAdapterStack(
      { base_model: "llama", adapters: [] },
      config, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.payload_signature).toHaveLength(64);
  });
});
