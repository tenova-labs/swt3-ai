import { describe, it, expect, vi } from "vitest";
import { handleWitness } from "../src/tools/witness.js";
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

describe("witness_inference tool", () => {
  it("mints an anchor with model_id only", async () => {
    const client = mockClient({
      ok: true,
      procedure_id: "AI-INF.1",
      verdict: "PASS",
      swt3_anchor: "SWT3-E-TEST-AI-AIINF1-PASS-1700000000-abcdef123456",
      clearing_level: 1,
      witnessed_at: "2026-04-22T10:00:00Z",
      verification_url: "/api/v1/attest/verify?token=SWT3-...",
    });

    const result = await handleWitness({ model_id: "gpt-4o" }, mockConfig, client);
    expect(result).toContain("Verdict: PASS");
    expect(result).toContain("Anchor: SWT3-E-TEST");
    expect(result).toContain("Procedure: AI-INF.1");

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.procedure_id).toBe("AI-INF.1");
    expect(call.clearing_level).toBe(1);
    expect(call.ai_model_id).toBe("gpt-4o");
    expect(call.anchor_fingerprint).toHaveLength(12);
  });

  it("hashes raw prompt text locally", async () => {
    const client = mockClient({
      ok: true,
      procedure_id: "AI-INF.1",
      verdict: "PASS",
      swt3_anchor: "SWT3-...",
      clearing_level: 1,
      witnessed_at: "2026-04-22T10:00:00Z",
      verification_url: "/api/v1/attest/verify?token=SWT3-...",
    });

    await handleWitness(
      { model_id: "gpt-4o", prompt: "Hello, world!", response: "Hi there!" },
      mockConfig,
      client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    // Prompt hash should be SHA-256 truncated to 16 chars
    expect(call.ai_prompt_hash).toHaveLength(16);
    expect(call.ai_response_hash).toHaveLength(16);
    // Raw text should NOT appear in payload
    expect(JSON.stringify(call)).not.toContain("Hello, world!");
    expect(JSON.stringify(call)).not.toContain("Hi there!");
  });

  it("applies clearing level 3 — hashes model_id", async () => {
    const config = { ...mockConfig, clearingLevel: 3 as const };
    const client = mockClient({
      ok: true,
      procedure_id: "AI-INF.1",
      verdict: "PASS",
      swt3_anchor: "SWT3-...",
      clearing_level: 3,
      witnessed_at: "2026-04-22T10:00:00Z",
      verification_url: "/api/v1/attest/verify?token=SWT3-...",
    });

    await handleWitness({ model_id: "gpt-4o" }, config, client);

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    // Model ID should be hashed at level 3
    expect(call.ai_model_id).toHaveLength(16);
    expect(call.ai_model_id).not.toBe("gpt-4o");
    // No prompt/response hashes at level 3
    expect(call.ai_prompt_hash).toBeUndefined();
    expect(call.ai_response_hash).toBeUndefined();
    expect(call.ai_context).toBeUndefined();
  });

  it("includes agent_id when configured", async () => {
    const config = { ...mockConfig, agentId: "agent-007" };
    const client = mockClient({
      ok: true,
      procedure_id: "AI-INF.1",
      verdict: "PASS",
      swt3_anchor: "SWT3-...",
      clearing_level: 1,
      witnessed_at: "2026-04-22T10:00:00Z",
      verification_url: "/api/v1/attest/verify?token=SWT3-...",
    });

    await handleWitness({ model_id: "gpt-4o" }, config, client);

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.agent_id).toBe("agent-007");
  });

  it("uses custom procedure when specified", async () => {
    const client = mockClient({
      ok: true,
      procedure_id: "AI-MDL.1",
      verdict: "PASS",
      swt3_anchor: "SWT3-...",
      clearing_level: 1,
      witnessed_at: "2026-04-22T10:00:00Z",
      verification_url: "/api/v1/attest/verify?token=SWT3-...",
    });

    await handleWitness(
      { model_id: "gpt-4o", procedure: "AI-MDL.1" },
      mockConfig,
      client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.procedure_id).toBe("AI-MDL.1");
  });
});
