import { describe, it, expect, vi } from "vitest";
import { handleAuthorize } from "../src/tools/authorize.js";
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
  procedure_id: "AI-ACC.1",
  verdict: "PASS",
  swt3_anchor: "SWT3-E-TEST-AI-AIACC1-PASS-1700000000-abcdef123456",
  clearing_level: 1,
  witnessed_at: "2026-04-28T10:00:00Z",
  verification_url: "/api/v1/attest/verify?token=SWT3-...",
};

describe("witness_authorization tool", () => {
  it("granted access mints PASS anchor with factor_b=1", async () => {
    const client = mockClient(baseReceipt);
    const result = await handleAuthorize(
      { resource: "prod-database", scope: "read-only", granted: true },
      mockConfig,
      client,
    );

    expect(result).toContain("Authorization GRANTED");
    expect(result).toContain("Verdict: PASS");
    expect(result).toContain("Procedure: AI-ACC.1");
    expect(result).toContain("Resource: prod-database");
    expect(result).toContain("Scope: read-only");

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.procedure_id).toBe("AI-ACC.1");
    expect(call.factor_a).toBe(1);
    expect(call.factor_b).toBe(1);
    expect(call.factor_c).toBe(1);
    expect(call.anchor_fingerprint).toHaveLength(12);
  });

  it("denied access mints FAIL anchor with factor_b=0", async () => {
    const failReceipt = { ...baseReceipt, verdict: "FAIL" };
    const client = mockClient(failReceipt);
    const result = await handleAuthorize(
      { resource: "user-pii-store", scope: "admin", granted: false },
      mockConfig,
      client,
    );

    expect(result).toContain("Authorization DENIED");
    expect(result).toContain("Verdict: FAIL");

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.factor_b).toBe(0);
    expect(call.factor_c).toBe(0);
  });

  it("clearing level 3 hashes resource name", async () => {
    const config = { ...mockConfig, clearingLevel: 3 as const };
    const client = mockClient(baseReceipt);

    await handleAuthorize(
      { resource: "prod-database", granted: true },
      config,
      client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    // Resource name should be hashed at level 3
    expect(call.ai_model_id).toHaveLength(16);
    expect(call.ai_model_id).not.toBe("prod-database");
    // No context at level 3
    expect(call.ai_context).toBeUndefined();
  });

  it("clearing level 0 includes full access context", async () => {
    const config = { ...mockConfig, clearingLevel: 0 as const };
    const client = mockClient(baseReceipt);

    await handleAuthorize(
      { resource: "prod-database", scope: "write", granted: true },
      config,
      client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.ai_model_id).toBe("prod-database");
    expect(call.ai_context).toEqual({
      provider: "access",
      access_target: "prod-database",
      access_scope: "write",
      access_granted: true,
    });
  });

  it("demo mode returns local-only anchor", async () => {
    const config = { ...mockConfig, demo: true };
    const client = mockClient(baseReceipt);

    const result = await handleAuthorize(
      { resource: "test-resource", granted: true },
      config,
      client,
    );

    expect(result).toContain("[DEMO MODE");
    expect(result).toContain("Authorization GRANTED");
    expect(result).toContain("Anchor: SWT3-DEMO-LOCAL");
    expect(result).toContain("Fingerprint:");
    // Should NOT have called the API
    expect(client.postWitness).not.toHaveBeenCalled();
  });

  it("agent_id and cycle_id survive all clearing levels", async () => {
    const config = { ...mockConfig, clearingLevel: 3 as const };
    const client = mockClient(baseReceipt);

    await handleAuthorize(
      { resource: "test", granted: true, agent_id: "agent-alpha", cycle_id: "cycle-001" },
      config,
      client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.agent_id).toBe("agent-alpha");
    expect(call.cycle_id).toBe("cycle-001");
  });

  it("fingerprint is 12 hex characters from locked formula", async () => {
    const client = mockClient(baseReceipt);

    await handleAuthorize(
      { resource: "any-resource", granted: false },
      mockConfig,
      client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.anchor_fingerprint).toHaveLength(12);
    expect(call.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
    expect(call.fingerprint_timestamp_ms).toBeGreaterThan(0);
  });

  // ── Edge cases ──────────────────────────────────────────────────

  it("default scope is 'default' when omitted", async () => {
    const client = mockClient(baseReceipt);
    const result = await handleAuthorize(
      { resource: "test-resource", granted: true },
      { ...mockConfig, clearingLevel: 0 as const },
      client,
    );

    expect(result).toContain("Scope: default");
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.ai_context.access_scope).toBe("default");
  });

  it("witness_source is always 'mcp'", async () => {
    const client = mockClient(baseReceipt);
    await handleAuthorize(
      { resource: "test", granted: true },
      mockConfig,
      client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.witness_source).toBe("mcp");
  });

  it("signing key produces payload_signature", async () => {
    const config = { ...mockConfig, signingKey: "test-key" };
    const client = mockClient(baseReceipt);
    await handleAuthorize(
      { resource: "test", granted: true },
      config,
      client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.payload_signature).toBeDefined();
    expect(call.payload_signature).toHaveLength(64);
  });

  it("clearing level 2 strips context but keeps resource name", async () => {
    const config = { ...mockConfig, clearingLevel: 2 as const };
    const client = mockClient(baseReceipt);
    await handleAuthorize(
      { resource: "prod-db", scope: "admin", granted: true },
      config,
      client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.ai_model_id).toBe("prod-db");
    expect(call.ai_context).toBeUndefined();
  });

  it("config agent_id is used when per-call agent_id not provided", async () => {
    const config = { ...mockConfig, agentId: "config-agent" };
    const client = mockClient(baseReceipt);
    await handleAuthorize(
      { resource: "test", granted: true },
      config,
      client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.agent_id).toBe("config-agent");
  });

  it("per-call agent_id overrides config agent_id", async () => {
    const config = { ...mockConfig, agentId: "config-agent" };
    const client = mockClient(baseReceipt);
    await handleAuthorize(
      { resource: "test", granted: true, agent_id: "call-agent" },
      config,
      client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.agent_id).toBe("call-agent");
  });
});
