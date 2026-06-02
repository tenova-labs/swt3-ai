/**
 * SWT3 MCP Server: verify_agent_trust + present_trust_credential tests.
 */

import { describe, it, expect, vi } from "vitest";
import { handleVerifyAgentTrust, handlePresentCredential } from "../src/tools/trust.js";
import type { McpConfig } from "../src/config.js";
import type { AxiomClient } from "../src/client.js";
import type { SessionState } from "../src/state.js";

const mockConfig: McpConfig = {
  endpoint: "https://test.example.com",
  apiKey: "axm_live_test",
  tenantId: "TEST_ENCLAVE",
  clearingLevel: 1,
  demo: false,
};

const demoConfig: McpConfig = {
  ...mockConfig,
  apiKey: "axm_demo_local",
  tenantId: "DEMO_LOCAL",
  demo: true,
};

function mockClient(receipt?: Record<string, unknown>): AxiomClient {
  const defaultReceipt = {
    ok: true,
    procedure_id: "AI-TRUST.1",
    verdict: "PASS",
    swt3_anchor: "SWT3-E-TEST-AI-AITRUST1-PASS-1700000000-abcdef123456",
    clearing_level: 1,
    witnessed_at: "2026-05-03T10:00:00Z",
    verification_url: "/api/v1/attest/verify?token=SWT3-...",
    tenant_id: "TEST_ENCLAVE",
  };
  return {
    postWitness: vi.fn().mockResolvedValue(receipt ?? defaultReceipt),
  } as unknown as AxiomClient;
}

function mockState(overrides?: Partial<SessionState>): SessionState {
  return {
    activeAuditSession: null,
    activeChain: null,
    trustedTenants: new Set(),
    deniedAgents: new Set(),
    ...overrides,
  };
}

// ── verify_agent_trust ──────────────────────────────────────────────

describe("verify_agent_trust", () => {
  it("same-tenant agent is auto-trusted", async () => {
    const client = mockClient();
    const state = mockState();
    const result = await handleVerifyAgentTrust({
      counterpart_agent_id: "agent-b",
      counterpart_tenant_id: "TEST_ENCLAVE",
      anchor_fingerprint: "abc123def456",
    }, mockConfig, client, state);

    expect(result).toContain("GRANTED");
    expect(result).toContain("AI-TRUST.1");
    expect(result).toContain("AI-TRUST.2");
    expect((client.postWitness as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(2);
  });

  it("cross-tenant untrusted agent is denied", async () => {
    const client = mockClient({
      ok: true, procedure_id: "AI-TRUST.1", verdict: "FAIL",
      swt3_anchor: "SWT3-E-TEST-AI-AITRUST1-FAIL-1700000000-xyz",
      clearing_level: 1, witnessed_at: "2026-05-03T10:00:00Z",
      verification_url: "/verify", tenant_id: "TEST_ENCLAVE",
    });
    const state = mockState();
    const result = await handleVerifyAgentTrust({
      counterpart_agent_id: "agent-x",
      counterpart_tenant_id: "STRANGER_TENANT",
      anchor_fingerprint: "xyz789",
    }, mockConfig, client, state);

    expect(result).toContain("DENIED");
    expect(result).toContain("tenant_not_trusted");
  });

  it("trusted tenant passes", async () => {
    const client = mockClient();
    const state = mockState({ trustedTenants: new Set(["PARTNER_TENANT"]) });
    const result = await handleVerifyAgentTrust({
      counterpart_agent_id: "partner-agent",
      counterpart_tenant_id: "PARTNER_TENANT",
      anchor_fingerprint: "abc123def456",
    }, mockConfig, client, state);

    expect(result).toContain("GRANTED");
  });

  it("deny-listed agent is blocked", async () => {
    const client = mockClient({
      ok: true, procedure_id: "AI-TRUST.1", verdict: "FAIL",
      swt3_anchor: "SWT3-FAIL", clearing_level: 1,
      witnessed_at: "2026-05-03T10:00:00Z", verification_url: "/verify",
      tenant_id: "TEST_ENCLAVE",
    });
    const state = mockState({
      trustedTenants: new Set(["PARTNER"]),
      deniedAgents: new Set(["bad-agent"]),
    });
    const result = await handleVerifyAgentTrust({
      counterpart_agent_id: "bad-agent",
      counterpart_tenant_id: "PARTNER",
      anchor_fingerprint: "xyz",
    }, mockConfig, client, state);

    expect(result).toContain("DENIED");
    expect(result).toContain("deny_listed");
  });

  it("signed agent gets verified trust level", async () => {
    const client = mockClient();
    const state = mockState();
    const result = await handleVerifyAgentTrust({
      counterpart_agent_id: "agent-b",
      counterpart_tenant_id: "TEST_ENCLAVE",
      anchor_fingerprint: "abc123def456",
      is_signed: true,
    }, mockConfig, client, state);

    expect(result).toContain("GRANTED");
    expect(result).toContain("verified");
  });

  it("attested agent (signed + hw + guardrails) gets attested level", async () => {
    const client = mockClient();
    const state = mockState();
    const result = await handleVerifyAgentTrust({
      counterpart_agent_id: "agent-b",
      counterpart_tenant_id: "TEST_ENCLAVE",
      anchor_fingerprint: "abc123def456",
      is_signed: true,
      has_hardware_attestation: true,
      has_guardrails: true,
    }, mockConfig, client, state);

    expect(result).toContain("attested");
  });

  it("demo mode returns local anchors", async () => {
    const client = mockClient();
    const state = mockState();
    const result = await handleVerifyAgentTrust({
      counterpart_agent_id: "agent-b",
      counterpart_tenant_id: "DEMO_LOCAL",
      anchor_fingerprint: "abc123def456",
    }, demoConfig, client, state);

    expect(result).toContain("DEMO MODE");
    expect(result).toContain("AITRUST1");
    expect(result).toContain("AITRUST2");
    expect((client.postWitness as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(0);
  });

  it("posts two witness payloads in live mode", async () => {
    const client = mockClient();
    const state = mockState();
    await handleVerifyAgentTrust({
      counterpart_agent_id: "agent-b",
      counterpart_tenant_id: "TEST_ENCLAVE",
      anchor_fingerprint: "abc123def456",
    }, mockConfig, client, state);

    const calls = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls;
    expect(calls).toHaveLength(2);
    expect(calls[0][0].procedure_id).toBe("AI-TRUST.1");
    expect(calls[1][0].procedure_id).toBe("AI-TRUST.2");
  });

  it("payloads include witness_source=mcp", async () => {
    const client = mockClient();
    const state = mockState();
    await handleVerifyAgentTrust({
      counterpart_agent_id: "agent-b",
      counterpart_tenant_id: "TEST_ENCLAVE",
      anchor_fingerprint: "abc",
    }, mockConfig, client, state);

    const calls = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls;
    expect(calls[0][0].witness_source).toBe("mcp");
    expect(calls[1][0].witness_source).toBe("mcp");
  });

  it("clearing level 2 strips ai_context", async () => {
    const client = mockClient();
    const state = mockState();
    const configL2 = { ...mockConfig, clearingLevel: 2 as const };
    await handleVerifyAgentTrust({
      counterpart_agent_id: "agent-b",
      counterpart_tenant_id: "TEST_ENCLAVE",
      anchor_fingerprint: "abc",
      clearing_level: 2,
    }, configL2, client, state);

    const calls = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls;
    expect(calls[0][0].ai_context).toBeUndefined();
  });
});

// ── present_trust_credential ────────────────────────────────────────

describe("present_trust_credential", () => {
  it("returns formatted credential", () => {
    const result = handlePresentCredential({}, mockConfig);
    expect(result).toContain("agent_id: anonymous");
    expect(result).toContain("tenant_id: TEST_ENCLAVE");
    expect(result).toContain("anchor_fingerprint:");
    expect(result).toContain("verify_agent_trust");
  });

  it("uses config agentId", () => {
    const configWithAgent = { ...mockConfig, agentId: "my-agent-001" };
    const result = handlePresentCredential({}, configWithAgent);
    expect(result).toContain("agent_id: my-agent-001");
  });

  it("override agent_id takes precedence", () => {
    const configWithAgent = { ...mockConfig, agentId: "config-agent" };
    const result = handlePresentCredential({ agent_id: "override-agent" }, configWithAgent);
    expect(result).toContain("agent_id: override-agent");
  });

  it("shows signing status", () => {
    const configSigned = { ...mockConfig, signingKey: "secret" };
    const result = handlePresentCredential({}, configSigned);
    expect(result).toContain("is_signed: true");
  });

  it("demo mode shows notice", () => {
    const result = handlePresentCredential({}, demoConfig);
    expect(result).toContain("DEMO MODE");
  });

  it("no network calls", () => {
    // presentCredential is pure local -- no client needed
    const result = handlePresentCredential({}, mockConfig);
    expect(result).toContain("anchor_fingerprint:");
  });
});
