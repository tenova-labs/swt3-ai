import { describe, it, expect, vi } from "vitest";
import { handleAttestSkillManifest, handleAttestMemoryContext } from "../src/tools/skill.js";
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
// AI-SKILL.1: attest_skill_manifest
// ---------------------------------------------------------------------------

const skill1Receipt = {
  ok: true,
  procedure_id: "AI-SKILL.1",
  verdict: "PASS",
  swt3_anchor: "SWT3-E-TEST-AI-AISKILL1-PASS-1700000000-abcdef123456",
  clearing_level: 1,
  witnessed_at: "2026-05-02T10:00:00Z",
  verification_url: "/api/v1/attest/verify?token=SWT3-...",
};

describe("attest_skill_manifest", () => {
  it("mints AI-SKILL.1 with skill count", async () => {
    const client = mockClient(skill1Receipt);
    const result = await handleAttestSkillManifest(
      {
        skills: [
          { name: "code_exec", version: "1.0" },
          { name: "web_search" },
          { name: "file_read", hash: "abc123" },
        ],
      },
      mockConfig, client,
    );

    expect(result).toContain("Skill Manifest Attestation");
    expect(result).toContain("Count: 3");

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.procedure_id).toBe("AI-SKILL.1");
    expect(call.factor_a).toBe(3);
    expect(call.factor_b).toBe(1); // no expected hash = attested
    expect(call.factor_c).toBe(0);
    expect(call.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
    expect(call.witness_source).toBe("mcp");
  });

  it("PASS when no expected manifest hash", async () => {
    const client = mockClient(skill1Receipt);
    await handleAttestSkillManifest(
      { skills: [{ name: "tool_a" }] },
      mockConfig, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.factor_b).toBe(1);
  });

  it("FAIL when manifest hash mismatches", async () => {
    const client = mockClient({ ...skill1Receipt, verdict: "FAIL" });
    await handleAttestSkillManifest(
      { skills: [{ name: "tool_a" }], expected_manifest_hash: "wrong_hash" },
      mockConfig, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.factor_b).toBe(0);
  });

  it("clearing level 0 includes full skill context", async () => {
    const config = { ...mockConfig, clearingLevel: 0 as const };
    const client = mockClient(skill1Receipt);
    await handleAttestSkillManifest(
      { skills: [{ name: "search", version: "2.0", hash: "abc" }] },
      config, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.ai_model_id).toBe("skill-manifest");
    expect(call.ai_context.provider).toBe("skill-manifest");
    expect(call.ai_context.skills).toHaveLength(1);
    expect(call.ai_context.skills[0].name).toBe("search");
    expect(call.ai_context.manifest_hash).toBeTruthy();
  });

  it("clearing level 2 strips context", async () => {
    const config = { ...mockConfig, clearingLevel: 2 as const };
    const client = mockClient(skill1Receipt);
    await handleAttestSkillManifest(
      { skills: [{ name: "tool" }] },
      config, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.ai_model_id).toBe("skill-manifest");
    expect(call.ai_context).toBeUndefined();
  });

  it("clearing level 3 hashes model_id", async () => {
    const config = { ...mockConfig, clearingLevel: 3 as const };
    const client = mockClient(skill1Receipt);
    await handleAttestSkillManifest(
      { skills: [{ name: "tool" }] },
      config, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.ai_model_id).toHaveLength(16);
    expect(call.ai_model_id).not.toBe("skill-manifest");
    expect(call.ai_context).toBeUndefined();
  });

  it("demo mode returns local anchor", async () => {
    const config = { ...mockConfig, demo: true };
    const client = mockClient(skill1Receipt);
    const result = await handleAttestSkillManifest(
      { skills: [{ name: "tool" }] },
      config, client,
    );
    expect(result).toContain("[DEMO MODE");
    expect(result).toContain("SWT3-DEMO-LOCAL");
    expect(result).toContain("Manifest Hash:");
    expect(client.postWitness).not.toHaveBeenCalled();
  });

  it("agent_id and cycle_id survive level 3", async () => {
    const config = { ...mockConfig, clearingLevel: 3 as const };
    const client = mockClient(skill1Receipt);
    await handleAttestSkillManifest(
      { skills: [{ name: "t" }], agent_id: "agent-1", cycle_id: "chain-1" },
      config, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.agent_id).toBe("agent-1");
    expect(call.cycle_id).toBe("chain-1");
  });

  it("signing key produces signature", async () => {
    const config = { ...mockConfig, signingKey: "test-key" };
    const client = mockClient(skill1Receipt);
    await handleAttestSkillManifest(
      { skills: [{ name: "t" }] },
      config, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.payload_signature).toHaveLength(64);
  });

  it("manifest hash is deterministic", async () => {
    const client1 = mockClient(skill1Receipt);
    const client2 = mockClient(skill1Receipt);
    const skills = [{ name: "a", hash: "h1" }, { name: "b", hash: "h2" }];

    await handleAttestSkillManifest({ skills }, mockConfig, client1);
    await handleAttestSkillManifest({ skills }, mockConfig, client2);

    const ctx1 = (client1.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0].ai_context;
    const ctx2 = (client2.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0].ai_context;
    expect(ctx1.manifest_hash).toBe(ctx2.manifest_hash);
  });
});

// ---------------------------------------------------------------------------
// AI-SKILL.2: attest_memory_context
// ---------------------------------------------------------------------------

const skill2Receipt = {
  ok: true,
  procedure_id: "AI-SKILL.2",
  verdict: "PASS",
  swt3_anchor: "SWT3-E-TEST-AI-AISKILL2-PASS-1700000000-abcdef123456",
  clearing_level: 1,
  witnessed_at: "2026-05-02T10:00:00Z",
  verification_url: "/api/v1/attest/verify?token=SWT3-...",
};

describe("attest_memory_context", () => {
  it("mints AI-SKILL.2 with source count", async () => {
    const client = mockClient(skill2Receipt);
    const result = await handleAttestMemoryContext(
      {
        memory_sources: [
          { type: "vector_store", id: "pinecone-prod", hash: "abc" },
          { type: "conversation", id: "session-123" },
        ],
      },
      mockConfig, client,
    );

    expect(result).toContain("Memory Context Binding");
    expect(result).toContain("Count: 2");

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.procedure_id).toBe("AI-SKILL.2");
    expect(call.factor_a).toBe(2);
    expect(call.factor_b).toBe(1); // all identified
    expect(call.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
    expect(call.witness_source).toBe("mcp");
  });

  it("FAIL when source has no id or hash (anonymous)", async () => {
    const client = mockClient({ ...skill2Receipt, verdict: "FAIL" });
    await handleAttestMemoryContext(
      { memory_sources: [{ type: "scratchpad" }] },
      mockConfig, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.factor_b).toBe(0);
  });

  it("PASS when all sources identified by id", async () => {
    const client = mockClient(skill2Receipt);
    await handleAttestMemoryContext(
      { memory_sources: [{ type: "vector_store", id: "vs-1" }] },
      mockConfig, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.factor_b).toBe(1);
  });

  it("PASS when all sources identified by hash", async () => {
    const client = mockClient(skill2Receipt);
    await handleAttestMemoryContext(
      { memory_sources: [{ type: "knowledge_base", hash: "abc123" }] },
      mockConfig, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.factor_b).toBe(1);
  });

  it("clearing level 0 includes full memory context", async () => {
    const config = { ...mockConfig, clearingLevel: 0 as const };
    const client = mockClient(skill2Receipt);
    await handleAttestMemoryContext(
      { memory_sources: [{ type: "vector_store", id: "vs-1", hash: "h1" }] },
      config, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.ai_context.provider).toBe("memory");
    expect(call.ai_context.sources).toHaveLength(1);
    expect(call.ai_context.total_sources).toBe(1);
  });

  it("clearing level 3 hashes model_id and strips context", async () => {
    const config = { ...mockConfig, clearingLevel: 3 as const };
    const client = mockClient(skill2Receipt);
    await handleAttestMemoryContext(
      { memory_sources: [{ type: "vs", id: "p" }] },
      config, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.ai_model_id).toHaveLength(16);
    expect(call.ai_context).toBeUndefined();
  });

  it("demo mode returns local anchor", async () => {
    const config = { ...mockConfig, demo: true };
    const client = mockClient(skill2Receipt);
    const result = await handleAttestMemoryContext(
      { memory_sources: [{ type: "vs", id: "p" }] },
      config, client,
    );
    expect(result).toContain("[DEMO MODE");
    expect(result).toContain("SWT3-DEMO-LOCAL");
    expect(client.postWitness).not.toHaveBeenCalled();
  });

  it("agent_id survives level 3", async () => {
    const config = { ...mockConfig, clearingLevel: 3 as const };
    const client = mockClient(skill2Receipt);
    await handleAttestMemoryContext(
      { memory_sources: [{ type: "vs", id: "p" }], agent_id: "agent-x" },
      config, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.agent_id).toBe("agent-x");
  });

  it("signing key produces signature", async () => {
    const config = { ...mockConfig, signingKey: "test-key" };
    const client = mockClient(skill2Receipt);
    await handleAttestMemoryContext(
      { memory_sources: [{ type: "vs", id: "p" }] },
      config, client,
    );
    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.payload_signature).toHaveLength(64);
  });
});
