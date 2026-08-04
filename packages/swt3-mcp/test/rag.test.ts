import { describe, it, expect, vi } from "vitest";
import { handleWitnessRagContext } from "../src/tools/rag.js";
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
  verdict: "PASS",
  clearing_level: 1,
  witnessed_at: "2026-07-29T10:00:00Z",
  verification_url: "/api/v1/attest/verify?token=SWT3-...",
};

describe("witness_rag_context tool", () => {
  it("mints AI-RAG.1 with chunk hashes", async () => {
    const client = mockClient({
      ...baseReceipt,
      procedure_id: "AI-RAG.1",
      swt3_anchor: "SWT3-E-TEST-AI-AIRAG1-PASS-1700000000-abcdef123456",
    });

    const result = await handleWitnessRagContext(
      { chunks: ["hello world", "second chunk"] },
      mockConfig,
      client,
    );

    expect(result).toContain("RAG Context Witnessed (AI-RAG.1)");
    expect(result).toContain("Verdict: PASS");
    expect(result).toContain("Chunks: 2");

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.procedure_id).toBe("AI-RAG.1");
    expect(call.factor_a).toBe(2); // chunk count
    expect(call.factor_b).toBe(0); // no corpus
    expect(call.anchor_fingerprint).toHaveLength(12);
    // Raw text must NOT appear in payload
    expect(JSON.stringify(call)).not.toContain("hello world");
    expect(call.ai_context.chunk_hashes).toHaveLength(2);
  });

  it("sets factor_b=1 when corpus_id provided", async () => {
    const client = mockClient({
      ...baseReceipt,
      procedure_id: "AI-RAG.1",
      swt3_anchor: "SWT3-...",
    });

    await handleWitnessRagContext(
      { chunks: ["text"], corpus_id: "legal-docs-v3" },
      mockConfig,
      client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.factor_b).toBe(1);
    expect(call.ai_context.corpus_id).toBe("legal-docs-v3");
  });

  it("mints AI-RAG.2 when similarity_threshold and scores provided", async () => {
    const client = mockClient({
      ...baseReceipt,
      procedure_id: "AI-RAG.1",
      swt3_anchor: "SWT3-RAG1",
    });
    // Second call for RAG.2
    (client.postWitness as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ...baseReceipt,
      procedure_id: "AI-RAG.1",
      swt3_anchor: "SWT3-RAG1",
    }).mockResolvedValueOnce({
      ...baseReceipt,
      procedure_id: "AI-RAG.2",
      swt3_anchor: "SWT3-RAG2",
    });

    const result = await handleWitnessRagContext(
      {
        chunks: ["chunk1", "chunk2", "chunk3"],
        similarity_threshold: 0.7,
        similarity_scores: [0.9, 0.6, 0.8],
      },
      mockConfig,
      client,
    );

    expect(result).toContain("RAG Context Witnessed (AI-RAG.1)");
    expect(result).toContain("Context Relevance Witnessed (AI-RAG.2)");
    expect((client.postWitness as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(2);

    const rag2Call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[1][0];
    expect(rag2Call.procedure_id).toBe("AI-RAG.2");
    expect(rag2Call.factor_a).toBe(700); // threshold * 1000
    expect(rag2Call.factor_c).toBe(1); // 1 chunk below threshold
  });

  it("does NOT mint RAG.2 without similarity_scores", async () => {
    const client = mockClient({
      ...baseReceipt,
      procedure_id: "AI-RAG.1",
      swt3_anchor: "SWT3-RAG1",
    });

    await handleWitnessRagContext(
      { chunks: ["chunk1"], similarity_threshold: 0.7 },
      mockConfig,
      client,
    );

    expect((client.postWitness as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(1);
  });

  it("handles partial failure (RAG.2 fails)", async () => {
    const client = {
      postWitness: vi.fn()
        .mockResolvedValueOnce({
          ...baseReceipt,
          procedure_id: "AI-RAG.1",
          swt3_anchor: "SWT3-RAG1",
        })
        .mockRejectedValueOnce(new Error("server error")),
    } as unknown as AxiomClient;

    const result = await handleWitnessRagContext(
      {
        chunks: ["c1"],
        similarity_threshold: 0.5,
        similarity_scores: [0.8],
      },
      mockConfig,
      client,
    );

    expect(result).toContain("RAG Context Witnessed (AI-RAG.1)");
    expect(result).toContain("AI-RAG.2: Error");
  });

  it("works in demo mode", async () => {
    const client = mockClient(baseReceipt);

    const result = await handleWitnessRagContext(
      { chunks: ["demo chunk"], corpus_id: "test-corpus" },
      demoConfig,
      client,
    );

    expect(result).toContain("DEMO MODE");
    expect(result).toContain("AI-RAG.1");
    expect(result).toContain("Corpus: test-corpus");
    expect((client.postWitness as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(0);
  });

  it("demo mode shows RAG.2 when scores provided", async () => {
    const client = mockClient(baseReceipt);

    const result = await handleWitnessRagContext(
      {
        chunks: ["c1", "c2"],
        similarity_threshold: 0.5,
        similarity_scores: [0.8, 0.3],
      },
      demoConfig,
      client,
    );

    expect(result).toContain("AI-RAG.1");
    expect(result).toContain("AI-RAG.2");
    expect(result).toContain("Below Threshold: 1/2");
  });

  it("strips context at clearing level 3", async () => {
    const cl3Config = { ...mockConfig, clearingLevel: 3 as const };
    const client = mockClient({
      ...baseReceipt,
      procedure_id: "AI-RAG.1",
      swt3_anchor: "SWT3-...",
    });

    await handleWitnessRagContext(
      { chunks: ["secret"], embedding_model: "text-embedding-3" },
      cl3Config,
      client,
    );

    const call = (client.postWitness as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call.ai_context).toBeUndefined();
    expect(call.ai_model_id).not.toBe("text-embedding-3"); // hashed
    expect(call.ai_model_id).toHaveLength(16); // sha256Truncated default
  });
});
