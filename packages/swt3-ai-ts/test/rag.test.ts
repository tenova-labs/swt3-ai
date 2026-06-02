/**
 * RAG context witnessing tests (TypeScript).
 *
 * Tests for witnessRagContext() -- AI-RAG.1 (Context Retrieval Provenance)
 * and AI-RAG.2 (Context Relevance).
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Witness } from "../src/witness.js";
import type { RagChunk, WitnessPayload } from "../src/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeWitness(clearingLevel: 0 | 1 | 2 | 3 = 1): Witness {
  const w = new Witness({
    endpoint: "https://test.tenova.io",
    apiKey: "axm_test_key",
    tenantId: "TEST_TENANT",
    clearingLevel,
  });
  // Mock the buffer to prevent network calls
  (w as any).buffer = {
    enqueueMany: vi.fn(),
    flush: vi.fn().mockResolvedValue([]),
    stop: vi.fn().mockResolvedValue([]),
    pending: 0,
    receipts: [],
  };
  return w;
}

// ---------------------------------------------------------------------------
// AI-RAG.1: Context Retrieval Provenance
// ---------------------------------------------------------------------------

describe("witnessRagContext - string chunks", () => {
  it("witnesses basic string chunks", () => {
    const w = makeWitness();
    const payloads = w.witnessRagContext({
      chunks: ["chunk one", "chunk two", "chunk three"],
      corpusId: "legal-docs-v3",
    });

    expect(payloads).toHaveLength(1);
    const p = payloads[0];
    expect(p.procedure_id).toBe("AI-RAG.1");
    expect(p.factor_a).toBe(3); // 3 chunks
    expect(p.factor_b).toBe(1); // corpus identified
    expect(p.factor_c).toBe(0); // reserved
    expect(p.anchor_fingerprint).toBeTruthy();
    expect(p.ai_context).toBeDefined();
    expect(p.ai_context!.provider).toBe("rag");
    expect(p.ai_context!.chunk_count).toBe(3);
    expect((p.ai_context!.chunk_hashes as string[]).length).toBe(3);
    expect(p.ai_context!.corpus_id).toBe("legal-docs-v3");
  });

  it("handles anonymous retrieval", () => {
    const w = makeWitness();
    const payloads = w.witnessRagContext({ chunks: ["chunk"] });

    expect(payloads[0].factor_b).toBe(0); // no corpus
    expect(payloads[0].ai_context!.corpus_id).toBeUndefined();
  });

  it("auto-hashes deterministically", () => {
    const w = makeWitness();
    const p1 = w.witnessRagContext({ chunks: ["same text"] })[0];
    const p2 = w.witnessRagContext({ chunks: ["same text"] })[0];

    expect((p1.ai_context!.chunk_hashes as string[])[0]).toBe(
      (p2.ai_context!.chunk_hashes as string[])[0],
    );
  });

  it("different text produces different hash", () => {
    const w = makeWitness();
    const p1 = w.witnessRagContext({ chunks: ["text A"] })[0];
    const p2 = w.witnessRagContext({ chunks: ["text B"] })[0];

    expect((p1.ai_context!.chunk_hashes as string[])[0]).not.toBe(
      (p2.ai_context!.chunk_hashes as string[])[0],
    );
  });
});

describe("witnessRagContext - RagChunk objects", () => {
  it("uses pre-hashed chunks with full metadata", () => {
    const w = makeWitness();
    const chunks: RagChunk[] = [
      { contentHash: "abc123def456", sourceId: "doc-7/p3", similarityScore: 0.92 },
      { contentHash: "789012345678", sourceId: "doc-2/p1", similarityScore: 0.78 },
    ];
    const payloads = w.witnessRagContext({
      chunks,
      corpusId: "legal-docs-v3",
      corpusHash: "fedcba987654",
      embeddingModel: "text-embedding-3-small",
      retrievalLatencyMs: 124,
      topK: 10,
    });

    expect(payloads).toHaveLength(1); // no threshold, no AI-RAG.2
    const p = payloads[0];
    expect(p.factor_a).toBe(2);
    expect(p.ai_context!.chunk_hashes).toEqual(["abc123def456", "789012345678"]);
    expect(p.ai_context!.corpus_hash).toBe("fedcba987654");
    expect(p.ai_context!.embedding_model).toBe("text-embedding-3-small");
    expect(p.ai_context!.retrieval_latency_ms).toBe(124);
    expect(p.ai_context!.top_k).toBe(10);
    expect(p.ai_latency_ms).toBe(124);
  });
});

// ---------------------------------------------------------------------------
// AI-RAG.2: Context Relevance (conditional dual-emit)
// ---------------------------------------------------------------------------

describe("witnessRagContext - dual emit (AI-RAG.2)", () => {
  it("emits both procedures when threshold and scores present", () => {
    const w = makeWitness();
    const chunks: RagChunk[] = [
      { contentHash: "aaa", similarityScore: 0.92 },
      { contentHash: "bbb", similarityScore: 0.85 },
      { contentHash: "ccc", similarityScore: 0.61 },
    ];
    const payloads = w.witnessRagContext({
      chunks,
      corpusId: "my-corpus",
      similarityThreshold: 0.75,
    });

    expect(payloads).toHaveLength(2);

    // AI-RAG.1
    expect(payloads[0].procedure_id).toBe("AI-RAG.1");
    expect(payloads[0].factor_a).toBe(3);

    // AI-RAG.2
    const p2 = payloads[1];
    expect(p2.procedure_id).toBe("AI-RAG.2");
    expect(p2.factor_a).toBe(750); // threshold * 1000
    const avg = (0.92 + 0.85 + 0.61) / 3;
    expect(p2.factor_b).toBe(Math.round(avg * 1000));
    expect(p2.factor_c).toBe(1); // 1 chunk below 0.75
    expect(p2.ai_context!.similarity_threshold).toBe(0.75);
    expect(p2.ai_context!.chunks_below_threshold).toBe(1);
    expect(p2.ai_context!.min_similarity).toBe(0.61);
  });

  it("does not emit AI-RAG.2 without threshold", () => {
    const w = makeWitness();
    const chunks: RagChunk[] = [{ contentHash: "aaa", similarityScore: 0.92 }];
    const payloads = w.witnessRagContext({ chunks });

    expect(payloads).toHaveLength(1);
    expect(payloads[0].procedure_id).toBe("AI-RAG.1");
  });

  it("does not emit AI-RAG.2 without scores", () => {
    const w = makeWitness();
    const payloads = w.witnessRagContext({
      chunks: ["text without scores"],
      similarityThreshold: 0.75,
    });

    expect(payloads).toHaveLength(1); // strings have no scores
  });

  it("handles all chunks above threshold", () => {
    const w = makeWitness();
    const chunks: RagChunk[] = [
      { contentHash: "aaa", similarityScore: 0.92 },
      { contentHash: "bbb", similarityScore: 0.85 },
    ];
    const payloads = w.witnessRagContext({
      chunks,
      similarityThreshold: 0.75,
    });

    expect(payloads).toHaveLength(2);
    expect(payloads[1].factor_c).toBe(0); // none below threshold
  });
});

// ---------------------------------------------------------------------------
// Clearing level behavior
// ---------------------------------------------------------------------------

describe("witnessRagContext - clearing levels", () => {
  it("level 0: full metadata", () => {
    const w = makeWitness(0);
    const payloads = w.witnessRagContext({
      chunks: ["chunk"],
      corpusId: "corp",
      retrievalLatencyMs: 50,
    });
    const p = payloads[0];
    expect(p.ai_context).toBeDefined();
    expect(p.ai_context!.corpus_id).toBe("corp");
    expect(p.ai_latency_ms).toBe(50);
  });

  it("level 1: full metadata", () => {
    const w = makeWitness(1);
    const payloads = w.witnessRagContext({ chunks: ["chunk"], corpusId: "corp" });
    const p = payloads[0];
    expect(p.ai_context).toBeDefined();
    expect(p.ai_model_id).toBeTruthy();
  });

  it("level 2: strips ai_context", () => {
    const w = makeWitness(2);
    const payloads = w.witnessRagContext({
      chunks: ["chunk"],
      corpusId: "corp",
      retrievalLatencyMs: 50,
    });
    const p = payloads[0];
    expect(p.ai_context).toBeUndefined(); // stripped at level 2
    expect(p.ai_model_id).toBeUndefined(); // no model at level 2
    expect(p.ai_latency_ms).toBe(50); // latency survives level 2
  });

  it("level 3: factors only", () => {
    const w = makeWitness(3);
    const payloads = w.witnessRagContext({
      chunks: ["chunk"],
      corpusId: "corp",
      retrievalLatencyMs: 50,
    });
    const p = payloads[0];
    expect(p.ai_context).toBeUndefined();
    expect(p.ai_model_id).toBeUndefined();
    expect(p.ai_latency_ms).toBeUndefined(); // stripped at level 3
    // Factors always survive
    expect(p.factor_a).toBe(1);
    expect(p.factor_b).toBe(1);
    expect(p.factor_c).toBe(0);
  });

  it("level 2: strips AI-RAG.2 context", () => {
    const w = makeWitness(2);
    const chunks: RagChunk[] = [{ contentHash: "aaa", similarityScore: 0.92 }];
    const payloads = w.witnessRagContext({
      chunks,
      similarityThreshold: 0.75,
    });
    expect(payloads).toHaveLength(2);
    expect(payloads[1].ai_context).toBeUndefined();
    expect(payloads[1].factor_a).toBe(750); // factors survive
  });
});
