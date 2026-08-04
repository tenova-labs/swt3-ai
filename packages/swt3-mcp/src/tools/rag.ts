/**
 * SWT3 MCP Server: witness_rag_context tool (AI-RAG.1 / AI-RAG.2).
 *
 * Witnesses RAG retrieval provenance and optional relevance scoring.
 * Chunk text is hashed locally and never sent to the server.
 */

import type { McpConfig } from "../config.js";
import type { AxiomClient, WitnessPayload } from "../client.js";
import {
  mintFingerprint,
  sha256Truncated,
  timestampMs,
  signPayload,
} from "../fingerprint.js";

interface RagContextArgs {
  chunks: string[];
  corpus_id?: string;
  corpus_hash?: string;
  embedding_model?: string;
  retrieval_latency_ms?: number;
  top_k?: number;
  similarity_threshold?: number;
  similarity_scores?: number[];
  agent_id?: string;
  cycle_id?: string;
  clearing_level?: 0 | 1 | 2 | 3;
}

const ACTION_CODES: Record<string, number> = {
  blocked: 3,
  redacted: 2,
  flagged: 1,
  allowed: 0,
};

function buildRag1Payload(
  args: RagContextArgs,
  chunkHashes: string[],
  config: McpConfig,
): WitnessPayload {
  const procedureId = "AI-RAG.1";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;
  const fa = chunkHashes.length;
  const fb = args.corpus_id ? 1 : 0;
  const fc = 0;

  const [ts, epoch] = timestampMs();
  const fp = mintFingerprint(config.tenantId, procedureId, fa, fb, fc, ts);

  const payload: WitnessPayload = {
    procedure_id: procedureId,
    factor_a: fa,
    factor_b: fb,
    factor_c: fc,
    clearing_level: clearingLevel,
    anchor_fingerprint: fp,
    anchor_epoch: epoch,
    fingerprint_timestamp_ms: ts,
  };

  if (clearingLevel <= 1) {
    payload.ai_model_id = args.embedding_model ?? "rag-retrieval";
    const ctx: Record<string, unknown> = {
      provider: "rag",
      chunk_count: chunkHashes.length,
      chunk_hashes: chunkHashes,
    };
    if (args.corpus_id) ctx.corpus_id = args.corpus_id;
    if (args.corpus_hash) ctx.corpus_hash = args.corpus_hash;
    if (args.embedding_model) ctx.embedding_model = args.embedding_model;
    if (args.retrieval_latency_ms != null) ctx.retrieval_latency_ms = args.retrieval_latency_ms;
    if (args.top_k != null) ctx.top_k = args.top_k;
    payload.ai_context = ctx;
  } else if (clearingLevel === 2) {
    payload.ai_model_id = args.embedding_model ?? "rag-retrieval";
    payload.ai_context = { provider_category: "rag" };
  } else {
    payload.ai_model_id = sha256Truncated(args.embedding_model ?? "rag-retrieval");
  }

  if (clearingLevel <= 2 && args.retrieval_latency_ms != null) {
    payload.ai_latency_ms = args.retrieval_latency_ms;
  }

  payload.witness_source = "mcp";
  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  return payload;
}

function buildRag2Payload(
  args: RagContextArgs,
  scores: number[],
  config: McpConfig,
): WitnessPayload {
  const procedureId = "AI-RAG.2";
  const clearingLevel = args.clearing_level ?? config.clearingLevel;
  const threshold = args.similarity_threshold!;
  const avgSim = scores.reduce((a, b) => a + b, 0) / scores.length;
  const belowCount = scores.filter((s) => s < threshold).length;

  const fa = Math.round(threshold * 1000);
  const fb = Math.round(avgSim * 1000);
  const fc = belowCount;

  const [ts, epoch] = timestampMs();
  const fp = mintFingerprint(config.tenantId, procedureId, fa, fb, fc, ts);

  const payload: WitnessPayload = {
    procedure_id: procedureId,
    factor_a: fa,
    factor_b: fb,
    factor_c: fc,
    clearing_level: clearingLevel,
    anchor_fingerprint: fp,
    anchor_epoch: epoch,
    fingerprint_timestamp_ms: ts,
  };

  if (clearingLevel <= 1) {
    payload.ai_model_id = args.embedding_model ?? "rag-retrieval";
    payload.ai_context = {
      provider: "rag",
      similarity_threshold: threshold,
      avg_similarity: Math.round(avgSim * 10000) / 10000,
      min_similarity: Math.round(Math.min(...scores) * 10000) / 10000,
      chunks_below_threshold: belowCount,
      chunk_scores: scores.map((s) => Math.round(s * 10000) / 10000),
    };
  }

  payload.witness_source = "mcp";
  const agentId = args.agent_id || config.agentId;
  if (agentId) payload.agent_id = agentId;
  if (args.cycle_id) payload.cycle_id = args.cycle_id;
  if (config.signingKey) {
    payload.payload_signature = signPayload(config.signingKey, fp, agentId);
  }

  return payload;
}

export async function handleWitnessRagContext(
  args: RagContextArgs,
  config: McpConfig,
  client: AxiomClient,
): Promise<string> {
  // Hash chunks locally -- raw text never leaves the machine
  const chunkHashes = args.chunks.map((chunk) => sha256Truncated(chunk));

  const rag1Payload = buildRag1Payload(args, chunkHashes, config);

  // Check if AI-RAG.2 should be minted
  const shouldMintRag2 =
    args.similarity_threshold != null &&
    args.similarity_scores != null &&
    args.similarity_scores.length > 0;

  if (config.demo) {
    const lines = [
      `[DEMO MODE: local only, not persisted]`,
      ``,
      `RAG Context Witnessed (AI-RAG.1)`,
      `Verdict: PASS`,
      `Anchor: SWT3-DEMO-LOCAL-AI-AIRAG1-PASS-${rag1Payload.anchor_epoch}-${rag1Payload.anchor_fingerprint}`,
      `Chunks: ${chunkHashes.length}`,
      `Corpus: ${args.corpus_id ?? "none"}`,
      `Embedding Model: ${args.embedding_model ?? "unknown"}`,
      `Clearing Level: ${rag1Payload.clearing_level}`,
      `Fingerprint: ${rag1Payload.anchor_fingerprint}`,
    ];

    if (shouldMintRag2) {
      const scores = args.similarity_scores!;
      const avgSim = scores.reduce((a, b) => a + b, 0) / scores.length;
      const belowCount = scores.filter((s) => s < args.similarity_threshold!).length;
      const rag2Payload = buildRag2Payload(args, scores, config);
      lines.push(
        ``,
        `Context Relevance Witnessed (AI-RAG.2)`,
        `Verdict: PASS`,
        `Anchor: SWT3-DEMO-LOCAL-AI-AIRAG2-PASS-${rag2Payload.anchor_epoch}-${rag2Payload.anchor_fingerprint}`,
        `Threshold: ${args.similarity_threshold}`,
        `Avg Similarity: ${Math.round(avgSim * 10000) / 10000}`,
        `Below Threshold: ${belowCount}/${scores.length}`,
        `Fingerprint: ${rag2Payload.anchor_fingerprint}`,
      );
    }

    return lines.join("\n");
  }

  // Live mode -- post witness(es)
  const promises: Array<Promise<{ procedure: string; receipt?: Record<string, unknown>; error?: string }>> = [];

  promises.push(
    client.postWitness(rag1Payload)
      .then((receipt) => ({ procedure: "AI-RAG.1", receipt: receipt as unknown as Record<string, unknown> }))
      .catch((err) => ({ procedure: "AI-RAG.1", error: (err as Error).message })),
  );

  if (shouldMintRag2) {
    const rag2Payload = buildRag2Payload(args, args.similarity_scores!, config);
    promises.push(
      client.postWitness(rag2Payload)
        .then((receipt) => ({ procedure: "AI-RAG.2", receipt: receipt as unknown as Record<string, unknown> }))
        .catch((err) => ({ procedure: "AI-RAG.2", error: (err as Error).message })),
    );
  }

  const results = await Promise.allSettled(promises);
  const lines: string[] = [];

  for (const result of results) {
    const val = result.status === "fulfilled" ? result.value : { procedure: "unknown", error: "unexpected failure" };
    if (val.receipt) {
      const r = val.receipt;
      if (r.tenant_id && !process.env.SWT3_TENANT_ID) config.tenantId = r.tenant_id as string;
      lines.push(
        `${val.procedure === "AI-RAG.1" ? "RAG Context" : "Context Relevance"} Witnessed (${val.procedure})`,
        `Verdict: ${r.verdict}`,
        `Anchor: ${r.swt3_anchor}`,
        `Clearing Level: ${r.clearing_level}`,
        `Witnessed: ${r.witnessed_at}`,
        `Verify: ${config.endpoint}${r.verification_url}`,
        ``,
      );
    } else {
      lines.push(
        `${val.procedure}: Error -- ${val.error}`,
        ``,
      );
    }
  }

  lines.push(
    `Chunks: ${chunkHashes.length}`,
    `Corpus: ${args.corpus_id ?? "none"}`,
    `Embedding Model: ${args.embedding_model ?? "unknown"}`,
    `Fingerprint (RAG.1): ${rag1Payload.anchor_fingerprint}`,
  );

  return lines.join("\n");
}
