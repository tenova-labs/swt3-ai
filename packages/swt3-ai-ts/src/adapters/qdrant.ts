/**
 * SWT3 AI Witness SDK -- Qdrant Vector Database Adapter.
 *
 * Wraps the Qdrant JavaScript/TypeScript client to witness vector search
 * operations. Mints AI-RAG.1 anchors for each retrieval, creating
 * database-level compliance evidence for RAG pipelines.
 *
 * Usage:
 *   import { QdrantClient } from "@qdrant/js-client-rest";
 *   import { wrapQdrant } from "@tenova/swt3-ai/adapters/qdrant";
 *
 *   const witness = new Witness({ endpoint: "...", apiKey: "...", tenantId: "..." });
 *   const client = new QdrantClient({ url: "http://localhost:6333" });
 *   const witnessed = wrapQdrant(client, witness);
 *
 *   const results = await witnessed.search("docs", { vector: [...], limit: 10 });
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import type { Witness } from "../witness.js";

const INTERCEPTED = new Set(["search", "query"]);

/**
 * Wrap a QdrantClient with an ES6 Proxy for transparent RAG witnessing.
 *
 * Intercepts search() and query() to mint AI-RAG.1 anchors for every
 * vector retrieval operation.
 */
export function wrapQdrant(client: unknown, witness: Witness): unknown {
  return new Proxy(client as object, {
    get(target: object, prop: string | symbol): unknown {
      if (typeof prop === "symbol") return Reflect.get(target, prop);
      const real = Reflect.get(target, prop);

      if (INTERCEPTED.has(prop) && typeof real === "function") {
        return createSearchInterceptor(
          real as (...args: unknown[]) => unknown,
          witness,
          prop,
          target,
        );
      }

      return real;
    },
  });
}

function createSearchInterceptor(
  realMethod: (...args: unknown[]) => unknown,
  witness: Witness,
  methodName: string,
  target: object,
): (...args: unknown[]) => unknown {
  return function interceptedSearch(this: unknown, ...args: unknown[]): unknown {
    // -- Extract parameters --
    const collectionName = extractCollectionName(args, methodName);
    const opts = extractOptions(args, methodName);
    const limit = (opts.limit as number) ?? (opts.top as number) ?? 10;
    const scoreThreshold = opts.score_threshold as number | undefined;

    const start = performance.now();

    const result = realMethod.call(target, ...args);

    // Qdrant JS client is async -- result is a Promise
    if (result && typeof (result as Promise<unknown>).then === "function") {
      return (result as Promise<unknown>).then((response: unknown) => {
        const elapsedMs = Math.round(performance.now() - start);
        witnessSearch(witness, response, collectionName, limit, scoreThreshold, elapsedMs, methodName);
        return response;
      });
    }

    // Synchronous fallback (unlikely but safe)
    const elapsedMs = Math.round(performance.now() - start);
    witnessSearch(witness, result, collectionName, limit, scoreThreshold, elapsedMs, methodName);
    return result;
  };
}

function witnessSearch(
  witness: Witness,
  result: unknown,
  collectionName: string,
  limit: number,
  scoreThreshold: number | undefined,
  elapsedMs: number,
  methodName: string,
): void {
  const resultCount = countResults(result);
  const chunkIds = extractChunkIds(result);
  const chunks = chunkIds.length > 0 ? chunkIds : Array(resultCount).fill("search-result");
  const modelId = collectionName ? `qdrant-${collectionName}` : "qdrant-unknown";

  witness.witnessRagContext({
    chunks,
    corpusId: collectionName,
    embeddingModel: modelId,
    retrievalLatencyMs: elapsedMs,
    topK: typeof limit === "number" ? limit : undefined,
    similarityThreshold: scoreThreshold,
  });
}

function extractCollectionName(args: unknown[], methodName: string): string {
  // search(collectionName, opts) or query(collectionName, opts)
  if (args.length > 0 && typeof args[0] === "string") {
    return args[0];
  }
  // Object-style: search({ collection_name: "..." })
  if (args.length > 0 && typeof args[0] === "object" && args[0] !== null) {
    const obj = args[0] as Record<string, unknown>;
    if (typeof obj.collection_name === "string") return obj.collection_name;
    if (typeof obj.collectionName === "string") return obj.collectionName;
  }
  return "unknown";
}

function extractOptions(args: unknown[], methodName: string): Record<string, unknown> {
  // search(collectionName, opts) -- opts is second arg
  if (args.length >= 2 && typeof args[0] === "string" && typeof args[1] === "object" && args[1] !== null) {
    return args[1] as Record<string, unknown>;
  }
  // Object-style: search({ collection_name, limit, ... })
  if (args.length > 0 && typeof args[0] === "object" && args[0] !== null) {
    return args[0] as Record<string, unknown>;
  }
  return {};
}

function countResults(result: unknown): number {
  // search() returns ScoredPoint[]
  if (Array.isArray(result)) return result.length;
  // query() returns { points: ScoredPoint[] }
  if (result && typeof result === "object") {
    const r = result as Record<string, unknown>;
    if (Array.isArray(r.points)) return r.points.length;
  }
  return 0;
}

function extractChunkIds(result: unknown): string[] {
  let points: unknown[] = [];

  if (Array.isArray(result)) {
    points = result;
  } else if (result && typeof result === "object") {
    const r = result as Record<string, unknown>;
    if (Array.isArray(r.points)) points = r.points;
  }

  const ids: string[] = [];
  for (const point of points) {
    if (point && typeof point === "object") {
      const p = point as Record<string, unknown>;
      if (p.id !== undefined && p.id !== null) {
        ids.push(String(p.id));
      }
    }
  }
  return ids;
}
