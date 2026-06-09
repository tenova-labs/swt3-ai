/**
 * SWT3 MCP Server: Redis Stream Reader for real-time anchor freshness.
 *
 * Subscribes to the swt3:anchors Redis stream as a separate consumer group
 * (swt3-mcp-verifiers) and maintains an in-memory index for 0ms lookups.
 * The chain verifier queries this index before falling back to the persistent ledger.
 *
 * Architecture:
 *   - Consumer group: swt3-mcp-verifiers (separate from swt3-processors)
 *   - XREADGROUP with BLOCK for backpressure-friendly consumption
 *   - In-memory index keyed by agent_id and cycle_id
 *   - TTL eviction (1 hour) + max entries (10,000 LRU)
 *
 * Patent pending.
 */

import { hostname } from "node:os";

// ── Types ───────────────────────────────────────────────────────────���─

export interface AnchorEntry {
  messageId: string;
  procedure_id: string;
  anchor_fingerprint: string;
  anchor_epoch: number;
  agent_id?: string;
  cycle_id?: string;
  provider?: string;
  payload_signature?: string;
  verdict?: string;
  ai_input_tokens?: number;
  ai_output_tokens?: number;
  clearing_level?: number;
  receivedAt: number; // local timestamp for TTL
}

export interface RedisReaderState {
  running: boolean;
  connected: boolean;
  entriesCount: number;
  lastMessageId: string;
}

interface RedisReaderConfig {
  redisUrl: string;
  streamName: string;
  groupName: string;
  maxEntries: number;
  ttlMs: number;
}

// ── Constants ──────────────────────────────────────────��──────────────

const DEFAULT_GROUP = "swt3-mcp-verifiers";
const DEFAULT_STREAM = "swt3:anchors";
const DEFAULT_MAX_ENTRIES = parseInt(process.env.SWT3_READER_MAX_ENTRIES || "10000", 10);
const DEFAULT_TTL_MS = parseInt(process.env.SWT3_READER_TTL_MINUTES || "60", 10) * 60 * 1000;
const EVICTION_INTERVAL_MS = 60_000; // 60 seconds
const READ_BLOCK_MS = 2000; // block 2s per read cycle
const READ_COUNT = 100; // messages per read

// ── Module State ───────────────��──────────────────────────────────────

let redis: any = null;
let running = false;
let readLoopPromise: Promise<void> | null = null;
let evictionTimer: ReturnType<typeof setInterval> | null = null;
let config: RedisReaderConfig | null = null;

// In-memory indices
const byAgent = new Map<string, AnchorEntry[]>();
const byCycle = new Map<string, AnchorEntry[]>();
const allEntries: AnchorEntry[] = [];

// ── Public API ────────────────────────��───────────────────────────────

/**
 * Start the Redis stream reader. No-op if already running or ioredis unavailable.
 */
export async function startRedisReader(opts: {
  redisUrl?: string;
  streamName?: string;
}): Promise<boolean> {
  if (running) return true;

  let Redis: any;
  try {
    Redis = (await import("ioredis")).default;
  } catch {
    // ioredis not installed -- graceful degradation
    return false;
  }

  config = {
    redisUrl: opts.redisUrl || process.env.SWT3_REDIS_URL || "redis://localhost:6379",
    streamName: opts.streamName || process.env.SWT3_REDIS_STREAM || DEFAULT_STREAM,
    groupName: DEFAULT_GROUP,
    maxEntries: DEFAULT_MAX_ENTRIES,
    ttlMs: DEFAULT_TTL_MS,
  };

  try {
    redis = new Redis(config.redisUrl, {
      maxRetriesPerRequest: 3,
      retryStrategy: (times: number) => (times > 5 ? null : Math.min(times * 200, 2000)),
      lazyConnect: true,
    });
    await redis.connect();
  } catch {
    redis = null;
    return false;
  }

  // Create consumer group (idempotent)
  try {
    await redis.xgroup("CREATE", config.streamName, config.groupName, "$", "MKSTREAM");
  } catch (err: any) {
    // BUSYGROUP = group already exists, fine
    if (!err.message?.includes("BUSYGROUP")) {
      redis.disconnect();
      redis = null;
      return false;
    }
  }

  running = true;

  // Start background read loop
  readLoopPromise = readLoop();

  // Start TTL eviction timer
  evictionTimer = setInterval(evictStale, EVICTION_INTERVAL_MS);

  return true;
}

/**
 * Stop the Redis reader gracefully.
 */
export async function stopRedisReader(): Promise<void> {
  running = false;

  if (evictionTimer) {
    clearInterval(evictionTimer);
    evictionTimer = null;
  }

  if (readLoopPromise) {
    await readLoopPromise;
    readLoopPromise = null;
  }

  if (redis) {
    try {
      redis.disconnect();
    } catch { /* ignore */ }
    redis = null;
  }

  // Clear indices
  byAgent.clear();
  byCycle.clear();
  allEntries.length = 0;
}

/**
 * Query cached anchors by agent_id and/or cycle_id.
 * Returns empty array if Redis reader not running.
 */
export function queryAnchors(agentId?: string, cycleId?: string): AnchorEntry[] {
  if (!running) return [];

  // If both provided, intersect
  if (agentId && cycleId) {
    const agentAnchors = byAgent.get(agentId) || [];
    const cycleSet = new Set((byCycle.get(cycleId) || []).map((e) => e.messageId));
    return agentAnchors.filter((e) => cycleSet.has(e.messageId));
  }

  if (agentId) return byAgent.get(agentId) || [];
  if (cycleId) return byCycle.get(cycleId) || [];

  return [];
}

/**
 * Get reader state for health/diagnostics.
 */
export function getReaderState(): RedisReaderState | null {
  if (!running) return null;
  return {
    running,
    connected: redis?.status === "ready",
    entriesCount: allEntries.length,
    lastMessageId: allEntries.length > 0 ? allEntries[allEntries.length - 1].messageId : "0-0",
  };
}

// ── Internal: Read Loop ──────────────────────��────────────────────────

async function readLoop(): Promise<void> {
  const consumer = `mcp-${hostname()}-${process.pid}`;

  while (running && redis && config) {
    try {
      const results = await redis.xreadgroup(
        "GROUP", config.groupName, consumer,
        "COUNT", READ_COUNT,
        "BLOCK", READ_BLOCK_MS,
        "STREAMS", config.streamName, ">",
      );

      if (!results || !running) continue;

      const idsToAck: string[] = [];

      for (const [, messages] of results) {
        for (const [id, fields] of messages) {
          const entry = parseStreamMessage(id, fields);
          if (entry) {
            indexEntry(entry);
            idsToAck.push(id);
          }
        }
      }

      // ACK processed messages
      if (idsToAck.length > 0) {
        await redis.xack(config.streamName, config.groupName, ...idsToAck);
      }
    } catch (err: any) {
      // Connection lost -- wait briefly then retry
      if (running) {
        await sleep(1000);
      }
    }
  }
}

// ── Internal: Parse & Index ───────────────────────────────────────────

function parseStreamMessage(id: string, fields: string[]): AnchorEntry | null {
  const map: Record<string, string> = {};
  for (let i = 0; i < fields.length; i += 2) {
    map[fields[i]] = fields[i + 1];
  }

  // Require at minimum: procedure_id and anchor_fingerprint
  if (!map.procedure_id || !map.anchor_fingerprint) return null;

  return {
    messageId: id,
    procedure_id: map.procedure_id,
    anchor_fingerprint: map.anchor_fingerprint,
    anchor_epoch: parseInt(map.anchor_epoch || "0", 10),
    agent_id: map.agent_id || undefined,
    cycle_id: map.cycle_id || undefined,
    provider: map.provider || map.witness_source || undefined,
    payload_signature: map.payload_signature || undefined,
    verdict: map.verdict || undefined,
    ai_input_tokens: map.ai_input_tokens ? parseInt(map.ai_input_tokens, 10) : undefined,
    ai_output_tokens: map.ai_output_tokens ? parseInt(map.ai_output_tokens, 10) : undefined,
    clearing_level: map.clearing_level ? parseInt(map.clearing_level, 10) : undefined,
    receivedAt: Date.now(),
  };
}

function indexEntry(entry: AnchorEntry): void {
  // Enforce max entries (LRU: drop oldest)
  if (allEntries.length >= (config?.maxEntries ?? DEFAULT_MAX_ENTRIES)) {
    const evicted = allEntries.shift();
    if (evicted) removeFromIndices(evicted);
  }

  allEntries.push(entry);

  if (entry.agent_id) {
    const list = byAgent.get(entry.agent_id) || [];
    list.push(entry);
    byAgent.set(entry.agent_id, list);
  }

  if (entry.cycle_id) {
    const list = byCycle.get(entry.cycle_id) || [];
    list.push(entry);
    byCycle.set(entry.cycle_id, list);
  }
}

function removeFromIndices(entry: AnchorEntry): void {
  if (entry.agent_id) {
    const list = byAgent.get(entry.agent_id);
    if (list) {
      const idx = list.indexOf(entry);
      if (idx >= 0) list.splice(idx, 1);
      if (list.length === 0) byAgent.delete(entry.agent_id);
    }
  }
  if (entry.cycle_id) {
    const list = byCycle.get(entry.cycle_id);
    if (list) {
      const idx = list.indexOf(entry);
      if (idx >= 0) list.splice(idx, 1);
      if (list.length === 0) byCycle.delete(entry.cycle_id);
    }
  }
}

// ── Internal: Eviction ────────────────���───────────────────────────────

function evictStale(): void {
  const cutoff = Date.now() - (config?.ttlMs ?? DEFAULT_TTL_MS);
  while (allEntries.length > 0 && allEntries[0].receivedAt < cutoff) {
    const evicted = allEntries.shift()!;
    removeFromIndices(evicted);
  }
}

// ── Utility ─────────────────��─────────────────────────────��───────────

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
