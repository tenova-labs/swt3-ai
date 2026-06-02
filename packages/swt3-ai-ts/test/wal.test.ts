/**
 * SWT3 AI Witness SDK -- WAL (Write-Ahead Log) + Replay Protection Tests.
 *
 * Tests crash-resilient buffer and replay protection.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { WriteAheadLog } from "../src/wal.js";
import type { WitnessPayload } from "../src/types.js";

beforeEach(() => {
  vi.spyOn(console, "info").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => vi.restoreAllMocks());

function mkPayload(fingerprint: string, proc = "AI-INF.1"): WitnessPayload {
  return {
    procedure_id: proc,
    factor_a: 1.0,
    factor_b: 0.9,
    factor_c: 0.8,
    clearing_level: 1,
    anchor_fingerprint: fingerprint,
    anchor_epoch: 1234567890,
    fingerprint_timestamp_ms: Date.now(),
    ai_model_id: "gpt-4o",
  };
}

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), "swt3-wal-test-"));
}

describe("WriteAheadLog", () => {
  let walDir: string;
  let wal: WriteAheadLog;

  beforeEach(() => {
    walDir = freshDir();
    wal = new WriteAheadLog("test_tenant", { walDir });
  });

  afterEach(() => {
    wal.destroy();
  });

  it("appends payloads and assigns increasing sequence numbers", () => {
    const s1 = wal.append(mkPayload("fp_001"));
    const s2 = wal.append(mkPayload("fp_002"));
    const s3 = wal.append(mkPayload("fp_003"));
    expect(s1).toBe(1);
    expect(s2).toBe(2);
    expect(s3).toBe(3);
    expect(wal.currentSeq).toBe(3);
  });

  it("persists entries to JSONL file", () => {
    wal.append(mkPayload("fp_persist"));
    const walFile = join(walDir, "test_tenant.wal");
    expect(existsSync(walFile)).toBe(true);
    const lines = readFileSync(walFile, "utf-8").trim().split("\n");
    expect(lines.length).toBe(1);
    const entry = JSON.parse(lines[0]);
    expect(entry.seq).toBe(1);
    expect(entry.fingerprint).toBe("fp_persist");
    expect(entry.payload.procedure_id).toBe("AI-INF.1");
  });

  it("marks flushed and updates checkpoint file", () => {
    wal.append(mkPayload("fp_flush_1"));
    wal.append(mkPayload("fp_flush_2"));
    wal.markFlushed(2);
    expect(wal.currentCheckpoint).toBe(2);
    const ckptFile = join(walDir, "test_tenant.ckpt");
    expect(readFileSync(ckptFile, "utf-8")).toBe("2");
  });

  it("recovers unflushed entries after simulated crash", () => {
    wal.append(mkPayload("fp_crash_1"));
    wal.append(mkPayload("fp_crash_2"));
    wal.append(mkPayload("fp_crash_3"));
    wal.markFlushed(1); // Only first one flushed

    // Simulate crash: create new WAL from same directory
    const wal2 = new WriteAheadLog("test_tenant", { walDir });
    const recovered = wal2.recover();
    expect(recovered.length).toBe(2);
    expect((recovered[0] as any).anchor_fingerprint).toBe("fp_crash_2");
    expect((recovered[1] as any).anchor_fingerprint).toBe("fp_crash_3");
    wal2.destroy();
  });

  it("returns empty array when no unflushed entries", () => {
    wal.append(mkPayload("fp_all_flushed"));
    wal.markFlushed(1);
    const wal2 = new WriteAheadLog("test_tenant", { walDir });
    const recovered = wal2.recover();
    expect(recovered.length).toBe(0);
    wal2.destroy();
  });
});

describe("Replay Protection", () => {
  let walDir: string;
  let wal: WriteAheadLog;

  beforeEach(() => {
    walDir = freshDir();
    wal = new WriteAheadLog("test_tenant", { walDir });
  });

  afterEach(() => {
    wal.destroy();
  });

  it("rejects duplicate fingerprints", () => {
    const s1 = wal.append(mkPayload("fp_dup"));
    const s2 = wal.append(mkPayload("fp_dup"));
    expect(s1).toBe(1);
    expect(s2).toBe(-1); // Duplicate rejected
    expect(wal.currentSeq).toBe(1); // Seq not incremented
  });

  it("allows different fingerprints", () => {
    const s1 = wal.append(mkPayload("fp_unique_1"));
    const s2 = wal.append(mkPayload("fp_unique_2"));
    expect(s1).toBe(1);
    expect(s2).toBe(2);
  });

  it("isDuplicate returns true for seen fingerprints", () => {
    wal.append(mkPayload("fp_check"));
    expect(wal.isDuplicate("fp_check")).toBe(true);
    expect(wal.isDuplicate("fp_unseen")).toBe(false);
  });

  it("populates replay set from existing WAL on startup", () => {
    wal.append(mkPayload("fp_startup_1"));
    wal.append(mkPayload("fp_startup_2"));

    // Create new WAL from same dir (simulates restart)
    const wal2 = new WriteAheadLog("test_tenant", { walDir });
    expect(wal2.isDuplicate("fp_startup_1")).toBe(true);
    expect(wal2.isDuplicate("fp_startup_2")).toBe(true);
    expect(wal2.isDuplicate("fp_new")).toBe(false);
    wal2.destroy();
  });

  it("evicts oldest fingerprints when replay window exceeded", () => {
    const smallWal = new WriteAheadLog("test_evict", {
      walDir,
      replayWindow: 3,
    });

    smallWal.append(mkPayload("fp_evict_1"));
    smallWal.append(mkPayload("fp_evict_2"));
    smallWal.append(mkPayload("fp_evict_3"));
    expect(smallWal.replaySetSize).toBe(3);

    smallWal.append(mkPayload("fp_evict_4")); // Should evict fp_evict_1
    expect(smallWal.replaySetSize).toBe(3);
    expect(smallWal.isDuplicate("fp_evict_1")).toBe(false); // Evicted
    expect(smallWal.isDuplicate("fp_evict_4")).toBe(true); // Present
    smallWal.destroy();
  });

  it("can disable replay protection", () => {
    const noReplay = new WriteAheadLog("test_noreplay", {
      walDir,
      replayProtection: false,
    });

    const s1 = noReplay.append(mkPayload("fp_norep"));
    const s2 = noReplay.append(mkPayload("fp_norep")); // Same fingerprint
    expect(s1).toBe(1);
    expect(s2).toBe(2); // Not rejected
    expect(noReplay.isDuplicate("fp_norep")).toBe(false); // Always false
    noReplay.destroy();
  });
});

describe("WAL Rotation", () => {
  it("handles empty WAL gracefully", () => {
    const walDir = freshDir();
    const wal = new WriteAheadLog("test_empty", { walDir });
    expect(wal.currentSeq).toBe(0);
    expect(wal.recover()).toEqual([]);
    wal.destroy();
  });

  it("survives corrupted WAL lines", () => {
    const walDir = freshDir();
    const wal = new WriteAheadLog("test_corrupt", { walDir });
    wal.append(mkPayload("fp_ok"));

    // Inject corruption
    const walFile = join(walDir, "test_corrupt.wal");
    const { appendFileSync } = require("node:fs");
    appendFileSync(walFile, "this is not json\n", "utf-8");
    wal.append(mkPayload("fp_after_corrupt"));

    // New WAL should skip corrupted line
    const wal2 = new WriteAheadLog("test_corrupt", { walDir });
    expect(wal2.currentSeq).toBe(2);
    wal2.destroy();
  });

  it("tenant scoping isolates WAL files", () => {
    const walDir = freshDir();
    const wal1 = new WriteAheadLog("tenant_a", { walDir });
    const wal2 = new WriteAheadLog("tenant_b", { walDir });

    wal1.append(mkPayload("fp_a"));
    wal2.append(mkPayload("fp_b"));

    expect(wal1.isDuplicate("fp_b")).toBe(false);
    expect(wal2.isDuplicate("fp_a")).toBe(false);
    wal1.destroy();
    wal2.destroy();
  });
});
