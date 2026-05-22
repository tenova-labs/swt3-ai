/**
 * SWT3 AI Witness SDK -- Write-Ahead Log (WAL).
 *
 * Crash-resilient buffer persistence. Payloads are written to a JSONL
 * file before network transmission. If the process crashes, unsent
 * entries survive on disk and replay on next startup.
 *
 * Format:
 *   Each line: JSON object with { seq, fingerprint, payload }
 *   Checkpoint file: single number (last successfully flushed seq)
 *
 * Replay protection:
 *   A bounded set of recently-seen anchor_fingerprint values prevents
 *   duplicate witness anchors from being submitted. The set is populated
 *   from the WAL on startup and updated on each enqueue.
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import { mkdirSync, appendFileSync, readFileSync, writeFileSync, existsSync, renameSync, unlinkSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import type { WitnessPayload } from "./types.js";

/** Default WAL directory under OS temp. */
const DEFAULT_WAL_DIR = join(tmpdir(), "swt3-wal");

/** Maximum fingerprints tracked for replay protection. */
const DEFAULT_REPLAY_WINDOW = 50_000;

/** WAL file rotation threshold (5 MB). */
const WAL_ROTATION_BYTES = 5 * 1024 * 1024;

interface WalEntry {
  seq: number;
  fingerprint: string;
  payload: Record<string, unknown>;
}

export interface WalOptions {
  /** Directory for WAL files. Default: $TMPDIR/swt3-wal */
  walDir?: string;
  /** Max fingerprints in replay protection set. Default: 50000 */
  replayWindow?: number;
  /** Enable replay protection (dedup). Default: true when WAL enabled */
  replayProtection?: boolean;
}

export class WriteAheadLog {
  private walPath: string;
  private checkpointPath: string;
  private seq: number = 0;
  private checkpoint: number = 0;
  private replaySet: Set<string>;
  private replayWindow: number;
  private replayEnabled: boolean;

  constructor(tenantId: string, options: WalOptions = {}) {
    const dir = options.walDir ?? DEFAULT_WAL_DIR;
    this.replayWindow = options.replayWindow ?? DEFAULT_REPLAY_WINDOW;
    this.replayEnabled = options.replayProtection ?? true;
    this.replaySet = new Set();

    // Tenant-scoped WAL file (multiple SDK instances on same machine)
    const safe = tenantId.replace(/[^a-zA-Z0-9_-]/g, "_");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.walPath = join(dir, `${safe}.wal`);
    this.checkpointPath = join(dir, `${safe}.ckpt`);

    // Load checkpoint
    if (existsSync(this.checkpointPath)) {
      const raw = readFileSync(this.checkpointPath, "utf-8").trim();
      this.checkpoint = parseInt(raw, 10) || 0;
    }

    // Scan existing WAL to find max seq and populate replay set
    if (existsSync(this.walPath)) {
      this._scanWal();
    }
  }

  /**
   * Write a payload to the WAL before sending. Returns the sequence number.
   * Returns -1 if the fingerprint is a duplicate (replay protection).
   */
  append(payload: WitnessPayload): number {
    const fp = payload.anchor_fingerprint;

    // Replay protection: reject duplicates
    if (this.replayEnabled && fp && this.replaySet.has(fp)) {
      return -1;
    }

    this.seq++;
    const entry: WalEntry = {
      seq: this.seq,
      fingerprint: fp || "",
      payload: payloadToRecord(payload),
    };

    appendFileSync(this.walPath, JSON.stringify(entry) + "\n", "utf-8");

    // Track fingerprint
    if (this.replayEnabled && fp) {
      this._addToReplaySet(fp);
    }

    return this.seq;
  }

  /**
   * Mark entries up to this sequence as successfully flushed.
   * Updates the checkpoint file atomically.
   */
  markFlushed(upToSeq: number): void {
    if (upToSeq <= this.checkpoint) return;
    this.checkpoint = upToSeq;

    // Atomic write: write to temp then rename
    const tmp = this.checkpointPath + ".tmp";
    writeFileSync(tmp, String(this.checkpoint), "utf-8");
    renameSync(tmp, this.checkpointPath);

    // Rotate WAL if it's large and fully flushed
    this._maybeRotate();
  }

  /**
   * Recover unflushed entries from the WAL. Called on startup.
   * Returns payloads that were written but never confirmed as flushed.
   */
  recover(): WitnessPayload[] {
    if (!existsSync(this.walPath)) return [];

    const entries = this._readEntries();
    const unflushed = entries.filter((e) => e.seq > this.checkpoint);

    if (unflushed.length > 0) {
      console.info(
        `[swt3-ai] WAL recovery: ${unflushed.length} unflushed entries found (checkpoint: ${this.checkpoint}, max seq: ${this.seq})`,
      );
    }

    return unflushed.map((e) => e.payload as unknown as WitnessPayload);
  }

  /**
   * Check if a fingerprint has already been seen (replay protection).
   */
  isDuplicate(fingerprint: string): boolean {
    if (!this.replayEnabled || !fingerprint) return false;
    return this.replaySet.has(fingerprint);
  }

  /** Current sequence number. */
  get currentSeq(): number {
    return this.seq;
  }

  /** Last flushed checkpoint. */
  get currentCheckpoint(): number {
    return this.checkpoint;
  }

  /** Number of fingerprints in the replay set. */
  get replaySetSize(): number {
    return this.replaySet.size;
  }

  /** Remove WAL and checkpoint files (for testing or cleanup). */
  destroy(): void {
    try { unlinkSync(this.walPath); } catch { /* noop */ }
    try { unlinkSync(this.checkpointPath); } catch { /* noop */ }
    try { unlinkSync(this.walPath + ".tmp"); } catch { /* noop */ }
    try { unlinkSync(this.checkpointPath + ".tmp"); } catch { /* noop */ }
  }

  // ── Internal ──

  private _scanWal(): void {
    const entries = this._readEntries();
    for (const entry of entries) {
      if (entry.seq > this.seq) this.seq = entry.seq;
      if (this.replayEnabled && entry.fingerprint) {
        this._addToReplaySet(entry.fingerprint);
      }
    }
  }

  private _readEntries(): WalEntry[] {
    if (!existsSync(this.walPath)) return [];
    const raw = readFileSync(this.walPath, "utf-8");
    const entries: WalEntry[] = [];
    for (const line of raw.split("\n")) {
      if (!line.trim()) continue;
      try {
        entries.push(JSON.parse(line) as WalEntry);
      } catch {
        // Corrupted line (partial write from crash) -- skip
      }
    }
    return entries;
  }

  private _addToReplaySet(fp: string): void {
    this.replaySet.add(fp);
    // Evict oldest entries if over window (convert to array, drop first N)
    if (this.replaySet.size > this.replayWindow) {
      const overflow = this.replaySet.size - this.replayWindow;
      const iter = this.replaySet.values();
      for (let i = 0; i < overflow; i++) {
        const oldest = iter.next().value;
        if (oldest !== undefined) this.replaySet.delete(oldest);
      }
    }
  }

  private _maybeRotate(): void {
    if (!existsSync(this.walPath)) return;
    try {
      const stat = statSync(this.walPath);
      if (stat.size < WAL_ROTATION_BYTES) return;
    } catch {
      return;
    }

    // Read entries, keep only unflushed
    const entries = this._readEntries();
    const unflushed = entries.filter((e) => e.seq > this.checkpoint);

    if (unflushed.length === 0) {
      // All flushed -- truncate
      writeFileSync(this.walPath, "", "utf-8");
    } else {
      // Rewrite with only unflushed entries
      const tmp = this.walPath + ".tmp";
      writeFileSync(tmp, unflushed.map((e) => JSON.stringify(e)).join("\n") + "\n", "utf-8");
      renameSync(tmp, this.walPath);
    }
  }
}

/** Convert WitnessPayload to a plain record for JSON serialization. */
function payloadToRecord(p: WitnessPayload): Record<string, unknown> {
  const r: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(p)) {
    if (v !== undefined && v !== null) r[k] = v;
  }
  return r;
}
