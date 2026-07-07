/**
 * SWT3 AI Witness SDK: Sentinel Client.
 *
 * Thin proxy that connects to the swt3-sentinel daemon over a Unix
 * domain socket. When the daemon is detected, witness operations
 * (attestation signing, WAL persistence, Merkle accumulation) are
 * delegated to the isolated process for tamper-proof evidence.
 * When the daemon is absent, the SDK operates standalone with
 * zero degradation.
 *
 * Auto-detection adds less than 10ms to initialization and requires
 * zero code changes from the developer.
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import { connect, type Socket } from "node:net";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { homedir } from "node:os";

/** User-writable default: ~/.swt3/sentinel.sock. No root needed. */
const DEFAULT_SOCKET_PATH = join(homedir(), ".swt3", "sentinel.sock");
const DEFAULT_TIMEOUT_MS = 50;
const DETECT_TIMEOUT_MS = 10;

export interface SentinelClientOptions {
  socketPath?: string;
  timeoutMs?: number;
  failSecure?: boolean;
}

export interface SentinelViolation {
  rule: string;
  tool: string;
  action: "blocked" | "logged";
  reason: string;
  timestamp: number;
  context?: Record<string, unknown>;
}

export interface SentinelCheckResult {
  allowed: boolean;
  violation?: SentinelViolation;
}

export interface SentinelStatusResult {
  uptime: number;
  tokens: number;
  violations: number;
  walSeq: number;
  walCheckpoint: number;
  connections: number;
  protocolVersion: number;
}

interface PendingRequest {
  resolve: (value: any) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

export class SentinelClient {
  private socket: Socket | null = null;
  private _connected = false;
  private pending = new Map<string, PendingRequest>();
  private buffer = "";
  private socketPath: string;
  private timeoutMs: number;
  private failSecure: boolean;

  constructor(options: SentinelClientOptions = {}) {
    this.socketPath = options.socketPath
      ?? process.env.SWT3_SENTINEL_SOCKET
      ?? DEFAULT_SOCKET_PATH;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.failSecure = options.failSecure ?? false;
  }

  /**
   * Non-blocking auto-detection. Attempts to connect to the sentinel
   * daemon with a 10ms timeout. Returns a connected client or null.
   *
   * Usage:
   *   const sentinel = await SentinelClient.detect();
   *   if (sentinel) { // daemon present, delegate operations }
   */
  static detect(socketPath?: string): Promise<SentinelClient | null> {
    const path = socketPath
      ?? process.env.SWT3_SENTINEL_SOCKET
      ?? DEFAULT_SOCKET_PATH;

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        sock.destroy();
        resolve(null);
      }, DETECT_TIMEOUT_MS);

      const sock = connect({ path }, () => {
        clearTimeout(timer);
        sock.destroy();
        // Socket exists and accepts connections -- create a real client
        const client = new SentinelClient({ socketPath: path });
        client.connect()
          .then(() => resolve(client))
          .catch(() => resolve(null));
      });

      sock.on("error", () => {
        clearTimeout(timer);
        resolve(null);
      });
    });
  }

  /** Connect to the sentinel daemon. */
  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.socket = connect({ path: this.socketPath }, () => {
        this._connected = true;
        resolve();
      });

      this.socket.on("data", (chunk: Buffer) => this.onData(chunk));

      this.socket.on("close", () => {
        this._connected = false;
        this.rejectAllPending("Connection closed");
      });

      this.socket.on("error", (err) => {
        this._connected = false;
        this.rejectAllPending(err.message);
        reject(err);
      });
    });
  }

  get connected(): boolean {
    return this._connected;
  }

  /** Check a tool call against the shared enforcement engine. */
  async check(tool: string): Promise<SentinelCheckResult> {
    return this.request({ op: "check", tool });
  }

  /** Record a witness entry in the protected WAL. */
  async record(fingerprint: string, payload: string): Promise<{ seq: number; merkleRoot?: string }> {
    return this.request({ op: "record", fingerprint, payload });
  }

  /** Sign a payload using the daemon's isolated key. */
  async sign(data: string, agentId?: string): Promise<string> {
    const resp = await this.request({ op: "sign", payload: data, agentId });
    return resp.signature;
  }

  /** Record token consumption in the shared budget. */
  async recordTokens(count: number): Promise<{ total: number; budget: number }> {
    return this.request({ op: "tokens", count });
  }

  /** Flush the protected WAL. */
  async flush(): Promise<{ flushedSeq: number; merkleRoot?: string }> {
    return this.request({ op: "flush" });
  }

  /** Get daemon status. */
  async status(): Promise<SentinelStatusResult> {
    return this.request({ op: "status" });
  }

  /** Disconnect from the daemon. */
  destroy(): void {
    this.rejectAllPending("Client destroyed");
    if (this.socket) {
      this.socket.destroy();
      this.socket = null;
    }
    this._connected = false;
  }

  // ── Internal ──────────────────────────────────────────────────────

  private request(req: Record<string, unknown>): Promise<any> {
    const id = randomUUID().slice(0, 8);
    const line = JSON.stringify({ ...req, id }) + "\n";

    return new Promise((resolve, reject) => {
      if (!this.socket || !this._connected) {
        reject(new Error("Not connected to sentinel daemon"));
        return;
      }

      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error("Sentinel request timed out"));
      }, this.timeoutMs);

      this.pending.set(id, { resolve, reject, timer });
      this.socket.write(line);
    });
  }

  private onData(chunk: Buffer): void {
    this.buffer += chunk.toString();
    let idx: number;
    while ((idx = this.buffer.indexOf("\n")) !== -1) {
      const line = this.buffer.slice(0, idx).trim();
      this.buffer = this.buffer.slice(idx + 1);
      if (!line) continue;

      try {
        const resp = JSON.parse(line);
        const pending = this.pending.get(resp.id);
        if (pending) {
          clearTimeout(pending.timer);
          this.pending.delete(resp.id);
          if (resp.ok) {
            pending.resolve(resp);
          } else {
            pending.reject(new Error(resp.error ?? "Sentinel error"));
          }
        }
      } catch {
        // Corrupted response line -- skip
      }
    }
  }

  private rejectAllPending(reason: string): void {
    for (const [id, pending] of this.pending) {
      clearTimeout(pending.timer);
      pending.reject(new Error(reason));
    }
    this.pending.clear();
  }
}
