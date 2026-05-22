/**
 * SWT3 AI Witness SDK -- Merkle Tree + Tiered Accumulator.
 *
 * Inline port of libswt3 Merkle primitives (no external dependency)
 * plus a tiered accumulator that computes session-level Merkle roots
 * on each flush.
 *
 * Domain separation (SWT3:LEAF: / SWT3:NODE:) prevents second-preimage
 * attacks. Fingerprints are sorted lexicographically before tree
 * construction for determinism.
 *
 * Tiers:
 *   Session root  -- computed per flush (SDK-side, this file)
 *   Endpoint root -- computed per interval (server-side, daily_merkle_rollups)
 *
 * Spec: SWT3-SPEC-v1.0.md, Section 6.3 (Enclave Integrity)
 * Patent pending.
 */

import { createHash } from "node:crypto";
import { appendFileSync, readFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

// ── Domain Separators ────────────────────────────────────────────────

const LEAF_PREFIX = "SWT3:LEAF:";
const NODE_PREFIX = "SWT3:NODE:";

// ── Merkle Primitives ────────────────────────────────────────────────

function sha256(data: string): string {
  return createHash("sha256").update(data, "utf-8").digest("hex");
}

/** Hash a leaf node (a single fingerprint). Domain-separated. */
export function hashLeaf(fingerprint: string): string {
  return sha256(LEAF_PREFIX + fingerprint);
}

/** Hash an internal node (two child hashes). Domain-separated. */
export function hashNode(left: string, right: string): string {
  return sha256(NODE_PREFIX + left + ":" + right);
}

/**
 * Compute the Merkle root from a set of fingerprints.
 * Sorted lexicographically for determinism.
 */
export function getMerkleRoot(fingerprints: string[]): string {
  if (fingerprints.length === 0) return "";

  const sorted = [...fingerprints].sort();
  let level = sorted.map(hashLeaf);

  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(hashNode(level[i], level[i + 1]));
      } else {
        next.push(level[i]);
      }
    }
    level = next;
  }

  return level[0];
}

/** A single step in a Merkle inclusion proof. */
export interface MerkleProofStep {
  hash: string;
  position: "left" | "right";
}

/** Merkle inclusion proof for a single fingerprint. */
export interface MerkleProof {
  fingerprint: string;
  leafHash: string;
  root: string;
  steps: MerkleProofStep[];
}

/**
 * Generate a Merkle inclusion proof for a fingerprint.
 * Returns null if the fingerprint is not in the set.
 */
export function getMerkleProof(
  fingerprints: string[],
  target: string,
): MerkleProof | null {
  if (fingerprints.length === 0) return null;

  const sorted = [...fingerprints].sort();
  const targetIndex = sorted.indexOf(target);
  if (targetIndex === -1) return null;

  let level = sorted.map(hashLeaf);
  let index = targetIndex;
  const steps: MerkleProofStep[] = [];

  while (level.length > 1) {
    const next: string[] = [];
    const nextIndex = Math.floor(index / 2);

    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        if (i === index || i + 1 === index) {
          if (index % 2 === 0) {
            steps.push({ hash: level[i + 1], position: "right" });
          } else {
            steps.push({ hash: level[i], position: "left" });
          }
        }
        next.push(hashNode(level[i], level[i + 1]));
      } else {
        next.push(level[i]);
      }
    }

    level = next;
    index = nextIndex;
  }

  return {
    fingerprint: target,
    leafHash: hashLeaf(target),
    root: level[0],
    steps,
  };
}

/**
 * Verify a Merkle inclusion proof. Requires only the fingerprint,
 * proof steps, and claimed root -- no access to the full set needed.
 */
export function verifyMerkleProof(
  fingerprint: string,
  proof: MerkleProof,
): boolean {
  let current = hashLeaf(fingerprint);

  for (const step of proof.steps) {
    if (step.position === "left") {
      current = hashNode(step.hash, current);
    } else {
      current = hashNode(current, step.hash);
    }
  }

  return current === proof.root;
}

// ── Session Root Entry ───────────────────────────────────────────────

export interface SessionRoot {
  root: string;
  fingerprints: string[];
  count: number;
  timestamp: string;
}

// ── Merkle Config ────────────────────────────────────────────────────

export interface MerkleConfig {
  enabled: boolean;
  accumulatorInterval: number;
}

// ── Tiered Merkle Accumulator ────────────────────────────────────────

export interface MerkleAccumulatorOptions {
  /** Directory for session root JSONL persistence. Default: $TMPDIR/swt3-merkle */
  persistDir?: string;
  /** Tenant ID for scoping persistence files. */
  tenantId?: string;
}

/**
 * Tiered Merkle Accumulator.
 *
 * Collects anchor fingerprints and computes a session-level Merkle root
 * on each flush. Session roots are persisted to a JSONL file for
 * crash recovery and auditor export.
 *
 * Usage:
 *   const acc = new MerkleAccumulator({ tenantId: "ACME" });
 *   acc.add("abc123def456");
 *   acc.add("789012345678");
 *   const root = acc.flush();  // computes + persists session root
 */
export class MerkleAccumulator {
  private fingerprints: string[] = [];
  private sessionRoots: SessionRoot[] = [];
  private persistPath: string | null;

  constructor(options: MerkleAccumulatorOptions = {}) {
    if (options.persistDir || options.tenantId) {
      const dir = options.persistDir ?? join(tmpdir(), "swt3-merkle");
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      const safe = (options.tenantId ?? "default").replace(/[^a-zA-Z0-9_-]/g, "_");
      this.persistPath = join(dir, `${safe}.roots.jsonl`);

      // Load existing session roots
      if (existsSync(this.persistPath)) {
        const raw = readFileSync(this.persistPath, "utf-8");
        for (const line of raw.split("\n")) {
          if (!line.trim()) continue;
          try {
            this.sessionRoots.push(JSON.parse(line) as SessionRoot);
          } catch {
            // Corrupted line -- skip
          }
        }
      }
    } else {
      this.persistPath = null;
    }
  }

  /** Add a fingerprint to the current session batch. */
  add(fingerprint: string): void {
    this.fingerprints.push(fingerprint);
  }

  /** Add multiple fingerprints. */
  addMany(fingerprints: string[]): void {
    this.fingerprints.push(...fingerprints);
  }

  /** Number of fingerprints in the current (unflushed) batch. */
  get pending(): number {
    return this.fingerprints.length;
  }

  /** All session roots computed so far. */
  get roots(): SessionRoot[] {
    return [...this.sessionRoots];
  }

  /**
   * Compute the Merkle root for the current batch and persist it.
   * Returns the session root entry, or null if the batch is empty.
   */
  flush(): SessionRoot | null {
    if (this.fingerprints.length === 0) return null;

    const fps = [...this.fingerprints];
    const root = getMerkleRoot(fps);
    const entry: SessionRoot = {
      root,
      fingerprints: fps,
      count: fps.length,
      timestamp: new Date().toISOString(),
    };

    this.sessionRoots.push(entry);
    this.fingerprints = [];

    // Persist to JSONL
    if (this.persistPath) {
      appendFileSync(this.persistPath, JSON.stringify(entry) + "\n", "utf-8");
    }

    return entry;
  }

  /**
   * Generate a Merkle proof for a fingerprint within a specific session root.
   * If no root is specified, searches the most recent session.
   */
  prove(fingerprint: string, rootHash?: string): MerkleProof | null {
    const sessions = rootHash
      ? this.sessionRoots.filter((s) => s.root === rootHash)
      : this.sessionRoots.slice(-1);

    for (const session of sessions) {
      const proof = getMerkleProof(session.fingerprints, fingerprint);
      if (proof) return proof;
    }

    return null;
  }

  /** Reset the accumulator (clears pending fingerprints, keeps history). */
  reset(): void {
    this.fingerprints = [];
  }

  /** Clear all state including history (for testing). */
  clear(): void {
    this.fingerprints = [];
    this.sessionRoots = [];
  }

  /**
   * Compose multiple session roots into a higher-level Merkle root.
   *
   * Enables aggregate attestation over an entire audit period (daily,
   * weekly, organizational) without re-processing individual anchors.
   * Any individual session can be proven as included via proveSession().
   *
   * @param sessionRootHashes - Session root hashes to compose.
   *   If omitted, uses all session roots from this accumulator's history.
   */
  composeSessionRoots(sessionRootHashes?: string[]): {
    aggregateRoot: string;
    sessionCount: number;
    proveSession(sessionRootHash: string): MerkleProof | null;
  } {
    const roots = sessionRootHashes ?? this.sessionRoots.map((s) => s.root);
    if (roots.length === 0) {
      return { aggregateRoot: "", sessionCount: 0, proveSession: () => null };
    }

    const aggregateRoot = getMerkleRoot(roots);

    return {
      aggregateRoot,
      sessionCount: roots.length,
      proveSession(sessionRootHash: string): MerkleProof | null {
        return getMerkleProof(roots, sessionRootHash);
      },
    };
  }
}
