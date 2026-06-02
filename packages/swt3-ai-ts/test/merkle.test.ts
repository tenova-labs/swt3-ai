/**
 * SWT3 AI Witness SDK -- Merkle Tree + Accumulator Tests.
 *
 * 10 tests: primitives, root determinism, proof verification,
 * accumulator lifecycle, config extraction, edge cases.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  hashLeaf, hashNode, getMerkleRoot, getMerkleProof, verifyMerkleProof,
  MerkleAccumulator,
} from "../src/merkle.js";

beforeEach(() => {
  vi.spyOn(console, "info").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
});
afterEach(() => vi.restoreAllMocks());

describe("Merkle Primitives", () => {
  it("hashLeaf uses SWT3:LEAF: domain separator", () => {
    const h = hashLeaf("abc123def456");
    expect(h).toHaveLength(64);
    // Different input = different hash
    expect(hashLeaf("xyz")).not.toBe(h);
  });

  it("hashNode uses SWT3:NODE: domain separator", () => {
    const h = hashNode("aaa", "bbb");
    expect(h).toHaveLength(64);
    // leaf and node of same content differ (domain separation)
    expect(hashLeaf("aaa")).not.toBe(hashNode("aaa", ""));
  });

  it("getMerkleRoot is deterministic regardless of input order", () => {
    const fps = ["fp_c", "fp_a", "fp_b", "fp_d"];
    const root1 = getMerkleRoot(fps);
    const root2 = getMerkleRoot(["fp_b", "fp_d", "fp_a", "fp_c"]);
    expect(root1).toBe(root2);
    expect(root1).toHaveLength(64);
  });

  it("getMerkleRoot returns empty string for empty input", () => {
    expect(getMerkleRoot([])).toBe("");
  });

  it("getMerkleRoot handles single fingerprint", () => {
    const root = getMerkleRoot(["solo"]);
    expect(root).toBe(hashLeaf("solo"));
  });
});

describe("Merkle Proofs", () => {
  it("generates and verifies a valid proof", () => {
    const fps = ["fp_1", "fp_2", "fp_3", "fp_4", "fp_5"];
    const proof = getMerkleProof(fps, "fp_3");
    expect(proof).not.toBeNull();
    expect(proof!.fingerprint).toBe("fp_3");
    expect(proof!.root).toBe(getMerkleRoot(fps));
    expect(verifyMerkleProof("fp_3", proof!)).toBe(true);
  });

  it("returns null for missing fingerprint", () => {
    expect(getMerkleProof(["a", "b"], "c")).toBeNull();
    expect(getMerkleProof([], "a")).toBeNull();
  });

  it("rejects tampered proof", () => {
    const fps = ["fp_1", "fp_2", "fp_3"];
    const proof = getMerkleProof(fps, "fp_1")!;
    // Tamper with the root
    const tampered = { ...proof, root: "0".repeat(64) };
    expect(verifyMerkleProof("fp_1", tampered)).toBe(false);
  });
});

describe("MerkleAccumulator", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "swt3-merkle-test-"));
  });

  it("computes session root on flush and persists to JSONL", () => {
    const acc = new MerkleAccumulator({ persistDir: dir, tenantId: "TEST" });
    acc.add("fp_a");
    acc.add("fp_b");
    expect(acc.pending).toBe(2);

    const result = acc.flush();
    expect(result).not.toBeNull();
    expect(result!.root).toBe(getMerkleRoot(["fp_a", "fp_b"]));
    expect(result!.count).toBe(2);
    expect(acc.pending).toBe(0);
    expect(acc.roots).toHaveLength(1);

    // Verify JSONL persistence
    const jsonlPath = join(dir, "TEST.roots.jsonl");
    expect(existsSync(jsonlPath)).toBe(true);
    const lines = readFileSync(jsonlPath, "utf-8").trim().split("\n");
    expect(lines).toHaveLength(1);
    const persisted = JSON.parse(lines[0]);
    expect(persisted.root).toBe(result!.root);
  });

  it("returns null on empty flush", () => {
    const acc = new MerkleAccumulator();
    expect(acc.flush()).toBeNull();
  });

  it("generates proofs from accumulated sessions", () => {
    const acc = new MerkleAccumulator();
    acc.addMany(["fp_x", "fp_y", "fp_z"]);
    acc.flush();

    const proof = acc.prove("fp_y");
    expect(proof).not.toBeNull();
    expect(verifyMerkleProof("fp_y", proof!)).toBe(true);

    // Non-existent fingerprint
    expect(acc.prove("fp_missing")).toBeNull();
  });

  it("reset clears pending but keeps history", () => {
    const acc = new MerkleAccumulator();
    acc.add("fp_1");
    acc.flush();
    acc.add("fp_2");
    acc.reset();
    expect(acc.pending).toBe(0);
    expect(acc.roots).toHaveLength(1);

    acc.clear();
    expect(acc.roots).toHaveLength(0);
  });
});

describe("Cross-Session Merkle Composition", () => {
  it("returns empty for accumulator with no sessions", () => {
    const acc = new MerkleAccumulator();
    const result = acc.composeSessionRoots();
    expect(result.aggregateRoot).toBe("");
    expect(result.sessionCount).toBe(0);
    expect(result.proveSession("anything")).toBeNull();
  });

  it("composes single session root", () => {
    const acc = new MerkleAccumulator();
    acc.addMany(["fp_a", "fp_b"]);
    acc.flush();

    const result = acc.composeSessionRoots();
    expect(result.aggregateRoot).toHaveLength(64);
    expect(result.sessionCount).toBe(1);
  });

  it("composes multiple session roots with valid aggregate", () => {
    const acc = new MerkleAccumulator();
    acc.addMany(["fp_a", "fp_b"]);
    const s1 = acc.flush()!;
    acc.addMany(["fp_c", "fp_d"]);
    const s2 = acc.flush()!;
    acc.addMany(["fp_e"]);
    const s3 = acc.flush()!;

    const result = acc.composeSessionRoots();
    expect(result.aggregateRoot).toHaveLength(64);
    expect(result.sessionCount).toBe(3);

    // Aggregate root is deterministic
    const result2 = acc.composeSessionRoots();
    expect(result2.aggregateRoot).toBe(result.aggregateRoot);
  });

  it("proves session inclusion in aggregate", () => {
    const acc = new MerkleAccumulator();
    acc.addMany(["fp_a", "fp_b"]);
    const s1 = acc.flush()!;
    acc.addMany(["fp_c", "fp_d"]);
    const s2 = acc.flush()!;

    const result = acc.composeSessionRoots();
    const proof = result.proveSession(s1.root);
    expect(proof).not.toBeNull();
    expect(verifyMerkleProof(s1.root, proof!)).toBe(true);

    const proof2 = result.proveSession(s2.root);
    expect(proof2).not.toBeNull();
    expect(verifyMerkleProof(s2.root, proof2!)).toBe(true);
  });

  it("returns null for non-existent session", () => {
    const acc = new MerkleAccumulator();
    acc.addMany(["fp_a"]);
    acc.flush();

    const result = acc.composeSessionRoots();
    expect(result.proveSession("nonexistent_root")).toBeNull();
  });

  it("accepts explicit session root array", () => {
    const acc = new MerkleAccumulator();
    const explicit = ["root_aaa", "root_bbb", "root_ccc"];
    const result = acc.composeSessionRoots(explicit);
    expect(result.aggregateRoot).toHaveLength(64);
    expect(result.sessionCount).toBe(3);

    const proof = result.proveSession("root_bbb");
    expect(proof).not.toBeNull();
    expect(verifyMerkleProof("root_bbb", proof!)).toBe(true);
  });
});
