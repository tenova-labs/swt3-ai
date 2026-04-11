// ── SWT3 Merkle Tree Engine ──────────────────────────────────────
//
// Binary Merkle tree for enclave integrity rollups.
// Replaces the flat enclave signature with a proper tree structure
// that supports efficient single-anchor membership proofs and
// tamper localization.
//
// Properties:
//   - Deterministic: same fingerprints (any order) = same root
//   - Efficient: verify membership in O(log2 n) hashes
//   - Tamper-localized: identify which branch was altered
//   - Backward compatible: root hash replaces flat signature
//
// Algorithm:
//   1. Sort fingerprints lexicographically (determinism)
//   2. Hash each fingerprint to create leaf nodes
//   3. Pair adjacent leaves and hash upward (binary tree)
//   4. Odd nodes are promoted (carried up unpaired)
//   5. Root hash = daily rollup digest
//
// Spec: SWT3-SPEC-v1.0.md, Section 6.3 (Enclave Integrity)
// Patent pending.

import { sha256 } from "./fingerprint.js";
import type { MerkleProof, MerkleProofStep } from "./types.js";

// Domain separation prefix to prevent second-preimage attacks.
// Leaf nodes and internal nodes use different prefixes so a leaf
// hash can never collide with an internal node hash.
const LEAF_PREFIX = "SWT3:LEAF:";
const NODE_PREFIX = "SWT3:NODE:";

/**
 * Hash a leaf node (a single fingerprint).
 * Domain-separated to prevent second-preimage attacks.
 */
export function hashLeaf(fingerprint: string): string {
  return sha256(LEAF_PREFIX + fingerprint);
}

/**
 * Hash an internal node (two child hashes concatenated).
 * Domain-separated from leaf hashes.
 */
export function hashNode(left: string, right: string): string {
  return sha256(NODE_PREFIX + left + ":" + right);
}

/**
 * Compute the Merkle root from a set of fingerprints.
 *
 * Fingerprints are sorted lexicographically before tree construction
 * to guarantee determinism regardless of input order.
 *
 * Returns the 64-character hex root hash, or an empty string if
 * the input array is empty.
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
        // Odd node: promote to next level
        next.push(level[i]);
      }
    }
    level = next;
  }

  return level[0];
}

/**
 * Generate a Merkle proof for a specific fingerprint.
 *
 * The proof is an array of sibling hashes from the leaf to the root,
 * each tagged with its position ("left" or "right"). Given the proof,
 * anyone can verify the fingerprint's membership in the tree by
 * recomputing the path from leaf to root.
 *
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
        // Paired node
        if (i === index || i + 1 === index) {
          // This pair contains our target
          if (index % 2 === 0) {
            // Target is on the left, sibling is on the right
            steps.push({ hash: level[i + 1], position: "right" });
          } else {
            // Target is on the right, sibling is on the left
            steps.push({ hash: level[i], position: "left" });
          }
        }
        next.push(hashNode(level[i], level[i + 1]));
      } else {
        // Odd node promoted — no sibling to record
        next.push(level[i]);
      }
    }

    level = next;
    index = nextIndex;
  }

  return {
    fingerprint: target,
    leaf_hash: hashLeaf(target),
    root: level[0],
    steps,
  };
}

/**
 * Verify a Merkle proof — confirm that a fingerprint belongs to the
 * tree with the given root hash.
 *
 * This requires NO access to the full fingerprint set. Given only
 * the fingerprint, the proof steps, and the claimed root, the
 * verifier can independently confirm membership.
 *
 * This is the function you hand to an auditor who needs to verify
 * a single anchor without downloading the entire ledger.
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
