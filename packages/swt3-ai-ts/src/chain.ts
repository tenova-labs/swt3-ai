/**
 * SWT3 AI Witness SDK -- Client-side chain verification.
 *
 * Walk provenance reference chains using locally available data.
 * No HTTP calls -- the caller provides a lookup map built from their payloads.
 */

import type { AnchorReference, ChainLink, ChainSummary } from "./types.js";

/**
 * Build a lookup map from an array of payload-like objects.
 * Each object must have an `anchor_fingerprint` and optional `references` array.
 */
export function buildLookup(
  payloads: Array<{ anchor_fingerprint: string; references?: AnchorReference[] }>,
): Map<string, AnchorReference[]> {
  const map = new Map<string, AnchorReference[]>();
  for (const p of payloads) {
    if (p.references && p.references.length > 0) {
      map.set(p.anchor_fingerprint, p.references);
    } else {
      map.set(p.anchor_fingerprint, []);
    }
  }
  return map;
}

/**
 * Walk a provenance chain starting from a fingerprint using BFS.
 * Cycle-safe via visited set. Depth-limited via maxDepth.
 *
 * @param startFingerprint - The anchor to start from.
 * @param lookup - Map from fingerprint to its references (from buildLookup).
 * @param maxDepth - Maximum traversal depth (default 10).
 */
export function walkChain(
  startFingerprint: string,
  lookup: Map<string, AnchorReference[]>,
  maxDepth = 10,
): ChainSummary {
  const links: ChainLink[] = [];
  const gaps: string[] = [];
  const visited = new Set<string>();
  let maxReached = 0;
  let truncated = false;

  // BFS queue: [fingerprint, depth]
  const queue: Array<[string, number]> = [[startFingerprint, 0]];

  while (queue.length > 0) {
    const [fp, depth] = queue.shift()!;

    if (visited.has(fp)) continue;
    visited.add(fp);

    if (depth > maxDepth) {
      truncated = true;
      continue;
    }

    const refs = lookup.get(fp);
    if (refs === undefined) {
      if (fp !== startFingerprint) {
        gaps.push(fp);
      } else {
        // Start fingerprint not in lookup -- it's still a gap
        gaps.push(fp);
      }
      continue;
    }

    if (depth > maxReached) maxReached = depth;
    links.push({ fingerprint: fp, references: refs, depth });

    for (const ref of refs) {
      if (!visited.has(ref.fingerprint)) {
        queue.push([ref.fingerprint, depth + 1]);
      }
    }
  }

  return {
    root: startFingerprint,
    links,
    depth: maxReached,
    gaps,
    complete: gaps.length === 0,
    truncated,
  };
}

/**
 * Verify the integrity of a chain walk result.
 * Returns whether the chain is intact and any issues found.
 */
export function verifyChainIntegrity(chain: ChainSummary): { intact: boolean; issues: string[] } {
  const issues: string[] = [];

  if (chain.links.length === 0) {
    issues.push("Chain has no resolved links");
  }

  if (chain.gaps.length > 0) {
    issues.push(`${chain.gaps.length} referenced fingerprint(s) not found in lookup`);
  }

  if (chain.truncated) {
    issues.push("Chain traversal was truncated at max depth");
  }

  return { intact: issues.length === 0, issues };
}
