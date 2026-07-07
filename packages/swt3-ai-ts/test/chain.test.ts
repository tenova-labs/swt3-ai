import { describe, it, expect } from "vitest";
import { buildLookup, walkChain, verifyChainIntegrity } from "../src/chain.js";
import type { AnchorReference } from "../src/types.js";

describe("buildLookup", () => {
  it("builds map from payloads", () => {
    const payloads = [
      { anchor_fingerprint: "fp1", references: [{ fingerprint: "fp2" }] },
      { anchor_fingerprint: "fp2" },
    ];
    const lookup = buildLookup(payloads);
    expect(lookup.size).toBe(2);
    expect(lookup.get("fp1")!).toHaveLength(1);
    expect(lookup.get("fp2")!).toHaveLength(0);
  });

  it("handles empty payloads", () => {
    const lookup = buildLookup([]);
    expect(lookup.size).toBe(0);
  });
});

describe("walkChain", () => {
  it("walks a linear chain A->B->C", () => {
    const lookup = new Map<string, AnchorReference[]>([
      ["A", [{ fingerprint: "B" }]],
      ["B", [{ fingerprint: "C" }]],
      ["C", []],
    ]);
    const chain = walkChain("A", lookup);
    expect(chain.links).toHaveLength(3);
    expect(chain.depth).toBe(2);
    expect(chain.complete).toBe(true);
    expect(chain.gaps).toHaveLength(0);
    expect(chain.truncated).toBe(false);
  });

  it("handles branching references", () => {
    const lookup = new Map<string, AnchorReference[]>([
      ["A", [{ fingerprint: "B" }, { fingerprint: "C" }]],
      ["B", []],
      ["C", []],
    ]);
    const chain = walkChain("A", lookup);
    expect(chain.links).toHaveLength(3);
    expect(chain.complete).toBe(true);
  });

  it("detects gaps when reference not in lookup", () => {
    const lookup = new Map<string, AnchorReference[]>([
      ["A", [{ fingerprint: "B" }]],
    ]);
    const chain = walkChain("A", lookup);
    expect(chain.links).toHaveLength(1);
    expect(chain.gaps).toEqual(["B"]);
    expect(chain.complete).toBe(false);
  });

  it("handles cycle A->B->A without infinite loop", () => {
    const lookup = new Map<string, AnchorReference[]>([
      ["A", [{ fingerprint: "B" }]],
      ["B", [{ fingerprint: "A" }]],
    ]);
    const chain = walkChain("A", lookup);
    expect(chain.links).toHaveLength(2);
    expect(chain.complete).toBe(true);
  });

  it("truncates at maxDepth", () => {
    // Build chain of depth 20
    const lookup = new Map<string, AnchorReference[]>();
    for (let i = 0; i < 20; i++) {
      lookup.set(`n${i}`, [{ fingerprint: `n${i + 1}` }]);
    }
    lookup.set("n20", []);

    const chain = walkChain("n0", lookup, 5);
    expect(chain.truncated).toBe(true);
    // Should have resolved links up to depth 5
    expect(chain.links.length).toBeLessThanOrEqual(7);
  });

  it("reports gap when start fingerprint not in lookup", () => {
    const lookup = new Map<string, AnchorReference[]>();
    const chain = walkChain("missing", lookup);
    expect(chain.links).toHaveLength(0);
    expect(chain.gaps).toEqual(["missing"]);
    expect(chain.complete).toBe(false);
  });

  it("handles deep chain within maxDepth", () => {
    const lookup = new Map<string, AnchorReference[]>();
    for (let i = 0; i < 5; i++) {
      lookup.set(`n${i}`, [{ fingerprint: `n${i + 1}` }]);
    }
    lookup.set("n5", []);
    const chain = walkChain("n0", lookup, 10);
    expect(chain.links).toHaveLength(6);
    expect(chain.truncated).toBe(false);
    expect(chain.complete).toBe(true);
  });

  it("does not crash on very large maxDepth with short chain", () => {
    const lookup = new Map<string, AnchorReference[]>([["A", []]]);
    const chain = walkChain("A", lookup, 1000);
    expect(chain.links).toHaveLength(1);
  });
});

describe("verifyChainIntegrity", () => {
  it("returns intact for complete chain", () => {
    const lookup = new Map<string, AnchorReference[]>([
      ["A", [{ fingerprint: "B" }]],
      ["B", []],
    ]);
    const chain = walkChain("A", lookup);
    const result = verifyChainIntegrity(chain);
    expect(result.intact).toBe(true);
    expect(result.issues).toHaveLength(0);
  });

  it("reports gaps as issue", () => {
    const lookup = new Map<string, AnchorReference[]>([
      ["A", [{ fingerprint: "B" }]],
    ]);
    const chain = walkChain("A", lookup);
    const result = verifyChainIntegrity(chain);
    expect(result.intact).toBe(false);
    expect(result.issues).toContainEqual(expect.stringContaining("not found"));
  });

  it("reports truncation as issue", () => {
    const lookup = new Map<string, AnchorReference[]>();
    for (let i = 0; i < 15; i++) {
      lookup.set(`n${i}`, [{ fingerprint: `n${i + 1}` }]);
    }
    lookup.set("n15", []);
    const chain = walkChain("n0", lookup, 3);
    const result = verifyChainIntegrity(chain);
    expect(result.intact).toBe(false);
    expect(result.issues).toContainEqual(expect.stringContaining("truncated"));
  });

  it("reports empty chain as issue", () => {
    const chain = walkChain("missing", new Map());
    const result = verifyChainIntegrity(chain);
    expect(result.intact).toBe(false);
    expect(result.issues).toContainEqual(expect.stringContaining("no resolved links"));
  });
});
