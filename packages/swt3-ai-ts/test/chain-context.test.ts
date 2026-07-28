import { describe, it, expect } from "vitest";
import { Witness, ChainContext } from "../src/index.js";

function makeWitness(opts: Record<string, unknown> = {}) {
  return new Witness({
    endpoint: "https://example.com",
    apiKey: "axm_test_key",
    tenantId: "TEST_TENANT",
    clearingLevel: 1,
    ...opts,
  });
}

describe("ChainContext basic", () => {
  it("chain() returns a promise", async () => {
    const w = makeWitness();
    const result = await w.chain("test", async (ctx) => {
      return ctx.cycleId;
    });
    expect(result).toMatch(/^CHAIN-[0-9a-f]{16}$/);
  });

  it("auto-generates cycle_id with CHAIN- prefix", async () => {
    const w = makeWitness();
    await w.chain("test", async (ctx) => {
      expect(ctx.cycleId).toMatch(/^CHAIN-/);
      expect(ctx.cycleId.length).toBe(22); // CHAIN- + 16 hex
    });
  });

  it("uses custom cycleId when provided", async () => {
    const w = makeWitness();
    await w.chain("test", async (ctx) => {
      expect(ctx.cycleId).toBe("MY-CUSTOM-ID");
    }, { cycleId: "MY-CUSTOM-ID" });
  });

  it("preserves name on context", async () => {
    const w = makeWitness();
    await w.chain("credit-decision", async (ctx) => {
      expect(ctx.name).toBe("credit-decision");
    });
  });
});

describe("cycle_id injection", () => {
  it("sets config.cycleId inside block", async () => {
    const w = makeWitness();
    expect(w.config.cycleId).toBeUndefined();
    await w.chain("test", async (ctx) => {
      expect(w.config.cycleId).toBe(ctx.cycleId);
    });
    expect(w.config.cycleId).toBeUndefined();
  });

  it("restores undefined after block", async () => {
    const w = makeWitness();
    await w.chain("test", async () => {});
    expect(w.config.cycleId).toBeUndefined();
  });

  it("restores config-level cycleId after block", async () => {
    const w = makeWitness({ cycleId: "CONFIG-LEVEL" });
    expect(w.config.cycleId).toBe("CONFIG-LEVEL");
    await w.chain("override", async (ctx) => {
      expect(w.config.cycleId).toBe(ctx.cycleId);
    }, { cycleId: "CHAIN-LEVEL" });
    expect(w.config.cycleId).toBe("CONFIG-LEVEL");
  });
});

describe("nesting", () => {
  it("inner chain restores outer cycle_id", async () => {
    const w = makeWitness();
    await w.chain("outer", async () => {
      expect(w.config.cycleId).toBe("OUTER");
      await w.chain("inner", async () => {
        expect(w.config.cycleId).toBe("INNER");
      }, { cycleId: "INNER" });
      expect(w.config.cycleId).toBe("OUTER");
    }, { cycleId: "OUTER" });
    expect(w.config.cycleId).toBeUndefined();
  });

  it("triple nesting restores correctly", async () => {
    const w = makeWitness();
    await w.chain("a", async () => {
      await w.chain("b", async () => {
        await w.chain("c", async () => {
          expect(w.config.cycleId).toBe("C");
        }, { cycleId: "C" });
        expect(w.config.cycleId).toBe("B");
      }, { cycleId: "B" });
      expect(w.config.cycleId).toBe("A");
    }, { cycleId: "A" });
    expect(w.config.cycleId).toBeUndefined();
  });
});

describe("exception safety", () => {
  it("restores cycleId on error", async () => {
    const w = makeWitness();
    await expect(
      w.chain("test", async () => {
        throw new Error("test error");
      }, { cycleId: "WILL-RESTORE" }),
    ).rejects.toThrow("test error");
    expect(w.config.cycleId).toBeUndefined();
  });

  it("nested error restores outer", async () => {
    const w = makeWitness();
    await w.chain("outer", async () => {
      await expect(
        w.chain("inner", async () => {
          throw new Error("inner error");
        }, { cycleId: "INNER" }),
      ).rejects.toThrow("inner error");
      expect(w.config.cycleId).toBe("OUTER");
    }, { cycleId: "OUTER" });
  });

  it("config-level restored after error", async () => {
    const w = makeWitness({ cycleId: "ORIGINAL" });
    await expect(
      w.chain("test", async () => {
        throw new TypeError("boom");
      }),
    ).rejects.toThrow("boom");
    expect(w.config.cycleId).toBe("ORIGINAL");
  });
});

describe("uniqueness", () => {
  it("sequential chains get different ids", async () => {
    const w = makeWitness();
    let id1 = "";
    let id2 = "";
    await w.chain("first", async (ctx) => { id1 = ctx.cycleId; });
    await w.chain("second", async (ctx) => { id2 = ctx.cycleId; });
    expect(id1).not.toBe(id2);
  });

  it("generates unique ids across 100 chains", async () => {
    const w = makeWitness();
    const ids = new Set<string>();
    for (let i = 0; i < 100; i++) {
      await w.chain("test", async (ctx) => { ids.add(ctx.cycleId); });
    }
    expect(ids.size).toBe(100);
  });
});
