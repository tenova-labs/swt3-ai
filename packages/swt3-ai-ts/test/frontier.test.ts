/**
 * Tests for v0.5.7 frontier procedures: AI-FIN.1, AI-TOOL.2, AI-LCM.1, AI-JUR.1.
 */
import { describe, it, expect } from "vitest";
import { Witness } from "../src/witness.js";

function w(opts: Record<string, unknown> = {}) {
  return new Witness({ endpoint: "https://test.example.com", apiKey: "axm_test_key", tenantId: "TEST", clearingLevel: 1, disableFlush: true, ...opts });
}

describe("witnessTransaction (AI-FIN.1)", () => {
  it("mints correct procedure", () => {
    const p = w().witnessTransaction({ amountCents: 5000, authorizationType: "human", status: "authorized" });
    expect(p.procedure_id).toBe("AI-FIN.1");
  });

  it("maps authorization codes", () => {
    expect(w().witnessTransaction({ amountCents: 100, authorizationType: "none", status: "pending" }).factor_a).toBe(0);
    expect(w().witnessTransaction({ amountCents: 100, authorizationType: "pre_approved", status: "pending" }).factor_a).toBe(1);
    expect(w().witnessTransaction({ amountCents: 100, authorizationType: "human", status: "pending" }).factor_a).toBe(2);
    expect(w().witnessTransaction({ amountCents: 100, authorizationType: "policy", status: "pending" }).factor_a).toBe(3);
    expect(w().witnessTransaction({ amountCents: 100, authorizationType: "budget_limit", status: "pending" }).factor_a).toBe(4);
  });

  it("records amount in cents", () => {
    const p = w().witnessTransaction({ amountCents: 9999, authorizationType: "human", status: "authorized" });
    expect(p.factor_b).toBe(9999);
  });

  it("maps status codes", () => {
    expect(w().witnessTransaction({ amountCents: 100, authorizationType: "human", status: "pending" }).factor_c).toBe(0);
    expect(w().witnessTransaction({ amountCents: 100, authorizationType: "human", status: "authorized" }).factor_c).toBe(1);
    expect(w().witnessTransaction({ amountCents: 100, authorizationType: "human", status: "denied" }).factor_c).toBe(2);
    expect(w().witnessTransaction({ amountCents: 100, authorizationType: "human", status: "escalated" }).factor_c).toBe(3);
  });

  it("includes context at clearing level 1", () => {
    const p = w().witnessTransaction({ amountCents: 5000, authorizationType: "human", status: "authorized", currency: "USD" });
    expect(p.ai_context).toBeDefined();
    expect(p.ai_context!.currency).toBe("USD");
  });

  it("strips context at clearing level 2", () => {
    const p = w({ clearingLevel: 2 }).witnessTransaction({ amountCents: 5000, authorizationType: "human", status: "authorized" });
    expect(p.ai_context).toBeUndefined();
  });

  it("mints valid 12-char hex fingerprint", () => {
    const p = w().witnessTransaction({ amountCents: 100, authorizationType: "human", status: "authorized" });
    expect(p.anchor_fingerprint).toHaveLength(12);
    expect(parseInt(p.anchor_fingerprint, 16)).not.toBeNaN();
  });
});

describe("witnessToolPermissions (AI-TOOL.2)", () => {
  it("mints correct procedure", () => {
    const p = w().witnessToolPermissions({ tools: ["read", "write"], charterMatch: true });
    expect(p.procedure_id).toBe("AI-TOOL.2");
  });

  it("counts tools", () => {
    expect(w().witnessToolPermissions({ tools: ["a", "b", "c"], charterMatch: true }).factor_a).toBe(3);
  });

  it("records charter match", () => {
    expect(w().witnessToolPermissions({ tools: ["a"], charterMatch: true }).factor_b).toBe(1);
    expect(w().witnessToolPermissions({ tools: ["a"], charterMatch: false }).factor_b).toBe(0);
  });

  it("includes context at clearing level 1", () => {
    const p = w().witnessToolPermissions({ tools: ["read"], charterMatch: true, charterHash: "abc" });
    expect(p.ai_context).toBeDefined();
    expect(p.ai_context!.charter_hash).toBe("abc");
  });

  it("strips context at clearing level 2", () => {
    const p = w({ clearingLevel: 2 }).witnessToolPermissions({ tools: ["a"], charterMatch: true });
    expect(p.ai_context).toBeUndefined();
  });
});

describe("witnessLifecycle (AI-LCM.1)", () => {
  it("mints correct procedure", () => {
    const p = w().witnessLifecycle({ event: "spawn" });
    expect(p.procedure_id).toBe("AI-LCM.1");
  });

  it("maps event codes", () => {
    expect(w().witnessLifecycle({ event: "spawn" }).factor_a).toBe(0);
    expect(w().witnessLifecycle({ event: "checkpoint" }).factor_a).toBe(1);
    expect(w().witnessLifecycle({ event: "migrate" }).factor_a).toBe(2);
    expect(w().witnessLifecycle({ event: "terminate" }).factor_a).toBe(3);
    expect(w().witnessLifecycle({ event: "crash" }).factor_a).toBe(4);
  });

  it("records context tokens", () => {
    const p = w().witnessLifecycle({ event: "checkpoint", contextTokens: 4096 });
    expect(p.factor_b).toBe(4096);
  });

  it("records state hash presence", () => {
    expect(w().witnessLifecycle({ event: "checkpoint", stateHash: "abc123" }).factor_c).toBe(1);
    expect(w().witnessLifecycle({ event: "checkpoint" }).factor_c).toBe(0);
  });

  it("includes context at clearing level 1", () => {
    const p = w().witnessLifecycle({ event: "spawn", parentAgentId: "parent-1" });
    expect(p.ai_context).toBeDefined();
    expect(p.ai_context!.event).toBe("spawn");
  });

  it("strips context at clearing level 2", () => {
    const p = w({ clearingLevel: 2 }).witnessLifecycle({ event: "terminate" });
    expect(p.ai_context).toBeUndefined();
  });
});

describe("witnessRouting (AI-JUR.1)", () => {
  it("mints correct procedure", () => {
    const p = w().witnessRouting({ servingRegion: "US", userRegion: "DE" });
    expect(p.procedure_id).toBe("AI-JUR.1");
  });

  it("maps region codes", () => {
    const p = w().witnessRouting({ servingRegion: "US", userRegion: "DE" });
    expect(p.factor_a).toBe(840);
    expect(p.factor_b).toBe(276);
  });

  it("unknown region defaults to 0", () => {
    const p = w().witnessRouting({ servingRegion: "ZZ", userRegion: "XX" });
    expect(p.factor_a).toBe(0);
    expect(p.factor_b).toBe(0);
  });

  it("includes context at clearing level 1", () => {
    const p = w().witnessRouting({ servingRegion: "US", userRegion: "FR", routingDecision: "geo-route" });
    expect(p.ai_context).toBeDefined();
    expect(p.ai_context!.serving_region).toBe("US");
    expect(p.ai_context!.user_region).toBe("FR");
  });

  it("strips context at clearing level 2", () => {
    const p = w({ clearingLevel: 2 }).witnessRouting({ servingRegion: "US", userRegion: "DE" });
    expect(p.ai_context).toBeUndefined();
  });
});
