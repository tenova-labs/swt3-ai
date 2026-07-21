/**
 * Tests for AI-DEL.1 Delegation Tree Witnessing.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Witness } from "../src/witness.js";
import { sha256Truncated } from "../src/fingerprint.js";

function mkWitness(opts: Record<string, unknown> = {}) {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "test_tenant",
    disableFlush: true,
    ...opts,
  });
}

describe("witnessDelegationTree (AI-DEL.1)", () => {
  let origConsole: typeof console.log;
  beforeEach(() => { origConsole = console.log; console.log = vi.fn(); });
  afterEach(() => { console.log = origConsole; });

  it("mints correct procedure and factor semantics", () => {
    const w = mkWitness();
    const p = w.witnessDelegationTree({
      delegatorId: "agent-root",
      scope: "read_file,write_file",
      delegationDepth: 2,
    });
    expect(p.procedure_id).toBe("AI-DEL.1");
    // fa = uint32 from SHA256(delegatorId)[:8]
    const delegatorHash = sha256Truncated("agent-root", 16);
    expect(p.factor_a).toBe(parseInt(delegatorHash.slice(0, 8), 16));
    // fb = uint32 from SHA256(scope)[:8]
    const scopeHash = sha256Truncated("read_file,write_file", 16);
    expect(p.factor_b).toBe(parseInt(scopeHash.slice(0, 8), 16));
    expect(p.factor_c).toBe(2);
    expect(p.anchor_fingerprint).toBeTruthy();
  });

  it("supports depth 0 for root grants", () => {
    const w = mkWitness();
    const p = w.witnessDelegationTree({
      delegatorId: "root", scope: "admin", delegationDepth: 0,
    });
    expect(p.factor_c).toBe(0);
  });

  it("populates context fields at clearing level 1", () => {
    const w = mkWitness({ clearingLevel: 1 });
    const p = w.witnessDelegationTree({
      delegatorId: "orchestrator",
      scope: "execute_query",
      delegationDepth: 1,
      delegates: ["worker-a", "worker-b"],
      treeHash: "abc123",
      cascadeRevocation: true,
      timeBoundMinutes: 60,
      parentGrantFingerprint: "f1f2f3f4f5f6",
    });
    const ctx = p.ai_context!;
    expect(ctx.provider).toBe("delegation-tree");
    expect(ctx.delegator_hash).toBe(sha256Truncated("orchestrator", 16));
    expect(ctx.scope_hash).toBe(sha256Truncated("execute_query", 16));
    expect(ctx.cascade_revocation).toBe(true);
    expect(ctx.time_bound_minutes).toBe(60);
    expect(ctx.tree_hash).toBe("abc123");
    expect(ctx.parent_grant_fingerprint).toBe("f1f2f3f4f5f6");
    // Delegates must be hashed
    expect((ctx.delegates as string[]).length).toBe(2);
    expect((ctx.delegates as string[])[0]).toBe(sha256Truncated("worker-a"));
    expect((ctx.delegates as string[])[1]).toBe(sha256Truncated("worker-b"));
    expect(p.ai_model_id).toBe("delegation-tree-depth-1");
  });

  it("defaults cascade_revocation to false", () => {
    const w = mkWitness({ clearingLevel: 1 });
    const p = w.witnessDelegationTree({
      delegatorId: "root", scope: "scope", delegationDepth: 0,
    });
    expect(p.ai_context!.cascade_revocation).toBe(false);
  });

  it("strips context at clearing level 3", () => {
    const w = mkWitness({ clearingLevel: 3 });
    const p = w.witnessDelegationTree({
      delegatorId: "root", scope: "scope", delegationDepth: 2,
      delegates: ["child"],
      cascadeRevocation: true,
    });
    expect(p.ai_context).toBeUndefined();
  });

  it("delegationTreeFromTools computes sorted scope", () => {
    const w = mkWitness();
    const p = w.delegationTreeFromTools({
      delegatorId: "agent-1",
      tools: ["write_file", "read_file", "execute"],
    });
    expect(p.procedure_id).toBe("AI-DEL.1");
    const expectedScope = "execute,read_file,write_file";
    const scopeHash = sha256Truncated(expectedScope, 16);
    expect(p.factor_b).toBe(parseInt(scopeHash.slice(0, 8), 16));
    expect(p.factor_c).toBe(1); // default depth
  });

  it("delegationTreeFromCapabilities computes sorted scope", () => {
    const w = mkWitness();
    const p = w.delegationTreeFromCapabilities({
      delegatorId: "agent-1",
      capabilities: ["internet_access", "code_execution"],
    });
    expect(p.procedure_id).toBe("AI-DEL.1");
    const expectedScope = "code_execution,internet_access";
    const scopeHash = sha256Truncated(expectedScope, 16);
    expect(p.factor_b).toBe(parseInt(scopeHash.slice(0, 8), 16));
  });

  it("delegationTreeFromTools supports custom depth", () => {
    const w = mkWitness();
    const p = w.delegationTreeFromTools({
      delegatorId: "agent-1", tools: ["tool_a"], delegationDepth: 3,
    });
    expect(p.factor_c).toBe(3);
  });

  it("fingerprint is valid 12-char hex", () => {
    const w = mkWitness();
    const p = w.witnessDelegationTree({
      delegatorId: "agent", scope: "scope", delegationDepth: 1,
    });
    expect(p.anchor_fingerprint).toHaveLength(12);
    expect(() => parseInt(p.anchor_fingerprint, 16)).not.toThrow();
  });

  it("handles deep delegation trees", () => {
    const w = mkWitness();
    const p = w.witnessDelegationTree({
      delegatorId: "agent", scope: "scope", delegationDepth: 99,
    });
    expect(p.factor_c).toBe(99);
  });
});
