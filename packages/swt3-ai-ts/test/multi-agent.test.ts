/**
 * Tests for AI-MULTI.1 Multi-Agent Delegation Witnessing.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Witness } from "../src/witness.js";

function mkWitness(opts: Record<string, unknown> = {}) {
  return new Witness({
    endpoint: "https://test.example.com",
    apiKey: "axm_test_key",
    tenantId: "test_tenant",
    disableFlush: true,
    ...opts,
  });
}

describe("witnessMultiAgentDelegation (AI-MULTI.1)", () => {
  let origConsole: typeof console.log;
  beforeEach(() => { origConsole = console.log; console.log = vi.fn(); });
  afterEach(() => { console.log = origConsole; });

  it("mints correct procedure and factors", () => {
    const w = mkWitness();
    const p = w.witnessMultiAgentDelegation({
      delegationDepth: 2, permissionsGranted: 5,
      timeBoundMinutes: 60,
      parentAgentId: "orchestrator-1",
      childAgentId: "worker-2",
    });
    expect(p.procedure_id).toBe("AI-MULTI.1");
    expect(p.factor_a).toBe(2);
    expect(p.factor_b).toBe(5);
    expect(p.factor_c).toBe(60);
    expect(p.anchor_fingerprint).toBeTruthy();
  });

  it("sets factor_c to 0 for unbounded delegation", () => {
    const w = mkWitness();
    const p = w.witnessMultiAgentDelegation({
      delegationDepth: 1, permissionsGranted: 3,
      timeBoundMinutes: 0,
      parentAgentId: "parent", childAgentId: "child",
    });
    expect(p.factor_c).toBe(0);
  });

  it("hashes parent and child agent IDs in context", () => {
    const w = mkWitness({ clearingLevel: 1 });
    const p = w.witnessMultiAgentDelegation({
      delegationDepth: 1, permissionsGranted: 2,
      timeBoundMinutes: 30,
      parentAgentId: "orchestrator-1",
      childAgentId: "worker-2",
    });
    expect(p.ai_context).toBeTruthy();
    expect(p.ai_context!.provider).toBe("multi-agent");
    // Agent IDs must be hashed, not raw
    expect(p.ai_context!.parent_agent_hash).toBeTruthy();
    expect(p.ai_context!.parent_agent_hash).not.toBe("orchestrator-1");
    expect(p.ai_context!.child_agent_hash).toBeTruthy();
    expect(p.ai_context!.child_agent_hash).not.toBe("worker-2");
    expect(p.ai_model_id).toBe("delegation-depth-1");
  });

  it("includes delegated_tools in context", () => {
    const w = mkWitness({ clearingLevel: 0 });
    const p = w.witnessMultiAgentDelegation({
      delegationDepth: 1, permissionsGranted: 3,
      timeBoundMinutes: 120,
      parentAgentId: "p", childAgentId: "c",
      delegatedTools: ["read_file", "write_file", "execute_query"],
    });
    expect(p.ai_context!.delegated_tools).toEqual(
      ["read_file", "write_file", "execute_query"],
    );
  });

  it("includes scope_hash in context", () => {
    const w = mkWitness({ clearingLevel: 1 });
    const p = w.witnessMultiAgentDelegation({
      delegationDepth: 1, permissionsGranted: 2,
      timeBoundMinutes: 60,
      parentAgentId: "p", childAgentId: "c",
      scopeHash: "abc123def456",
    });
    expect(p.ai_context!.scope_hash).toBe("abc123def456");
  });

  it("hashes each authorization_chain entry", () => {
    const w = mkWitness({ clearingLevel: 1 });
    const p = w.witnessMultiAgentDelegation({
      delegationDepth: 3, permissionsGranted: 2,
      timeBoundMinutes: 60,
      parentAgentId: "mid-agent",
      childAgentId: "leaf-agent",
      authorizationChain: ["human-user", "orchestrator", "mid-agent"],
    });
    const chain = p.ai_context!.authorization_chain as string[];
    expect(chain).toHaveLength(3);
    // Each entry must be hashed, not raw
    expect(chain[0]).not.toBe("human-user");
    expect(chain[1]).not.toBe("orchestrator");
    expect(chain[2]).not.toBe("mid-agent");
    // Each entry should be a consistent hash
    expect(chain[0]).toMatch(/^[0-9a-f]+$/);
  });

  it("strips context at clearing level 2", () => {
    const w = mkWitness({ clearingLevel: 2 });
    const p = w.witnessMultiAgentDelegation({
      delegationDepth: 2, permissionsGranted: 5,
      timeBoundMinutes: 60,
      parentAgentId: "p", childAgentId: "c",
      delegatedTools: ["tool1"],
    });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(2);
    expect(p.factor_b).toBe(5);
    expect(p.factor_c).toBe(60);
  });

  it("preserves factors at clearing level 3", () => {
    const w = mkWitness({ clearingLevel: 3 });
    const p = w.witnessMultiAgentDelegation({
      delegationDepth: 4, permissionsGranted: 10,
      timeBoundMinutes: 0,
      parentAgentId: "p", childAgentId: "c",
    });
    expect(p.ai_context).toBeUndefined();
    expect(p.factor_a).toBe(4);
    expect(p.factor_b).toBe(10);
    expect(p.factor_c).toBe(0);
  });

  it("handles deep delegation (10 hops)", () => {
    const w = mkWitness();
    const p = w.witnessMultiAgentDelegation({
      delegationDepth: 10, permissionsGranted: 1,
      timeBoundMinutes: 5,
      parentAgentId: "agent-9", childAgentId: "agent-10",
    });
    expect(p.factor_a).toBe(10);
  });

  it("mints valid 12-char hex fingerprint", () => {
    const w = mkWitness();
    const p = w.witnessMultiAgentDelegation({
      delegationDepth: 1, permissionsGranted: 1,
      timeBoundMinutes: 0,
      parentAgentId: "a", childAgentId: "b",
    });
    expect(p.anchor_fingerprint).toMatch(/^[0-9a-f]{12}$/);
  });
});
