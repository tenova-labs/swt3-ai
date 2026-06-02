/**
 * SWT3 MCP Server -- Tool Policy Enforcement Tests.
 */

import { describe, it, expect } from "vitest";
import {
  matchesToolPattern,
  initChainDensity,
  checkChainDensity,
  evaluateToolPolicy,
} from "../src/tool-policy.js";
import type { McpToolPolicy } from "../src/config.js";

function makePolicy(overrides: Partial<McpToolPolicy> = {}): McpToolPolicy {
  return {
    witnessedTools: [],
    exemptTools: [],
    requireTrustLevel: 0,
    autoWitness: true,
    blockOnFailure: true,
    ...overrides,
  };
}

describe("matchesToolPattern", () => {
  it("matches exact tool name", () => {
    expect(matchesToolPattern("witness_inference", ["witness_inference"])).toBe(true);
  });

  it("matches wildcard glob", () => {
    expect(matchesToolPattern("witness_inference", ["witness_*"])).toBe(true);
    expect(matchesToolPattern("verify_anchor", ["witness_*"])).toBe(false);
  });

  it("matches ? single char", () => {
    expect(matchesToolPattern("tool_a", ["tool_?"])).toBe(true);
    expect(matchesToolPattern("tool_ab", ["tool_?"])).toBe(false);
  });

  it("returns false for empty pattern list", () => {
    expect(matchesToolPattern("anything", [])).toBe(false);
  });

  it("matches across multiple patterns", () => {
    expect(matchesToolPattern("verify_anchor", ["witness_*", "verify_*"])).toBe(true);
  });
});

describe("evaluateToolPolicy", () => {
  it("returns null when no policy configured", () => {
    expect(evaluateToolPolicy("witness_inference", null, null)).toBeNull();
  });

  it("returns witness when autoWitness is true and tool matches", () => {
    const policy = makePolicy({ autoWitness: true });
    expect(evaluateToolPolicy("any_tool", policy, null)).toBe("witness");
  });

  it("returns exempt when autoWitness is false", () => {
    const policy = makePolicy({ autoWitness: false });
    expect(evaluateToolPolicy("any_tool", policy, null)).toBe("exempt");
  });

  it("returns exempt for tools in exemptTools list", () => {
    const policy = makePolicy({ exemptTools: ["health_*", "signup"] });
    expect(evaluateToolPolicy("signup", policy, null)).toBe("exempt");
    expect(evaluateToolPolicy("health_check", policy, null)).toBe("exempt");
    expect(evaluateToolPolicy("witness_inference", policy, null)).toBe("witness");
  });

  it("returns exempt for tools not matching witnessedTools", () => {
    const policy = makePolicy({ witnessedTools: ["witness_*"] });
    expect(evaluateToolPolicy("verify_anchor", policy, null)).toBe("exempt");
    expect(evaluateToolPolicy("witness_inference", policy, null)).toBe("witness");
  });

  it("blocks when trust level is insufficient", () => {
    const policy = makePolicy({ requireTrustLevel: 2 });
    expect(evaluateToolPolicy("tool_a", policy, null, 1)).toBe("block");
    expect(evaluateToolPolicy("tool_a", policy, null, 2)).toBe("witness");
    expect(evaluateToolPolicy("tool_a", policy, null, 3)).toBe("witness");
  });

  it("defaults trust level to 0 when not provided", () => {
    const policy = makePolicy({ requireTrustLevel: 1 });
    expect(evaluateToolPolicy("tool_a", policy, null)).toBe("block");
  });
});

describe("initChainDensity", () => {
  it("returns null when no density config", () => {
    const policy = makePolicy();
    expect(initChainDensity(policy)).toBeNull();
  });

  it("initializes with velocity config", () => {
    const policy = makePolicy({ maxVelocity: "5/30s" });
    const state = initChainDensity(policy);
    expect(state).not.toBeNull();
    expect(state!.velocityLimit).toBe(5);
    expect(state!.velocityWindowMs).toBe(30000);
  });

  it("initializes with blocklist", () => {
    const policy = makePolicy({ toolBlocklist: ["dangerous_*"] });
    const state = initChainDensity(policy);
    expect(state).not.toBeNull();
    expect(state!.blockPatterns).toHaveLength(1);
  });

  it("initializes with allowlist", () => {
    const policy = makePolicy({ toolAllowlist: ["safe_*", "witness_*"] });
    const state = initChainDensity(policy);
    expect(state).not.toBeNull();
    expect(state!.allowPatterns).toHaveLength(2);
  });
});

describe("checkChainDensity", () => {
  it("blocks tools on the blocklist", () => {
    const policy = makePolicy({ toolBlocklist: ["evil_*"] });
    const state = initChainDensity(policy)!;
    expect(checkChainDensity(state, "evil_tool")).toContain("blocklist");
    expect(checkChainDensity(state, "safe_tool")).toBeNull();
  });

  it("blocks tools not on the allowlist", () => {
    const policy = makePolicy({ toolAllowlist: ["allowed_*"] });
    const state = initChainDensity(policy)!;
    expect(checkChainDensity(state, "not_allowed")).toContain("allowlist");
    expect(checkChainDensity(state, "allowed_tool")).toBeNull();
  });

  it("enforces chain depth limit", () => {
    const policy = makePolicy({ maxChainDepth: 2 });
    const state = initChainDensity(policy)!;
    expect(checkChainDensity(state, "tool_a")).toBeNull(); // depth 1
    expect(checkChainDensity(state, "tool_a")).toBeNull(); // depth 2
    expect(checkChainDensity(state, "tool_a")).toContain("Chain depth"); // depth 3
  });

  it("resets chain depth on tool name change", () => {
    const policy = makePolicy({ maxChainDepth: 2 });
    const state = initChainDensity(policy)!;
    checkChainDensity(state, "tool_a"); // depth 1
    checkChainDensity(state, "tool_a"); // depth 2
    expect(checkChainDensity(state, "tool_b")).toBeNull(); // reset to 1
  });
});

describe("evaluateToolPolicy with chain density", () => {
  it("blocks when chain density check fails", () => {
    const policy = makePolicy({ toolBlocklist: ["blocked_tool"] });
    const density = initChainDensity(policy);
    expect(evaluateToolPolicy("blocked_tool", policy, density)).toBe("block");
  });

  it("passes when chain density check succeeds", () => {
    const policy = makePolicy({ toolAllowlist: ["allowed_*"] });
    const density = initChainDensity(policy);
    expect(evaluateToolPolicy("allowed_tool", policy, density)).toBe("witness");
  });
});
