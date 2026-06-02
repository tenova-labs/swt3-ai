/**
 * Chain density enforcement tests.
 *
 * Tests the ChainEnforcer class, schema validation for new mcp_policy fields,
 * config loading, and wrapTool integration.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { ChainEnforcer, PolicyViolationError } from "../src/witness.js";
import { validateSchema } from "../src/schema.js";
import type { McpPolicyConfig, ChainRule } from "../src/types.js";

function makePolicy(overrides: Partial<McpPolicyConfig> = {}): McpPolicyConfig {
  return {
    witnessedTools: [],
    exemptTools: [],
    requireTrustLevel: 0,
    autoWitness: true,
    blockOnFailure: false,
    failSecure: true,
    toolAllowlist: [],
    toolBlocklist: [],
    rules: [],
    ...overrides,
  };
}

// ── Schema Validation ───────────────────────────────────────────────────

describe("schema: chain density fields", () => {
  it("accepts valid chain density config", () => {
    const result = validateSchema({
      mcp_policy: {
        max_velocity: "4/30s",
        max_chain_depth: 5,
        tool_allowlist: ["read_*"],
        tool_blocklist: ["shell_*"],
        fail_secure: true,
        rules: [
          { match: "dangerous_*", action: "block", reason: "dangerous tool" },
        ],
      },
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("rejects invalid max_velocity format", () => {
    const result = validateSchema({
      mcp_policy: { max_velocity: "fast" },
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path === "mcp_policy.max_velocity")).toBe(true);
  });

  it("rejects max_chain_depth < 1", () => {
    const result = validateSchema({
      mcp_policy: { max_chain_depth: 0 },
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path === "mcp_policy.max_chain_depth")).toBe(true);
  });

  it("rejects non-number max_chain_depth", () => {
    const result = validateSchema({
      mcp_policy: { max_chain_depth: "five" },
    });
    expect(result.valid).toBe(false);
  });

  it("rejects rules with missing required fields", () => {
    const result = validateSchema({
      mcp_policy: {
        rules: [{ match: "foo" }],
      },
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path.includes("action"))).toBe(true);
    expect(result.errors.some((e) => e.path.includes("reason"))).toBe(true);
  });

  it("rejects rules with invalid action", () => {
    const result = validateSchema({
      mcp_policy: {
        rules: [{ match: "*", action: "destroy", reason: "test" }],
      },
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path.includes("action"))).toBe(true);
  });

  it("accepts valid velocity formats", () => {
    for (const v of ["1/1s", "10/60s", "100/3600s"]) {
      const result = validateSchema({ mcp_policy: { max_velocity: v } });
      expect(result.valid).toBe(true);
    }
  });
});

// ── ChainEnforcer: Blocklist ────────────────────────────────────────────

describe("ChainEnforcer: blocklist", () => {
  it("blocks tool on the blocklist", () => {
    const enforcer = new ChainEnforcer(makePolicy({ toolBlocklist: ["shell_execute"] }));
    const v = enforcer.check("shell_execute");
    expect(v).not.toBeNull();
    expect(v!.action).toBe("blocked");
    expect(v!.rule).toBe("blocklist");
  });

  it("blocks tool matching glob pattern", () => {
    const enforcer = new ChainEnforcer(makePolicy({ toolBlocklist: ["shell_*"] }));
    const v = enforcer.check("shell_run");
    expect(v).not.toBeNull();
    expect(v!.action).toBe("blocked");
  });

  it("allows tool not on the blocklist", () => {
    const enforcer = new ChainEnforcer(makePolicy({ toolBlocklist: ["shell_*"] }));
    expect(enforcer.check("read_file")).toBeNull();
  });
});

// ── ChainEnforcer: Allowlist ────────────────────────────────────────────

describe("ChainEnforcer: allowlist", () => {
  it("allows tool on the allowlist", () => {
    const enforcer = new ChainEnforcer(makePolicy({ toolAllowlist: ["read_*", "list_files"] }));
    expect(enforcer.check("read_file")).toBeNull();
    expect(enforcer.check("list_files")).toBeNull();
  });

  it("blocks tool not on the allowlist", () => {
    const enforcer = new ChainEnforcer(makePolicy({ toolAllowlist: ["read_*"] }));
    const v = enforcer.check("write_file");
    expect(v).not.toBeNull();
    expect(v!.action).toBe("blocked");
    expect(v!.rule).toBe("allowlist");
  });

  it("allows all tools when allowlist is empty", () => {
    const enforcer = new ChainEnforcer(makePolicy({ toolAllowlist: [] }));
    expect(enforcer.check("anything")).toBeNull();
  });
});

// ── ChainEnforcer: Blocklist precedence ─────────────────────────────────

describe("ChainEnforcer: blocklist takes precedence over allowlist", () => {
  it("blocks tool even if on the allowlist", () => {
    const enforcer = new ChainEnforcer(makePolicy({
      toolAllowlist: ["shell_*"],
      toolBlocklist: ["shell_execute"],
    }));
    const v = enforcer.check("shell_execute");
    expect(v).not.toBeNull();
    expect(v!.rule).toBe("blocklist");
  });
});

// ── ChainEnforcer: Velocity ─────────────────────────────────────────────

describe("ChainEnforcer: velocity", () => {
  it("allows calls under the limit", () => {
    const enforcer = new ChainEnforcer(makePolicy({ maxVelocity: "3/60s" }));
    expect(enforcer.check("tool_a")).toBeNull();
    expect(enforcer.check("tool_b")).toBeNull();
    expect(enforcer.check("tool_c")).toBeNull();
  });

  it("blocks when velocity limit is exceeded", () => {
    const enforcer = new ChainEnforcer(makePolicy({ maxVelocity: "2/60s" }));
    expect(enforcer.check("tool_a")).toBeNull();
    expect(enforcer.check("tool_b")).toBeNull();
    const v = enforcer.check("tool_c");
    expect(v).not.toBeNull();
    expect(v!.rule).toBe("velocity");
    expect(v!.action).toBe("blocked");
  });

  it("resets after window expires", () => {
    const enforcer = new ChainEnforcer(makePolicy({ maxVelocity: "2/1s" }));
    expect(enforcer.check("tool_a")).toBeNull();
    expect(enforcer.check("tool_b")).toBeNull();

    // Simulate time passing by manipulating the internal window
    const internal = enforcer as any;
    internal.velocityWindow = [Date.now() - 2000, Date.now() - 2000];

    expect(enforcer.check("tool_c")).toBeNull();
  });

  it("logs instead of blocking when fail_secure is false", () => {
    const enforcer = new ChainEnforcer(makePolicy({ maxVelocity: "1/60s", failSecure: false }));
    expect(enforcer.check("tool_a")).toBeNull();
    const v = enforcer.check("tool_b");
    expect(v).not.toBeNull();
    expect(v!.action).toBe("logged");
  });
});

// ── ChainEnforcer: Depth ────────────────────────────────────────────────

describe("ChainEnforcer: depth", () => {
  it("allows calls up to max depth", () => {
    const enforcer = new ChainEnforcer(makePolicy({ maxChainDepth: 3 }));
    expect(enforcer.check("tool_a")).toBeNull();
    expect(enforcer.check("tool_a")).toBeNull();
    expect(enforcer.check("tool_a")).toBeNull();
  });

  it("blocks when depth exceeds max", () => {
    const enforcer = new ChainEnforcer(makePolicy({ maxChainDepth: 2 }));
    expect(enforcer.check("tool_a")).toBeNull();
    expect(enforcer.check("tool_a")).toBeNull();
    const v = enforcer.check("tool_a");
    expect(v).not.toBeNull();
    expect(v!.rule).toBe("depth");
  });

  it("resets depth when tool name changes", () => {
    const enforcer = new ChainEnforcer(makePolicy({ maxChainDepth: 2 }));
    expect(enforcer.check("tool_a")).toBeNull();
    expect(enforcer.check("tool_a")).toBeNull();
    // Switch tool -- resets depth
    expect(enforcer.check("tool_b")).toBeNull();
    expect(enforcer.check("tool_b")).toBeNull();
  });

  it("resetDepth zeroes the counter", () => {
    const enforcer = new ChainEnforcer(makePolicy({ maxChainDepth: 2 }));
    expect(enforcer.check("tool_a")).toBeNull();
    expect(enforcer.check("tool_a")).toBeNull();
    enforcer.resetDepth();
    expect(enforcer.check("tool_a")).toBeNull();
  });
});

// ── ChainEnforcer: Custom Rules ─────────────────────────────────────────

describe("ChainEnforcer: custom rules", () => {
  it("fires matching custom rule", () => {
    const rules: ChainRule[] = [
      { match: "danger_*", action: "block", reason: "Dangerous operation" },
    ];
    const enforcer = new ChainEnforcer(makePolicy({ rules }));
    const v = enforcer.check("danger_zone");
    expect(v).not.toBeNull();
    expect(v!.reason).toBe("Dangerous operation");
    expect(v!.action).toBe("blocked");
  });

  it("passes non-matching tools through", () => {
    const rules: ChainRule[] = [
      { match: "danger_*", action: "block", reason: "Dangerous" },
    ];
    const enforcer = new ChainEnforcer(makePolicy({ rules }));
    expect(enforcer.check("safe_tool")).toBeNull();
  });

  it("logs instead of blocking for log action", () => {
    const rules: ChainRule[] = [
      { match: "*", action: "log", reason: "Audit all calls" },
    ];
    const enforcer = new ChainEnforcer(makePolicy({ rules }));
    const v = enforcer.check("any_tool");
    expect(v).not.toBeNull();
    expect(v!.action).toBe("logged");
  });
});

// ── PolicyViolationError ────────────────────────────────────────────────

describe("PolicyViolationError", () => {
  it("contains violation details", () => {
    const violation = {
      rule: "blocklist",
      toolName: "shell_exec",
      action: "blocked" as const,
      reason: "Tool on blocklist",
      timestamp: Date.now(),
    };
    const err = new PolicyViolationError(violation);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("PolicyViolationError");
    expect(err.violation).toBe(violation);
    expect(err.message).toContain("Tool on blocklist");
  });
});

// ── ChainEnforcer: Token Budget ──────────────────────────────────────────

describe("ChainEnforcer: token budget", () => {
  it("allows calls when under budget", () => {
    const enforcer = new ChainEnforcer(makePolicy({ maxTokensPerSession: 1000 }));
    enforcer.recordTokens(500);
    expect(enforcer.check("tool_a")).toBeNull();
  });

  it("blocks when token budget is exceeded", () => {
    const enforcer = new ChainEnforcer(makePolicy({ maxTokensPerSession: 1000 }));
    enforcer.recordTokens(1000);
    const v = enforcer.check("tool_a");
    expect(v).not.toBeNull();
    expect(v!.rule).toBe("token_budget");
    expect(v!.action).toBe("blocked");
  });

  it("logs instead of blocking when fail_secure is false", () => {
    const enforcer = new ChainEnforcer(makePolicy({ maxTokensPerSession: 100, failSecure: false }));
    enforcer.recordTokens(200);
    const v = enforcer.check("tool_a");
    expect(v).not.toBeNull();
    expect(v!.action).toBe("logged");
  });

  it("accumulates across multiple recordTokens calls", () => {
    const enforcer = new ChainEnforcer(makePolicy({ maxTokensPerSession: 100 }));
    enforcer.recordTokens(40);
    enforcer.recordTokens(40);
    expect(enforcer.check("tool_a")).toBeNull();
    enforcer.recordTokens(30);
    const v = enforcer.check("tool_a");
    expect(v).not.toBeNull();
    expect(v!.rule).toBe("token_budget");
  });

  it("resetTokens clears the counter", () => {
    const enforcer = new ChainEnforcer(makePolicy({ maxTokensPerSession: 100 }));
    enforcer.recordTokens(200);
    enforcer.resetTokens();
    expect(enforcer.check("tool_a")).toBeNull();
  });

  it("allows unlimited when maxTokensPerSession is not set", () => {
    const enforcer = new ChainEnforcer(makePolicy());
    enforcer.recordTokens(999999);
    expect(enforcer.check("tool_a")).toBeNull();
  });
});

// ── ChainEnforcer: Violation History ────────────────────────────────────

describe("ChainEnforcer: violation history", () => {
  it("records violations in history", () => {
    const enforcer = new ChainEnforcer(makePolicy({ toolBlocklist: ["bad_tool"] }));
    enforcer.check("bad_tool");
    expect(enforcer.violations).toHaveLength(1);
    expect(enforcer.violations[0].rule).toBe("blocklist");
  });

  it("clearViolations empties history", () => {
    const enforcer = new ChainEnforcer(makePolicy({ toolBlocklist: ["bad_tool"] }));
    enforcer.check("bad_tool");
    enforcer.clearViolations();
    expect(enforcer.violations).toHaveLength(0);
  });

  it("does not record when check passes", () => {
    const enforcer = new ChainEnforcer(makePolicy({ toolBlocklist: ["bad_tool"] }));
    enforcer.check("good_tool");
    expect(enforcer.violations).toHaveLength(0);
  });
});

// ── Schema: max_tokens_per_session ──────────────────────────────────────

describe("schema: max_tokens_per_session", () => {
  it("accepts valid value", () => {
    const result = validateSchema({ mcp_policy: { max_tokens_per_session: 10000 } });
    expect(result.valid).toBe(true);
  });

  it("rejects value < 1", () => {
    const result = validateSchema({ mcp_policy: { max_tokens_per_session: 0 } });
    expect(result.valid).toBe(false);
  });

  it("rejects non-number", () => {
    const result = validateSchema({ mcp_policy: { max_tokens_per_session: "many" } });
    expect(result.valid).toBe(false);
  });
});

// ── No-op when no chain density configured ──────────────────────────────

describe("ChainEnforcer: passthrough with no constraints", () => {
  it("allows all calls when no limits are set", () => {
    const enforcer = new ChainEnforcer(makePolicy());
    for (let i = 0; i < 100; i++) {
      expect(enforcer.check(`tool_${i}`)).toBeNull();
    }
  });
});
