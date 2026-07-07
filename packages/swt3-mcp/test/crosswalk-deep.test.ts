import { describe, it, expect } from "vitest";
import { handleResolveCrosswalk, handleCoverageReport } from "../src/tools/crosswalk.js";
import { createSessionState } from "../src/state.js";

describe("resolve_crosswalk: procedure resolution", () => {
  it("resolves AI-INF.1 to multiple frameworks", () => {
    const result = handleResolveCrosswalk({ procedure_id: "AI-INF.1" });
    expect(result).toContain("AI-INF.1");
    expect(result).toContain("frameworks");
    // AI-INF.1 should map to EU AI Act and NIST AI RMF at minimum
    expect(result).toMatch(/EU-AI-ACT|NIST-AI-RMF/);
  });

  it("resolves AI-FAIR.1 with framework details", () => {
    const result = handleResolveCrosswalk({ procedure_id: "AI-FAIR.1" });
    expect(result).toContain("AI-FAIR.1");
    expect(result).toContain("Data version:");
  });

  it("resolves AI-REV.1 (revocation procedure)", () => {
    const result = handleResolveCrosswalk({ procedure_id: "AI-REV.1" });
    // AI-REV.1 should exist in the crosswalk data
    expect(result).not.toContain("No crosswalk mappings found");
  });

  it("returns empty for non-existent procedure", () => {
    const result = handleResolveCrosswalk({ procedure_id: "AI-FAKE.99" });
    expect(result).toContain("No crosswalk mappings found");
  });
});

describe("resolve_crosswalk: framework resolution", () => {
  it("resolves EU-AI-ACT to requirement mappings", () => {
    const result = handleResolveCrosswalk({ framework_id: "EU-AI-ACT" });
    expect(result).toContain("EU-AI-ACT");
    expect(result).toContain("requirements mapped");
    // Should have multiple requirements
    expect(result).toMatch(/Art\./);
  });

  it("resolves NIST-AI-RMF", () => {
    const result = handleResolveCrosswalk({ framework_id: "NIST-AI-RMF" });
    expect(result).toContain("NIST-AI-RMF");
    expect(result).toContain("requirements mapped");
  });

  it("resolves NIST-800-53", () => {
    const result = handleResolveCrosswalk({ framework_id: "NIST-800-53" });
    expect(result).toContain("requirements mapped");
  });

  it("resolves SR-11-7", () => {
    const result = handleResolveCrosswalk({ framework_id: "SR-11-7" });
    expect(result).toContain("requirements mapped");
  });

  it("returns error for non-existent framework", () => {
    const result = handleResolveCrosswalk({ framework_id: "FAKE-FW-2099" });
    expect(result).toContain("No crosswalk mappings found");
    expect(result).toContain("available frameworks");
  });
});

describe("resolve_crosswalk: no args (framework listing)", () => {
  it("lists all available frameworks", () => {
    const result = handleResolveCrosswalk({});
    expect(result).toContain("Available frameworks");
    // Should have 20+ frameworks
    expect(result).toContain("EU-AI-ACT");
    expect(result).toContain("NIST-AI-RMF");
    expect(result).toContain("Data version:");
  });

  it("includes enforcement dates where available", () => {
    const result = handleResolveCrosswalk({});
    expect(result).toContain("Enforcement:");
  });
});

describe("coverage_report: session coverage", () => {
  it("reports zero coverage with no audit session", () => {
    const state = createSessionState();
    const result = handleCoverageReport({ framework: "EU-AI-ACT" }, state);
    expect(result).toContain("0%");
    expect(result).toContain("No active audit session");
    expect(result).toContain("Remaining");
  });

  it("reports partial coverage for witnessed procedures", () => {
    const state = createSessionState();
    state.activeAuditSession = {
      sessionId: "test-session",
      startedAt: Date.now(),
      proceduresWitnessed: ["AI-INF.1", "AI-GRD.1", "AI-FAIR.1"],
    };
    const result = handleCoverageReport({ framework: "EU-AI-ACT" }, state);
    expect(result).toContain("Framework Coverage: EU-AI-ACT");
    // Should have some covered and some remaining
    expect(result).toContain("[x]");
    expect(result).toContain("[ ]");
    // Score should be between 1% and 99% (not full coverage with just 3 procs)
    const scoreMatch = result.match(/Score: (\d+)%/);
    expect(scoreMatch).toBeTruthy();
    const score = parseInt(scoreMatch![1]);
    expect(score).toBeGreaterThan(0);
    expect(score).toBeLessThan(100);
  });

  it("handles duplicate witnessed procedures", () => {
    const state = createSessionState();
    state.activeAuditSession = {
      sessionId: "test-session",
      startedAt: Date.now(),
      proceduresWitnessed: ["AI-INF.1", "AI-INF.1", "AI-INF.1"],
    };
    const result = handleCoverageReport({ framework: "EU-AI-ACT" }, state);
    // Should still show AI-INF.1 as covered only once
    const coveredMatches = result.match(/\[x\]/g);
    expect(coveredMatches).toBeTruthy();
    // Only 1 unique procedure, so only 1 [x]
    expect(coveredMatches!.length).toBe(1);
  });

  it("rejects unknown framework with helpful message", () => {
    const state = createSessionState();
    const result = handleCoverageReport({ framework: "NOT-A-FRAMEWORK" }, state);
    expect(result).toContain("Unknown framework");
    expect(result).toContain("Available:");
    // Should list some real framework IDs
    expect(result).toContain("EU-AI-ACT");
  });

  it("works with NIST-AI-RMF framework", () => {
    const state = createSessionState();
    state.activeAuditSession = {
      sessionId: "nist-test",
      startedAt: Date.now(),
      proceduresWitnessed: ["AI-INF.1"],
    };
    const result = handleCoverageReport({ framework: "NIST-AI-RMF" }, state);
    expect(result).toContain("Framework Coverage: NIST-AI-RMF");
  });
});
