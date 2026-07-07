import { describe, it, expect } from "vitest";
import { handleResolveCrosswalk, handleCoverageReport } from "../src/tools/crosswalk.js";
import { createSessionState } from "../src/state.js";

describe("resolve_crosswalk tool", () => {
  it("resolves a procedure to framework mappings", () => {
    const result = handleResolveCrosswalk({ procedure_id: "AI-INF.1" });
    expect(result).toContain("AI-INF.1");
    expect(result).toContain("frameworks");
  });

  it("returns empty message for unknown procedure", () => {
    const result = handleResolveCrosswalk({ procedure_id: "AI-FAKE.99" });
    expect(result).toContain("No crosswalk mappings found");
  });

  it("resolves a framework to requirement mappings", () => {
    const result = handleResolveCrosswalk({ framework_id: "EU-AI-ACT" });
    expect(result).toContain("EU-AI-ACT");
    expect(result).toContain("requirements mapped");
  });

  it("returns empty message for unknown framework", () => {
    const result = handleResolveCrosswalk({ framework_id: "FAKE-FW" });
    expect(result).toContain("No crosswalk mappings found");
  });

  it("lists all frameworks when no args given", () => {
    const result = handleResolveCrosswalk({});
    expect(result).toContain("Available frameworks");
    expect(result).toContain("Data version:");
  });
});

describe("coverage_report tool", () => {
  it("reports zero coverage with no audit session", () => {
    const state = createSessionState();
    const result = handleCoverageReport({ framework: "EU-AI-ACT" }, state);
    expect(result).toContain("0%");
    expect(result).toContain("No active audit session");
  });

  it("reports coverage for witnessed procedures", () => {
    const state = createSessionState();
    state.activeAuditSession = {
      sessionId: "test-session",
      startedAt: Date.now(),
      proceduresWitnessed: ["AI-INF.1", "AI-GRD.1"],
    };
    const result = handleCoverageReport({ framework: "EU-AI-ACT" }, state);
    expect(result).toContain("Framework Coverage: EU-AI-ACT");
    expect(result).toContain("[x]");
  });

  it("rejects unknown framework", () => {
    const state = createSessionState();
    const result = handleCoverageReport({ framework: "FAKE-FW" }, state);
    expect(result).toContain("Unknown framework");
  });
});
