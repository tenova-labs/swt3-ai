import { describe, it, expect, vi } from "vitest";
import { handleStartAudit, handleEndAudit, trackProcedure } from "../src/tools/audit.js";
import { handleSuggest } from "../src/tools/suggest.js";
import { createSessionState } from "../src/state.js";
import type { AxiomClient } from "../src/client.js";

function mockClient(registry: Record<string, unknown> = {}): AxiomClient {
  return {
    fetchRegistry: vi.fn().mockResolvedValue(registry),
  } as unknown as AxiomClient;
}

const mockRegistry = {
  procedures: [
    { procedure_id: "AI-INF.1" },
    { procedure_id: "AI-DRIFT.1" },
    { procedure_id: "AI-GRD.1" },
    { procedure_id: "AI-ID.1" },
    { procedure_id: "AI-ACC.1" },
    { procedure_id: "AI-TOOL.1" },
    { procedure_id: "AI-REV.1" },
    { procedure_id: "AI-CHAIN.1" },
    { procedure_id: "AI-VIO.1" },
  ],
};

describe("start_audit_session", () => {
  it("starts a new session", () => {
    const state = createSessionState();
    const result = handleStartAudit(state);

    expect(result).toContain("Audit session started");
    expect(result).toContain("Session ID:");
    expect(state.activeAuditSession).not.toBeNull();
    expect(state.activeAuditSession!.proceduresWitnessed).toEqual([]);
  });

  it("is idempotent -- returns existing session", () => {
    const state = createSessionState();
    const result1 = handleStartAudit(state);
    const sessionId = state.activeAuditSession!.sessionId;

    const result2 = handleStartAudit(state);
    expect(result2).toContain("already active");
    expect(state.activeAuditSession!.sessionId).toBe(sessionId);
  });
});

describe("end_audit_session", () => {
  it("produces gap report with witnessed and unwitnessed procedures", async () => {
    const state = createSessionState();
    handleStartAudit(state);

    trackProcedure(state, "AI-INF.1");
    trackProcedure(state, "AI-ACC.1");

    const client = mockClient(mockRegistry);
    const result = await handleEndAudit({}, state, client);

    expect(result).toContain("Audit Session Complete");
    expect(result).toContain("[x] AI-ACC.1");
    expect(result).toContain("[x] AI-INF.1");
    expect(result).toContain("[ ] AI-DRIFT.1");
    expect(result).toContain("AI Procedure Coverage:");
    expect(state.activeAuditSession).toBeNull(); // cleared
  });

  it("returns helpful message when no session active", async () => {
    const state = createSessionState();
    const client = mockClient(mockRegistry);
    const result = await handleEndAudit({}, state, client);

    expect(result).toContain("No audit session");
  });

  it("deduplicates witnessed procedures", async () => {
    const state = createSessionState();
    handleStartAudit(state);

    trackProcedure(state, "AI-INF.1");
    trackProcedure(state, "AI-INF.1");
    trackProcedure(state, "AI-INF.1");

    const client = mockClient(mockRegistry);
    const result = await handleEndAudit({}, state, client);

    const matches = result.match(/\[x\] AI-INF\.1/g);
    expect(matches).toHaveLength(1);
  });

  it("handles registry fetch failure gracefully", async () => {
    const state = createSessionState();
    handleStartAudit(state);
    trackProcedure(state, "AI-INF.1");

    const client = {
      fetchRegistry: vi.fn().mockRejectedValue(new Error("network error")),
    } as unknown as AxiomClient;

    const result = await handleEndAudit({}, state, client);
    expect(result).toContain("Audit Session Complete");
    expect(result).toContain("[x] AI-INF.1");
  });
});

describe("trackProcedure", () => {
  it("tracks when session is active", () => {
    const state = createSessionState();
    handleStartAudit(state);
    trackProcedure(state, "AI-INF.1");
    expect(state.activeAuditSession!.proceduresWitnessed).toEqual(["AI-INF.1"]);
  });

  it("is a no-op when no session active", () => {
    const state = createSessionState();
    trackProcedure(state, "AI-INF.1"); // should not throw
  });
});

describe("suggest_procedures", () => {
  it("suggests AI-INF.1 for inference context", () => {
    const result = handleSuggest({ context: "calling GPT-4o to generate a summary" });
    expect(result).toContain("AI-INF.1");
    expect(result).toContain("Inference Provenance");
  });

  it("suggests AI-ACC.1 for data access context", () => {
    const result = handleSuggest({ context: "reading from the database to fetch user records" });
    expect(result).toContain("AI-ACC.1");
  });

  it("suggests AI-TOOL.1 for tool use context", () => {
    const result = handleSuggest({ context: "executing a function call to search the web" });
    expect(result).toContain("AI-TOOL.1");
  });

  it("suggests AI-GRD.1 for safety context", () => {
    const result = handleSuggest({ context: "checking content filter and safety guardrails" });
    expect(result).toContain("AI-GRD.1");
  });

  it("boosts AI-ACC.1 for sensitive data classification", () => {
    const result = handleSuggest({ context: "processing records", data_classification: "sensitive" });
    expect(result).toContain("AI-ACC.1");
  });

  it("returns at least one suggestion for empty context", () => {
    const result = handleSuggest({ context: "" });
    expect(result).toContain("AI-INF.1"); // default fallback
  });

  it("is advisory only", () => {
    const result = handleSuggest({ context: "anything" });
    expect(result).toContain("advisory only");
  });
});
