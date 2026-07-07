/**
 * Tests for CrewAI adapter.
 */

import { describe, it, expect, vi } from "vitest";
import { wrapCrewAI } from "../src/adapters/crewai.js";
import type { CrewAICrew } from "../src/adapters/crewai.js";

function mockWitness() {
  return {
    record: vi.fn(),
    config: {
      clearingLevel: 1,
      tenantId: "TEST",
      guardrailNames: [],
      guardrailsRequired: 0,
      procedures: [],
    },
  } as any;
}

function mockCrew(output: unknown = "Crew completed successfully."): CrewAICrew {
  return {
    kickoff: vi.fn(() => output),
    name: "research-crew",
    agents: [{ name: "researcher" }, { name: "writer" }],
    tasks: [{ description: "research" }, { description: "write" }, { description: "review" }],
  };
}

describe("wrapCrewAI", () => {
  it("wraps kickoff and calls witness.record", () => {
    const crew = mockCrew();
    const w = mockWitness();
    const wrapped = wrapCrewAI(crew, w);

    wrapped.kickoff();

    expect(crew.kickoff).toHaveBeenCalledTimes(1);
    expect(w.record).toHaveBeenCalledTimes(1);
  });

  it("preserves return value", () => {
    const expected = { raw: "Report content", tasks_output: [1, 2, 3] };
    const crew = mockCrew(expected);
    const w = mockWitness();
    const wrapped = wrapCrewAI(crew, w);

    const result = wrapped.kickoff();

    expect(result).toBe(expected);
  });

  it("passes inputs to original kickoff", () => {
    const crew = mockCrew();
    const w = mockWitness();
    const wrapped = wrapCrewAI(crew, w);

    wrapped.kickoff({ topic: "AI compliance" });

    expect(crew.kickoff).toHaveBeenCalledWith({ topic: "AI compliance" });
  });

  it("defaults modelId to crewai-{name}", () => {
    const crew = mockCrew();
    const w = mockWitness();
    const wrapped = wrapCrewAI(crew, w);

    wrapped.kickoff();

    const record = w.record.mock.calls[0][0];
    expect(record.modelId).toBe("crewai-research-crew");
  });

  it("defaults to crewai-crew when no name", () => {
    const crew: CrewAICrew = { kickoff: vi.fn(() => "ok") };
    const w = mockWitness();
    const wrapped = wrapCrewAI(crew, w);

    wrapped.kickoff();

    const record = w.record.mock.calls[0][0];
    expect(record.modelId).toBe("crewai-crew");
  });

  it("uses explicit modelId", () => {
    const crew = mockCrew();
    const w = mockWitness();
    const wrapped = wrapCrewAI(crew, w, "custom-crew-v2");

    wrapped.kickoff();

    const record = w.record.mock.calls[0][0];
    expect(record.modelId).toBe("custom-crew-v2");
  });

  it("sets provider to crewai", () => {
    const crew = mockCrew();
    const w = mockWitness();
    const wrapped = wrapCrewAI(crew, w);

    wrapped.kickoff();

    const record = w.record.mock.calls[0][0];
    expect(record.provider).toBe("crewai");
  });

  it("captures agent and task counts in tokens", () => {
    const crew = mockCrew();
    const w = mockWitness();
    const wrapped = wrapCrewAI(crew, w);

    wrapped.kickoff();

    const record = w.record.mock.calls[0][0];
    expect(record.inputTokens).toBe(2);  // 2 agents
    expect(record.outputTokens).toBe(3); // 3 tasks
  });

  it("measures latency", () => {
    const crew = mockCrew();
    const w = mockWitness();
    const wrapped = wrapCrewAI(crew, w);

    wrapped.kickoff();

    const record = w.record.mock.calls[0][0];
    expect(record.latencyMs).toBeGreaterThanOrEqual(0);
  });

  it("handles async kickoff", async () => {
    const crew: CrewAICrew = {
      kickoff: vi.fn(() => Promise.resolve("async crew result")),
    };
    const w = mockWitness();
    const wrapped = wrapCrewAI(crew, w);

    const result = await wrapped.kickoff();

    expect(result).toBe("async crew result");
    expect(w.record).toHaveBeenCalledTimes(1);
  });
});
